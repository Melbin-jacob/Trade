"""FastAPI application: the HITL review API and partner webhooks."""


import json
import os
import re
from datetime import datetime
from typing import Annotated, Any

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from sentinel.api import views
from sentinel.api.auth import AuthError, TokenVerifier
from sentinel.api.cosign import CosignBook
from sentinel.api.middleware import BodySizeLimit, RateLimiter, SecurityHeaders
from sentinel.api.settings import Settings
from sentinel.dispatch.filing import build_filing_payload
from sentinel.dispatch.outbox import filing_key
from sentinel.domain.documents import DocumentType
from sentinel.ingestion.channels import SHIPMENT_REF_RE, ChannelRejected, IntakeItem, ReplayCache, from_port_api, verify_webhook
from sentinel.kernel.service import GuardViolation, Severity, sha256_hex
from sentinel.kernel.shipment import InvalidTransition, ShipmentAggregate
from sentinel.ledger.chain import ConcurrencyConflict, verify_chain
from sentinel.platform import Platform
from sentinel.rules.runner import current_documents
from sentinel.security.principals import AuthorizationError, Permission, Principal, Role

UPLOAD_ROLES = {Role.REVIEWER, Role.COMPLIANCE_OFFICER}


# --------------------------------------------------------------------------- #
# Request bodies
# --------------------------------------------------------------------------- #


class OpenShipment(BaseModel):
    shipment_id: str = Field(pattern=r"^SHP-\d{4}-\d{6}$")
    reference: str = Field(min_length=1, max_length=64)
    free_time_expires_at: datetime | None = None


class Approve(BaseModel):
    draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class Reason(BaseModel):
    reason: str = Field(min_length=20, max_length=2000)


class Waive(BaseModel):
    issue_ids: list[str] = Field(min_length=1, max_length=100)
    justification: str = Field(min_length=20, max_length=2000)


class HoldRelease(BaseModel):
    justification: str = Field(min_length=20, max_length=2000)


class Filing(BaseModel):
    customs_system: str = Field(pattern=r"^[A-Z0-9\-]{2,20}$")
    reviewed_docset_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


def mount_frontend(app: FastAPI, dist: str | None = None) -> None:
    """Serve the built dashboard. Call after every API route is registered."""
    from pathlib import Path

    from fastapi.staticfiles import StaticFiles

    path = Path(dist or os.environ.get("SENTINEL_FRONTEND_DIST", ""))
    if str(path) and path.is_dir():
        app.mount("/", StaticFiles(directory=path, html=True), name="frontend")


def create_app(platform: Platform, settings: Settings, verifier: TokenVerifier | None = None,
               run_pipeline_inline: bool = True, demo_access_code_required: bool = False) -> FastAPI:
    settings.validate()
    verifier = verifier or TokenVerifier(settings)
    cosign = CosignBook(platform.audit)
    replay = ReplayCache()
    app = FastAPI(title="Trade-Lane Sentinel", version="1.0.0",
                  docs_url="/api/docs" if settings.is_dev else None, redoc_url=None,
                  openapi_url="/api/openapi.json" if settings.is_dev else None)
    app.state.platform, app.state.settings = platform, settings

    app.add_middleware(BodySizeLimit, max_bytes=settings.max_upload_mb * 1024 * 1024 + 64 * 1024)
    app.add_middleware(RateLimiter, per_minute=settings.rate_limit_per_minute)
    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                           allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    app.add_middleware(SecurityHeaders)

    # ---------------- error mapping (never leak internals) ----------------
    @app.exception_handler(AuthorizationError)
    async def _authz(request: Request, exc: AuthorizationError):
        code = 404 if str(exc) == "not found" else 403
        return JSONResponse({"detail": "not found" if code == 404 else "forbidden"}, status_code=code)

    @app.exception_handler(InvalidTransition)
    async def _conflict(request: Request, exc: InvalidTransition):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(ConcurrencyConflict)
    async def _cc(request: Request, exc: ConcurrencyConflict):
        return JSONResponse({"detail": "shipment changed; reload and retry"}, status_code=409)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        return JSONResponse({"detail": "internal error", "request_id": getattr(request.state, "request_id", "")},
                            status_code=500)

    # ---------------- auth ----------------
    def user(authorization: Annotated[str | None, Header()] = None) -> Principal:
        try:
            p = verifier.principal(authorization)
            platform.tenants.get(p.tenant_id)
            return p
        except (AuthError, LookupError) as exc:
            raise HTTPException(401, str(exc) if isinstance(exc, AuthError) else "unknown tenant",
                                headers={"WWW-Authenticate": "Bearer"}) from None

    User = Annotated[Principal, Depends(user)]

    def load(u: Principal, shipment_id: str) -> ShipmentAggregate:
        if not SHIPMENT_REF_RE.fullmatch(shipment_id):
            raise HTTPException(404, "not found")
        return platform.service.load(u, u.tenant_id, shipment_id)

    def advance(tenant_id: str, shipment_id: str) -> None:
        try:
            platform.runtime(tenant_id).orchestrator.process_shipment(tenant_id, shipment_id)
        except Exception:
            pass  # failures are audited by the orchestrator; the worker retries

    def kick(bg: BackgroundTasks, tenant_id: str, shipment_id: str) -> None:
        if run_pipeline_inline:
            bg.add_task(advance, tenant_id, shipment_id)

    # ---------------- routes ----------------
    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/config")
    def public_config() -> dict[str, Any]:
        """Non-secret settings the SPA needs to start its OIDC (authorization code + PKCE) login."""
        if settings.is_dev:
            return {"auth": "dev", "access_code_required": demo_access_code_required}
        return {"auth": "oidc", "issuer": settings.oidc_issuer, "client_id": settings.oidc_client_id,
                "audience": settings.oidc_audience}

    @app.get("/api/v1/me")
    def me(u: User) -> dict[str, Any]:
        return {"id": u.id, "tenant_id": u.tenant_id, "roles": sorted(r.value for r in u.roles),
                "permissions": sorted(p.value for p in u.permissions)}

    @app.get("/api/v1/dashboard")
    def dashboard(u: User) -> dict[str, Any]:
        u.require(Permission.SHIPMENT_READ, u.tenant_id)
        return views.dashboard(platform.store, platform.blobs, u.tenant_id)

    @app.get("/api/v1/shipments")
    def list_shipments(u: User) -> list[dict[str, Any]]:
        u.require(Permission.SHIPMENT_READ, u.tenant_id)
        now = datetime.now().astimezone()
        return sorted((views.summary(a, now) for a in views.load_all(platform.store, u.tenant_id)),
                      key=lambda s: -s["updated_seq"])

    @app.post("/api/v1/shipments", status_code=201)
    def open_shipment(body: OpenShipment, u: User) -> dict[str, Any]:
        if not u.roles & UPLOAD_ROLES:
            raise HTTPException(403, "forbidden")
        rt = platform.runtime(u.tenant_id)
        agg = platform.service.open_shipment(rt.principals["ingest"], u.tenant_id, body.shipment_id,
                                             body.reference, body.free_time_expires_at)
        platform.audit.record(tenant_id=u.tenant_id, actor=u.audit_ref(), aggregate_type="user_action",
                              aggregate_id=f"user:{u.id}", event_type="shipment.open_requested",
                              payload={"shipment_id": body.shipment_id})
        return views.summary(agg, datetime.now().astimezone())

    @app.get("/api/v1/shipments/{shipment_id}")
    def get_shipment(shipment_id: str, u: User) -> dict[str, Any]:
        return views.shipment_detail(platform.store, platform.blobs, load(u, shipment_id), u)

    @app.get("/api/v1/shipments/{shipment_id}/issues/{issue_id}/diff")
    def diff(shipment_id: str, issue_id: str, u: User) -> dict[str, Any]:
        try:
            return views.issue_diff(platform.blobs, load(u, shipment_id), issue_id)
        except KeyError:
            raise HTTPException(404, "not found") from None

    @app.get("/api/v1/shipments/{shipment_id}/documents/{sha}")
    def get_document(shipment_id: str, sha: str, u: User) -> Response:
        agg = load(u, shipment_id)
        version = next((v for vs in agg.documents.values() for v in vs if v.content_sha256 == sha), None)
        if version is None:
            raise HTTPException(404, "not found")
        data = platform.blobs.get(u.tenant_id, version.storage_uri.removeprefix(f"blob://{u.tenant_id}/"))
        platform.audit.record(tenant_id=u.tenant_id, actor=u.audit_ref(), aggregate_type="data_access",
                              aggregate_id=f"access:{u.id}", event_type="document.viewed",
                              payload={"shipment_id": shipment_id, "content_sha256": sha})
        media = "application/pdf" if data.startswith(b"%PDF-") else "application/octet-stream"
        return Response(data, media_type=media, headers={
            "Content-Disposition": f'inline; filename="{version.doc_type.value}-v{version.version}"',
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'self'"})

    @app.post("/api/v1/shipments/{shipment_id}/documents", status_code=201)
    async def upload(shipment_id: str, u: User, bg: BackgroundTasks, file: UploadFile = File(...),
                     doc_type: str | None = Form(default=None)) -> dict[str, Any]:
        if not u.roles & UPLOAD_ROLES:
            raise HTTPException(403, "forbidden")
        load(u, shipment_id)
        content = await file.read(settings.max_upload_mb * 1024 * 1024 + 1)
        hint = DocumentType(doc_type) if doc_type else None
        rt = platform.runtime(u.tenant_id)
        result = rt.gateway.ingest(IntakeItem(
            u.tenant_id, shipment_id, re.sub(r"[^\w.\- ]", "_", file.filename or "upload")[:120], content,
            "manual_upload", hint, {"uploaded_by": u.id}))
        kick(bg, u.tenant_id, shipment_id)
        return {"outcome": result.outcome.value, "reason": result.reason, "content_sha256": result.content_sha256,
                "doc_type": result.doc_type.value if result.doc_type else None}

    @app.post("/api/v1/shipments/{shipment_id}/proposals/{proposal_id}/approve")
    def approve(shipment_id: str, proposal_id: str, body: Approve, u: User, bg: BackgroundTasks) -> dict[str, Any]:
        load(u, shipment_id)
        agg = platform.service.approve_remediation(u, u.tenant_id, shipment_id, proposal_id, body.draft_sha256)
        kick(bg, u.tenant_id, shipment_id)
        return views.summary(agg, datetime.now().astimezone())

    @app.post("/api/v1/shipments/{shipment_id}/proposals/{proposal_id}/reject")
    def reject(shipment_id: str, proposal_id: str, body: Reason, u: User) -> dict[str, Any]:
        load(u, shipment_id)
        agg = platform.service.reject_remediation(u, u.tenant_id, shipment_id, proposal_id, body.reason)
        return views.summary(agg, datetime.now().astimezone())

    @app.post("/api/v1/shipments/{shipment_id}/waivers")
    def waive(shipment_id: str, body: Waive, u: User, bg: BackgroundTasks) -> JSONResponse:
        agg = load(u, shipment_id)
        u.require(Permission.EXCEPTION_OVERRIDE, u.tenant_id)
        if any(agg.open_issues.get(i, {}).get("severity") == Severity.CRITICAL for i in body.issue_ids):
            req = cosign.request(u, "waive_critical", shipment_id, body.model_dump())
            return JSONResponse({"status": "cosign_required", "request": req.view()}, status_code=202)
        agg = platform.service.waive_issues(u, u.tenant_id, shipment_id, body.issue_ids, body.justification)
        kick(bg, u.tenant_id, shipment_id)
        return JSONResponse({"status": "waived", "shipment": views.summary(agg, datetime.now().astimezone())})

    @app.post("/api/v1/shipments/{shipment_id}/hold-release", status_code=202)
    def hold_release(shipment_id: str, body: HoldRelease, u: User) -> dict[str, Any]:
        load(u, shipment_id)
        u.require(Permission.HOLD_RELEASE, u.tenant_id)
        return {"status": "cosign_required", "request": cosign.request(u, "release_hold", shipment_id,
                                                                         body.model_dump()).view()}

    @app.get("/api/v1/cosign")
    def cosign_pending(u: User) -> list[dict[str, Any]]:
        u.require(Permission.SHIPMENT_READ, u.tenant_id)
        return [r.view() for r in cosign.pending(u.tenant_id)]

    @app.post("/api/v1/cosign/{request_id}/approve")
    def cosign_approve(request_id: str, u: User, bg: BackgroundTasks) -> dict[str, Any]:
        try:
            req = cosign.take(u.tenant_id, request_id)
        except KeyError:
            raise HTTPException(404, "not found") from None
        try:
            if req.kind == "release_hold":
                agg = platform.service.release_hold(req.requester, u, u.tenant_id, req.shipment_id,
                                                    req.params["justification"])
            else:
                agg = platform.service.waive_issues(req.requester, u.tenant_id, req.shipment_id,
                                                    req.params["issue_ids"], req.params["justification"],
                                                    second_approver=u)
        except (GuardViolation, AuthorizationError):
            cosign.restore(req)  # e.g. requester tried to co-sign their own request
            raise
        kick(bg, u.tenant_id, req.shipment_id)
        return views.summary(agg, datetime.now().astimezone())

    @app.post("/api/v1/shipments/{shipment_id}/filing")
    def file_declaration(shipment_id: str, body: Filing, u: User, bg: BackgroundTasks) -> dict[str, Any]:
        agg = load(u, shipment_id)
        u.require(Permission.FILING_SUBMIT, u.tenant_id)
        if body.reviewed_docset_hash != agg.docset_hash:
            raise HTTPException(409, "documents changed since you reviewed them")
        payload = build_filing_payload(agg, current_documents(platform.blobs, agg), body.customs_system)
        platform.blobs.put(u.tenant_id, filing_key(shipment_id, sha256_hex(payload)), payload)
        agg = platform.service.submit_filing(u, u.tenant_id, shipment_id, body.customs_system, payload,
                                             body.reviewed_docset_hash)
        kick(bg, u.tenant_id, shipment_id)
        return {"shipment": views.summary(agg, datetime.now().astimezone()),
                "filing_payload_sha256": sha256_hex(payload), "payload": json.loads(payload)}

    @app.post("/api/v1/shipments/{shipment_id}/cancel")
    def cancel(shipment_id: str, body: Reason, u: User) -> dict[str, Any]:
        load(u, shipment_id)
        agg = platform.service.cancel(u, u.tenant_id, shipment_id, body.reason)
        return views.summary(agg, datetime.now().astimezone())

    @app.get("/api/v1/ledger/verify")
    def verify(u: User) -> dict[str, Any]:
        if not u.roles & {Role.AUDITOR, Role.COMPLIANCE_OFFICER}:
            raise HTTPException(403, "forbidden")
        r = verify_chain(platform.store.read_chain(u.tenant_id), platform.keyring)
        return {"ok": r.ok, "entries_checked": r.entries_checked, "failed_sequence": r.failed_sequence,
                "reason": r.reason, "head": platform.store.head(u.tenant_id)[1]}

    @app.get("/api/v1/audit")
    def audit_log(u: User, limit: int = 200, aggregate_type: str | None = None) -> list[dict[str, Any]]:
        u.require(Permission.SHIPMENT_READ, u.tenant_id)
        entries = [e for e in platform.store.read_chain(u.tenant_id)
                   if aggregate_type is None or e.aggregate_type == aggregate_type]
        return [{"sequence": e.sequence, "at": e.recorded_at.isoformat(), "aggregate_type": e.aggregate_type,
                 "aggregate_id": e.aggregate_id, "event": e.event_type, "actor": e.actor,
                 "entry_hash": e.entry_hash, "prev_hash": e.prev_hash, "key_id": e.key_id}
                for e in entries[-max(1, min(limit, 1000)):]][::-1]

    # ---------------- partner / port webhooks (HMAC-signed, no user token) ----------------
    @app.post("/api/v1/webhooks/{tenant_id}/{partner_id}", status_code=202)
    async def webhook(tenant_id: str, partner_id: str, request: Request, bg: BackgroundTasks,
                      x_sentinel_timestamp: Annotated[str, Header()],
                      x_sentinel_nonce: Annotated[str, Header()],
                      x_sentinel_signature: Annotated[str, Header()]) -> dict[str, Any]:
        try:
            tenant = platform.tenants.get(tenant_id)
        except LookupError:
            raise HTTPException(404, "not found") from None
        body = await request.body()
        try:
            verify_webhook(tenant=tenant, partner_id=partner_id, timestamp=x_sentinel_timestamp,
                           nonce=x_sentinel_nonce[:128], signature=x_sentinel_signature, body=body, replay=replay)
            item = from_port_api(body, tenant, partner_id)
        except ChannelRejected:
            raise HTTPException(401, "rejected") from None
        result = platform.runtime(tenant_id).gateway.ingest(item)
        kick(bg, tenant_id, item.shipment_id)
        return {"outcome": result.outcome.value, "content_sha256": result.content_sha256}

    return app
