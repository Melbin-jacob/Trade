import hashlib
import hmac
import json
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from sentinel.api.demo import TENANT, create_demo_app
from sentinel.api.settings import Settings

SECRET = "test-dev-secret-0123456789-abcdefghijklmnopqrstuvwxyz"


@pytest.fixture(scope="module")
def client(monkeypatch_module):
    monkeypatch_module.setenv("SENTINEL_DEV_JWT_SECRET", SECRET)
    monkeypatch_module.setenv("SENTINEL_FRONTEND_DIST", "/nonexistent")
    app = create_demo_app()
    with TestClient(app, base_url="https://testserver") as c:
        c.app_ref = app
        yield c


@pytest.fixture(scope="module")
def monkeypatch_module():
    mp = pytest.MonkeyPatch()
    yield mp
    mp.undo()


def auth(client, user):
    token = client.post("/api/v1/dev/token", json={"user": user}).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_requires_valid_token(client):
    assert client.get("/api/v1/dashboard").status_code == 401
    assert client.get("/api/v1/dashboard", headers={"Authorization": "Bearer nope"}).status_code == 401
    now = int(time.time())
    base = {"sub": "x", "tenant": TENANT, "roles": ["reviewer"], "iat": now, "exp": now + 600,
            "iss": "sentinel-dev", "aud": "trade-lane-sentinel"}
    no_mfa = jwt.encode(base, SECRET, algorithm="HS256")
    assert client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {no_mfa}"}).status_code == 401
    agent_role = jwt.encode({**base, "amr": ["otp"], "roles": ["remediation_agent"]}, SECRET, algorithm="HS256")
    assert client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {agent_role}"}).status_code == 401
    other_tenant = jwt.encode({**base, "amr": ["otp"], "tenant": "globex_freight"}, SECRET, algorithm="HS256")
    assert client.get("/api/v1/dashboard", headers={"Authorization": f"Bearer {other_tenant}"}).status_code == 401


def test_security_headers(client):
    r = client.get("/healthz")
    assert r.headers["Strict-Transport-Security"].startswith("max-age=")
    assert r.headers["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_dashboard_shape(client):
    d = client.get("/api/v1/dashboard", headers=auth(client, "alex.lee")).json()
    assert d["overall_score"] is not None and len(d["categories"]) == 4
    assert d["attention"]["buckets"]["demurrage"] == 1
    assert {c["shipment_id"] for c in d["attention"]["cards"]} >= {"SHP-2026-000123", "SHP-2026-000126"}


def test_diff_and_decision_tree(client):
    h = auth(client, "alex.lee")
    s = client.get("/api/v1/shipments/SHP-2026-000123", headers=h).json()
    assert s["decision_tree"] and "approve_remediation" in s["actions"]
    d = client.get("/api/v1/shipments/SHP-2026-000123/issues/pl_net_le_gross:line2/diff", headers=h).json()
    side = d["sides"][0]
    assert side["highlight"] == "net_weight" and side["context"][0]["path"] == "lines[1]"
    assert client.get("/api/v1/shipments/SHP-2026-000999", headers=h).status_code == 404


def test_role_boundaries(client):
    h = auth(client, "alex.lee")
    assert client.post("/api/v1/shipments/SHP-2026-000126/hold-release",
                       json={"justification": "x" * 30}, headers=h).status_code == 403
    s = client.get("/api/v1/shipments/SHP-2026-000124", headers=h).json()
    r = client.post("/api/v1/shipments/SHP-2026-000124/filing",
                    json={"customs_system": "CBSA-CARM", "reviewed_docset_hash": s["docset_hash"]}, headers=h)
    assert r.status_code == 403


def test_approve_then_upload_correction_reaches_ready(client):
    h = auth(client, "alex.lee")
    s = client.get("/api/v1/shipments/SHP-2026-000123", headers=h).json()
    p = s["proposal"]
    assert client.post(f"/api/v1/shipments/SHP-2026-000123/proposals/{p['proposal_id']}/approve",
                       json={"draft_sha256": "0" * 64}, headers=h).status_code == 409
    r = client.post(f"/api/v1/shipments/SHP-2026-000123/proposals/{p['proposal_id']}/approve",
                    json={"draft_sha256": p["draft_sha256"]}, headers=h)
    assert r.status_code == 200 and r.json()["state"] == "awaiting_correction"
    outbox = client.get("/api/v1/dev/outbox").json()
    assert outbox["emails"][0]["to"] == ["export@fazendaboavista.example"]

    pdf = client.get("/api/v1/dev/sample/corrected-packing-list").content
    r = client.post("/api/v1/shipments/SHP-2026-000123/documents", headers=h,
                    files={"file": ("pl.pdf", pdf, "application/pdf")})
    assert r.json()["outcome"] == "accepted"
    s = client.get("/api/v1/shipments/SHP-2026-000123", headers=h).json()
    assert s["state"] == "ready_for_filing", s["blocking_reasons"]


def test_four_eyes_hold_release(client):
    emma, jane = auth(client, "emma.davis"), auth(client, "jane.doe")
    r = client.post("/api/v1/shipments/SHP-2026-000126/hold-release",
                    json={"justification": "Consignee verified as a different legal entity (registry no. 4471)."},
                    headers=emma)
    assert r.status_code == 202
    req = r.json()["request"]["id"]
    assert client.post(f"/api/v1/cosign/{req}/approve", headers=emma).status_code == 409  # same person
    r = client.post(f"/api/v1/cosign/{req}/approve", headers=jane)
    assert r.status_code == 200 and r.json()["state"] != "compliance_hold"


def test_filing_and_ledger_verification(client):
    sam = auth(client, "sam.patel")
    s = client.get("/api/v1/shipments/SHP-2026-000124", headers=sam).json()
    r = client.post("/api/v1/shipments/SHP-2026-000124/filing",
                    json={"customs_system": "CBSA-CARM", "reviewed_docset_hash": s["docset_hash"]}, headers=sam)
    assert r.status_code == 200 and r.json()["payload"]["containers"] == ["TGHU1234567"]
    assert client.get("/api/v1/dev/outbox").json()["customs"]
    v = client.get("/api/v1/ledger/verify", headers=auth(client, "kim.auditor")).json()
    assert v["ok"] and v["entries_checked"] > 50
    assert client.get("/api/v1/ledger/verify", headers=auth(client, "alex.lee")).status_code == 403


def test_webhook_signature_required(client):
    body = json.dumps({"shipment_id": "SHP-2026-000123", "content_b64": ""}).encode()
    r = client.post(f"/api/v1/webhooks/{TENANT}/port-montreal", content=body, headers={
        "X-Sentinel-Timestamp": str(int(time.time())), "X-Sentinel-Nonce": "n1",
        "X-Sentinel-Signature": hmac.new(b"wrong", body, hashlib.sha256).hexdigest()})
    assert r.status_code == 401


def test_production_settings_validation(monkeypatch):
    with pytest.raises(RuntimeError):
        Settings(env="production", dev_jwt_secret="").validate()
    with pytest.raises(RuntimeError):
        Settings(env="production", dev_jwt_secret="x" * 40, oidc_issuer="https://idp", oidc_jwks_url="https://idp/jwks").validate()
    Settings(env="production", dev_jwt_secret="", oidc_issuer="https://idp.example",
             oidc_jwks_url="https://idp.example/jwks").validate()
