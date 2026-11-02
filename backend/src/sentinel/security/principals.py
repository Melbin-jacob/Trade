"""Principals, roles and the agent permission boundary.

The deterministic execution boundary is enforced here, not in prompts:

* AI agents (analyzer / orchestrator / drafter) hold READ permissions and, at
  most, ``REMEDIATION_PROPOSE``. They can never hold a permission that changes
  an external system or approves their own proposal - ``Principal`` refuses to
  be constructed that way.
* Write actions with external effect (ERP updates, customs filing, outbound
  email) require a HUMAN principal with the matching permission, and the most
  sensitive ones require a second, distinct approver (four-eyes).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator

from sentinel.domain.identifiers import TenantId


class PrincipalKind(StrEnum):
    HUMAN = "human"
    AGENT = "agent"  # LLM-driven component
    SERVICE = "service"  # deterministic pipeline service (OCR, rule engine, ...)


class Permission(StrEnum):
    SHIPMENT_READ = "shipment:read"
    DOCUMENT_INGEST = "document:ingest"
    EXTRACTION_RECORD = "extraction:record"
    VALIDATION_RECORD = "validation:record"
    SCREENING_RECORD = "screening:record"
    REMEDIATION_PROPOSE = "remediation:propose"
    REMEDIATION_APPROVE = "remediation:approve"
    EXCEPTION_OVERRIDE = "exception:override"
    HOLD_RELEASE = "hold:release"
    FILING_SUBMIT = "filing:submit"
    SHIPMENT_CLOSE = "shipment:close"
    SHIPMENT_CANCEL = "shipment:cancel"


#: Permissions an AGENT principal may ever hold. Anything else is rejected.
AGENT_ALLOWED: frozenset[Permission] = frozenset(
    {Permission.SHIPMENT_READ, Permission.REMEDIATION_PROPOSE}
)

#: Permissions only a HUMAN principal may hold.
HUMAN_ONLY: frozenset[Permission] = frozenset(
    {
        Permission.REMEDIATION_APPROVE,
        Permission.EXCEPTION_OVERRIDE,
        Permission.HOLD_RELEASE,
        Permission.FILING_SUBMIT,
        Permission.SHIPMENT_CANCEL,
    }
)


class Role(StrEnum):
    ANALYZER_AGENT = "analyzer_agent"
    REMEDIATION_AGENT = "remediation_agent"
    INGESTION_SERVICE = "ingestion_service"
    EXTRACTION_SERVICE = "extraction_service"
    RULE_ENGINE = "rule_engine"
    SCREENING_SERVICE = "screening_service"
    REVIEWER = "reviewer"
    COMPLIANCE_OFFICER = "compliance_officer"
    CUSTOMS_FILER = "customs_filer"
    AUDITOR = "auditor"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ANALYZER_AGENT: frozenset({Permission.SHIPMENT_READ}),
    Role.REMEDIATION_AGENT: frozenset({Permission.SHIPMENT_READ, Permission.REMEDIATION_PROPOSE}),
    Role.INGESTION_SERVICE: frozenset({Permission.DOCUMENT_INGEST}),
    Role.EXTRACTION_SERVICE: frozenset({Permission.SHIPMENT_READ, Permission.EXTRACTION_RECORD}),
    Role.RULE_ENGINE: frozenset({Permission.SHIPMENT_READ, Permission.VALIDATION_RECORD}),
    Role.SCREENING_SERVICE: frozenset({Permission.SHIPMENT_READ, Permission.SCREENING_RECORD}),
    Role.REVIEWER: frozenset(
        {Permission.SHIPMENT_READ, Permission.REMEDIATION_APPROVE, Permission.EXCEPTION_OVERRIDE}
    ),
    Role.COMPLIANCE_OFFICER: frozenset(
        {
            Permission.SHIPMENT_READ,
            Permission.REMEDIATION_APPROVE,
            Permission.EXCEPTION_OVERRIDE,
            Permission.HOLD_RELEASE,
            Permission.SHIPMENT_CANCEL,
        }
    ),
    Role.CUSTOMS_FILER: frozenset(
        {Permission.SHIPMENT_READ, Permission.FILING_SUBMIT, Permission.SHIPMENT_CLOSE}
    ),
    Role.AUDITOR: frozenset({Permission.SHIPMENT_READ}),
}


class AuthorizationError(PermissionError):
    pass


class Principal(BaseModel):
    """An authenticated caller. Built from a verified OIDC / workload token."""

    model_config = ConfigDict(frozen=True)

    id: str
    kind: PrincipalKind
    tenant_id: TenantId
    roles: frozenset[Role]

    @property
    def permissions(self) -> frozenset[Permission]:
        perms: set[Permission] = set()
        for role in self.roles:
            perms |= ROLE_PERMISSIONS[role]
        return frozenset(perms)

    @model_validator(mode="after")
    def _enforce_boundary(self) -> "Principal":
        perms = self.permissions
        if self.kind is PrincipalKind.AGENT and not perms <= AGENT_ALLOWED:
            raise ValueError(
                f"agent principal {self.id!r} may not hold {sorted(perms - AGENT_ALLOWED)}"
            )
        if self.kind is not PrincipalKind.HUMAN and perms & HUMAN_ONLY:
            raise ValueError(
                f"non-human principal {self.id!r} may not hold {sorted(perms & HUMAN_ONLY)}"
            )
        return self

    def require(self, permission: Permission, tenant_id: str) -> None:
        if tenant_id != self.tenant_id:
            # Never leak whether the resource exists in another tenant.
            raise AuthorizationError("not found")
        if permission not in self.permissions:
            raise AuthorizationError(f"{self.id} lacks {permission}")

    def audit_ref(self) -> dict[str, str]:
        return {"id": self.id, "kind": self.kind.value}
