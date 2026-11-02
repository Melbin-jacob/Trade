"""Tenant configuration: key references, residency and counterparty allowlists.

Counterparty contact details come from here (maintained by the tenant's admins),
never from document text - a forged invoice must not be able to redirect a
correction email to an attacker's address.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.domain.identifiers import TenantId  # noqa: F401  (documentation of the format)


@dataclass(frozen=True)
class Counterparty:
    name: str
    role: str  # supplier | shipping_line | freight_forwarder | customs_broker
    email: str
    domains: frozenset[str]


@dataclass(frozen=True)
class TenantConfig:
    tenant_id: str
    kms_key_ref: str
    data_region: str
    counterparties: tuple[Counterparty, ...] = ()
    #: Shared secrets for signed port/partner API webhooks, keyed by partner id.
    webhook_secrets: dict[str, bytes] = field(default_factory=dict)
    #: Domains we accept trade documents from by email.
    inbound_email_domains: frozenset[str] = frozenset()
    #: Importing country (ISO 3166-1 alpha-2) - drives import rules.
    home_country: str = "CA"

    def allowed_recipient(self, address: str) -> bool:
        domain = address.rsplit("@", 1)[-1].lower()
        return any(domain in c.domains for c in self.counterparties)

    def counterparty_for_role(self, role: str) -> Counterparty | None:
        return next((c for c in self.counterparties if c.role == role), None)


class TenantDirectory:
    def __init__(self, tenants: list[TenantConfig] | None = None) -> None:
        self._tenants = {t.tenant_id: t for t in tenants or []}

    def add(self, tenant: TenantConfig) -> None:
        self._tenants[tenant.tenant_id] = tenant

    def get(self, tenant_id: str) -> TenantConfig:
        try:
            return self._tenants[tenant_id]
        except KeyError:
            raise LookupError("unknown tenant") from None

    def all(self) -> list[TenantConfig]:
        return list(self._tenants.values())
