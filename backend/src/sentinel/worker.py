"""Background worker: ``python -m sentinel.worker`` - ticks the orchestrator for every tenant."""

from __future__ import annotations

import logging
import signal
import time

from sentinel.api.main import build_from_env

log = logging.getLogger("sentinel.worker")


def main(interval: float = 5.0) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    platform, _ = build_from_env()
    stop = False

    def _stop(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while not stop:
        for tenant in platform.tenants.all():
            try:
                report = platform.runtime(tenant.tenant_id).orchestrator.tick(tenant.tenant_id)
                if report.failures:
                    log.warning("tenant=%s failures=%s", tenant.tenant_id, report.failures)
            except Exception:
                log.exception("tick failed for tenant %s", tenant.tenant_id)
        time.sleep(interval)


if __name__ == "__main__":
    main()
