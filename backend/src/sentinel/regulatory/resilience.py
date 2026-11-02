"""Circuit breaker for external regulatory services.

When a provider keeps failing we stop calling it for ``reset_after`` seconds.
Callers treat an open circuit exactly like a failure, so nothing is cleared
while a dependency is down (fail closed).
"""

from __future__ import annotations

import threading
import time
from typing import Callable, TypeVar

T = TypeVar("T")


class CircuitOpen(RuntimeError):
    pass


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 3, reset_after: float = 60.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.name, self._threshold, self._reset_after, self._clock = name, failure_threshold, reset_after, clock
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        if self._opened_at is None:
            return "closed"
        return "half_open" if self._clock() - self._opened_at >= self._reset_after else "open"

    def call(self, fn: Callable[[], T]) -> T:
        with self._lock:
            if self.state == "open":
                raise CircuitOpen(f"{self.name} circuit is open")
        try:
            result = fn()
        except Exception:
            with self._lock:
                self._failures += 1
                if self._failures >= self._threshold or self._opened_at is not None:
                    self._opened_at = self._clock()
            raise
        with self._lock:
            self._failures, self._opened_at = 0, None
        return result
