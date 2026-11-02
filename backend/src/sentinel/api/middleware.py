"""HTTP hardening: security headers, body-size limits, rate limiting, request ids."""

from __future__ import annotations

import threading
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

CSP = ("default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src 'self' https://fonts.gstatic.com; frame-src 'self' blob:; object-src 'none'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request.state.request_id = request.headers.get("x-request-id", str(uuid.uuid4()))[:64]
        response = await call_next(request)
        h = response.headers
        h["X-Request-ID"] = request.state.request_id
        h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h.setdefault("Content-Security-Policy", CSP)
        if request.url.path.startswith("/api/"):
            h["Cache-Control"] = "no-store"
        return response


class BodySizeLimit(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int) -> None:
        super().__init__(app)
        self._max = max_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > self._max):
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)


class RateLimiter(BaseHTTPMiddleware):
    """Token bucket per client (bearer-token subject hash or IP). Use a shared
    store (e.g. Redis) when running more than one API replica."""

    def __init__(self, app, per_minute: int) -> None:
        super().__init__(app)
        self._rate = per_minute / 60.0
        self._cap = float(per_minute)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def _key(self, request: Request) -> str:
        auth = request.headers.get("authorization", "")
        if auth:
            return "t:" + str(hash(auth))
        return "ip:" + (request.client.host if request.client else "unknown")

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path == "/healthz":
            return await call_next(request)
        now, key = time.monotonic(), self._key(request)
        with self._lock:
            tokens, last = self._buckets.get(key, (self._cap, now))
            tokens = min(self._cap, tokens + (now - last) * self._rate)
            allowed = tokens >= 1
            self._buckets[key] = (tokens - 1 if allowed else tokens, now)
        if not allowed:
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429, headers={"Retry-After": "10"})
        return await call_next(request)
