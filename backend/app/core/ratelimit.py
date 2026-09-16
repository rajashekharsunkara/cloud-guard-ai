import asyncio
import math
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import HTTPException, Request

from backend.app.core.config import settings


class SlidingWindowLimiter:
    """Per-client request counts kept in memory.

    The app runs as a single process on one host, so there is nothing to
    share state with. Counts reset on restart, which is acceptable for abuse
    protection (daily quotas that must survive restarts live in Postgres).
    """

    def __init__(self):
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)

    def hit(self, bucket: str, client: str, limit: int, window: int) -> float:
        """Record a request. Returns 0 if allowed, else seconds until retry."""
        now = time.monotonic()
        hits = self._hits[(bucket, client)]
        while hits and hits[0] <= now - window:
            hits.popleft()
        if len(hits) >= limit:
            return hits[0] + window - now
        hits.append(now)
        if len(self._hits) > 10_000:
            self._prune(now, window)
        return 0

    def _prune(self, now: float, window: int) -> None:
        stale = [k for k, v in self._hits.items() if not v or v[-1] <= now - window]
        for key in stale:
            del self._hits[key]

    def reset(self) -> None:
        self._hits.clear()


limiter = SlidingWindowLimiter()


def client_ip(request: Request) -> str:
    # Uvicorn has already replaced this with the X-Forwarded-For address when
    # the request came through a trusted proxy (FORWARDED_ALLOW_IPS).
    return request.client.host if request.client else "unknown"


def rate_limit(bucket: str, limit_setting: str, window: int):
    def dependency(request: Request) -> None:
        limit = getattr(settings, limit_setting)
        retry_after = limiter.hit(bucket, client_ip(request), limit, window)
        if retry_after:
            seconds = math.ceil(retry_after)
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests. Try again in {_humanize(seconds)}.",
                headers={"Retry-After": str(seconds)},
            )

    return dependency


def _humanize(seconds: int) -> str:
    if seconds < 90:
        return f"{seconds} seconds"
    return f"{math.ceil(seconds / 60)} minutes"


class ScanSlots:
    """Caps how many scans run at once so a burst can't exhaust memory."""

    def __init__(self):
        self._semaphore = None
        self._size = None

    def _get(self) -> asyncio.Semaphore:
        size = settings.max_concurrent_scans
        if self._semaphore is None or self._size != size:
            self._semaphore = asyncio.Semaphore(size)
            self._size = size
        return self._semaphore

    @asynccontextmanager
    async def acquire(self, wait: float = 30):
        semaphore = self._get()
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=wait)
        except asyncio.TimeoutError:
            raise HTTPException(
                status_code=503,
                detail="The scanner is busy right now. Try again in a minute.",
                headers={"Retry-After": "30"},
            )
        try:
            yield
        finally:
            semaphore.release()


scan_slots = ScanSlots()

scan_rate_limit = rate_limit("scan", "scan_rate_limit", window=600)
search_rate_limit = rate_limit("search", "search_rate_limit", window=60)
