import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.ratelimit import ScanSlots, SlidingWindowLimiter
from backend.app.main import app


class TestSlidingWindowLimiter:

    def test_allows_up_to_limit_then_blocks(self):
        limiter = SlidingWindowLimiter()
        for _ in range(3):
            assert limiter.hit("scan", "1.2.3.4", limit=3, window=60) == 0
        retry = limiter.hit("scan", "1.2.3.4", limit=3, window=60)
        assert 0 < retry <= 60

    def test_clients_and_buckets_are_independent(self):
        limiter = SlidingWindowLimiter()
        assert limiter.hit("scan", "1.1.1.1", limit=1, window=60) == 0
        assert limiter.hit("scan", "1.1.1.1", limit=1, window=60) > 0
        assert limiter.hit("scan", "2.2.2.2", limit=1, window=60) == 0
        assert limiter.hit("search", "1.1.1.1", limit=1, window=60) == 0

    def test_window_expiry(self):
        limiter = SlidingWindowLimiter()
        with patch("backend.app.core.ratelimit.time.monotonic", return_value=100.0):
            assert limiter.hit("scan", "ip", limit=1, window=10) == 0
            assert limiter.hit("scan", "ip", limit=1, window=10) > 0
        with patch("backend.app.core.ratelimit.time.monotonic", return_value=111.0):
            assert limiter.hit("scan", "ip", limit=1, window=10) == 0


class TestScanSlots:

    @pytest.mark.asyncio
    async def test_busy_when_all_slots_taken(self, monkeypatch):
        monkeypatch.setattr(settings, "max_concurrent_scans", 1)
        slots = ScanSlots()
        async with slots.acquire():
            with pytest.raises(HTTPException) as exc:
                async with slots.acquire(wait=0.05):
                    pass
            assert exc.value.status_code == 503
        # Released again after the first scan finishes.
        async with slots.acquire(wait=0.05):
            pass

    @pytest.mark.asyncio
    async def test_slot_released_on_error(self, monkeypatch):
        monkeypatch.setattr(settings, "max_concurrent_scans", 1)
        slots = ScanSlots()
        with pytest.raises(RuntimeError):
            async with slots.acquire():
                raise RuntimeError("scan blew up")
        await asyncio.wait_for(slots._get().acquire(), timeout=0.05)


class TestRateLimitedEndpoints:

    @patch("backend.app.routers.auditor.run_to_completion")
    def test_audit_returns_429_after_limit(self, mock_audit, monkeypatch):
        monkeypatch.setattr(settings, "scan_rate_limit", 2)
        mock_audit.return_value = {
            "audit_id": "a1",
            "file_name": "main.tf",
            "security_score": 100,
            "vulnerabilities": [],
            "patched_code": "",
            "analysis": {"mode": "static"},
        }

        async def override_get_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = override_get_db
        payload = {"iac_content": 'resource "x" "y" { a = 1 }'}
        try:
            client = TestClient(app)
            assert client.post("/api/audit", json=payload).status_code == 200
            assert client.post("/api/audit", json=payload).status_code == 200
            blocked = client.post("/api/audit", json=payload)
            assert blocked.status_code == 429
            assert int(blocked.headers["Retry-After"]) > 0
            assert "Too many requests" in blocked.json()["detail"]
            assert mock_audit.call_count == 2
        finally:
            app.dependency_overrides.clear()

    @patch("backend.app.routers.auditor.generate_embedding")
    @patch("backend.app.routers.auditor.DBService")
    def test_search_has_its_own_limit(self, mock_db_class, mock_embed, monkeypatch):
        monkeypatch.setattr(settings, "search_rate_limit", 1)
        mock_embed.return_value = [0.0] * 768
        mock_db = MagicMock()
        mock_db.search_similar = AsyncMock(return_value=[])
        mock_db_class.return_value = mock_db

        async def override_get_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = override_get_db
        try:
            client = TestClient(app)
            assert (
                client.post("/api/search", json={"query": "open port"}).status_code
                == 200
            )
            assert (
                client.post("/api/search", json={"query": "open port"}).status_code
                == 429
            )
        finally:
            app.dependency_overrides.clear()
