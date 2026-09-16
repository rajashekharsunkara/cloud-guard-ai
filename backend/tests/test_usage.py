import asyncio
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from backend.app.core.config import settings
from backend.app.core.database import init_db
from backend.app.services.usage import FreeQuota, LlmUsage, _client_hash


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    await init_db()
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture
def client():
    return f"test-{uuid.uuid4().hex}"


@pytest_asyncio.fixture(autouse=True)
async def cleanup(session_factory, client):
    yield
    async with session_factory() as session:
        await session.execute(
            delete(LlmUsage).where(LlmUsage.client_hash == _client_hash(client))
        )
        await session.commit()


@pytest.mark.asyncio
async def test_claims_until_limit_then_refund(session_factory, client, monkeypatch):
    monkeypatch.setattr(settings, "free_llm_scans_per_day", 2)
    async with session_factory() as session:
        quota = FreeQuota(session, client)
        assert await quota.remaining() == 2
        assert await quota.claim()
        assert await quota.claim()
        assert not await quota.claim()
        assert await quota.remaining() == 0

        await quota.refund()
        assert await quota.remaining() == 1


@pytest.mark.asyncio
async def test_clients_are_counted_separately(session_factory, client, monkeypatch):
    monkeypatch.setattr(settings, "free_llm_scans_per_day", 1)
    other = client + "-other"
    async with session_factory() as session:
        assert await FreeQuota(session, client).claim()
        assert await FreeQuota(session, other).claim()
        assert not await FreeQuota(session, client).claim()
    async with session_factory() as session:
        await session.execute(
            delete(LlmUsage).where(LlmUsage.client_hash == _client_hash(other))
        )
        await session.commit()


@pytest.mark.asyncio
async def test_concurrent_claims_never_exceed_limit(
    session_factory, client, monkeypatch
):
    monkeypatch.setattr(settings, "free_llm_scans_per_day", 5)

    async def claim():
        async with session_factory() as session:
            return await FreeQuota(session, client).claim()

    results = await asyncio.gather(*(claim() for _ in range(12)))
    assert results.count(True) == 5


@pytest.mark.asyncio
async def test_disabled_without_server_key(session_factory, client, monkeypatch):
    monkeypatch.setattr(settings, "groq_api_key", "")
    async with session_factory() as session:
        quota = FreeQuota(session, client)
        assert not quota.enabled
        assert not await quota.claim()
        assert await quota.remaining() == 0


def test_addresses_are_not_stored_in_clear():
    hashed = _client_hash("203.0.113.9")
    assert "203.0.113.9" not in hashed
    assert len(hashed) == 64
