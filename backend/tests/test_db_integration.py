import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text, delete

from backend.app.core.config import settings
from backend.app.core.database import init_db
from backend.app.services.db_service import Audit, DBService, Vulnerability


@pytest_asyncio.fixture
async def test_engine():
    engine_url = settings.database_url
    engine = create_async_engine(engine_url, echo=False)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def test_session_factory(test_engine):
    return async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.mark.asyncio
async def test_db_init_and_pgvector_extension(test_engine):
    await init_db()

    async with test_engine.connect() as conn:
        result = await conn.execute(
            text("SELECT extname FROM pg_extension WHERE extname = 'vector'")
        )
        row = result.fetchone()
        assert row is not None
        assert row[0] == "vector"

        table_check = await conn.execute(
            text(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'vulnerabilities'"
            )
        )
        assert table_check.fetchone() is not None


WORKSPACE_A = "a1" * 16
WORKSPACE_B = "b2" * 16


async def _cleanup(session, *audit_ids):
    await session.execute(
        delete(Vulnerability).where(Vulnerability.audit_id.in_(audit_ids))
    )
    await session.execute(delete(Audit).where(Audit.id.in_(audit_ids)))
    await session.commit()


@pytest.mark.asyncio
async def test_save_and_list_audit(test_session_factory):
    async with test_session_factory() as session:
        db_service = DBService(session)
        audit_id = "integration_test_123"
        await _cleanup(session, audit_id)

        await db_service.save_audit(
            audit_id=audit_id,
            workspace_id=WORKSPACE_A,
            file_name="test_deployment.tf",
            security_score=70,
            findings=[
                {"severity": "HIGH", "title": "Exposed Storage"},
                {"severity": "medium", "title": "No logging"},
            ],
            original_code="acl = public",
            patched_code="acl = private",
        )

        summaries = await db_service.list_audits(WORKSPACE_A)
        ours = [a for a in summaries if a["audit_id"] == audit_id]
        assert len(ours) == 1
        assert ours[0]["finding_count"] == 2
        assert ours[0]["severity_counts"] == {"HIGH": 1, "MEDIUM": 1}

        detail = await db_service.get_audit(WORKSPACE_A, audit_id)
        assert detail["patched_code"] == "acl = private"
        assert detail["vulnerabilities"][0]["title"] == "Exposed Storage"

        assert await db_service.get_audit(WORKSPACE_B, audit_id) is None
        assert audit_id not in [
            a["audit_id"] for a in await db_service.list_audits(WORKSPACE_B)
        ]

        await _cleanup(session, audit_id)


@pytest.mark.asyncio
async def test_vector_similarity_search(test_session_factory):
    async with test_session_factory() as session:
        db_service = DBService(session)
        await _cleanup(session, "sim_test", "sim_other")

        await db_service.save_vulnerability(
            audit_id="sim_test",
            workspace_id=WORKSPACE_A,
            file_name="a.tf",
            vulnerability_type="S3 Exposure A",
            severity="CRITICAL",
            description="Vector A bucket",
            embedding=[0.5] * 768,
        )
        await db_service.save_vulnerability(
            audit_id="sim_test",
            workspace_id=WORKSPACE_A,
            file_name="b.tf",
            vulnerability_type="S3 Exposure B",
            severity="LOW",
            description="Vector B bucket",
            embedding=[-0.5] * 768,
        )
        # Same vector in another workspace must never show up.
        await db_service.save_vulnerability(
            audit_id="sim_other",
            workspace_id=WORKSPACE_B,
            file_name="c.tf",
            vulnerability_type="Someone else's finding",
            severity="HIGH",
            description="Vector A bucket",
            embedding=[0.5] * 768,
        )

        results = await db_service.search_similar([0.49] * 768, WORKSPACE_A, limit=100)

        assert all(r["audit_id"] != "sim_other" for r in results)
        sim_results = [r for r in results if r["audit_id"] == "sim_test"]
        assert len(sim_results) == 2
        assert sim_results[0]["vulnerability_type"] == "S3 Exposure A"
        assert sim_results[0]["severity"] == "CRITICAL"
        assert sim_results[0]["similarity_score"] > 0.99
        assert sim_results[1]["vulnerability_type"] == "S3 Exposure B"
        assert sim_results[1]["similarity_score"] < 0.0

        await db_service.clear_workspace(WORKSPACE_A)
        assert await db_service.search_similar([0.49] * 768, WORKSPACE_A) == []

        await _cleanup(session, "sim_test", "sim_other")
