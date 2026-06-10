import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import text, delete

from backend.app.core.config import settings
from backend.app.core.database import init_db
from backend.app.services.db_service import DBService, Vulnerability


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
        result = await conn.execute(text("SELECT extname FROM pg_extension WHERE extname = 'vector'"))
        row = result.fetchone()
        assert row is not None
        assert row[0] == "vector"

        table_check = await conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'vulnerabilities'")
        )
        assert table_check.fetchone() is not None


@pytest.mark.asyncio
async def test_save_and_retrieve_vulnerability(test_session_factory):
    async with test_session_factory() as session:
        db_service = DBService(session)

        audit_id = "integration_test_123"
        mock_embedding = [0.1] * 768

        vuln = await db_service.save_vulnerability(
            audit_id=audit_id,
            file_name="test_deployment.tf",
            vulnerability_type="Exposed Storage",
            severity="HIGH",
            description="Detailed test description of public access",
            resource="aws_s3_bucket.test",
            original_code="acl = public",
            patched_code="acl = private",
            embedding=mock_embedding,
        )

        assert vuln.id is not None
        assert vuln.audit_id == audit_id

        history = await db_service.get_audit_history(limit=5)
        test_records = [h for h in history if h["audit_id"] == audit_id]
        assert len(test_records) == 1
        assert test_records[0]["vulnerability_type"] == "Exposed Storage"
        assert test_records[0]["severity"] == "HIGH"

        # Clean up
        await session.execute(delete(Vulnerability).where(Vulnerability.audit_id == audit_id))
        await session.commit()


@pytest.mark.asyncio
async def test_vector_similarity_search(test_session_factory):
    async with test_session_factory() as session:
        db_service = DBService(session)

        await session.execute(delete(Vulnerability).where(Vulnerability.audit_id == "sim_test"))
        await session.commit()

        vector_a = [0.5] * 768
        vector_b = [-0.5] * 768

        await db_service.save_vulnerability(
            audit_id="sim_test",
            file_name="a.tf",
            vulnerability_type="S3 Exposure A",
            severity="CRITICAL",
            description="Vector A bucket",
            embedding=vector_a,
        )

        await db_service.save_vulnerability(
            audit_id="sim_test",
            file_name="b.tf",
            vulnerability_type="S3 Exposure B",
            severity="LOW",
            description="Vector B bucket",
            embedding=vector_b,
        )

        # Query with a vector close to A
        query_vector = [0.49] * 768
        results = await db_service.search_similar(query_vector, limit=100)

        assert len(results) >= 2
        sim_results = [r for r in results if r["audit_id"] == "sim_test"]
        assert len(sim_results) == 2

        assert sim_results[0]["vulnerability_type"] == "S3 Exposure A"
        assert sim_results[0]["similarity_score"] > 0.99
        assert sim_results[1]["vulnerability_type"] == "S3 Exposure B"
        assert sim_results[1]["similarity_score"] < 0.0

        # Clean up
        await session.execute(delete(Vulnerability).where(Vulnerability.audit_id == "sim_test"))
        await session.commit()
