from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from backend.app.core.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=settings.app_env == "development",
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
)

async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


# create_all never alters existing tables, so columns added after the first
# deploy are applied here. Each statement must be safe to run repeatedly.
_UPGRADES = (
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS workspace_id VARCHAR",
    "CREATE INDEX IF NOT EXISTS ix_vulnerabilities_workspace_id "
    "ON vulnerabilities (workspace_id)",
)


async def init_db() -> None:
    """Install pgvector extension and create all tables."""
    async with engine.begin() as conn:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        await conn.run_sync(Base.metadata.create_all)
        for statement in _UPGRADES:
            await conn.execute(text(statement))


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session
