from backend.app.core.config import settings
from backend.app.core import database
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Point to localhost instead of container hostnames when running tests on the host
settings.aws_endpoint_url = settings.aws_endpoint_url.replace("localstack", "localhost")
settings.database_url = settings.database_url.replace("@postgres:", "@localhost:")

# Use NullPool to avoid event loop reuse issues in tests
database.engine = create_async_engine(
    settings.database_url,
    poolclass=NullPool,
)
database.async_session = async_sessionmaker(
    database.engine,
    class_=AsyncSession,
    expire_on_commit=False,
)
