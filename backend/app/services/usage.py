import hashlib
from datetime import datetime, timezone

from sqlalchemy import Column, Date, Integer, String, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import Base


class LlmUsage(Base):
    """Free explained scans used per client per UTC day."""

    __tablename__ = "llm_usage"

    client_hash = Column(String, primary_key=True)
    day = Column(Date, primary_key=True)
    count = Column(Integer, nullable=False, default=0)


def _client_hash(client_ip: str) -> str:
    # Only a keyed hash of the address is stored, never the address itself.
    salt = settings.usage_hash_salt or settings.database_url
    return hashlib.sha256(f"{salt}:{client_ip}".encode()).hexdigest()


def _today():
    return datetime.now(timezone.utc).date()


class FreeQuota:
    def __init__(self, session: AsyncSession, client_ip: str):
        self.session = session
        self.client = _client_hash(client_ip)

    @property
    def enabled(self) -> bool:
        return bool(settings.groq_api_key) and settings.free_llm_scans_per_day > 0

    async def remaining(self) -> int:
        if not self.enabled:
            return 0
        result = await self.session.execute(
            text("SELECT count FROM llm_usage WHERE client_hash = :c AND day = :d"),
            {"c": self.client, "d": _today()},
        )
        used = result.scalar() or 0
        return max(0, settings.free_llm_scans_per_day - used)

    async def claim(self) -> bool:
        """Use one free scan if any are left. Safe against concurrent requests."""
        if not self.enabled:
            return False
        result = await self.session.execute(
            text(
                "INSERT INTO llm_usage (client_hash, day, count) VALUES (:c, :d, 1) "
                "ON CONFLICT (client_hash, day) DO UPDATE "
                "SET count = llm_usage.count + 1 "
                "WHERE llm_usage.count < :limit "
                "RETURNING count"
            ),
            {"c": self.client, "d": _today(), "limit": settings.free_llm_scans_per_day},
        )
        claimed = result.scalar() is not None
        await self.session.commit()
        return claimed

    async def refund(self) -> None:
        await self.session.execute(
            text(
                "UPDATE llm_usage SET count = GREATEST(count - 1, 0) "
                "WHERE client_hash = :c AND day = :d"
            ),
            {"c": self.client, "d": _today()},
        )
        await self.session.commit()
