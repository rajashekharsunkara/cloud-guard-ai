import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("cloudguard.db")

from sqlalchemy import Column, String, Integer, Text, DateTime, select
from sqlalchemy.ext.asyncio import AsyncSession
from pgvector.sqlalchemy import Vector

from backend.app.core.database import Base


class Vulnerability(Base):
    """Audit finding with a vector embedding for similarity search."""

    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, default=lambda: uuid.uuid4().hex)
    audit_id = Column(String, nullable=False, index=True)
    file_name = Column(String, nullable=False)
    vulnerability_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    resource = Column(String, default="")
    original_code = Column(Text, default="")
    patched_code = Column(Text, default="")
    embedding = Column(Vector(768))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))


class DBService:
    """Database read/write operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_vulnerability(
        self,
        audit_id: str,
        file_name: str,
        vulnerability_type: str,
        severity: str,
        description: str,
        resource: str = "",
        original_code: str = "",
        patched_code: str = "",
        embedding: Optional[list[float]] = None,
    ) -> Vulnerability:
        """Save a vulnerability finding with its vector embedding."""
        vuln = Vulnerability(
            audit_id=audit_id,
            file_name=file_name,
            vulnerability_type=vulnerability_type,
            severity=severity,
            description=description,
            resource=resource,
            original_code=original_code,
            patched_code=patched_code,
            embedding=embedding,
        )
        self.session.add(vuln)
        await self.session.commit()
        await self.session.refresh(vuln)
        logger.info(f"saved vulnerability: {vulnerability_type} [{severity}] for audit {audit_id}")
        return vuln

    async def search_similar(
        self, query_embedding: list[float], limit: int = 5
    ) -> list[dict]:
        """Find similar vulnerabilities using pgvector cosine distance."""
        stmt = (
            select(
                Vulnerability,
                Vulnerability.embedding.cosine_distance(query_embedding).label(
                    "distance"
                ),
            )
            .where(Vulnerability.embedding.isnot(None))
            .order_by("distance")
            .limit(limit)
        )

        result = await self.session.execute(stmt)
        rows = result.all()
        logger.info(f"search returned {len(rows)} similar vulnerabilities")

        return [
            {
                "audit_id": row.Vulnerability.audit_id,
                "file_name": row.Vulnerability.file_name,
                "vulnerability_type": row.Vulnerability.vulnerability_type,
                "description": row.Vulnerability.description,
                "patched_code": row.Vulnerability.patched_code,
                "similarity_score": round(1 - row.distance, 4),
            }
            for row in rows
        ]

    async def get_audit_history(self, limit: int = 20) -> list[dict]:
        """Retrieve recent audit records."""
        stmt = (
            select(Vulnerability)
            .order_by(Vulnerability.created_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        vulns = result.scalars().all()

        return [
            {
                "audit_id": v.audit_id,
                "file_name": v.file_name,
                "vulnerability_type": v.vulnerability_type,
                "severity": v.severity,
                "description": v.description,
                "created_at": v.created_at.isoformat() if v.created_at else None,
            }
            for v in vulns
        ]
