import logging
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from pgvector.sqlalchemy import Vector
from sqlalchemy import Column, DateTime, Integer, String, Text, delete, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import Base

logger = logging.getLogger("cloudguard.db")


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Audit(Base):
    __tablename__ = "audits"

    id = Column(String, primary_key=True)
    workspace_id = Column(String, nullable=False, index=True)
    file_name = Column(String, nullable=False)
    security_score = Column(Integer, nullable=False)
    findings = Column(JSONB, nullable=False, default=list)
    original_code = Column(Text, default="")
    patched_code = Column(Text, default="")
    diagram_analysis = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_utcnow, index=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, default=lambda: uuid.uuid4().hex)
    # Nullable because rows written before workspaces existed have none;
    # those rows are never returned to anyone.
    workspace_id = Column(String, index=True)
    audit_id = Column(String, nullable=False, index=True)
    file_name = Column(String, nullable=False)
    vulnerability_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    resource = Column(String, default="")
    original_code = Column(Text, default="")
    patched_code = Column(Text, default="")
    embedding = Column(Vector(768))
    created_at = Column(DateTime, default=_utcnow)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


class DBService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_audit(
        self,
        audit_id: str,
        workspace_id: str,
        file_name: str,
        security_score: int,
        findings: list[dict],
        original_code: str = "",
        patched_code: str = "",
        diagram_analysis: Optional[str] = None,
    ) -> Audit:
        audit = Audit(
            id=audit_id,
            workspace_id=workspace_id,
            file_name=file_name,
            security_score=security_score,
            findings=findings,
            original_code=original_code,
            patched_code=patched_code,
            diagram_analysis=diagram_analysis,
        )
        self.session.add(audit)
        await self.session.commit()
        return audit

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
        workspace_id: Optional[str] = None,
    ) -> Vulnerability:
        vuln = Vulnerability(
            workspace_id=workspace_id,
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
        logger.info(
            "saved vulnerability: %s [%s] for audit %s",
            vulnerability_type,
            severity,
            audit_id,
        )
        return vuln

    async def search_similar(
        self, query_embedding: list[float], workspace_id: str, limit: int = 5
    ) -> list[dict]:
        distance = Vulnerability.embedding.cosine_distance(query_embedding)
        stmt = (
            select(Vulnerability, distance.label("distance"))
            .where(Vulnerability.workspace_id == workspace_id)
            .where(Vulnerability.embedding.isnot(None))
            .order_by("distance")
            .limit(limit)
        )

        result = await self.session.execute(stmt)
        rows = result.all()
        logger.info("search returned %d similar vulnerabilities", len(rows))

        return [
            {
                "audit_id": row.Vulnerability.audit_id,
                "file_name": row.Vulnerability.file_name,
                "vulnerability_type": row.Vulnerability.vulnerability_type,
                "severity": row.Vulnerability.severity,
                "description": row.Vulnerability.description,
                "patched_code": row.Vulnerability.patched_code,
                "similarity_score": round(1 - row.distance, 4),
            }
            for row in rows
        ]

    async def list_audits(self, workspace_id: str, limit: int = 50) -> list[dict]:
        stmt = (
            select(Audit)
            .where(Audit.workspace_id == workspace_id)
            .order_by(Audit.created_at.desc())
            .limit(limit)
        )
        audits = (await self.session.execute(stmt)).scalars().all()

        summaries = []
        for audit in audits:
            counts = Counter(
                str(f.get("severity", "LOW")).upper() for f in audit.findings
            )
            summaries.append(
                {
                    "audit_id": audit.id,
                    "file_name": audit.file_name,
                    "security_score": audit.security_score,
                    "finding_count": len(audit.findings),
                    "severity_counts": dict(counts),
                    "has_diagram": audit.diagram_analysis is not None,
                    "created_at": _iso(audit.created_at),
                }
            )
        return summaries

    async def get_audit(self, workspace_id: str, audit_id: str) -> Optional[dict]:
        stmt = select(Audit).where(
            Audit.id == audit_id, Audit.workspace_id == workspace_id
        )
        audit = (await self.session.execute(stmt)).scalar_one_or_none()
        if audit is None:
            return None
        return {
            "audit_id": audit.id,
            "file_name": audit.file_name,
            "security_score": audit.security_score,
            "vulnerabilities": audit.findings,
            "original_code": audit.original_code,
            "patched_code": audit.patched_code,
            "diagram_analysis": audit.diagram_analysis,
            "created_at": audit.created_at,
        }

    async def clear_workspace(self, workspace_id: str) -> None:
        await self.session.execute(
            delete(Vulnerability).where(Vulnerability.workspace_id == workspace_id)
        )
        await self.session.execute(
            delete(Audit).where(Audit.workspace_id == workspace_id)
        )
        await self.session.commit()
