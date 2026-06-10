import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.database import get_db
from backend.app.schemas.auditor import (
    AuditRequest,
    AuditResult,
    SearchRequest,
    SearchResponse,
    SearchResultItem,
    HealthResponse,
)
from backend.app.services.db_service import DBService
from backend.app.services.storage import StorageService
from backend.app.services.agents import (
    run_full_audit,
    generate_embedding,
    run_security_audit,
)

logger = logging.getLogger("cloudguard.auditor")
router = APIRouter(prefix="/api", tags=["auditor"])


@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    """Check the health of all connected services."""
    db_status = "connected"
    s3_status = "connected"

    try:
        from sqlalchemy import text

        await db.execute(text("SELECT 1"))
    except Exception:
        logger.exception("Health check database failure")
        db_status = "disconnected"

    try:
        storage = StorageService()
        storage.client.head_bucket(Bucket=storage.bucket)
    except Exception:
        logger.exception("Health check S3 failure")
        s3_status = "disconnected"

    return HealthResponse(
        status=(
            "healthy"
            if db_status == "connected" and s3_status == "connected"
            else "degraded"
        ),
        database=db_status,
        s3=s3_status,
    )


@router.post("/audit", response_model=AuditResult)
async def audit_iac(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
):
    """Run the full multi-agent audit pipeline on an IaC configuration."""
    db_service = DBService(db)
    storage = StorageService()

    result = await run_full_audit(
        iac_content=request.iac_content,
        file_name=request.file_name,
        db_service=db_service,
    )

    try:
        original_key = storage.upload_file(
            content=request.iac_content,
            file_name=request.file_name,
            unique_id=result["audit_id"],
        )
        if result.get("patched_code"):
            storage.upload_patched_file(
                original_key=original_key,
                patched_content=result["patched_code"],
            )
    except Exception:
        logger.exception("S3 upload failed in API route")

    return AuditResult(
        audit_id=result["audit_id"],
        file_name=result["file_name"],
        security_score=result["security_score"],
        vulnerabilities=result["vulnerabilities"],
        patched_code=result.get("patched_code", ""),
        similar_past_audits=result.get("similar_past_audits", []),
        diagram_analysis=result.get("diagram_analysis"),
        created_at=datetime.now(timezone.utc),
    )


@router.post("/audit/diagram")
async def audit_with_diagram(
    iac_content: str = Form(...),
    file_name: str = Form(default="main.tf"),
    diagram: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Audit IaC with an architecture diagram for drift detection."""
    allowed_types = {"image/png", "image/jpeg", "image/jpg", "image/webp"}
    if diagram.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid image type: {diagram.content_type}. Allowed: {allowed_types}",
        )

    image_bytes = await diagram.read()
    db_service = DBService(db)

    result = await run_full_audit(
        iac_content=iac_content,
        file_name=file_name,
        db_service=db_service,
        image_bytes=image_bytes,
    )

    return result


async def _get_historical_patches(
    db_service: DBService, vulnerabilities: list[dict]
) -> list[dict]:
    """Retrieve similar historical patches for RAG context."""
    if not vulnerabilities:
        return []
    combined_desc = " | ".join(v.get("description", "") for v in vulnerabilities)
    try:
        query_embedding = await generate_embedding(combined_desc)
        return await db_service.search_similar(query_embedding, limit=3)
    except Exception:
        return []


async def _save_audit_vulnerabilities(
    db_service: DBService,
    audit_id: str,
    file_name: str,
    iac_content: str,
    patched_code: str,
    vulnerabilities: list[dict],
) -> None:
    """Persist all found vulnerabilities to the database."""
    for vuln in vulnerabilities:
        try:
            desc = vuln.get("description", "")
            embedding = await generate_embedding(desc)
            await db_service.save_vulnerability(
                audit_id=audit_id,
                file_name=file_name,
                vulnerability_type=vuln.get("title", "Unknown"),
                severity=vuln.get("severity", "LOW"),
                description=desc,
                resource=vuln.get("resource", ""),
                original_code=iac_content[:2000],
                patched_code=patched_code[:2000],
                embedding=embedding,
            )
        except Exception:
            pass


async def _stream_audit_events(
    iac_content: str,
    file_name: str,
    db: AsyncSession,
):
    """Event generator helper for SSE auditing to keep complexity low."""
    db_service = DBService(db)

    def send_event(step, status, message=None, data=None):
        payload = {"step": step, "status": status}
        if message is not None:
            payload["message"] = message
        if data is not None:
            payload["data"] = data
        return f"data: {json.dumps(payload)}\n\n"

    yield send_event("security_scan", "running", "Scanning configuration...")
    vulnerabilities = await run_security_audit(iac_content)
    yield send_event(
        "security_scan",
        "complete",
        f"Found {len(vulnerabilities)} vulnerabilities",
        vulnerabilities,
    )

    yield send_event("rag_retrieval", "running", "Searching historical patches...")
    similar_patches = await _get_historical_patches(db_service, vulnerabilities)
    yield send_event(
        "rag_retrieval",
        "complete",
        f"Retrieved {len(similar_patches)} similar past patches",
    )

    if vulnerabilities:
        yield send_event("patch_generation", "running", "Generating secure code...")
        from backend.app.services.agents import run_patch_generation

        patched_code = await run_patch_generation(
            iac_content, vulnerabilities, similar_patches
        )
        yield send_event(
            "patch_generation", "complete", "Patched code generated", patched_code
        )
    else:
        patched_code = ""

    from backend.app.services.agents import calculate_security_score

    score = await calculate_security_score(vulnerabilities)
    yield send_event(
        "scoring", "complete", f"Security Score: {score}/100", {"score": score}
    )

    yield send_event("storage", "running", "Storing results...")
    import uuid as _uuid

    audit_id = _uuid.uuid4().hex[:12]
    await _save_audit_vulnerabilities(
        db_service, audit_id, file_name, iac_content, patched_code, vulnerabilities
    )
    yield send_event("storage", "complete", "Results persisted")

    yield send_event(
        "done",
        "complete",
        data={
            "audit_id": audit_id,
            "security_score": score,
            "vulnerabilities": vulnerabilities,
            "patched_code": patched_code,
        },
    )


@router.post("/audit/stream")
async def audit_stream(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
):
    """Stream audit progress via Server-Sent Events."""
    return StreamingResponse(
        _stream_audit_events(request.iac_content, request.file_name, db),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/search", response_model=SearchResponse)
async def search_audits(
    request: SearchRequest,
    db: AsyncSession = Depends(get_db),
):
    """Semantic search over past audit findings using pgvector."""
    db_service = DBService(db)

    query_embedding = await generate_embedding(request.query)
    results = await db_service.search_similar(query_embedding, limit=request.limit)

    return SearchResponse(
        query=request.query,
        results=[
            SearchResultItem(
                audit_id=r["audit_id"],
                file_name=r["file_name"],
                vulnerability_type=r["vulnerability_type"],
                description=r["description"],
                patched_code=r["patched_code"],
                similarity_score=r["similarity_score"],
            )
            for r in results
        ],
        total=len(results),
    )


@router.get("/history")
async def get_history(db: AsyncSession = Depends(get_db)):
    """Retrieve recent audit history."""
    db_service = DBService(db)
    return await db_service.get_audit_history()
