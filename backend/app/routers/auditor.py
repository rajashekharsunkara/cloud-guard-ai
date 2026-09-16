import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.ratelimit import scan_rate_limit, scan_slots, search_rate_limit
from backend.app.core.workspace import get_workspace_id
from backend.app.schemas.auditor import (
    AuditDetail,
    AuditRequest,
    AuditResult,
    AuditSummary,
    HealthResponse,
    SearchRequest,
    SearchResponse,
    SearchResultItem,
)
from backend.app.services.agents import (
    AuditError,
    calculate_security_score,
    find_similar_patches,
    generate_embedding,
    persist_audit,
    run_full_audit,
    run_patch_generation,
    run_security_audit,
)
from backend.app.services.db_service import DBService
from backend.app.services.storage import StorageService

logger = logging.getLogger("cloudguard.auditor")
router = APIRouter(prefix="/api", tags=["auditor"])

ALLOWED_DIAGRAM_TYPES = {"image/png", "image/jpeg", "image/webp"}


def _upload_audit_artifacts(iac_content: str, file_name: str, result: dict) -> None:
    """Store the original and patched configs in S3. Best effort."""
    try:
        storage = StorageService()
        original_key = storage.upload_file(
            content=iac_content,
            file_name=file_name,
            unique_id=result["audit_id"],
        )
        if result.get("patched_code"):
            storage.upload_patched_file(
                original_key=original_key,
                patched_content=result["patched_code"],
            )
    except Exception:
        logger.exception("S3 upload failed for audit %s", result.get("audit_id"))


@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    """Check the health of all connected services."""
    db_status = "connected"
    s3_status = "connected"

    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        logger.exception("health check: database unreachable")
        db_status = "disconnected"

    try:
        storage = StorageService()
        await asyncio.to_thread(storage.client.head_bucket, Bucket=storage.bucket)
    except Exception:
        logger.exception("health check: s3 unreachable")
        s3_status = "disconnected"

    return HealthResponse(
        status=(
            "healthy"
            if db_status == "connected" and s3_status == "connected"
            else "degraded"
        ),
        database=db_status,
        s3=s3_status,
        environment=settings.app_env,
    )


@router.post(
    "/audit", response_model=AuditResult, dependencies=[Depends(scan_rate_limit)]
)
async def audit_iac(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
):
    """Run the full audit pipeline on an IaC configuration."""
    async with scan_slots.acquire():
        result = await run_full_audit(
            iac_content=request.iac_content,
            file_name=request.file_name,
            db_service=DBService(db),
            workspace_id=workspace_id,
        )

    await asyncio.to_thread(
        _upload_audit_artifacts, request.iac_content, request.file_name, result
    )

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


@router.post(
    "/audit/diagram",
    response_model=AuditResult,
    dependencies=[Depends(scan_rate_limit)],
)
async def audit_with_diagram(
    iac_content: str = Form(...),
    file_name: str = Form(default="main.tf", max_length=255),
    diagram: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
):
    """Audit IaC with an architecture diagram for drift detection."""
    if diagram.content_type not in ALLOWED_DIAGRAM_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported image type {diagram.content_type!r}; "
            "use PNG, JPEG, or WebP",
        )
    if len(iac_content) > settings.max_iac_chars:
        raise HTTPException(status_code=413, detail="Configuration too large")

    image_bytes = await diagram.read()
    if len(image_bytes) > settings.max_diagram_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Diagram exceeds {settings.max_diagram_bytes // (1024 * 1024)} MB limit",
        )

    async with scan_slots.acquire():
        result = await run_full_audit(
            iac_content=iac_content,
            file_name=file_name,
            db_service=DBService(db),
            workspace_id=workspace_id,
            image_bytes=image_bytes,
            image_type=diagram.content_type,
        )
    return AuditResult(**result)


async def _stream_audit_events(
    iac_content: str,
    file_name: str,
    db: AsyncSession,
    workspace_id: str,
):
    db_service = DBService(db)

    def send_event(step, status, message=None, data=None):
        payload = {"step": step, "status": status}
        if message is not None:
            payload["message"] = message
        if data is not None:
            payload["data"] = data
        return f"data: {json.dumps(payload)}\n\n"

    try:
        async with scan_slots.acquire():
            yield send_event("security_scan", "running", "Reviewing configuration...")
            vulnerabilities = await run_security_audit(iac_content)
            yield send_event(
                "security_scan",
                "complete",
                f"{len(vulnerabilities)} findings",
                vulnerabilities,
            )

            yield send_event(
                "rag_retrieval", "running", "Checking your earlier fixes..."
            )
            similar_patches = await find_similar_patches(
                db_service, workspace_id, vulnerabilities
            )
            yield send_event(
                "rag_retrieval",
                "complete",
                f"{len(similar_patches)} related fixes from earlier scans",
            )

            patched_code = ""
            if vulnerabilities:
                yield send_event("patch_generation", "running", "Writing a patch...")
                patched_code = await run_patch_generation(
                    iac_content, vulnerabilities, similar_patches
                )
                yield send_event(
                    "patch_generation", "complete", "Patch written", patched_code
                )

            score = calculate_security_score(vulnerabilities)
            yield send_event(
                "scoring", "complete", f"Security Score: {score}/100", {"score": score}
            )

            yield send_event("storage", "running", "Saving to your history...")
            result = {
                "audit_id": uuid.uuid4().hex[:12],
                "file_name": file_name,
                "security_score": score,
                "vulnerabilities": vulnerabilities,
                "patched_code": patched_code,
                "similar_past_audits": [
                    p.get("description", "") for p in similar_patches
                ],
            }
            await persist_audit(db_service, workspace_id, result, iac_content)
            await asyncio.to_thread(
                _upload_audit_artifacts, iac_content, file_name, result
            )
            yield send_event("storage", "complete", "Saved")

            yield send_event("done", "complete", data=result)
    except HTTPException as e:
        yield send_event("error", "error", e.detail)
    except AuditError as e:
        yield send_event("error", "error", str(e))
    except Exception:
        logger.exception("streaming audit failed")
        yield send_event("error", "error", "The scan failed. Please try again.")


@router.post("/audit/stream", dependencies=[Depends(scan_rate_limit)])
async def audit_stream(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
):
    """Stream audit progress via Server-Sent Events."""
    return StreamingResponse(
        _stream_audit_events(request.iac_content, request.file_name, db, workspace_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post(
    "/search", response_model=SearchResponse, dependencies=[Depends(search_rate_limit)]
)
async def search_audits(
    request: SearchRequest,
    db: AsyncSession = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
):
    """Semantic search over this workspace's past findings."""
    query_embedding = await generate_embedding(request.query)
    results = await DBService(db).search_similar(
        query_embedding, workspace_id, limit=request.limit
    )

    return SearchResponse(
        query=request.query,
        results=[SearchResultItem(**r) for r in results],
        total=len(results),
    )


@router.get("/history", response_model=list[AuditSummary])
async def get_history(
    db: AsyncSession = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
):
    """Scans made from this browser, newest first."""
    return await DBService(db).list_audits(workspace_id)


@router.get("/history/{audit_id}", response_model=AuditDetail)
async def get_history_item(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
):
    audit = await DBService(db).get_audit(workspace_id, audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return audit


@router.delete("/history", status_code=204)
async def clear_history(
    db: AsyncSession = Depends(get_db),
    workspace_id: str = Depends(get_workspace_id),
):
    """Delete every scan and finding stored for this browser."""
    await DBService(db).clear_workspace(workspace_id)
    return Response(status_code=204)
