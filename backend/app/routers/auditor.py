import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger("cloudguard.auditor")

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
    run_diagram_analysis,
)

router = APIRouter(prefix="/api", tags=["auditor"])


@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    """Check the health of all connected services."""
    db_status = "connected"
    s3_status = "connected"

    try:
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
    except Exception as e:
        logger.exception("Health check database failure")
        db_status = "disconnected"

    try:
        storage = StorageService()
        storage.client.head_bucket(Bucket=storage.bucket)
    except Exception as e:
        logger.exception("Health check S3 failure")
        s3_status = "disconnected"

    return HealthResponse(
        status="healthy" if db_status == "connected" and s3_status == "connected" else "degraded",
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
    except Exception as e:
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


@router.post("/audit/stream")
async def audit_stream(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
):
    """Stream audit progress via Server-Sent Events."""

    async def event_generator():
        db_service = DBService(db)

        yield f"data: {json.dumps({'step': 'security_scan', 'status': 'running', 'message': 'Scanning configuration...'})}\n\n"
        vulnerabilities = await run_security_audit(request.iac_content)
        yield f"data: {json.dumps({'step': 'security_scan', 'status': 'complete', 'message': f'Found {len(vulnerabilities)} vulnerabilities', 'data': vulnerabilities})}\n\n"

        similar_patches = []
        if vulnerabilities:
            yield f"data: {json.dumps({'step': 'rag_retrieval', 'status': 'running', 'message': 'Searching historical patches...'})}\n\n"
            combined_desc = " | ".join(v.get("description", "") for v in vulnerabilities)
            try:
                query_embedding = await generate_embedding(combined_desc)
                similar_patches = await db_service.search_similar(query_embedding, limit=3)
            except Exception:
                similar_patches = []
            yield f"data: {json.dumps({'step': 'rag_retrieval', 'status': 'complete', 'message': f'Retrieved {len(similar_patches)} similar past patches'})}\n\n"

        if vulnerabilities:
            yield f"data: {json.dumps({'step': 'patch_generation', 'status': 'running', 'message': 'Generating secure code...'})}\n\n"
            from backend.app.services.agents import run_patch_generation
            patched_code = await run_patch_generation(
                request.iac_content, vulnerabilities, similar_patches
            )
            yield f"data: {json.dumps({'step': 'patch_generation', 'status': 'complete', 'message': 'Patched code generated', 'data': patched_code})}\n\n"
        else:
            patched_code = ""

        from backend.app.services.agents import calculate_security_score
        score = await calculate_security_score(vulnerabilities)
        yield f"data: {json.dumps({'step': 'scoring', 'status': 'complete', 'message': f'Security Score: {score}/100', 'data': {'score': score}})}\n\n"

        yield f"data: {json.dumps({'step': 'storage', 'status': 'running', 'message': 'Storing results...'})}\n\n"
        import uuid as _uuid
        audit_id = _uuid.uuid4().hex[:12]
        for vuln in vulnerabilities:
            try:
                desc = vuln.get("description", "")
                embedding = await generate_embedding(desc)
                await db_service.save_vulnerability(
                    audit_id=audit_id,
                    file_name=request.file_name,
                    vulnerability_type=vuln.get("title", "Unknown"),
                    severity=vuln.get("severity", "LOW"),
                    description=desc,
                    resource=vuln.get("resource", ""),
                    original_code=request.iac_content[:2000],
                    patched_code=patched_code[:2000],
                    embedding=embedding,
                )
            except Exception:
                pass
        yield f"data: {json.dumps({'step': 'storage', 'status': 'complete', 'message': 'Results persisted'})}\n\n"

        yield f"data: {json.dumps({'step': 'done', 'status': 'complete', 'data': {'audit_id': audit_id, 'security_score': score, 'vulnerabilities': vulnerabilities, 'patched_code': patched_code}})}\n\n"

    return StreamingResponse(
        event_generator(),
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
