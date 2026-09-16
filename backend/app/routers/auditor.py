import asyncio
import json
import logging

from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.core.ratelimit import (
    client_ip,
    scan_rate_limit,
    scan_slots,
    search_rate_limit,
)
from backend.app.core.workspace import get_workspace_id
from backend.app.schemas.auditor import (
    AuditDetail,
    AuditRequest,
    AuditResult,
    AuditSummary,
    HealthResponse,
    ModelListRequest,
    ModelListResponse,
    ProviderInfo,
    RepoRequest,
    SearchRequest,
    SearchResponse,
    SearchResultItem,
    UsageResponse,
)
from backend.app.services import llm
from backend.app.services.agents import generate_embedding
from backend.app.services.db_service import DBService
from backend.app.services.pipeline import (
    Scan,
    ScanFailed,
    ScanInput,
    event,
    run_to_completion,
)
from backend.app.services.sources import (
    MAX_ARCHIVE_BYTES,
    SourceError,
    download_repo,
    load_tarball,
    load_zip,
    parse_github_url,
)
from backend.app.services.storage import StorageService
from backend.app.services.usage import FreeQuota

logger = logging.getLogger("cloudguard.auditor")
router = APIRouter(prefix="/api", tags=["auditor"])

ALLOWED_DIAGRAM_TYPES = {"image/png", "image/jpeg", "image/webp"}


def get_quota(request: Request, db: AsyncSession = Depends(get_db)) -> FreeQuota:
    return FreeQuota(db, client_ip(request))


def get_own_choice(
    x_llm_provider: Optional[str] = Header(default=None),
    x_llm_model: Optional[str] = Header(default=None),
    x_llm_key: Optional[str] = Header(default=None),
) -> Optional[llm.LlmChoice]:
    """The visitor's own provider, model and key, when they sent one.

    Sent as headers on each request and used only for that request.
    """
    if not (x_llm_provider or x_llm_model or x_llm_key):
        return None
    try:
        return llm.validate_choice(
            x_llm_provider or "", x_llm_model or "", x_llm_key or ""
        )
    except llm.LlmError as e:
        raise HTTPException(status_code=400, detail=e.message)


@router.get("/llm/providers", response_model=list[ProviderInfo])
async def providers():
    """Providers a visitor can use with their own API key."""
    return [
        ProviderInfo(id=p.id, label=p.label, key_url=p.key_url)
        for p in llm.PROVIDERS.values()
    ]


@router.post(
    "/llm/models",
    response_model=ModelListResponse,
    dependencies=[Depends(search_rate_limit)],
)
async def list_models(
    request: ModelListRequest, x_llm_key: str = Header(..., max_length=400)
):
    """Check a key and list the chat models it can use. The key isn't stored."""
    try:
        return await llm.list_models(request.provider, x_llm_key)
    except llm.LlmError as e:
        status = 400 if e.kind in ("auth", "bad_request") else 502
        raise HTTPException(status_code=status, detail=e.message)


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


@router.get("/usage", response_model=UsageResponse)
async def usage(quota: FreeQuota = Depends(get_quota)):
    """Free explained scans left for this client today."""
    return UsageResponse(
        explanations_available=quota.enabled,
        free_scans_per_day=settings.free_llm_scans_per_day,
        free_scans_left=await quota.remaining(),
    )


async def _run_scan(scan: Scan) -> dict:
    async with scan_slots.acquire():
        try:
            return await run_to_completion(scan)
        except ScanFailed as e:
            raise HTTPException(status_code=502, detail=str(e))


@router.post(
    "/audit", response_model=AuditResult, dependencies=[Depends(scan_rate_limit)]
)
async def audit_iac(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
    quota: FreeQuota = Depends(get_quota),
    workspace_id: str = Depends(get_workspace_id),
    own_choice: Optional[llm.LlmChoice] = Depends(get_own_choice),
):
    """Run Checkov on a configuration, then explain and patch it when allowed."""
    scan = Scan(
        ScanInput.single(request.iac_content, request.file_name),
        DBService(db),
        quota,
        workspace_id,
        own_choice,
    )
    return await _run_scan(scan)


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
    quota: FreeQuota = Depends(get_quota),
    workspace_id: str = Depends(get_workspace_id),
    own_choice: Optional[llm.LlmChoice] = Depends(get_own_choice),
):
    """Scan the configuration and compare it with an architecture diagram."""
    if diagram.content_type not in ALLOWED_DIAGRAM_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported image type {diagram.content_type!r}; "
            "use PNG, JPEG, or WebP",
        )
    if len(iac_content) > settings.max_iac_chars:
        raise HTTPException(status_code=413, detail="Configuration too large")
    if own_choice is None:
        raise HTTPException(
            status_code=400,
            detail="Diagram checks use your own API key with a model that can read "
            "images. Add one in Model settings.",
        )

    image_bytes = await diagram.read()
    if len(image_bytes) > settings.max_diagram_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Diagram exceeds {settings.max_diagram_bytes // (1024 * 1024)} MB limit",
        )

    scan = Scan(
        ScanInput.single(
            iac_content,
            file_name,
            image_bytes=image_bytes,
            image_type=diagram.content_type,
        ),
        DBService(db),
        quota,
        workspace_id,
        own_choice,
    )
    return await _run_scan(scan)


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


def _stream_response(events) -> StreamingResponse:
    return StreamingResponse(
        events,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _stream_scan(scan: Scan, fetch=None):
    """Stream a scan. ``fetch`` optionally loads the files first, inside the slot."""
    try:
        async with scan_slots.acquire():
            if fetch is not None:
                yield _sse(event("fetch", "running", "Downloading repository..."))
                source = await fetch()
                scan.input.files = source.files
                scan.input.label = source.label
                yield _sse(event("fetch", "complete", f"{len(source.files)} files"))
            async for item in scan.run():
                yield _sse(item)
    except SourceError as e:
        yield _sse({"step": "error", "status": "error", "message": str(e)})
    except HTTPException as e:
        yield _sse({"step": "error", "status": "error", "message": e.detail})
    except ScanFailed as e:
        yield _sse({"step": "error", "status": "error", "message": str(e)})
    except Exception:
        logger.exception("streaming scan failed")
        yield _sse(
            {
                "step": "error",
                "status": "error",
                "message": "The scan failed. Please try again.",
            }
        )


@router.post("/audit/stream", dependencies=[Depends(scan_rate_limit)])
async def audit_stream(
    request: AuditRequest,
    db: AsyncSession = Depends(get_db),
    quota: FreeQuota = Depends(get_quota),
    workspace_id: str = Depends(get_workspace_id),
    own_choice: Optional[llm.LlmChoice] = Depends(get_own_choice),
):
    """Same as /audit, streamed as Server-Sent Events while each step runs."""
    scan = Scan(
        ScanInput.single(request.iac_content, request.file_name),
        DBService(db),
        quota,
        workspace_id,
        own_choice,
    )
    return _stream_response(_stream_scan(scan))


@router.post("/audit/archive", dependencies=[Depends(scan_rate_limit)])
async def audit_archive(
    archive: UploadFile = File(..., description="Zip of the infrastructure code"),
    db: AsyncSession = Depends(get_db),
    quota: FreeQuota = Depends(get_quota),
    workspace_id: str = Depends(get_workspace_id),
    own_choice: Optional[llm.LlmChoice] = Depends(get_own_choice),
):
    """Scan every configuration file in a zip. Streamed as Server-Sent Events."""
    data = await archive.read(MAX_ARCHIVE_BYTES + 1)
    label = (archive.filename or "upload.zip")[:255]
    try:
        source = load_zip(data, label)
    except SourceError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan = Scan(
        ScanInput(files=source.files, label=source.label, source="zip"),
        DBService(db),
        quota,
        workspace_id,
        own_choice,
    )
    return _stream_response(_stream_scan(scan))


@router.post("/audit/repo", dependencies=[Depends(scan_rate_limit)])
async def audit_repo(
    request: RepoRequest,
    db: AsyncSession = Depends(get_db),
    quota: FreeQuota = Depends(get_quota),
    workspace_id: str = Depends(get_workspace_id),
    own_choice: Optional[llm.LlmChoice] = Depends(get_own_choice),
):
    """Scan a public GitHub repository or folder. Streamed as Server-Sent Events."""
    try:
        repo = parse_github_url(request.url)
    except SourceError as e:
        raise HTTPException(status_code=400, detail=str(e))

    async def fetch():
        data = await download_repo(repo)
        return await asyncio.to_thread(load_tarball, data, repo)

    scan = Scan(
        ScanInput(files={}, label=repo.label, source="github"),
        DBService(db),
        quota,
        workspace_id,
        own_choice,
    )
    return _stream_response(_stream_scan(scan, fetch=fetch))


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
