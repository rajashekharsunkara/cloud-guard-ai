import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.app.core.aws import ensure_bucket_exists
from backend.app.core.config import settings
from backend.app.core.database import init_db
from backend.app.routers.auditor import router as auditor_router

logging.basicConfig(
    level=logging.DEBUG if settings.app_env == "development" else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("cloudguard")

FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting up (env=%s)", settings.app_env)

    try:
        await init_db()
        logger.info("database ready")
    except Exception as e:
        logger.error("database init failed: %s", e)

    try:
        ensure_bucket_exists()
        logger.info("s3 bucket ready")
    except Exception as e:
        logger.warning("s3 setup issue: %s", e)

    yield

    logger.info("shutting down")


app = FastAPI(
    title="CloudGuard",
    description=(
        "Scans Terraform and Docker Compose configurations for security "
        "issues, generates patched versions, and checks architecture "
        "diagrams against the code they describe."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

allowed_origins = settings.cors_origin_list
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    # Credentialed requests cannot be combined with a wildcard origin.
    allow_credentials="*" not in allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(auditor_router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled error on %s %s", request.method, request.url.path)
    detail = {"detail": "Internal Server Error"}
    if settings.app_env == "development":
        detail["message"] = str(exc)
    return JSONResponse(status_code=500, content=detail)


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/", include_in_schema=False)
async def serve_frontend():
    return FileResponse(FRONTEND_DIR / "index.html")
