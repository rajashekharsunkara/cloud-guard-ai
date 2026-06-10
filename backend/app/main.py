import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from backend.app.core.config import settings
from backend.app.core.database import init_db
from backend.app.core.aws import ensure_bucket_exists
from backend.app.routers.auditor import router as auditor_router

logging.basicConfig(
    level=logging.DEBUG if settings.app_env == "development" else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("cloudguard")


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

    logger.info("ready, docs at http://localhost:%d/docs", settings.app_port)

    yield

    logger.info("shutting down")


app = FastAPI(
    title="CloudGuard AI",
    description=(
        "AI-powered IaC Threat Modeler & Remediation Engine. "
        "Scans Terraform and Docker Compose configurations for "
        "security vulnerabilities using multi-agent LLM analysis, "
        "RAG-based historical patching, and multimodal diagram validation."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auditor_router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception occurred during request:")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "message": str(exc)},
    )

app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/")
async def serve_frontend():
    return FileResponse("frontend/index.html")
