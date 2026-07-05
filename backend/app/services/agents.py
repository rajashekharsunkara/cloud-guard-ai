import base64
import json
import logging
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_groq import ChatGroq

from backend.app.core.config import settings

logger = logging.getLogger("cloudguard.agents")

PROMPTS_DIR = Path(__file__).parent.parent / "prompts"

AUDITOR_MODEL = "llama-3.3-70b-versatile"
VISION_MODEL = "gemini-2.5-flash"
EMBEDDING_MODEL = "models/gemini-embedding-2"
EMBEDDING_DIM = 768


@lru_cache(maxsize=None)
def _load_prompt(name: str) -> str:
    return (PROMPTS_DIR / name).read_text(encoding="utf-8")


def _strip_code_fence(content: str) -> str:
    content = content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1].rsplit("```", 1)[0]
    return content


def _get_groq_llm() -> ChatGroq:
    return ChatGroq(
        api_key=settings.groq_api_key,
        model=AUDITOR_MODEL,
        temperature=0.1,
        max_tokens=4096,
    )


def _get_gemini_llm() -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        api_key=settings.gemini_api_key,
        model=VISION_MODEL,
        temperature=0.1,
    )


def _get_embedding_model() -> GoogleGenerativeAIEmbeddings:
    return GoogleGenerativeAIEmbeddings(
        google_api_key=settings.gemini_api_key,
        model=EMBEDDING_MODEL,
        output_dimensionality=EMBEDDING_DIM,
    )


async def generate_embedding(text: str) -> list[float]:
    model = _get_embedding_model()
    return await model.aembed_query(text)


async def run_security_audit(iac_content: str) -> list[dict]:
    logger.info("scanning IaC configuration (%d chars)", len(iac_content))
    llm = _get_groq_llm()
    prompt = _load_prompt("security_rules.txt").format(iac_content=iac_content)

    response = await llm.ainvoke(
        [
            SystemMessage(
                content="You are a cloud security expert. Always respond with valid JSON."
            ),
            HumanMessage(content=prompt),
        ]
    )

    try:
        vulnerabilities = json.loads(_strip_code_fence(response.content))
        if not isinstance(vulnerabilities, list):
            return []
        logger.info("found %d vulnerabilities", len(vulnerabilities))
        return vulnerabilities
    except (json.JSONDecodeError, IndexError) as e:
        logger.error("failed to parse auditor response: %s", e)
        return []


async def run_patch_generation(
    iac_content: str,
    vulnerabilities: list[dict],
    similar_patches: list[dict],
) -> str:
    logger.info("generating patched code with %d RAG patches", len(similar_patches))
    llm = _get_groq_llm()

    patches_context = "No historical data available."
    if similar_patches:
        patches_context = "\n\n".join(
            f"--- Past Fix (similarity: {p.get('similarity_score', 'N/A')}) ---\n"
            f"Issue: {p.get('description', 'N/A')}\n"
            f"Patch:\n{p.get('patched_code', 'N/A')}"
            for p in similar_patches
        )

    prompt = _load_prompt("patch_generator.txt").format(
        iac_content=iac_content,
        vulnerabilities=json.dumps(vulnerabilities, indent=2),
        similar_patches=patches_context,
    )

    response = await llm.ainvoke(
        [
            SystemMessage(
                content="You are an IaC security engineer. Output only valid code."
            ),
            HumanMessage(content=prompt),
        ]
    )
    return _strip_code_fence(response.content)


async def run_diagram_analysis(iac_content: str, image_bytes: bytes) -> str:
    llm = _get_gemini_llm()
    prompt_text = _load_prompt("vision_audit.txt").format(iac_content=iac_content)
    image_b64 = base64.b64encode(image_bytes).decode("utf-8")

    response = await llm.ainvoke(
        [
            HumanMessage(
                content=[
                    {"type": "text", "text": prompt_text},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/png;base64,{image_b64}"},
                    },
                ]
            )
        ]
    )
    return response.content


def calculate_security_score(vulnerabilities: list[dict]) -> int:
    """Score from 100 down: CRITICAL=-25, HIGH=-15, MEDIUM=-8, LOW=-3."""
    penalties = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 100
    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "LOW")).upper()
        score -= penalties.get(severity, 3)
    return max(0, score)


async def find_similar_patches(
    db_service, vulnerabilities: list[dict], limit: int = 3
) -> list[dict]:
    """Look up past fixes for similar findings. Failures degrade to no context."""
    if not (db_service and vulnerabilities):
        return []
    combined = " | ".join(v.get("description", "") for v in vulnerabilities)
    try:
        query_embedding = await generate_embedding(combined)
        return await db_service.search_similar(query_embedding, limit=limit)
    except Exception:
        logger.warning("similar-patch lookup failed", exc_info=True)
        return []


async def persist_findings(
    db_service,
    audit_id: str,
    file_name: str,
    iac_content: str,
    patched_code: str,
    vulnerabilities: list[dict],
) -> None:
    """Embed and store each finding; one bad row shouldn't sink the rest."""
    for vuln in vulnerabilities:
        try:
            description = vuln.get("description", "")
            embedding = await generate_embedding(description)
            await db_service.save_vulnerability(
                audit_id=audit_id,
                file_name=file_name,
                vulnerability_type=vuln.get("title", "Unknown"),
                severity=vuln.get("severity", "LOW"),
                description=description,
                resource=vuln.get("resource", ""),
                original_code=iac_content[:2000],
                patched_code=patched_code[:2000],
                embedding=embedding,
            )
        except Exception:
            logger.warning(
                "failed to save finding for audit %s", audit_id, exc_info=True
            )


async def run_full_audit(
    iac_content: str,
    file_name: str,
    db_service=None,
    image_bytes: Optional[bytes] = None,
) -> dict:
    audit_id = uuid.uuid4().hex[:12]
    logger.info("starting audit %s for %s", audit_id, file_name)

    vulnerabilities = await run_security_audit(iac_content)
    security_score = calculate_security_score(vulnerabilities)

    similar_patches = await find_similar_patches(db_service, vulnerabilities)

    patched_code = ""
    if vulnerabilities:
        patched_code = await run_patch_generation(
            iac_content, vulnerabilities, similar_patches
        )

    diagram_analysis = None
    if image_bytes:
        diagram_analysis = await run_diagram_analysis(iac_content, image_bytes)

    if db_service:
        await persist_findings(
            db_service, audit_id, file_name, iac_content, patched_code, vulnerabilities
        )

    return {
        "audit_id": audit_id,
        "file_name": file_name,
        "security_score": security_score,
        "vulnerabilities": vulnerabilities,
        "patched_code": patched_code,
        "similar_past_audits": [p.get("description", "") for p in similar_patches],
        "diagram_analysis": diagram_analysis,
    }
