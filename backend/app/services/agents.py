import json
import logging
import uuid
import base64
from pathlib import Path
from typing import Optional

from langchain_groq import ChatGroq
from langchain_google_genai import ChatGoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain_core.messages import HumanMessage, SystemMessage

from backend.app.core.config import settings

logger = logging.getLogger("cloudguard.agents")

PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


def _load_prompt(name: str) -> str:
    return (PROMPTS_DIR / name).read_text(encoding="utf-8")


def _get_groq_llm() -> ChatGroq:
    return ChatGroq(
        api_key=settings.groq_api_key,
        model_name="llama-3.3-70b-versatile",
        temperature=0.1,
        max_tokens=4096,
    )


def _get_gemini_llm() -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        api_key=settings.gemini_api_key,
        model="gemini-2.5-flash-preview-05-20",
        temperature=0.1,
    )


def _get_embedding_model() -> GoogleGenerativeAIEmbeddings:
    return GoogleGenerativeAIEmbeddings(
        google_api_key=settings.gemini_api_key,
        model="models/gemini-embedding-2",
        output_dimensionality=768,
    )


async def generate_embedding(text: str) -> list[float]:
    """Generate a 768-dim vector embedding for the given text."""
    model = _get_embedding_model()
    embedding = await model.aembed_query(text)
    return embedding


async def run_security_audit(iac_content: str) -> list[dict]:
    """Scan IaC configuration for vulnerabilities using Groq."""
    logger.info("scanning IaC configuration (%d chars)", len(iac_content))
    llm = _get_groq_llm()
    prompt_template = _load_prompt("security_rules.txt")
    prompt = prompt_template.format(iac_content=iac_content)

    response = await llm.ainvoke(
        [
            SystemMessage(
                content="You are a cloud security expert. Always respond with valid JSON."
            ),
            HumanMessage(content=prompt),
        ]
    )

    try:
        content = response.content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1].rsplit("```", 1)[0]
        vulnerabilities = json.loads(content)
        logger.info(
            "found %d vulnerabilities",
            len(vulnerabilities) if isinstance(vulnerabilities, list) else 0,
        )
        return vulnerabilities if isinstance(vulnerabilities, list) else []
    except (json.JSONDecodeError, IndexError) as e:
        logger.error("failed to parse auditor response: %s", e)
        return []


async def run_patch_generation(
    iac_content: str,
    vulnerabilities: list[dict],
    similar_patches: list[dict],
) -> str:
    """Generate remediated IaC code using historical patches as RAG context."""
    logger.info("generating patched code with %d RAG patches", len(similar_patches))
    llm = _get_groq_llm()
    prompt_template = _load_prompt("patch_generator.txt")

    patches_context = "No historical data available."
    if similar_patches:
        patches_context = "\n\n".join(
            f"--- Past Fix (similarity: {p.get('similarity_score', 'N/A')}) ---\n"
            f"Issue: {p.get('description', 'N/A')}\n"
            f"Patch:\n{p.get('patched_code', 'N/A')}"
            for p in similar_patches
        )

    prompt = prompt_template.format(
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

    content = response.content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1].rsplit("```", 1)[0]
    return content


async def run_diagram_analysis(iac_content: str, image_bytes: bytes) -> str:
    """Compare architecture diagram against IaC code using Gemini vision."""
    llm = _get_gemini_llm()
    prompt_template = _load_prompt("vision_audit.txt")
    prompt_text = prompt_template.format(iac_content=iac_content)

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


async def calculate_security_score(vulnerabilities: list[dict]) -> int:
    """Score from 100 down: CRITICAL=-25, HIGH=-15, MEDIUM=-8, LOW=-3."""
    score = 100
    severity_penalties = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
    }
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "LOW").upper()
        score -= severity_penalties.get(severity, 3)
    return max(0, score)


async def run_full_audit(
    iac_content: str,
    file_name: str,
    db_service=None,
    image_bytes: Optional[bytes] = None,
) -> dict:
    """Run the complete multi-agent audit pipeline."""
    audit_id = uuid.uuid4().hex[:12]
    logger.info("starting audit %s for %s", audit_id, file_name)

    vulnerabilities = await run_security_audit(iac_content)
    security_score = await calculate_security_score(vulnerabilities)

    similar_patches = []
    if db_service and vulnerabilities:
        combined_desc = " | ".join(v.get("description", "") for v in vulnerabilities)
        query_embedding = await generate_embedding(combined_desc)
        similar_patches = await db_service.search_similar(query_embedding, limit=3)

    patched_code = ""
    if vulnerabilities:
        patched_code = await run_patch_generation(
            iac_content, vulnerabilities, similar_patches
        )

    diagram_analysis = None
    if image_bytes:
        diagram_analysis = await run_diagram_analysis(iac_content, image_bytes)

    if db_service:
        for vuln in vulnerabilities:
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

    return {
        "audit_id": audit_id,
        "file_name": file_name,
        "security_score": security_score,
        "vulnerabilities": vulnerabilities,
        "patched_code": patched_code,
        "similar_past_audits": [p.get("description", "") for p in similar_patches],
        "diagram_analysis": diagram_analysis,
    }
