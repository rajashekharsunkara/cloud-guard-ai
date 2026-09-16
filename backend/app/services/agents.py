import base64
import json
import logging
from functools import lru_cache
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq

from backend.app.core.config import settings
from backend.app.services import embeddings

logger = logging.getLogger("cloudguard.agents")

PROMPTS_DIR = Path(__file__).parent.parent / "prompts"

AUDITOR_MODEL = "openai/gpt-oss-120b"
VISION_MODEL = "gemini-2.5-flash"


@lru_cache(maxsize=None)
def _load_prompt(name: str) -> str:
    return (PROMPTS_DIR / name).read_text(encoding="utf-8")


def _strip_code_fence(content: str) -> str:
    content = content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1].rsplit("```", 1)[0]
    return content


class AuditError(RuntimeError):
    """The model's answer couldn't be used, so there is no trustworthy result."""


def _get_groq_llm(json_mode: bool = False) -> ChatGroq:
    extra = {"response_format": {"type": "json_object"}} if json_mode else {}
    return ChatGroq(
        api_key=settings.groq_api_key,
        model=AUDITOR_MODEL,
        temperature=0.1,
        # Reasoning tokens count against this limit, so leave room for them
        # on top of a full rewritten configuration.
        max_tokens=16384,
        reasoning_effort="medium",
        # Groq's rate-limit responses say when to retry; waiting a little is
        # better than dropping the explanation.
        max_retries=3,
        model_kwargs=extra,
    )


def _get_gemini_llm() -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        api_key=settings.gemini_api_key,
        model=VISION_MODEL,
        temperature=0.1,
    )


async def generate_embedding(text: str) -> list[float]:
    return await embeddings.embed_query(text)


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _format_findings(findings: list[dict]) -> str:
    if not findings:
        return "(none: the analyzer doesn't cover this file type or found nothing)"
    return "\n".join(
        f"[{i}] {f['check_id']} ({f['severity']}) {f['resource']}, "
        f"{f['file']} lines {f['line_start']}-{f['line_end']}: {f['title']}"
        for i, f in enumerate(findings, start=1)
    )


def _parse_json_object(content: str) -> dict:
    try:
        parsed = json.loads(_strip_code_fence(content))
    except (json.JSONDecodeError, IndexError) as e:
        logger.error("failed to parse review response: %s", e)
        parsed = None
    if not isinstance(parsed, dict):
        raise AuditError("The review came back unreadable.")
    return parsed


def select_review_files(
    files: dict[str, str], findings: list[dict], budget: int = None
) -> tuple[dict[str, str], list[str]]:
    """Pick files for the review prompt within the size budget.

    Files with the most serious findings go first, then the rest in path
    order. Returns (included files, paths left out).
    """
    budget = settings.llm_review_max_chars if budget is None else budget
    worst = {}
    for f in findings:
        rank = SEVERITY_ORDER.get(f.get("severity"), 4)
        path = f.get("file")
        if path in files:
            worst[path] = min(rank, worst.get(path, 4))
    order = sorted(files, key=lambda p: (worst.get(p, 5), p))

    included, left_out, used = {}, [], 0
    for path in order:
        if used + len(files[path]) > budget:
            left_out.append(path)
            continue
        included[path] = files[path]
        used += len(files[path])
    return included, left_out


def _format_files(files: dict[str, str]) -> str:
    return "\n".join(
        f"File: {path}\n---\n{content}\n---\n" for path, content in files.items()
    )


def _clean_additional(items, paths) -> list[dict]:
    cleaned = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or not item.get("title"):
            continue
        severity = str(item.get("severity", "MEDIUM")).upper()
        file_path = str(item.get("file", ""))
        cleaned.append(
            {
                "source": "review",
                "check_id": None,
                "severity": severity if severity in SEVERITY_ORDER else "MEDIUM",
                "title": str(item["title"]),
                "description": str(item.get("description", "")),
                "remediation": str(item.get("remediation", "")),
                "resource": str(item.get("resource", "")),
                "file": file_path if file_path in paths else "",
            }
        )
    return cleaned


async def review_findings(
    files: dict[str, str], findings: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Explain Checkov findings and look for problems it can't detect.

    ``files`` should already fit the prompt budget (see select_review_files).
    Returns (findings with description/remediation filled in where the model
    explained them, additional findings from the review).
    """
    ranked = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 4))
    to_explain = ranked[: settings.llm_max_explained_findings]

    prompt = _load_prompt("review_findings.txt").format(
        files=_format_files(files),
        findings=_format_findings(to_explain),
    )
    llm = _get_groq_llm(json_mode=True)
    response = await llm.ainvoke(
        [
            SystemMessage(
                content="You are a cloud security engineer. Always respond with valid JSON."
            ),
            HumanMessage(content=prompt),
        ]
    )
    parsed = _parse_json_object(response.content)

    explained = [dict(f) for f in ranked]
    for item in parsed.get("explanations") or []:
        if not isinstance(item, dict):
            continue
        ref = item.get("ref")
        if isinstance(ref, int) and 1 <= ref <= len(to_explain):
            explained[ref - 1]["description"] = str(item.get("description", ""))
            explained[ref - 1]["remediation"] = str(item.get("remediation", ""))

    additional = _clean_additional(parsed.get("additional"), set(files))
    logger.info(
        "review explained %d of %d findings, added %d",
        sum(1 for f in explained if f["description"]),
        len(findings),
        len(additional),
    )
    return explained, additional


async def run_patch_generation(
    iac_content: str,
    vulnerabilities: list[dict],
    similar_patches: list[dict],
    file_name: str = "main.tf",
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
        file_name=file_name,
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


async def run_diagram_analysis(
    iac_content: str, image_bytes: bytes, mime_type: str = "image/png"
) -> str:
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
                        "image_url": {"url": f"data:{mime_type};base64,{image_b64}"},
                    },
                ]
            )
        ]
    )
    return response.content


def _finding_text(finding: dict) -> str:
    return f"{finding.get('title', '')}. {finding.get('description', '')}".strip(". ")


async def find_similar_patches(
    db_service, workspace_id: str, vulnerabilities: list[dict], limit: int = 3
) -> list[dict]:
    """Look up past fixes for similar findings. Failures degrade to no context."""
    if not (db_service and workspace_id and vulnerabilities):
        return []
    combined = " | ".join(_finding_text(v) for v in vulnerabilities)
    try:
        query_embedding = (await embeddings.embed_documents([combined]))[0]
        return await db_service.search_similar(
            query_embedding, workspace_id, limit=limit
        )
    except Exception:
        logger.warning("similar-patch lookup failed", exc_info=True)
        return []


async def index_findings(
    db_service,
    workspace_id: str,
    audit_id: str,
    label: str,
    files: dict[str, str],
    patched_files: dict[str, str],
    findings: list[dict],
) -> None:
    """Embed findings for search and patch examples. Best effort."""
    if not findings:
        return
    try:
        vectors = await embeddings.embed_documents([_finding_text(f) for f in findings])
    except Exception:
        logger.warning("embedding failed for audit %s", audit_id, exc_info=True)
        return

    rows = []
    for f, embedding in zip(findings, vectors):
        path = f.get("file") or ""
        rows.append(
            {
                "audit_id": audit_id,
                "workspace_id": workspace_id,
                "file_name": path or label,
                "vulnerability_type": f.get("title", "Unknown"),
                "severity": f.get("severity", "LOW"),
                "description": f.get("description") or f.get("title", ""),
                "resource": f.get("resource", ""),
                "original_code": files.get(path, "")[:2000],
                "patched_code": patched_files.get(path, "")[:2000],
                "embedding": embedding,
            }
        )
    try:
        await db_service.save_vulnerabilities(rows)
    except Exception:
        logger.warning("failed to index findings for audit %s", audit_id, exc_info=True)
