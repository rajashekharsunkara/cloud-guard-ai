import json
import logging
from functools import lru_cache
from pathlib import Path

from backend.app.services import embeddings, llm
from backend.app.services.llm import LlmChoice

logger = logging.getLogger("cloudguard.agents")

PROMPTS_DIR = Path(__file__).parent.parent / "prompts"

REVIEW_SYSTEM = "You are a cloud security engineer. Always respond with valid JSON."
PATCH_SYSTEM = (
    "You are an infrastructure-as-code security engineer. Output only the file."
)
DIAGRAM_SYSTEM = "You are a cloud architecture reviewer."

# Also sent to providers that support schema-constrained output (Anthropic);
# others get JSON mode and the same shape described in the prompt.
REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "explanations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "ref": {"type": "integer"},
                    "description": {"type": "string"},
                    "remediation": {"type": "string"},
                },
                "required": ["ref", "description", "remediation"],
                "additionalProperties": False,
            },
        },
        "additional": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    },
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "resource": {"type": "string"},
                    "file": {"type": "string"},
                    "remediation": {"type": "string"},
                },
                "required": [
                    "severity",
                    "title",
                    "description",
                    "resource",
                    "file",
                    "remediation",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["explanations", "additional"],
    "additionalProperties": False,
}


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
    parsed = llm.parse_json_object(content)
    if parsed is None:
        logger.error("review response wasn't a JSON object")
        raise AuditError("The review came back unreadable.")
    return parsed


def select_review_files(
    files: dict[str, str], findings: list[dict], budget: int
) -> tuple[dict[str, str], list[str]]:
    """Pick files for the review prompt within the size budget.

    Files with the most serious findings go first, then the rest in path
    order. Returns (included files, paths left out).
    """
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
    choice: LlmChoice,
    files: dict[str, str],
    findings: list[dict],
    max_explained: int,
) -> tuple[list[dict], list[dict]]:
    """Explain Checkov findings and look for problems it can't detect.

    ``files`` should already fit the prompt budget (see select_review_files).
    Returns (findings with description/remediation filled in where the model
    explained them, additional findings from the review).
    """
    ranked = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 4))
    to_explain = ranked[:max_explained]

    prompt = _load_prompt("review_findings.txt").format(
        files=_format_files(files),
        findings=_format_findings(to_explain),
    )
    content = await llm.complete(
        choice, REVIEW_SYSTEM, prompt, json_schema=REVIEW_SCHEMA
    )
    parsed = _parse_json_object(content)

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
    choice: LlmChoice,
    iac_content: str,
    vulnerabilities: list[dict],
    similar_patches: list[dict],
    file_name: str = "main.tf",
) -> str:
    patches_context = "No earlier fixes."
    if similar_patches:
        patches_context = "\n\n".join(
            f"--- Earlier fix (similarity: {p.get('similarity_score', 'N/A')}) ---\n"
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
    content = await llm.complete(choice, PATCH_SYSTEM, prompt)
    return _strip_code_fence(content)


async def run_diagram_analysis(
    choice: LlmChoice,
    iac_content: str,
    image_bytes: bytes,
    mime_type: str = "image/png",
) -> str:
    prompt = _load_prompt("vision_audit.txt").format(iac_content=iac_content)
    return await llm.complete_with_image(
        choice, DIAGRAM_SYSTEM, prompt, image_bytes, mime_type
    )


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
