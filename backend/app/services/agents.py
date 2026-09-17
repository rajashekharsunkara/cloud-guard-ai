import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

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


def _clean_additional(items, files: dict[str, str]) -> list[dict]:
    cleaned = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict) or not item.get("title"):
            continue
        severity = str(item.get("severity", "MEDIUM")).upper()
        file_path = str(item.get("file", ""))
        if not file_path and len(files) == 1:
            file_path = next(iter(files))
        elif file_path not in files:
            file_path = ""
        finding = {
            "source": "review",
            "check_id": None,
            "severity": severity if severity in SEVERITY_ORDER else "MEDIUM",
            "title": str(item["title"]),
            "description": str(item.get("description", "")),
            "remediation": str(item.get("remediation", "")),
            "resource": str(item.get("resource", "")),
            "file": file_path,
        }
        lines = locate_resource(files.get(file_path, ""), finding["resource"])
        if lines:
            finding["line_start"], finding["line_end"] = lines
        cleaned.append(finding)
    return cleaned


def locate_resource(content: str, resource: str) -> Optional[tuple[int, int]]:
    """The lines of a resource the review named, found in the file itself.

    The model names resources the way the file does (a Terraform address, a
    Compose service, a Kubernetes object name), which is more reliable than
    asking it for line numbers. Returns None when the name can't be found.
    """
    name = resource.strip().strip("`'\"")
    if not content or not name:
        return None
    lines = content.splitlines()
    # Names sometimes come with a description ("Deployment ledger-api",
    # "compose service api"), so the words are tried last to first.
    words = [w.strip("`'\",:()") for w in reversed(name.split())]
    candidates = [name] + [w for w in words if len(w) >= 3 and w != name]
    for candidate in candidates:
        for find in (_terraform_block, _yaml_key_block, _kubernetes_object):
            found = find(lines, candidate)
            if found:
                return found
    return None


def _terraform_block(lines: list[str], name: str) -> Optional[tuple[int, int]]:
    parts = name.split(".")
    if len(parts) < 2:
        return None
    if parts[0] == "module":
        pattern = rf'^\s*module\s+"{re.escape(parts[1])}"'
    else:
        kind = "data" if parts[0] == "data" and len(parts) >= 3 else "resource"
        type_, label = parts[-2], parts[-1]
        pattern = rf'^\s*{kind}\s+"{re.escape(type_)}"\s+"{re.escape(label)}"'
    start = _first_match(lines, pattern)
    if start is None:
        return None
    depth, opened = 0, False
    for i in range(start, len(lines)):
        opened = opened or "{" in lines[i]
        depth += lines[i].count("{") - lines[i].count("}")
        if opened and depth <= 0:
            return start + 1, i + 1
    return start + 1, start + 1


def _yaml_key_block(lines: list[str], name: str) -> Optional[tuple[int, int]]:
    key = name.split(".")[-1]
    start = _first_match(lines, rf"^(\s*){re.escape(key)}\s*:\s*(#.*)?$")
    if start is None:
        return None
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = start
    for i in range(start + 1, len(lines)):
        text = lines[i]
        if not text.strip() or text.lstrip().startswith("#"):
            continue
        if len(text) - len(text.lstrip()) <= indent:
            break
        end = i
    return start + 1, end + 1


def _kubernetes_object(lines: list[str], name: str) -> Optional[tuple[int, int]]:
    key = name.split("/")[-1].split(".")[-1]
    at = _first_match(lines, rf"^\s*name:\s*[\"']?{re.escape(key)}[\"']?\s*$")
    if at is None:
        return None
    start = at
    while start > 0 and not lines[start - 1].startswith("---"):
        start -= 1
    end = next(
        (i for i in range(at, len(lines)) if lines[i].startswith("---")), len(lines)
    )
    return start + 1, max(end, start + 1)


def _first_match(lines: list[str], pattern: str) -> Optional[int]:
    compiled = re.compile(pattern)
    return next((i for i, line in enumerate(lines) if compiled.match(line)), None)


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

    additional = _clean_additional(parsed.get("additional"), files)
    logger.info(
        "review explained %d of %d findings, added %d",
        sum(1 for f in explained if f["description"]),
        len(findings),
        len(additional),
    )
    return explained, additional


def format_patch_findings(findings: list[dict], max_chars: int) -> str:
    """One line per finding, most severe first, within ``max_chars``.

    The patch only needs what to fix, so explanations are shortened and the
    least severe findings are dropped first when the list is long.
    """
    ranked = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 4))
    lines, used = [], 0
    for f in ranked:
        what = f.get("check_id") or "review"
        where = f" ({f['resource']})" if f.get("resource") else ""
        line = f"- [{f.get('severity', 'MEDIUM')}] {what}: {f.get('title', '')}{where}"
        fix = f.get("remediation") or f.get("description") or ""
        if fix:
            line += f" Fix: {_shorten(fix, 300)}"
        if lines and used + len(line) > max_chars:
            lines.append(f"- ...and {len(ranked) - len(lines)} lower-severity findings")
            break
        lines.append(line)
        used += len(line) + 1
    return "\n".join(lines) or "(none)"


def format_earlier_fixes(similar_patches: list[dict], max_chars: int) -> str:
    """Earlier fixes as short examples: the issue and the lines that changed.

    Stored patches are whole files, often the same file for several findings,
    so they're de-duplicated and reduced to their "FIXED:" lines.
    """
    blocks, seen, used = [], set(), 0
    for p in similar_patches:
        patched = p.get("patched_code") or ""
        changed = [line.strip() for line in patched.splitlines() if "FIXED:" in line]
        if not changed or patched in seen:
            continue
        seen.add(patched)
        block = f"Issue: {_shorten(p.get('description') or '', 200)}\nChanged lines:\n"
        for line in changed:
            if used + len(block) + len(line) > max_chars:
                break
            block += line + "\n"
        if block.endswith("Changed lines:\n"):
            break
        blocks.append(block.rstrip())
        used += len(block)
    return "\n\n".join(blocks) or "No earlier fixes."


def _shorten(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


async def run_patch_generation(
    choice: LlmChoice,
    iac_content: str,
    vulnerabilities: list[dict],
    similar_patches: list[dict],
    file_name: str = "main.tf",
    findings_chars: int = 3_000,
    examples_chars: int = 1_500,
) -> str:
    prompt = _load_prompt("patch_generator.txt").format(
        file_name=file_name,
        iac_content=iac_content,
        vulnerabilities=format_patch_findings(vulnerabilities, findings_chars),
        similar_patches=format_earlier_fixes(similar_patches, examples_chars),
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
