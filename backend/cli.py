"""Scan a local directory from the command line or CI.

    python -m backend.cli scan infra/ --fail-on high
    CLOUDGUARD_LLM_KEY=sk-... python -m backend.cli scan . --provider openai --format markdown

The model key is read from CLOUDGUARD_LLM_KEY rather than a flag so it doesn't
end up in shell history or CI logs. Without a key, the scan is Checkov only.
Exit codes: 0 no findings at or above --fail-on, 1 there are, 2 the scan failed.
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from backend.app.services import llm
from backend.app.services.pipeline import (
    NoQuota,
    Scan,
    ScanFailed,
    ScanInput,
    run_to_completion,
)
from backend.app.services.severity import score_findings
from backend.app.services.sources import SourceError, load_directory

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
REPORT_MARKER = "<!-- cloudguard-report -->"
MAX_TABLE_ROWS = 50


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cloudguard", description=__doc__.split("\n")[0]
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a directory of infrastructure code")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument(
        "--provider",
        choices=sorted(llm.PROVIDERS),
        help="model provider for explanations",
    )
    scan.add_argument(
        "--model", help="model id; defaults to the provider's suggested model"
    )
    scan.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    scan.add_argument(
        "--output", help="write the report to this file instead of stdout"
    )
    scan.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="exit 1 when a Checkov finding is at or above this severity (default: high)",
    )
    scan.add_argument(
        "--changed-since",
        metavar="REF",
        help="only report files changed since this git ref",
    )
    scan.add_argument(
        "--link-base",
        help="URL prefix for file links, e.g. https://github.com/o/r/blob/<sha>/",
    )
    scan.add_argument(
        "--write-patches", metavar="DIR", help="write patched files into this directory"
    )
    return parser.parse_args(argv)


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    ).stdout


def changed_files(root: Path, ref: str) -> set[str]:
    """Paths under ``root`` (relative to it) that changed since ``ref``."""
    top = _git("-C", str(root), "rev-parse", "--show-toplevel").strip()
    try:
        # Changes on this branch since it split from ref, like a pull request diff.
        names = _git("-C", top, "diff", "--name-only", f"{ref}...HEAD").split()
    except subprocess.CalledProcessError:
        # Shallow clones may lack the merge base; compare the trees directly.
        names = _git("-C", top, "diff", "--name-only", ref, "HEAD").split()
    changed = set()
    for name in names:
        full = Path(top, name).resolve()
        if full.is_relative_to(root):
            changed.add(full.relative_to(root).as_posix())
    return changed


async def resolve_choice(
    provider: Optional[str], model: Optional[str]
) -> Optional[llm.LlmChoice]:
    key = os.environ.get("CLOUDGUARD_LLM_KEY", "")
    if not provider:
        return None
    if not key:
        raise SystemExit("--provider needs the API key in CLOUDGUARD_LLM_KEY")
    if not model:
        model = (await llm.list_models(provider, key))["default"]
        if not model:
            raise SystemExit(f"No chat models are available to this {provider} key")
    return llm.validate_choice(provider, model, key)


def filter_to_changed(result: dict, changed: set[str]) -> dict:
    findings = [f for f in result["vulnerabilities"] if f.get("file") in changed]
    covered = set(result["analysis"]["covered_files"]) & changed
    scored = [
        f for f in findings if f.get("source") == "checkov" and f.get("file") in covered
    ]
    return {
        **result,
        "vulnerabilities": findings,
        "patches": [p for p in result["patches"] if p["file"] in changed],
        "security_score": score_findings(scored) if covered else None,
        "changed_files": sorted(changed),
    }


def fails(result: dict, threshold: str) -> bool:
    if threshold == "none":
        return False
    limit = SEVERITIES.index(threshold.upper())
    return any(
        f.get("source") == "checkov" and SEVERITIES.index(f["severity"]) <= limit
        for f in result["vulnerabilities"]
        if f.get("severity") in SEVERITIES
    )


def _counts(findings: list[dict]) -> str:
    parts = []
    for severity in SEVERITIES:
        n = sum(1 for f in findings if f.get("severity") == severity)
        if n:
            parts.append(f"{n} {severity.lower()}")
    return ", ".join(parts) or "no findings"


def _cell(text: str) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def _location(finding: dict, link_base: Optional[str]) -> str:
    path = finding.get("file") or ""
    if not path:
        return ""
    start, end = finding.get("line_start"), finding.get("line_end")
    label = f"{path}:{start}" if start else path
    if not link_base:
        return f"`{label}`"
    anchor = (
        f"#L{start}-L{end}"
        if start and end and end != start
        else (f"#L{start}" if start else "")
    )
    return f"[`{label}`]({link_base.rstrip('/')}/{path}{anchor})"


def _score_line(result: dict) -> str:
    score = result["security_score"]
    analysis = result["analysis"]
    head = f"**Score {score}/100**" if score is not None else "**Not scored**"
    files = (
        f"{len(result.get('files', []))} files"
        if len(result.get("files", [])) != 1
        else "1 file"
    )
    return f"{head} · {_counts(result['vulnerabilities'])} · Checkov {analysis['checkov_version']}, {files}"


def _markdown_table(findings: list[dict], link_base: Optional[str]) -> list[str]:
    lines = ["| Severity | Finding | Resource | Location |", "|---|---|---|---|"]
    for f in findings[:MAX_TABLE_ROWS]:
        title = f"{f['title']} ({f['check_id']})" if f.get("check_id") else f["title"]
        lines.append(
            f"| {f['severity'].title()} | {_cell(title)} | {_cell(f.get('resource'))} | {_location(f, link_base)} |"
        )
    if len(findings) > MAX_TABLE_ROWS:
        lines.append(f"\n_and {len(findings) - MAX_TABLE_ROWS} more_")
    return lines


def _markdown_details(findings: list[dict]) -> list[str]:
    explained = [f for f in findings if f.get("description")][:MAX_TABLE_ROWS]
    if not explained:
        return []
    lines = ["", "<details><summary>Explanations and fixes</summary>", ""]
    for f in explained:
        lines += [
            f"**{_cell(f['title'])}** ({f['severity'].title()})",
            "",
            f["description"],
        ]
        if f.get("remediation"):
            lines += ["", f"Fix: {f['remediation']}"]
        lines.append("")
    lines.append("</details>")
    return lines


def render_markdown(result: dict, link_base: Optional[str] = None) -> str:
    analysis = result["analysis"]
    checks = [f for f in result["vulnerabilities"] if f.get("source") == "checkov"]
    review = [f for f in result["vulnerabilities"] if f.get("source") != "checkov"]
    lines = [
        REPORT_MARKER,
        f"## CloudGuard scan: {_cell(result['file_name'])}",
        "",
        _score_line(result),
    ]
    if "changed_files" in result:
        count = len(result["changed_files"])
        lines += [
            "",
            f"Only findings in the {count} changed {'file' if count == 1 else 'files'} are listed.",
        ]
    for notice in analysis.get("notices", []):
        lines += ["", f"> {notice}"]
    if checks:
        lines += ["", "### Checkov findings", ""] + _markdown_table(checks, link_base)
    if review:
        lines += [
            "",
            "### Also noticed in review",
            "",
            "Not from a Checkov policy and not scored. Double-check these.",
            "",
        ]
        lines += _markdown_table(review, link_base)
    lines += _markdown_details(result["vulnerabilities"])
    model = analysis.get("model")
    footer = (
        f"Explained by {model['provider']} {model['model']}."
        if model
        else "Checkov results only. Set an API key for explanations and patches."
    )
    lines += ["", f"<sub>{footer}</sub>", ""]
    return "\n".join(lines)


def render_text(result: dict) -> str:
    score = result["security_score"]
    lines = [
        f"CloudGuard scan: {result['file_name']}",
        f"Score: {score}/100" if score is not None else "Not scored",
        _counts(result["vulnerabilities"]),
    ]
    lines += [f"note: {n}" for n in result["analysis"].get("notices", [])]
    lines.append("")
    for f in result["vulnerabilities"]:
        where = (
            f"{f['file']}:{f['line_start']}"
            if f.get("line_start")
            else f.get("file", "")
        )
        check = f" {f['check_id']}" if f.get("check_id") else " review"
        lines.append(f"{f['severity']:<8}{check:<14} {where:<30} {f['title']}")
    return "\n".join(lines) + "\n"


def render(result: dict, fmt: str, link_base: Optional[str]) -> str:
    if fmt == "json":
        return json.dumps(result, indent=2) + "\n"
    if fmt == "markdown":
        return render_markdown(result, link_base)
    return render_text(result)


def write_patches(result: dict, directory: str) -> None:
    for patch in result["patches"]:
        target = Path(directory, patch["file"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(patch["patched"], encoding="utf-8")


def _clean_notices(result: dict, choice: Optional[llm.LlmChoice]) -> None:
    analysis = result["analysis"]
    if choice is None and analysis.get("limit"):
        # The web app's free-tier messages don't apply on the command line,
        # where no key simply means a Checkov-only scan.
        from backend.app.services.pipeline import limit_notice

        analysis["notices"].remove(limit_notice(analysis["limit"]))
        analysis["limit"] = None
    analysis["notices"] = [
        n.replace(" Check it in Model settings.", "").replace(" in Model settings", "")
        for n in analysis["notices"]
    ]


async def run(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    source = load_directory(str(root))
    choice = await resolve_choice(args.provider, args.model)
    scan = Scan(
        ScanInput(files=source.files, label=source.label, source="cli"),
        None,
        NoQuota(),
        "",
        choice,
    )
    result = await run_to_completion(scan)
    _clean_notices(result, choice)

    if args.changed_since:
        result = filter_to_changed(result, changed_files(root, args.changed_since))
    if args.write_patches:
        write_patches(result, args.write_patches)

    report = render(result, args.format, args.link_base)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)
    return 1 if fails(result, args.fail_on) else 0


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        return asyncio.run(run(args))
    except (SourceError, ScanFailed, llm.LlmError) as e:
        print(f"cloudguard: {getattr(e, 'message', None) or e}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError:
        print(
            "cloudguard: git diff failed; is --changed-since a valid ref?",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
