import asyncio
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from backend.app.core.config import settings
from backend.app.services.severity import rate_check

logger = logging.getLogger("cloudguard.checkov")

# SCA frameworks need a Prisma Cloud API key and would only fail or reach out
# to the network.
SKIPPED_FRAMEWORKS = ("sca_package", "sca_image")

# The secrets scanner reads every file, so a hit there doesn't mean Checkov
# understands the file's format. Only real IaC frameworks count as coverage.
GENERIC_FRAMEWORKS = ("secrets",)


class ScannerError(RuntimeError):
    pass


@dataclass
class CheckovReport:
    findings: list[dict] = field(default_factory=list)
    covered_files: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    version: str = ""


def safe_relative_path(name: str) -> PurePosixPath:
    """Turn a client-supplied path into a relative path that stays inside the scan dir."""
    parts = [
        p
        for p in PurePosixPath(name.replace("\\", "/")).parts
        if p not in ("", ".", "..", "/")
    ]
    if not parts:
        raise ValueError(f"invalid file name: {name!r}")
    return PurePosixPath(*parts)


def _checkov_env(home: str) -> dict:
    # The app's environment holds API keys and database credentials; the
    # scanner gets none of it.
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "LANG": "C.UTF-8",
    }


def parse_report(raw: str) -> CheckovReport:
    if not raw.strip():
        return CheckovReport()
    data = json.loads(raw)
    # One framework produces a dict, several produce a list, and a directory
    # with nothing Checkov understands produces a bare summary.
    reports = data if isinstance(data, list) else [data]

    report = CheckovReport()
    covered = set()
    seen = set()
    for item in reports:
        results = item.get("results")
        if not results:
            report.version = report.version or item.get("checkov_version", "")
            continue
        framework = item.get("check_type", "")
        counts_as_coverage = framework not in GENERIC_FRAMEWORKS
        report.frameworks.append(framework)
        report.version = report.version or item.get("summary", {}).get(
            "checkov_version", ""
        )
        for check in results.get("passed_checks", []):
            if counts_as_coverage:
                covered.add(check["file_path"].lstrip("/"))
        for check in results.get("failed_checks", []):
            file_path = check["file_path"].lstrip("/")
            if counts_as_coverage:
                covered.add(file_path)
            key = (check["check_id"], check["resource"], file_path)
            if key in seen:
                continue
            seen.add(key)
            report.findings.append(_to_finding(check, file_path))

    report.covered_files = sorted(covered)
    return report


def _to_finding(check: dict, file_path: str) -> dict:
    line_range = check.get("file_line_range") or [0, 0]
    resource = check["resource"]
    if check["check_id"].startswith("CKV_SECRET"):
        # Secret findings use a hash of the secret as the resource name.
        resource = ""
    return {
        "source": "checkov",
        "check_id": check["check_id"],
        "severity": rate_check(check["check_id"], check["check_name"]),
        "title": check["check_name"].rstrip("."),
        "description": "",
        "remediation": "",
        "resource": resource,
        "file": file_path,
        "line_start": line_range[0],
        "line_end": line_range[-1],
        "guideline": check.get("guideline") or "",
    }


async def run_checkov(files: dict[str, str]) -> CheckovReport:
    """Scan ``files`` (relative path -> content) and return rated findings."""
    with tempfile.TemporaryDirectory(prefix="cloudguard-") as workdir:
        source = Path(workdir, "src")
        for name, content in files.items():
            target = source / safe_relative_path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        command = [
            settings.checkov_bin,
            "--directory",
            str(source),
            "--output",
            "json",
            "--compact",
            "--skip-download",
            "--skip-framework",
            *SKIPPED_FRAMEWORKS,
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workdir,
                env=_checkov_env(workdir),
            )
        except FileNotFoundError as e:
            raise ScannerError("Checkov is not installed on the server") from e

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=settings.checkov_timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise ScannerError("The static checks took too long and were stopped")

    # Exit code 1 just means some checks failed.
    if process.returncode not in (0, 1):
        logger.error(
            "checkov exited %s: %s", process.returncode, stderr.decode()[-2000:]
        )
        raise ScannerError("The static checks failed to run")

    try:
        return parse_report(stdout.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.error("unreadable checkov output: %s", e)
        raise ScannerError("The static checks returned unreadable output") from e
