import asyncio
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import yaml

from backend.app.core.config import settings
from backend.app.services.severity import rate_check

logger = logging.getLogger("cloudguard.checkov")

# SCA frameworks need a Prisma Cloud API key and would only fail or reach out
# to the network.
SKIPPED_FRAMEWORKS = ("sca_package", "sca_image")

# The secrets scanner reads every file, so a hit there doesn't mean Checkov
# understands the file's format. Only real IaC frameworks count as coverage.
GENERIC_FRAMEWORKS = ("secrets",)

# Files where a Helm chart declares dependencies. Checkov renders charts with
# `helm template --dependency-update`, which downloads every dependency from
# the repository it names, so an uploaded chart could make the server request
# any URL, internal addresses included.
HELM_DEPENDENCY_FILES = ("chart.yaml", "requirements.yaml")


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
        # Checkov's own guard against remote chart repositories. It only
        # covers http(s) URLs, so dependencies are also removed before the
        # scan (see without_remote_dependencies).
        "CHECKOV_HELM_ALLOWED_REMOTE_REPOS": "none",
    }


def _is_local_dependency(dependency) -> bool:
    if not isinstance(dependency, dict):
        return False
    repository = dependency.get("repository") or ""
    if not isinstance(repository, str):
        return False
    if repository == "":
        return True
    # A subchart shipped in the upload, e.g. file://charts/common.
    path = repository.removeprefix("file://")
    return (
        path != repository
        and not path.startswith("/")
        and ".." not in PurePosixPath(path).parts
    )


def without_remote_dependencies(content: str) -> str | None:
    """Chart.yaml or requirements.yaml with only local dependencies kept.

    The parsed data is always written back out, even without dependencies,
    so Helm never sees anything this parser didn't. Returns None when the
    file can't be read as a mapping, so it's left out of the scan rather than
    handed to Helm unchecked.
    """
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    dependencies = data.pop("dependencies", None)
    if isinstance(dependencies, list):
        data["dependencies"] = [d for d in dependencies if _is_local_dependency(d)]
    return yaml.safe_dump(data, sort_keys=False)


def _prepare(name: str, content: str) -> str | None:
    if PurePosixPath(name).name.lower() in HELM_DEPENDENCY_FILES:
        return without_remote_dependencies(content)
    return content


def parse_report(raw: str, sources: dict[str, str] | None = None) -> CheckovReport:
    if not raw.strip():
        return CheckovReport()
    data = json.loads(raw)
    # One framework produces a dict, several produce a list, and a directory
    # with nothing Checkov understands produces a bare summary.
    reports = data if isinstance(data, list) else [data]

    sources = sources or {}
    charts = _chart_dirs(sources)
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
            file_path = _source_path(framework, check["file_path"], sources, charts)
            if file_path and counts_as_coverage:
                covered.add(file_path)
        for check in results.get("failed_checks", []):
            file_path = _source_path(framework, check["file_path"], sources, charts)
            if not file_path:
                continue
            if counts_as_coverage:
                covered.add(file_path)
            key = (check["check_id"], check["resource"], file_path)
            if key not in seen:
                seen.add(key)
                report.findings.append(
                    _to_finding(check, file_path, framework, sources)
                )

    report.covered_files = sorted(covered)
    return report


def _to_finding(
    check: dict, file_path: str, framework: str = "", sources: dict | None = None
) -> dict:
    line_range = check.get("file_line_range") or [0, 0]
    # Dockerfile resources come as "/Dockerfile.FROM"; paths elsewhere are relative.
    resource = check["resource"].lstrip("/")
    if check["check_id"].startswith("CKV_SECRET"):
        # Secret findings use a hash of the secret as the resource name.
        resource = ""
    finding = {
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
    if sources and file_path in sources:
        if framework == "helm":
            _pin_to_template(finding, check["resource"], sources[file_path])
        _clamp_lines(finding, sources[file_path])
    return finding


def _clamp_lines(finding: dict, content: str) -> None:
    # Some frameworks (OpenAPI, for one) report ranges past the end of the file.
    last = max(len(content.splitlines()), 1)
    start = min(max(int(finding["line_start"] or 0), 0), last)
    end = min(max(int(finding["line_end"] or 0), start), last)
    finding["line_start"], finding["line_end"] = start, end


def _chart_dirs(sources: dict[str, str]) -> set[str]:
    """Directories in the upload that hold a Helm chart ("" for the root)."""
    dirs = set()
    for name in sources:
        path = PurePosixPath(name)
        if path.name == "Chart.yaml":
            dirs.add("" if str(path.parent) == "." else str(path.parent))
    return dirs


def _in_chart(file_path: str, charts: set[str]) -> bool:
    parents = {str(p) for p in PurePosixPath(file_path).parents}
    return any((chart or ".") in parents for chart in charts)


def _source_path(
    framework: str, reported: str, sources: dict[str, str], charts: set[str]
) -> str | None:
    """The uploaded file a result belongs to, or None to ignore the result.

    Checkov reports a rendered Helm template under the chart's name inside the
    chart directory (charts/app/<name>/templates/x.yaml for charts/app), and
    also scans templates without template syntax as plain Kubernetes. The
    Helm result is mapped back to the uploaded file and the plain one dropped,
    so each template is reported once.
    """
    file_path = reported.lstrip("/")
    if not sources:
        return file_path
    if framework == "kubernetes" and _in_chart(file_path, charts):
        return None
    if framework != "helm" or file_path in sources:
        return file_path
    parts = PurePosixPath(file_path).parts
    for chart in charts:
        prefix = PurePosixPath(chart).parts if chart else ()
        n = len(prefix)
        if parts[:n] == prefix and len(parts) > n + 1:
            rest = parts[n:][1:]
            candidate = str(PurePosixPath(*prefix, *rest))
            if candidate in sources:
                return candidate
    return file_path


def _pin_to_template(finding: dict, resource: str, template: str) -> None:
    """Point a Helm finding at its resource in the template.

    Checkov reports lines in the rendered output, which don't match the
    template once values and includes are expanded. The resource is named
    like "Deployment.default.release-name-web", so the finding goes from the
    template's matching `kind:` line to the end of that document.
    """
    lines = template.splitlines()
    kind = resource.split(".", 1)[0]
    pattern = re.compile(rf"^\s*kind:\s*[\"']?{re.escape(kind)}[\"']?\s*$")
    start = next((i for i, line in enumerate(lines) if pattern.match(line)), None)
    if start is None:
        finding["line_start"], finding["line_end"] = 1, max(len(lines), 1)
        return
    while start > 0 and not lines[start - 1].startswith("---"):
        start -= 1
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("---")),
        len(lines),
    )
    finding["line_start"], finding["line_end"] = start + 1, max(end, start + 1)


async def run_checkov(files: dict[str, str]) -> CheckovReport:
    """Scan ``files`` (relative path -> content) and return rated findings."""
    with tempfile.TemporaryDirectory(prefix="cloudguard-") as workdir:
        source = Path(workdir, "src")
        for name, content in files.items():
            content = _prepare(name, content)
            if content is None:
                logger.info("left %s out of the scan: unreadable chart file", name)
                continue
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
        return parse_report(stdout.decode("utf-8", errors="replace"), files)
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.error("unreadable checkov output: %s", e)
        raise ScannerError("The static checks returned unreadable output") from e
