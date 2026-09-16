import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from typing import AsyncIterator, Optional

from backend.app.core.config import settings
from backend.app.services import agents, llm
from backend.app.services.checkov import ScannerError, run_checkov, safe_relative_path
from backend.app.services.severity import score_findings

logger = logging.getLogger("cloudguard.pipeline")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
MAX_DIAGRAM_CONTEXT_CHARS = 60_000


class NoQuota:
    """Quota for runs outside the web app (the CLI): no free tier at all."""

    enabled = False

    async def claim(self) -> bool:
        return False

    async def refund(self) -> None:
        pass

    async def remaining(self) -> int:
        return 0


class ScanFailed(Exception):
    """The scan can't produce a result at all (as opposed to a partial one)."""


@dataclass
class ScanInput:
    files: dict[str, str]
    label: str
    source: str = "paste"
    image_bytes: Optional[bytes] = None
    image_type: str = "image/png"

    @classmethod
    def single(cls, content: str, file_name: str, **kwargs) -> "ScanInput":
        try:
            path = str(safe_relative_path(file_name))
        except ValueError:
            path = "main.tf"
        return cls(files={path: content}, label=file_name, **kwargs)

    @property
    def single_path(self) -> Optional[str]:
        return next(iter(self.files)) if len(self.files) == 1 else None


def event(step: str, status: str, message: str = None, data=None) -> dict:
    payload = {"step": step, "status": status}
    if message is not None:
        payload["message"] = message
    if data is not None:
        payload["data"] = data
    return payload


def _by_severity(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 4))


def _plural(n: int, word: str, many: str = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


BUSY_NOTICE = (
    "The explanation model is at its per-minute limit right now, because the free "
    "tier is shared by everyone using this site. The Checkov results are complete; "
    "scan again in a minute for explanations and patches. This didn't use a free scan."
)


@dataclass(frozen=True)
class Budget:
    review_chars: int
    explained: int
    patched_files: int
    patch_file_chars: int
    patch_concurrency: int

    @classmethod
    def free(cls) -> "Budget":
        return cls(
            settings.llm_review_max_chars,
            settings.llm_max_explained_findings,
            settings.llm_max_patched_files,
            settings.llm_patch_max_file_chars,
            settings.llm_patch_concurrency,
        )

    @classmethod
    def own_key(cls) -> "Budget":
        # A visitor's own key has its own rate limits, so the scan can send
        # much more. These still keep one scan to a few minutes.
        return cls(120_000, 60, 5, 60_000, 3)


def model_failure_notice(error: Exception, choice: llm.LlmChoice) -> str:
    complete = "The Checkov results are still complete."
    if not isinstance(error, llm.LlmError):
        return f"Explanations couldn't be generated for this scan. {complete}"
    if not choice.own_key:
        if error.kind == "rate_limit":
            return BUSY_NOTICE
        return f"Explanations couldn't be generated for this scan. {complete}"
    messages = {
        "auth": f"Your {choice.label} key was rejected. Check it in Model settings.",
        "not_found": f"Your {choice.label} key can't use {choice.model}. "
        "Pick another model in Model settings.",
        "rate_limit": f"Your {choice.label} account hit a rate limit or ran out of quota.",
        "refused": f"{choice.label} declined to review this file.",
        "too_large": f"The files were too large for {choice.model}.",
    }
    return f"{messages.get(error.kind, error.message)} {complete}"


def files_to_patch(
    files: dict[str, str], findings: list[dict], budget: Budget
) -> list[str]:
    """Files with findings, most serious first, within the patch budget.

    Each patch is a full rewrite of one file, so only files small enough to
    rewrite are considered and larger projects get patches for the files with
    the most serious findings.
    """
    worst = {}
    for f in findings:
        path = f.get("file")
        if path in files and len(files[path]) <= budget.patch_file_chars:
            rank = SEVERITY_ORDER.get(f.get("severity"), 4)
            worst[path] = min(rank, worst.get(path, 4))
    ranked = sorted(worst, key=lambda p: (worst[p], p))
    return ranked[: budget.patched_files]


class Scan:
    """One scan: Checkov first, then explanations and patches when allowed."""

    def __init__(
        self,
        scan_input: ScanInput,
        db_service,
        quota,
        workspace_id: str,
        own_choice: Optional[llm.LlmChoice] = None,
    ):
        self.input = scan_input
        self.db = db_service
        self.quota = quota
        self.workspace_id = workspace_id
        self.own_choice = own_choice
        self.audit_id = uuid.uuid4().hex[:12]

        self.mode = "static"
        self.choice: Optional[llm.LlmChoice] = None
        self.budget = Budget.free()
        self.notices: list[str] = []
        self.findings: list[dict] = []
        self.additional: list[dict] = []
        self.similar: list[dict] = []
        self.patches: list[dict] = []
        self.diagram_analysis: Optional[str] = None
        self.checkov_version = ""
        self.covered_files: list[str] = []
        self.frameworks: list[str] = []

    async def run(self) -> AsyncIterator[dict]:
        async for item in self._static_checks():
            yield item

        if await self._claim_model():
            async for item in self._model_steps():
                yield item
        elif self.input.image_bytes:
            self.notices.append(
                "The diagram wasn't compared because explanations aren't available "
                "for this scan."
            )

        if not self.covered_files:
            self.notices.append(self._coverage_notice())

        result = await self._result()
        if self.db is not None:
            yield event("storage", "running", "Saving to your history...")
            await self._persist(result)
            yield event("storage", "complete", "Saved")
        yield event("done", "complete", data=result)

    async def _static_checks(self) -> AsyncIterator[dict]:
        count = len(self.input.files)
        yield event(
            "static_checks",
            "running",
            (
                "Running Checkov..."
                if count == 1
                else f"Running Checkov on {count} files..."
            ),
        )
        try:
            report = await run_checkov(self.input.files)
        except ScannerError as e:
            raise ScanFailed(str(e)) from e

        self.findings = _by_severity(report.findings)
        self.checkov_version = report.version
        self.covered_files = report.covered_files
        self.frameworks = report.frameworks

        if not self.covered_files:
            message = "File type not covered by Checkov"
        else:
            message = _plural(len(self.findings), "finding")
        yield event("static_checks", "complete", message)

    async def _claim_model(self) -> bool:
        if self.own_choice is not None:
            self.mode, self.choice, self.budget = (
                "own_key",
                self.own_choice,
                Budget.own_key(),
            )
            return True
        free_choice = llm.free_tier_choice()
        if free_choice is None or not self.quota.enabled:
            self.notices.append(
                "This server doesn't offer free explanations, so only the Checkov "
                "results are shown. Add your own API key in Model settings for "
                "explanations and patches."
            )
            return False
        if not await self.quota.claim():
            self.notices.append(
                f"You've used today's {settings.free_llm_scans_per_day} free explained "
                "scans. The Checkov results are still complete. Explanations and "
                "patches come back tomorrow, or add your own API key in Model settings."
            )
            return False
        self.mode, self.choice = "free", free_choice
        return True

    async def _model_steps(self) -> AsyncIterator[dict]:
        async for item in self._review():
            yield item
        if self.mode == "static":
            return
        if self.findings or self.additional:
            async for item in self._patch():
                yield item
        if self.input.image_bytes:
            async for item in self._diagram():
                yield item

    async def _review(self) -> AsyncIterator[dict]:
        """Explain findings; on failure, fall back to static mode with a notice."""
        yield event("review", "running", "Explaining findings...")
        review_files, left_out = agents.select_review_files(
            self.input.files, self.findings, self.budget.review_chars
        )
        try:
            self.findings, self.additional = await agents.review_findings(
                self.choice, review_files, self.findings, self.budget.explained
            )
        except Exception as error:
            self._log_model_failure("review", error)
            if self.mode == "free":
                await self.quota.refund()
            self.notices.append(model_failure_notice(error, self.choice))
            self.mode = "static"
            yield event("review", "error", "Explanations unavailable")
            return
        if self.input.single_path:
            # With one file there's no doubt which file a review finding is about.
            for finding in self.additional:
                finding["file"] = finding.get("file") or self.input.single_path
        if left_out:
            self.notices.append(
                f"{_plural(len(left_out), 'file')} didn't fit in the review, so "
                "some findings aren't explained. Their Checkov results are listed."
            )
        yield event("review", "complete", self._review_message())

    def _log_model_failure(self, step: str, error: Exception) -> None:
        if isinstance(error, llm.LlmError):
            # Provider errors can quote part of the key, so only the
            # classification is logged.
            logger.warning(
                "%s failed for audit %s: %s (%s)",
                step,
                self.audit_id,
                error.kind,
                error.status,
            )
        else:
            logger.warning("%s failed for audit %s", step, self.audit_id, exc_info=True)

    def _review_message(self) -> str:
        if self.additional:
            return f"{_plural(len(self.additional), 'more issue')} spotted in review"
        return "Explained"

    async def _patch(self) -> AsyncIterator[dict]:
        all_findings = self.findings + self.additional
        yield event("rag_retrieval", "running", "Checking your earlier fixes...")
        self.similar = await agents.find_similar_patches(
            self.db, self.workspace_id, all_findings
        )
        yield event(
            "rag_retrieval",
            "complete",
            f"{_plural(len(self.similar), 'related fix', 'related fixes')} from earlier scans",
        )

        targets = files_to_patch(self.input.files, all_findings, self.budget)
        if not targets:
            return
        yield event(
            "patch_generation",
            "running",
            (
                "Writing a patch..."
                if len(targets) == 1
                else f"Patching {len(targets)} files..."
            ),
        )
        self.patches = await self._write_patches(targets, all_findings)

        failed = len(targets) - len(self.patches)
        if failed:
            self.notices.append(
                "A patch couldn't be written for this scan."
                if len(targets) == 1
                else f"Patches couldn't be written for {_plural(failed, 'file')}."
            )
        with_findings = {f.get("file") for f in all_findings} & set(self.input.files)
        skipped = len(with_findings) - len(targets)
        if skipped > 0:
            self.notices.append(
                f"{_plural(skipped, 'file')} with findings "
                f"{'was' if skipped == 1 else 'were'}n't patched. Patches "
                f"cover up to {self.budget.patched_files} files per scan, and "
                "files too large to rewrite in one go are skipped."
            )
        if not self.patches:
            yield event("patch_generation", "error", "Patch unavailable")
            return
        yield event("patch_generation", "complete", self._patch_message())

    def _patch_message(self) -> str:
        if self.input.single_path:
            return "Patch written"
        return f"{_plural(len(self.patches), 'file')} patched"

    async def _write_patches(
        self, targets: list[str], findings: list[dict]
    ) -> list[dict]:
        limit = asyncio.Semaphore(self.budget.patch_concurrency)

        async def patch_one(path: str) -> Optional[dict]:
            context = [_patch_context(f) for f in findings if f.get("file") == path]
            async with limit:
                try:
                    patched = await agents.run_patch_generation(
                        self.choice,
                        self.input.files[path],
                        context,
                        self.similar,
                        file_name=path,
                    )
                except Exception as error:
                    self._log_model_failure(f"patch of {path}", error)
                    return None
            if not patched.strip():
                return None
            return {
                "file": path,
                "original": self.input.files[path],
                "patched": patched,
            }

        results = await asyncio.gather(*(patch_one(p) for p in targets))
        return [r for r in results if r]

    async def _diagram(self) -> AsyncIterator[dict]:
        yield event("diagram", "running", "Comparing the diagram...")
        try:
            self.diagram_analysis = await agents.run_diagram_analysis(
                self.choice,
                self._diagram_context(),
                self.input.image_bytes,
                self.input.image_type,
            )
        except Exception as error:
            self._log_model_failure("diagram", error)
            reason = error.message if isinstance(error, llm.LlmError) else ""
            self.notices.append(f"The diagram couldn't be compared. {reason}".strip())
            yield event("diagram", "error", "Comparison unavailable")
            return
        yield event("diagram", "complete", "Compared")

    def _diagram_context(self) -> str:
        if self.input.single_path:
            return self.input.files[self.input.single_path]
        parts, used = [], 0
        for path in sorted(self.input.files):
            chunk = f"# File: {path}\n{self.input.files[path]}\n"
            if used + len(chunk) > MAX_DIAGRAM_CONTEXT_CHARS:
                break
            parts.append(chunk)
            used += len(chunk)
        return "\n".join(parts)

    def _coverage_notice(self) -> str:
        notice = (
            "Checkov doesn't support this file type (Docker Compose, for example), "
            "so there's no score."
            if self.input.single_path
            else "None of these files are types Checkov supports, so there's no score."
        )
        if self.mode == "free":
            return notice + " The findings come from the review alone."
        return notice + " An explained scan is needed to review it."

    def _score(self):
        if not self.covered_files:
            return None
        # A secret found in a file Checkov can't parse (Compose, say) is still
        # listed, but only findings in covered files feed the score.
        covered = set(self.covered_files)
        return score_findings([f for f in self.findings if f.get("file") in covered])

    async def _result(self) -> dict:
        single = self.input.single_path
        return {
            "audit_id": self.audit_id,
            "file_name": self.input.label,
            "security_score": self._score(),
            "vulnerabilities": self.findings + _by_severity(self.additional),
            "files": sorted(self.input.files),
            "patches": self.patches,
            # Kept for single-file API clients.
            "patched_code": (
                self.patches[0]["patched"] if single and self.patches else ""
            ),
            "similar_past_audits": [p.get("description", "") for p in self.similar],
            "diagram_analysis": self.diagram_analysis,
            "analysis": {
                "mode": self.mode,
                "model": (
                    {"provider": self.choice.label, "model": self.choice.model}
                    if self.choice and self.mode != "static"
                    else None
                ),
                "source": self.input.source,
                "checkov_version": self.checkov_version,
                "covered_files": self.covered_files,
                "frameworks": self.frameworks,
                "notices": self.notices,
                "free_scans_left": await self.quota.remaining(),
            },
        }

    async def _persist(self, result: dict) -> None:
        single = self.input.single_path
        await self.db.save_audit(
            audit_id=self.audit_id,
            workspace_id=self.workspace_id,
            file_name=self.input.label,
            security_score=result["security_score"],
            findings=result["vulnerabilities"],
            original_code=self.input.files[single] if single else "",
            patched_code=result["patched_code"],
            diagram_analysis=self.diagram_analysis,
            analysis=result["analysis"],
            files=result["files"],
            patches=self.patches,
        )
        await agents.index_findings(
            self.db,
            self.workspace_id,
            self.audit_id,
            self.input.label,
            self.input.files,
            {p["file"]: p["patched"] for p in self.patches},
            result["vulnerabilities"],
        )
        await asyncio.to_thread(upload_artifacts, self.input, result)


def _patch_context(finding: dict) -> dict:
    keys = ("check_id", "severity", "title", "resource", "description", "remediation")
    return {k: finding.get(k) for k in keys if finding.get(k)}


def upload_artifacts(scan_input: ScanInput, result: dict) -> None:
    """Store the scanned and patched files in S3. Best effort."""
    try:
        # Imported here so the CLI can use the pipeline without boto3.
        from backend.app.services.storage import StorageService

        storage = StorageService()
        single = scan_input.single_path
        if single:
            original = scan_input.files[single]
            name = scan_input.label
        else:
            original = json.dumps(scan_input.files)
            name = f"{scan_input.label}.json"
        original_key = storage.upload_file(
            content=original, file_name=name, unique_id=result["audit_id"]
        )
        if result.get("patches"):
            patched = (
                result["patches"][0]["patched"]
                if single
                else json.dumps({p["file"]: p["patched"] for p in result["patches"]})
            )
            storage.upload_patched_file(
                original_key=original_key, patched_content=patched
            )
    except Exception:
        logger.exception("S3 upload failed for audit %s", result.get("audit_id"))


async def run_to_completion(scan: Scan) -> dict:
    async for item in scan.run():
        if item["step"] == "done":
            return item["data"]
    raise ScanFailed("The scan ended without a result")
