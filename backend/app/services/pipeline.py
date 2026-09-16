import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import AsyncIterator, Optional

from backend.app.core.config import settings
from backend.app.services import agents
from backend.app.services.checkov import ScannerError, run_checkov
from backend.app.services.severity import score_findings
from backend.app.services.storage import StorageService

logger = logging.getLogger("cloudguard.pipeline")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class ScanFailed(Exception):
    """The scan can't produce a result at all (as opposed to a partial one)."""


@dataclass
class ScanInput:
    iac_content: str
    file_name: str
    image_bytes: Optional[bytes] = None
    image_type: str = "image/png"


def event(step: str, status: str, message: str = None, data=None) -> dict:
    payload = {"step": step, "status": status}
    if message is not None:
        payload["message"] = message
    if data is not None:
        payload["data"] = data
    return payload


def _by_severity(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 4))


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


class Scan:
    """One scan: Checkov first, then explanations and a patch when allowed."""

    def __init__(self, scan_input: ScanInput, db_service, quota, workspace_id: str):
        self.input = scan_input
        self.db = db_service
        self.quota = quota
        self.workspace_id = workspace_id
        self.audit_id = uuid.uuid4().hex[:12]

        self.mode = "static"
        self.notices: list[str] = []
        self.findings: list[dict] = []
        self.additional: list[dict] = []
        self.similar: list[dict] = []
        self.patched_code = ""
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
                "The diagram wasn't compared because explanations aren't available for this scan."
            )

        if not self.covered_files:
            self.notices.append(self._coverage_notice())

        yield event("storage", "running", "Saving to your history...")
        result = await self._result()
        await self._persist(result)
        yield event("storage", "complete", "Saved")
        yield event("done", "complete", data=result)

    async def _static_checks(self) -> AsyncIterator[dict]:
        yield event("static_checks", "running", "Running Checkov...")
        try:
            report = await run_checkov({self.input.file_name: self.input.iac_content})
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
        if not self.quota.enabled:
            self.notices.append(
                "Explanations and patches aren't available on this server, "
                "so only the Checkov results are shown."
            )
            return False
        if not await self.quota.claim():
            self.notices.append(
                f"You've used today's {settings.free_llm_scans_per_day} free explained "
                "scans. The Checkov results are still complete; explanations and "
                "patches are available again tomorrow."
            )
            return False
        self.mode = "free"
        return True

    async def _model_steps(self) -> AsyncIterator[dict]:
        yield event("review", "running", "Explaining findings...")
        try:
            self.findings, self.additional = await agents.review_findings(
                self.input.iac_content, self.input.file_name, self.findings
            )
        except Exception:
            logger.warning("review failed for audit %s", self.audit_id, exc_info=True)
            await self.quota.refund()
            self.mode = "static"
            self.notices.append(
                "Explanations couldn't be generated for this scan. "
                "The Checkov results are still complete."
            )
            yield event("review", "error", "Explanations unavailable")
            return
        yield event("review", "complete", self._review_message())

        if self.findings or self.additional:
            async for item in self._patch():
                yield item
        if self.input.image_bytes:
            async for item in self._diagram():
                yield item

    def _review_message(self) -> str:
        if self.additional:
            return f"{_plural(len(self.additional), 'more issue')} spotted in review"
        return "Explained"

    async def _patch(self) -> AsyncIterator[dict]:
        yield event("rag_retrieval", "running", "Checking your earlier fixes...")
        self.similar = await agents.find_similar_patches(
            self.db, self.workspace_id, self.findings + self.additional
        )
        yield event(
            "rag_retrieval",
            "complete",
            f"{len(self.similar)} related {'fix' if len(self.similar) == 1 else 'fixes'} from earlier scans",
        )

        yield event("patch_generation", "running", "Writing a patch...")
        try:
            self.patched_code = await agents.run_patch_generation(
                self.input.iac_content,
                [_patch_context(f) for f in self.findings + self.additional],
                self.similar,
            )
        except Exception:
            logger.warning("patch failed for audit %s", self.audit_id, exc_info=True)
            self.notices.append("A patch couldn't be written for this scan.")
            yield event("patch_generation", "error", "Patch unavailable")
            return
        yield event("patch_generation", "complete", "Patch written")

    async def _diagram(self) -> AsyncIterator[dict]:
        yield event("diagram", "running", "Comparing the diagram...")
        try:
            self.diagram_analysis = await agents.run_diagram_analysis(
                self.input.iac_content, self.input.image_bytes, self.input.image_type
            )
        except Exception:
            logger.warning("diagram failed for audit %s", self.audit_id, exc_info=True)
            self.notices.append("The diagram couldn't be compared this time.")
            yield event("diagram", "error", "Comparison unavailable")
            return
        yield event("diagram", "complete", "Compared")

    def _coverage_notice(self) -> str:
        notice = (
            "Checkov doesn't support this file type (Docker Compose, for example), "
            "so there's no score."
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
        return {
            "audit_id": self.audit_id,
            "file_name": self.input.file_name,
            "security_score": self._score(),
            "vulnerabilities": self.findings + _by_severity(self.additional),
            "patched_code": self.patched_code,
            "similar_past_audits": [p.get("description", "") for p in self.similar],
            "diagram_analysis": self.diagram_analysis,
            "analysis": {
                "mode": self.mode,
                "checkov_version": self.checkov_version,
                "covered_files": self.covered_files,
                "frameworks": self.frameworks,
                "notices": self.notices,
                "free_scans_left": await self.quota.remaining(),
            },
        }

    async def _persist(self, result: dict) -> None:
        await self.db.save_audit(
            audit_id=self.audit_id,
            workspace_id=self.workspace_id,
            file_name=self.input.file_name,
            security_score=result["security_score"],
            findings=result["vulnerabilities"],
            original_code=self.input.iac_content,
            patched_code=self.patched_code,
            diagram_analysis=self.diagram_analysis,
            analysis=result["analysis"],
        )
        await agents.index_findings(
            self.db,
            self.workspace_id,
            self.audit_id,
            self.input.file_name,
            self.input.iac_content,
            self.patched_code,
            result["vulnerabilities"],
        )
        await asyncio.to_thread(
            upload_artifacts, self.input.iac_content, self.input.file_name, result
        )


def _patch_context(finding: dict) -> dict:
    keys = ("check_id", "severity", "title", "resource", "description", "remediation")
    return {k: finding.get(k) for k in keys if finding.get(k)}


def upload_artifacts(iac_content: str, file_name: str, result: dict) -> None:
    """Store the original and patched configs in S3. Best effort."""
    try:
        storage = StorageService()
        original_key = storage.upload_file(
            content=iac_content, file_name=file_name, unique_id=result["audit_id"]
        )
        if result.get("patched_code"):
            storage.upload_patched_file(
                original_key=original_key, patched_content=result["patched_code"]
            )
    except Exception:
        logger.exception("S3 upload failed for audit %s", result.get("audit_id"))


async def run_to_completion(scan: Scan) -> dict:
    async for item in scan.run():
        if item["step"] == "done":
            return item["data"]
    raise ScanFailed("The scan ended without a result")
