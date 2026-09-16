from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.app.services.agents import AuditError
from backend.app.services.checkov import CheckovReport, ScannerError, parse_report
from backend.app.services.llm import LlmChoice, LlmError
from backend.app.services.pipeline import Scan, ScanFailed, ScanInput, run_to_completion

FIXTURE = Path(__file__).parent / "fixtures" / "checkov_sample.json"


class FakeQuota:
    def __init__(self, enabled=True, available=True, left=4):
        self.enabled = enabled
        self.available = available
        self.left = left
        self.refunded = False

    async def claim(self):
        return self.enabled and self.available

    async def refund(self):
        self.refunded = True

    async def remaining(self):
        return self.left if self.enabled else 0


def fake_db():
    db = MagicMock()
    db.save_audit = AsyncMock()
    db.save_vulnerabilities = AsyncMock()
    db.search_similar = AsyncMock(return_value=[])
    return db


def sample_report():
    return parse_report(FIXTURE.read_text())


async def events_and_result(scan):
    events = [e async for e in scan.run()]
    return events, events[-1]["data"]


@pytest.fixture(autouse=True)
def no_side_effects():
    with (
        patch("backend.app.services.pipeline.upload_artifacts"),
        patch("backend.app.services.agents.index_findings", new=AsyncMock()),
    ):
        yield


@pytest.mark.asyncio
@patch("backend.app.services.pipeline.run_checkov")
async def test_static_only_when_explanations_unavailable(mock_checkov):
    mock_checkov.return_value = sample_report()
    db = fake_db()
    scan = Scan(ScanInput.single("code", "main.tf"), db, FakeQuota(enabled=False), "ws")

    events, result = await events_and_result(scan)

    assert [e["step"] for e in events] == [
        "static_checks",
        "static_checks",
        "storage",
        "storage",
        "done",
    ]
    assert result["analysis"]["mode"] == "static"
    assert result["security_score"] == 4
    assert len(result["vulnerabilities"]) == 34
    assert result["patched_code"] == ""
    assert "doesn't offer free explanations" in result["analysis"]["notices"][0]
    db.save_audit.assert_awaited_once()
    assert db.save_audit.call_args.kwargs["analysis"]["mode"] == "static"


@pytest.mark.asyncio
@patch(
    "backend.app.services.pipeline.agents.run_patch_generation", new_callable=AsyncMock
)
@patch(
    "backend.app.services.pipeline.agents.find_similar_patches", new_callable=AsyncMock
)
@patch("backend.app.services.pipeline.agents.review_findings", new_callable=AsyncMock)
@patch("backend.app.services.pipeline.run_checkov")
async def test_explained_scan(mock_checkov, mock_review, mock_similar, mock_patch):
    report = sample_report()
    mock_checkov.return_value = report
    explained = [dict(f, description="why") for f in report.findings]
    extra = [{"source": "review", "severity": "HIGH", "title": "Password in file"}]
    mock_review.return_value = (explained, extra)
    mock_similar.return_value = [{"description": "old fix"}]
    mock_patch.return_value = "patched"

    scan = Scan(ScanInput.single("code", "main.tf"), fake_db(), FakeQuota(), "ws")
    events, result = await events_and_result(scan)

    steps = [e["step"] for e in events if e["status"] == "complete"]
    assert steps == [
        "static_checks",
        "review",
        "rag_retrieval",
        "patch_generation",
        "storage",
        "done",
    ]
    assert result["analysis"]["mode"] == "free"
    assert result["patched_code"] == "patched"
    assert result["similar_past_audits"] == ["old fix"]
    # Review-only findings are listed but don't change the Checkov score.
    assert result["vulnerabilities"][-1]["title"] == "Password in file"
    assert result["security_score"] == 4
    assert result["analysis"]["notices"] == []


@pytest.mark.asyncio
@patch("backend.app.services.pipeline.agents.review_findings", new_callable=AsyncMock)
@patch("backend.app.services.pipeline.run_checkov")
async def test_review_failure_keeps_checkov_results_and_refunds(
    mock_checkov, mock_review
):
    mock_checkov.return_value = sample_report()
    mock_review.side_effect = AuditError("unreadable")
    quota = FakeQuota()

    events, result = await events_and_result(
        Scan(ScanInput.single("c", "main.tf"), fake_db(), quota, "ws")
    )

    assert quota.refunded
    assert result["analysis"]["mode"] == "static"
    assert len(result["vulnerabilities"]) == 34
    assert any(e["step"] == "review" and e["status"] == "error" for e in events)
    assert "couldn't be generated" in result["analysis"]["notices"][0]


@pytest.mark.asyncio
@patch("backend.app.services.pipeline.run_checkov")
async def test_daily_limit_reached(mock_checkov):
    mock_checkov.return_value = sample_report()
    quota = FakeQuota(available=False, left=0)
    _, result = await events_and_result(
        Scan(ScanInput.single("c", "main.tf"), fake_db(), quota, "ws")
    )
    assert result["analysis"]["mode"] == "static"
    assert "free explained scans" in result["analysis"]["notices"][0]
    assert result["analysis"]["free_scans_left"] == 0


@pytest.mark.asyncio
@patch(
    "backend.app.services.pipeline.agents.run_patch_generation", new_callable=AsyncMock
)
@patch(
    "backend.app.services.pipeline.agents.find_similar_patches", new_callable=AsyncMock
)
@patch("backend.app.services.pipeline.agents.review_findings", new_callable=AsyncMock)
@patch("backend.app.services.pipeline.run_checkov")
async def test_uncovered_file_has_no_score(
    mock_checkov, mock_review, mock_similar, mock_patch
):
    mock_checkov.return_value = CheckovReport(version="3.3.17")
    mock_review.return_value = (
        [],
        [{"source": "review", "severity": "HIGH", "title": "Privileged container"}],
    )
    mock_similar.return_value = []
    mock_patch.return_value = "fixed compose"

    _, result = await events_and_result(
        Scan(
            ScanInput.single("services: {}", "docker-compose.yml"),
            fake_db(),
            FakeQuota(),
            "ws",
        )
    )
    assert result["security_score"] is None
    assert result["vulnerabilities"][0]["title"] == "Privileged container"
    assert "doesn't support this file type" in result["analysis"]["notices"][-1]


@pytest.mark.asyncio
@patch(
    "backend.app.services.pipeline.agents.run_patch_generation", new_callable=AsyncMock
)
@patch(
    "backend.app.services.pipeline.agents.find_similar_patches", new_callable=AsyncMock
)
@patch("backend.app.services.pipeline.agents.review_findings", new_callable=AsyncMock)
@patch("backend.app.services.pipeline.run_checkov")
async def test_patch_failure_is_a_notice(
    mock_checkov, mock_review, mock_similar, mock_patch
):
    report = sample_report()
    mock_checkov.return_value = report
    mock_review.return_value = (report.findings, [])
    mock_similar.return_value = []
    mock_patch.side_effect = RuntimeError("provider down")

    _, result = await events_and_result(
        Scan(ScanInput.single("c", "main.tf"), fake_db(), FakeQuota(), "ws")
    )
    assert result["patched_code"] == ""
    assert result["analysis"]["mode"] == "free"
    assert "patch couldn't be written" in result["analysis"]["notices"][0]


@pytest.mark.asyncio
@patch("backend.app.services.pipeline.run_checkov")
async def test_scanner_failure_fails_the_scan(mock_checkov):
    mock_checkov.side_effect = ScannerError("The static checks failed to run")
    db = fake_db()
    with pytest.raises(ScanFailed, match="failed to run"):
        await run_to_completion(
            Scan(ScanInput.single("c", "main.tf"), db, FakeQuota(), "ws")
        )
    db.save_audit.assert_not_called()


@pytest.mark.asyncio
@patch("backend.app.services.pipeline.run_checkov")
async def test_only_covered_files_feed_the_score(mock_checkov):
    report = sample_report()
    report.findings.append(
        {
            "source": "checkov",
            "check_id": "CKV_SECRET_6",
            "severity": "CRITICAL",
            "title": "Base64 High Entropy String",
            "resource": "",
            "file": "docker-compose.yml",
        }
    )
    mock_checkov.return_value = report
    _, result = await events_and_result(
        Scan(
            ScanInput.single("c", "main.tf"), fake_db(), FakeQuota(enabled=False), "ws"
        )
    )
    # Same score as without the Compose secret, which is still listed.
    assert result["security_score"] == 4
    assert any(f["check_id"] == "CKV_SECRET_6" for f in result["vulnerabilities"])


def multi_file_findings():
    def f(path, severity, check_id):
        return {
            "source": "checkov",
            "check_id": check_id,
            "severity": severity,
            "title": check_id,
            "resource": "r",
            "file": path,
        }

    return [
        f("a.tf", "LOW", "CKV_1"),
        f("b.tf", "CRITICAL", "CKV_2"),
        f("c.tf", "HIGH", "CKV_3"),
        f("d.tf", "MEDIUM", "CKV_4"),
        f("e.tf", "LOW", "CKV_5"),
        f("f.tf", "LOW", "CKV_6"),
        f("g.tf", "HIGH", "CKV_7"),
    ]


def test_files_to_patch_ranks_and_caps():
    from backend.app.services.pipeline import Budget, files_to_patch

    budget = Budget(
        review_chars=1000,
        explained=10,
        patched_files=5,
        patch_file_chars=100,
        patch_concurrency=1,
    )
    files = {f"{k}.tf": "x" for k in "abcdefg"}
    files["c.tf"] = "x" * 101  # too large to rewrite
    assert files_to_patch(files, multi_file_findings(), budget) == [
        "b.tf",
        "g.tf",
        "d.tf",
        "a.tf",
        "e.tf",
    ]
    assert (
        files_to_patch(files, [{"file": "not-scanned.tf", "severity": "HIGH"}], budget)
        == []
    )


@pytest.mark.asyncio
@patch(
    "backend.app.services.pipeline.agents.run_patch_generation", new_callable=AsyncMock
)
@patch(
    "backend.app.services.pipeline.agents.find_similar_patches", new_callable=AsyncMock
)
@patch("backend.app.services.pipeline.agents.review_findings", new_callable=AsyncMock)
@patch("backend.app.services.pipeline.run_checkov")
async def test_multi_file_scan(
    mock_checkov, mock_review, mock_similar, mock_patch, monkeypatch
):
    from backend.app.core.config import settings

    monkeypatch.setattr(settings, "llm_max_patched_files", 5)
    monkeypatch.setattr(settings, "llm_patch_concurrency", 3)
    files = {f"{k}.tf": f"content {k}" for k in "abcdefg"}
    findings = multi_file_findings()
    mock_checkov.return_value = CheckovReport(
        findings=findings,
        covered_files=sorted(files),
        frameworks=["terraform"],
        version="3.3.17",
    )
    mock_review.return_value = (findings, [])
    mock_similar.return_value = []

    async def fake_patch(choice, content, context, similar, file_name):
        if file_name == "c.tf":
            raise RuntimeError("provider hiccup")
        return f"patched {file_name}"

    mock_patch.side_effect = fake_patch
    db = fake_db()
    scan = Scan(
        ScanInput(files=files, label="org/repo", source="github"), db, FakeQuota(), "ws"
    )

    events, result = await events_and_result(scan)

    assert result["file_name"] == "org/repo"
    assert result["files"] == sorted(files)
    assert result["patched_code"] == ""
    assert [p["file"] for p in result["patches"]] == ["b.tf", "g.tf", "d.tf", "a.tf"]
    assert result["patches"][0] == {
        "file": "b.tf",
        "original": "content b",
        "patched": "patched b.tf",
    }
    notices = " ".join(result["analysis"]["notices"])
    assert "couldn't be written for 1 file" in notices
    assert "2 files with findings weren't patched" in notices
    assert result["analysis"]["source"] == "github"

    # Each patch only sees its own file's findings.
    for call in mock_patch.call_args_list:
        path = call.kwargs["file_name"]
        assert call.args[0].provider == "groq"
        assert all(ctx["check_id"] for ctx in call.args[2])
        assert len(call.args[2]) == 1
        assert call.args[1] == files[path]

    saved = db.save_audit.call_args.kwargs
    assert saved["files"] == sorted(files)
    assert saved["original_code"] == ""
    assert len(saved["patches"]) == 4


def own_choice(provider="openai", model="gpt-5.6-terra"):
    return LlmChoice(provider, model, "sk-test-key-123456", own_key=True)


@pytest.mark.asyncio
@patch("backend.app.services.pipeline.agents.review_findings", new_callable=AsyncMock)
@patch("backend.app.services.pipeline.run_checkov")
async def test_rate_limited_free_review_says_so(mock_checkov, mock_review):
    mock_checkov.return_value = sample_report()
    mock_review.side_effect = LlmError(
        "rate_limit", "Groq rate limit or quota reached.", 413
    )
    quota = FakeQuota()
    _, result = await events_and_result(
        Scan(ScanInput.single("c", "main.tf"), fake_db(), quota, "ws")
    )
    assert quota.refunded
    assert "per-minute limit" in result["analysis"]["notices"][0]


@pytest.mark.asyncio
@patch(
    "backend.app.services.pipeline.agents.run_patch_generation", new_callable=AsyncMock
)
@patch(
    "backend.app.services.pipeline.agents.find_similar_patches", new_callable=AsyncMock
)
@patch("backend.app.services.pipeline.agents.review_findings", new_callable=AsyncMock)
@patch("backend.app.services.pipeline.run_checkov")
async def test_own_key_skips_quota_and_uses_bigger_budget(
    mock_checkov, mock_review, mock_similar, mock_patch
):
    report = sample_report()
    mock_checkov.return_value = report
    mock_review.return_value = (report.findings, [])
    mock_similar.return_value = []
    mock_patch.return_value = "patched"
    quota = FakeQuota(available=False, left=0)
    choice = own_choice()

    _, result = await events_and_result(
        Scan(
            ScanInput.single("c", "main.tf"), fake_db(), quota, "ws", own_choice=choice
        )
    )

    assert result["analysis"]["mode"] == "own_key"
    assert result["analysis"]["model"] == {
        "provider": "OpenAI",
        "model": "gpt-5.6-terra",
    }
    assert result["analysis"]["notices"] == []
    review_call = mock_review.call_args
    assert review_call.args[0] is choice
    assert review_call.args[3] == 60  # own-key explanation budget
    assert mock_patch.call_args.args[0] is choice


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error, expected",
    [
        (
            LlmError("auth", "OpenAI rejected the API key.", 401),
            "Your OpenAI key was rejected",
        ),
        (LlmError("not_found", "x", 404), "can't use gpt-5.6-terra"),
        (LlmError("rate_limit", "x", 429), "hit a rate limit or ran out of quota"),
    ],
)
@patch("backend.app.services.pipeline.agents.review_findings", new_callable=AsyncMock)
@patch("backend.app.services.pipeline.run_checkov")
async def test_own_key_failures_are_explained(
    mock_checkov, mock_review, error, expected, caplog
):
    mock_checkov.return_value = sample_report()
    mock_review.side_effect = error
    quota = FakeQuota()
    _, result = await events_and_result(
        Scan(
            ScanInput.single("c", "main.tf"),
            fake_db(),
            quota,
            "ws",
            own_choice=own_choice(),
        )
    )
    assert not quota.refunded
    assert result["analysis"]["mode"] == "static"
    assert expected in result["analysis"]["notices"][0]
    assert len(result["vulnerabilities"]) == 34
    assert "sk-test-key" not in caplog.text


@pytest.mark.asyncio
@patch("backend.app.services.pipeline.run_checkov")
async def test_free_tier_needs_server_key(mock_checkov, monkeypatch):
    from backend.app.core.config import settings

    monkeypatch.setattr(settings, "groq_api_key", "")
    mock_checkov.return_value = sample_report()
    _, result = await events_and_result(
        Scan(ScanInput.single("c", "main.tf"), fake_db(), FakeQuota(), "ws")
    )
    assert result["analysis"]["mode"] == "static"
    assert "add your own api key" in result["analysis"]["notices"][0].lower()
