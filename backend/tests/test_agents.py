import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.app.services.agents import (
    REVIEW_SCHEMA,
    AuditError,
    index_findings,
    review_findings,
    run_diagram_analysis,
    run_patch_generation,
    select_review_files,
)
from backend.app.services.llm import LlmChoice

CHOICE = LlmChoice("groq", "openai/gpt-oss-120b", "gsk_test_key_000", own_key=False)


def finding(
    check_id, severity, title="Check", resource="aws_s3_bucket.a", file="main.tf"
):
    return {
        "source": "checkov",
        "check_id": check_id,
        "severity": severity,
        "title": title,
        "description": "",
        "remediation": "",
        "resource": resource,
        "file": file,
        "line_start": 1,
        "line_end": 4,
    }


class TestReviewFindings:

    @pytest.mark.asyncio
    @patch("backend.app.services.agents.llm.complete", new_callable=AsyncMock)
    async def test_explanations_are_matched_by_ref(self, mock_complete):
        findings = [
            finding("CKV_AWS_21", "MEDIUM", "Versioning"),
            finding("CKV_AWS_20", "CRITICAL", "Public read"),
        ]
        # Findings are ranked by severity before numbering, so ref 1 is the
        # critical one even though it came second.
        mock_complete.return_value = json.dumps(
            {
                "explanations": [
                    {
                        "ref": 1,
                        "description": "Anyone can list it",
                        "remediation": "acl = private",
                    },
                    {
                        "ref": 2,
                        "description": "No history",
                        "remediation": "enable versioning",
                    },
                    {"ref": 99, "description": "ignored"},
                    "junk",
                ],
                "additional": [],
            }
        )

        explained, additional = await review_findings(
            CHOICE, {"main.tf": "code"}, findings, 25
        )

        assert [f["check_id"] for f in explained] == ["CKV_AWS_20", "CKV_AWS_21"]
        assert explained[0]["description"] == "Anyone can list it"
        assert explained[1]["remediation"] == "enable versioning"
        assert additional == []

        choice, _system, prompt = mock_complete.call_args.args
        assert choice is CHOICE
        assert mock_complete.call_args.kwargs["json_schema"] is REVIEW_SCHEMA
        assert "[1] CKV_AWS_20 (CRITICAL)" in prompt
        assert "File: main.tf\n---\ncode\n---" in prompt

    @pytest.mark.asyncio
    @patch("backend.app.services.agents.llm.complete", new_callable=AsyncMock)
    async def test_additional_findings_are_cleaned(self, mock_complete):
        mock_complete.return_value = json.dumps(
            {
                "explanations": [],
                "additional": [
                    {
                        "severity": "high",
                        "title": "Password in env",
                        "resource": "web",
                        "file": "docker-compose.yml",
                    },
                    {
                        "severity": "LOW",
                        "title": "Made-up file",
                        "file": "../etc/passwd",
                    },
                    {"severity": "EXTREME", "title": "Odd severity"},
                    {"description": "no title, dropped"},
                    "junk",
                ],
            }
        )
        _, additional = await review_findings(
            CHOICE, {"docker-compose.yml": "code"}, [], 25
        )
        assert [(a["title"], a["severity"], a["file"]) for a in additional] == [
            ("Password in env", "HIGH", "docker-compose.yml"),
            ("Made-up file", "LOW", ""),
            ("Odd severity", "MEDIUM", ""),
        ]
        assert all(
            a["source"] == "review" and a["check_id"] is None for a in additional
        )

    @pytest.mark.asyncio
    @patch("backend.app.services.agents.llm.complete", new_callable=AsyncMock)
    async def test_fenced_json_is_accepted(self, mock_complete):
        mock_complete.return_value = (
            '```json\n{"explanations": [], "additional": []}\n```'
        )
        explained, _ = await review_findings(
            CHOICE, {"main.tf": "x"}, [finding("A", "LOW")], 25
        )
        assert len(explained) == 1

    @pytest.mark.asyncio
    @patch("backend.app.services.agents.llm.complete", new_callable=AsyncMock)
    async def test_unreadable_answer_raises(self, mock_complete):
        mock_complete.return_value = "This is not JSON!"
        with pytest.raises(AuditError):
            await review_findings(
                CHOICE, {"main.tf": "code"}, [finding("CKV_AWS_20", "CRITICAL")], 25
            )

    @pytest.mark.asyncio
    @patch("backend.app.services.agents.llm.complete", new_callable=AsyncMock)
    async def test_long_lists_are_capped(self, mock_complete):
        mock_complete.return_value = '{"explanations": [], "additional": []}'
        findings = [finding(f"CKV_X_{i}", "LOW") for i in range(15)]
        explained, _ = await review_findings(CHOICE, {"main.tf": "code"}, findings, 10)
        prompt = mock_complete.call_args.args[2]
        assert "[10]" in prompt
        assert "[11]" not in prompt
        assert len(explained) == len(findings)


class TestSelectReviewFiles:

    def test_files_with_serious_findings_go_first(self):
        files = {"a.tf": "x" * 50, "b.tf": "y" * 50, "c.tf": "z" * 50}
        findings = [
            finding("CKV_1", "LOW", file="b.tf"),
            finding("CKV_2", "CRITICAL", file="c.tf"),
        ]
        included, left_out = select_review_files(files, findings, budget=110)
        assert list(included) == ["c.tf", "b.tf"]
        assert left_out == ["a.tf"]

    def test_everything_fits(self):
        included, left_out = select_review_files(
            {"a.tf": "1", "b.tf": "2"}, [], budget=100
        )
        assert set(included) == {"a.tf", "b.tf"}
        assert left_out == []


class TestOtherModelCalls:

    @pytest.mark.asyncio
    @patch("backend.app.services.agents.llm.complete", new_callable=AsyncMock)
    async def test_patch_generation_strips_fence(self, mock_complete):
        mock_complete.return_value = '```hcl\nresource "x" "y" { acl = "private" }\n```'
        result = await run_patch_generation(
            CHOICE,
            "original",
            [{"title": "Public"}],
            [{"description": "old", "patched_code": "x"}],
            file_name="modules/s3/main.tf",
        )
        assert result.strip() == 'resource "x" "y" { acl = "private" }'
        assert "File: modules/s3/main.tf" in mock_complete.call_args.args[2]
        assert "json_schema" not in mock_complete.call_args.kwargs

    @pytest.mark.asyncio
    @patch(
        "backend.app.services.agents.llm.complete_with_image", new_callable=AsyncMock
    )
    async def test_diagram_passes_image_and_type(self, mock_vision):
        mock_vision.return_value = "matches"
        assert (
            await run_diagram_analysis(CHOICE, "tf code", b"img", "image/webp")
            == "matches"
        )
        choice, _system, prompt, image, mime = mock_vision.call_args.args
        assert (choice, image, mime) == (CHOICE, b"img", "image/webp")
        assert "tf code" in prompt


class TestIndexFindings:

    @pytest.mark.asyncio
    @patch(
        "backend.app.services.agents.embeddings.embed_documents", new_callable=AsyncMock
    )
    async def test_batches_embeddings_and_saves_once(self, mock_embed):
        mock_embed.return_value = [[0.1] * 384] * 2
        db = MagicMock()
        db.save_vulnerabilities = AsyncMock()

        await index_findings(
            db,
            "ws",
            "a1",
            "project",
            {"main.tf": "code"},
            {"main.tf": "patched"},
            [
                finding("CKV_AWS_20", "CRITICAL", "Public read"),
                finding("CKV_AWS_21", "LOW", file="other.tf"),
            ],
        )

        mock_embed.assert_awaited_once()
        rows = db.save_vulnerabilities.call_args.args[0]
        assert [r["vulnerability_type"] for r in rows] == ["Public read", "Check"]
        assert rows[0]["workspace_id"] == "ws"
        # Unexplained findings fall back to the title for search.
        assert rows[0]["description"] == "Public read"
        assert (rows[0]["original_code"], rows[0]["patched_code"]) == (
            "code",
            "patched",
        )
        assert (rows[1]["file_name"], rows[1]["original_code"]) == ("other.tf", "")

    @pytest.mark.asyncio
    @patch(
        "backend.app.services.agents.embeddings.embed_documents", new_callable=AsyncMock
    )
    async def test_embedding_failure_is_not_fatal(self, mock_embed):
        mock_embed.side_effect = RuntimeError("model files missing")
        db = MagicMock()
        db.save_vulnerabilities = AsyncMock()
        await index_findings(
            db, "ws", "a1", "main.tf", {"main.tf": "c"}, {}, [finding("A", "LOW")]
        )
        db.save_vulnerabilities.assert_not_called()
