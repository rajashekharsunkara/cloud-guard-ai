import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from backend.app.core.config import settings
from backend.app.services.agents import (
    AuditError,
    index_findings,
    review_findings,
    run_diagram_analysis,
    run_patch_generation,
    select_review_files,
)


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


def model_returns(mock_get_llm, content):
    llm = AsyncMock()
    llm.ainvoke.return_value = AIMessage(content=content)
    mock_get_llm.return_value = llm
    return llm


class TestReviewFindings:

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_groq_llm")
    async def test_explanations_are_matched_by_ref(self, mock_get_llm):
        findings = [
            finding("CKV_AWS_21", "MEDIUM", "Versioning"),
            finding("CKV_AWS_20", "CRITICAL", "Public read"),
        ]
        # Findings are ranked by severity before numbering, so ref 1 is the
        # critical one even though it came second.
        llm = model_returns(
            mock_get_llm,
            json.dumps(
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
            ),
        )

        explained, additional = await review_findings({"main.tf": "code"}, findings)

        assert [f["check_id"] for f in explained] == ["CKV_AWS_20", "CKV_AWS_21"]
        assert explained[0]["description"] == "Anyone can list it"
        assert explained[1]["remediation"] == "enable versioning"
        assert additional == []
        mock_get_llm.assert_called_once_with(json_mode=True)
        prompt = llm.ainvoke.call_args.args[0][1].content
        assert "[1] CKV_AWS_20 (CRITICAL)" in prompt
        assert "File: main.tf\n---\ncode\n---" in prompt

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_groq_llm")
    async def test_additional_findings_are_cleaned(self, mock_get_llm):
        model_returns(
            mock_get_llm,
            json.dumps(
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
            ),
        )
        _, additional = await review_findings({"docker-compose.yml": "code"}, [])
        assert [(a["title"], a["severity"], a["file"]) for a in additional] == [
            ("Password in env", "HIGH", "docker-compose.yml"),
            ("Made-up file", "LOW", ""),
            ("Odd severity", "MEDIUM", ""),
        ]
        assert all(
            a["source"] == "review" and a["check_id"] is None for a in additional
        )

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_groq_llm")
    async def test_unreadable_answer_raises(self, mock_get_llm):
        model_returns(mock_get_llm, "This is not JSON!")
        with pytest.raises(AuditError):
            await review_findings(
                {"main.tf": "code"}, [finding("CKV_AWS_20", "CRITICAL")]
            )

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_groq_llm")
    async def test_long_lists_are_capped(self, mock_get_llm):
        llm = model_returns(mock_get_llm, '{"explanations": [], "additional": []}')
        cap = settings.llm_max_explained_findings
        findings = [finding(f"CKV_X_{i}", "LOW") for i in range(cap + 5)]
        explained, _ = await review_findings({"main.tf": "code"}, findings)
        prompt = llm.ainvoke.call_args.args[0][1].content
        assert f"[{cap}]" in prompt
        assert f"[{cap + 1}]" not in prompt
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
        included, left_out = select_review_files({"a.tf": "1", "b.tf": "2"}, [])
        assert set(included) == {"a.tf", "b.tf"}
        assert left_out == []


class TestOtherModelCalls:

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_groq_llm")
    async def test_patch_generation_strips_fence(self, mock_get_llm):
        llm = model_returns(
            mock_get_llm, '```hcl\nresource "x" "y" { acl = "private" }\n```'
        )
        result = await run_patch_generation(
            "original",
            [{"title": "Public"}],
            [{"description": "old", "patched_code": "x"}],
            file_name="modules/s3/main.tf",
        )
        assert result.strip() == 'resource "x" "y" { acl = "private" }'
        assert "File: modules/s3/main.tf" in llm.ainvoke.call_args.args[0][1].content

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_gemini_llm")
    async def test_diagram_uses_real_mime_type(self, mock_get_llm):
        llm = model_returns(mock_get_llm, "matches")
        assert await run_diagram_analysis("tf", b"img", "image/webp") == "matches"
        parts = llm.ainvoke.call_args.args[0][0].content
        assert parts[1]["image_url"]["url"].startswith("data:image/webp;base64,")


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
