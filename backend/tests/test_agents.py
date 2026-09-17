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
        compose = (
            "services:\n  web:\n    image: app\n    environment:\n      PASSWORD: x\n"
        )
        _, additional = await review_findings(
            CHOICE, {"docker-compose.yml": compose}, [], 25
        )
        assert [(a["title"], a["severity"], a["file"]) for a in additional] == [
            ("Password in env", "HIGH", "docker-compose.yml"),
            ("Made-up file", "LOW", ""),
            # No file named, but only one was reviewed.
            ("Odd severity", "MEDIUM", "docker-compose.yml"),
        ]
        assert (additional[0]["line_start"], additional[0]["line_end"]) == (2, 5)
        assert "line_start" not in additional[1]
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


class TestLocateResource:

    TERRAFORM = """provider "aws" {}

resource "aws_s3_bucket" "logs" {
  bucket = "x"
  tags = {
    Team = "a"
  }
}

data "aws_iam_policy_document" "read" {
  statement {}
}

module "vpc" {
  source = "./vpc"
}
"""

    COMPOSE = """services:
  web:
    image: app
    ports:
      - "80:80"

  worker:
    image: worker
    privileged: true
volumes:
  data:
"""

    KUBERNETES = """apiVersion: v1
kind: Service
metadata:
  name: web
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 2
"""

    @pytest.mark.parametrize(
        "content, resource, expected",
        [
            (TERRAFORM, "aws_s3_bucket.logs", (3, 8)),
            (TERRAFORM, "data.aws_iam_policy_document.read", (10, 12)),
            (TERRAFORM, "module.vpc", (14, 16)),
            (COMPOSE, "worker", (7, 9)),
            (COMPOSE, "services.web", (2, 5)),
            (KUBERNETES, "api", (6, 11)),
            (KUBERNETES, "Deployment/api", (6, 11)),
            (KUBERNETES, "kubernetes Deployment api", (6, 11)),
            (COMPOSE, "docker-compose service worker", (7, 9)),
        ],
    )
    def test_finds_the_named_resource(self, content, resource, expected):
        from backend.app.services.agents import locate_resource

        assert locate_resource(content, resource) == expected

    @pytest.mark.parametrize("resource", ["", "aws_s3_bucket.missing", "nothing here"])
    def test_unknown_names_are_not_placed(self, resource):
        from backend.app.services.agents import locate_resource

        assert locate_resource(self.TERRAFORM, resource) is None


class TestPatchPrompt:

    def test_findings_are_capped_most_severe_first(self):
        from backend.app.services.agents import format_patch_findings

        findings = [
            {"severity": "LOW", "check_id": "CKV_LOW", "title": "low " * 20},
            {
                "severity": "CRITICAL",
                "check_id": "CKV_CRIT",
                "title": "Public bucket",
                "remediation": "Set acl to private",
            },
        ] + [
            {"severity": "MEDIUM", "check_id": f"CKV_M{i}", "title": "medium " * 10}
            for i in range(20)
        ]
        text = format_patch_findings(findings, max_chars=400)
        assert text.splitlines()[0].startswith("- [CRITICAL] CKV_CRIT: Public bucket")
        assert "Fix: Set acl to private" in text
        assert "CKV_LOW" not in text
        assert text.splitlines()[-1].startswith("- ...and ")
        assert len(text) < 600

    def test_earlier_fixes_are_reduced_to_changed_lines(self):
        from backend.app.services.agents import format_earlier_fixes

        patched = "\n".join(
            ['resource "x" "y" {']
            + ["  unchanged = true"] * 2000
            + ['  acl = "private" # FIXED: no public ACL', "}"]
        )
        similar = [
            {"description": "Public ACL", "patched_code": patched},
            {"description": "Same file again", "patched_code": patched},
            {"description": "No marked lines", "patched_code": "a = 1"},
        ]
        text = format_earlier_fixes(similar, max_chars=1500)
        assert 'acl = "private" # FIXED: no public ACL' in text
        assert "unchanged" not in text
        assert text.count("Issue:") == 1
        assert len(text) < 300

    def test_no_usable_fixes(self):
        from backend.app.services.agents import format_earlier_fixes

        assert format_earlier_fixes([], 1500) == "No earlier fixes."
        assert (
            format_earlier_fixes([{"patched_code": "x = 1"}], 1500)
            == "No earlier fixes."
        )
