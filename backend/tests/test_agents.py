import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from langchain_core.messages import AIMessage

from backend.app.services.agents import (
    run_security_audit,
    run_patch_generation,
    run_diagram_analysis,
    run_full_audit,
)


class TestAgentsUnit:

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_groq_llm")
    async def test_run_security_audit_success(self, mock_get_llm):
        mock_llm = AsyncMock()
        mock_get_llm.return_value = mock_llm

        findings = [
            {
                "title": "Exposed S3 Bucket",
                "severity": "CRITICAL",
                "description": "Bucket public",
                "resource": "aws_s3_bucket.lake",
            }
        ]
        mock_llm.ainvoke.return_value = AIMessage(content=json.dumps(findings))

        iac = 'resource "aws_s3_bucket" "lake" {}'
        result = await run_security_audit(iac)

        assert len(result) == 1
        assert result[0]["title"] == "Exposed S3 Bucket"
        assert result[0]["severity"] == "CRITICAL"
        mock_llm.ainvoke.assert_called_once()

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_groq_llm")
    async def test_run_security_audit_json_code_block(self, mock_get_llm):
        """Markdown-wrapped JSON responses should be handled correctly."""
        mock_llm = AsyncMock()
        mock_get_llm.return_value = mock_llm

        response_content = "```json\n" + json.dumps([{"title": "Low Issue", "severity": "LOW"}]) + "\n```"
        mock_llm.ainvoke.return_value = AIMessage(content=response_content)

        result = await run_security_audit("dummy config")
        assert len(result) == 1
        assert result[0]["title"] == "Low Issue"

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_groq_llm")
    async def test_run_security_audit_malformed_json_fallback(self, mock_get_llm):
        mock_llm = AsyncMock()
        mock_get_llm.return_value = mock_llm
        mock_llm.ainvoke.return_value = AIMessage(content="This is not JSON!")

        result = await run_security_audit("dummy config")
        assert result == []

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_groq_llm")
    async def test_run_patch_generation(self, mock_get_llm):
        mock_llm = AsyncMock()
        mock_get_llm.return_value = mock_llm
        mock_llm.ainvoke.return_value = AIMessage(content="resource \"aws_s3_bucket\" \"lake\" { acl = \"private\" }")

        vulns = [{"title": "Exposed S3 Bucket", "severity": "CRITICAL"}]
        similar = [{"description": "S3 public", "patched_code": "acl = private"}]

        result = await run_patch_generation("original code", vulns, similar)
        assert "private" in result
        mock_llm.ainvoke.assert_called_once()

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_gemini_llm")
    async def test_run_diagram_analysis(self, mock_get_llm):
        mock_llm = AsyncMock()
        mock_get_llm.return_value = mock_llm
        mock_llm.ainvoke.return_value = AIMessage(content="Visual verification: code matches diagram.")

        result = await run_diagram_analysis("terraform code", b"fake_image_bytes")
        assert "verification" in result
        mock_llm.ainvoke.assert_called_once()

    @pytest.mark.asyncio
    @patch("backend.app.services.agents.generate_embedding")
    @patch("backend.app.services.agents.run_patch_generation")
    @patch("backend.app.services.agents.run_security_audit")
    async def test_run_full_audit_orchestration(self, mock_scan, mock_patch, mock_embedding):
        mock_scan.return_value = [{"title": "Insecure Port", "severity": "HIGH", "description": "Port 22 open"}]
        mock_patch.return_value = "patched configuration code"
        mock_embedding.return_value = [0.2] * 768

        mock_db = MagicMock()
        mock_db.search_similar = AsyncMock(
            return_value=[{"description": "Past port patch", "patched_code": "close port"}]
        )
        mock_db.save_vulnerability = AsyncMock()

        result = await run_full_audit(
            iac_content="insecure config code",
            file_name="deployment.tf",
            db_service=mock_db,
        )

        assert result["security_score"] == 85  # 100 - 15 (HIGH)
        assert len(result["vulnerabilities"]) == 1
        assert result["patched_code"] == "patched configuration code"
        assert result["similar_past_audits"] == ["Past port patch"]

        mock_scan.assert_called_once_with("insecure config code")
        mock_db.search_similar.assert_called_once()
        mock_db.save_vulnerability.assert_called_once()
