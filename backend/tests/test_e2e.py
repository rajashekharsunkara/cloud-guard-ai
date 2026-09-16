import uuid
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import AsyncClient

from backend.app.core.aws import get_s3_client
from backend.app.core.config import settings
from backend.app.main import app
from backend.app.services.checkov import CheckovReport
from backend.app.services.storage import StorageService

SSH_FINDING = {
    "source": "checkov",
    "check_id": "CKV_AWS_24",
    "severity": "CRITICAL",
    "title": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
    "description": "",
    "remediation": "",
    "resource": "aws_security_group.web_sg",
    "file": "e2e_test.tf",
    "line_start": 1,
    "line_end": 1,
}


class TestEndToEndWorkflow:

    @pytest.mark.asyncio
    @patch("backend.app.services.agents._get_embedding_model")
    @patch("backend.app.services.agents.run_patch_generation", new_callable=AsyncMock)
    @patch("backend.app.services.agents.review_findings", new_callable=AsyncMock)
    @patch("backend.app.services.pipeline.run_checkov", new_callable=AsyncMock)
    async def test_complete_audit_search_history_flow(
        self, mock_checkov, mock_review, mock_patch, mock_embedding_model, monkeypatch
    ):
        # A fresh salt gives this run its own free-scan counter.
        monkeypatch.setattr(settings, "usage_hash_salt", uuid.uuid4().hex)

        async with AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Health check
            health_resp = await client.get("/api/health")
            assert health_resp.status_code == 200
            health_data = health_resp.json()
            assert health_data["status"] == "healthy"
            assert health_data["database"] == "connected"
            assert health_data["s3"] == "connected"

            usage = (await client.get("/api/usage")).json()
            assert usage["explanations_available"] is True
            assert usage["free_scans_left"] == settings.free_llm_scans_per_day

            # Configure mocks
            mock_checkov.return_value = CheckovReport(
                findings=[SSH_FINDING],
                covered_files=["e2e_test.tf"],
                frameworks=["terraform"],
                version="3.3.17",
            )
            mock_review.return_value = (
                [dict(SSH_FINDING, description="Port 22 is open to the internet")],
                [],
            )
            mock_patch.return_value = 'resource "aws_security_group" "web_sg" {\n  # FIXED: restricted port 22\n}'
            mock_embedding_model.return_value.aembed_documents = AsyncMock(
                side_effect=lambda texts: [[0.05] * 768 for _ in texts]
            )
            mock_embedding_model.return_value.aembed_query = AsyncMock(
                return_value=[0.05] * 768
            )

            # Run audit
            audit_payload = {
                "file_name": "e2e_test.tf",
                "iac_content": (
                    'resource "aws_security_group" "web_sg" { '
                    'ingress { from_port = 22 cidr_blocks = ["0.0.0.0/0"] } }'
                ),
            }

            audit_resp = await client.post("/api/audit", json=audit_payload)
            assert audit_resp.status_code == 200
            audit_data = audit_resp.json()

            audit_id = audit_data["audit_id"]
            assert audit_data["file_name"] == "e2e_test.tf"
            assert audit_data["security_score"] == 69  # one critical Checkov finding
            assert len(audit_data["vulnerabilities"]) == 1
            assert audit_data["vulnerabilities"][0]["check_id"] == "CKV_AWS_24"
            assert "FIXED" in audit_data["patched_code"]
            assert audit_data["analysis"]["mode"] == "free"
            assert (
                audit_data["analysis"]["free_scans_left"]
                == settings.free_llm_scans_per_day - 1
            )

            # Verify S3 storage
            storage = StorageService()
            scans = storage.list_files(prefix="scans")
            scan_keys = [item["key"] for item in scans]
            uploaded_scan_key = [
                k for k in scan_keys if audit_id in k and "e2e_test.tf" in k
            ]
            assert len(uploaded_scan_key) == 1

            uploaded_content = storage.download_file(uploaded_scan_key[0])
            assert "ingress" in uploaded_content

            patched_keys = [
                item["key"] for item in storage.list_files(prefix="patches")
            ]
            uploaded_patched_key = [
                k for k in patched_keys if audit_id in k and "e2e_test.tf" in k
            ]
            assert len(uploaded_patched_key) == 1
            patched_content = storage.download_file(uploaded_patched_key[0])
            assert "FIXED" in patched_content

            # Semantic search
            search_payload = {"query": "Port 22 is open to the internet", "limit": 10}
            search_resp = await client.post("/api/search", json=search_payload)
            assert search_resp.status_code == 200
            search_data = search_resp.json()
            assert search_data["total"] >= 1

            our_results = [
                r for r in search_data["results"] if r["audit_id"] == audit_id
            ]
            assert len(our_results) == 1
            assert our_results[0]["vulnerability_type"] == SSH_FINDING["title"]

            # Audit history
            history_resp = await client.get("/api/history")
            assert history_resp.status_code == 200
            history_data = history_resp.json()

            history_audit_ids = [item["audit_id"] for item in history_data]
            assert audit_id in history_audit_ids

            detail_resp = await client.get(f"/api/history/{audit_id}")
            assert detail_resp.status_code == 200
            detail = detail_resp.json()
            assert detail["original_code"] == audit_payload["iac_content"]
            assert detail["analysis"]["covered_files"] == ["e2e_test.tf"]

        # A different browser gets its own workspace and sees none of it.
        async with AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as stranger:
            history = (await stranger.get("/api/history")).json()
            assert audit_id not in [item["audit_id"] for item in history]
            assert (await stranger.get(f"/api/history/{audit_id}")).status_code == 404

            search = (await stranger.post("/api/search", json=search_payload)).json()
            assert all(r["audit_id"] != audit_id for r in search["results"])

        # Cleanup
        s3_client = get_s3_client()
        s3_client.delete_object(
            Bucket=settings.s3_bucket_name, Key=uploaded_scan_key[0]
        )
        s3_client.delete_object(
            Bucket=settings.s3_bucket_name, Key=uploaded_patched_key[0]
        )

        async with AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            cookies=client.cookies,
        ) as owner:
            assert (await owner.delete("/api/history")).status_code == 204
            assert (await owner.get("/api/history")).json() == []
