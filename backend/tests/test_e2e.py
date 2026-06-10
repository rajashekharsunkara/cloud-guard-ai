import pytest
from unittest.mock import patch
import httpx
from httpx import AsyncClient

from backend.app.main import app
from backend.app.services.storage import StorageService
from backend.app.core.aws import get_s3_client
from backend.app.core.config import settings


class TestEndToEndWorkflow:

    @pytest.mark.asyncio
    @patch("backend.app.routers.auditor.generate_embedding")
    @patch("backend.app.services.agents.run_security_audit")
    @patch("backend.app.services.agents.run_patch_generation")
    @patch("backend.app.services.agents.generate_embedding")
    async def test_complete_audit_search_history_flow(
        self, mock_embedding_agents, mock_patch, mock_scan, mock_embedding_router
    ):
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

            # Configure mocks
            mock_scan.return_value = [
                {
                    "title": "Unsecured SSH Port",
                    "severity": "CRITICAL",
                    "description": "Port 22 is open to the internet",
                    "resource": "aws_security_group.web_sg",
                    "remediation": "Restrict access to specific IPs",
                }
            ]
            mock_patch.return_value = 'resource "aws_security_group" "web_sg" {\n  # FIXED: restricted port 22\n}'
            mock_embedding_agents.return_value = [0.05] * 768
            mock_embedding_router.return_value = [0.05] * 768

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
            assert audit_data["security_score"] == 75  # 100 - 25 (CRITICAL)
            assert len(audit_data["vulnerabilities"]) == 1
            assert audit_data["vulnerabilities"][0]["severity"] == "CRITICAL"
            assert "FIXED" in audit_data["patched_code"]

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
            assert our_results[0]["vulnerability_type"] == "Unsecured SSH Port"

            # Audit history
            history_resp = await client.get("/api/history")
            assert history_resp.status_code == 200
            history_data = history_resp.json()

            history_audit_ids = [item["audit_id"] for item in history_data]
            assert audit_id in history_audit_ids

            # Cleanup
            s3_client = get_s3_client()
            s3_client.delete_object(
                Bucket=settings.s3_bucket_name, Key=uploaded_scan_key[0]
            )
            s3_client.delete_object(
                Bucket=settings.s3_bucket_name, Key=uploaded_patched_key[0]
            )

            from sqlalchemy import delete
            from backend.app.core.database import async_session
            from backend.app.services.db_service import Vulnerability

            async with async_session() as session:
                await session.execute(
                    delete(Vulnerability).where(Vulnerability.audit_id == audit_id)
                )
                await session.commit()
