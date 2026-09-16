from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import get_db

client = TestClient(app)


class TestAPIIntegration:

    @patch("backend.app.routers.auditor.StorageService")
    def test_health_endpoint_healthy(self, mock_storage_class):
        mock_storage = MagicMock()
        mock_storage.bucket = "test-bucket"
        mock_storage.client = MagicMock()
        mock_storage.client.head_bucket.return_value = {}
        mock_storage_class.return_value = mock_storage

        mock_db = AsyncMock()
        mock_db.execute.return_value = MagicMock()

        async def override_get_db():
            yield mock_db

        app.dependency_overrides[get_db] = override_get_db

        try:
            response = client.get("/api/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["database"] == "connected"
            assert data["s3"] == "connected"
        finally:
            app.dependency_overrides.clear()

    @patch("backend.app.routers.auditor.StorageService")
    def test_health_endpoint_degraded(self, mock_storage_class):
        mock_storage = MagicMock()
        mock_storage.client.head_bucket.side_effect = Exception("S3 error")
        mock_storage_class.return_value = mock_storage

        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("DB connection error")

        async def override_get_db():
            yield mock_db

        app.dependency_overrides[get_db] = override_get_db

        try:
            response = client.get("/api/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "degraded"
            assert data["database"] == "disconnected"
            assert data["s3"] == "disconnected"
        finally:
            app.dependency_overrides.clear()

    @patch("backend.app.routers.auditor.run_to_completion")
    def test_audit_endpoint_success(self, mock_run):
        mock_run.return_value = {
            "audit_id": "test_audit_id",
            "file_name": "main.tf",
            "security_score": 69,
            "vulnerabilities": [
                {
                    "source": "checkov",
                    "check_id": "CKV_AWS_20",
                    "title": "S3 Bucket has an ACL defined which allows public READ access",
                    "severity": "CRITICAL",
                    "description": "S3 bucket is public",
                    "resource": "aws_s3_bucket.main",
                    "file": "main.tf",
                    "line_start": 1,
                    "line_end": 3,
                }
            ],
            "patched_code": 'resource "aws_s3_bucket" "main" { acl = "private" }',
            "similar_past_audits": [],
            "diagram_analysis": None,
            "analysis": {
                "mode": "free",
                "covered_files": ["main.tf"],
                "free_scans_left": 4,
            },
        }

        async def override_get_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = override_get_db
        payload = {
            "iac_content": 'resource "aws_s3_bucket" "main" { acl = "public-read" }',
            "file_name": "main.tf",
        }

        try:
            response = client.post("/api/audit", json=payload)
            assert response.status_code == 200
            data = response.json()
            assert data["audit_id"] == "test_audit_id"
            assert data["security_score"] == 69
            assert data["vulnerabilities"][0]["check_id"] == "CKV_AWS_20"
            assert data["analysis"]["mode"] == "free"
        finally:
            app.dependency_overrides.clear()

    @patch("backend.app.routers.auditor.run_to_completion")
    def test_audit_endpoint_scanner_failure(self, mock_run):
        from backend.app.services.pipeline import ScanFailed

        mock_run.side_effect = ScanFailed("The static checks failed to run")

        async def override_get_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = override_get_db
        try:
            response = client.post(
                "/api/audit", json={"iac_content": "resource {} x y z"}
            )
            assert response.status_code == 502
            assert response.json()["detail"] == "The static checks failed to run"
        finally:
            app.dependency_overrides.clear()

    @patch("backend.app.routers.auditor.generate_embedding")
    @patch("backend.app.routers.auditor.DBService")
    def test_search_endpoint_success(self, mock_db_class, mock_gen_embedding):
        mock_gen_embedding.return_value = [0.1] * 768
        mock_db = MagicMock()
        mock_db.search_similar = AsyncMock(
            return_value=[
                {
                    "audit_id": "audit123",
                    "file_name": "main.tf",
                    "vulnerability_type": "Exposed S3",
                    "description": "Exposed S3 bucket finding",
                    "patched_code": "acl = private",
                    "similarity_score": 0.88,
                }
            ]
        )
        mock_db_class.return_value = mock_db

        mock_scoped_db = AsyncMock()

        async def override_get_db():
            yield mock_scoped_db

        app.dependency_overrides[get_db] = override_get_db

        payload = {"query": "exposed S3 bucket", "limit": 3}
        try:
            response = client.post("/api/search", json=payload)
            assert response.status_code == 200
            data = response.json()
            assert data["query"] == "exposed S3 bucket"
            assert data["total"] == 1
            assert len(data["results"]) == 1
            assert data["results"][0]["vulnerability_type"] == "Exposed S3"
            assert data["results"][0]["similarity_score"] == 0.88
        finally:
            app.dependency_overrides.clear()

    @patch("backend.app.routers.auditor.DBService")
    def test_history_endpoint_success(self, mock_db_class):
        mock_db = MagicMock()
        mock_db.list_audits = AsyncMock(
            return_value=[
                {
                    "audit_id": "audit123",
                    "file_name": "main.tf",
                    "security_score": 85,
                    "finding_count": 1,
                    "severity_counts": {"HIGH": 1},
                    "has_diagram": False,
                    "created_at": "2026-06-08T09:00:00",
                }
            ]
        )
        mock_db_class.return_value = mock_db

        mock_scoped_db = AsyncMock()

        async def override_get_db():
            yield mock_scoped_db

        app.dependency_overrides[get_db] = override_get_db

        try:
            response = client.get("/api/history")
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 1
            assert data[0]["audit_id"] == "audit123"
            assert data[0]["severity_counts"] == {"HIGH": 1}
        finally:
            app.dependency_overrides.clear()
