import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime


class TestSchemaValidation:

    def test_audit_request_valid(self):
        from backend.app.schemas.auditor import AuditRequest
        req = AuditRequest(
            iac_content='resource "aws_s3_bucket" "test" { bucket = "my-bucket" }',
            file_name="main.tf",
        )
        assert req.file_name == "main.tf"
        assert len(req.iac_content) > 10

    def test_audit_request_default_filename(self):
        from backend.app.schemas.auditor import AuditRequest
        req = AuditRequest(
            iac_content='resource "aws_s3_bucket" "test" { bucket = "x" }',
        )
        assert req.file_name == "main.tf"

    def test_audit_request_too_short(self):
        from pydantic import ValidationError
        from backend.app.schemas.auditor import AuditRequest
        with pytest.raises(ValidationError):
            AuditRequest(iac_content="short")

    def test_audit_request_empty(self):
        from pydantic import ValidationError
        from backend.app.schemas.auditor import AuditRequest
        with pytest.raises(ValidationError):
            AuditRequest(iac_content="")

    def test_search_request_valid(self):
        from backend.app.schemas.auditor import SearchRequest
        req = SearchRequest(query="exposed S3 bucket", limit=5)
        assert req.query == "exposed S3 bucket"
        assert req.limit == 5

    def test_search_request_default_limit(self):
        from backend.app.schemas.auditor import SearchRequest
        req = SearchRequest(query="test query here")
        assert req.limit == 5

    def test_search_request_limit_too_low(self):
        from pydantic import ValidationError
        from backend.app.schemas.auditor import SearchRequest
        with pytest.raises(ValidationError):
            SearchRequest(query="test", limit=0)

    def test_search_request_limit_too_high(self):
        from pydantic import ValidationError
        from backend.app.schemas.auditor import SearchRequest
        with pytest.raises(ValidationError):
            SearchRequest(query="test", limit=25)

    def test_search_request_query_too_short(self):
        from pydantic import ValidationError
        from backend.app.schemas.auditor import SearchRequest
        with pytest.raises(ValidationError):
            SearchRequest(query="ab")

    def test_vulnerability_item(self):
        from backend.app.schemas.auditor import VulnerabilityItem
        vuln = VulnerabilityItem(
            severity="HIGH",
            title="Public S3 Bucket",
            description="S3 bucket is publicly accessible",
            resource="aws_s3_bucket.main",
            remediation="Add public access block",
        )
        assert vuln.severity == "HIGH"
        assert vuln.title == "Public S3 Bucket"

    def test_vulnerability_item_defaults(self):
        from backend.app.schemas.auditor import VulnerabilityItem
        vuln = VulnerabilityItem(
            severity="LOW",
            title="Minor Issue",
            description="Something minor",
        )
        assert vuln.resource == ""
        assert vuln.remediation == ""

    def test_audit_result_score_bounds(self):
        from pydantic import ValidationError
        from backend.app.schemas.auditor import AuditResult
        with pytest.raises(ValidationError):
            AuditResult(
                audit_id="test123",
                file_name="main.tf",
                security_score=150,
            )
        with pytest.raises(ValidationError):
            AuditResult(
                audit_id="test123",
                file_name="main.tf",
                security_score=-10,
            )

    def test_audit_result_valid(self):
        from backend.app.schemas.auditor import AuditResult
        result = AuditResult(
            audit_id="abc123",
            file_name="main.tf",
            security_score=75,
            vulnerabilities=[],
            patched_code="",
        )
        assert result.audit_id == "abc123"
        assert result.security_score == 75

    def test_health_response_defaults(self):
        from backend.app.schemas.auditor import HealthResponse
        health = HealthResponse()
        assert health.status == "healthy"
        assert health.database == "connected"
        assert health.s3 == "connected"

    def test_search_response_empty(self):
        from backend.app.schemas.auditor import SearchResponse
        resp = SearchResponse(query="test", results=[], total=0)
        assert resp.total == 0
        assert resp.results == []

    def test_search_result_item(self):
        from backend.app.schemas.auditor import SearchResultItem
        item = SearchResultItem(
            audit_id="x123",
            file_name="main.tf",
            vulnerability_type="Exposed S3",
            description="Bucket is public",
            patched_code='bucket = "private"',
            similarity_score=0.95,
        )
        assert item.similarity_score == 0.95


class TestSecurityScoring:

    @pytest.mark.asyncio
    async def test_perfect_score(self):
        from backend.app.services.agents import calculate_security_score
        score = await calculate_security_score([])
        assert score == 100

    @pytest.mark.asyncio
    async def test_critical_penalty(self):
        from backend.app.services.agents import calculate_security_score
        vulns = [{"severity": "CRITICAL", "title": "Test"}]
        score = await calculate_security_score(vulns)
        assert score == 75

    @pytest.mark.asyncio
    async def test_high_penalty(self):
        from backend.app.services.agents import calculate_security_score
        vulns = [{"severity": "HIGH", "title": "Test"}]
        score = await calculate_security_score(vulns)
        assert score == 85

    @pytest.mark.asyncio
    async def test_medium_penalty(self):
        from backend.app.services.agents import calculate_security_score
        vulns = [{"severity": "MEDIUM", "title": "Test"}]
        score = await calculate_security_score(vulns)
        assert score == 92

    @pytest.mark.asyncio
    async def test_low_penalty(self):
        from backend.app.services.agents import calculate_security_score
        vulns = [{"severity": "LOW", "title": "Test"}]
        score = await calculate_security_score(vulns)
        assert score == 97

    @pytest.mark.asyncio
    async def test_mixed_severities(self):
        from backend.app.services.agents import calculate_security_score
        vulns = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ]
        score = await calculate_security_score(vulns)
        # 100 - 25 - 15 - 8 - 3 = 49
        assert score == 49

    @pytest.mark.asyncio
    async def test_score_floor_at_zero(self):
        from backend.app.services.agents import calculate_security_score
        vulns = [{"severity": "CRITICAL"}] * 10
        score = await calculate_security_score(vulns)
        assert score == 0

    @pytest.mark.asyncio
    async def test_case_insensitive_severity(self):
        from backend.app.services.agents import calculate_security_score
        vulns = [{"severity": "critical"}]
        score = await calculate_security_score(vulns)
        assert score == 75

    @pytest.mark.asyncio
    async def test_unknown_severity_defaults_to_low(self):
        from backend.app.services.agents import calculate_security_score
        vulns = [{"severity": "UNKNOWN"}]
        score = await calculate_security_score(vulns)
        assert score == 97

    @pytest.mark.asyncio
    async def test_missing_severity_defaults_to_low(self):
        from backend.app.services.agents import calculate_security_score
        vulns = [{"title": "Test"}]
        score = await calculate_security_score(vulns)
        assert score == 97


class TestPromptLoading:

    def test_security_rules_prompt_exists(self):
        from backend.app.services.agents import _load_prompt
        content = _load_prompt("security_rules.txt")
        assert "IaC Configuration to Audit" in content
        assert "{iac_content}" in content

    def test_patch_generator_prompt_exists(self):
        from backend.app.services.agents import _load_prompt
        content = _load_prompt("patch_generator.txt")
        assert "{iac_content}" in content
        assert "{vulnerabilities}" in content
        assert "{similar_patches}" in content

    def test_vision_audit_prompt_exists(self):
        from backend.app.services.agents import _load_prompt
        content = _load_prompt("vision_audit.txt")
        assert "STRUCTURAL VERIFICATION" in content
        assert "{iac_content}" in content

    def test_nonexistent_prompt_raises(self):
        from backend.app.services.agents import _load_prompt
        with pytest.raises(FileNotFoundError):
            _load_prompt("nonexistent_prompt.txt")


class TestConfiguration:

    def test_settings_loads(self):
        from backend.app.core.config import settings
        assert settings.app_port == 8000
        assert settings.app_host == "0.0.0.0"

    def test_settings_has_database_url(self):
        from backend.app.core.config import settings
        assert "postgresql" in settings.database_url

    def test_settings_has_s3_bucket(self):
        from backend.app.core.config import settings
        assert len(settings.s3_bucket_name) > 0


class TestStorageService:

    @patch("backend.app.services.storage.get_s3_client")
    def test_upload_file_generates_key(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        from backend.app.services.storage import StorageService
        svc = StorageService()
        key = svc.upload_file(content="test content", file_name="main.tf")

        assert key.startswith("scans/")
        assert "main.tf" in key
        mock_client.put_object.assert_called_once()

    @patch("backend.app.services.storage.get_s3_client")
    def test_upload_patched_file(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        from backend.app.services.storage import StorageService
        svc = StorageService()
        patched_key = svc.upload_patched_file(
            original_key="scans/20240101_abc_main.tf",
            patched_content="fixed content",
        )

        assert patched_key.startswith("patches/")
        assert "main.tf" in patched_key

    @patch("backend.app.services.storage.get_s3_client")
    def test_download_file(self, mock_get_client):
        mock_client = MagicMock()
        mock_body = MagicMock()
        mock_body.read.return_value = b"file content here"
        mock_client.get_object.return_value = {"Body": mock_body}
        mock_get_client.return_value = mock_client

        from backend.app.services.storage import StorageService
        svc = StorageService()
        content = svc.download_file("scans/test_key")

        assert content == "file content here"

    @patch("backend.app.services.storage.get_s3_client")
    def test_list_files_empty(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.list_objects_v2.return_value = {}
        mock_get_client.return_value = mock_client

        from backend.app.services.storage import StorageService
        svc = StorageService()
        files = svc.list_files()

        assert files == []

    @patch("backend.app.services.storage.get_s3_client")
    def test_list_files_with_objects(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.list_objects_v2.return_value = {
            "Contents": [
                {
                    "Key": "scans/test.tf",
                    "Size": 1024,
                    "LastModified": datetime(2024, 1, 1),
                },
            ],
        }
        mock_get_client.return_value = mock_client

        from backend.app.services.storage import StorageService
        svc = StorageService()
        files = svc.list_files()

        assert len(files) == 1
        assert files[0]["key"] == "scans/test.tf"
        assert files[0]["size"] == 1024


class TestAWSClient:

    @patch("backend.app.core.aws.boto3")
    def test_get_s3_client_uses_endpoint(self, mock_boto3):
        from backend.app.core.aws import get_s3_client
        get_s3_client()
        mock_boto3.client.assert_called_once()
        call_kwargs = mock_boto3.client.call_args
        assert call_kwargs[1]["endpoint_url"] is not None

    @patch("backend.app.core.aws.boto3")
    def test_ensure_bucket_exists_creates_when_missing(self, mock_boto3):
        mock_client = MagicMock()
        mock_client.head_bucket.side_effect = mock_client.exceptions.ClientError
        mock_client.exceptions.ClientError = Exception
        mock_client.head_bucket.side_effect = Exception("Not found")
        mock_boto3.client.return_value = mock_client

        from backend.app.core.aws import ensure_bucket_exists
        ensure_bucket_exists(client=mock_client)
        mock_client.create_bucket.assert_called_once()
