import pytest
from backend.app.core.config import settings
from backend.app.services.storage import StorageService
from backend.app.core.aws import get_s3_client


class TestStorageIntegration:

    @pytest.fixture(autouse=True)
    def setup_storage(self):
        self.storage = StorageService()

    def test_bucket_creation_and_file_flow(self):
        s3_client = get_s3_client()
        response = s3_client.list_buckets()
        bucket_names = [b["Name"] for b in response.get("Buckets", [])]
        assert settings.s3_bucket_name in bucket_names

        # Upload original config
        iac_content = 'resource "aws_security_group" "allow_ssh" { name = "allow_ssh" }'
        original_key = self.storage.upload_file(
            content=iac_content, file_name="ssh_test.tf", prefix="integration-scans"
        )

        assert original_key.startswith("integration-scans/")
        assert "ssh_test.tf" in original_key

        # Upload patched config
        patched_content = 'resource "aws_security_group" "allow_ssh" { name = "allow_ssh"; ingress = [] }'
        patched_key = self.storage.upload_patched_file(
            original_key=original_key, patched_content=patched_content
        )

        assert patched_key.startswith("integration-patches/")
        assert "ssh_test.tf" in patched_key

        # Verify round-trip content
        downloaded_original = self.storage.download_file(original_key)
        assert downloaded_original == iac_content

        downloaded_patched = self.storage.download_file(patched_key)
        assert downloaded_patched == patched_content

        # Verify listing
        scans_list = self.storage.list_files(prefix="integration-scans")
        keys = [item["key"] for item in scans_list]
        assert original_key in keys

        # Clean up
        s3_client.delete_object(Bucket=settings.s3_bucket_name, Key=original_key)
        s3_client.delete_object(Bucket=settings.s3_bucket_name, Key=patched_key)
