import uuid
from datetime import datetime, timezone

from backend.app.core.aws import get_s3_client
from backend.app.core.config import settings


class StorageService:
    def __init__(self):
        self.client = get_s3_client()
        self.bucket = settings.s3_bucket_name

    def upload_file(
        self, content: str, file_name: str, prefix: str = "scans", unique_id: str = None
    ) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if not unique_id:
            unique_id = uuid.uuid4().hex[:8]
        key = f"{prefix}/{timestamp}_{unique_id}_{file_name}"

        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=content.encode("utf-8"),
            ContentType="text/plain",
        )
        return key

    def upload_patched_file(self, original_key: str, patched_content: str) -> str:
        patched_key = original_key.replace("scans/", "patches/")
        self.client.put_object(
            Bucket=self.bucket,
            Key=patched_key,
            Body=patched_content.encode("utf-8"),
            ContentType="text/plain",
        )
        return patched_key

    def download_file(self, key: str) -> str:
        response = self.client.get_object(Bucket=self.bucket, Key=key)
        return response["Body"].read().decode("utf-8")

    def list_files(self, prefix: str = "scans") -> list[dict]:
        response = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        files = []
        for obj in response.get("Contents", []):
            files.append(
                {
                    "key": obj["Key"],
                    "size": obj["Size"],
                    "last_modified": obj["LastModified"].isoformat(),
                }
            )
        return files
