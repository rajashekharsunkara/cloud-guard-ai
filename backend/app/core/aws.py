import boto3
from botocore.exceptions import ClientError

from backend.app.core.config import settings


def get_s3_client():
    kwargs = {"region_name": settings.aws_default_region}
    if settings.aws_endpoint_url:
        kwargs["endpoint_url"] = settings.aws_endpoint_url
    # Only pass static credentials when configured; otherwise boto3 falls back
    # to its default chain (IAM role, instance profile, shared config).
    if settings.aws_access_key_id and settings.aws_secret_access_key:
        kwargs["aws_access_key_id"] = settings.aws_access_key_id
        kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
    return boto3.client("s3", **kwargs)


def ensure_bucket_exists(client=None) -> None:
    client = client or get_s3_client()
    try:
        client.head_bucket(Bucket=settings.s3_bucket_name)
    except ClientError:
        params = {"Bucket": settings.s3_bucket_name}
        # us-east-1 rejects an explicit LocationConstraint; every other
        # region requires one.
        if settings.aws_default_region != "us-east-1":
            params["CreateBucketConfiguration"] = {
                "LocationConstraint": settings.aws_default_region
            }
        client.create_bucket(**params)
