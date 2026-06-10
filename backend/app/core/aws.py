import boto3

from backend.app.core.config import settings


def get_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=settings.aws_endpoint_url,
        aws_access_key_id=settings.aws_access_key_id,
        aws_secret_access_key=settings.aws_secret_access_key,
        region_name=settings.aws_default_region,
    )


def ensure_bucket_exists(client=None) -> None:
    client = client or get_s3_client()
    try:
        client.head_bucket(Bucket=settings.s3_bucket_name)
    except client.exceptions.ClientError:
        client.create_bucket(Bucket=settings.s3_bucket_name)
