from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: str = Field(default="development", description="Application environment")
    app_host: str = Field(default="0.0.0.0", description="Server host")
    app_port: int = Field(default=8000, description="Server port")

    # Comma-separated list of allowed CORS origins, or "*" to allow any.
    cors_origins: str = Field(default="*", description="Allowed CORS origins")

    groq_api_key: str = Field(default="", description="Groq API key")
    gemini_api_key: str = Field(default="", description="Google Gemini API key")

    database_url: str = Field(
        default="postgresql+asyncpg://cloudguard:cloudguard_secret@localhost:5432/cloudguard_db",
        description="Async PostgreSQL connection string",
    )

    # Leave unset to use the real AWS endpoint; point at LocalStack for local dev.
    aws_endpoint_url: Optional[str] = Field(
        default=None, description="Custom S3 endpoint (LocalStack)"
    )
    # Leave both unset to use the default boto3 credential chain (IAM role,
    # instance profile, ~/.aws/credentials).
    aws_access_key_id: str = Field(default="", description="AWS access key")
    aws_secret_access_key: str = Field(default="", description="AWS secret key")
    aws_default_region: str = Field(default="us-east-1", description="AWS region")
    s3_bucket_name: str = Field(
        default="cloudguard-artifacts", description="S3 bucket for audit artifacts"
    )

    # Guardrails for request payloads.
    max_iac_chars: int = 120_000
    max_diagram_bytes: int = 8 * 1024 * 1024

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
