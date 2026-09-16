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

    # Abuse protection, per client IP.
    scan_rate_limit: int = Field(default=8, description="Scans per 10 minutes")
    search_rate_limit: int = Field(default=30, description="Searches per minute")
    max_concurrent_scans: int = Field(default=2, description="Scans running at once")

    checkov_bin: str = Field(default="checkov", description="Path to the checkov CLI")
    checkov_timeout: int = Field(
        default=90, description="Seconds before a scan is killed"
    )

    # Explanations and patches on the server's own LLM key, per client per day.
    # Set to 0 to offer static checks only unless visitors bring a key.
    free_llm_scans_per_day: int = Field(default=5)
    # Keyed hash for client addresses in the usage table. Defaults to a value
    # derived from DATABASE_URL so counts survive restarts without extra setup.
    usage_hash_salt: str = Field(default="")

    # Model budgets. The defaults fit Groq's free tier, which allows 8,000
    # tokens per minute for gpt-oss-120b; raise them on a paid tier.
    llm_review_max_chars: int = Field(default=16_000)
    llm_max_explained_findings: int = Field(default=25)
    llm_patch_max_file_chars: int = Field(default=12_000)
    llm_max_patched_files: int = Field(default=3)
    llm_patch_concurrency: int = Field(default=1)

    # Local embedding model files; the Docker image bakes them in here.
    embedding_cache_dir: str = Field(default="")
    embedding_threads: int = Field(default=2)

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
