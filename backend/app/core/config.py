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

    groq_api_key: str = Field(default="", description="Groq API key for Llama 3")
    gemini_api_key: str = Field(default="", description="Google Gemini API key")

    database_url: str = Field(
        default="postgresql+asyncpg://cloudguard:cloudguard_secret@localhost:5432/cloudguard_db",
        description="Async PostgreSQL connection string",
    )

    aws_endpoint_url: str = Field(
        default="http://localhost:4566", description="AWS/LocalStack endpoint"
    )
    aws_access_key_id: str = Field(default="test", description="AWS access key")
    aws_secret_access_key: str = Field(default="test", description="AWS secret key")
    aws_default_region: str = Field(default="us-east-1", description="AWS region")
    s3_bucket_name: str = Field(
        default="cloudguard-artifacts", description="S3 bucket for audit artifacts"
    )


settings = Settings()
