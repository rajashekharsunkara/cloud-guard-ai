from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class AuditRequest(BaseModel):
    iac_content: str = Field(
        ...,
        description="Raw Terraform or Docker Compose configuration content",
        min_length=10,
    )
    file_name: str = Field(
        default="main.tf",
        description="Original filename for context",
    )


class SearchRequest(BaseModel):
    query: str = Field(
        ...,
        description="Natural language search query",
        min_length=3,
    )
    limit: int = Field(default=5, ge=1, le=20, description="Max results to return")


class VulnerabilityItem(BaseModel):
    severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, or LOW")
    title: str = Field(..., description="Short vulnerability title")
    description: str = Field(..., description="Detailed explanation")
    resource: str = Field(default="", description="Affected Terraform resource")
    remediation: str = Field(default="", description="Suggested fix")


class AuditResult(BaseModel):
    audit_id: str = Field(..., description="Unique audit identifier")
    file_name: str
    security_score: int = Field(..., ge=0, le=100, description="Overall security score")
    vulnerabilities: list[VulnerabilityItem] = []
    patched_code: str = Field(default="", description="Remediated IaC configuration")
    diagram_analysis: Optional[str] = Field(
        default=None, description="Diagram drift analysis (if image provided)"
    )
    similar_past_audits: list[str] = Field(
        default=[], description="Summaries of similar historical vulnerabilities"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SearchResultItem(BaseModel):
    audit_id: str
    file_name: str
    vulnerability_type: str
    description: str
    patched_code: str
    similarity_score: float = Field(..., description="Cosine similarity (0-1)")


class SearchResponse(BaseModel):
    query: str
    results: list[SearchResultItem] = []
    total: int = 0


class HealthResponse(BaseModel):
    status: str = "healthy"
    database: str = "connected"
    s3: str = "connected"
    environment: str = ""
