from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class AuditRequest(BaseModel):
    iac_content: str = Field(
        ...,
        description="Raw Terraform or Docker Compose configuration content",
        min_length=10,
        max_length=120_000,
    )
    file_name: str = Field(
        default="main.tf",
        description="Original filename for context",
        max_length=255,
    )


class SearchRequest(BaseModel):
    query: str = Field(
        ...,
        description="Natural language search query",
        min_length=3,
        max_length=1000,
    )
    limit: int = Field(default=5, ge=1, le=20, description="Max results to return")


class VulnerabilityItem(BaseModel):
    severity: str = Field(default="LOW", description="CRITICAL, HIGH, MEDIUM, or LOW")
    title: str = Field(
        default="Untitled finding", description="Short vulnerability title"
    )
    description: str = Field(default="", description="Detailed explanation")
    resource: str = Field(default="", description="Affected Terraform resource")
    remediation: str = Field(default="", description="Suggested fix")
    source: str = Field(
        default="review",
        description="checkov for static checks (counted in the score), "
        "review for issues only the model review found",
    )
    check_id: Optional[str] = Field(default=None, description="Checkov check ID")
    file: str = ""
    line_start: Optional[int] = None
    line_end: Optional[int] = None


class PatchItem(BaseModel):
    file: str
    original: str
    patched: str


class RepoRequest(BaseModel):
    url: str = Field(
        ...,
        max_length=500,
        description="Public GitHub repository or folder, e.g. "
        "https://github.com/owner/repo/tree/main/infra",
    )


class ScanAnalysis(BaseModel):
    mode: str = Field(
        default="static",
        description="static: Checkov only; free: explained on the server's free tier",
    )
    source: str = Field(default="paste", description="paste, zip or github")
    checkov_version: str = ""
    covered_files: list[str] = []
    frameworks: list[str] = []
    notices: list[str] = []
    free_scans_left: int = 0


class AuditResult(BaseModel):
    audit_id: str = Field(..., description="Unique audit identifier")
    file_name: str
    security_score: Optional[int] = Field(
        ...,
        ge=0,
        le=100,
        description="Score from Checkov findings; null when no file type is covered",
    )
    vulnerabilities: list[VulnerabilityItem] = []
    patched_code: str = Field(default="", description="Remediated IaC configuration")
    diagram_analysis: Optional[str] = Field(
        default=None, description="Diagram drift analysis (if image provided)"
    )
    similar_past_audits: list[str] = Field(
        default=[], description="Summaries of similar historical vulnerabilities"
    )
    files: list[str] = Field(default=[], description="Paths that were scanned")
    patches: list[PatchItem] = []
    analysis: Optional[ScanAnalysis] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditDetail(AuditResult):
    original_code: str = Field(default="", description="Configuration as submitted")


class SearchResultItem(BaseModel):
    audit_id: str
    file_name: str
    vulnerability_type: str
    severity: str = "LOW"
    description: str
    patched_code: str
    similarity_score: float = Field(..., description="Cosine similarity (0-1)")


class SearchResponse(BaseModel):
    query: str
    results: list[SearchResultItem] = []
    total: int = 0


class AuditSummary(BaseModel):
    audit_id: str
    file_name: str
    security_score: Optional[int] = None
    finding_count: int
    severity_counts: dict[str, int] = {}
    has_diagram: bool = False
    file_count: int = 1
    source: str = "paste"
    created_at: Optional[str] = None


class HealthResponse(BaseModel):
    status: str = "healthy"
    database: str = "connected"
    s3: str = "connected"
    environment: str = ""


class UsageResponse(BaseModel):
    explanations_available: bool
    free_scans_per_day: int
    free_scans_left: int
