"""Severity ratings for Checkov findings.

Checkov's open-source release doesn't ship severities, so CloudGuard assigns
its own. The rating only depends on the check, never on a model, which keeps
scores identical between runs of the same file.

Order of precedence: an explicit rating for well-known checks, then the first
matching keyword rule on the check name, then MEDIUM.
"""

import math
import re

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Checks where the name alone is ambiguous or undersells the risk.
CHECK_SEVERITY = {
    # Data readable or writable by anyone
    "CKV_AWS_20": "CRITICAL",  # S3 ACL allows public READ
    "CKV_AWS_57": "CRITICAL",  # S3 ACL allows public WRITE
    "CKV_AWS_17": "CRITICAL",  # RDS publicly accessible
    "CKV_AWS_24": "CRITICAL",  # SSH open to the internet
    "CKV_AWS_25": "CRITICAL",  # RDP open to the internet
    "CKV_AWS_41": "CRITICAL",  # AWS keys hardcoded in provider
    "CKV_AWS_46": "CRITICAL",  # secrets in EC2 user data
    "CKV_AWS_1": "CRITICAL",  # IAM policy allows *:* admin
    "CKV_AWS_62": "CRITICAL",  # IAM role allows *:* admin
    "CKV_AWS_63": "CRITICAL",  # IAM policy allows * actions
    "CKV_AZURE_9": "CRITICAL",  # RDP open to the internet
    "CKV_AZURE_10": "CRITICAL",  # SSH open to the internet
    "CKV_GCP_2": "CRITICAL",  # SSH open to the internet
    "CKV_GCP_3": "CRITICAL",  # RDP open to the internet
    # Serious but not an open door by itself
    "CKV2_AWS_6": "HIGH",  # no S3 public access block
    "CKV_AWS_79": "HIGH",  # IMDSv1 enabled
    "CKV_AWS_16": "HIGH",  # RDS not encrypted
    "CKV_AWS_8": "HIGH",  # EBS in launch config not encrypted
    "CKV_AWS_3": "HIGH",  # EBS volume not encrypted
    "CKV_AWS_19": "HIGH",  # S3 default encryption missing
    "CKV_K8S_16": "HIGH",  # privileged container
    "CKV_K8S_20": "HIGH",  # privilege escalation allowed
    "CKV_K8S_23": "HIGH",  # container runs as root (host PID/IPC)
    "CKV_DOCKER_3": "MEDIUM",  # no non-root user
    # Worth fixing, rarely urgent
    "CKV_AWS_260": "MEDIUM",  # port 80 open (often intentional)
    "CKV_AWS_382": "MEDIUM",  # unrestricted egress
    "CKV_AWS_145": "MEDIUM",  # S3 uses AWS-managed rather than customer KMS key
    "CKV2_AWS_41": "MEDIUM",  # EC2 without IAM role
    "CKV_AWS_161": "MEDIUM",  # RDS IAM auth disabled
    "CKV_DOCKER_7": "MEDIUM",  # image uses latest tag
    "CKV_DOCKER_2": "LOW",  # no HEALTHCHECK
    "CKV_DOCKER_5": "LOW",  # apt-get update alone
}

_RULES = [
    (
        "CRITICAL",
        r"hard[- ]?coded|secret|private key|access key|password in|"
        r"public (read|write)|world[- ]?(readable|writable)|"
        r"0\.0\.0\.0.*(port 22\b|port 3389\b|all ports)|"
        r"full administrative|admin(istrator)? privileges",
    ),
    (
        "LOW",
        r"\bdescription\b|\btag(s|ged|ging)?\b|monitoring|performance insights|"
        r"multi-?az|replication|lifecycle|event notification|ebs optimi[sz]ed|"
        r"minor (version )?upgrade|x-?ray|tracing|healthcheck|"
        r"deletion protection|termination protection|copy tags|"
        r"latest version tag|retention period",
    ),
    (
        "HIGH",
        r"encrypt|\btls\b|\bssl\b|https|publicly accessible|public access|"
        r"privileged|run(s|ning)? as root|root user|metadata service|imds|"
        r"0\.0\.0\.0|wildcard|\"\*\"|unrestricted|anonymous|"
        r"authentication (is )?(disabled|not enabled)",
    ),
    (
        "MEDIUM",
        r"logg(ing|ed)|\blogs?\b|versioning|backup|kms|customer managed|cmk|"
        r"iam|least privilege|rotation|mfa",
    ),
]

_COMPILED = [(severity, re.compile(pattern)) for severity, pattern in _RULES]


def rate_check(check_id: str, check_name: str) -> str:
    if check_id in CHECK_SEVERITY:
        return CHECK_SEVERITY[check_id]
    if check_id.startswith("CKV_SECRET"):
        return "CRITICAL"
    name = (check_name or "").lower()
    for severity, pattern in _COMPILED:
        if pattern.search(name):
            return severity
    return "MEDIUM"


# Points per finding. The score follows 100 * e^(-points / SCORE_SCALE), so
# the first serious problems cost the most and a long tail of minor warnings
# can't push an otherwise sound file to zero.
SEVERITY_POINTS = {"CRITICAL": 30, "HIGH": 12, "MEDIUM": 4, "LOW": 1}
SCORE_SCALE = 80


def score_findings(findings: list[dict]) -> int:
    points = sum(
        SEVERITY_POINTS.get(str(f.get("severity", "")).upper(), SEVERITY_POINTS["LOW"])
        for f in findings
    )
    return round(100 * math.exp(-points / SCORE_SCALE))
