import json
from pathlib import Path

import pytest

from backend.app.services.severity import rate_check, score_findings

FIXTURE = Path(__file__).parent / "fixtures" / "checkov_sample.json"


class TestRateCheck:

    @pytest.mark.parametrize(
        "check_id, name, expected",
        [
            (
                "CKV_AWS_20",
                "S3 Bucket has an ACL defined which allows public READ access.",
                "CRITICAL",
            ),
            (
                "CKV_AWS_24",
                "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
                "CRITICAL",
            ),
            (
                "CKV_AWS_16",
                "Ensure all data stored in the RDS is securely encrypted at rest",
                "HIGH",
            ),
            (
                "CKV_AWS_260",
                "Ensure no security groups allow ingress from 0.0.0.0:0 to port 80",
                "MEDIUM",
            ),
            (
                "CKV_DOCKER_2",
                "Ensure that HEALTHCHECK instructions have been added",
                "LOW",
            ),
        ],
    )
    def test_explicit_ratings(self, check_id, name, expected):
        assert rate_check(check_id, name) == expected

    def test_secret_checks_are_critical(self):
        assert rate_check("CKV_SECRET_6", "Base64 High Entropy String") == "CRITICAL"

    @pytest.mark.parametrize(
        "name, expected",
        [
            ("Ensure hardcoded credentials are not present", "CRITICAL"),
            ("Ensure the Redis cluster is encrypted in transit", "HIGH"),
            ("Ensure the load balancer has access logging enabled", "MEDIUM"),
            ("Ensure every resource has a description", "LOW"),
            ("Ensure the widget has cross-region replication enabled", "LOW"),
            ("Ensure something nobody has a rule for", "MEDIUM"),
        ],
    )
    def test_keyword_rules(self, name, expected):
        assert rate_check("CKV_TEST_999", name) == expected

    def test_same_check_always_rates_the_same(self):
        checks = [
            c
            for report in json.loads(FIXTURE.read_text())
            for c in report["results"]["failed_checks"]
        ]
        first = [rate_check(c["check_id"], c["check_name"]) for c in checks]
        second = [rate_check(c["check_id"], c["check_name"]) for c in checks]
        assert first == second
        assert {"CRITICAL", "HIGH", "MEDIUM", "LOW"} <= set(first)


class TestScore:

    def _score(self, *severities):
        return score_findings([{"severity": s} for s in severities])

    def test_clean_file_scores_100(self):
        assert score_findings([]) == 100

    def test_known_values(self):
        assert self._score("CRITICAL") == 69
        assert self._score("HIGH") == 86
        assert self._score(*["LOW"] * 10) == 88
        assert self._score("CRITICAL", "CRITICAL") == 47

    def test_more_or_worse_findings_never_raise_the_score(self):
        base = self._score("HIGH", "MEDIUM")
        assert self._score("HIGH", "MEDIUM", "LOW") <= base
        assert self._score("CRITICAL", "MEDIUM") < base

    def test_minor_warnings_alone_dont_reach_zero(self):
        assert self._score(*["LOW"] * 50) > 50

    def test_unknown_severity_counts_as_low(self):
        assert self._score("weird") == self._score("LOW")
