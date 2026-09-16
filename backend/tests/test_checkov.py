import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from backend.app.core.config import settings
from backend.app.services.checkov import (
    ScannerError,
    parse_report,
    run_checkov,
    safe_relative_path,
)

FIXTURE = Path(__file__).parent / "fixtures" / "checkov_sample.json"


def fake_checkov(tmp_path, body: str) -> str:
    script = tmp_path / "fake-checkov"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


class TestParseReport:

    def test_real_output(self):
        report = parse_report(FIXTURE.read_text())
        assert report.version == "3.3.17"
        assert report.frameworks == ["terraform", "dockerfile"]
        assert report.covered_files == ["Dockerfile", "main.tf"]
        assert len(report.findings) == 34

        public_write = next(f for f in report.findings if f["check_id"] == "CKV_AWS_57")
        assert public_write["severity"] == "CRITICAL"
        assert public_write["resource"] == "aws_s3_bucket.data_lake"
        assert public_write["file"] == "main.tf"
        assert (public_write["line_start"], public_write["line_end"]) == (1, 4)
        assert public_write["source"] == "checkov"
        assert public_write["description"] == ""

    def test_nothing_supported(self):
        raw = json.dumps({"passed": 0, "failed": 0, "checkov_version": "3.3.17"})
        report = parse_report(raw)
        assert report.findings == []
        assert report.covered_files == []
        assert report.version == "3.3.17"

    def test_single_framework_dict_and_duplicates(self):
        check = {
            "check_id": "CKV_AWS_20",
            "check_name": "public read",
            "resource": "aws_s3_bucket.a",
            "file_path": "/main.tf",
            "file_line_range": [1, 3],
        }
        raw = json.dumps(
            {
                "check_type": "terraform",
                "results": {"failed_checks": [check, check], "passed_checks": []},
                "summary": {"checkov_version": "3.3.17"},
            }
        )
        report = parse_report(raw)
        assert len(report.findings) == 1

    def test_secrets_alone_do_not_count_as_coverage(self):
        secret = {
            "check_id": "CKV_SECRET_6",
            "check_name": "Base64 High Entropy String",
            "resource": "21dde79b804497e122f38dabc393f8e94f103ca6",
            "file_path": "/docker-compose.yml",
            "file_line_range": [5, 6],
        }
        raw = json.dumps(
            {
                "check_type": "secrets",
                "results": {"failed_checks": [secret], "passed_checks": []},
                "summary": {"checkov_version": "3.3.17"},
            }
        )
        report = parse_report(raw)
        assert report.covered_files == []
        assert report.findings[0]["severity"] == "CRITICAL"
        assert report.findings[0]["resource"] == ""
        assert report.findings[0]["file"] == "docker-compose.yml"

    def test_empty_output(self):
        assert parse_report("").findings == []


class TestSafeRelativePath:

    @pytest.mark.parametrize(
        "name, expected",
        [
            ("main.tf", "main.tf"),
            ("modules/vpc/main.tf", "modules/vpc/main.tf"),
            ("../../etc/passwd", "etc/passwd"),
            ("/etc/passwd", "etc/passwd"),
            ("..\\..\\windows\\x.tf", "windows/x.tf"),
        ],
    )
    def test_stays_relative(self, name, expected):
        assert str(safe_relative_path(name)) == expected

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            safe_relative_path("../..")


class TestRunCheckov:

    @pytest.mark.asyncio
    async def test_exit_code_one_is_success(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            settings, "checkov_bin", fake_checkov(tmp_path, f"cat {FIXTURE}\nexit 1\n")
        )
        report = await run_checkov({"main.tf": "resource {}"})
        assert len(report.findings) == 34

    @pytest.mark.asyncio
    async def test_writes_files_inside_scan_dir(self, tmp_path, monkeypatch):
        listing = tmp_path / "listing.txt"
        body = (
            "dir=$2\n"
            f'(cd "$dir" && find . -type f | sort) > {listing}\n'
            'echo "{}"\n'
        )
        monkeypatch.setattr(settings, "checkov_bin", fake_checkov(tmp_path, body))
        await run_checkov({"main.tf": "a", "../../escape.tf": "b", "mod/x.tf": "c"})
        assert listing.read_text().split() == ["./escape.tf", "./main.tf", "./mod/x.tf"]

    @pytest.mark.asyncio
    async def test_scanner_gets_no_secrets(self, tmp_path, monkeypatch):
        dump = tmp_path / "env.txt"
        monkeypatch.setenv("GROQ_API_KEY", "gsk_should_not_leak")
        monkeypatch.setattr(
            settings,
            "checkov_bin",
            fake_checkov(tmp_path, f'env > {dump}\necho "{{}}"\n'),
        )
        await run_checkov({"main.tf": "a"})
        env = dump.read_text()
        assert "gsk_should_not_leak" not in env
        assert "DATABASE_URL" not in env

    @pytest.mark.asyncio
    async def test_crash_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            settings, "checkov_bin", fake_checkov(tmp_path, "echo boom >&2\nexit 2\n")
        )
        with pytest.raises(ScannerError):
            await run_checkov({"main.tf": "a"})

    @pytest.mark.asyncio
    async def test_garbage_output_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            settings, "checkov_bin", fake_checkov(tmp_path, "echo not json\n")
        )
        with pytest.raises(ScannerError):
            await run_checkov({"main.tf": "a"})

    @pytest.mark.asyncio
    async def test_timeout(self, tmp_path, monkeypatch):
        monkeypatch.setattr(settings, "checkov_timeout", 0.5)
        monkeypatch.setattr(
            settings, "checkov_bin", fake_checkov(tmp_path, "exec sleep 10\n")
        )
        with pytest.raises(ScannerError, match="too long"):
            await run_checkov({"main.tf": "a"})

    @pytest.mark.asyncio
    async def test_missing_binary(self, monkeypatch):
        monkeypatch.setattr(settings, "checkov_bin", "/nonexistent/checkov")
        with pytest.raises(ScannerError, match="not installed"):
            await run_checkov({"main.tf": "a"})


REAL_CHECKOV = os.environ.get("CHECKOV_BIN") or shutil.which("checkov")


@pytest.mark.skipif(not REAL_CHECKOV, reason="checkov is not installed")
class TestRealCheckov:

    @pytest.mark.asyncio
    async def test_public_bucket(self, monkeypatch):
        monkeypatch.setattr(settings, "checkov_bin", REAL_CHECKOV)
        report = await run_checkov(
            {
                "main.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl = "public-read"\n}\n'
            }
        )
        ids = {f["check_id"] for f in report.findings}
        assert "CKV_AWS_20" in ids
        assert report.covered_files == ["main.tf"]

    @pytest.mark.asyncio
    async def test_compose_secret_is_found_but_not_coverage(self, monkeypatch):
        monkeypatch.setattr(settings, "checkov_bin", REAL_CHECKOV)
        report = await run_checkov(
            {
                "docker-compose.yml": "services:\n  db:\n    image: postgres\n"
                "    environment:\n      POSTGRES_PASSWORD: supersecret123\n"
            }
        )
        assert report.covered_files == []
        assert any(f["check_id"].startswith("CKV_SECRET") for f in report.findings)

    @pytest.mark.asyncio
    async def test_compose_is_not_covered(self, monkeypatch):
        monkeypatch.setattr(settings, "checkov_bin", REAL_CHECKOV)
        report = await run_checkov(
            {
                "docker-compose.yml": "services:\n  web:\n    image: nginx\n    privileged: true\n"
            }
        )
        assert report.covered_files == []
