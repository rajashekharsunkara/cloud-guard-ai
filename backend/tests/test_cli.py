import json
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from backend import cli
from backend.app.services.checkov import parse_report

FIXTURE = Path(__file__).parent / "fixtures" / "checkov_sample.json"


def result(findings, score=40, covered=("main.tf",), model=None, notices=()):
    return {
        "audit_id": "a1",
        "file_name": "infra",
        "security_score": score,
        "vulnerabilities": findings,
        "files": ["main.tf", "Dockerfile"],
        "patches": [{"file": "main.tf", "original": "a", "patched": "b"}],
        "analysis": {
            "mode": "static",
            "checkov_version": "3.3.17",
            "covered_files": list(covered),
            "notices": list(notices),
            "model": model,
        },
    }


def f(severity, file="main.tf", source="checkov", title="Title", **extra):
    return {
        "severity": severity,
        "file": file,
        "source": source,
        "title": title,
        "check_id": "CKV_1" if source == "checkov" else None,
        "resource": "r",
        "line_start": 3,
        "line_end": 9,
        **extra,
    }


class TestThreshold:

    @pytest.mark.parametrize(
        "threshold, expected",
        [("critical", False), ("high", True), ("medium", True), ("none", False)],
    )
    def test_fails(self, threshold, expected):
        assert cli.fails(result([f("HIGH"), f("LOW")]), threshold) is expected

    def test_review_findings_never_fail_the_build(self):
        assert not cli.fails(result([f("CRITICAL", source="review")]), "low")


class TestChangedFiles:

    def test_filter(self):
        filtered = cli.filter_to_changed(
            result(
                [f("CRITICAL", file="old.tf"), f("LOW", file="main.tf")],
                covered=("main.tf", "old.tf"),
            ),
            {"main.tf"},
        )
        assert [x["file"] for x in filtered["vulnerabilities"]] == ["main.tf"]
        assert filtered["security_score"] == 99
        assert filtered["changed_files"] == ["main.tf"]

    def test_nothing_changed_is_not_scored(self):
        filtered = cli.filter_to_changed(result([f("LOW")]), set())
        assert filtered["vulnerabilities"] == [] and filtered["security_score"] is None

    def test_git_diff(self, tmp_path):
        def git(*args):
            subprocess.run(
                ["git", "-C", str(tmp_path), *args], check=True, capture_output=True
            )

        git("init", "-q")
        git("config", "user.email", "t@t")
        git("config", "user.name", "t")
        (tmp_path / "infra").mkdir()
        (tmp_path / "infra" / "base.tf").write_text("a")
        (tmp_path / "README.md").write_text("docs")
        git("add", "-A")
        git("commit", "-qm", "base")
        git("branch", "base")
        (tmp_path / "infra" / "app.tf").write_text("b")
        (tmp_path / "README.md").write_text("changed docs")
        git("add", "-A")
        git("commit", "-qm", "change")

        assert cli.changed_files((tmp_path / "infra").resolve(), "base") == {"app.tf"}


class TestMarkdown:

    def test_report(self):
        text = cli.render_markdown(
            result(
                [
                    f(
                        "CRITICAL",
                        title="Pipe | in title",
                        description="Why",
                        remediation="How",
                    ),
                    f("HIGH", source="review", title="Secret in env"),
                ],
                model={"provider": "OpenAI", "model": "gpt-5.6-terra"},
                notices=["Heads up"],
            ),
            link_base="https://github.com/o/r/blob/abc/",
        )
        assert text.startswith(cli.REPORT_MARKER)
        assert "**Score 40/100** · 1 critical, 1 high · Checkov 3.3.17, 2 files" in text
        assert "Pipe \\| in title (CKV_1)" in text
        assert "[`main.tf:3`](https://github.com/o/r/blob/abc/main.tf#L3-L9)" in text
        assert "### Also noticed in review" in text
        assert "> Heads up" in text
        assert "Fix: How" in text
        assert "Explained by OpenAI gpt-5.6-terra." in text

    def test_static_and_unscored(self):
        text = cli.render_markdown(result([], score=None))
        assert "**Not scored**" in text
        assert "Checkov results only." in text
        assert "### Checkov findings" not in text

    def test_long_tables_are_cut(self):
        text = cli.render_markdown(
            result([f("LOW") for _ in range(cli.MAX_TABLE_ROWS + 7)])
        )
        assert "_and 7 more_" in text


class TestMain:

    def make_project(self, tmp_path):
        tmp_path.mkdir(parents=True, exist_ok=True)
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}')
        (tmp_path / "notes.md").write_text("ignored")
        return tmp_path

    @patch("backend.app.services.pipeline.run_checkov", new_callable=AsyncMock)
    def test_json_output_and_exit_code(
        self, mock_checkov, tmp_path, capsys, monkeypatch
    ):
        monkeypatch.delenv("CLOUDGUARD_LLM_KEY", raising=False)
        mock_checkov.return_value = parse_report(FIXTURE.read_text())
        project = self.make_project(tmp_path)

        code = cli.main(
            ["scan", str(project), "--format", "json", "--fail-on", "critical"]
        )

        out = json.loads(capsys.readouterr().out)
        assert code == 1
        assert out["analysis"]["mode"] == "static"
        assert out["analysis"]["notices"] == []
        assert mock_checkov.call_args.args[0] == {
            "main.tf": 'resource "aws_s3_bucket" "b" {}'
        }

    @patch("backend.app.services.pipeline.run_checkov", new_callable=AsyncMock)
    def test_writes_report_file(self, mock_checkov, tmp_path, monkeypatch):
        from backend.app.services.checkov import CheckovReport

        mock_checkov.return_value = CheckovReport(
            covered_files=["main.tf"], version="3.3.17"
        )
        project = self.make_project(tmp_path / "p")
        out = tmp_path / "report.md"
        code = cli.main(
            ["scan", str(project), "--format", "markdown", "--output", str(out)]
        )
        assert code == 0
        assert "**Score 100/100**" in out.read_text()

    def test_provider_without_key(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CLOUDGUARD_LLM_KEY", raising=False)
        project = self.make_project(tmp_path)
        with pytest.raises(SystemExit, match="CLOUDGUARD_LLM_KEY"):
            cli.main(["scan", str(project), "--provider", "openai"])

    def test_missing_directory(self, capsys):
        assert cli.main(["scan", "/definitely/not/here"]) == 2
        assert "is not a directory" in capsys.readouterr().err
