import json
import os
import shutil
import socket
import stat
import threading
from pathlib import Path

import pytest

from backend.app.core.config import settings
from backend.app.services.checkov import (
    ScannerError,
    _pin_to_template,
    _source_path,
    parse_report,
    run_checkov,
    safe_relative_path,
    without_remote_dependencies,
)
import yaml

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


class TestHelmDependencies:

    def test_remote_repositories_are_removed(self):
        chart = """apiVersion: v2
name: web
version: 0.1.0
dependencies:
  - name: redis
    version: 1.0.0
    repository: https://charts.example.com
  - name: pg
    version: 1.0.0
    repository: oci://registry.example.com/charts
  - name: meta
    version: 1.0.0
    repository: http://169.254.169.254/latest
  - name: named
    version: 1.0.0
    repository: "@bitnami"
  - name: common
    version: 1.0.0
    repository: file://charts/common
  - name: vendored
    version: 1.0.0
"""
        data = yaml.safe_load(without_remote_dependencies(chart))
        assert [d["name"] for d in data["dependencies"]] == ["common", "vendored"]
        assert data["name"] == "web"

    @pytest.mark.parametrize(
        "repository", ["file:///etc", "file://../../outside", "file://charts/../../x"]
    )
    def test_local_paths_must_stay_in_the_chart(self, repository):
        chart = f"name: web\ndependencies:\n  - name: x\n    repository: {repository}\n"
        assert yaml.safe_load(without_remote_dependencies(chart))["dependencies"] == []

    def test_chart_without_dependencies_keeps_its_fields(self):
        chart = "apiVersion: v2  # comment\nname: web\nversion: 0.1.0\n"
        assert yaml.safe_load(without_remote_dependencies(chart)) == {
            "apiVersion": "v2",
            "name": "web",
            "version": "0.1.0",
        }

    def test_merge_keys_cannot_hide_dependencies(self):
        chart = (
            "base: &base\n  dependencies:\n    - name: x\n"
            "      repository: https://evil.example\n"
            "<<: *base\nname: web\n"
        )
        assert yaml.safe_load(chart)["dependencies"]  # the merge applies
        assert yaml.safe_load(without_remote_dependencies(chart))["dependencies"] == []

    @pytest.mark.parametrize("content", ["a: [unclosed", "- just\n- a list\n", ""])
    def test_unreadable_chart_files_are_left_out(self, content):
        assert without_remote_dependencies(content) is None


class TestHelmPaths:

    SOURCES = {
        "Chart.yaml": "name: root",
        "templates/svc.yaml": "",
        "deploy/app/Chart.yaml": "name: storefront",
        "deploy/app/templates/deploy.yaml": "",
        "k8s/pod.yaml": "",
    }
    CHARTS = {"", "deploy/app"}

    @pytest.mark.parametrize(
        "reported, expected",
        [
            ("/root/templates/svc.yaml", "templates/svc.yaml"),
            (
                "/deploy/app/storefront/templates/deploy.yaml",
                "deploy/app/templates/deploy.yaml",
            ),
            ("/deploy/app/templates/deploy.yaml", "deploy/app/templates/deploy.yaml"),
        ],
    )
    def test_rendered_templates_map_to_uploaded_files(self, reported, expected):
        assert _source_path("helm", reported, self.SOURCES, self.CHARTS) == expected

    def test_plain_kubernetes_results_for_chart_files_are_dropped(self):
        assert (
            _source_path(
                "kubernetes",
                "/deploy/app/templates/deploy.yaml",
                self.SOURCES,
                {"deploy/app"},
            )
            is None
        )

    def test_kubernetes_outside_charts_is_kept(self):
        assert (
            _source_path("kubernetes", "/k8s/pod.yaml", self.SOURCES, {"deploy/app"})
            == "k8s/pod.yaml"
        )


class TestPinToTemplate:

    TEMPLATE = """apiVersion: v1
kind: Service
metadata:
  name: {{ include "web.fullname" . }}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "web.fullname" . }}
spec:
  replicas: {{ .Values.replicaCount }}
"""

    def test_finding_covers_its_document(self):
        finding = {"line_start": 3, "line_end": 40}
        _pin_to_template(finding, "Deployment.default.release-name-web", self.TEMPLATE)
        assert (finding["line_start"], finding["line_end"]) == (6, 11)

    def test_first_document(self):
        finding = {"line_start": 3, "line_end": 14}
        _pin_to_template(finding, "Service.default.release-name-web", self.TEMPLATE)
        assert (finding["line_start"], finding["line_end"]) == (1, 4)

    def test_unknown_kind_covers_the_file(self):
        finding = {"line_start": 30, "line_end": 90}
        _pin_to_template(finding, "CronJob.default.x", self.TEMPLATE)
        assert (finding["line_start"], finding["line_end"]) == (1, 11)


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
    async def test_chart_dependencies_are_stripped_before_scanning(
        self, tmp_path, monkeypatch
    ):
        copy = tmp_path / "chart-seen.yaml"
        body = f'cp "$2/web/Chart.yaml" {copy}\necho "{{}}"\n'
        monkeypatch.setattr(settings, "checkov_bin", fake_checkov(tmp_path, body))
        chart = (
            "name: web\ndependencies:\n  - name: r\n"
            "    repository: http://10.0.0.1/charts\n"
        )
        await run_checkov({"web/Chart.yaml": chart})
        assert "10.0.0.1" not in copy.read_text()

    @pytest.mark.asyncio
    async def test_unreadable_chart_file_is_not_written(self, tmp_path, monkeypatch):
        listing = tmp_path / "listing.txt"
        body = f'(cd "$2" && find . -type f | sort) > {listing}\necho "{{}}"\n'
        monkeypatch.setattr(settings, "checkov_bin", fake_checkov(tmp_path, body))
        await run_checkov({"web/Chart.yaml": "a: [unclosed", "web/values.yaml": "a: 1"})
        assert listing.read_text().split() == ["./web/values.yaml"]

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
        assert "CHECKOV_HELM_ALLOWED_REMOTE_REPOS=none" in env

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


HELM = shutil.which("helm")

HELPERS = """{{- define "web.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
"""

DEPLOYMENT = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "web.fullname" . }}
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: "nginx:{{ .Values.tag }}"
          securityContext:
            {{- toYaml .Values.securityContext | nindent 12 }}
"""


def chart_files(extra_chart_yaml: str = "") -> dict[str, str]:
    return {
        "web/Chart.yaml": "apiVersion: v2\nname: web\nversion: 0.1.0\n"
        + extra_chart_yaml,
        "web/values.yaml": "tag: latest\nsecurityContext:\n  privileged: true\n",
        "web/templates/_helpers.tpl": HELPERS,
        "web/templates/deployment.yaml": DEPLOYMENT,
    }


@pytest.mark.skipif(
    not (REAL_CHECKOV and HELM), reason="checkov or helm is not installed"
)
class TestRealHelm:

    @pytest.mark.asyncio
    async def test_chart_is_rendered_and_pinned_to_the_template(self, monkeypatch):
        monkeypatch.setattr(settings, "checkov_bin", REAL_CHECKOV)
        report = await run_checkov(chart_files())
        assert "helm" in report.frameworks
        assert report.covered_files == ["web/templates/deployment.yaml"]
        privileged = [f for f in report.findings if f["check_id"] == "CKV_K8S_16"]
        assert privileged
        assert privileged[0]["file"] == "web/templates/deployment.yaml"
        assert privileged[0]["line_start"] == 1
        assert privileged[0]["line_end"] == len(DEPLOYMENT.splitlines())

    @pytest.mark.asyncio
    async def test_chart_paths_match_the_upload_without_duplicates(self, monkeypatch):
        monkeypatch.setattr(settings, "checkov_bin", REAL_CHECKOV)
        service = (
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n"
            "spec:\n  type: LoadBalancer\n  ports:\n    - port: 80\n"
        )
        files = {
            name.replace("web/", "deploy/helm/", 1): content
            for name, content in chart_files().items()
        }
        files["deploy/helm/Chart.yaml"] = (
            "apiVersion: v2\nname: storefront\nversion: 0.1.0\n"
        )
        files["deploy/helm/templates/service.yaml"] = service
        report = await run_checkov(files)
        assert set(report.covered_files) == {
            "deploy/helm/templates/deployment.yaml",
            "deploy/helm/templates/service.yaml",
        }
        assert {f["file"] for f in report.findings} <= set(files)
        ids = [
            f["check_id"]
            for f in report.findings
            if f["file"] == "deploy/helm/templates/service.yaml"
        ]
        assert ids and len(ids) == len(set(ids))

    @pytest.mark.asyncio
    async def test_dependency_repositories_are_never_contacted(self, monkeypatch):
        monkeypatch.setattr(settings, "checkov_bin", REAL_CHECKOV)
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        server.settimeout(0.2)
        port = server.getsockname()[1]
        connections = []
        stop = threading.Event()

        def accept():
            while not stop.is_set():
                try:
                    conn, _ = server.accept()
                except OSError:
                    continue
                connections.append(conn)
                conn.close()

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        dependencies = (
            "dependencies:\n"
            f"  - name: a\n    version: 1.0.0\n    repository: http://127.0.0.1:{port}/charts\n"
            f"  - name: b\n    version: 1.0.0\n    repository: oci://127.0.0.1:{port}/charts\n"
        )
        try:
            report = await run_checkov(chart_files(dependencies))
        finally:
            stop.set()
            thread.join()
            server.close()
        assert connections == []
        assert any(f["check_id"] == "CKV_K8S_16" for f in report.findings)
