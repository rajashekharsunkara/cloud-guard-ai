import io
import stat
import tarfile
import zipfile

import httpx
import pytest

from backend.app.services import sources
from backend.app.services.sources import (
    RepoRef,
    SourceError,
    download_repo,
    is_scannable,
    load_tarball,
    load_zip,
    parse_github_url,
)


def make_zip(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buf.getvalue()


def make_tarball(entries: dict, root="repo-abc123") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, content in entries.items():
            data = content.encode()
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class TestScannable:

    @pytest.mark.parametrize(
        "path, expected",
        [
            ("main.tf", True),
            ("modules/vpc/variables.tf", True),
            ("k8s/deploy.yaml", True),
            ("docker-compose.yml", True),
            ("Dockerfile", True),
            ("api/Dockerfile.prod", True),
            ("template.json", True),
            ("README.md", False),
            ("app/main.py", False),
            ("package-lock.json", False),
            (".terraform/modules/x/main.tf", False),
            ("node_modules/pkg/config.yaml", False),
        ],
    )
    def test_paths(self, path, expected):
        from pathlib import PurePosixPath

        assert is_scannable(PurePosixPath(path)) is expected


class TestLoadZip:

    def test_collects_config_files(self):
        data = make_zip(
            {
                "infra/main.tf": 'resource "x" "y" {}',
                "infra/README.md": "docs",
                "app/Dockerfile": "FROM python:3.12",
                "chart/templates/_helpers.tpl": '{{- define "x" -}}{{- end -}}',
                "infra/": "",
            }
        )
        source = load_zip(data, "project.zip")
        assert source.label == "project.zip"
        assert source.files == {
            "infra/main.tf": 'resource "x" "y" {}',
            "app/Dockerfile": "FROM python:3.12",
            "chart/templates/_helpers.tpl": '{{- define "x" -}}{{- end -}}',
        }

    def test_traversal_names_stay_inside(self):
        source = load_zip(
            make_zip({"../../etc/cron.d/evil.tf": "x", "/abs/main.tf": "y"}), "z"
        )
        assert set(source.files) == {"etc/cron.d/evil.tf", "abs/main.tf"}

    def test_symlinks_are_ignored(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            link = zipfile.ZipInfo("link.tf")
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(link, "/etc/passwd")
            archive.writestr("main.tf", "real")
        assert load_zip(buf.getvalue(), "z").files == {"main.tf": "real"}

    def test_not_a_zip(self):
        with pytest.raises(SourceError, match="valid zip"):
            load_zip(b"definitely not a zip", "z")

    def test_no_config_files(self):
        with pytest.raises(SourceError, match="No Terraform"):
            load_zip(make_zip({"README.md": "hi"}), "z")

    def test_too_large_upload(self):
        with pytest.raises(SourceError, match="10 MB"):
            load_zip(b"0" * (sources.MAX_ARCHIVE_BYTES + 1), "z")

    def test_compression_bomb_is_capped(self, monkeypatch):
        monkeypatch.setattr(sources, "MAX_TOTAL_BYTES", 3 * 1024 * 1024)
        # Each file is 900 KB of zeros and compresses to almost nothing.
        entries = {f"f{i}.tf": "0" * (900 * 1024) for i in range(10)}
        data = make_zip(entries)
        assert len(data) < 100 * 1024
        with pytest.raises(SourceError, match="add up to more than"):
            load_zip(data, "bomb.zip")

    def test_oversized_single_file_is_skipped(self):
        data = make_zip({"big.tf": "0" * (sources.MAX_FILE_BYTES + 10), "ok.tf": "x"})
        source = load_zip(data, "z")
        assert source.files == {"ok.tf": "x"}
        assert source.skipped_large == 1

    def test_too_many_files(self, monkeypatch):
        monkeypatch.setattr(sources, "MAX_FILES", 3)
        with pytest.raises(SourceError, match="More than 3"):
            load_zip(make_zip({f"{i}.tf": "x" for i in range(5)}), "z")

    def test_binary_files_are_skipped(self):
        data = make_zip(
            {"weird.json": b"\xff\xfe\x00bad".decode("latin-1"), "main.tf": "ok"}
        )
        assert "main.tf" in load_zip(data, "z").files


class TestGithubUrls:

    @pytest.mark.parametrize(
        "url, expected",
        [
            ("https://github.com/org/repo", ("org", "repo", "HEAD", "")),
            ("https://github.com/org/repo/", ("org", "repo", "HEAD", "")),
            ("https://github.com/org/repo.git", ("org", "repo", "HEAD", "")),
            ("https://github.com/org/my.repo", ("org", "my.repo", "HEAD", "")),
            ("https://github.com/org/repo/tree/main", ("org", "repo", "main", "")),
            (
                "https://github.com/org/repo/tree/v1.2/infra/prod",
                ("org", "repo", "v1.2", "infra/prod"),
            ),
        ],
    )
    def test_accepted(self, url, expected):
        ref = parse_github_url(url)
        assert (ref.owner, ref.repo, ref.ref, ref.subpath) == expected

    @pytest.mark.parametrize(
        "url",
        [
            "http://github.com/org/repo",
            "https://gitlab.com/org/repo",
            "https://github.com.evil.com/org/repo",
            "https://github.com/org",
            "https://github.com/org/repo/blob/main/main.tf",
            "https://github.com/org/repo/tree/../../x",
            "https://github.com/org/repo/tree/main/../../etc",
            "https://github.com/org/repo/tree/ma in",
            "https://github.com/org/repo?x=1",
        ],
    )
    def test_rejected(self, url):
        with pytest.raises(SourceError):
            parse_github_url(url)

    def test_label(self):
        assert RepoRef("org", "repo", "HEAD", "").label == "org/repo"
        assert RepoRef("org", "repo", "main", "infra").label == "org/repo@main/infra"


class TestLoadTarball:

    def test_strips_root_and_filters_folder(self):
        data = make_tarball(
            {
                "infra/main.tf": "a",
                "infra/sub/x.tf": "b",
                "other/y.tf": "c",
                "README.md": "d",
            }
        )
        repo = RepoRef("org", "repo", "main", "infra")
        assert load_tarball(data, repo).files == {"main.tf": "a", "sub/x.tf": "b"}

    def test_whole_repo(self):
        data = make_tarball({"main.tf": "a", "k8s/app.yaml": "b"})
        assert set(load_tarball(data, RepoRef("o", "r", "HEAD", "")).files) == {
            "main.tf",
            "k8s/app.yaml",
        }

    def test_missing_folder(self):
        data = make_tarball({"main.tf": "a"})
        with pytest.raises(SourceError, match="infra/"):
            load_tarball(data, RepoRef("o", "r", "HEAD", "infra"))

    def test_corrupt_archive(self):
        with pytest.raises(SourceError, match="couldn't be read"):
            load_tarball(b"\x1f\x8bgarbage", RepoRef("o", "r", "HEAD", ""))


class TestDownloadRepo:

    @pytest.mark.asyncio
    async def test_requests_codeload_only(self):
        seen = []

        def handler(request):
            seen.append(str(request.url))
            return httpx.Response(200, content=b"tarball")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        data = await download_repo(RepoRef("org", "repo", "v1.2", "infra"), client)
        assert data == b"tarball"
        assert seen == ["https://codeload.github.com/org/repo/tar.gz/v1.2"]

    @pytest.mark.asyncio
    async def test_not_found(self):
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(404))
        )
        with pytest.raises(SourceError, match="public repositories"):
            await download_repo(RepoRef("org", "private", "HEAD", ""), client)

    @pytest.mark.asyncio
    async def test_size_cap(self, monkeypatch):
        monkeypatch.setattr(sources, "MAX_REPO_BYTES", 10)
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, content=b"x" * 50)
            )
        )
        with pytest.raises(SourceError, match="larger than"):
            await download_repo(RepoRef("org", "big", "HEAD", ""), client)

    @pytest.mark.asyncio
    async def test_network_error(self):
        def handler(request):
            raise httpx.ConnectError("down")

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        with pytest.raises(SourceError, match="reach GitHub"):
            await download_repo(RepoRef("org", "repo", "HEAD", ""), client)
