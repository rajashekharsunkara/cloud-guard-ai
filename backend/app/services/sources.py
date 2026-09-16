"""Turn a zip upload or a public GitHub repository into files to scan.

Everything is read into memory with hard limits and never extracted to disk
under client-controlled names, so archives can't write outside the scan
directory, and oversized or deeply compressed archives stop early.
"""

import io
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import httpx

from backend.app.services.checkov import safe_relative_path

MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
# GitHub serves whole-repository tarballs even when only a folder is wanted.
MAX_REPO_BYTES = 25 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 400
# Members walked, including skipped ones; stops archives built to waste CPU.
MAX_MEMBERS = 20_000

SCANNED_SUFFIXES = (
    ".tf",
    ".tf.json",
    ".tfvars",
    ".hcl",
    ".yaml",
    ".yml",
    ".json",
    ".template",
    ".bicep",
    ".dockerfile",
)
SKIPPED_DIRS = {".git", ".terraform", "node_modules", "vendor", ".venv", "venv"}
# JSON and YAML that is never infrastructure code but often large.
SKIPPED_NAMES = {
    "package-lock.json",
    "package.json",
    "composer.json",
    "composer.lock",
    "tsconfig.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    ".terraform.lock.hcl",
}


class SourceError(ValueError):
    """The upload or repository can't be scanned; the message is shown to the user."""


@dataclass
class SourceFiles:
    label: str
    files: dict[str, str] = field(default_factory=dict)
    skipped_large: int = 0


def is_scannable(path: PurePosixPath) -> bool:
    if any(part in SKIPPED_DIRS for part in path.parts[:-1]):
        return False
    name = path.name.lower()
    if name in SKIPPED_NAMES:
        return False
    return name.startswith("dockerfile") or name.endswith(SCANNED_SUFFIXES)


class _Collector:
    def __init__(self, label: str):
        self.result = SourceFiles(label=label)
        self.total = 0
        self.members = 0

    def visit(self) -> None:
        self.members += 1
        if self.members > MAX_MEMBERS:
            raise SourceError("The archive has too many entries to scan.")

    def add(self, name: str, size: int, read) -> None:
        try:
            path = safe_relative_path(name)
        except ValueError:
            return
        if not is_scannable(path):
            return
        if size > MAX_FILE_BYTES:
            self.result.skipped_large += 1
            return
        if len(self.result.files) >= MAX_FILES:
            raise SourceError(
                f"More than {MAX_FILES} configuration files. "
                "Scan the folder that holds your infrastructure code instead."
            )
        # Read one byte past the limit so a header that lies about the size
        # can't sneak a bigger file through.
        data = read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            self.result.skipped_large += 1
            return
        self.total += len(data)
        if self.total > MAX_TOTAL_BYTES:
            raise SourceError("The configuration files add up to more than 20 MB.")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return
        self.result.files[str(path)] = text

    def finish(self) -> SourceFiles:
        if not self.result.files:
            raise SourceError(
                "No Terraform, CloudFormation, Kubernetes, Compose or Dockerfile "
                "files were found."
            )
        return self.result


def load_zip(data: bytes, label: str) -> SourceFiles:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise SourceError("Zip files can be up to 10 MB.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise SourceError("That file isn't a valid zip archive.")

    collector = _Collector(label)
    with archive:
        for info in archive.infolist():
            collector.visit()
            if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
                continue
            if info.flag_bits & 0x1:
                raise SourceError("Encrypted zip files aren't supported.")

            def read(limit, info=info):
                with archive.open(info) as member:
                    return member.read(limit)

            collector.add(info.filename, info.file_size, read)
    return collector.finish()


GITHUB_URL = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<repo>[A-Za-z0-9._-]{1,100}?)(?:\.git)?"
    r"(?:/tree/(?P<ref>[A-Za-z0-9._/-]+?))?/?$"
)
SAFE_REF = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass
class RepoRef:
    owner: str
    repo: str
    ref: str
    subpath: str

    @property
    def label(self) -> str:
        where = f"{self.owner}/{self.repo}"
        if self.ref != "HEAD":
            where += f"@{self.ref}"
        return f"{where}/{self.subpath}" if self.subpath else where


def parse_github_url(url: str) -> RepoRef:
    match = GITHUB_URL.match(url.strip())
    if not match:
        raise SourceError(
            "Use a GitHub link like https://github.com/owner/repo "
            "or https://github.com/owner/repo/tree/main/infra"
        )
    ref, subpath = "HEAD", ""
    if match["ref"]:
        # Branch names can contain slashes, which makes tree URLs ambiguous;
        # treat the first segment as the ref and the rest as a folder.
        ref, _, subpath = match["ref"].partition("/")
    if not SAFE_REF.match(ref) or ref.startswith("."):
        raise SourceError("That branch or tag name isn't supported.")
    if match["repo"] in (".", "..") or ".." in subpath.split("/"):
        raise SourceError("That repository link isn't supported.")
    return RepoRef(match["owner"], match["repo"], ref, subpath.strip("/"))


async def download_repo(repo: RepoRef, client: httpx.AsyncClient = None) -> bytes:
    # Always this host with a path built from validated parts, so the
    # request can't be pointed anywhere else.
    url = f"https://codeload.github.com/{repo.owner}/{repo.repo}/tar.gz/{repo.ref}"
    owns_client = client is None
    client = client or httpx.AsyncClient(
        timeout=httpx.Timeout(30.0), follow_redirects=False
    )
    try:
        async with client.stream("GET", url) as response:
            if response.status_code == 404:
                raise SourceError(
                    "Repository or branch not found. Only public repositories can be scanned."
                )
            if response.status_code != 200:
                raise SourceError(
                    "GitHub didn't return the repository. Try again later."
                )
            chunks, size = [], 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_REPO_BYTES:
                    raise SourceError(
                        "The repository is larger than 25 MB compressed, which is more "
                        "than CloudGuard downloads. Upload a zip of the folder with your "
                        "infrastructure code instead."
                    )
                chunks.append(chunk)
            return b"".join(chunks)
    except httpx.HTTPError:
        raise SourceError("Couldn't reach GitHub. Try again later.")
    finally:
        if owns_client:
            await client.aclose()


def load_tarball(data: bytes, repo: RepoRef) -> SourceFiles:
    collector = _Collector(repo.label)
    prefix = PurePosixPath(repo.subpath) if repo.subpath else None
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
            for member in archive:
                collector.visit()
                if not member.isfile():
                    continue
                # GitHub tarballs wrap everything in "<repo>-<sha>/".
                parts = PurePosixPath(member.name).parts[1:]
                if not parts:
                    continue
                path = PurePosixPath(*parts)
                if prefix is not None:
                    if prefix not in path.parents:
                        continue
                    path = path.relative_to(prefix)

                def read(limit, member=member):
                    handle = archive.extractfile(member)
                    return handle.read(limit) if handle else b""

                collector.add(str(path), member.size, read)
    except (tarfile.TarError, EOFError, OSError):
        raise SourceError("The repository archive couldn't be read.")

    if prefix is not None and not collector.result.files:
        raise SourceError(f"No configuration files found in {repo.subpath}/.")
    return collector.finish()
