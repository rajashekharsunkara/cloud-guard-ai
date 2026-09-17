# GitHub Action and CLI

The web app is convenient for a one-off review. For code that changes every day, the same scanner runs from a terminal or on every pull request. Both use the pipeline described in [Architecture](architecture.md) without the database or S3: nothing is stored and nothing is sent anywhere except to the model provider you choose.

## GitHub Action

### Minimal setup

Add `.github/workflows/cloudguard.yml` to the repository that holds your infrastructure code:

```yaml
name: CloudGuard

on:
  pull_request:
    paths:
      - "infra/**"

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: rajashekharsunkara/cloud-guard-ai@main
        with:
          path: infra
          fail-on: high
```

On each pull request this:

1. Installs CloudGuard and a pinned Checkov into separate virtual environments on the runner.
2. Scans `infra/` and keeps only findings in files the pull request changes.
3. Posts the report as a comment on the pull request, and edits that same comment on later pushes instead of adding new ones.
4. Writes the report to the job summary.
5. Fails the check if any Checkov finding is `high` or `critical`.

`fetch-depth: 0` lets the action compare the branch with its base. With a shallow checkout it fetches the base commit itself, so the default depth also works in most cases.

Pinning to a commit SHA rather than `@main` is recommended for anything beyond a trial.

### With explanations

Add an API key as a repository secret (**Settings → Secrets and variables → Actions**) and pass it in:

```yaml
      - uses: rajashekharsunkara/cloud-guard-ai@main
        with:
          path: infra
          fail-on: high
          provider: anthropic
          model: claude-sonnet-5        # optional; the provider's suggested model otherwise
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

The comment then includes an explanation and fix for each finding, and issues found in review that no policy covers, listed separately and not scored. The key is passed to the scanner through an environment variable and GitHub masks it in logs.

Explanations never change whether the check passes. Only Checkov findings count towards `fail-on`, so the result is the same with or without a key and from one run to the next.

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan, relative to the repository root |
| `fail-on` | `high` | Fail when a Checkov finding is at or above this severity: `critical`, `high`, `medium`, `low` or `none` |
| `provider` | empty | `openai`, `anthropic`, `google`, `xai`, `groq` or `mistral`. Empty means Checkov only |
| `model` | empty | Model ID. Empty picks the provider's suggested model available to the key |
| `api-key` | empty | Provider API key; pass it from a secret |
| `changed-only` | `true` | On pull requests, report only findings in changed files |
| `comment` | `true` | Post or update a pull request comment |
| `github-token` | `github.token` | Token for the comment; needs `pull-requests: write` |

### Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | `0` nothing reached `fail-on`, `1` something did, `2` the scan failed |
| `report` | Path to the Markdown report on the runner |

To keep the report without failing the job, set `fail-on: none`, or use `continue-on-error: true` on the step and read `exit-code` in a later step.

### Behaviour worth knowing

- **Forks.** Pull requests from forks get a read-only token, so posting the comment fails without failing the job. The report is still in the job summary. Secrets aren't available to fork pull requests either, so those runs are Checkov only.
- **Push events.** Outside pull requests there's no base to compare with, so the whole path is reported and no comment is posted.
- **Scores for changed files.** With `changed-only`, the score in the comment is recalculated from the changed files alone.
- **Links.** File and line references in the comment link to the exact commit that was scanned.
- **Limits.** The same file limits as uploads apply: 400 configuration files, 1 MB per file. Point `path` at the infrastructure directory in large monorepos.

## CLI

### Install

The CLI runs from a checkout of this repository and needs Python 3.12 or newer.

```bash
git clone https://github.com/rajashekharsunkara/cloud-guard-ai.git
cd cloud-guard-ai
python -m venv .venv && .venv/bin/pip install -r requirements-cli.txt
python -m venv .checkov && .checkov/bin/pip install -r requirements-checkov.txt
export CHECKOV_BIN="$PWD/.checkov/bin/checkov"
```

`requirements-cli.txt` is a subset of the server's dependencies: the model SDKs and nothing for the database, S3 or embeddings. Checkov lives in its own virtual environment because its dependency pins conflict with the app's. Helm charts are only rendered when `helm` is on `PATH`; GitHub-hosted runners include it.

### Scan

```bash
.venv/bin/python -m backend.cli scan path/to/infra
```

```
CloudGuard scan: infra
Score: 32/100
2 critical, 1 high, 4 medium, 4 low

CRITICAL CKV_AWS_24    main.tf:6      Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
CRITICAL CKV_AWS_20    main.tf:1      S3 Bucket has an ACL defined which allows public READ access
HIGH     CKV2_AWS_6    main.tf:1      Ensure that S3 bucket has a Public Access block
MEDIUM   CKV_AWS_145   main.tf:1      Ensure that S3 buckets are encrypted with KMS by default
...
```

With a model:

```bash
export CLOUDGUARD_LLM_KEY=...        # read from the environment, never from a flag
.venv/bin/python -m backend.cli scan infra --provider openai --format markdown --output report.md
```

The key is only accepted through `CLOUDGUARD_LLM_KEY` so it doesn't end up in shell history or in a CI log that prints commands.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `path` | `.` | Directory to scan |
| `--provider` | none | Model provider; requires `CLOUDGUARD_LLM_KEY` |
| `--model` | provider's suggestion | Model ID |
| `--format` | `text` | `text`, `markdown` or `json` |
| `--output FILE` | stdout | Write the report to a file |
| `--fail-on` | `high` | `critical`, `high`, `medium`, `low` or `none` |
| `--changed-since REF` | none | Report only files changed on this branch since `REF` (like a pull request diff) |
| `--link-base URL` | none | Prefix for file links in Markdown output, for example `https://github.com/org/repo/blob/<sha>/infra/` |
| `--write-patches DIR` | none | Write patched files into `DIR`, keeping their relative paths |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No Checkov finding at or above `--fail-on` |
| `1` | At least one finding at or above `--fail-on` |
| `2` | The scan couldn't run: no configuration files, Checkov missing or failing, an invalid key format (or, without `--model`, a key the provider rejects), or an invalid git ref |

A model failure on its own doesn't cause a non-zero exit. The report falls back to Checkov results and says why in its notices, in the same way as the web app.

### Output formats

- **`text`** is for reading in a terminal: score, counts, then one line per finding.
- **`markdown`** is what the GitHub Action posts. It starts with the marker `<!-- cloudguard-report -->` so a later run can find and update its own comment, lists up to 50 Checkov findings and 50 review findings in tables, and puts explanations in a collapsible section. Patches aren't included in the comment; use `--write-patches` to get them as files.
- **`json`** is the full [scan result](api.md#scan-result), with `changed_files` added when `--changed-since` is used. Use it to feed other tools:

```bash
.venv/bin/python -m backend.cli scan infra --format json --fail-on none \
  | jq -r '.vulnerabilities[] | select(.severity == "CRITICAL") | "\(.file):\(.line_start) \(.check_id)"'
```

### Other CI systems

The CLI has no GitHub-specific behaviour apart from the options the action passes. In GitLab CI, for example:

```yaml
cloudguard:
  image: python:3.12
  script:
    - git clone --depth 1 https://github.com/rajashekharsunkara/cloud-guard-ai.git /opt/cloudguard
    - python -m venv /opt/cg && /opt/cg/bin/pip install -q -r /opt/cloudguard/requirements-cli.txt
    - python -m venv /opt/ck && /opt/ck/bin/pip install -q -r /opt/cloudguard/requirements-checkov.txt
    - export CHECKOV_BIN=/opt/ck/bin/checkov PYTHONPATH=/opt/cloudguard
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - /opt/cg/bin/python -m backend.cli scan infra --changed-since "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --format markdown --output cloudguard.md
  artifacts:
    when: always
    paths: [cloudguard.md]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```
