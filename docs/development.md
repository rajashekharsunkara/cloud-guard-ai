# Development

## Project layout

```
backend/
  app/
    main.py                FastAPI app, startup checks, middleware, static files
    core/
      config.py            settings from environment variables
      database.py          engine, tables, idempotent schema upgrades
      aws.py               S3 client and bucket creation
      ratelimit.py         per-IP sliding windows, concurrent scan slots
      workspace.py         anonymous per-browser workspace cookie
    routers/auditor.py     every /api endpoint
    schemas/auditor.py     request and response models
    services/
      pipeline.py          a scan from files to saved result, as a stream of events
      sources.py           paste, zip, GitHub and local directory inputs with limits
      checkov.py           runs Checkov and parses its JSON
      severity.py          severity per check and the score
      llm.py               provider interface: JSON completions, images, model lists, errors
      agents.py            review, patch and diagram steps built on llm.py
      embeddings.py        local bge-small embedding model
      usage.py             daily free-scan quota in PostgreSQL
      free_tier.py         shared busy/exhausted state for the free provider
      db_service.py        queries, always scoped to a workspace
      storage.py           S3 uploads
    prompts/               prompt templates for review, patches and diagrams
  cli.py                   command-line scanner
  tests/                   pytest suite and fixtures
frontend/
  index.html               single page: scan, report, history, how it works
  css/styles.css
  js/                      ES modules, no build step
  fonts/                   IBM Plex, self-hosted
deploy/backup/             pg_dump-to-S3 container
terraform/                 S3 bucket definition
action.yml                 GitHub Action
docker-compose.yml         local stack with live reload
docker-compose.prod.yml    production stack
requirements.txt           server dependencies
requirements-cli.txt       CLI and Action dependencies (subset)
requirements-checkov.txt   Checkov, pinned, installed in its own virtualenv
requirements-dev.txt       test and lint tools
```

## Local setup

### Everything in containers

```bash
cp .env.example .env
docker compose up --build
```

The backend container mounts `backend/` and `frontend/` and reloads on change. Open `http://localhost:8000`.

### App on the host, services in containers

Faster to iterate on and easier to debug.

```bash
docker compose up -d postgres localstack

python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
python3.12 -m venv .checkov
.checkov/bin/pip install -r requirements-checkov.txt

cp .env.example .env
export DATABASE_URL=postgresql+asyncpg://cloudguard:cloudguard_secret@localhost:5432/cloudguard_db
export AWS_ENDPOINT_URL=http://localhost:4566
export CHECKOV_BIN="$PWD/.checkov/bin/checkov"

.venv/bin/uvicorn backend.app.main:app --reload
```

Exported variables take precedence over `.env`, so the container hostnames in `.env` can stay as they are.

## Tests

```bash
docker compose up -d postgres localstack
CHECKOV_BIN="$PWD/.checkov/bin/checkov" .venv/bin/pytest backend/tests
```

The test configuration rewrites the `postgres` and `localstack` hostnames from `.env` to `localhost`, so the same `.env` works for both. No test calls a real model provider; provider responses are faked at the SDK or HTTP layer.

| File | Covers |
|------|--------|
| `test_checkov.py` | Parsing real Checkov output, coverage rules, path safety, and a run of the real binary when `CHECKOV_BIN` is set (skipped otherwise) |
| `test_severity.py` | Explicit and keyword ratings, score curve, determinism |
| `test_sources.py` | Zip and tarball limits, traversal and symlink handling, GitHub URL parsing, directory loading |
| `test_llm.py` | Key and model validation, fixed base URLs, error classification and retry times, request shapes for each SDK (JSON mode, schemas, images, fallbacks), model listing and defaults |
| `test_agents.py` | Matching explanations to findings, cleaning model output, review file selection within budgets, patch and diagram requests, embedding batches |
| `test_pipeline.py` | Static-only, explained, failed-review, daily-limit, uncovered-file and failed-patch scans |
| `test_usage.py` | Quota claims and refunds, concurrent claims never exceeding the limit, hashed addresses |
| `test_ratelimit.py` | Sliding windows and scan slots |
| `test_schemas.py` | Request validation |
| `test_cli.py` | Exit codes, changed-file filtering against a real git repository, output formats |
| `test_integration.py` | Endpoints with dependencies mocked: health, audit, search, history, upload and repository errors, own-key headers, usage |
| `test_db_integration.py` | Tables, pgvector extension, similarity search against PostgreSQL |
| `test_storage_integration.py` | Bucket creation and uploads against LocalStack |
| `test_e2e.py` | Scan, search and history through the API against real PostgreSQL, with Checkov and the model mocked |

Run a subset while working:

```bash
.venv/bin/pytest backend/tests/test_sources.py -k traversal -q
```

`backend/tests/fixtures/checkov_sample.json` is trimmed real Checkov output. When upgrading Checkov, regenerate it with `checkov -o json --compact` on the same inputs so parsing is tested against the new format.

## Lint and format

```bash
.venv/bin/black backend/
.venv/bin/flake8 backend/ --max-line-length=120 --max-complexity=10
```

## Continuous integration

`.github/workflows/devsecops-ci.yml` runs on pushes to `main` and `develop` and on pull requests:

1. **Lint and test:** installs dependencies and Checkov, runs flake8, `black --check` and the full test suite against PostgreSQL (pgvector) and LocalStack service containers.
2. **Container build:** builds the production image once tests pass.

`.github/workflows/cloudguard.yml` runs this repository's own GitHub Action on pull requests that touch Terraform, deployment or Compose files, and fails on critical findings.

## Common changes

### Adjust a severity rating

Ratings live in `backend/app/services/severity.py`. For one check, add it to `CHECK_SEVERITY`:

```python
CHECK_SEVERITY = {
    ...
    "CKV_AWS_338": "LOW",  # CloudWatch log group retention under a year
}
```

For a family of checks, add or edit a keyword rule in `_RULES`; the first match wins and anything unmatched is `MEDIUM`. Add a case to `test_severity.py`. Scores in history aren't recalculated, so existing scans keep the rating they were saved with.

### Add a model provider

Providers that offer an OpenAI-compatible chat completions API need only an entry in `PROVIDERS` in `backend/app/services/llm.py`:

```python
Provider(
    "example",
    "Example AI",
    "openai",                                  # use the OpenAI SDK
    base_url="https://api.example.com/v1",     # fixed; never taken from a request
    preferred=("example-large", "example-medium"),
    key_url="https://example.com/account/keys",
),
```

- `preferred` is the order of default models; the first one returned by the provider's model list for that key wins.
- Check that the provider supports JSON mode (`response_format: {"type": "json_object"}`). If it doesn't, the review step will report unreadable responses.
- Check its rate limit error format. `_limit_error` recognises per-day limits by phrases such as "per day", `(TPD)` and `(RPD)`, and retry times from the `Retry-After` header or "try again in 1m30s" in the message. Add a case to `test_llm.py` with a real error body.
- Add the ID to the `provider` input description in `action.yml`.

The model settings dialog reads `/api/llm/providers`, so the frontend needs no change.

Providers with their own API shape need a `kind`, a completion function next to `_anthropic_complete` and `_google_complete`, a model list function, and error classification for their SDK's exception types.

### Change a prompt

Prompts are plain text files in `backend/app/prompts/` with `str.format` placeholders. The review prompt's JSON shape must match `REVIEW_SCHEMA` in `agents.py`, which Anthropic models receive as a strict schema. Test changes against the free-tier model as well as a large one: the free tier's budgets leave little room, and a longer prompt reduces how much code fits.

### Change the database schema

Tables are created from the SQLAlchemy models on startup. For a change to an existing table, append an idempotent statement to `_UPGRADES` in `backend/app/core/database.py`:

```python
"ALTER TABLE audits ADD COLUMN IF NOT EXISTS reviewed_by TEXT",
```

It runs on every start, on fresh and existing databases alike, so it must be safe to repeat. Wrap anything that isn't naturally idempotent in a `DO $$ ... $$` block that checks the current state first.

### Add a scan input

Inputs produce a `SourceFiles` object through a `_Collector`, which applies file type filters and size limits. Build a `ScanInput` with a new `source` value, then stream `_stream_scan(scan, fetch)` from a router endpoint the way `/audit/repo` does, so the download happens inside a scan slot and failures become `error` events.

## Frontend

No framework or build step. `index.html` holds the markup; `js/app.js` wires the modules together.

| Module | Responsibility |
|--------|----------------|
| `scan.js` | Intake tabs, request streaming, progress |
| `report.js` | The annotated code sheet, notes, minimap, keyboard navigation, limit messages |
| `diff.js` | Line diff for patches |
| `history.js` | History list, search, detail view, clearing |
| `model.js` | Model settings dialog, key storage, request headers |
| `diagram.js` | Diagram check form |
| `markdown.js`, `util.js` | Escaping, a minimal Markdown renderer, shared helpers |

Everything inserted into the page goes through `escapeHtml` or `inlineMarkdown`. Keep it that way for any new field: filenames, source code and model output all come from untrusted input.

The styles use CSS custom properties for the palette, with the dark theme under `:root[data-theme="dark"]`. Test changes at phone width as well as desktop.
