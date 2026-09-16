# CloudGuard

Scans infrastructure code for security issues: a pasted file, a zip, or a public GitHub repository. [Checkov](https://www.checkov.io/) finds the problems and decides the score, so results are the same on every run; a language model then explains each finding, flags issues no policy covers, and writes patched files. A local embedding model (bge-small via fastembed) and pgvector retrieve earlier fixes as examples, and a vision-capable model compares architecture diagrams with the code.

Checkov results are free and unlimited. Explained scans run on the server's Groq key (gpt-oss-120b), capped per visitor per day, or on the visitor's own OpenAI, Anthropic, Google, xAI, Groq or Mistral key with no cap. Visitor keys stay in the browser and are sent per request as `X-LLM-Provider`, `X-LLM-Model` and `X-LLM-Key` headers; the server never stores or logs them, and provider base URLs are fixed server-side.

**[Live demo](https://cloud-guard-ai.duckdns.org)** — running on AWS.

## Running locally

You'll need Docker (or Podman). A [Groq API key](https://console.groq.com/) enables free explained scans; without one, scans show Checkov results unless visitors add their own key.

```bash
cp .env.example .env
# fill in GROQ_API_KEY for free explained scans (optional)
docker compose up --build
```

Dashboard is at `http://localhost:8000`. Swagger at `/docs`. Postgres and a LocalStack S3 run alongside the backend; nothing leaves your machine except the LLM calls.

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | DB + S3 status |
| `GET` | `/api/usage` | Free explained scans left today for this client |
| `GET` | `/api/llm/providers` | Providers usable with a visitor's own key |
| `POST` | `/api/llm/models` | Check a key (`X-LLM-Key` header) and list the chat models it can use |
| `POST` | `/api/audit` | Checkov scan, explained and patched when the free tier allows; JSON response |
| `POST` | `/api/audit/stream` | Same pipeline, streamed as SSE |
| `POST` | `/api/audit/archive` | Scan a zip upload (multipart field `archive`), streamed as SSE |
| `POST` | `/api/audit/repo` | Scan a public GitHub repo or folder (`{"url": ...}`), streamed as SSE |
| `POST` | `/api/audit/diagram` | Audit + architecture diagram drift check; needs the own-key headers |
| `POST` | `/api/search` | Semantic search over your past findings |
| `GET` | `/api/history` | Your recent scans |
| `GET` | `/api/history/{audit_id}` | One scan with findings, original and patched file |
| `DELETE` | `/api/history` | Delete your scans and findings |

There are no accounts. Each browser gets a random `cg_workspace` cookie on its first request, and scans, search and the past fixes used as patch examples are all limited to that workspace, so visitors never see each other's data. Rows saved before workspaces existed have no workspace and aren't returned to anyone.

## GitHub Action

Scan infrastructure code on every pull request and get the report as a comment. The action runs in your own CI with your own secrets; nothing is sent to the CloudGuard site.

```yaml
name: CloudGuard
on: pull_request

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # lets the scan compare against the pull request base

      - uses: rajashekharsunkara/cloud-guard-ai@main
        with:
          path: infra
          fail-on: high              # critical, high, medium, low or none
          # Optional explanations and review findings with your own key:
          provider: anthropic        # openai, anthropic, google, xai, groq, mistral
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

| Input | Default | |
|-------|---------|--|
| `path` | `.` | directory to scan |
| `fail-on` | `high` | fail the job when a Checkov finding reaches this severity; review findings never fail it |
| `provider`, `model`, `api-key` | empty | explanations with your own key; without them the report is Checkov only |
| `changed-only` | `true` | on pull requests, only report files the pull request changes |
| `comment` | `true` | create or update one comment on the pull request |

The report also goes to the job summary, so pull requests from forks (which get a read-only token) still show it. This repository runs the action on itself in `.github/workflows/cloudguard.yml`.

## Command line

The same scan runs locally without the web app, database or S3:

```bash
pip install -r requirements-cli.txt
python -m venv .checkov && .checkov/bin/pip install -r requirements-checkov.txt
export CHECKOV_BIN=.checkov/bin/checkov

python -m backend.cli scan infra/ --fail-on high
CLOUDGUARD_LLM_KEY=sk-... python -m backend.cli scan infra/ --provider openai --format markdown --output report.md
python -m backend.cli scan . --changed-since origin/main --write-patches patched/
```

The key is read from `CLOUDGUARD_LLM_KEY` so it stays out of shell history. Exit code 0 means nothing reached `--fail-on`, 1 means something did, 2 means the scan couldn't run. `--format` takes `text`, `markdown` or `json`.

## Configuration

Everything is set through environment variables (see `.env.example`):

| Variable | Default | Notes |
|----------|---------|-------|
| `GROQ_API_KEY` | — | explained scans and patches; without it scans are Checkov only |
| `DATABASE_URL` | local Postgres | any Postgres 15+ with the pgvector extension |
| `AWS_ENDPOINT_URL` | unset | set to a LocalStack URL for dev; leave unset for real AWS |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | unset | leave empty on AWS to use the IAM role |
| `AWS_DEFAULT_REGION` | `us-east-1` | |
| `S3_BUCKET_NAME` | `cloudguard-artifacts` | must be globally unique on real AWS |
| `APP_ENV` | `development` | set `production` to reduce log noise and hide error details |
| `CORS_ORIGINS` | `*` | comma-separated; lock down in production |
| `SCAN_RATE_LIMIT` | `8` | scans per client IP per 10 minutes |
| `SEARCH_RATE_LIMIT` | `30` | searches per client IP per minute |
| `MAX_CONCURRENT_SCANS` | `2` | scans running at once; others wait up to 30s, then get a 503 |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | proxies trusted to set `X-Forwarded-For`; the prod compose file trusts the Docker bridge |
| `BACKUP_INTERVAL_SECONDS` | `86400` | prod compose only; how often the database is dumped to S3 |
| `FREE_LLM_SCANS_PER_DAY` | `5` | explained scans per client IP per UTC day; `0` for Checkov only |
| `USAGE_HASH_SALT` | derived from `DATABASE_URL` | key for hashing client IPs in the usage table |
| `CHECKOV_BIN` | `checkov` | set by the Docker image; point at a checkov install for local runs |
| `CHECKOV_TIMEOUT` | `90` | seconds before a scan is stopped |
| `LLM_REVIEW_MAX_CHARS` | `16000` | file content sent for explanations; files with worse findings go first |
| `LLM_MAX_EXPLAINED_FINDINGS` | `25` | findings explained per scan |
| `LLM_MAX_PATCHED_FILES` | `3` | files patched per scan |
| `LLM_PATCH_MAX_FILE_CHARS` | `12000` | larger files aren't rewritten |
| `LLM_PATCH_CONCURRENCY` | `1` | patch requests in parallel |
| `EMBEDDING_CACHE_DIR` | set by the image | where the local embedding model lives |

The `LLM_*` defaults fit Groq's free tier, which allows 8,000 tokens per minute for gpt-oss-120b across all visitors. On that tier an explained scan of a large project takes a few minutes, and concurrent explained scans will hit the limit; the app then falls back to Checkov results and says so. A paid Groq tier lifts the limit, after which these values can be raised.

## Deploying to AWS

The simplest setup is a single EC2 instance with Docker, using RDS-style managed Postgres or the bundled Postgres container, and a real S3 bucket.

1. **Instance**: t3.small or larger, Amazon Linux 2023 or Ubuntu, Docker + the compose plugin installed. Open ports 80/443 (behind a load balancer or reverse proxy) — don't expose 5432.
2. **IAM role**: attach an instance profile allowing `s3:CreateBucket`, `s3:HeadBucket`, `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` on your artifacts bucket. Then no AWS keys go in `.env` at all. Containers reach the role through instance metadata, so the instance's metadata hop limit must be at least 2 (`aws ec2 modify-instance-metadata-options --http-put-response-hop-limit 2`).
3. **Environment**: copy `.env.example` to `.env` on the host and set:

   ```bash
   APP_ENV=production
   GROQ_API_KEY=...           # real keys
   POSTGRES_PASSWORD=...      # generate a strong one
   AWS_ENDPOINT_URL=          # empty: use real AWS
   AWS_ACCESS_KEY_ID=         # empty: use the IAM role
   AWS_SECRET_ACCESS_KEY=
   AWS_DEFAULT_REGION=us-east-1
   S3_BUCKET_NAME=your-unique-bucket-name
   CORS_ORIGINS=https://your-domain.example
   ```

4. **Run it**:

   ```bash
   docker compose -f docker-compose.prod.yml up --build -d
   ```

   The backend listens on `127.0.0.1:8000` only, so run the TLS proxy on the same host. With Caddy the whole config is:

   ```
   your-domain.example {
       reverse_proxy localhost:8000
   }
   ```

   `/api/health` works as a health check.

5. **Backups**: the `backup` service dumps the database to `s3://<bucket>/backups/` when it starts and then once a day. Check it with `docker compose -f docker-compose.prod.yml logs backup`. Add an S3 lifecycle rule on the `backups/` prefix (for example, expire after 30 days) so old dumps don't pile up.

   To restore, stop the backend, then load a dump into the database:

   ```bash
   docker compose -f docker-compose.prod.yml stop backend
   aws s3 cp s3://<bucket>/backups/cloudguard-<timestamp>.dump restore.dump
   docker compose -f docker-compose.prod.yml exec -T postgres \
     pg_restore --clean --if-exists --no-owner -U cloudguard -d cloudguard_db < restore.dump
   docker compose -f docker-compose.prod.yml start backend
   ```

To use a managed database instead of the Postgres container, point `DATABASE_URL` at an RDS Postgres instance with the `vector` extension available (RDS supports pgvector on Postgres 15.2+) and drop the `postgres` service from the compose file.

ECS/Fargate works the same way: build the image from the `Dockerfile`, pass the environment above as task definition secrets, and give the task role the S3 permissions. Rate limits are kept in memory per process, so behind a load balancer with several tasks each task counts separately.

## Tests

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m venv .checkov && .checkov/bin/pip install -r requirements-checkov.txt
docker compose up -d postgres localstack
CHECKOV_BIN=.checkov/bin/checkov pytest backend/tests/ -v
```

Checkov lives in its own virtualenv because its dependency tree is large and pinned separately (`requirements-checkov.txt`). Without `CHECKOV_BIN` the tests that run the real scanner are skipped; everything else uses recorded Checkov output from `backend/tests/fixtures`.

The suite covers severity ratings and scoring, Checkov output parsing and sandboxing, the scan pipeline in each mode (mocked LLMs), rate limits, the daily free-scan quota under concurrency, S3 round-trips against LocalStack, pgvector search, and a full audit → search → history flow.

## License

MIT
