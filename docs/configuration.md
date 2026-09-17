# Configuration

CloudGuard reads its settings from environment variables, or from a `.env` file in the working directory. Names aren't case-sensitive. Start from [`.env.example`](../.env.example).

Containers read `.env` when they're created, not when they restart. After changing it, recreate the container:

```bash
docker compose -f docker-compose.prod.yml up -d --force-recreate backend
```

## Application

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | `production` hides exception messages in 500 responses. The production Compose file sets it for you |
| `APP_HOST` | `0.0.0.0` | Bind address when run directly |
| `APP_PORT` | `8000` | Port when run directly |
| `CORS_ORIGINS` | `*` | Comma-separated origins allowed to call the API from another site. The web app is served from the same origin and doesn't need this; set it to your domain in production. With `*`, cross-origin requests can't send cookies |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1,172.16.0.0/12` in production Compose | Proxies whose `X-Forwarded-For` header Uvicorn trusts. Rate limits and free-scan quotas use the resulting client address, so this must match your proxy and nothing else |

## Database and storage

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://cloudguard:cloudguard_secret@localhost:5432/cloudguard_db` | Async SQLAlchemy URL. The database needs the `vector` extension available; CloudGuard enables it on startup. Built from the `POSTGRES_*` values in production Compose |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | `cloudguard`, required, `cloudguard_db` | Used by the Compose files to create the database container |
| `S3_BUCKET_NAME` | `cloudguard-artifacts` | Bucket for scanned files, patches and database backups. Created on startup if it doesn't exist. Must be globally unique on AWS |
| `AWS_DEFAULT_REGION` | `us-east-1` | Region for the bucket |
| `AWS_ENDPOINT_URL` | unset | Set to LocalStack (`http://localstack:4566`) for local development. Leave unset on AWS |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | unset | Static credentials. Leave unset on AWS so the instance or task role is used |

## Scanner

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECKOV_BIN` | `checkov` (image: `/opt/checkov/bin/checkov`) | Path to the Checkov executable |
| `CHECKOV_TIMEOUT` | `90` | Seconds before a Checkov run is stopped and the scan fails |
| `MAX_IAC_CHARS` | `120000` | Largest Terraform accepted by the diagram endpoint. Pasted files on the JSON endpoints are also capped at 120,000 characters by the request schema |
| `MAX_DIAGRAM_BYTES` | `8388608` | Largest diagram image |

Upload and repository limits (10 MB zips, 25 MB repository downloads, 400 files) are constants in `backend/app/services/sources.py`, since raising them also changes memory needs.

## Abuse protection

| Variable | Default | Description |
|----------|---------|-------------|
| `SCAN_RATE_LIMIT` | `8` | Scans per client IP per 10 minutes, across all scan endpoints |
| `SEARCH_RATE_LIMIT` | `30` | Searches and model-list requests per client IP per minute |
| `MAX_CONCURRENT_SCANS` | `2` | Scans running at once in this process. Others wait up to 30 seconds |

Rate limit counters are kept in memory per process and reset on restart. That's deliberate for a single host; see [Deployment](deployment.md#running-more-than-one-instance) before scaling out.

## Free explained scans

| Variable | Default | Description |
|----------|---------|-------------|
| `GROQ_API_KEY` | empty | Key for the free tier. Empty means scans are Checkov only unless the visitor adds their own key |
| `FREE_LLM_SCANS_PER_DAY` | `5` | Explained scans per client IP per UTC day on the server's key. `0` turns the free tier off without removing the key |
| `USAGE_HASH_SALT` | derived from `DATABASE_URL` | Salt for the hashed client addresses stored in `llm_usage`. Set it explicitly if you rotate the database password, or counts restart for the day |

The free tier uses Groq's `openai/gpt-oss-120b`.

## Model budgets

These apply to free-tier scans. Scans with a visitor's own key use fixed, larger budgets (120,000 characters of review context, 60 explained findings, 5 patched files up to 60,000 characters each, 3 patches at a time, 40,000 characters of findings and 12,000 of earlier fixes per patch).

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_REVIEW_MAX_CHARS` | `9000` | Characters of source sent for review. Files with the most serious findings are chosen first |
| `LLM_MAX_EXPLAINED_FINDINGS` | `20` | Findings explained per scan, most severe first. The rest are listed without explanations |
| `LLM_PATCH_MAX_FILE_CHARS` | `8000` | Largest file that gets a patch |
| `LLM_MAX_PATCHED_FILES` | `3` | Files patched per scan |
| `LLM_PATCH_CONCURRENCY` | `1` | Patch requests sent at once |
| `LLM_PATCH_FINDINGS_CHARS` | `3000` | Characters of findings sent with each patch request, most severe first |
| `LLM_PATCH_EXAMPLES_CHARS` | `1500` | Characters of earlier fixes sent as examples with each patch request. Earlier patches are reduced to their changed lines first |

The defaults fit Groq's free allowance of 8,000 tokens per minute for this model. Terraform runs at about 2.5 characters per token, so 9,000 characters of source plus the findings list and instructions stays under the per-request ceiling. On a paid Groq tier, raising all of these gives fuller explanations for larger projects:

```bash
LLM_REVIEW_MAX_CHARS=40000
LLM_MAX_EXPLAINED_FINDINGS=40
LLM_PATCH_MAX_FILE_CHARS=30000
LLM_MAX_PATCHED_FILES=5
LLM_PATCH_CONCURRENCY=2
LLM_PATCH_FINDINGS_CHARS=10000
LLM_PATCH_EXAMPLES_CHARS=5000
```

## Embeddings

| Variable | Default | Description |
|----------|---------|-------------|
| `EMBEDDING_CACHE_DIR` | fastembed's cache (image: `/opt/models`) | Where the bge-small-en-v1.5 model files live |
| `EMBEDDING_THREADS` | `2` | ONNX Runtime threads for embedding |
| `HF_HUB_OFFLINE` | `1` in the image | Stops the model library from checking for updates at runtime |

Outside the image, the model (about 70 MB) downloads on first use.

## Backups

Read by the `backup` service in `docker-compose.prod.yml`.

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKUP_INTERVAL_SECONDS` | `86400` | Time between dumps. One also runs at startup |
| `BACKUP_PREFIX` | `backups` | Key prefix in `S3_BUCKET_NAME` |
