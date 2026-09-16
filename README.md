# CloudGuard

Scans Terraform and Docker Compose configs for security issues using a multi-agent LLM pipeline — Groq (gpt-oss-120b) for auditing and patch generation, Gemini for embeddings and diagram analysis, pgvector for retrieval over past findings.

**[Live demo](https://cloud-guard-ai.duckdns.org)** — running on AWS.

## Running locally

You'll need Docker (or Podman), a [Groq API key](https://console.groq.com/) and a [Gemini API key](https://aistudio.google.com/).

```bash
cp .env.example .env
# fill in GROQ_API_KEY and GEMINI_API_KEY
docker compose up --build
```

Dashboard is at `http://localhost:8000`. Swagger at `/docs`. Postgres and a LocalStack S3 run alongside the backend; nothing leaves your machine except the LLM calls.

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | DB + S3 status |
| `POST` | `/api/audit` | Full audit, JSON response |
| `POST` | `/api/audit/stream` | Same pipeline, streamed as SSE |
| `POST` | `/api/audit/diagram` | Audit + architecture diagram drift check |
| `POST` | `/api/search` | Semantic search over your past findings |
| `GET` | `/api/history` | Your recent scans |
| `GET` | `/api/history/{audit_id}` | One scan with findings, original and patched file |
| `DELETE` | `/api/history` | Delete your scans and findings |

There are no accounts. Each browser gets a random `cg_workspace` cookie on its first request, and scans, search and the past fixes used as patch examples are all limited to that workspace, so visitors never see each other's data. Rows saved before workspaces existed have no workspace and aren't returned to anyone.

## Configuration

Everything is set through environment variables (see `.env.example`):

| Variable | Default | Notes |
|----------|---------|-------|
| `GROQ_API_KEY` | — | required |
| `GEMINI_API_KEY` | — | required |
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

## Deploying to AWS

The simplest setup is a single EC2 instance with Docker, using RDS-style managed Postgres or the bundled Postgres container, and a real S3 bucket.

1. **Instance**: t3.small or larger, Amazon Linux 2023 or Ubuntu, Docker + the compose plugin installed. Open ports 80/443 (behind a load balancer or reverse proxy) — don't expose 5432.
2. **IAM role**: attach an instance profile allowing `s3:CreateBucket`, `s3:HeadBucket`, `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` on your artifacts bucket. Then no AWS keys go in `.env` at all. Containers reach the role through instance metadata, so the instance's metadata hop limit must be at least 2 (`aws ec2 modify-instance-metadata-options --http-put-response-hop-limit 2`).
3. **Environment**: copy `.env.example` to `.env` on the host and set:

   ```bash
   APP_ENV=production
   GROQ_API_KEY=...           # real keys
   GEMINI_API_KEY=...
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
docker compose up -d postgres localstack
pytest backend/tests/ -v
```

The suite covers schemas, scoring, the agent pipeline (mocked LLMs), S3 round-trips against LocalStack, pgvector similarity search, and a full audit → search → history flow.

## License

MIT
