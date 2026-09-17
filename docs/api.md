# API reference

Everything the web app does goes through this JSON API. An interactive reference generated from the code is served at `/docs` (Swagger UI) and `/redoc`.

Base path: `/api`. All request and response bodies are JSON unless noted.

## Identity and keys

**Workspace cookie.** There are no accounts. The first response to a client sets `cg_workspace`, a random 32-character ID in an HttpOnly, SameSite=Lax cookie (Secure over HTTPS, valid for a year). Scans, history and search are scoped to it. API clients that want to see their history should keep cookies between requests, for example with `curl -c jar -b jar`.

**Own model key (optional).** To explain a scan with your own provider account instead of the free tier, send all three headers:

| Header | Value |
|--------|-------|
| `X-LLM-Provider` | `openai`, `anthropic`, `google`, `xai`, `groq` or `mistral` |
| `X-LLM-Model` | A model ID from `POST /api/llm/models` |
| `X-LLM-Key` | Your API key |

The key is used for that request only and is never stored or logged. An invalid provider, model name or key format returns `400`.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/health` | Database and S3 status |
| `GET` | `/api/usage` | Free explained scans left and the free tier's state |
| `GET` | `/api/llm/providers` | Providers usable with an own key |
| `POST` | `/api/llm/models` | Check a key and list the chat models it can use |
| `POST` | `/api/audit` | Scan one file; returns the full result |
| `POST` | `/api/audit/stream` | Scan one file; streams progress as server-sent events |
| `POST` | `/api/audit/archive` | Scan a zip upload; streams events |
| `POST` | `/api/audit/repo` | Scan a public GitHub repository or folder; streams events |
| `POST` | `/api/audit/diagram` | Compare an architecture diagram with Terraform, plus a normal scan |
| `POST` | `/api/search` | Semantic search over your earlier findings |
| `GET` | `/api/history` | Your scans, newest first |
| `GET` | `/api/history/{audit_id}` | One scan in full |
| `DELETE` | `/api/history` | Delete your scans and findings |

### `GET /api/health`

```json
{ "status": "healthy", "database": "connected", "s3": "connected", "environment": "production" }
```

`status` is `degraded` when either dependency is unreachable. The response is always `200`, so it can double as a load balancer health check.

### `GET /api/usage`

```json
{
  "explanations_available": true,
  "free_scans_per_day": 5,
  "free_scans_left": 3,
  "free_tier_state": "ok",
  "retry_after": 0,
  "resets_at": "2026-09-18T00:00:00+00:00"
}
```

| Field | Meaning |
|-------|---------|
| `explanations_available` | Whether the server offers a free tier at all |
| `free_scans_left` | This client's remaining free explained scans today |
| `free_tier_state` | `ok`, `busy` (provider per-minute limit) or `exhausted` (provider daily limit, shared by all users) |
| `retry_after` | Seconds until a `busy` or `exhausted` free tier is expected to work again |
| `resets_at` | When this client's daily count resets (midnight UTC) |

### `POST /api/llm/models`

Header `X-LLM-Key`, body:

```json
{ "provider": "anthropic" }
```

Response:

```json
{
  "models": [
    { "id": "claude-opus-5", "vision": true },
    { "id": "claude-sonnet-5", "vision": true }
  ],
  "default": "claude-opus-5"
}
```

`vision` is `null` when the provider doesn't say whether a model accepts images. This endpoint shares the search rate limit. A rejected key returns `400` with a message such as `"Anthropic rejected the API key."`; a provider outage returns `502`.

### `POST /api/audit`

```json
{ "iac_content": "resource \"aws_s3_bucket\" \"logs\" {\n  acl = \"public-read\"\n}\n", "file_name": "main.tf" }
```

`iac_content` is 10 to 120,000 characters; `file_name` up to 255. The response is a [scan result](#scan-result).

```bash
curl -s -c jar -b jar https://cloud-guard-ai.duckdns.org/api/audit \
  -H 'Content-Type: application/json' \
  -d '{"iac_content": "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n", "file_name": "main.tf"}'
```

### `POST /api/audit/stream`

Same body as `/api/audit`. The response is `text/event-stream`; each event is a `data:` line with a JSON object:

```
data: {"step": "static_checks", "status": "running", "message": "Running Checkov..."}

data: {"step": "static_checks", "status": "complete", "message": "29 findings"}

data: {"step": "review", "status": "running", "message": "Explaining findings..."}

data: {"step": "review", "status": "complete", "message": "2 more issues spotted in review"}

data: {"step": "done", "status": "complete", "data": { ...scan result... }}
```

| `step` | When |
|--------|------|
| `fetch` | Downloading a repository (repository scans only) |
| `static_checks` | Running Checkov |
| `review` | Explaining findings |
| `rag_retrieval` | Looking up earlier fixes |
| `patch_generation` | Writing patches |
| `diagram` | Comparing a diagram |
| `storage` | Saving to history |
| `done` | Final event; `data` holds the scan result |
| `error` | The scan couldn't complete; `message` says why |

`status` is `running`, `complete` or `error`. Steps that don't apply are simply not sent. A step with `status: error` (for example `review`) doesn't end the scan; only the `error` step does.

```bash
curl -N -s https://cloud-guard-ai.duckdns.org/api/audit/stream \
  -H 'Content-Type: application/json' \
  -d @payload.json
```

### `POST /api/audit/archive`

`multipart/form-data` with the zip in the `archive` field. Streams the same events.

Limits: 10 MB compressed, 20 MB of configuration files after extraction, 1 MB per file (larger files are skipped), 400 configuration files and 20,000 archive entries. Only these file types are kept: `.tf`, `.tf.json`, `.tfvars`, `.hcl`, `.yaml`, `.yml`, `.json`, `.template`, `.bicep`, `.dockerfile` and files named `Dockerfile*`. The directories `.git`, `.terraform`, `node_modules`, `vendor`, `.venv` and `venv` are ignored, as are package manifests and lock files such as `package.json` and `.terraform.lock.hcl`.

```bash
curl -N -s https://cloud-guard-ai.duckdns.org/api/audit/archive -F archive=@infra.zip
```

An archive that isn't a valid zip, is encrypted, or has no configuration files returns `400` before streaming starts.

### `POST /api/audit/repo`

```json
{ "url": "https://github.com/bridgecrewio/terragoat/tree/master/terraform/aws" }
```

Accepts `https://github.com/<owner>/<repo>` and `https://github.com/<owner>/<repo>/tree/<ref>/<folder>`. Only public repositories work; branch names containing `/` aren't supported in folder links. The download is capped at 25 MB compressed and then goes through the same limits as zip uploads. A malformed URL returns `400`; a missing or private repository is reported as an `error` event after the `fetch` step.

### `POST /api/audit/diagram`

`multipart/form-data` fields:

| Field | Value |
|-------|-------|
| `iac_content` | Terraform, up to 120,000 characters |
| `file_name` | Optional, default `main.tf` |
| `diagram` | PNG, JPEG or WebP, up to 8 MB |

Requires the own-key headers with a model that accepts images; without them the response is `400`. Returns a scan result with `diagram_analysis` set to a Markdown report.

### `POST /api/search`

```json
{ "query": "database reachable from the internet", "limit": 5 }
```

`query` is 3 to 1,000 characters; `limit` 1 to 20. Only your own findings are searched.

```json
{
  "query": "database reachable from the internet",
  "total": 1,
  "results": [
    {
      "audit_id": "22ce74b37c24",
      "file_name": "main.tf",
      "vulnerability_type": "Ensure all data stored in RDS is not publicly accessible",
      "severity": "CRITICAL",
      "description": "The RDS instance is marked publicly_accessible ...",
      "patched_code": "...",
      "similarity_score": 0.8123
    }
  ]
}
```

### `GET /api/history`

```json
[
  {
    "audit_id": "3e62c9e3864a",
    "file_name": "bridgecrewio/terragoat@master/terraform/aws",
    "security_score": 0,
    "finding_count": 221,
    "severity_counts": { "CRITICAL": 10, "HIGH": 49, "MEDIUM": 108, "LOW": 54 },
    "has_diagram": false,
    "file_count": 15,
    "source": "github",
    "created_at": "2026-09-16T21:23:06"
  }
]
```

Returns up to 50 scans. `GET /api/history/{audit_id}` returns the full [scan result](#scan-result) plus `original_code` for pasted files; scans from another workspace return `404`. `DELETE /api/history` returns `204`.

## Scan result

```json
{
  "audit_id": "22ce74b37c24",
  "file_name": "main.tf",
  "security_score": 5,
  "vulnerabilities": [
    {
      "source": "checkov",
      "check_id": "CKV_AWS_20",
      "severity": "CRITICAL",
      "title": "S3 Bucket has an ACL defined which allows public READ access",
      "description": "The bucket's acl grants public read, so anyone can list and download objects.",
      "remediation": "Set acl = \"private\" and grant access through a bucket policy.",
      "resource": "aws_s3_bucket.data_lake",
      "file": "main.tf",
      "line_start": 1,
      "line_end": 4
    }
  ],
  "files": ["main.tf"],
  "sources": { "main.tf": "resource \"aws_s3_bucket\" \"data_lake\" { ... }" },
  "patches": [{ "file": "main.tf", "original": "...", "patched": "..." }],
  "patched_code": "...",
  "similar_past_audits": [],
  "diagram_analysis": null,
  "analysis": {
    "mode": "free",
    "source": "paste",
    "checkov_version": "3.3.17",
    "covered_files": ["main.tf"],
    "frameworks": ["terraform"],
    "model": { "provider": "Groq", "model": "openai/gpt-oss-120b" },
    "notices": [],
    "limit": null,
    "free_scans_left": 3
  },
  "created_at": "2026-09-17T09:12:44Z"
}
```

| Field | Notes |
|-------|-------|
| `security_score` | 0 to 100 from Checkov findings in covered files; `null` when no file type is covered (for example a Compose file alone) |
| `vulnerabilities[].source` | `checkov` findings are scored; `review` findings come from the model, aren't scored, and have no `check_id` |
| `vulnerabilities[].description`, `remediation` | Empty in Checkov-only scans |
| `sources` | Contents of files with findings, so a client can show findings on their lines (capped at 1.5 MB in total, 300 KB per file) |
| `patches` | One entry per rewritten file |
| `patched_code` | The patch for single-file scans, for older clients |
| `analysis.mode` | `static` (Checkov only), `free` or `own_key` |
| `analysis.notices` | Plain-language notes about anything that didn't go as planned |
| `analysis.limit` | Set when a limit shaped the result; see below |

### The `limit` object

When explanations are missing because of a limit, `analysis.limit` says which one and what to do, and its `message` is ready to show to a user.

```json
{
  "kind": "busy",
  "retry_after": 42,
  "resets_at": null,
  "message": "Our free explanation model is busy right now. The results below are the free Checkov scan and they're complete. Try again in about 42 seconds, or add your own API key to get explanations without waiting. This didn't use one of your free scans."
}
```

| `kind` | Meaning | Suggested action |
|--------|---------|------------------|
| `busy` | The free model hit its per-minute allowance | Retry after `retry_after` seconds, or use an own key |
| `patch_busy` | Findings were explained, but the patch hit the per-minute allowance | Retry, or use an own key |
| `site_daily` | The free model's daily allowance is used up for everyone | Retry after `retry_after`; Checkov scans still work; or use an own key |
| `visitor_daily` | This client used its free explained scans today | Wait for `resets_at`, or use an own key |
| `too_large` | The files are too large for the free model | Scan less code, or use an own key |
| `unavailable` | The server has no free tier configured | Use an own key |

## Errors

Errors return `{"detail": "..."}` with a message that's safe to show.

| Status | When |
|--------|------|
| `400` | Unsupported upload or URL, invalid own-key headers, diagram without an own key |
| `404` | Scan not found in this workspace |
| `413` | Diagram, or the Terraform sent with it, over the size limit (oversized pasted text on the JSON endpoints is a `422`) |
| `422` | Request body failed validation (`detail` is a list of field errors) |
| `429` | Rate limit reached; the `Retry-After` header gives seconds |
| `500` | Unexpected server error |
| `502` | Checkov couldn't run, or a provider failed while listing models |
| `503` | All scan slots stayed busy for 30 seconds (`/api/audit` and `/api/audit/diagram`; streams send an `error` event); `Retry-After: 30` |

Streaming endpoints report errors that happen after the response has started as an `error` event instead of a status code.

Default rate limits are 8 scans per 10 minutes and 30 searches (and model-list requests) per minute per client IP; see [Configuration](configuration.md).
