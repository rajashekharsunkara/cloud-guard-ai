# Security

CloudGuard accepts code from anyone on the internet, downloads repositories on request, runs a scanner over what it receives, and handles third-party API keys. This guide covers what could go wrong with each and what the code does about it.

To report a vulnerability, use GitHub's private vulnerability reporting on the repository (Security → Report a vulnerability) rather than a public issue.

## Threat model

| Asset | Threat |
|-------|--------|
| The host and its credentials (IAM role, database password, Groq key) | Code execution or file access through uploads, the scanner or repository downloads; requests to internal addresses |
| Visitors' scans and findings | One visitor reading another's history or search results, or their code leaking into another visitor's prompts |
| Visitors' model API keys | Being stored, logged or sent anywhere other than the provider |
| The free tier and the service's availability | Scripted scanning, oversized uploads, archive bombs, concurrent bursts |
| Anyone viewing a report | Script injection through filenames, source code or model output |

Out of scope: the correctness of Checkov's policies, and what model providers do with code sent to them under their own terms. The interface says which provider receives code on each explained scan.

## Uploads and repositories

Code in `backend/app/services/sources.py`.

- **Nothing is extracted to disk.** Zips and tarballs are read member by member in memory. Only configuration file types are kept, and only their contents are passed on.
- **Size limits at every layer.** 10 MB per zip upload, 25 MB per repository download (counted while streaming, so a large response is cut off rather than buffered), 1 MB per file, 20 MB in total, 400 files and 20,000 archive entries. Members are read with a byte limit rather than trusting the size in the archive header, which stops compression bombs that lie about their size.
- **Only regular files are read.** Symlinks in zips, and links and device entries in tarballs, are skipped. Encrypted zips are rejected and files that aren't valid UTF-8 are ignored.
- **Paths are normalised.** `..`, absolute paths and empty segments are removed before a file is written for Checkov, so an archive entry can't land outside the scan directory (`safe_relative_path` in `checkov.py`).
- **Repository downloads can't be redirected.** Only `https://github.com/owner/repo[/tree/ref/folder]` is accepted. Owner, repository and ref are validated against strict patterns, and the request always goes to `https://codeload.github.com/...` built from those parts with redirects disabled. A user can't make the server fetch another host or an internal address.
- **Diagrams** must be PNG, JPEG or WebP, are capped at 8 MB and are only sent to the visitor's chosen provider.

## The scanner

Code in `backend/app/services/checkov.py`.

- Checkov runs as a subprocess with an argument list, never through a shell, so file names can't become commands.
- Its environment is replaced entirely: only `PATH`, `LANG` and a `HOME` inside the temporary scan directory are passed. The database URL, AWS credentials and API keys in the app's environment aren't visible to it or anything it loads.
- It runs with `--skip-download` (no fetching of external modules or policies), in a fresh temporary directory that's removed afterwards, under a timeout (90 seconds by default) after which the process is killed.
- Checkov is installed from a fully pinned requirements file into its own virtual environment. The container runs as an unprivileged user.
- Checkov parses Terraform and templates but doesn't execute them. Terraform providers, `external` data sources and provisioners are never run.
- For secrets that Checkov detects, the hash it uses as a resource name is dropped, so the report points at the line without carrying anything derived from the secret.

## Model API keys

- **The server doesn't keep them.** Keys arrive in the `X-LLM-Key` header of each request, are used to create a client for that request and are then discarded. They're never written to the database, S3 or logs.
- **Logging avoids them.** Some provider error messages quote part of the key, so provider failures are logged by classification and status code only (for example `review failed for audit ...: rate_limit (429)`).
- **Format checks first.** A key must be 8 to 400 printable ASCII characters and a model name must match a conservative pattern before either is used.
- **Fixed destinations.** Each provider's base URL is a constant in `llm.py`. There's no way for a request to choose the host a key is sent to.
- **In the browser**, the key is kept in `localStorage` when "Remember on this device" is ticked (the default) and in `sessionStorage`, cleared when the tab closes, when it isn't. It's sent only to CloudGuard's own API.
- **In the CLI and Action**, the key is only read from the `CLOUDGUARD_LLM_KEY` environment variable, never from a command-line flag.

Visitors who don't want to share a key with a hosted service can run CloudGuard locally or use the CLI.

## Isolation between visitors

- There are no accounts. Each browser gets a random 128-bit workspace ID in an `HttpOnly`, `SameSite=Lax` cookie, marked `Secure` behind HTTPS. Cookies that don't match the expected format are replaced.
- Every query for history, a single scan, search and deletion filters by workspace. Fetching another workspace's scan ID returns `404`, not `403`, so IDs can't be probed.
- Earlier fixes used as examples in patch prompts come only from the same workspace, so one visitor's code never appears in another visitor's model request.
- Search embeddings are computed on the server, so findings aren't sent to an embedding provider.

A workspace is only as private as the cookie: anyone with access to the browser profile can see its history. The history page has a button to delete everything in the workspace.

## Rendering untrusted content

Filenames, source code, Checkov messages and model output are all untrusted. The frontend escapes every value before inserting it into the page. Model-written reports are rendered by a small Markdown subset (headings, lists, bold, inline code) that escapes first and adds only those tags, with no links, images or raw HTML. The frontend has no third-party scripts and serves its fonts itself.

## Availability and abuse

- Per-IP sliding-window limits on scans (8 per 10 minutes) and search (30 per minute), with `Retry-After` on refusal.
- At most two scans run at once per process, which bounds memory on small instances. Others wait up to 30 seconds, then get a clear busy response.
- Free explained scans are limited per client per day in PostgreSQL with a single atomic statement, so parallel requests can't exceed the quota. Client addresses in that table are stored as salted SHA-256 hashes, not in plain text.
- When the free provider reports a rate or daily limit, later scans skip it until the reset time instead of amplifying the failure.
- Behind a proxy, Uvicorn only trusts `X-Forwarded-For` from the addresses in `FORWARDED_ALLOW_IPS`, and the production Compose file binds the app to loopback so it can only be reached through the proxy. Clients can't spoof their address to escape limits.

## Infrastructure

- **No long-lived AWS keys on the host.** The EC2 instance uses an instance profile limited to the one bucket (see [Deployment](deployment.md#iam)).
- **Database** is only reachable on the Docker network; its port isn't published in production.
- **TLS** is terminated by Caddy with automatically renewed certificates.
- **Backups** are custom-format `pg_dump` files in S3, written to a temporary file first so a failed dump never overwrites a good object.
- **Error responses** in production contain a generic message. Details go to the container log.
- **CI** runs this project's own GitHub Action on changes to infrastructure files, so the deployment configuration is scanned too.

## Data retention

| Data | Where | Kept |
|------|-------|------|
| Scanned files with findings, patches, findings, embeddings | PostgreSQL | Until the visitor deletes their history |
| Original and patched files | S3 `scans/`, `patches/` | Until removed; add a lifecycle rule to expire them |
| Hashed client address and daily count | PostgreSQL `llm_usage` | One row per client per day |
| Database dumps | S3 `backups/` | Until removed; a lifecycle rule is recommended |
| Model API keys | Nowhere on the server | Only for the duration of a request |
