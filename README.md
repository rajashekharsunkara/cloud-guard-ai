# CloudGuard AI

Scans Terraform and Docker Compose configs for security issues using a multi-agent LLM pipeline — Groq for auditing and patch generation, Gemini for embeddings and vision, pgvector for RAG over past findings.

## Setup

You'll need Docker, a [Groq API key](https://console.groq.com/) and a [Gemini API key](https://aistudio.google.com/).

```bash
cp .env.example .env
# fill in GROQ_API_KEY and GEMINI_API_KEY
docker-compose up --build
```

Dashboard is at `http://localhost:8000`. Swagger at `/docs`.

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | DB + S3 status |
| `POST` | `/api/audit` | Full audit, JSON response |
| `POST` | `/api/audit/stream` | Same but SSE |
| `POST` | `/api/audit/diagram` | Audit + architecture diagram drift check |
| `POST` | `/api/search` | Semantic search over past findings |
| `GET` | `/api/history` | Recent audit history |

## Tests

```bash
pytest backend/tests/ -v
```

## License

MIT
