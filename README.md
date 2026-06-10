# CloudGuard AI

> AI-powered Infrastructure as Code security auditing with multi-agent LLM orchestration, RAG-based historical patching, and multimodal architecture diagram validation.

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+pgvector-336791?logo=postgresql)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![Terraform](https://img.shields.io/badge/Terraform-IaC-7B42BC?logo=terraform)
![LangChain](https://img.shields.io/badge/LangChain-Agents-orange)

---

## Overview

CloudGuard AI addresses a critical gap in cloud security: infrastructure misconfigurations are the leading cause of data breaches. Traditional static analysis tools (like `checkov` or `tfsec`) flag rule violations but fall short in several ways:

- They don't explain architectural context
- They don't learn from your organization's past fixes
- They can't verify if your code matches your architecture diagrams
- They don't generate drop-in secure code replacements

CloudGuard AI tackles all of these using a multi-agent LLM pipeline:

```
Upload Terraform/Docker Compose
    ↓
SecOps Auditor Agent (Groq/Llama 3) → Finds vulnerabilities
    ↓
RAG Retrieval (pgvector) → Fetches similar past fixes from PostgreSQL
    ↓
Patch Developer Agent (Groq/Llama 3) → Generates secure, drop-in code
    ↓
Vision Auditor Agent (Gemini Multimodal) → Validates architecture diagram vs code
    ↓
Dashboard → Real-time SSE streaming, code diff, security score
```

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Backend** | FastAPI (async) | REST API + SSE streaming |
| **Database** | PostgreSQL 16 + pgvector | Audit storage + vector similarity search |
| **Cloud Mock** | LocalStack | Simulates AWS S3 locally (free) |
| **IaC** | Terraform | Provisions S3 resources (works with LocalStack) |
| **LLM (Text)** | Groq API (Llama 3.3 70B) | Security scanning + code patching |
| **LLM (Vision)** | Gemini API (2.5 Flash) | Multimodal diagram analysis |
| **Embeddings** | Gemini text-embedding-004 | 768-dim vectors for pgvector RAG |
| **Frontend** | HTML + CSS + Vanilla JS | Responsive dashboard |
| **CI/CD** | GitHub Actions | Linting, testing, Docker builds |
| **Containers** | Docker Compose | Full orchestration (3 services) |

---

## Quick Start

### Prerequisites

- **Docker & Docker Compose** installed
- **API Keys** (both have free tiers):
  - [Groq API Key](https://console.groq.com/) — free, fast inference
  - [Gemini API Key](https://aistudio.google.com/) — free, generous rate limits

### 1. Clone & Configure

```bash
git clone https://github.com/rajashekharsunkara/cloudguard-ai.git
cd cloudguard-ai

# Copy the env template and add your API keys
cp .env.example .env
# Edit .env and fill in GROQ_API_KEY and GEMINI_API_KEY
```

### 2. Launch Everything

```bash
docker-compose up --build
```

This starts 3 services:
- **PostgreSQL + pgvector** on port `5432`
- **LocalStack (S3)** on port `4566`
- **FastAPI Backend** on port `8000`

### 3. Open the Dashboard

Visit **http://localhost:8000** in your browser.

### 4. Run Your First Scan

1. Navigate to the **IaC Scanner** tab
2. Click **"Load Sample"** to load an intentionally insecure Terraform config
3. Click **"Run Security Audit"** or **"Scan with Live SSE Stream"**
4. Watch the multi-agent pipeline find vulnerabilities and generate patches

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Web Browser                       │
│          (Interactive Dashboard + SSE)               │
└──────────────────────┬──────────────────────────────┘
                       │ REST API / SSE
┌──────────────────────▼──────────────────────────────┐
│                  FastAPI Backend                      │
│  ┌─────────────┐  ┌──────────┐  ┌────────────────┐  │
│  │  Auditor    │  │ Storage  │  │  DB Service    │  │
│  │  Router     │  │ Service  │  │  (pgvector)    │  │
│  └──────┬──────┘  └────┬─────┘  └───────┬────────┘  │
│         │              │                │            │
│  ┌──────▼──────────────▼────────────────▼─────────┐  │
│  │           Agent Orchestrator (LangChain)        │  │
│  │  ┌──────────┐ ┌──────────┐ ┌────────────────┐  │  │
│  │  │ SecOps   │ │ Patch    │ │ Vision Auditor │  │  │
│  │  │ Auditor  │ │ Developer│ │ (Gemini Multi) │  │  │
│  │  │ (Groq)   │ │ (Groq)  │ │                │  │  │
│  │  └──────────┘ └──────────┘ └────────────────┘  │  │
│  └────────────────────────────────────────────────┘  │
└──────────┬──────────────────────────┬────────────────┘
           │                          │
┌──────────▼──────────┐  ┌───────────▼──────────────┐
│  PostgreSQL 16      │  │  LocalStack (AWS S3)     │
│  + pgvector         │  │  Port 4566               │
│  Port 5432          │  │                          │
└─────────────────────┘  └──────────────────────────┘
```

---

## How the RAG Loop Works

The Retrieval-Augmented Generation pattern is the core differentiator:

1. **Scan** — The SecOps Auditor finds vulnerabilities in your IaC code
2. **Embed** — Each vulnerability description is converted to a 768-dimensional vector using Gemini's `text-embedding-004`
3. **Store** — Vectors are saved in PostgreSQL using the `pgvector` extension
4. **Search** — For new scans, the vulnerability embedding is compared via `cosine distance` to find similar past findings:
   ```sql
   SELECT description, patched_code,
          (embedding <=> :query_embedding) AS distance
   FROM vulnerabilities
   ORDER BY distance
   LIMIT 3;
   ```
5. **Augment** — The top matching historical patches are injected into the Patch Developer's context prompt
6. **Generate** — The LLM produces a higher-quality fix because it has real organizational context

---

## Project Structure

```
cloudguard-ai/
├── docker-compose.yml          # 3 services: FastAPI, Postgres, LocalStack
├── Dockerfile                  # Multi-stage Python build
├── requirements.txt            # All Python dependencies
├── .env.example                # Environment template
├── .gitignore / .dockerignore
├── README.md
│
├── terraform/                  # Infrastructure as Code
│   ├── main.tf                 # S3 bucket with encryption + versioning
│   ├── localstack.tf           # LocalStack provider overrides
│   ├── variables.tf
│   └── outputs.tf
│
├── .github/workflows/
│   └── devsecops-ci.yml        # CI pipeline (lint, test, build)
│
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI entrypoint + lifespan
│   │   ├── core/
│   │   │   ├── config.py       # Pydantic settings validation
│   │   │   ├── database.py     # SQLAlchemy + pgvector setup
│   │   │   └── aws.py          # boto3 S3 client factory
│   │   ├── prompts/            # LLM prompt templates (separated)
│   │   │   ├── security_rules.txt
│   │   │   ├── patch_generator.txt
│   │   │   └── vision_audit.txt
│   │   ├── routers/
│   │   │   └── auditor.py      # API endpoints
│   │   ├── services/
│   │   │   ├── agents.py       # Multi-agent LLM orchestration
│   │   │   ├── db_service.py   # pgvector CRUD + similarity search
│   │   │   └── storage.py      # S3 file management
│   │   └── schemas/
│   │       └── auditor.py      # Pydantic request/response models
│   └── tests/
│       └── test_schemas.py     # Schema validation tests
│
└── frontend/
    ├── index.html              # Dashboard (5 tabbed views)
    ├── css/styles.css           # Glassmorphism dark theme
    └── js/app.js               # SSE streaming + API integration
```

---

## Running Tests

```bash
# With Docker running:
docker-compose exec backend pytest backend/tests/ -v

# Or locally with a virtual environment:
pip install -r requirements.txt
pytest backend/tests/ -v
```

---

## Terraform (LocalStack)

Provision the S3 bucket using Terraform against LocalStack:

```bash
cd terraform
terraform init
terraform plan
terraform apply -auto-approve
```

This creates the `cloudguard-artifacts` S3 bucket in LocalStack with:
- Versioning enabled
- AES-256 server-side encryption
- Public access blocked

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | System health check (DB + S3 status) |
| `POST` | `/api/audit` | Run full security audit (JSON response) |
| `POST` | `/api/audit/stream` | Run audit with real-time SSE streaming |
| `POST` | `/api/audit/diagram` | Audit with architecture diagram (multimodal) |
| `POST` | `/api/search` | Semantic search over past audits (pgvector) |
| `GET` | `/api/history` | Retrieve audit history |
| `GET` | `/docs` | Interactive Swagger API documentation |

---

## License

MIT License
