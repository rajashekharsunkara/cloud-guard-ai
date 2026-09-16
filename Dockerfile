FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Checkov gets its own virtualenv: it has a large dependency tree that would
# otherwise have to agree with the app's pins.
COPY requirements-checkov.txt .
RUN python -m venv /opt/checkov \
    && /opt/checkov/bin/pip install --no-cache-dir -r requirements-checkov.txt

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --from=builder /opt/checkov /opt/checkov
ENV CHECKOV_BIN=/opt/checkov/bin/checkov
COPY backend/ ./backend/
COPY frontend/ ./frontend/

RUN useradd --create-home --shell /usr/sbin/nologin cloudguard
USER cloudguard

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
