FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Checkov gets its own virtualenv: it has a large dependency tree that would
# otherwise have to agree with the app's pins.
COPY requirements-checkov.txt .
RUN python -m venv /opt/checkov \
    && /opt/checkov/bin/pip install --no-cache-dir -r requirements-checkov.txt

# Checkov renders Helm charts with the helm binary. Pinned and checked against
# the published SHA-256 for each architecture.
ARG HELM_VERSION=v3.22.0
ARG HELM_SHA256_AMD64=1e4ab49e429626cf6c6958d914248b78c9730803c2751b87627e171dc800e7bb
ARG HELM_SHA256_ARM64=f14e804dfee240f55525b667488fe9adca349e63e00c9af634c0beb1421ac310
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
         amd64) sha="$HELM_SHA256_AMD64" ;; \
         arm64) sha="$HELM_SHA256_ARM64" ;; \
         *) echo "no helm checksum for $arch" >&2; exit 1 ;; \
       esac \
    && python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/tmp/helm.tgz')" \
         "https://get.helm.sh/helm-${HELM_VERSION}-linux-${arch}.tar.gz" \
    && echo "$sha  /tmp/helm.tgz" | sha256sum -c - \
    && tar -xzf /tmp/helm.tgz -C /tmp "linux-${arch}/helm" \
    && install -m 0755 "/tmp/linux-${arch}/helm" /usr/local/bin/helm \
    && rm -rf /tmp/helm.tgz "/tmp/linux-${arch}"

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --from=builder /opt/checkov /opt/checkov
COPY --from=builder /usr/local/bin/helm /usr/local/bin/helm
ENV CHECKOV_BIN=/opt/checkov/bin/checkov
COPY backend/ ./backend/
COPY frontend/ ./frontend/

RUN useradd --create-home --shell /usr/sbin/nologin cloudguard

# Bake the embedding model into the image so containers never download it.
ENV EMBEDDING_CACHE_DIR=/opt/models
RUN mkdir -p /opt/models && chown cloudguard /opt/models
USER cloudguard
RUN python -c "from fastembed import TextEmbedding; TextEmbedding('BAAI/bge-small-en-v1.5', cache_dir='/opt/models')"
ENV HF_HUB_OFFLINE=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
