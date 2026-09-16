"""Local text embeddings for search and earlier-fix lookup.

A small open model runs on the server, so embeddings need no API key, have no
per-minute quota, and findings never leave the machine for this step.
"""

import asyncio
import threading

from backend.app.core.config import settings

MODEL_NAME = "BAAI/bge-small-en-v1.5"
EMBEDDING_DIM = 384

_model = None
_lock = threading.Lock()


def _get_model():
    global _model
    with _lock:
        if _model is None:
            # Imported lazily: loading onnxruntime and the model takes a few
            # seconds and ~150 MB, which the app shouldn't pay until needed.
            from fastembed import TextEmbedding

            _model = TextEmbedding(
                MODEL_NAME,
                cache_dir=settings.embedding_cache_dir or None,
                threads=settings.embedding_threads,
            )
    return _model


def _embed(texts: list[str]) -> list[list[float]]:
    return [vector.tolist() for vector in _get_model().embed(texts)]


def _embed_query(text: str) -> list[float]:
    return next(iter(_get_model().query_embed([text]))).tolist()


async def embed_documents(texts: list[str]) -> list[list[float]]:
    if not texts:
        return []
    return await asyncio.to_thread(_embed, texts)


async def embed_query(text: str) -> list[float]:
    return await asyncio.to_thread(_embed_query, text)
