"""One interface over the model providers CloudGuard can use.

Visitors can bring their own key for any provider below; the server's free
tier uses Groq. Keys arrive per request, are passed straight to the provider
SDK and are never stored or logged. Base URLs are fixed here and never taken
from the client, so a request can't point the server at another host.
"""

import asyncio
import base64
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import anthropic
import openai
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from backend.app.core.config import settings

logger = logging.getLogger("cloudguard.llm")


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    kind: str  # "openai" (chat completions API), "anthropic" or "google"
    base_url: Optional[str] = None
    # Tried in order when picking a default; the first one the key can use
    # wins. Providers rename models often, so the live model list decides.
    preferred: tuple = ()
    key_url: str = ""


PROVIDERS = {
    p.id: p
    for p in (
        Provider(
            "openai",
            "OpenAI",
            "openai",
            preferred=(
                "gpt-5.6-terra",
                "gpt-5.6-sol",
                "gpt-6-astra",
                "gpt-5.1",
                "gpt-5",
            ),
            key_url="https://platform.openai.com/api-keys",
        ),
        Provider(
            "anthropic",
            "Anthropic",
            "anthropic",
            preferred=("claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"),
            key_url="https://console.anthropic.com/settings/keys",
        ),
        Provider(
            "google",
            "Google Gemini",
            "google",
            # The "latest" alias tracks Google's current stable Flash model;
            # brand-new previews are often overloaded.
            preferred=("gemini-flash-latest", "gemini-2.5-flash", "gemini-pro-latest"),
            key_url="https://aistudio.google.com/apikey",
        ),
        Provider(
            "xai",
            "xAI",
            "openai",
            base_url="https://api.x.ai/v1",
            preferred=("grok-4.6", "grok-4.5"),
            key_url="https://console.x.ai",
        ),
        Provider(
            "groq",
            "Groq",
            "openai",
            base_url="https://api.groq.com/openai/v1",
            preferred=("openai/gpt-oss-120b", "qwen/qwen3.8-27b"),
            key_url="https://console.groq.com/keys",
        ),
        Provider(
            "mistral",
            "Mistral",
            "openai",
            base_url="https://api.mistral.ai/v1",
            preferred=(
                "mistral-medium-latest",
                "mistral-large-latest",
                "mistral-small-latest",
            ),
            key_url="https://console.mistral.ai/api-keys",
        ),
    )
}

FREE_TIER_PROVIDER = "groq"
FREE_TIER_MODEL = "openai/gpt-oss-120b"

_MODEL_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,120}$")
_KEY_RE = re.compile(r"^[\x21-\x7e]{8,400}$")

# Model list entries that aren't chat models.
_NON_CHAT = re.compile(
    r"embed|tts|whisper|transcri|realtime|audio|image|dall-e|moderation|"
    r"guard|ocr|voxtral|sora|live|speech|search|rerank|safeguard|orpheus|"
    r"lyria|banana|robotics|veo|imagen|computer-use|aqa|allam",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LlmChoice:
    provider: str
    model: str
    api_key: str = field(repr=False)
    own_key: bool = True

    @property
    def label(self) -> str:
        return PROVIDERS[self.provider].label


def free_tier_choice() -> Optional[LlmChoice]:
    if not settings.groq_api_key:
        return None
    return LlmChoice(
        FREE_TIER_PROVIDER, FREE_TIER_MODEL, settings.groq_api_key, own_key=False
    )


class LlmError(Exception):
    """A provider call failed. ``message`` is safe to show and never has the key."""

    def __init__(self, kind: str, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.status = status


def validate_choice(provider: str, model: str, api_key: str) -> LlmChoice:
    if provider not in PROVIDERS:
        raise LlmError("bad_request", "Unknown model provider.")
    if not _MODEL_RE.match(model or ""):
        raise LlmError("bad_request", "That model name isn't valid.")
    if not _KEY_RE.match(api_key or ""):
        raise LlmError("bad_request", "That API key doesn't look valid.")
    return LlmChoice(provider, model, api_key, own_key=True)


def _error_from_status(
    status: Optional[int], provider: str, text: str = ""
) -> LlmError:
    label = PROVIDERS[provider].label
    lowered = text.lower()
    # Google and xAI answer a bad key with 400 rather than 401.
    bad_key = status == 400 and re.search(r"api[ _-]?key", lowered)
    if status in (401, 403) or bad_key:
        return LlmError("auth", f"{label} rejected the API key.", status)
    if status == 404:
        return LlmError(
            "not_found", f"{label} doesn't offer that model to this key.", status
        )
    if status == 429 or (status == 413 and "rate" in lowered):
        return LlmError("rate_limit", f"{label} rate limit or quota reached.", status)
    if status == 413:
        return LlmError(
            "too_large", f"The request was too large for this {label} model.", status
        )
    if status is not None and 400 <= status < 500:
        return LlmError(
            "bad_request", f"{label} couldn't handle the request ({status}).", status
        )
    return LlmError("unavailable", f"{label} is unavailable right now.", status)


def classify(error: Exception, provider: str) -> LlmError:
    if isinstance(error, LlmError):
        return error
    if isinstance(error, (openai.APIStatusError, anthropic.APIStatusError)):
        return _error_from_status(error.status_code, provider, str(error))
    if isinstance(error, genai_errors.APIError):
        return _error_from_status(error.code, provider, str(error))
    if isinstance(error, (openai.APIConnectionError, anthropic.APIConnectionError)):
        return LlmError("unavailable", f"Couldn't reach {PROVIDERS[provider].label}.")
    return LlmError(
        "unavailable", f"{PROVIDERS[provider].label} returned an unexpected error."
    )


def _openai_client(choice: LlmChoice) -> openai.AsyncOpenAI:
    return openai.AsyncOpenAI(
        api_key=choice.api_key,
        base_url=PROVIDERS[choice.provider].base_url,
        max_retries=2 if choice.own_key else 3,
        timeout=180,
    )


def _openai_params(choice: LlmChoice, max_tokens: int) -> dict:
    if choice.provider == "openai":
        # Current OpenAI models are reasoning models: no temperature, and the
        # token limit is named differently.
        return {"max_completion_tokens": max_tokens}
    params = {"max_tokens": max_tokens, "temperature": 0.1}
    if choice.model.startswith("openai/gpt-oss"):
        params["reasoning_effort"] = "medium"
    return params


async def _openai_complete(choice, system, content, json_schema, max_tokens) -> str:
    client = _openai_client(choice)
    params = _openai_params(choice, max_tokens)
    if json_schema is not None:
        params["response_format"] = {"type": "json_object"}
    response = await client.chat.completions.create(
        model=choice.model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": content},
        ],
        **params,
    )
    return response.choices[0].message.content or ""


def _anthropic_text(response) -> str:
    if response.stop_reason == "refusal":
        raise LlmError("refused", "Anthropic declined this request.")
    return "".join(block.text for block in response.content if block.type == "text")


async def _anthropic_complete(choice, system, content, json_schema, max_tokens) -> str:
    client = anthropic.AsyncAnthropic(
        api_key=choice.api_key, max_retries=2, timeout=300
    )
    params = {
        "model": choice.model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": content}],
    }
    if json_schema is not None:
        params["output_config"] = {
            "format": {"type": "json_schema", "schema": json_schema}
        }
    if choice.model in ("claude-opus-5", "claude-fable-5-1"):
        # These models can decline security-heavy prompts; let the API retry
        # the same request on Opus 4.8 instead of returning nothing.
        response = await client.beta.messages.create(
            betas=["server-side-fallback-2026-06-01"],
            fallbacks=[{"model": "claude-opus-4-8"}],
            **params,
        )
    else:
        response = await client.messages.create(**params)
    return _anthropic_text(response)


async def _google_complete(choice, system, content, json_schema, max_tokens) -> str:
    client = genai.Client(api_key=choice.api_key)
    config = genai_types.GenerateContentConfig(
        system_instruction=system,
        temperature=0.1,
        max_output_tokens=max_tokens,
        response_mime_type="application/json" if json_schema is not None else None,
    )
    # Unlike the OpenAI and Anthropic SDKs, this one doesn't retry overloaded
    # (5xx) responses, which Gemini returns often under load.
    for delay in (2, 6, None):
        try:
            response = await client.aio.models.generate_content(
                model=choice.model, contents=content, config=config
            )
            return response.text or ""
        except genai_errors.ServerError:
            if delay is None:
                raise
            await asyncio.sleep(delay)


_COMPLETERS = {
    "openai": _openai_complete,
    "anthropic": _anthropic_complete,
    "google": _google_complete,
}


async def complete(
    choice: LlmChoice,
    system: str,
    prompt: str,
    json_schema: Optional[dict] = None,
    max_tokens: int = 16000,
) -> str:
    """Send one prompt and return the text. ``json_schema`` asks for JSON output."""
    kind = PROVIDERS[choice.provider].kind
    try:
        return await _COMPLETERS[kind](choice, system, prompt, json_schema, max_tokens)
    except Exception as error:
        raise classify(error, choice.provider) from None


def _image_content(kind: str, prompt: str, image_bytes: bytes, mime_type: str):
    if kind == "google":
        return [
            genai_types.Part.from_bytes(data=image_bytes, mime_type=mime_type),
            prompt,
        ]
    data = base64.b64encode(image_bytes).decode("ascii")
    if kind == "anthropic":
        return [
            {
                "type": "image",
                "source": {"type": "base64", "media_type": mime_type, "data": data},
            },
            {"type": "text", "text": prompt},
        ]
    return [
        {"type": "text", "text": prompt},
        {"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{data}"}},
    ]


async def complete_with_image(
    choice: LlmChoice, system: str, prompt: str, image_bytes: bytes, mime_type: str
) -> str:
    kind = PROVIDERS[choice.provider].kind
    content = _image_content(kind, prompt, image_bytes, mime_type)
    try:
        return await _COMPLETERS[kind](choice, system, content, None, 8000)
    except Exception as error:
        raise classify(error, choice.provider) from None


def pick_default(provider: str, model_ids: list[str]) -> Optional[str]:
    available = set(model_ids)
    for preferred in PROVIDERS[provider].preferred:
        if preferred in available:
            return preferred
    return model_ids[0] if model_ids else None


async def _openai_models(choice: LlmChoice) -> list[dict]:
    client = _openai_client(choice)
    models = []
    async for model in client.models.list():
        extra = model.model_extra or {}
        capabilities = extra.get("capabilities") or {}
        if capabilities and not capabilities.get("completion_chat", True):
            continue
        if extra.get("active") is False or _NON_CHAT.search(model.id):
            continue
        vision = capabilities.get("vision") if capabilities else None
        models.append({"id": model.id, "vision": vision})
    return models


async def _anthropic_models(choice: LlmChoice) -> list[dict]:
    client = anthropic.AsyncAnthropic(api_key=choice.api_key, max_retries=1)
    # Every current Claude model accepts images.
    return [{"id": m.id, "vision": True} async for m in client.models.list()]


async def _google_models(choice: LlmChoice) -> list[dict]:
    client = genai.Client(api_key=choice.api_key)
    models = []
    async for model in await client.aio.models.list():
        name = (model.name or "").removeprefix("models/")
        actions = model.supported_actions or []
        if "generateContent" not in actions or _NON_CHAT.search(name):
            continue
        models.append({"id": name, "vision": name.startswith("gemini")})
    return models


_LISTERS = {
    "openai": _openai_models,
    "anthropic": _anthropic_models,
    "google": _google_models,
}


async def list_models(provider: str, api_key: str) -> dict:
    """Models this key can use, newest names first, plus a suggested default."""
    choice = validate_choice(provider, "placeholder", api_key)
    try:
        models = await _LISTERS[PROVIDERS[provider].kind](choice)
    except Exception as error:
        raise classify(error, provider) from None
    preferred = PROVIDERS[provider].preferred
    rank = {model_id: i for i, model_id in enumerate(preferred)}
    models.sort(key=lambda m: (rank.get(m["id"], len(preferred)), m["id"]))
    ids = [m["id"] for m in models]
    return {"models": models, "default": pick_default(provider, ids)}


def parse_json_object(text: str) -> Optional[dict]:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1].rsplit("```", 1)[0]
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
