from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.app.core.config import settings
from backend.app.services import llm
from backend.app.services.llm import LlmChoice, LlmError


def choice(provider, model, own_key=True):
    return LlmChoice(provider, model, "key-for-tests-123", own_key=own_key)


def openai_stub(content='{"ok": true}', models=()):
    client = MagicMock()
    client.chat.completions.create = AsyncMock(
        return_value=SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )
    )

    async def model_iter():
        for m in models:
            yield m

    client.models.list = MagicMock(side_effect=lambda: model_iter())
    return client


class TestValidation:

    def test_valid_choice(self):
        c = llm.validate_choice("anthropic", "claude-opus-5", "sk-ant-abcdefgh")
        assert (c.provider, c.model, c.own_key) == ("anthropic", "claude-opus-5", True)
        assert "sk-ant" not in repr(c)

    @pytest.mark.parametrize(
        "provider, model, key",
        [
            ("evilcorp", "m", "abcdefgh1"),
            ("openai", "gpt 5; rm -rf", "abcdefgh1"),
            ("openai", "", "abcdefgh1"),
            ("openai", "gpt-5", "short"),
            ("openai", "gpt-5", "has spaces in the key"),
            ("openai", "gpt-5", "x" * 401),
        ],
    )
    def test_invalid_choice(self, provider, model, key):
        with pytest.raises(LlmError) as exc:
            llm.validate_choice(provider, model, key)
        assert exc.value.kind == "bad_request"
        assert key not in exc.value.message

    def test_free_tier_uses_server_groq_key(self, monkeypatch):
        monkeypatch.setattr(settings, "groq_api_key", "gsk_server")
        c = llm.free_tier_choice()
        assert (c.provider, c.model, c.own_key) == (
            "groq",
            "openai/gpt-oss-120b",
            False,
        )
        monkeypatch.setattr(settings, "groq_api_key", "")
        assert llm.free_tier_choice() is None

    def test_provider_base_urls_are_fixed_https(self):
        for provider in llm.PROVIDERS.values():
            assert provider.base_url is None or provider.base_url.startswith(
                "https://api."
            )


class TestErrors:

    @pytest.mark.parametrize(
        "status, text, kind",
        [
            (401, "", "auth"),
            (403, "", "auth"),
            (400, "API key not valid. Please pass a valid API key.", "auth"),
            (400, "Incorrect API key provided", "auth"),
            (400, "invalid schema", "bad_request"),
            (404, "", "not_found"),
            (429, "", "rate_limit"),
            (429, "Rate limit reached on tokens per minute (TPM)", "rate_limit"),
            (
                429,
                "Rate limit reached on tokens per day (TPD): Limit 200000",
                "daily_limit",
            ),
            (429, "Rate limit reached on requests per day (RPD)", "daily_limit"),
            (
                413,
                "Request too large on tokens per minute (TPM): rate_limit_exceeded",
                "too_large",
            ),
            (413, "context too long", "too_large"),
            (503, "overloaded", "unavailable"),
            (None, "", "unavailable"),
        ],
    )
    def test_status_mapping(self, status, text, kind):
        error = llm._error_from_status(status, "openai", text)
        assert error.kind == kind
        assert "OpenAI" in error.message

    def test_unknown_exception_is_generic(self):
        error = llm.classify(RuntimeError("sk-leaky-key in message"), "xai")
        assert error.kind == "unavailable"
        assert "sk-leaky" not in error.message


class TestOpenAICompatible:

    @pytest.mark.asyncio
    async def test_openai_reasoning_params_and_json_mode(self):
        stub = openai_stub()
        with patch.object(llm, "_openai_client", return_value=stub):
            out = await llm.complete(
                choice("openai", "gpt-5.6-terra"), "sys", "hi", json_schema={}
            )
        assert out == '{"ok": true}'
        kwargs = stub.chat.completions.create.call_args.kwargs
        assert kwargs["max_completion_tokens"] == 16000
        assert "temperature" not in kwargs and "max_tokens" not in kwargs
        assert kwargs["response_format"] == {"type": "json_object"}
        assert kwargs["messages"][0] == {"role": "system", "content": "sys"}

    @pytest.mark.asyncio
    async def test_groq_gpt_oss_gets_reasoning_effort(self):
        stub = openai_stub("text")
        with patch.object(llm, "_openai_client", return_value=stub):
            await llm.complete(
                choice("groq", "openai/gpt-oss-120b", own_key=False), "s", "p"
            )
        kwargs = stub.chat.completions.create.call_args.kwargs
        assert kwargs["reasoning_effort"] == "medium"
        assert kwargs["temperature"] == 0.1
        assert "response_format" not in kwargs

    @pytest.mark.asyncio
    async def test_mistral_plain_params(self):
        stub = openai_stub("text")
        with patch.object(llm, "_openai_client", return_value=stub):
            await llm.complete(choice("mistral", "mistral-medium-latest"), "s", "p")
        kwargs = stub.chat.completions.create.call_args.kwargs
        assert "reasoning_effort" not in kwargs and kwargs["max_tokens"] == 16000

    def test_client_uses_fixed_base_url(self):
        client = llm._openai_client(choice("xai", "grok-4.6"))
        assert str(client.base_url).startswith("https://api.x.ai/v1")

    @pytest.mark.asyncio
    async def test_image_content_shape(self):
        stub = openai_stub("looks fine")
        with patch.object(llm, "_openai_client", return_value=stub):
            await llm.complete_with_image(
                choice("openai", "gpt-5.6-terra"),
                "s",
                "compare",
                b"\x89PNG",
                "image/png",
            )
        content = stub.chat.completions.create.call_args.kwargs["messages"][1][
            "content"
        ]
        assert content[0] == {"type": "text", "text": "compare"}
        assert content[1]["image_url"]["url"].startswith("data:image/png;base64,")

    @pytest.mark.asyncio
    async def test_model_listing_filters_non_chat(self):
        models = [
            SimpleNamespace(id="gpt-5.6-terra", model_extra={}),
            SimpleNamespace(id="text-embedding-3-large", model_extra={}),
            SimpleNamespace(id="gpt-realtime-2.1", model_extra={}),
            SimpleNamespace(id="old-model", model_extra={"active": False}),
            SimpleNamespace(
                id="mistral-medium-latest",
                model_extra={"capabilities": {"completion_chat": True, "vision": True}},
            ),
            SimpleNamespace(
                id="mistral-embed",
                model_extra={"capabilities": {"completion_chat": False}},
            ),
        ]
        with patch.object(
            llm, "_openai_client", return_value=openai_stub(models=models)
        ):
            result = await llm.list_models("openai", "key-for-tests-123")
        ids = [m["id"] for m in result["models"]]
        assert ids == ["gpt-5.6-terra", "mistral-medium-latest"]
        assert result["default"] == "gpt-5.6-terra"
        assert result["models"][1]["vision"] is True


class TestAnthropic:

    def anthropic_stub(self, stop_reason="end_turn", text='{"ok": true}'):
        response = SimpleNamespace(
            stop_reason=stop_reason, content=[SimpleNamespace(type="text", text=text)]
        )
        client = MagicMock()
        client.messages.create = AsyncMock(return_value=response)
        client.beta.messages.create = AsyncMock(return_value=response)
        return client

    @pytest.mark.asyncio
    async def test_schema_output_and_fallback_for_opus_5(self):
        stub = self.anthropic_stub()
        with patch.object(llm.anthropic, "AsyncAnthropic", return_value=stub):
            out = await llm.complete(
                choice("anthropic", "claude-opus-5"),
                "sys",
                "p",
                json_schema={"type": "object"},
            )
        assert out == '{"ok": true}'
        kwargs = stub.beta.messages.create.call_args.kwargs
        assert kwargs["output_config"] == {
            "format": {"type": "json_schema", "schema": {"type": "object"}}
        }
        assert kwargs["fallbacks"] == [{"model": "claude-opus-4-8"}]
        assert kwargs["betas"] == ["server-side-fallback-2026-06-01"]
        assert kwargs["system"] == "sys"
        stub.messages.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_other_models_use_plain_create(self):
        stub = self.anthropic_stub(text="patched file")
        with patch.object(llm.anthropic, "AsyncAnthropic", return_value=stub):
            out = await llm.complete(
                choice("anthropic", "claude-haiku-4-5"), "sys", "p"
            )
        assert out == "patched file"
        assert "output_config" not in stub.messages.create.call_args.kwargs

    @pytest.mark.asyncio
    async def test_refusal_is_an_error(self):
        stub = self.anthropic_stub(stop_reason="refusal", text="")
        with patch.object(llm.anthropic, "AsyncAnthropic", return_value=stub):
            with pytest.raises(LlmError) as exc:
                await llm.complete(choice("anthropic", "claude-sonnet-5"), "s", "p")
        assert exc.value.kind == "refused"

    def test_image_block(self):
        content = llm._image_content("anthropic", "compare", b"img", "image/jpeg")
        assert content[0]["source"]["media_type"] == "image/jpeg"
        assert content[1] == {"type": "text", "text": "compare"}


class TestGoogle:

    @pytest.mark.asyncio
    async def test_json_mode_and_retry_on_overload(self, monkeypatch):
        from google.genai import errors as genai_errors

        monkeypatch.setattr(llm.asyncio, "sleep", AsyncMock())
        overloaded = genai_errors.ServerError(
            503, {"error": {"message": "high demand", "status": "UNAVAILABLE"}}
        )
        client = MagicMock()
        client.aio.models.generate_content = AsyncMock(
            side_effect=[overloaded, SimpleNamespace(text='{"ok": true}')]
        )
        with patch.object(llm.genai, "Client", return_value=client):
            out = await llm.complete(
                choice("google", "gemini-flash-latest"), "sys", "p", json_schema={}
            )
        assert out == '{"ok": true}'
        config = client.aio.models.generate_content.call_args.kwargs["config"]
        assert config.response_mime_type == "application/json"
        assert config.system_instruction == "sys"
        assert client.aio.models.generate_content.await_count == 2

    @pytest.mark.asyncio
    async def test_persistent_overload_becomes_unavailable(self, monkeypatch):
        from google.genai import errors as genai_errors

        monkeypatch.setattr(llm.asyncio, "sleep", AsyncMock())
        overloaded = genai_errors.ServerError(
            503, {"error": {"message": "busy", "status": "UNAVAILABLE"}}
        )
        client = MagicMock()
        client.aio.models.generate_content = AsyncMock(side_effect=overloaded)
        with patch.object(llm.genai, "Client", return_value=client):
            with pytest.raises(LlmError) as exc:
                await llm.complete(choice("google", "gemini-flash-latest"), "s", "p")
        assert exc.value.kind == "unavailable"


class TestHelpers:

    def test_pick_default(self):
        assert (
            llm.pick_default("anthropic", ["claude-haiku-4-5", "claude-sonnet-5"])
            == "claude-sonnet-5"
        )
        assert llm.pick_default("xai", ["grok-unknown"]) == "grok-unknown"
        assert llm.pick_default("xai", []) is None

    @pytest.mark.parametrize(
        "text, expected",
        [
            ('{"a": 1}', {"a": 1}),
            ('```json\n{"a": 1}\n```', {"a": 1}),
            ("[1, 2]", None),
            ("nope", None),
        ],
    )
    def test_parse_json_object(self, text, expected):
        assert llm.parse_json_object(text) == expected


class TestRetryAfter:

    @pytest.mark.parametrize(
        "text, seconds",
        [
            ("Please try again in 12.5s.", 12.5),
            ("Please try again in 7m54.2s.", 474.2),
            ("Please try again in 1h2m3s.", 3723),
            ("no hint here", None),
        ],
    )
    def test_from_message(self, text, seconds):
        error = llm._error_from_status(
            429, "groq", f"Rate limit reached on tokens per minute (TPM). {text}"
        )
        assert error.retry_after == seconds

    def test_header_wins(self):
        error = llm._error_from_status(
            429, "groq", "try again in 50s", headers={"retry-after": "7"}
        )
        assert error.retry_after == 7.0
