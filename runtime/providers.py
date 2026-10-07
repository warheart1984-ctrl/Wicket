"""OpenAI-compatible chat providers (Groq, NVIDIA, OpenRouter). Standard library only."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib import error, request

USER_AGENT = "infinity-core/0.1"  # Groq's CDN rejects Python's default user agent.


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    url: str
    key_env: str
    model_env: str
    default_model: str
    # Reasoning models spend tokens thinking; a tiny budget returns empty text.
    min_tokens: int = 256
    extra: Callable[[str], dict[str, Any]] = field(default=lambda model: {})


def _groq_extra(model: str) -> dict[str, Any]:
    return {"reasoning_effort": "low"} if model.startswith("openai/gpt-oss") else {}


def _nvidia_extra(model: str) -> dict[str, Any]:
    if "nemotron" in model:
        return {"chat_template_kwargs": {"enable_thinking": False}}
    return {}


PROVIDERS: dict[str, ProviderSpec] = {
    "groq": ProviderSpec(
        "groq",
        "https://api.groq.com/openai/v1/chat/completions",
        "GROQ_API_KEY",
        "INFINITY_GROQ_MODEL",
        "openai/gpt-oss-120b",
        extra=_groq_extra,
    ),
    "nvidia": ProviderSpec(
        "nvidia",
        "https://integrate.api.nvidia.com/v1/chat/completions",
        "NVIDIA_API_KEY",
        "INFINITY_NVIDIA_MODEL",
        "nvidia/nemotron-3-super-120b-a12b",
        extra=_nvidia_extra,
    ),
    "openrouter": ProviderSpec(
        "openrouter",
        "https://openrouter.ai/api/v1/chat/completions",
        "OPENROUTER_API_KEY",
        "INFINITY_OPENROUTER_MODEL",
        "openrouter/free",
    ),
}

Client = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]


class ProviderError(RuntimeError):
    pass


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    req = request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with request.urlopen(req, timeout=90) as response:
            return json.loads(response.read().decode())
    except error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:300]
        raise ProviderError(f"{url} failed: {exc.code} {body}") from exc
    except error.URLError as exc:
        raise ProviderError(f"{url} failed: {exc.reason}") from exc


def prepared_request(
    provider: str,
    messages: list[dict[str, str]],
    *,
    max_tokens: int = 512,
    api_key: str | None = None,
) -> tuple[str, dict[str, Any], dict[str, str]]:
    """URL, JSON body, and headers for one provider call. Raises ProviderError before any send."""
    spec = PROVIDERS.get(provider)
    if spec is None:
        raise ProviderError(f"unknown provider: {provider}")
    key = api_key or os.getenv(spec.key_env, "").strip()
    if not key:
        raise ProviderError(f"{spec.key_env} is not set")
    model = os.getenv(spec.model_env, "").strip() or spec.default_model
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max(int(max_tokens), spec.min_tokens),
        **spec.extra(model),
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    return spec.url, payload, headers


def complete(
    provider: str,
    messages: list[dict[str, str]],
    *,
    max_tokens: int = 512,
    client: Client | None = None,
    api_key: str | None = None,
) -> str:
    """Return the reply text from `provider`, or raise ProviderError."""
    url, payload, headers = prepared_request(provider, messages, max_tokens=max_tokens, api_key=api_key)
    response = (client or _post_json)(url, payload, headers)
    choice = (response.get("choices") or [{}])[0]
    text = str((choice.get("message") or {}).get("content") or "").strip()
    if not text:
        raise ProviderError(f"{provider} returned no text (finish_reason={choice.get('finish_reason')})")
    return text
