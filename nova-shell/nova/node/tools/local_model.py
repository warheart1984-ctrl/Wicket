from __future__ import annotations

import json
import os
import urllib.request

from nova.ick import IckGate, KernelRefusal, gate_outcome
from nova.providers.http import begin_direct_model_http, refuse_unconfigured_model_http


DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_VLLM_URL = "http://localhost:8000/v1/completions"
DEFAULT_CODER_MODEL = "qwen2.5-coder:3b"
_READ_TOOLS = {"explain", "status"}
_WRITE_TOOLS = {"code", "wire"}


def generate(
    prompt: str,
    *,
    tool: str = "explain",
    model: str | None = DEFAULT_CODER_MODEL,
    temperature: float = 0.2,
    max_tokens: int = 2048,
) -> str:
    active_model = model or DEFAULT_CODER_MODEL
    gate = IckGate.from_env()
    if gate is None:
        refuse_unconfigured_model_http()
        return _direct(prompt, active_model, temperature, max_tokens)
    if tool not in _READ_TOOLS and tool not in _WRITE_TOOLS:
        raise KernelRefusal(code="UNKNOWN_CALL_SHAPE", message=f"tool {tool!r} is not a known local model tool")
    call = {
        "shape": "local_model_tool",
        "tool": tool,
        "arguments": {
            "max_tokens": max_tokens,
            "model": active_model,
            "prompt": prompt,
            "temperature": temperature,
        },
    }
    reply, ick = gate.run_witnessed(
        call,
        action="chat_completion",
        source="local-model-tool",
        governed_request={"messages": [{"role": "user", "content": prompt}]},
    )
    if reply.status == "failed":
        gate_outcome(ick, status="failed", strict=False)
        raise OSError(reply.error or "the witness could not run the local model tool")
    text = (reply.body or b"").decode("utf-8")
    gate_outcome(ick, status="completed", response_text=text)
    return text


def _direct(prompt: str, model: str, temperature: float, max_tokens: int) -> str:
    try:
        return _ollama_generate(prompt, model, temperature, max_tokens)
    except Exception:
        return _vllm_generate(prompt, model, temperature, max_tokens)


def _ollama_generate(prompt: str, model: str, temperature: float, max_tokens: int) -> str:
    data = _post_json(
        _ollama_url(),
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        },
        _timeout(),
    )
    return str(data.get("response", ""))


def _vllm_generate(prompt: str, model: str, temperature: float, max_tokens: int) -> str:
    data = _post_json(
        _vllm_url(),
        {"model": model, "prompt": prompt, "temperature": temperature, "max_tokens": max_tokens},
        _timeout(),
    )
    return str(data["choices"][0]["text"])


def _post_json(url: str, payload: dict[str, object], timeout: float) -> dict[str, object]:
    begin_direct_model_http()
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _ollama_url() -> str:
    return os.environ.get("NOVA_NODE_OLLAMA_URL", DEFAULT_OLLAMA_URL)


def _vllm_url() -> str:
    return os.environ.get("NOVA_NODE_VLLM_URL", DEFAULT_VLLM_URL)


def _timeout() -> float:
    return float(os.environ.get("NOVA_NODE_LOCAL_MODEL_TIMEOUT", "60"))
