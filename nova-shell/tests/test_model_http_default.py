"""Nova model HTTP sends nothing unless a policy and a witness are configured.

The only escape is WICKET_ALLOW_DIRECT_CALLS=1. These tests use an in-process witness
and 127.0.0.1. They do not open a Unix socket.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import nova.audit
from nova.api import OllamaChatProvider, app
from nova.errors import ProviderError
from nova.executor import WitnessEndpoint, WitnessReply, witness_installed
from nova.ick import IckGate, IckGatedProvider, KernelRefusal
from nova.node.tools import local_model
from nova.providers import http
from nova.providers.provider_ollama import OllamaProvider
from runtime.chat import direct_calls_allowed

DEMO = Path(__file__).resolve().parents[2] / "demo" / "policy.json"
ASK = {"prompt": "What is the capital of France?"}


class _Model:
    def __init__(self) -> None:
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append({"path": self.path, "body": body})
                data = json.dumps({
                    "id": "x", "created": 1, "model": body.get("model", "m"),
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "from-the-provider"}}],
                }).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_args):
                return

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_port}/v1"

    def close(self) -> None:
        self.httpd.shutdown()


class _RecordingWitness(WitnessEndpoint):
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def execute(self, call: dict, allow_receipt_id: str, authorization: str | None = None) -> WitnessReply:
        self.calls.append(call)
        return WitnessReply(dispatched=True, divergence=None, status="completed", body=b"{}", error=None)


@pytest.fixture
def model():
    server = _Model()
    yield server
    server.close()


@pytest.fixture
def client(tmp_path, monkeypatch, model):
    monkeypatch.setenv("NOVA_NODE_RUNTIME_DIR", str(tmp_path / "node"))
    monkeypatch.setattr(nova.audit, "AUDIT_PATH", tmp_path / "nova-audit.log")
    monkeypatch.delenv("NOVA_ICK_POLICY", raising=False)
    monkeypatch.delenv("NOVA_ICK_SERVICE", raising=False)
    monkeypatch.delenv("NOVA_ICK_WITNESS", raising=False)
    monkeypatch.delenv("WICKET_ALLOW_DIRECT_CALLS", raising=False)
    monkeypatch.setenv("NOVA_PROVIDER", "external")
    monkeypatch.setenv("NOVA_EXTERNAL_URL", model.url)
    monkeypatch.setenv("NOVA_EXTERNAL_API_KEY", "secret-key")
    monkeypatch.setenv("NOVA_EXTERNAL_MODEL", "model-1")
    return TestClient(app, raise_server_exceptions=False)


def _spy_on_the_provider_client(monkeypatch):
    calls = []

    def post_json(*_args, **_kwargs):
        calls.append("post_json")
        raise AssertionError("Nova called the provider client")

    def urlopen(*_args, **_kwargs):
        calls.append("urlopen")
        raise AssertionError("Nova opened a provider connection")

    monkeypatch.setattr("nova.providers.provider_external.post_json", post_json)
    monkeypatch.setattr("nova.providers.provider_ollama.post_json", post_json)
    monkeypatch.setattr("nova.providers.provider_ollama.post_json_lines", post_json)
    monkeypatch.setattr(local_model, "_post_json", post_json)
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return calls


def test_unset_config_does_not_call_the_provider_client(client, model, monkeypatch, capsys):
    calls = _spy_on_the_provider_client(monkeypatch)
    chat = client.post("/v1/chat", json=ASK)
    completions = client.post("/v1/chat/completions", json={
        "model": "x", "messages": [{"role": "user", "content": "hi"}],
    })
    assert chat.status_code == 403, chat.text
    assert completions.status_code == 403, completions.text
    assert chat.json()["error"]["code"] == "WITNESS_REQUIRED"
    assert completions.json()["error"]["code"] == "WITNESS_REQUIRED"
    assert model.requests == []
    assert calls == []
    assert "WARNING: WICKET_ALLOW_DIRECT_CALLS" not in capsys.readouterr().err

    with pytest.raises(ProviderError) as direct:
        http.post_json("http://127.0.0.1:9/chat/completions", {"messages": []}, timeout=1)
    assert direct.value.code == "WITNESS_REQUIRED"
    assert calls == []


def test_a_witness_without_a_policy_sends_nothing(client, model, monkeypatch):
    calls = _spy_on_the_provider_client(monkeypatch)
    witness = _RecordingWitness()
    with witness_installed(witness):
        response = client.post("/v1/chat", json=ASK)
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "WITNESS_REQUIRED"
    assert witness.calls == []
    assert model.requests == []
    assert calls == []


def test_the_local_model_tool_and_ollama_path_send_nothing_when_unset(monkeypatch, capsys):
    calls = _spy_on_the_provider_client(monkeypatch)
    monkeypatch.delenv("NOVA_ICK_POLICY", raising=False)
    monkeypatch.delenv("NOVA_ICK_SERVICE", raising=False)
    monkeypatch.delenv("WICKET_ALLOW_DIRECT_CALLS", raising=False)
    with pytest.raises(ProviderError) as err:
        local_model.generate("hello", tool="explain")
    assert err.value.code == "WITNESS_REQUIRED"

    provider = OllamaChatProvider(base_url="http://127.0.0.1:9", model="m")
    with pytest.raises(ProviderError) as ollama:
        provider._invoke_sync([{"role": "user", "content": "hi"}], model="m", max_tokens=8, temperature=0)
    assert ollama.value.code == "WITNESS_REQUIRED"
    assert calls == []
    assert "WARNING: WICKET_ALLOW_DIRECT_CALLS" not in capsys.readouterr().err


def test_the_opt_out_is_off_by_default(monkeypatch):
    monkeypatch.delenv("WICKET_ALLOW_DIRECT_CALLS", raising=False)
    assert direct_calls_allowed() is False
    for value in ("", "0", "true", "yes", "on", "2"):
        monkeypatch.setenv("WICKET_ALLOW_DIRECT_CALLS", value)
        assert direct_calls_allowed() is False


@pytest.mark.parametrize("value", ["", "0", "true", "yes", "on"])
def test_any_other_opt_out_value_sends_nothing(client, model, monkeypatch, capsys, value):
    calls = _spy_on_the_provider_client(monkeypatch)
    monkeypatch.setenv("WICKET_ALLOW_DIRECT_CALLS", value)
    response = client.post("/v1/chat", json=ASK)
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "WITNESS_REQUIRED"
    assert model.requests == []
    assert calls == []
    assert "WARNING: WICKET_ALLOW_DIRECT_CALLS" not in capsys.readouterr().err


def test_the_opt_out_sends_and_warns_on_every_use(client, model, monkeypatch, capsys):
    monkeypatch.setenv("WICKET_ALLOW_DIRECT_CALLS", "1")
    first = client.post("/v1/chat", json=ASK)
    second = client.post("/v1/chat/completions", json={
        "model": "x", "messages": [{"role": "user", "content": "hi"}],
    })
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert len(model.requests) == 2
    err = capsys.readouterr().err
    assert err.count("WARNING: WICKET_ALLOW_DIRECT_CALLS=1") == 2
    assert "Local development only" in err and "unsafe" in err


def test_the_opt_out_ignores_a_witness_that_has_no_policy(client, model, monkeypatch, capsys):
    monkeypatch.setenv("WICKET_ALLOW_DIRECT_CALLS", "1")
    witness = _RecordingWitness()
    with witness_installed(witness):
        response = client.post("/v1/chat", json=ASK)
    assert response.status_code == 200, response.text
    assert witness.calls == []
    assert len(model.requests) == 1
    assert capsys.readouterr().err.count("WARNING: WICKET_ALLOW_DIRECT_CALLS=1") == 1


def test_a_streamed_known_shape_is_refused_when_a_witness_would_be_required(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "nova.providers.provider_ollama.post_json_lines",
        lambda *_args, **_kwargs: calls.append("stream") or iter(()),
    )
    provider = IckGatedProvider(
        OllamaProvider(base_url="http://127.0.0.1:9", model="m"),
        IckGate(DEMO),
    )
    with pytest.raises(KernelRefusal) as err:
        list(provider.chat_completion_stream({"messages": [{"role": "user", "content": "hi"}]}))
    assert err.value.code == "STREAM_NOT_BOUND"
    assert calls == []
