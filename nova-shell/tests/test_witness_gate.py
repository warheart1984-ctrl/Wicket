"""A known-shape Nova route does not reach the target unless the witness dispatched it."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import executor_setup
from nova.errors import ProviderError
from nova.ick import KernelRefusal, _find_binary
from nova.node.tools import local_model
from nova.providers.provider_external import ExternalProvider
from runtime.call_binding import derive, describe_https
from runtime.witness import dispatch_https

DEMO = Path(__file__).resolve().parents[2] / "demo" / "policy.json"

try:
    _find_binary(None)
except KernelRefusal:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)


class _Model:
    def __init__(self) -> None:
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append({"path": self.path, "body": body, "auth": self.headers.get("Authorization")})
                data = json.dumps({
                    "id": "x", "created": 1, "model": body["model"],
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "Paris is the capital of France."}}],
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


@pytest.fixture
def model():
    server = _Model()
    yield server
    server.httpd.shutdown()


@pytest.fixture
def client(tmp_path, monkeypatch, model):
    import nova.audit
    from fastapi.testclient import TestClient
    from nova.api import app

    monkeypatch.setenv("NOVA_NODE_RUNTIME_DIR", str(tmp_path / "node"))
    monkeypatch.setattr(nova.audit, "AUDIT_PATH", tmp_path / "nova-audit.log")
    monkeypatch.delenv("NOVA_ICK_POLICY", raising=False)
    monkeypatch.delenv("NOVA_ICK_WITNESS", raising=False)
    monkeypatch.setenv("NOVA_PROVIDER", "external")
    monkeypatch.setenv("NOVA_EXTERNAL_URL", model.url)
    monkeypatch.setenv("NOVA_EXTERNAL_API_KEY", "secret-key")
    monkeypatch.setenv("NOVA_EXTERNAL_MODEL", "model-1")
    return TestClient(app, raise_server_exceptions=False)


def _open_policy(path: Path) -> None:
    path.write_text(json.dumps({
        "version": "infinity.policy.v1",
        "policy_id": "policy-open-v1",
        "denied_effects": [],
        "effects_requiring_approval": [],
    }))


def test_api_chat_does_not_reach_the_provider_without_a_witness(client, model, monkeypatch, tmp_path):
    policy = tmp_path / "open.json"
    _open_policy(policy)
    executor_setup.arm_caller(monkeypatch, tmp_path)
    executor_setup.grant_caller(policy, "chat_completion")
    monkeypatch.setenv("NOVA_ICK_POLICY", str(policy))
    monkeypatch.setenv("NOVA_ICK_LOG", str(tmp_path / "receipts.jsonl"))
    response = client.post("/v1/chat", json={"prompt": "What is the capital of France?"})
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "WITNESS_UNAVAILABLE"
    assert model.requests == []


def test_the_direct_call_opt_out_does_not_bypass_a_configured_policy(client, model, monkeypatch, tmp_path, capsys):
    policy = tmp_path / "open.json"
    _open_policy(policy)
    executor_setup.arm_caller(monkeypatch, tmp_path)
    executor_setup.grant_caller(policy, "chat_completion")
    monkeypatch.setenv("NOVA_ICK_POLICY", str(policy))
    monkeypatch.setenv("NOVA_ICK_LOG", str(tmp_path / "receipts.jsonl"))
    monkeypatch.setenv("WICKET_ALLOW_DIRECT_CALLS", "1")
    response = client.post("/v1/chat", json={"prompt": "What is the capital of France?"})
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "WITNESS_UNAVAILABLE"
    assert model.requests == []
    assert "WARNING: WICKET_ALLOW_DIRECT_CALLS" not in capsys.readouterr().err


def test_a_configured_gate_keeps_the_derived_call_digest(client, model, monkeypatch, tmp_path):
    policy = tmp_path / "open.json"
    _open_policy(policy)
    log = tmp_path / "receipts.jsonl"
    monkeypatch.setenv("NOVA_ICK_POLICY", str(policy))
    monkeypatch.setenv("NOVA_ICK_LOG", str(log))
    client_calls = []

    def boom(*_args, **_kwargs):
        client_calls.append("post_json")
        raise AssertionError("Nova called the provider client")

    monkeypatch.setattr("nova.providers.provider_external.post_json", boom)
    digests = []

    def dispatch(bound):
        call = describe_https(bound.method, bound.url, dict(bound.headers), bound.body)
        derived = derive(call, bound.caller_id)
        assert bound.call_digest == derived.call_digest
        assert bound.effect == derived.effect == "write"
        assert bound.target == derived.target
        digests.append(derived.call_digest)
        return dispatch_https(bound)

    with executor_setup.install_witness(monkeypatch, tmp_path, dispatch):
        response = client.post("/v1/chat", json={"prompt": "What is the capital of France?"})
    assert response.status_code == 200, response.text
    assert response.json()["text"] == "Paris is the capital of France."
    assert client_calls == []
    assert len(model.requests) == 1
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    allow = next(entry for entry in entries if entry.get("verdict") == "allow")
    assert allow["call_digest"] == digests[0]


def test_api_chat_reaches_the_provider_only_through_the_witness(client, model, monkeypatch, tmp_path):
    policy = tmp_path / "open.json"
    _open_policy(policy)
    monkeypatch.setenv("NOVA_ICK_POLICY", str(policy))
    monkeypatch.setenv("NOVA_ICK_LOG", str(tmp_path / "receipts.jsonl"))
    seen = []

    def dispatch(bound):
        seen.append(bound.kind)
        return dispatch_https(bound)

    with executor_setup.install_witness(monkeypatch, tmp_path, dispatch):
        response = client.post("/v1/chat", json={"prompt": "What is the capital of France?"})
    assert response.status_code == 200, response.text
    assert response.json()["text"] == "Paris is the capital of France."
    assert seen == ["https_request"]
    assert len(model.requests) == 1
    assert model.requests[0]["path"] == "/v1/chat/completions"


def test_the_provider_client_refuses_a_direct_post_when_the_gate_is_on(monkeypatch):
    monkeypatch.setenv("NOVA_ICK_POLICY", str(DEMO))
    provider = ExternalProvider(base_url="http://127.0.0.1:9", api_key="k", model="m")
    with pytest.raises(ProviderError) as err:
        provider.chat_completion({"messages": [{"role": "user", "content": "hi"}]})
    assert err.value.code == "WITNESS_REQUIRED"


def test_a_local_model_tool_is_not_called_unless_the_witness_dispatches(monkeypatch, tmp_path):
    policy = tmp_path / "open.json"
    _open_policy(policy)
    executor_setup.arm_caller(monkeypatch, tmp_path)
    executor_setup.grant_caller(policy, "chat_completion")
    monkeypatch.setenv("NOVA_ICK_POLICY", str(policy))
    calls = []

    def fake_ollama(*_args, **_kwargs):
        calls.append("ollama")
        return "from-the-tool"

    monkeypatch.setattr(local_model, "_ollama_generate", fake_ollama)
    monkeypatch.setattr(local_model, "_vllm_generate", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("vllm")))
    with pytest.raises(KernelRefusal) as missing:
        local_model.generate("hello", tool="explain")
    assert missing.value.code == "WITNESS_UNAVAILABLE"
    assert calls == []

    def dispatch(bound):
        assert bound.tool == "explain"
        args = json.loads(bound.arguments_json)
        return local_model._ollama_generate(
            args["prompt"], args["model"], args["temperature"], args["max_tokens"],
        ).encode("utf-8")

    with executor_setup.install_witness(monkeypatch, tmp_path, dispatch):
        assert local_model.generate("hello", tool="explain") == "from-the-tool"
    assert calls == ["ollama"]
