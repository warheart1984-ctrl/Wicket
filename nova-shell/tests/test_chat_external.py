"""/v1/chat with NOVA_PROVIDER=external (it used to answer 500 for anything but Ollama)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

DEMO_POLICY = Path(__file__).resolve().parents[2] / "demo" / "policy.json"


class FakeModelServer:
    """A tiny OpenAI-style server. `mode` can be 'ok', 'http500' or 'empty'."""

    def __init__(self):
        self.requests, self.mode = [], "ok"
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append({"path": self.path, "body": body, "auth": self.headers.get("Authorization")})
                if outer.mode == "http500":
                    self._send(500, {"error": "boom"})
                elif outer.mode == "empty":
                    self._send(200, {"id": "x", "model": body["model"], "choices": []})
                else:
                    self._send(200, {"id": "x", "created": 1, "model": body["model"], "choices": [
                        {"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": "Paris is the capital of France."}}],
                        "usage": {"prompt_tokens": 7, "completion_tokens": 5}})

            def _send(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_port}/v1"


@pytest.fixture
def model():
    server = FakeModelServer()
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
    monkeypatch.setenv("NOVA_PROVIDER", "external")
    monkeypatch.setenv("NOVA_EXTERNAL_URL", model.url)
    monkeypatch.setenv("NOVA_EXTERNAL_API_KEY", "secret-key")
    monkeypatch.setenv("NOVA_EXTERNAL_MODEL", "model-1")
    return TestClient(app, raise_server_exceptions=False)


ASK = {"prompt": "What is the capital of France?"}


def test_v1_chat_answers_through_the_external_provider(client, model):
    response = client.post("/v1/chat", json=ASK)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["text"] == "Paris is the capital of France."
    assert body["decision"] == "EXECUTED" and body["receipt_verified"] is True
    (seen,) = model.requests
    assert seen["path"] == "/v1/chat/completions" and seen["auth"] == "Bearer secret-key"
    assert seen["body"]["model"] == "model-1"
    roles = [m["role"] for m in seen["body"]["messages"]]
    assert roles == ["system", "user"]
    assert seen["body"]["messages"][1]["content"] == ASK["prompt"]


def test_the_sibling_route_still_works_with_the_same_settings(client, model):
    body = {"model": "x", "messages": [{"role": "user", "content": "hi"}]}
    assert client.post("/v1/chat/completions", json=body).status_code == 200


def test_local_and_unset_use_the_builtin_stub_and_contact_nothing(client, model, monkeypatch):
    for value in ("local", ""):
        monkeypatch.setenv("NOVA_PROVIDER", value)
        response = client.post("/v1/chat", json=ASK)
        assert response.status_code == 200 and "Nova Cortex" in response.json()["text"]
    assert model.requests == []


def test_ollama_is_still_built_the_old_way(monkeypatch):
    from nova.api import OllamaChatProvider, _build_provider

    monkeypatch.setenv("NOVA_PROVIDER", "ollama")
    provider = _build_provider()
    assert isinstance(provider, OllamaChatProvider) and provider.provider_id == "ollama"


def test_an_unknown_provider_is_a_clear_error_not_a_crash(client, monkeypatch):
    monkeypatch.setenv("NOVA_PROVIDER", "nonsense")
    response = client.post("/v1/chat", json=ASK)
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "PROVIDER_UNSUPPORTED"


def test_a_failing_external_server_is_a_json_error(client, model):
    model.mode = "http500"
    response = client.post("/v1/chat", json=ASK)
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "PROVIDER_HTTP_ERROR"


def test_an_empty_reply_is_an_error_not_a_blank_answer(client, model):
    model.mode = "empty"
    response = client.post("/v1/chat", json=ASK)
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "PROVIDER_EMPTY_RESPONSE"


def test_the_provider_can_come_from_the_config_file(client, model, monkeypatch, tmp_path):
    config = tmp_path / "nova-config.json"
    config.write_text(json.dumps({"provider": "external", "external_url": model.url,
                                  "external_api_key": "from-file", "external_model": "file-model"}))
    monkeypatch.delenv("NOVA_PROVIDER")
    monkeypatch.delenv("NOVA_EXTERNAL_URL")
    monkeypatch.setenv("NOVA_CONFIG", str(config))
    assert client.post("/v1/chat", json=ASK).status_code == 200
    assert model.requests[0]["body"]["model"] == "file-model"


# --- with the kernel gate on --------------------------------------------------------------------

def test_one_kernel_receipt_per_call_not_two(client, model, monkeypatch, tmp_path):
    from nova.ick import KernelRefusal, _find_binary

    try:
        _find_binary(None)
    except KernelRefusal:
        pytest.skip("infinityctl not built")
    log = tmp_path / "r.jsonl"
    monkeypatch.setenv("NOVA_ICK_POLICY", str(DEMO_POLICY))
    monkeypatch.setenv("NOVA_ICK_LOG", str(log))
    assert client.post("/v1/chat", json=ASK).status_code == 200
    assert len(log.read_text().splitlines()) == 1  # the adapter does not gate a second time
    assert len(model.requests) == 1


def test_a_denied_call_never_reaches_the_external_server(client, model, monkeypatch, tmp_path):
    from nova.ick import KernelRefusal, _find_binary

    try:
        _find_binary(None)
    except KernelRefusal:
        pytest.skip("infinityctl not built")
    deny = tmp_path / "deny.json"
    deny.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-deny-v1",
                                "denied_effects": ["read"], "effects_requiring_approval": []}))
    monkeypatch.setenv("NOVA_ICK_POLICY", str(deny))
    response = client.post("/v1/chat", json=ASK)
    assert response.status_code == 403 and response.json()["error"]["code"] == "KERNEL_DENIED"
    assert model.requests == []
