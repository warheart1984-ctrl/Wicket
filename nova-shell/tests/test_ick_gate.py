import json
import shutil
import subprocess
from pathlib import Path

import pytest

from nova.ick import IckGate, IckGatedProvider, KernelRefusal, _find_binary

REPO = Path(__file__).resolve().parents[2]
DEMO_POLICY = REPO / "demo" / "policy.json"

try:
    BINARY = _find_binary(None)
except KernelRefusal:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)


class CountingProvider:
    model = "fake-model"
    provider_id = "fake"

    def __init__(self):
        self.calls = 0

    def chat_completion(self, governed_request):
        self.calls += 1
        return {"completion": {"id": "c1", "model": self.model, "created": 1, "choices": [
            {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}]},
            "receipt": {"r": 1}}

    def chat_completion_stream(self, governed_request):
        self.calls += 1
        yield {"chunk": 1}


REQUEST = {"messages": [{"role": "user", "content": "my secret message"}]}


@pytest.fixture
def deny_policy(tmp_path):
    path = tmp_path / "deny.json"
    path.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-deny-v1",
                                "denied_effects": ["read"], "effects_requiring_approval": []}))
    return path


def test_from_env_is_off_unless_a_policy_is_set(monkeypatch):
    monkeypatch.delenv("NOVA_ICK_POLICY", raising=False)
    assert IckGate.from_env() is None
    monkeypatch.setenv("NOVA_ICK_POLICY", str(DEMO_POLICY))
    assert IckGate.from_env() is not None


def test_allowed_call_reaches_the_provider_and_carries_a_receipt():
    inner = CountingProvider()
    result = IckGatedProvider(inner, IckGate(DEMO_POLICY)).chat_completion(REQUEST)
    assert inner.calls == 1
    assert result["ick"]["verdict"] == "allow" and result["ick"]["receipt_id"].startswith("receipt:")


def test_denied_call_never_reaches_the_provider(deny_policy):
    inner = CountingProvider()
    with pytest.raises(KernelRefusal) as err:
        IckGatedProvider(inner, IckGate(deny_policy)).chat_completion(REQUEST)
    assert err.value.code == "KERNEL_DENIED" and err.value.receipt_id
    assert inner.calls == 0


def test_streaming_is_gated_too(deny_policy):
    inner = CountingProvider()
    assert list(IckGatedProvider(inner, IckGate(DEMO_POLICY)).chat_completion_stream(REQUEST)) == [{"chunk": 1}]
    with pytest.raises(KernelRefusal):
        list(IckGatedProvider(inner, IckGate(deny_policy)).chat_completion_stream(REQUEST))
    assert inner.calls == 1


def test_fails_closed_when_the_kernel_is_missing(tmp_path):
    inner = CountingProvider()
    gate = IckGate(DEMO_POLICY, binary=str(tmp_path / "nope"))
    # An explicit path that does not exist falls through to the search, so also hide the search.
    import nova.ick as ick
    original = ick._find_binary
    ick._find_binary = lambda explicit: (_ for _ in ()).throw(
        KernelRefusal(code="KERNEL_UNAVAILABLE", message="infinityctl not found"))
    try:
        with pytest.raises(KernelRefusal) as err:
            IckGatedProvider(inner, gate).chat_completion(REQUEST)
    finally:
        ick._find_binary = original
    assert err.value.code == "KERNEL_UNAVAILABLE" and inner.calls == 0


def test_message_text_never_reaches_the_kernel_log(tmp_path):
    log = tmp_path / "r.jsonl"
    IckGatedProvider(CountingProvider(), IckGate(DEMO_POLICY, log=log)).chat_completion(REQUEST)
    assert "my secret" not in log.read_text()


def test_receipts_chain_and_anchor_across_calls(tmp_path):
    log, anchor = tmp_path / "log" / "r.jsonl", tmp_path / "safe" / "a.jsonl"
    provider = IckGatedProvider(CountingProvider(), IckGate(DEMO_POLICY, log=log, anchor=anchor))
    for _ in range(3):
        provider.chat_completion(REQUEST)
    done = subprocess.run([BINARY, "verify-log", "--log", str(log), "--anchor", str(anchor)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    # Drop the last receipt: a refused call, and the provider is not touched again.
    log.write_text("\n".join(log.read_text().splitlines()[:2]) + "\n")
    inner = provider._inner
    with pytest.raises(KernelRefusal):
        provider.chat_completion(REQUEST)
    assert inner.calls == 3


def test_anchor_needs_a_log():
    with pytest.raises(ValueError):
        IckGate(DEMO_POLICY, anchor="a.jsonl")


# --- through the real HTTP API -------------------------------------------------------------

@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from nova.api import app
    return TestClient(app)


CHAT = {"model": "x", "messages": [{"role": "user", "content": "hello"}]}


def test_api_returns_the_kernel_receipt_when_allowed(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NOVA_ICK_POLICY", str(DEMO_POLICY))
    monkeypatch.setenv("NOVA_ICK_LOG", str(tmp_path / "r.jsonl"))
    body = client.post("/v1/chat/completions", json=CHAT)
    assert body.status_code == 200
    assert body.json()["nova"]["ick"]["verdict"] == "allow"
    assert len((tmp_path / "r.jsonl").read_text().splitlines()) == 1


NODE = {"task_id": "t1", "payload": {"messages": [{"role": "user", "content": "hi"}]}}
ROUTES = (
    ("/v1/chat/completions", CHAT),
    ("/v1/completions", {"model": "x", "prompt": "hi"}),
    ("/node/submit", NODE),
)


def test_api_refuses_with_403_when_the_kernel_denies(client, monkeypatch, deny_policy):
    monkeypatch.setenv("NOVA_ICK_POLICY", str(deny_policy))
    for path, body in ROUTES:
        response = client.post(path, json=body)
        assert response.status_code == 403, (path, response.status_code, response.text)
        assert response.json()["error"]["code"] == "KERNEL_DENIED", path


def test_the_same_routes_succeed_when_the_kernel_allows(client, monkeypatch):
    monkeypatch.setenv("NOVA_ICK_POLICY", str(DEMO_POLICY))
    for path, body in ROUTES:
        response = client.post(path, json=body)
        assert response.status_code == 200, (path, response.status_code, response.text)


def test_api_is_unchanged_when_the_gate_is_off(client, monkeypatch):
    monkeypatch.delenv("NOVA_ICK_POLICY", raising=False)
    body = client.post("/v1/chat/completions", json=CHAT)
    assert body.status_code == 200 and body.json()["nova"]["ick"] is None
