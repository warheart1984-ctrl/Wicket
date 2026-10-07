import json
import shutil
import subprocess
from pathlib import Path

import pytest

import executor_setup
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
def client(tmp_path, monkeypatch):
    # Keep ledgers, rate-limit counters and the audit log out of the working directory, so
    # these tests neither leave state behind nor use up another test's rate limit.
    import nova.audit
    from fastapi.testclient import TestClient
    from nova.api import app

    monkeypatch.setenv("NOVA_NODE_RUNTIME_DIR", str(tmp_path / "node"))
    monkeypatch.setattr(nova.audit, "AUDIT_PATH", tmp_path / "nova-audit.log")
    return TestClient(app)


CHAT = {"model": "x", "messages": [{"role": "user", "content": "hello"}]}


def test_api_returns_the_kernel_receipt_when_allowed(client, monkeypatch, tmp_path):
    monkeypatch.setenv("NOVA_ICK_POLICY", str(DEMO_POLICY))
    monkeypatch.setenv("NOVA_ICK_LOG", str(tmp_path / "r.jsonl"))
    body = client.post("/v1/chat/completions", json=CHAT)
    assert body.status_code == 200
    ick = body.json()["nova"]["ick"]
    assert ick["verdict"] == "allow" and ick["outcome_receipt_id"].startswith("receipt:")
    assert len((tmp_path / "r.jsonl").read_text().splitlines()) == 2  # the decision, then its outcome


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


# --- the paths that are not the OpenAI-style routes ------------------------------------------

def _count_calls(monkeypatch, module, names):
    calls = []
    for name in names:
        monkeypatch.setattr(module, name, lambda *a, _n=name, **k: calls.append(_n) or "generated")
    return calls


def test_local_model_tool_is_gated(monkeypatch, deny_policy, tmp_path):
    from nova.node.tools import local_model

    calls = _count_calls(monkeypatch, local_model, ["_ollama_generate", "_vllm_generate"])
    monkeypatch.setenv("NOVA_ICK_POLICY", str(DEMO_POLICY))

    def dispatch(bound):
        args = json.loads(bound.arguments_json)
        try:
            text = local_model._ollama_generate(args["prompt"], args["model"], args["temperature"], args["max_tokens"])
        except Exception:
            text = local_model._vllm_generate(args["prompt"], args["model"], args["temperature"], args["max_tokens"])
        return str(text).encode("utf-8")

    with executor_setup.install_witness(monkeypatch, tmp_path, dispatch):
        assert local_model.generate("hello") == "generated" and calls == ["_ollama_generate"]
    monkeypatch.setenv("NOVA_ICK_POLICY", str(deny_policy))
    with pytest.raises(KernelRefusal) as err:
        local_model.generate("hello")
    assert err.value.code == "KERNEL_DENIED"
    assert calls == ["_ollama_generate"]  # neither the Ollama call nor the vLLM fallback ran


def test_local_model_tool_is_unchanged_when_the_gate_is_off(monkeypatch):
    from nova.node.tools import local_model

    calls = _count_calls(monkeypatch, local_model, ["_ollama_generate", "_vllm_generate"])
    monkeypatch.delenv("NOVA_ICK_POLICY", raising=False)
    assert local_model.generate("hello") == "generated" and calls == ["_ollama_generate"]


@pytest.mark.parametrize("intent", ["code", "wire", "explain"])
def test_every_node_tool_returns_403_when_the_kernel_denies(client, monkeypatch, tmp_path, intent):
    from nova.node.tools import local_model

    # code and wire derive as writes; explain derives as a read. Deny both.
    policy = tmp_path / "deny.json"
    policy.write_text(json.dumps({
        "version": "infinity.policy.v1", "policy_id": "policy-deny-v1",
        "denied_effects": ["read", "write"], "effects_requiring_approval": [],
    }))
    calls = _count_calls(monkeypatch, local_model, ["_ollama_generate", "_vllm_generate"])
    monkeypatch.setenv("NOVA_ICK_POLICY", str(policy))
    response = client.post("/node/tool", json={"intent": intent, "instruction": "x", "current_code": "y"})
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "KERNEL_DENIED"
    assert calls == []


def _gossip_setup(monkeypatch, tmp_path):
    from nova.node import federation

    sent = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(federation, "load_peers", lambda: [
        {"peer_id": "p1", "endpoint": "http://peer-one.test"},
        {"peer_id": "p2", "endpoint": "http://peer-two.test"}])
    monkeypatch.setattr(federation, "signed_gossip_summary", lambda: {"summary": {}, "signature": "s"})
    monkeypatch.setattr(federation.urllib.request, "urlopen",
                        lambda request, timeout=None: sent.append(request.full_url) or Response())
    return federation, sent


def test_gossip_waits_for_approval_under_the_demo_policy(monkeypatch, tmp_path):
    federation, sent = _gossip_setup(monkeypatch, tmp_path)
    monkeypatch.setenv("NOVA_ICK_POLICY", str(DEMO_POLICY))  # writes need approval
    results = federation.gossip_to_peers()
    assert [r["status"] for r in results] == ["refused", "refused"]
    assert results[0]["error"] == "KERNEL_AWAITING_APPROVAL"
    assert sent == []  # nothing left the node


def test_gossip_goes_out_when_the_policy_allows_writes(monkeypatch, tmp_path):
    federation, sent = _gossip_setup(monkeypatch, tmp_path)
    policy = tmp_path / "open.json"
    policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-open-v1",
                                  "denied_effects": [], "effects_requiring_approval": []}))
    monkeypatch.setenv("NOVA_ICK_POLICY", str(policy))
    results = federation.gossip_to_peers()
    assert [r["status"] for r in results] == [200, 200]
    assert sent == ["http://peer-one.test/node/gossip", "http://peer-two.test/node/gossip"]


def test_gossip_is_unchanged_when_the_gate_is_off(monkeypatch, tmp_path):
    federation, sent = _gossip_setup(monkeypatch, tmp_path)
    monkeypatch.delenv("NOVA_ICK_POLICY", raising=False)
    assert [r["status"] for r in federation.gossip_to_peers()] == [200, 200] and len(sent) == 2


def test_async_invoke_path_is_gated(deny_policy):
    import asyncio

    class Inner:
        model, provider_id, calls = "m", "ollama", 0

        async def invoke(self, messages, **kwargs):
            self.calls += 1
            return "reply"

    inner = Inner()
    messages = [{"role": "user", "content": "hi"}]
    assert asyncio.run(IckGatedProvider(inner, IckGate(DEMO_POLICY)).invoke(messages)) == "reply"
    with pytest.raises(KernelRefusal):
        asyncio.run(IckGatedProvider(inner, IckGate(deny_policy)).invoke(messages))
    assert inner.calls == 1


def test_builtin_stub_chat_contacts_nothing(client, monkeypatch, deny_policy):
    """/v1/chat with no provider uses the built-in stub: it never touches the network, so
    there is nothing for the kernel to gate and it answers even under a deny policy."""
    import socket
    import urllib.request

    def boom(*args, **kwargs):
        raise AssertionError("the stub made a network call")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.delenv("NOVA_PROVIDER", raising=False)
    monkeypatch.setenv("NOVA_ICK_POLICY", str(deny_policy))
    response = client.post("/v1/chat", json={"prompt": "hello"})
    assert response.status_code == 200 and response.json()["decision"] == "EXECUTED"


# --- which part of Nova is asking ---------------------------------------------------------------------------

def test_each_path_through_the_gate_names_itself_as_the_actor(monkeypatch, tmp_path):
    """The log used to carry one actor for everything. Now model calls, the local-model tool and gossip differ."""
    from nova.ick import IckGate, SOURCES
    from nova.node import federation
    from nova.node.tools import local_model

    seen = []
    real_run = IckGate._run

    def spy(self, proposal, approval_ids, call=None):
        seen.append((proposal["action"], proposal["actor"]))
        return real_run(self, proposal, approval_ids, call)

    monkeypatch.setattr(IckGate, "_run", spy)
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-allow-v1"}))
    monkeypatch.setenv("NOVA_ICK_POLICY", str(allow))
    def dispatch(bound):
        args = json.loads(bound.arguments_json)
        return str(local_model._ollama_generate(
            args["prompt"], args["model"], args["temperature"], args["max_tokens"],
        )).encode("utf-8")

    # 1. a model call through the provider wrapper
    class Provider:
        model, provider_id = "m", "fake"
        def chat_completion(self, governed_request):
            return {"completion": {"id": "c", "model": "m", "created": 1, "choices": [
                {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}]}, "receipt": {}}
    IckGatedProvider(Provider(), IckGate.from_env()).chat_completion({"messages": [{"role": "user", "content": "hi"}]})
    # 2. the local-model tool (the witness dispatches; Nova does not call the tool itself)
    monkeypatch.setattr(local_model, "_ollama_generate", lambda *a, **k: "text")
    with executor_setup.install_witness(monkeypatch, tmp_path, dispatch):
        local_model.generate("hello")
    # 3. gossip
    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *exc): return False
    monkeypatch.setattr(federation, "load_peers", lambda: [{"peer_id": "p1", "endpoint": "http://peer.test"}])
    monkeypatch.setattr(federation, "signed_gossip_summary", lambda: {"summary": {}, "signature": "s"})
    monkeypatch.setattr(federation.urllib.request, "urlopen", lambda request, timeout=None: Response())
    federation.gossip_to_peers()

    ids = [actor["id"] for _, actor in seen]
    assert sorted(ids) == sorted(["nova-shell/model-provider", "nova-shell/local-model-tool", "nova-shell/gossip"])
    assert set(i.split("/")[1] for i in ids) <= set(SOURCES)
    assert all(actor["kind"] == "agent" for _, actor in seen)


def test_a_source_must_be_one_of_the_known_paths_and_gate_action_requires_one():
    import inspect

    from nova.ick import actor_for, build_proposal, gate_action

    assert actor_for("gossip") == {"kind": "agent", "id": "nova-shell/gossip"}
    for bad in ("", "nova-shell", "gossip/../x", "root", "Gossip"):
        with pytest.raises(ValueError):
            actor_for(bad)
    assert inspect.signature(gate_action).parameters["source"].default is inspect.Parameter.empty  # required
    a = build_proposal(policy_id="p", target="t", governed_request=None, action="a", effect="read", risk="low", source="gossip")
    b = build_proposal(policy_id="p", target="t", governed_request=None, action="a", effect="read", risk="low", source="local-model-tool")
    assert a["actor"] != b["actor"]
