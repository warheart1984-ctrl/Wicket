import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from nova.ick import IckGate, IckGatedProvider, KernelRefusal, _find_binary
from nova.ick_approvals import ApprovalStore

HERE = Path(__file__).resolve().parents[1]

try:
    BINARY = _find_binary(None)
except KernelRefusal:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)


class CountingProvider:
    model, provider_id, calls = "fake-model", "fake", 0

    def chat_completion(self, governed_request):
        self.calls += 1
        return {"completion": {"id": "c", "model": self.model, "created": 1, "choices": [
            {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}]},
            "receipt": {}}


def request(text="hello"):
    return {"messages": [{"role": "user", "content": text}]}


@pytest.fixture
def policy(tmp_path):
    """Every read needs a human approval."""
    path = tmp_path / "needs-approval.json"
    path.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-approve-v1",
                                "denied_effects": [], "effects_requiring_approval": ["read"]}))
    return path


@pytest.fixture
def store(tmp_path):
    return ApprovalStore(tmp_path / "human" / "approvals.jsonl", tmp_path / "state")


def gated(policy, store, tmp_path=None, **kwargs):
    inner = CountingProvider()
    return inner, IckGatedProvider(inner, IckGate(policy, approvals=store, **kwargs))


def refuse_and_get_hash(provider, text="hello"):
    with pytest.raises(KernelRefusal) as err:
        provider.chat_completion(request(text))
    assert err.value.code == "KERNEL_AWAITING_APPROVAL" and err.value.proposal_hash
    return err.value.proposal_hash


# --- the store on its own ---------------------------------------------------------------------

def test_approve_requires_a_pending_request(store):
    with pytest.raises(KeyError):
        store.approve("sha3-256:nope", approved_by="me")


def test_claim_is_single_use_by_default_and_counts_uses(store):
    store.record_pending(proposal_hash="h1", summary={})
    store.approve("h1", approved_by="me", uses=2)
    assert store.claim("h1") and store.claim("h1")
    assert store.claim("h1") is None


def test_expired_approval_is_ignored(store):
    store.record_pending(proposal_hash="h1", summary={})
    store.approve("h1", approved_by="me", expires_in=10, now=1000)
    assert store.claim("h1", now=1005) is not None
    store.approve("h1", approved_by="me", expires_in=10, now=1000)
    assert store.claim("h1", now=1011) is None


def test_an_approval_matches_only_its_own_hash(store):
    store.record_pending(proposal_hash="h1", summary={})
    store.approve("h1", approved_by="me")
    assert store.claim("h2") is None


def test_malformed_records_never_approve(store):
    store.approvals_file.parent.mkdir(parents=True)
    store.approvals_file.write_text("not json\n"
                                    + json.dumps({"approval_id": "a", "proposal_hash": "h1"}) + "\n"
                                    + json.dumps({"approval_id": "b", "proposal_hash": "h1", "expires_at": "soon"}) + "\n"
                                    + json.dumps({"proposal_hash": "h1", "expires_at": 9e12}) + "\n")
    assert store.claim("h1") is None


def test_pending_requests_are_not_duplicated(store):
    for _ in range(3):
        store.record_pending(proposal_hash="h1", summary={"action": "x"})
    assert len(store.pending()) == 1


# --- the gate with the real kernel ------------------------------------------------------------

def test_refused_request_is_parked_and_never_self_approved(policy, store):
    inner, provider = gated(policy, store)
    refuse_and_get_hash(provider)
    assert inner.calls == 0
    assert len(store.pending()) == 1
    assert not store.approvals_file.exists()  # Nova never writes the approvals file


def test_same_request_gives_the_same_hash(policy, store):
    _, provider = gated(policy, store)
    assert refuse_and_get_hash(provider) == refuse_and_get_hash(provider)
    assert len(store.pending()) == 1


def test_approved_request_goes_through_once(policy, store):
    inner, provider = gated(policy, store)
    h = refuse_and_get_hash(provider)
    store.approve(h, approved_by="alice")
    result = provider.chat_completion(request())
    assert inner.calls == 1
    assert result["ick"]["verdict"] == "allow"
    assert result["ick"]["approved_by"] == "alice" and result["ick"]["approval_id"].startswith("approval-")
    refuse_and_get_hash(provider)  # the single use is spent
    assert inner.calls == 1


def test_an_approval_does_not_cover_a_different_request(policy, store):
    inner, provider = gated(policy, store)
    store.approve(refuse_and_get_hash(provider, "request A"), approved_by="alice")
    refuse_and_get_hash(provider, "request B")
    assert inner.calls == 0
    assert provider.chat_completion(request("request A"))["ick"]["verdict"] == "allow"


def test_expired_approval_does_not_let_a_request_through(policy, store):
    inner, provider = gated(policy, store)
    h = refuse_and_get_hash(provider)
    store.approve(h, approved_by="alice", expires_in=60, now=time.time() - 3600)
    refuse_and_get_hash(provider)
    assert inner.calls == 0


def test_without_an_approvals_file_nothing_changes_and_nothing_is_written(policy, tmp_path):
    inner = CountingProvider()
    provider = IckGatedProvider(inner, IckGate(policy))  # approvals switched off
    with pytest.raises(KernelRefusal) as err:
        provider.chat_completion(request())
    assert err.value.code == "KERNEL_AWAITING_APPROVAL" and inner.calls == 0
    assert not (tmp_path / "state").exists()


def test_a_denied_request_cannot_be_approved(tmp_path, store):
    deny = tmp_path / "deny.json"
    deny.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-deny-v1",
                                "denied_effects": ["read"], "effects_requiring_approval": []}))
    inner, provider = gated(deny, store)
    with pytest.raises(KernelRefusal) as err:
        provider.chat_completion(request())
    assert err.value.code == "KERNEL_DENIED" and err.value.proposal_hash is None
    assert store.pending() == [] and inner.calls == 0


def test_the_receipt_log_records_the_wait_and_the_approved_call(policy, store, tmp_path):
    log, anchor = tmp_path / "log" / "r.jsonl", tmp_path / "safe" / "a.jsonl"
    inner, provider = gated(policy, store, log=log, anchor=anchor)
    store.approve(refuse_and_get_hash(provider), approved_by="alice")
    provider.chat_completion(request())
    verdicts = [json.loads(line)["verdict"] for line in log.read_text().splitlines()]
    assert verdicts == ["await_human_approval", "await_human_approval", "allow"]
    done = subprocess.run([BINARY, "verify-log", "--log", str(log), "--anchor", str(anchor)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


# --- through the HTTP API and the real CLI ----------------------------------------------------

@pytest.fixture
def api(tmp_path, monkeypatch, policy):
    import nova.audit
    from fastapi.testclient import TestClient
    from nova.api import app

    monkeypatch.setenv("NOVA_NODE_RUNTIME_DIR", str(tmp_path / "node"))
    monkeypatch.setattr(nova.audit, "AUDIT_PATH", tmp_path / "nova-audit.log")
    monkeypatch.setenv("NOVA_ICK_POLICY", str(policy))
    monkeypatch.setenv("NOVA_ICK_APPROVALS", str(tmp_path / "human" / "approvals.jsonl"))
    monkeypatch.setenv("NOVA_ICK_STATE", str(tmp_path / "state"))
    return TestClient(app)


CHAT = {"model": "x", "messages": [{"role": "user", "content": "hello"}]}


def cli(*args):
    env = {**os.environ, "PYTHONPATH": str(HERE)}
    return subprocess.run([sys.executable, "-m", "nova.cli", *args], capture_output=True, text=True,
                          cwd=HERE, env=env)


def test_full_flow_over_http_with_a_human_using_the_cli(api):
    first = api.post("/v1/chat/completions", json=CHAT)
    assert first.status_code == 403
    error = first.json()["error"]
    assert error["code"] == "KERNEL_AWAITING_APPROVAL" and error["proposal_hash"]
    assert error["approve_with"] == f"python -m nova.cli approve {error['proposal_hash']}"

    listed = cli("approvals")
    assert error["proposal_hash"] in listed.stdout, listed.stderr

    assert api.post("/v1/chat/completions", json=CHAT).status_code == 403  # still not approved

    done = cli("approve", error["proposal_hash"], "--by", "alice", "--yes")
    assert done.returncode == 0, done.stderr
    ok = api.post("/v1/chat/completions", json=CHAT)
    assert ok.status_code == 200, ok.text
    assert ok.json()["nova"]["ick"]["approved_by"] == "alice"
    assert api.post("/v1/chat/completions", json=CHAT).status_code == 403  # single use

    assert error["proposal_hash"] not in cli("approvals").stdout  # nothing left waiting


def test_cli_will_not_approve_without_yes_when_not_a_terminal(api):
    h = api.post("/v1/chat/completions", json=CHAT).json()["error"]["proposal_hash"]
    done = cli("approve", h)
    assert done.returncode == 1 and "--yes" in done.stderr
    assert api.post("/v1/chat/completions", json=CHAT).status_code == 403


def test_cli_will_not_approve_an_unknown_hash(api):
    done = cli("approve", "sha3-256:made-up", "--yes")
    assert done.returncode == 1 and "no pending request" in done.stderr


def test_there_is_no_http_route_for_approving(api):
    from nova.api import app

    paths = [getattr(route, "path", "") for route in app.routes]
    assert not [p for p in paths if "approv" in p.lower()], paths
    for method, path in (("post", "/approve"), ("post", "/v1/approve"), ("post", "/node/approve")):
        assert getattr(api, method)(path, json={"proposal_hash": "x"}).status_code in (404, 405)


def test_gossip_can_be_approved_like_any_other_action(tmp_path, monkeypatch):
    from nova.node import federation

    sent = []

    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *exc): return False

    monkeypatch.setattr(federation, "load_peers", lambda: [{"peer_id": "p1", "endpoint": "http://peer.test"}])
    monkeypatch.setattr(federation, "signed_gossip_summary", lambda: {"summary": {}, "signature": "s"})
    monkeypatch.setattr(federation.urllib.request, "urlopen",
                        lambda request, timeout=None: sent.append(request.full_url) or Response())
    demo = HERE.parent / "demo" / "policy.json"  # writes need approval
    monkeypatch.setenv("NOVA_ICK_POLICY", str(demo))
    store = ApprovalStore(tmp_path / "human" / "approvals.jsonl", tmp_path / "state")
    monkeypatch.setenv("NOVA_ICK_APPROVALS", str(store.approvals_file))
    monkeypatch.setenv("NOVA_ICK_STATE", str(tmp_path / "state"))

    assert federation.gossip_to_peers()[0]["status"] == "refused" and sent == []
    store.approve(store.pending()[0]["proposal_hash"], approved_by="alice")
    assert federation.gossip_to_peers()[0]["status"] == 200 and sent == ["http://peer.test/node/gossip"]
    assert federation.gossip_to_peers()[0]["status"] == "refused"  # one use only


def test_the_gate_trusts_the_kernels_answer_not_its_own_bookkeeping(policy, store, tmp_path):
    """A valid approval is on file, but the kernel (here a stand-in) still says 'await'.
    The call must stay refused: Nova never overrides the kernel's verdict."""
    fake = tmp_path / "fake-infinityctl"
    fake.write_text("#!%s\nimport json\nprint(json.dumps({'decision': {'verdict': 'await_human_approval',"
                    " 'reason_codes': ['APPROVAL_REQUIRED'], 'proposal_hash': 'sha3-256:fixed'},"
                    " 'receipt': {'receipt_id': 'receipt:fake'}}))\n" % sys.executable)
    fake.chmod(0o755)
    store.record_pending(proposal_hash="sha3-256:fixed", summary={})
    store.approve("sha3-256:fixed", approved_by="alice")
    inner = CountingProvider()
    provider = IckGatedProvider(inner, IckGate(policy, binary=str(fake), approvals=store))
    with pytest.raises(KernelRefusal) as err:
        provider.chat_completion(request())
    assert err.value.code == "KERNEL_AWAITING_APPROVAL" and inner.calls == 0
