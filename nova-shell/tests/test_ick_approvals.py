import json
import os
import subprocess
import sys
import time
from pathlib import Path

import executor_setup
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
    kinds = [(e.get("verdict") or "outcome:" + e["status"])
             for e in map(json.loads, log.read_text().splitlines())]
    assert kinds == ["await_human_approval", "await_human_approval", "allow", "outcome:completed"]
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

    def dispatch(bound):
        sent.append(bound.url)
        return b"{}"

    monkeypatch.setattr(federation, "load_peers", lambda: [{"peer_id": "p1", "endpoint": "http://peer.test"}])
    monkeypatch.setattr(federation, "signed_gossip_summary", lambda: {"summary": {}, "signature": "s"})
    demo = HERE.parent / "demo" / "policy.json"  # writes need approval
    monkeypatch.setenv("NOVA_ICK_POLICY", str(demo))
    monkeypatch.delenv("WICKET_ALLOW_DIRECT_CALLS", raising=False)
    store = ApprovalStore(tmp_path / "human" / "approvals.jsonl", tmp_path / "state")
    monkeypatch.setenv("NOVA_ICK_APPROVALS", str(store.approvals_file))
    monkeypatch.setenv("NOVA_ICK_STATE", str(tmp_path / "state"))

    with executor_setup.install_witness(monkeypatch, tmp_path, dispatch):
        assert federation.gossip_to_peers()[0]["status"] == "refused" and sent == []
        store.approve(store.pending()[0]["proposal_hash"], approved_by="alice")
        assert federation.gossip_to_peers()[0]["status"] == "sent" and sent == ["http://peer.test:80/node/gossip"]
        assert federation.gossip_to_peers()[0]["status"] == "refused"  # one use only


@pytest.mark.skipif(os.name != "posix", reason="the stand-in binary is a #! script, which Windows cannot run")
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


# --- denying ----------------------------------------------------------------------------------

def test_deny_needs_a_pending_request_and_is_final(store):
    with pytest.raises(KeyError):
        store.deny("sha3-256:nope", denied_by="alice")
    store.record_pending(proposal_hash="h1", summary={"action": "a"})
    entry = store.deny("h1", denied_by="alice", reason="too risky")
    assert entry["denial_id"].startswith("denial-") and store.is_denied("h1") and not store.is_denied("h2")
    with pytest.raises(ValueError):
        store.deny("h1", denied_by="alice")
    with pytest.raises(ValueError):
        store.approve("h1", approved_by="alice")  # nothing can approve it afterwards
    assert store.waiting() == [] and store.pending() != []


def test_a_denial_cancels_an_approval_already_given(store):
    store.record_pending(proposal_hash="h1", summary={})
    store.approve("h1", approved_by="alice", uses=3)
    assert store.active() != []
    store.deny("h1", denied_by="bob")
    assert store.claim("h1") is None and store.active() == []


def test_a_denial_only_covers_its_own_request(store):
    store.record_pending(proposal_hash="h1", summary={})
    store.record_pending(proposal_hash="h2", summary={})
    store.deny("h1", denied_by="bob")
    store.approve("h2", approved_by="alice")
    assert store.claim("h1") is None and store.claim("h2") is not None


def test_an_unreadable_denials_file_denies_everything(store, tmp_path):
    store.record_pending(proposal_hash="h1", summary={})
    store.approve("h1", approved_by="alice")
    store.denials_file.mkdir(parents=True)  # exists, but cannot be read as a file
    assert store.is_denied("h1") and store.claim("h1") is None


def test_a_denied_request_is_refused_as_such_and_stays_refused(policy, store):
    inner, provider = gated(policy, store)
    h = refuse_and_get_hash(provider)
    store.deny(h, denied_by="alice", reason="no")
    for _ in range(2):
        with pytest.raises(KernelRefusal) as err:
            provider.chat_completion(request())
        assert err.value.code == "KERNEL_DENIED_BY_HUMAN" and err.value.proposal_hash is None
    assert inner.calls == 0
    refuse_and_get_hash(provider, "a different request")  # others still wait for approval as normal


def test_denying_after_approving_stops_the_request_going_through(policy, store):
    inner, provider = gated(policy, store)
    h = refuse_and_get_hash(provider)
    store.approve(h, approved_by="alice")
    store.deny(h, denied_by="bob")
    with pytest.raises(KernelRefusal) as err:
        provider.chat_completion(request())
    assert err.value.code == "KERNEL_DENIED_BY_HUMAN" and inner.calls == 0


def test_a_human_can_deny_with_the_cli_and_the_api_says_so(api):
    h = api.post("/v1/chat/completions", json=CHAT).json()["error"]["proposal_hash"]
    assert cli("deny", h).returncode == 1  # not a terminal and no --yes
    done = cli("deny", h, "--by", "alice", "--reason", "no thanks", "--yes")
    assert done.returncode == 0, done.stderr
    again = api.post("/v1/chat/completions", json=CHAT)
    assert again.status_code == 403 and again.json()["error"]["code"] == "KERNEL_DENIED_BY_HUMAN"
    assert h not in cli("approvals").stdout  # no longer waiting
    assert cli("approve", h, "--yes").returncode == 1  # and cannot be approved now
    assert cli("deny", h, "--yes").returncode == 1
    assert cli("deny", "sha3-256:made-up", "--yes").returncode == 1


def test_there_is_no_http_route_for_denying(api):
    from nova.api import app

    assert not [p for p in (getattr(r, "path", "") for r in app.routes) if "deny" in p.lower() or "denial" in p.lower()]
    for path in ("/deny", "/v1/deny", "/node/deny"):
        assert api.post(path, json={"proposal_hash": "x"}).status_code in (404, 405)


# --- expiry of undecided requests -------------------------------------------------------------

DAY = 86400.0


def test_an_undecided_request_expires_and_cannot_be_decided(tmp_path):
    store = ApprovalStore(tmp_path / "h" / "approvals.jsonl", tmp_path / "state", pending_ttl=DAY)
    store.record_pending(proposal_hash="h1", summary={"action": "a"}, now=1000)
    assert [r["proposal_hash"] for r in store.pending(now=1000 + DAY)] == ["h1"]  # right at the limit
    assert store.pending(now=1000 + DAY + 1) == [] and store.waiting(now=1000 + DAY + 1) == []
    assert store.expired_count(now=1000 + DAY + 1) == 1 and store.expired_count(now=1000 + DAY) == 0
    with pytest.raises(KeyError, match="expired"):
        store.approve("h1", approved_by="alice", now=1000 + DAY + 1)
    with pytest.raises(KeyError, match="expired"):
        store.deny("h1", denied_by="alice", now=1000 + DAY + 1)
    assert not store.approvals_file.exists() and not store.denials_file.exists()
    assert len(store.pending_file.read_text().splitlines()) == 1  # nothing was rewritten


def test_asking_again_after_expiry_makes_a_fresh_pending_request_once(tmp_path):
    store = ApprovalStore(tmp_path / "h" / "approvals.jsonl", tmp_path / "state", pending_ttl=DAY)
    store.record_pending(proposal_hash="h1", summary={}, now=1000)
    store.record_pending(proposal_hash="h1", summary={}, now=1000 + 2 * DAY)
    store.record_pending(proposal_hash="h1", summary={}, now=1000 + 2 * DAY + 5)  # already waiting
    now = 1000 + 2 * DAY + 10
    assert [r["requested_at"] for r in store.pending(now=now)] == [1000 + 2 * DAY]
    assert store.expired_count(now=now) == 0
    assert len(store.pending_file.read_text().splitlines()) == 2
    store.approve("h1", approved_by="alice", now=now)  # and it can be decided again


def test_a_request_with_a_bad_time_is_treated_as_expired(tmp_path):
    store = ApprovalStore(tmp_path / "h" / "approvals.jsonl", tmp_path / "state")
    store.pending_file.parent.mkdir(parents=True)
    store.pending_file.write_text("\n".join(json.dumps(r) for r in (
        {"proposal_hash": "a"}, {"proposal_hash": "b", "requested_at": "soon"},
        {"proposal_hash": "c", "requested_at": None}, {"proposal_hash": "d", "requested_at": 5})) + "\n")
    assert store.pending(now=10) == [{"proposal_hash": "d", "requested_at": 5}]


def test_expiry_does_not_touch_an_approval_already_given_or_a_denial(tmp_path):
    store = ApprovalStore(tmp_path / "h" / "approvals.jsonl", tmp_path / "state", pending_ttl=DAY)
    store.record_pending(proposal_hash="ok", summary={}, now=1000)
    store.record_pending(proposal_hash="no", summary={}, now=1000)
    store.approve("ok", approved_by="alice", expires_in=10 * DAY, now=1000)
    store.deny("no", denied_by="bob", now=1000)
    later = 1000 + 3 * DAY
    assert store.claim("ok", now=later) is not None  # the approval has its own, longer expiry
    assert store.is_denied("no") and store.expired_count(now=later) == 0  # decided is not "expired"


def test_the_ttl_must_be_positive_and_a_bad_setting_never_means_forever(tmp_path):
    from nova.ick import approval_store_from_env, pending_ttl_from
    from nova.ick_approvals import DEFAULT_PENDING_TTL

    with pytest.raises(ValueError):
        ApprovalStore(tmp_path / "a", tmp_path / "s", pending_ttl=0)
    for bad in (None, "", "abc", "0", "-5", "inf", "nan"):
        assert pending_ttl_from(bad) == DEFAULT_PENDING_TTL, bad
    assert pending_ttl_from("3600") == 3600.0
    store = approval_store_from_env({"NOVA_ICK_APPROVALS": str(tmp_path / "a"), "NOVA_ICK_PENDING_TTL": "60"})
    assert store.pending_ttl == 60.0


def test_the_gate_parks_an_expired_request_again_and_it_can_then_be_approved(policy, store, tmp_path):
    store.pending_ttl = DAY
    inner, provider = gated(policy, store)
    h = refuse_and_get_hash(provider)
    # make the first ask old
    rows = [json.loads(l) for l in store.pending_file.read_text().splitlines()]
    rows[0]["requested_at"] = int(time.time() - 3 * DAY)
    store.pending_file.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert store.pending() == []
    assert refuse_and_get_hash(provider) == h  # same request, same hash
    assert [r["proposal_hash"] for r in store.pending()] == [h]
    store.approve(h, approved_by="alice")
    assert provider.chat_completion(request())["ick"]["approved_by"] == "alice"


def test_a_confirmation_prompt_with_no_input_refuses_instead_of_crashing(store, monkeypatch, capsys):
    """Windows reports the NUL device as a terminal, so `input()` can hit end-of-file."""
    import argparse

    import nova.cli as cli_module

    store.record_pending(proposal_hash="h1", summary={"action": "a", "target": "t", "effect": "read", "risk": "low"})
    monkeypatch.setattr(cli_module, "_approval_store", lambda: store)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    def eof(_prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    approve = argparse.Namespace(proposal_hash="h1", by="alice", expires_in=60, uses=1, yes=False)
    deny = argparse.Namespace(proposal_hash="h1", by="alice", reason="", yes=False)
    assert cli_module.approve_command(approve) == 1 and "--yes" in capsys.readouterr().err
    assert cli_module.deny_command(deny) == 1 and "--yes" in capsys.readouterr().err
    assert not store.approvals_file.exists() and not store.denials_file.exists()


# --- counting uses: one at a time, across processes -------------------------------------------------------

RACER = '''
import json, sys, time
from nova.ick_approvals import ApprovalStore
approvals, state, start_at, proposal_hash = sys.argv[1:5]
store = ApprovalStore(approvals, state)
while time.time() < float(start_at):
    time.sleep(0.001)
print("WON" if store.claim(proposal_hash) is not None else "LOST")
'''


def race(tmp_path, uses, racers, rounds):
    """`racers` separate processes try to use an approval with `uses` uses at the same instant."""
    store = ApprovalStore(tmp_path / "h" / "approvals.jsonl", tmp_path / "state")
    outcomes = []
    for r in range(rounds):
        h = f"sha3-256:round{r}"
        store.record_pending(proposal_hash=h, summary={})
        store.approve(h, approved_by="alice", uses=uses)
        start = time.time() + 1.5
        procs = [subprocess.Popen([sys.executable, "-c", RACER, str(store.approvals_file), str(tmp_path / "state"),
                                   str(start), h], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                  cwd=HERE, env={**os.environ, "PYTHONPATH": str(HERE)}) for _ in range(racers)]
        results = [p.communicate(timeout=60) for p in procs]
        for p, (out, err) in zip(procs, results):
            assert p.returncode == 0, err
        outcomes.append(sum(out.strip() == "WON" for out, _ in results))
    return outcomes


def test_simultaneous_attempts_cannot_use_the_last_approval_twice(tmp_path):
    assert race(tmp_path, uses=1, racers=8, rounds=4) == [1, 1, 1, 1]


def test_an_approval_with_three_uses_is_used_exactly_three_times_by_eight_racers(tmp_path):
    assert race(tmp_path, uses=3, racers=8, rounds=2) == [3, 3]


def test_if_the_lock_cannot_be_taken_the_request_is_not_approved_and_the_approval_is_not_spent(tmp_path, monkeypatch):
    from nova import ick_approvals

    store = ApprovalStore(tmp_path / "h" / "approvals.jsonl", tmp_path / "state")
    store.record_pending(proposal_hash="h1", summary={})
    store.approve("h1", approved_by="alice")
    monkeypatch.setattr(ick_approvals, "LOCK_TIMEOUT", 0.3)
    started = time.monotonic()
    with ick_approvals._locked(store.used_file):  # somebody else is in the middle of counting
        assert store.claim("h1") is None
    assert 0.25 <= time.monotonic() - started < 5
    assert not store.used_file.exists() or store.used_file.read_text() == ""  # nothing was spent
    assert store.claim("h1") is not None  # and once the lock is free the approval still works
    assert store.claim("h1") is None  # once only


def test_a_pending_request_records_which_part_of_nova_asked(policy, store):
    inner, provider = gated(policy, store)
    refuse_and_get_hash(provider)
    assert store.pending()[0]["actor"] == "nova-shell/model-provider"
