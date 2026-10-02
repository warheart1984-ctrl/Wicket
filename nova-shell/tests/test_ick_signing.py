"""Nova's gate signs what it writes; the operator screen says whether the log is authenticated."""

import json
import os
import subprocess
import threading
from pathlib import Path

import pytest

from nova.ick import IckGate, IckGatedProvider, KernelRefusal, _find_binary
from nova.ick_approvals import ApprovalStore
from nova.operator_ui import OperatorConfig, make_server

DEMO_POLICY = Path(__file__).resolve().parents[2] / "demo" / "policy.json"

try:
    BINARY = _find_binary(None)
except KernelRefusal:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)

REQUEST = {"messages": [{"role": "user", "content": "hello"}]}


class Provider:
    model, provider_id, calls = "m", "fake", 0

    def chat_completion(self, governed_request):
        self.calls += 1
        return {"completion": {"choices": [{"message": {"content": "an answer"}}]}}


def make_key(directory, name="key"):
    private, public = directory / f"{name}.priv", directory / f"{name}.pub"
    subprocess.run([BINARY, "keygen", "--out", str(private), "--public-out", str(public)],
                   check=True, capture_output=True)
    return private, public


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def verify(log, anchor, public, require=True):
    cmd = [BINARY, "verify-log", "--log", str(log), "--anchor", str(anchor), "--trusted-keys", str(public)]
    if require:
        cmd.append("--require-signatures")
    done = subprocess.run(cmd, capture_output=True, text=True)
    return done.returncode == 0, (done.stdout + done.stderr).strip()


@pytest.fixture
def setup(tmp_path):
    private, public = make_key(tmp_path)
    return {"dir": tmp_path, "private": private, "public": public,
            "log": tmp_path / "log" / "r.jsonl", "anchor": tmp_path / "safe" / "a.jsonl"}


def gated(setup, inner=None, **kwargs):
    gate = IckGate(DEMO_POLICY, log=setup["log"], anchor=setup["anchor"], sign_key=setup["private"], **kwargs)
    return IckGatedProvider(inner or Provider(), gate)


def test_a_gated_call_writes_a_signed_decision_outcome_and_anchor(setup):
    gated(setup).chat_completion(REQUEST)
    entries, records = lines(setup["log"]), lines(setup["anchor"])
    assert [("verdict" in e) for e in entries] == [True, False]  # decision, then outcome
    assert all(row["signature"].startswith("ed25519:") for row in entries + records)
    ok, message = verify(setup["log"], setup["anchor"], setup["public"])
    assert ok and "signatures: 2 verified, 0 unsigned" in message, message


def test_the_key_can_be_set_in_the_environment(setup, monkeypatch):
    monkeypatch.setenv("NOVA_ICK_POLICY", str(DEMO_POLICY))
    monkeypatch.setenv("NOVA_ICK_LOG", str(setup["log"]))
    monkeypatch.setenv("NOVA_ICK_SIGN_KEY", str(setup["private"]))
    gate = IckGate.from_env()
    assert gate.sign_key == setup["private"]
    IckGatedProvider(Provider(), gate).chat_completion(REQUEST)
    assert all("signature" in e for e in lines(setup["log"]))


def test_without_a_key_nothing_is_signed_as_before(setup):
    IckGatedProvider(Provider(), IckGate(DEMO_POLICY, log=setup["log"])).chat_completion(REQUEST)
    assert not any("signature" in e for e in lines(setup["log"]))


@pytest.mark.skipif(os.name != "posix", reason="Unix file modes; the key-file check is a no-op elsewhere (see README)")
def test_a_key_file_others_can_read_stops_the_call_before_the_model_runs(setup):
    os.chmod(setup["private"], 0o644)
    inner = Provider()
    with pytest.raises(KernelRefusal, match="chmod 600") as err:
        gated(setup, inner).chat_completion(REQUEST)
    assert err.value.code == "KERNEL_UNAVAILABLE" and inner.calls == 0


def test_an_approved_request_is_signed_at_every_step(setup):
    policy = setup["dir"] / "needs.json"
    policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-approve-v1",
                                  "denied_effects": [], "effects_requiring_approval": ["read"]}))
    store = ApprovalStore(setup["dir"] / "human" / "ap.jsonl", setup["dir"] / "state")
    provider = IckGatedProvider(Provider(), IckGate(policy, log=setup["log"], anchor=setup["anchor"],
                                                    sign_key=setup["private"], approvals=store))
    with pytest.raises(KernelRefusal) as held:
        provider.chat_completion(REQUEST)
    store.approve(held.value.proposal_hash, approved_by="alice")
    provider.chat_completion(REQUEST)
    entries = lines(setup["log"])
    assert [e.get("verdict") or "outcome" for e in entries] == [
        "await_human_approval", "await_human_approval", "allow", "outcome"]
    assert all("signature" in e for e in entries)
    assert verify(setup["log"], setup["anchor"], setup["public"])[0]


# --- the operator screen ----------------------------------------------------------------------

class Operator:
    def __init__(self, setup, trusted=True, require=False):
        keys = setup["public"] if trusted else None
        self.server, self.token = make_server(OperatorConfig(
            setup["dir"] / "human" / "ap.jsonl", setup["dir"] / "state", log=setup["log"],
            anchor=setup["anchor"], trusted_keys=keys, require_signatures=require))
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def log(self):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        conn.request("GET", "/api/state", headers={"Host": f"127.0.0.1:{self.port}",
                                                   "Authorization": f"Bearer {self.token}"})
        data = json.loads(conn.getresponse().read())
        conn.close()
        return data["log"]


@pytest.fixture
def screen(setup):
    made = []

    def build(**kwargs):
        made.append(Operator(setup, **kwargs))
        return made[-1]

    yield build
    for operator in made:
        operator.server.shutdown()


def test_the_screen_says_when_signatures_are_checked_and_authentic(setup, screen):
    gated(setup).chat_completion(REQUEST)
    log = screen(require=True).log()
    assert log["verified"] and log["signatures"] == {"checked": True, "required": True, "authenticated": True}


def test_the_screen_says_so_when_it_was_not_given_keys(setup, screen):
    gated(setup).chat_completion(REQUEST)
    log = screen(trusted=False).log()
    assert log["verified"] and log["signatures"]["checked"] is False and log["signatures"]["authenticated"] is False


def test_an_unsigned_log_is_not_called_authenticated_even_though_its_hashes_are_fine(setup, screen):
    IckGatedProvider(Provider(), IckGate(DEMO_POLICY, log=setup["log"], anchor=setup["anchor"])).chat_completion(REQUEST)
    log = screen(trusted=True).log()
    assert log["verified"] is True and log["signatures"]["authenticated"] is False


def test_a_log_signed_by_someone_else_is_not_verified(setup, screen):
    other_private, _ = make_key(setup["dir"], "other")
    IckGatedProvider(Provider(), IckGate(DEMO_POLICY, log=setup["log"], anchor=setup["anchor"],
                                         sign_key=other_private)).chat_completion(REQUEST)
    log = screen(require=True).log()
    assert log["verified"] is False and "not trusted" in log["message"]


def test_stripped_signatures_make_the_screen_report_the_log_as_not_verified(setup, screen):
    gated(setup).chat_completion(REQUEST)
    for path in (setup["log"], setup["anchor"]):
        rows = lines(path)
        for row in rows:
            row.pop("signature"), row.pop("key_id")
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    assert screen(require=True).log()["verified"] is False
    assert screen(require=False).log()["signatures"]["authenticated"] is False  # not trusted either
