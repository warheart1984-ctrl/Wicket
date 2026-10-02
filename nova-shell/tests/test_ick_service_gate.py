"""Nova's gate with the kernel, key, policy and log in a separate signer service."""

import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from nova.ick import IckGate, IckGatedProvider, KernelRefusal, OutcomeNotRecorded, _find_binary

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

try:
    BINARY = _find_binary(None)
except KernelRefusal:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)

if os.name != "posix":
    pytest.skip("the signer service speaks over Unix domain sockets", allow_module_level=True)

from runtime.ick_service import Service, make_server  # noqa: E402
from runtime.kernel import Kernel  # noqa: E402

from nova.ick_approvals import ApprovalStore  # noqa: E402


class CountingProvider:
    model, provider_id, calls = "fake-model", "fake", 0

    def chat_completion(self, governed_request):
        self.calls += 1
        return {"completion": {"id": "c", "model": self.model, "created": 1, "choices": [
            {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}]},
            "receipt": {}}


def request(text="hello"):
    return {"messages": [{"role": "user", "content": text}]}


class Rig:
    def __init__(self, tmp_path, effects_requiring_approval=()):
        self.dir = tmp_path
        self.private, self.public = tmp_path / "k.priv", tmp_path / "k.pub"
        subprocess.run([BINARY, "keygen", "--out", str(self.private), "--public-out", str(self.public)],
                       check=True, capture_output=True)
        policy = tmp_path / "policy.json"
        policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-svc-v1",
                                      "denied_effects": [],
                                      "effects_requiring_approval": list(effects_requiring_approval)}))
        self.policy = policy
        self.log, self.anchor = tmp_path / "svc" / "r.jsonl", tmp_path / "safe" / "a.jsonl"
        self.store = ApprovalStore(tmp_path / "human" / "approvals.jsonl", tmp_path / "nova-state")
        kernel = Kernel(policy, self.log, binary=BINARY, anchor=self.anchor, sign_key=self.private)
        self.server = make_server(Service(kernel, approvals=self.store.approvals_file), tmp_path / "s.sock")
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.sock = tmp_path / "s.sock"

    def provider(self, **gate_kwargs):
        inner = CountingProvider()
        gate = IckGate(service_socket=self.sock, **gate_kwargs)
        return inner, IckGatedProvider(inner, gate)

    def verify(self):
        return Kernel(self.policy, self.log, binary=BINARY, anchor=self.anchor, trusted_keys=self.public,
                      require_signatures=True).verify()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path)
    yield r
    r.stop()


def test_a_call_is_allowed_signed_and_its_outcome_recorded_without_nova_holding_anything(rig):
    inner, provider = rig.provider()
    result = provider.chat_completion(request())
    assert inner.calls == 1 and result["ick"]["receipt_id"]
    entries = [json.loads(l) for l in rig.log.read_text().splitlines()]
    assert len(entries) == 2  # the decision and its outcome
    assert all(e.get("signature") for e in entries)
    assert rig.verify() is True
    gate = provider._gate
    assert gate.sign_key is None and gate.log is None and gate.anchor is None and gate.binary is None


def test_the_gate_cannot_be_given_the_things_the_service_owns(rig):
    for extra in ({"policy": rig.policy}, {"sign_key": rig.private}, {"log": rig.log}, {"binary": BINARY}):
        with pytest.raises(ValueError, match="belong to the service"):
            IckGate(service_socket=rig.sock, **extra)
    with pytest.raises(ValueError):
        IckGate()  # neither a policy nor a service


def test_from_env_prefers_nothing_ambiguous(rig):
    assert IckGate.from_env({}) is None
    gate = IckGate.from_env({"NOVA_ICK_SERVICE": str(rig.sock), "NOVA_ICK_LOG": str(rig.log)})  # log: operator's
    assert gate.service == rig.sock
    for clash in ({"NOVA_ICK_POLICY": str(rig.policy)}, {"NOVA_ICK_SIGN_KEY": str(rig.private)},
                  {"NOVA_ICK_BIN": BINARY}):
        with pytest.raises(ValueError, match="NOVA_ICK_SERVICE"):
            IckGate.from_env({"NOVA_ICK_SERVICE": str(rig.sock), **clash})


def test_when_the_service_is_gone_nothing_goes_through(rig):
    inner, provider = rig.provider()
    rig.stop()
    with pytest.raises(KernelRefusal) as err:
        provider.chat_completion(request())
    assert err.value.code == "KERNEL_UNAVAILABLE" and inner.calls == 0


def test_an_outcome_that_cannot_be_recorded_withholds_the_reply(rig):
    inner, provider = rig.provider()
    gate = provider._gate
    ick = gate.check(target="fake:m", governed_request=request())
    rig.stop()
    with pytest.raises(OutcomeNotRecorded):
        gate.record_outcome(ick, status="completed", response_text="x")


def test_a_service_that_sends_junk_is_a_refusal(tmp_path):
    path = tmp_path / "junk.sock"
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    server.listen(4)

    def serve():
        for reply in (b"not json\n", b"[1]\n", b'{"ok": false, "error": "no"}\n', b'{"ok": true}\n', b""):
            conn, _ = server.accept()
            conn.recv(65536)
            conn.sendall(reply)
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    gate = IckGate(service_socket=path)
    for _ in range(5):
        with pytest.raises(KernelRefusal) as err:
            gate.check(target="t", governed_request=request())
        assert err.value.code == "KERNEL_UNAVAILABLE"
    server.close()


def test_a_human_approval_works_through_the_service_and_a_made_up_one_does_not(tmp_path):
    rig = Rig(tmp_path, effects_requiring_approval=["read"])
    try:
        inner, provider = rig.provider(approvals=rig.store)
        with pytest.raises(KernelRefusal) as err:
            provider.chat_completion(request())
        assert err.value.code == "KERNEL_AWAITING_APPROVAL"
        h = err.value.proposal_hash

        # a taken-over Nova inventing an approval: the service has never heard of it
        real_claim = rig.store.claim
        rig.store.claim = lambda *_a, **_k: {"approval_id": "approval-made-up", "approved_by": "me"}
        with pytest.raises(KernelRefusal) as bad:
            provider.chat_completion(request())
        assert bad.value.code == "KERNEL_UNAVAILABLE" and inner.calls == 0
        rig.store.claim = real_claim

        rig.store.approve(h, approved_by="alice")
        assert provider.chat_completion(request())["ick"]["approved_by"] == "alice"
        assert inner.calls == 1
        with pytest.raises(KernelRefusal):
            provider.chat_completion(request())  # the single use is spent
        assert rig.verify() is True
    finally:
        rig.stop()


def test_a_denial_stops_an_approval_even_if_nova_ignored_it(tmp_path):
    rig = Rig(tmp_path, effects_requiring_approval=["read"])
    try:
        inner, provider = rig.provider(approvals=rig.store)
        with pytest.raises(KernelRefusal) as err:
            provider.chat_completion(request())
        h = err.value.proposal_hash
        entry = rig.store.approve(h, approved_by="alice")
        rig.store.deny(h, denied_by="bob")
        # Nova's own check would catch this first; ask the service directly, as a taken-over Nova could
        from nova.ick import _call_service, build_proposal
        proposal = build_proposal(policy_id="policy-svc-v1", target="fake:fake-model", governed_request=request(),
                                  action="chat_completion", effect="read", risk="low")
        with pytest.raises(KernelRefusal):
            _call_service(rig.sock, {"op": "evaluate", "proposal": {**proposal, "approval_id": entry["approval_id"]},
                                     "approval_ids": [entry["approval_id"]]})
    finally:
        rig.stop()
