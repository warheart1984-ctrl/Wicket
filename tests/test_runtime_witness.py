"""run_turn sends a known-shape provider call only through the witness when one is attached."""

from __future__ import annotations

import json
import pytest

from runtime.call_binding import derive
from runtime.chat import run_turn
from runtime.kernel import Kernel, KernelError, find_binary
from runtime.witness import Witness
from tests.test_execution_binding import keygen

try:
    BINARY = find_binary()
except KernelError:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)


class FakeClient:
    def __init__(self):
        self.calls = []

    def __call__(self, url, payload, headers):
        self.calls.append((url, payload, headers))
        return {"choices": [{"message": {"content": "Paris."}, "finish_reason": "stop"}]}


def test_run_turn_does_not_call_the_provider_unless_the_witness_dispatches(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    signer_priv, signer_pub = keygen(tmp_path, "signer")
    witness_priv, _witness_pub = keygen(tmp_path, "witness")
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "version": "infinity.policy.v1",
        "policy_id": "policy-open-v1",
        "denied_effects": [],
        "effects_requiring_approval": [],
    }))
    log = tmp_path / "receipts.jsonl"
    kernel = Kernel(policy, log, binary=BINARY, sign_key=signer_priv)
    client = FakeClient()
    called = {"complete": 0}

    def forbid_complete(*_args, **_kwargs):
        called["complete"] += 1
        raise AssertionError("run_turn called the provider client directly")

    monkeypatch.setattr("runtime.chat.complete", forbid_complete)

    def dispatch(bound):
        assert bound.kind == "https_request"
        assert bound.call_digest == derive({
            "shape": "https_request",
            "method": "POST",
            "scheme": "https",
            "host": "api.groq.com",
            "port": 443,
            "path": "/openai/v1/chat/completions",
            "headers": {"Content-Type": "application/json", "Authorization": "Bearer test-key"},
            "authorization_present": True,
            "body": bound.body.decode("utf-8"),
        }).call_digest
        payload = json.loads(bound.body.decode("utf-8"))
        return json.dumps(client(bound.url, payload, dict(bound.headers))).encode("utf-8")

    witness = Witness(
        binary=BINARY,
        receipt_log=log,
        witness_log=tmp_path / "witness.jsonl",
        witness_key=witness_priv,
        receipt_trusted_keys=signer_pub,
        dispatch=dispatch,
    )
    result = run_turn("Capital of France?", "groq", kernel, client=client, witness=witness)
    assert result.verdict == "allow" and result.reply == "Paris."
    assert called["complete"] == 0
    assert len(client.calls) == 1
    assert client.calls[0][0].startswith("https://api.groq.com")
    assert (tmp_path / "witness.jsonl").read_text(encoding="utf-8").count('"started"') == 1
