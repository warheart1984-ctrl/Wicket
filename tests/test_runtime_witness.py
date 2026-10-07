"""run_turn sends a known-shape provider call only through the witness when one is attached."""

from __future__ import annotations

import json
import pytest

from runtime.__main__ import main
from runtime.call_binding import derive
from runtime.chat import direct_calls_allowed, run_turn
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
    caller_priv, caller_pub = keygen(tmp_path, "caller")
    caller_keys = tmp_path / "caller-keys.json"
    caller_keys.write_text(json.dumps({
        "version": "wicket.caller-keys.v1",
        "keys": [{
            "caller_id": "runtime-caller",
            "public_key": caller_pub.read_text(encoding="utf-8").strip(),
        }],
    }))
    monkeypatch.setenv("WICKET_CALLER_KEY", str(caller_priv))
    monkeypatch.setenv("WICKET_CALLER_KEYS", str(caller_keys))
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "version": "infinity.policy.v1",
        "policy_id": "policy-open-v1",
        "denied_effects": [],
        "effects_requiring_approval": [],
        "callers": {
            "runtime-caller": {
                "effects": ["read", "write"],
                "target_prefixes": ["https://", "http://"],
                "risk": "low",
                "action": "chat_completion",
            },
        },
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
        }, bound.caller_id).call_digest
        payload = json.loads(bound.body.decode("utf-8"))
        return json.dumps(client(bound.url, payload, dict(bound.headers))).encode("utf-8")

    witness = Witness(
        binary=BINARY,
        receipt_log=log,
        witness_log=tmp_path / "witness.jsonl",
        witness_key=witness_priv,
        receipt_trusted_keys=signer_pub,
        dispatch=dispatch,
        caller_keys=caller_keys,
        policy=policy,
    )
    result = run_turn("Capital of France?", "groq", kernel, client=client, witness=witness)
    assert result.verdict == "allow" and result.reply == "Paris."
    assert called["complete"] == 0
    assert len(client.calls) == 1
    assert client.calls[0][0].startswith("https://api.groq.com")
    assert (tmp_path / "witness.jsonl").read_text(encoding="utf-8").count('"started"') == 1


def _open_kernel(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({
        "version": "infinity.policy.v1",
        "policy_id": "policy-open-v1",
        "denied_effects": [],
        "effects_requiring_approval": [],
    }))
    return Kernel(policy, tmp_path / "receipts.jsonl", binary=BINARY)


def test_run_turn_sends_nothing_when_no_witness_is_configured(tmp_path, monkeypatch):
    monkeypatch.delenv("WICKET_ALLOW_DIRECT_CALLS", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    client = FakeClient()

    def forbid(*_args, **_kwargs):
        raise AssertionError("run_turn called the provider client directly")

    monkeypatch.setattr("runtime.chat.complete", forbid)
    result = run_turn("Capital of France?", "groq", _open_kernel(tmp_path), client=client)
    assert result.verdict == "allow" and result.reply is None
    assert client.calls == []
    text = (tmp_path / "receipts.jsonl").read_text(encoding="utf-8")
    assert text.count('"allow"') == 1 and '"status"' not in text


def test_runtime_module_sends_nothing_when_no_witness_is_configured(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("WICKET_ALLOW_DIRECT_CALLS", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    called = []

    def forbid(*_args, **_kwargs):
        called.append("complete")
        raise AssertionError("python -m runtime called the provider")

    monkeypatch.setattr("runtime.chat.complete", forbid)
    code = main([
        "Capital of France?",
        "--provider", "groq",
        "--receipts", str(tmp_path / "receipts.jsonl"),
    ])
    captured = capsys.readouterr()
    assert code == 1
    assert called == []
    assert "no witness is configured; the provider was not called" in captured.err
    assert "WARNING: WICKET_ALLOW_DIRECT_CALLS" not in captured.err


def test_the_direct_call_opt_out_is_off_by_default(monkeypatch):
    monkeypatch.delenv("WICKET_ALLOW_DIRECT_CALLS", raising=False)
    assert direct_calls_allowed() is False
    for value in ("", "0", "true", "yes", "on"):
        monkeypatch.setenv("WICKET_ALLOW_DIRECT_CALLS", value)
        assert direct_calls_allowed() is False


def test_the_direct_call_opt_out_sends_and_warns(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WICKET_ALLOW_DIRECT_CALLS", "1")
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    client = FakeClient()
    first = run_turn("Capital of France?", "groq", _open_kernel(tmp_path), client=client)
    second = run_turn("Again?", "groq", _open_kernel(tmp_path), client=client)
    assert first.reply == "Paris." and second.reply == "Paris."
    assert len(client.calls) == 2
    err = capsys.readouterr().err
    assert err.count("WARNING: WICKET_ALLOW_DIRECT_CALLS=1") == 2
    assert "Local development only" in err and "unsafe" in err
