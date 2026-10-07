import json
import os
from pathlib import Path

import pytest

from runtime.chat import run_turn
from runtime.kernel import DEFAULT_POLICY, Kernel, KernelError, find_binary
from runtime.providers import ProviderError, complete

try:
    find_binary()
except KernelError:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)


class FakeClient:
    def __init__(self, text="Paris."):
        self.text, self.calls = text, []

    def __call__(self, url, payload, headers):
        self.calls.append((url, payload, headers))
        return {"choices": [{"message": {"content": self.text}, "finish_reason": "stop"}]}


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    for name in ("GROQ_API_KEY", "NVIDIA_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.setenv(name, "test-key")
    # Receipt-log tests need a completed provider call. This is the explicit local-dev
    # opt-out, not the default: tests/test_runtime_witness.py leaves it unset.
    monkeypatch.setenv("WICKET_ALLOW_DIRECT_CALLS", "1")


def test_allowed_turn_calls_provider_and_logs_receipt(tmp_path):
    log, client = tmp_path / "r.jsonl", FakeClient()
    result = run_turn("Capital of France?", "groq", Kernel(receipt_log=log), client=client)
    assert result.verdict == "allow" and result.reply == "Paris."
    assert len(client.calls) == 1
    assert json.loads(log.read_text().splitlines()[0])["receipt_id"] == result.receipt_id


def test_denied_turn_never_calls_provider(tmp_path):
    policy = tmp_path / "deny.json"
    policy.write_text(json.dumps({
        "version": "infinity.policy.v1", "policy_id": "policy-deny-v1",
        "denied_effects": ["read"], "effects_requiring_approval": [],
    }))
    client = FakeClient()
    result = run_turn("hi", "groq", Kernel(policy=policy), client=client)
    assert result.verdict != "allow" and result.reply is None
    assert client.calls == []


def test_message_text_is_not_sent_to_the_kernel(tmp_path):
    log = tmp_path / "r.jsonl"
    run_turn("my secret message", "nvidia", Kernel(receipt_log=log), client=FakeClient())
    assert "my secret" not in log.read_text()


def test_token_floor_and_headers():
    client = FakeClient()
    complete("groq", [{"role": "user", "content": "x"}], max_tokens=32, client=client)
    _, payload, headers = client.calls[0]
    assert payload["max_tokens"] == 256
    assert payload["reasoning_effort"] == "low"
    assert headers["User-Agent"].startswith("infinity-core")


def test_nvidia_turns_thinking_off():
    client = FakeClient()
    complete("nvidia", [{"role": "user", "content": "x"}], client=client)
    assert client.calls[0][1]["chat_template_kwargs"] == {"enable_thinking": False}


def test_missing_key_and_empty_reply_raise(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY")
    with pytest.raises(ProviderError, match="GROQ_API_KEY"):
        complete("groq", [], client=FakeClient())
    with pytest.raises(ProviderError, match="no text"):
        complete("nvidia", [], client=FakeClient(text=""))


def test_receipts_are_chained_and_verifiable(tmp_path):
    log, client = tmp_path / "r.jsonl", FakeClient()
    kernel = Kernel(receipt_log=log)
    for text in ("one", "two", "three"):
        run_turn(text, "groq", kernel, client=client)
    receipts = [json.loads(line) for line in log.read_text().splitlines()]
    assert receipts[0]["previous_receipt_hash"] is None
    assert receipts[1]["previous_receipt_hash"] == receipts[0]["receipt_id"]
    assert receipts[2]["previous_receipt_hash"] == receipts[1]["receipt_id"]
    assert kernel.verify() is True


def test_tampering_is_detected_and_blocks_further_turns(tmp_path):
    log, client = tmp_path / "r.jsonl", FakeClient()
    kernel = Kernel(receipt_log=log)
    for text in ("one", "two"):
        run_turn(text, "groq", kernel, client=client)
    lines = log.read_text().splitlines()
    log.write_text(lines[0].replace('"allow"', '"deny"') + "\n" + lines[1] + "\n")
    assert kernel.verify() is False
    with pytest.raises(KernelError, match="failed verification"):
        run_turn("three", "groq", kernel, client=client)
    assert len(client.calls) == 2  # the blocked turn never reached the provider


def test_anchor_catches_deleted_tail_that_the_chain_alone_misses(tmp_path):
    log, anchor, client = tmp_path / "r.jsonl", tmp_path / "anchors" / "a.jsonl", FakeClient()
    kernel = Kernel(receipt_log=log, anchor=anchor)
    for text in ("one", "two", "three"):
        run_turn(text, "groq", kernel, client=client)
    assert kernel.verify() is True
    log.write_text("\n".join(log.read_text().splitlines()[:-1]) + "\n")  # drop only the last entry
    assert Kernel(receipt_log=log).verify() is True  # chain only: fooled
    assert kernel.verify() is False  # chain + anchor: caught
    with pytest.raises(KernelError, match="deleted"):
        run_turn("four", "groq", kernel, client=client)
    assert len(client.calls) == 3  # the refused turn never reached the provider


def test_anchor_requires_a_log():
    with pytest.raises(KernelError, match="anchor needs"):
        Kernel(anchor=Path("a.jsonl"))


# --- outcomes: what the model call did, recorded in the same chain ---------------------------

from runtime.kernel import sha256_text  # noqa: E402


def entries_of(log):
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_a_turn_records_its_outcome_in_the_same_chain(tmp_path):
    log, anchor = tmp_path / "r.jsonl", tmp_path / "safe" / "a.jsonl"
    kernel = Kernel(receipt_log=log, anchor=anchor)
    result = run_turn("my private question", "groq", kernel, client=FakeClient("the private answer"))
    decision, outcome = entries_of(log)
    assert decision["verdict"] == "allow" and decision["version"] == "infinity.receipt.v2"
    assert outcome["decision_receipt_id"] == decision["receipt_id"] == result.receipt_id
    assert outcome["status"] == "completed" and result.outcome_receipt_id == outcome["receipt_id"]
    assert outcome["response_sha256"] == sha256_text("the private answer")
    assert "private" not in log.read_text() + anchor.read_text()
    assert kernel.verify() is True


def test_receipts_carry_a_real_utc_time(tmp_path):
    import re

    log = tmp_path / "r.jsonl"
    run_turn("hi", "groq", Kernel(receipt_log=log), client=FakeClient())
    for entry in entries_of(log):
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", entry["issued_at"]), entry["issued_at"]


def test_a_failing_provider_is_recorded_as_failed_and_the_error_survives(tmp_path):
    class Failing:
        def __call__(self, url, payload, headers):
            raise ProviderError("nope")

    log = tmp_path / "r.jsonl"
    with pytest.raises(ProviderError, match="nope"):
        run_turn("hi", "groq", Kernel(receipt_log=log), client=Failing())
    assert entries_of(log)[1]["status"] == "failed" and entries_of(log)[1]["response_sha256"] is None


@pytest.mark.skipif(os.name != "posix", reason="the stand-in binary is a #! script, which Windows cannot run")
def test_if_the_outcome_cannot_be_recorded_the_reply_is_withheld(tmp_path):
    import sys

    from runtime.kernel import find_binary

    real = find_binary()
    fake = tmp_path / "infinityctl"
    fake.write_text(f"#!{sys.executable}\nimport os, sys\n"
                    "if sys.argv[1] == 'record-outcome':\n    sys.stderr.write('disk full'); sys.exit(1)\n"
                    f"os.execv({real!r}, [{real!r}] + sys.argv[1:])\n")
    fake.chmod(0o755)
    kernel = Kernel(receipt_log=tmp_path / "r.jsonl", binary=str(fake))
    with pytest.raises(KernelError, match="disk full"):
        run_turn("hi", "groq", kernel, client=FakeClient("an answer nobody sees"))


def test_without_a_log_there_is_no_outcome_and_nothing_breaks():
    result = run_turn("hi", "groq", Kernel(), client=FakeClient())
    assert result.reply == "Paris." and result.outcome_receipt_id is None


def test_editing_an_outcome_is_detected(tmp_path):
    log = tmp_path / "r.jsonl"
    kernel = Kernel(receipt_log=log)
    run_turn("hi", "groq", kernel, client=FakeClient("honest answer"))
    assert kernel.verify() is True
    lines = log.read_text().splitlines()
    outcome = json.loads(lines[1])
    outcome["response_sha256"] = sha256_text("a different answer")
    log.write_text(lines[0] + "\n" + json.dumps(outcome) + "\n")
    assert kernel.verify() is False
