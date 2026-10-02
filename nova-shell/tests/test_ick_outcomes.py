"""After a model call, Nova writes an outcome entry into the same chained log."""

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from nova.ick import (IckGate, IckGatedProvider, KernelRefusal, OutcomeNotRecorded, _find_binary,
                      gate_action, gate_outcome, sha256_text)

DEMO_POLICY = Path(__file__).resolve().parents[2] / "demo" / "policy.json"

try:
    BINARY = _find_binary(None)
except KernelRefusal:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)

REQUEST = {"messages": [{"role": "user", "content": "my private question"}]}
REPLY = "the private answer"


class Provider:
    model, provider_id = "m", "fake"

    def __init__(self, fail=False):
        self.fail = fail

    def chat_completion(self, governed_request):
        if self.fail:
            raise RuntimeError("provider exploded")
        return {"completion": {"id": "c", "model": "m", "created": 1, "choices": [
            {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": REPLY}}]},
            "receipt": {}}

    def chat_completion_stream(self, governed_request):
        yield {"choices": [{"delta": {"content": "the private "}}]}
        yield {"choices": [{"delta": {"content": "answer"}}]}

    async def invoke(self, messages, **kwargs):
        class Response:
            content = REPLY
        return Response()


@pytest.fixture
def paths(tmp_path):
    return {"log": tmp_path / "log" / "r.jsonl", "anchor": tmp_path / "safe" / "a.jsonl", "dir": tmp_path}


def gated(paths, inner=None, **gate_kwargs):
    gate = IckGate(DEMO_POLICY, log=paths["log"], anchor=paths["anchor"], **gate_kwargs)
    return IckGatedProvider(inner or Provider(), gate)


def entries(paths):
    return [json.loads(line) for line in paths["log"].read_text().splitlines()]


def verify(paths, anchor=True):
    cmd = [BINARY, "verify-log", "--log", str(paths["log"])]
    if anchor:
        cmd += ["--anchor", str(paths["anchor"])]
    done = subprocess.run(cmd, capture_output=True, text=True)
    return done.returncode == 0, (done.stdout + done.stderr).strip()


def test_a_completed_call_is_followed_by_an_outcome_that_names_it(paths):
    result = gated(paths).chat_completion(REQUEST)
    decision, outcome = entries(paths)
    assert decision["verdict"] == "allow" and outcome["decision_receipt_id"] == decision["receipt_id"]
    assert outcome["status"] == "completed"
    assert outcome["response_sha256"] == sha256_text(REPLY)
    assert outcome["request_sha256"] == "sha256:" + hashlib.sha256(json.dumps(["my private question"]).encode()).hexdigest()
    assert result["ick"]["outcome_receipt_id"] == outcome["receipt_id"]
    ok, message = verify(paths)
    assert ok and "1 outcomes, 0 allowed without an outcome" in message, message


def test_neither_the_question_nor_the_answer_is_written_to_the_log(paths):
    gated(paths).chat_completion(REQUEST)
    text = paths["log"].read_text() + paths["anchor"].read_text()
    assert "private" not in text


def test_a_failed_call_is_recorded_as_failed_and_the_real_error_survives(paths):
    with pytest.raises(RuntimeError, match="provider exploded"):
        gated(paths, Provider(fail=True)).chat_completion(REQUEST)
    decision, outcome = entries(paths)
    assert outcome["status"] == "failed" and outcome["response_sha256"] is None
    assert outcome["decision_receipt_id"] == decision["receipt_id"] and verify(paths)[0]


@pytest.mark.skipif(os.name != "posix", reason="the stand-in binary is a #! script, which Windows cannot run")
def test_if_the_outcome_cannot_be_written_the_reply_is_withheld(paths):
    fake = paths["dir"] / "infinityctl"
    fake.write_text(f"#!{sys.executable}\nimport os, sys\n"
                    "if sys.argv[1] == 'record-outcome':\n    sys.stderr.write('disk full'); sys.exit(1)\n"
                    f"os.execv({BINARY!r}, [{BINARY!r}] + sys.argv[1:])\n")
    fake.chmod(0o755)
    provider = gated(paths, binary=str(fake))
    with pytest.raises(OutcomeNotRecorded, match="disk full") as err:
        provider.chat_completion(REQUEST)
    assert err.value.code == "KERNEL_OUTCOME_NOT_RECORDED"
    ok, message = verify(paths)
    assert ok and "1 allowed without an outcome" in message  # the gap is visible, not hidden


def test_an_allow_that_never_finished_shows_up_as_allowed_without_an_outcome(paths):
    IckGate(DEMO_POLICY, log=paths["log"], anchor=paths["anchor"]).check(target="fake:m", governed_request=REQUEST)
    ok, message = verify(paths)
    assert ok and "0 outcomes, 1 allowed without an outcome" in message


def test_without_a_receipt_log_there_is_nothing_to_record_and_nothing_breaks():
    result = IckGatedProvider(Provider(), IckGate(DEMO_POLICY)).chat_completion(REQUEST)
    assert result["ick"]["verdict"] == "allow" and "outcome_receipt_id" not in result["ick"]


def test_a_stream_records_a_hash_of_everything_it_sent(paths):
    chunks = list(gated(paths).chat_completion_stream(REQUEST))
    assert len(chunks) == 2
    _, outcome = entries(paths)
    assert outcome["status"] == "completed" and outcome["response_sha256"] == sha256_text(REPLY)


def test_a_stream_that_is_abandoned_midway_is_recorded_as_failed(paths):
    stream = gated(paths).chat_completion_stream(REQUEST)
    next(stream)
    stream.close()  # the client went away
    _, outcome = entries(paths)
    assert outcome["status"] == "failed" and outcome["response_sha256"] is None


def test_the_async_path_records_an_outcome_too(paths):
    messages = [{"role": "user", "content": "my private question"}]
    response = asyncio.run(gated(paths).invoke(messages))
    assert response.content == REPLY
    assert entries(paths)[1]["response_sha256"] == sha256_text(REPLY)


def test_the_local_model_tool_records_an_outcome(monkeypatch, paths):
    from nova.node.tools import local_model

    monkeypatch.setenv("NOVA_ICK_POLICY", str(DEMO_POLICY))
    monkeypatch.setenv("NOVA_ICK_LOG", str(paths["log"]))
    monkeypatch.setenv("NOVA_ICK_ANCHOR", str(paths["anchor"]))
    monkeypatch.setattr(local_model, "_ollama_generate", lambda *a, **k: "generated code")
    assert local_model.generate("write it") == "generated code"
    assert entries(paths)[1]["response_sha256"] == sha256_text("generated code")

    def boom(*a, **k):
        raise OSError("no server")

    monkeypatch.setattr(local_model, "_ollama_generate", boom)
    monkeypatch.setattr(local_model, "_vllm_generate", boom)
    with pytest.raises(OSError):
        local_model.generate("write it again")
    assert [e.get("status") for e in entries(paths) if "status" in e] == ["completed", "failed"]
    assert verify(paths)[0]


def test_gossip_records_whether_each_send_worked(monkeypatch, paths):
    import urllib.error

    from nova.node import federation

    class Ok:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *e): return False

    def urlopen(request, timeout=None):
        if "down" in request.full_url:
            raise urllib.error.URLError("unreachable")
        return Ok()

    policy = paths["dir"] / "open.json"
    policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-open-v1",
                                  "denied_effects": [], "effects_requiring_approval": []}))
    monkeypatch.setenv("NOVA_ICK_POLICY", str(policy))
    monkeypatch.setenv("NOVA_ICK_LOG", str(paths["log"]))
    monkeypatch.setattr(federation, "load_peers", lambda: [{"peer_id": "a", "endpoint": "http://up.test"},
                                                          {"peer_id": "b", "endpoint": "http://down.test"}])
    monkeypatch.setattr(federation, "signed_gossip_summary", lambda: {"summary": {}, "signature": "s"})
    monkeypatch.setattr(federation.urllib.request, "urlopen", urlopen)
    results = federation.gossip_to_peers()
    assert [r["status"] for r in results] == [200, "error"]
    assert [e["status"] for e in entries(paths) if "status" in e] == ["completed", "failed"]


def test_gate_outcome_is_a_no_op_when_the_gate_is_off(monkeypatch):
    monkeypatch.delenv("NOVA_ICK_POLICY", raising=False)
    assert gate_action(target="t", action="a", effect="read") is None
    assert gate_outcome(None, status="completed") is None


# --- tampering, end to end --------------------------------------------------------------------

@pytest.mark.parametrize("line, field, value", [
    (1, "response_sha256", sha256_text("a different answer")),  # the outcome's reply hash
    (1, "request_sha256", sha256_text("a different question")),
    (1, "status", "failed"),
    (1, "issued_at", "1999-01-01T00:00:00Z"),                    # the outcome's time
    (0, "issued_at", "1999-01-01T00:00:00Z"),                    # the decision's time
    (0, "verdict", "deny"),
])
def test_editing_any_field_of_any_entry_breaks_verification(paths, line, field, value):
    gated(paths).chat_completion(REQUEST)
    original = paths["log"].read_text().splitlines()
    assert verify(paths, anchor=False)[0]
    tampered = json.loads(original[line])
    assert tampered[field] != value
    tampered[field] = value  # change one field, leave the receipt_id as it was
    original[line] = json.dumps(tampered)
    paths["log"].write_text("\n".join(original) + "\n")
    assert verify(paths, anchor=False)[0] is False, f"editing {field} on line {line} went unnoticed"


def test_receipts_carry_the_real_time_not_a_placeholder(paths):
    gated(paths).chat_completion(REQUEST)
    for entry in entries(paths):
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", entry["issued_at"]), entry["issued_at"]
        assert entry["issued_at"] != "demo-provenance"
    first = entries(paths)[0]
    assert first["version"] == "infinity.receipt.v2"


def test_deleting_the_outcome_from_the_end_is_caught_by_the_anchor(paths):
    gated(paths).chat_completion(REQUEST)
    paths["log"].write_text(paths["log"].read_text().splitlines()[0] + "\n")
    assert verify(paths, anchor=False)[0] is True  # the chain alone is fooled
    ok, message = verify(paths)
    assert not ok and "deleted" in message
