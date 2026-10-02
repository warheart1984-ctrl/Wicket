"""The JSON contracts must describe what the kernel really writes (skipped without `jsonschema`)."""

import copy
import json
from pathlib import Path

import pytest

from runtime.chat import run_turn
from runtime.kernel import Kernel, KernelError, find_binary

jsonschema = pytest.importorskip("jsonschema")

try:
    find_binary()
except KernelError:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"


def schema(name):
    return json.loads((CONTRACTS / name).read_text())


class FakeClient:
    def __call__(self, url, payload, headers):
        return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}


@pytest.fixture
def log_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k")
    log = tmp_path / "r.jsonl"
    kernel = Kernel(receipt_log=log)
    run_turn("hi", "groq", kernel, client=FakeClient())
    run_turn("hi again", "groq", kernel, client=FakeClient())
    return [json.loads(line) for line in log.read_text().splitlines()]


def test_the_schemas_are_valid_schemas():
    for name in ("receipt.v2.json", "outcome.v1.json"):
        jsonschema.Draft202012Validator.check_schema(schema(name))


def test_real_receipts_and_outcomes_match_their_contracts(log_entries):
    decisions = [e for e in log_entries if "verdict" in e]
    outcomes = [e for e in log_entries if "decision_receipt_id" in e]
    assert len(decisions) == 2 and len(outcomes) == 2
    for entry in decisions:
        jsonschema.validate(entry, schema("receipt.v2.json"))
    for entry in outcomes:
        jsonschema.validate(entry, schema("outcome.v1.json"))


@pytest.mark.parametrize("name, key, bad", [
    ("receipt.v2.json", "version", "infinity.receipt.v1"),
    ("receipt.v2.json", "verdict", "maybe"),
    ("receipt.v2.json", "proposal_hash", "sha3-256:short"),
    ("receipt.v2.json", "receipt_id", "receipt:md5:abc"),
    ("outcome.v1.json", "status", "unknown"),
    ("outcome.v1.json", "response_sha256", "sha256:ABC"),
    ("outcome.v1.json", "decision_receipt_id", "not-a-receipt"),
    ("outcome.v1.json", "version", "infinity.outcome.v2"),
])
def test_the_contracts_reject_bad_values(log_entries, name, key, bad):
    entry = copy.deepcopy(next(e for e in log_entries if ("verdict" in e) == name.startswith("receipt")))
    entry[key] = bad
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(entry, schema(name))


def test_the_contracts_reject_unknown_and_missing_fields(log_entries):
    receipt = next(e for e in log_entries if "verdict" in e)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**receipt, "sneaky": 1}, schema("receipt.v2.json"))
    del receipt["issued_at"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(receipt, schema("receipt.v2.json"))


# --- signed entries and anchor records ---------------------------------------------------------

import subprocess  # noqa: E402


def test_signed_entries_and_anchor_records_match_their_contracts(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k")
    binary = find_binary()
    private, public = tmp_path / "k.priv", tmp_path / "k.pub"
    subprocess.run([binary, "keygen", "--out", str(private), "--public-out", str(public)], check=True,
                   capture_output=True)
    log, anchor = tmp_path / "r.jsonl", tmp_path / "a.jsonl"
    run_turn("hi", "groq", Kernel(receipt_log=log, anchor=anchor, sign_key=private), client=FakeClient())
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    anchors = [json.loads(line) for line in anchor.read_text().splitlines()]
    assert len(entries) == 2 and len(anchors) == 2
    for entry in entries:
        assert "signature" in entry and "key_id" in entry
        jsonschema.validate(entry, schema("receipt.v2.json" if "verdict" in entry else "outcome.v1.json"))
    for record in anchors:
        assert "signature" in record
        jsonschema.validate(record, schema("anchor.v1.json"))


@pytest.mark.parametrize("name, field, bad", [
    ("receipt.v2.json", "signature", "ed25519:short"),
    ("receipt.v2.json", "signature", "rsa:" + "0" * 128),
    ("receipt.v2.json", "key_id", "key:md5:abc"),
    ("anchor.v1.json", "head_receipt_id", "not-a-receipt"),
    ("anchor.v1.json", "count", 0),
])
def test_the_signature_and_anchor_contracts_reject_bad_values(log_entries, name, field, bad):
    base = ({"version": "infinity.anchor.v1", "count": 1, "head_receipt_id": log_entries[0]["receipt_id"]}
            if name.startswith("anchor") else copy.deepcopy(log_entries[0]))
    base[field] = bad
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(base, schema(name))
