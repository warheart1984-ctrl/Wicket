"""The JSON contracts must describe what the kernel really writes (skipped without `jsonschema`)."""

import copy
import json
import subprocess
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


# --- the proposal, policy and decision contracts ------------------------------------------------

FIXTURES = sorted((CONTRACTS.parent / "fixtures").glob("*.json"))
NOT_WELL_FORMED = {"deny-unknown-contract-version.v1.json"}  # the kernel must deny it; the contract rejects it


def fixture(path):
    return json.loads(path.read_text())


def kernel_answer(tmp_path, policy, proposal, approvals=()):
    """Run the real kernel on a policy and proposal and return {"decision", "receipt"}."""
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    (tmp_path / "proposal.json").write_text(json.dumps(proposal))
    cmd = [find_binary(), "evaluate", "--proposal", str(tmp_path / "proposal.json"),
           "--policy", str(tmp_path / "policy.json")]
    for approval in approvals:
        cmd += ["--approval", approval]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def test_the_new_schemas_are_valid_schemas():
    for name in ("proposal.v1.json", "policy.v1.json", "decision.v1.json"):
        jsonschema.Draft202012Validator.check_schema(schema(name))


def test_every_fixture_and_the_sample_policy_and_the_runtime_builder_match_their_contracts():
    from runtime.chat import build_proposal

    assert FIXTURES
    for path in FIXTURES:
        data = fixture(path)
        if path.name in NOT_WELL_FORMED:
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(data["proposal"], schema("proposal.v1.json"))
        else:
            jsonschema.validate(data["proposal"], schema("proposal.v1.json"))
        jsonschema.validate(data["policy"], schema("policy.v1.json"))
    jsonschema.validate(json.loads((CONTRACTS.parent / "demo" / "policy.json").read_text()), schema("policy.v1.json"))
    jsonschema.validate(build_proposal("groq", "hello", "policy-demo-v1"), schema("proposal.v1.json"))


def test_the_kernels_decisions_match_the_decision_contract_for_every_fixture(tmp_path):
    seen = set()
    for path in FIXTURES:
        data = fixture(path)
        out = kernel_answer(tmp_path, data["policy"], data["proposal"], data.get("approvals", []))
        jsonschema.validate(out["decision"], schema("decision.v1.json"))
        seen.add(out["decision"]["verdict"])
        assert out["decision"]["reason_codes"] == data["expected"]["reason_codes"]
    assert seen == {"allow", "deny", "await_human_approval"}  # all three verdicts were checked


def good_proposal():
    return fixture(next(p for p in FIXTURES if p.name == "allow-safe-read.v1.json"))["proposal"]


@pytest.mark.parametrize("mutate", [
    lambda p: p.update(version="infinity.proposal.v2"),
    lambda p: p.update(sneaky=1),
    lambda p: p.pop("evidence_refs"),
    lambda p: p.pop("payload"),
    lambda p: p.update(payload=[1]),
    lambda p: p.update(payload="text"),
    lambda p: p.update(requires_human_approval="no"),
    lambda p: p.update(requires_human_approval=None),
    lambda p: p.update(proposal_id=""),
    lambda p: p.update(effect=""),
    lambda p: p.update(effect=7),
    lambda p: p.update(risk=None),
    lambda p: p.update(target=["x"]),
    lambda p: p.update(policy_version=""),
    lambda p: p.update(evidence_refs="ref"),
    lambda p: p.update(evidence_refs=[1]),
    lambda p: p.update(actor={"kind": "agent"}),
    lambda p: p.update(actor={"kind": "agent", "id": "x", "extra": 1}),
    lambda p: p.update(actor="nova"),
    lambda p: p.update(approval_id=""),
    lambda p: p.update(approval_id=5),
])
def test_the_proposal_contract_rejects_malformed_proposals(mutate):
    proposal = copy.deepcopy(good_proposal())
    jsonschema.validate(proposal, schema("proposal.v1.json"))
    mutate(proposal)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(proposal, schema("proposal.v1.json"))


def test_a_proposal_may_carry_an_approval_id_or_null():
    for value in ("approval-1", None):
        jsonschema.validate({**good_proposal(), "approval_id": value}, schema("proposal.v1.json"))


@pytest.mark.parametrize("policy", [
    {"version": "infinity.policy.v2", "policy_id": "p"},
    {"version": "infinity.policy.v1"},
    {"version": "infinity.policy.v1", "policy_id": ""},
    {"version": "infinity.policy.v1", "policy_id": 1},
    {"version": "infinity.policy.v1", "policy_id": "p", "denied_effects": "write"},
    {"version": "infinity.policy.v1", "policy_id": "p", "effects_requiring_approval": [1]},
    {"version": "infinity.policy.v1", "policy_id": "p", "risks_requiring_approval": [""]},
    {"version": "infinity.policy.v1", "policy_id": "p", "denied_effect": ["write"]},  # a typo must not pass silently
    {"version": "infinity.policy.v1", "policy_id": "p", "allow_all": True},
])
def test_the_policy_contract_rejects_malformed_policies(policy):
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(policy, schema("policy.v1.json"))


def test_the_policy_contract_accepts_a_minimal_and_a_full_policy():
    jsonschema.validate({"version": "infinity.policy.v1", "policy_id": "p"}, schema("policy.v1.json"))
    jsonschema.validate({"version": "infinity.policy.v1", "policy_id": "p", "denied_effects": ["write"],
                         "effects_requiring_approval": ["read"], "risks_requiring_approval": ["critical"]},
                        schema("policy.v1.json"))


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(version="infinity.decision.v2"),
    lambda d: d.update(verdict="maybe"),
    lambda d: d.update(reason_codes=[]),
    lambda d: d.update(reason_codes=["safe_read"]),
    lambda d: d.update(reason_codes="ALLOWED"),
    lambda d: d.update(policy_hash="sha3-256:short"),
    lambda d: d.update(proposal_hash="sha256:" + "a" * 64),
    lambda d: d.update(decision_hash="sha3-256:" + "A" * 64),
    lambda d: d.update(sneaky=1),
    lambda d: d.pop("approval"),
    lambda d: d.pop("invariants_checked"),
    lambda d: d["approval"].update(required="yes"),
    lambda d: d["approval"].update(extra=1),
    lambda d: d["approval"].pop("approval_id"),
    lambda d: d.update(invariants_checked=[1]),
])
def test_the_decision_contract_rejects_malformed_decisions(tmp_path, mutate):
    decision = kernel_answer(tmp_path, {"version": "infinity.policy.v1", "policy_id": "policy-demo-v1"},
                             good_proposal())["decision"]
    jsonschema.validate(decision, schema("decision.v1.json"))
    mutate(decision)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(decision, schema("decision.v1.json"))


def test_the_decision_contract_describes_every_field_the_kernel_writes(tmp_path):
    decision = kernel_answer(tmp_path, {"version": "infinity.policy.v1", "policy_id": "policy-demo-v1"},
                             good_proposal())["decision"]
    assert set(decision) == set(schema("decision.v1.json")["properties"])  # none missing, none extra
    assert set(schema("decision.v1.json")["required"]) == set(decision)


def real_samples(tmp_path):
    policy = {"version": "infinity.policy.v1", "policy_id": "policy-demo-v1", "denied_effects": ["write"],
              "effects_requiring_approval": ["read"], "risks_requiring_approval": ["critical"]}
    proposal = {**good_proposal(), "approval_id": "approval-1"}
    decision = kernel_answer(tmp_path, {"version": "infinity.policy.v1", "policy_id": "policy-demo-v1"},
                             good_proposal())["decision"]
    return {"proposal.v1.json": proposal, "policy.v1.json": policy, "decision.v1.json": decision}


REQUIRED = {
    "proposal.v1.json": ["version", "proposal_id", "actor", "action", "target", "effect", "risk",
                         "requires_human_approval", "policy_version", "payload", "evidence_refs"],
    "policy.v1.json": ["version", "policy_id"],
    "decision.v1.json": ["version", "proposal_id", "verdict", "reason_codes", "policy_hash", "proposal_hash",
                         "approval", "invariants_checked", "decision_hash"],
}


@pytest.mark.parametrize("name", ["proposal.v1.json", "policy.v1.json", "decision.v1.json"])
def test_every_required_field_is_really_required_and_every_field_has_a_type(tmp_path, name):
    sample = real_samples(tmp_path)[name]
    jsonschema.validate(sample, schema(name))
    for field in REQUIRED[name]:  # fixed here, so a schema that quietly drops one is caught
        broken = {k: v for k, v in sample.items() if k != field}
        with pytest.raises(jsonschema.ValidationError, match=field):
            jsonschema.validate(broken, schema(name))
    for field in sample:
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({**sample, field: 12345}, schema(name))  # no field accepts a bare number


@pytest.mark.parametrize("field", ["proposal_id", "action", "target", "effect", "risk", "policy_version"])
def test_proposal_text_fields_cannot_be_empty(tmp_path, field):
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({**good_proposal(), field: ""}, schema("proposal.v1.json"))


def test_actor_fields_cannot_be_empty():
    for field in ("kind", "id"):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({**good_proposal(), "actor": {"kind": "a", "id": "b", field: ""}},
                                schema("proposal.v1.json"))
