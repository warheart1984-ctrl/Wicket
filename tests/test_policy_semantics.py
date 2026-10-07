"""What a policy can and cannot do, and what `actor` does not do, pinned against the real kernel."""

import json
import subprocess
from pathlib import Path

import pytest

from runtime.kernel import KernelError, find_binary

try:
    BINARY = find_binary()
except KernelError:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)

CONTRACTS = Path(__file__).resolve().parent.parent / "contracts"


def decide(tmp_path, policy_fields=None, **proposal_fields):
    proposal = {"version": "infinity.proposal.v1", "proposal_id": "p", "actor": {"kind": "agent", "id": "nova-shell"},
                "action": "act", "target": "t", "effect": "read", "risk": "low", "requires_human_approval": False,
                "policy_version": "policy-x", "payload": {}, "evidence_refs": [], **proposal_fields}
    policy = {"version": "infinity.policy.v1", "policy_id": "policy-x", **(policy_fields or {})}
    (tmp_path / "proposal.json").write_text(json.dumps(proposal))
    (tmp_path / "policy.json").write_text(json.dumps(policy))
    done = subprocess.run([BINARY, "evaluate", "--proposal", str(tmp_path / "proposal.json"),
                           "--policy", str(tmp_path / "policy.json")], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)["decision"]


@pytest.mark.parametrize("effect", ["deploy", "authority_change", "audit_delete"])
def test_the_kernel_always_denies_these_effects_whatever_the_policy_says(tmp_path, effect):
    for policy in ({}, {"denied_effects": []}, {"effects_requiring_approval": [], "risks_requiring_approval": []}):
        d = decide(tmp_path, policy, effect=effect)
        assert d["verdict"] == "deny" and d["reason_codes"] == ["FORBIDDEN_EFFECT"], (effect, policy, d)
    # not even a pending human approval can unlock them
    d = decide(tmp_path, {}, effect=effect, requires_human_approval=True, approval_id="approval-1")
    assert d["verdict"] == "deny" and d["reason_codes"] == ["FORBIDDEN_EFFECT"]


def test_an_empty_policy_allows_read_and_write_and_nothing_else(tmp_path):
    for effect in ("read", "write"):
        assert decide(tmp_path, {}, effect=effect)["verdict"] == "allow"
    for effect in ("deploy", "authority_change", "audit_delete", "something_else", ""):
        assert decide(tmp_path, {}, effect=effect)["verdict"] == "deny", effect
    assert decide(tmp_path, {}, effect="something_else")["reason_codes"] == ["UNKNOWN_EFFECT"]
    assert decide(tmp_path, {}, risk="astronomical")["reason_codes"] == ["UNKNOWN_RISK"]


def test_a_policy_can_only_restrict(tmp_path):
    assert decide(tmp_path, {"denied_effects": ["write"]}, effect="write")["verdict"] == "deny"
    assert decide(tmp_path, {"effects_requiring_approval": ["write"]}, effect="write")["verdict"] == "await_human_approval"
    assert decide(tmp_path, {"risks_requiring_approval": ["high"]}, risk="high")["verdict"] == "await_human_approval"
    # adding forbidden effects to the "approval" list or listing them anywhere does not unlock them
    d = decide(tmp_path, {"effects_requiring_approval": ["deploy"], "denied_effects": []}, effect="deploy")
    assert d["verdict"] == "deny" and d["reason_codes"] == ["FORBIDDEN_EFFECT"]
    # the three lists still cannot say "allow". callers is a separate grant, checked below.
    properties = set(json.loads((CONTRACTS / "policy.v1.json").read_text())["properties"])
    assert properties == {
        "version", "policy_id", "denied_effects", "effects_requiring_approval",
        "risks_requiring_approval", "callers",
    }


def test_a_callers_map_is_a_grant_and_its_absence_leaves_the_old_behavior(tmp_path):
    grant = {"effects": ["read"], "target_prefixes": ["demo"], "risk": "low", "action": "act"}
    assert decide(tmp_path, {"callers": {"alice": grant}})["reason_codes"] == ["AUTHORITY_DENIED"]
    assert decide(tmp_path, {"callers": {"alice": grant}}, caller_id="bob", target="demo")["reason_codes"] == ["AUTHORITY_DENIED"]
    assert decide(tmp_path, {"callers": {"alice": grant}}, caller_id="alice", target="other")["reason_codes"] == ["AUTHORITY_DENIED"]
    assert decide(tmp_path, {"callers": {"alice": grant}}, caller_id="alice", target="demo", effect="write")["reason_codes"] == ["AUTHORITY_DENIED"]
    assert decide(tmp_path, {"callers": {"alice": grant}}, caller_id="alice", target="demo", risk="high")["reason_codes"] == ["AUTHORITY_DENIED"]
    allowed = decide(tmp_path, {"callers": {"alice": grant}}, caller_id="alice", target="demo")
    assert allowed["verdict"] == "allow"
    # no callers map: a caller_id does not change the verdict. infinityctl does not verify a token.
    assert decide(tmp_path, {}, caller_id="alice")["verdict"] == "allow"


def test_the_actor_is_recorded_and_hashed_but_changes_no_decision(tmp_path):
    actors = [{"kind": "agent", "id": "nova-shell"}, {"kind": "human", "id": "alice"},
              {"kind": "agent", "id": "root"}, {"kind": "", "id": ""}]
    policies = [{}, {"denied_effects": ["write"]}, {"effects_requiring_approval": ["read"]}]
    for policy in policies:
        for effect in ("read", "write"):
            results = [decide(tmp_path, policy, actor=a, effect=effect) for a in actors]
            assert len({(r["verdict"], tuple(r["reason_codes"])) for r in results}) == 1, (policy, effect, results)
            assert len({r["proposal_hash"] for r in results}) == len(actors)  # but each actor is part of the hash


def test_the_documents_say_these_things():
    root = Path(__file__).resolve().parent.parent
    policy_text = json.loads((CONTRACTS / "policy.v1.json").read_text())["description"]
    assert "only RESTRICT" in policy_text and "FORBIDDEN_EFFECT" in policy_text and "not 'wide open'" in policy_text
    actor_text = json.loads((CONTRACTS / "proposal.v1.json").read_text())["properties"]["actor"]["description"]
    assert "never reads it" in actor_text and "not authenticated" in actor_text
    threat = (root / "THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "The `actor` field is not checked" in threat
    assert "Whoever can write the caller key file can add callers" in threat
    assert "The three lists can only restrict" in threat
    assert "What a policy can and cannot say" in (root / "README.md").read_text(encoding="utf-8")
