"""What Nova sends the kernel must satisfy the proposal contract (skipped without `jsonschema`)."""

import json
from pathlib import Path

import pytest

from nova.ick import build_proposal

jsonschema = pytest.importorskip("jsonschema")

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
PROPOSAL = json.loads((CONTRACTS / "proposal.v1.json").read_text())


@pytest.mark.parametrize("action, effect, risk", [
    ("chat_completion", "read", "low"),
    ("chat_completion", "write", "high"),
    ("gossip_send", "write", "medium"),
    ("node_tool", "read", "critical"),
])
def test_nova_builds_well_formed_proposals(action, effect, risk):
    request = {"messages": [{"role": "user", "content": "hello"}], "temperature": 0.2}
    proposal = build_proposal(policy_id="policy-x-v1", target="groq:model", governed_request=request,
                              action=action, effect=effect, risk=risk)
    jsonschema.validate(proposal, PROPOSAL)
    jsonschema.validate({**proposal, "approval_id": "approval-1"}, PROPOSAL)  # the re-submitted form


def test_nova_builds_a_well_formed_proposal_without_a_request_too():
    jsonschema.validate(build_proposal(policy_id="p", target="t", governed_request=None,
                                       action="chat_completion", effect="read", risk="low"), PROPOSAL)


def test_the_policies_the_tests_use_are_well_formed():
    policy = json.loads((CONTRACTS.parent / "demo" / "policy.json").read_text())
    jsonschema.validate(policy, json.loads((CONTRACTS / "policy.v1.json").read_text()))
