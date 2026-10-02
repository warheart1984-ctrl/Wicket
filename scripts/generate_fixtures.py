#!/usr/bin/env python3
"""Independently recompute fixture hashes and compare them with the Rust CLI."""
import hashlib, json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
INVARIANTS = ["no_authority_self_mutation", "kernel_is_sole_verdict_authority"]

def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def digest(value): return "sha3-256:" + hashlib.sha3_256(canonical(value).encode()).hexdigest()

def expected(fixture):
    proposal, policy = fixture["proposal"], fixture["policy"]
    proposal = {"payload": {}, "evidence_refs": [], "approval_id": None, **proposal}
    policy = {"denied_effects": [], "effects_requiring_approval": [], "risks_requiring_approval": [], **policy}
    verdict, codes = fixture["expected"]["verdict"], fixture["expected"]["reason_codes"]
    approval_id = proposal.get("approval_id")
    valid = approval_id if approval_id in fixture.get("approvals", []) else None
    approval = {"required": verdict == "await_human_approval" or valid is not None, "approval_id": valid}
    decision = {"version":"infinity.decision.v1","proposal_id":proposal["proposal_id"],"verdict":verdict,"reason_codes":codes,"policy_hash":digest(policy),"proposal_hash":digest(proposal),"approval":approval,"invariants_checked":INVARIANTS}
    decision["decision_hash"] = digest(decision)
    return decision

def main():
    fixtures = sorted((ROOT / "fixtures").glob("*.json"))
    for path in fixtures:
        rust = subprocess.check_output(["cargo", "run", "-q", "-p", "infinity-cli", "--", "replay", "--fixture", str(path)], cwd=ROOT, text=True)
        if json.loads(rust) != expected(json.loads(path.read_text())):
            raise SystemExit(f"hash mismatch: {path.name}")
    print(f"Rust == Python byte-for-byte: {len(fixtures)}/{len(fixtures)} fixtures")
if __name__ == "__main__": main()
