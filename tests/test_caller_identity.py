"""Caller identity and authority. Nothing in these attacks is sent, and each leaves a record.

The signer and the witness run in this process. That is caller A versus caller B, not two
operating-system accounts. It does not prove observed effect, and it does not prove the clock.
"""

from __future__ import annotations

import json

import pytest

from runtime.call_binding import derive
from runtime.caller_token import ed25519_verify, public_from_seed, sign
from runtime.kernel import Kernel
from tests.test_execution_binding import (
    BINARY,
    CALLER,
    OTHER,
    VERIFIER,
    World,
    https_call,
    proposal,
)

# RFC 8032 section 7.1, test 1. Empty message.
_RFC_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
_RFC_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
_RFC_SIG = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def test_ed25519_signs_the_rfc_vector():
    assert public_from_seed(_RFC_SEED) == _RFC_PUBLIC
    signature = sign(_RFC_SEED, b"")
    assert signature == _RFC_SIG
    assert ed25519_verify(_RFC_PUBLIC, b"", signature)
    assert not ed25519_verify(_RFC_PUBLIC, b"x", signature)


def _record(world):
    return world.witness_log.read_text(encoding="utf-8") if world.witness_log.is_file() else ""


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_caller_a_cannot_use_caller_b_allow(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/shared")
    allow_b = world.allow(call, who=OTHER)
    assert allow_b["decision"]["verdict"] == "allow"
    assert allow_b["receipt"]["caller_id"] == OTHER
    witness = world.witness()
    refused = world.run(witness, call, allow_b["receipt"]["receipt_id"], who=CALLER)
    assert refused.dispatched is False and refused.divergence == "mismatch"
    assert world.seen == []
    assert '"divergence":"mismatch"' in _record(world)


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_forged_token_sends_nothing(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/forge")
    receipt = world.allow(call)["receipt"]
    token = world.authorization(call)
    forged = token[:-1] + ("A" if token[-1] != "A" else "B")
    refused = world.witness().execute(call, receipt["receipt_id"], authorization=forged)
    assert refused.dispatched is False and refused.divergence == "IDENTITY_UNVERIFIED"
    assert world.seen == []
    assert "IDENTITY_UNVERIFIED" in _record(world)


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_replayed_token_sends_nothing(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/replay-token")
    receipt = world.allow(call)["receipt"]
    token = world.authorization(call, jti="token-once")
    witness = world.witness()
    first = witness.execute(call, receipt["receipt_id"], authorization=token)
    second = witness.execute(call, receipt["receipt_id"], authorization=token)
    assert first.dispatched is True and first.status == "completed"
    assert second.dispatched is False and second.divergence == "IDENTITY_UNVERIFIED"
    assert world.seen == ["GET"]
    assert "IDENTITY_UNVERIFIED" in _record(world)


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_token_replay_after_a_new_witness_is_still_refused(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/restart")
    receipt = world.allow(call)["receipt"]
    token = world.authorization(call, jti="survives-restart")
    first = world.witness()
    assert first.execute(call, receipt["receipt_id"], authorization=token).status == "completed"
    restarted = world.witness()
    assert restarted is not first
    replayed = restarted.execute(call, receipt["receipt_id"], authorization=token)
    assert replayed.dispatched is False and replayed.divergence == "IDENTITY_UNVERIFIED"
    assert world.seen == ["GET"]
    assert (world.witness_log.parent / (world.witness_log.name + ".token-ids")).is_file()
    assert "IDENTITY_UNVERIFIED" in _record(world)


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_valid_token_beyond_its_grant_is_authority_denied(tmp_path):
    world = World(tmp_path)
    policy = json.loads(world.policy.read_text(encoding="utf-8"))
    policy["callers"][CALLER]["effects"] = ["read"]
    policy["callers"][CALLER]["target_prefixes"] = ["http://example.test:443/only"]
    world.policy.write_text(json.dumps(policy), encoding="utf-8")
    post = https_call("POST", "example.test", 443, "/only", body="x")
    out = world.service.handle({
        "op": "evaluate",
        "proposal": proposal("write", "http://example.test:443/only"),
        "call": post,
        "authorization": world.authorization(post),
    })
    assert out["decision"]["verdict"] == "deny"
    assert out["decision"]["reason_codes"] == ["AUTHORITY_DENIED"]
    refused = world.witness().execute(
        post, out["receipt"]["receipt_id"], authorization=world.authorization(post, jti="beyond"),
    )
    assert refused.dispatched is False and refused.divergence == "AUTHORITY_DENIED"
    assert world.seen == []
    assert "AUTHORITY_DENIED" in _record(world)


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_stated_risk_the_grant_does_not_have_is_authority_denied(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/risk")
    body = proposal("read", "http://example.test:443/risk")
    body["risk"] = "high"
    out = world.service.handle({
        "op": "evaluate", "proposal": body, "call": call,
        "authorization": world.authorization(call),
    })
    assert out["decision"]["verdict"] == "deny"
    assert out["decision"]["reason_codes"] == ["AUTHORITY_DENIED"]
    assert world.seen == []


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_garbage_authorization_header_sends_nothing(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/garbage")
    receipt = world.allow(call)["receipt"]
    witness = world.witness()
    for header in ("Bearer secret", "Wicket !!!", "Wicket"):
        refused = witness.execute(call, receipt["receipt_id"], authorization=header)
        assert refused.dispatched is False and refused.divergence == "IDENTITY_UNVERIFIED"
    assert world.seen == []
    assert _record(world).count("IDENTITY_UNVERIFIED") == 3


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_no_header_is_identity_unverified_when_the_opt_out_is_off(tmp_path, monkeypatch):
    monkeypatch.delenv("WICKET_ALLOW_DIRECT_CALLS", raising=False)
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/no-header")
    receipt = world.allow(call)["receipt"]
    refused = world.witness().execute(call, receipt["receipt_id"], authorization=None)
    assert refused.dispatched is False and refused.divergence == "IDENTITY_UNVERIFIED"
    assert world.seen == []
    assert "IDENTITY_UNVERIFIED" in _record(world)


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_key_that_claims_another_caller_is_refused(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/claim")
    receipt = world.allow(call)["receipt"]
    witness = world.witness()
    claims_b_digest = world.authorization(
        call, who=CALLER, claimed=OTHER, call_digest=derive(call, OTHER).call_digest, jti="claim-b",
    )
    claims_b_but_signed_over_a = world.authorization(
        call, who=CALLER, claimed=OTHER, call_digest=derive(call, CALLER).call_digest, jti="claim-a",
    )
    first = witness.execute(call, receipt["receipt_id"], authorization=claims_b_digest)
    second = witness.execute(call, receipt["receipt_id"], authorization=claims_b_but_signed_over_a)
    assert first.dispatched is False and first.divergence == "IDENTITY_UNVERIFIED"
    assert second.dispatched is False and second.divergence == "IDENTITY_UNVERIFIED"
    assert world.seen == []
    assert _record(world).count("IDENTITY_UNVERIFIED") == 2


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_direct_infinityctl_evaluate_does_not_verify_a_token_and_the_witness_will_not_send_it(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/direct")
    digest = derive(call, CALLER).call_digest
    bare = proposal("read", derive(call, CALLER).target)
    bare["call_digest"] = digest
    bare["caller_id"] = CALLER
    # No callers map: the kernel allows this description and does not look at a token.
    open_policy = tmp_path / "open.json"
    open_policy.write_text(json.dumps({
        "version": "infinity.policy.v1", "policy_id": "policy-test-v1",
    }), encoding="utf-8")
    bare["policy_version"] = "policy-test-v1"
    log = tmp_path / "direct.jsonl"
    Kernel(open_policy, log, binary=BINARY, sign_key=world.signer_key).evaluate(bare)
    receipt = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert receipt["verdict"] == "allow" and receipt["caller_id"] == CALLER
    # The kernel minted this allow with no token. The witness still requires one.
    witness = world.witness()
    witness.receipt_log = log
    refused = witness.execute(call, receipt["receipt_id"], authorization=None)
    assert refused.dispatched is False and refused.divergence == "IDENTITY_UNVERIFIED"
    assert world.seen == []


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_ickverify_fails_an_omitted_or_forged_caller_id(tmp_path):
    import subprocess
    import sys

    world = World(tmp_path)
    call = https_call("GET", "example.test", 80, "/verify-caller")
    allowed = world.allow(call)
    receipt_id = allowed["receipt"]["receipt_id"]
    assert allowed["receipt"]["caller_id"] == CALLER
    assert world.witness().execute(
        call, receipt_id, authorization=world.authorization(call),
    ).status == "completed"
    bind = tmp_path / "call.json"
    bind.write_text(json.dumps({
        "receipt_id": receipt_id, "call": call, "caller_id": OTHER,
    }), encoding="utf-8")
    forged = subprocess.run(
        [sys.executable, str(VERIFIER), str(world.log), "--call", str(bind),
         "--witness-log", str(world.witness_log), "--witness-keys", str(world.witness_pub), "--json"],
        capture_output=True, text=True,
    )
    report = json.loads(forged.stdout)
    assert report["ok"] is False
    assert any("forged caller id" in error for error in report["errors"])

    stripped = tmp_path / "stripped.jsonl"
    row = json.loads(world.log.read_text(encoding="utf-8").splitlines()[0])
    row.pop("caller_id")
    stripped.write_text(json.dumps(row) + "\n", encoding="utf-8")
    bind.write_text(json.dumps({"receipt_id": receipt_id, "call": call}), encoding="utf-8")
    omitted = subprocess.run(
        [sys.executable, str(VERIFIER), str(stripped), "--call", str(bind), "--json"],
        capture_output=True, text=True,
    )
    omitted_report = json.loads(omitted.stdout)
    assert any("omitted caller id" in error for error in omitted_report["errors"])


@pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")
def test_a_started_entry_records_the_verified_caller_id(tmp_path):
    world = World(tmp_path)
    call = https_call("GET", "example.test", 443, "/started")
    receipt = world.allow(call)["receipt"]
    done = world.run(world.witness(), call, receipt["receipt_id"])
    assert done.status == "completed"
    started = done.entries[0]
    assert started["status"] == "started" and started["caller_id"] == CALLER
    assert receipt["caller_id"] == CALLER
