"""Signed receipts, outcomes and anchor records, tested against the real kernel binary."""

import hashlib
import json
import os
import subprocess

import pytest

from runtime import anchor_git
from runtime.chat import run_turn
from runtime.kernel import Kernel, KernelError, find_binary

try:
    BINARY = find_binary()
except KernelError:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)


class FakeClient:
    def __init__(self):
        self.calls = 0

    def __call__(self, url, payload, headers):
        self.calls += 1
        return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.delenv("INFINITY_SIGN_KEY", raising=False)


def make_key(directory, name="key"):
    private, public = directory / f"{name}.priv", directory / f"{name}.pub"
    subprocess.run([BINARY, "keygen", "--out", str(private), "--public-out", str(public)],
                   check=True, capture_output=True)
    return private, public


def lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def write(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


@pytest.fixture
def signed(tmp_path):
    """Three signed turns: six log entries, six anchor records, all signed with one key."""
    private, public = make_key(tmp_path)
    log, anchor = tmp_path / "log" / "r.jsonl", tmp_path / "safe" / "a.jsonl"
    writer = Kernel(receipt_log=log, anchor=anchor, sign_key=private)
    for text in ("one", "two", "three"):
        run_turn(text, "groq", writer, client=FakeClient())
    checker = Kernel(receipt_log=log, anchor=anchor, trusted_keys=public, require_signatures=True)
    return {"dir": tmp_path, "private": private, "public": public, "log": log, "anchor": anchor,
            "writer": writer, "checker": checker}


def test_everything_written_is_signed_and_verifies(signed):
    entries, records = lines(signed["log"]), lines(signed["anchor"])
    assert len(entries) == len(records) == 6
    assert all(e["signature"].startswith("ed25519:") and e["key_id"].startswith("key:sha3-256:") for e in entries + records)
    assert signed["checker"].verify() is True


def test_the_private_key_never_appears_in_any_output(signed):
    secret = signed["private"].read_text().strip().split(":", 1)[1]
    assert secret not in signed["log"].read_text() + signed["anchor"].read_text() + signed["public"].read_text()


def test_a_different_trusted_key_does_not_verify_the_log(signed):
    _, other_public = make_key(signed["dir"], "other")
    other = Kernel(receipt_log=signed["log"], anchor=signed["anchor"], trusted_keys=other_public,
                   require_signatures=True)
    assert other.verify() is False


def test_a_log_forged_and_signed_with_the_attackers_own_key_is_rejected(signed):
    evil_private, _ = make_key(signed["dir"], "evil")
    log, anchor = signed["dir"] / "forged.jsonl", signed["dir"] / "forged-anchor.jsonl"
    forger = Kernel(receipt_log=log, anchor=anchor, sign_key=evil_private)
    for text in ("one", "two", "three"):
        run_turn(text, "groq", forger, client=FakeClient())
    assert Kernel(receipt_log=log, anchor=anchor).verify() is True  # hashes alone are satisfied
    check = Kernel(receipt_log=log, anchor=anchor, trusted_keys=signed["public"], require_signatures=True)
    assert check.verify() is False  # but the key is not one we trust


def test_stripping_every_signature_is_caught_only_when_signatures_are_required(signed):
    for path in (signed["log"], signed["anchor"]):
        rows = lines(path)
        for row in rows:
            row.pop("signature"), row.pop("key_id")
        write(path, rows)
    lenient = Kernel(receipt_log=signed["log"], anchor=signed["anchor"], trusted_keys=signed["public"])
    assert lenient.verify() is True  # passes, but the tool says "authenticity is NOT checked"
    assert signed["checker"].verify() is False


def test_stripping_only_the_log_signatures_is_caught_when_required_even_though_the_anchor_is_signed(signed):
    # The signed anchor must not be able to cover for an unsigned log.
    rows = lines(signed["log"])
    for row in rows:
        row.pop("signature"), row.pop("key_id")
    write(signed["log"], rows)
    assert signed["checker"].verify() is False
    done = subprocess.run([BINARY, "verify-log", "--log", str(signed["log"]), "--anchor", str(signed["anchor"]),
                           "--trusted-keys", str(signed["public"]), "--require-signatures"],
                          capture_output=True, text=True)
    assert "entry 1 is not signed" in done.stderr, done.stderr


def test_stripping_only_the_newest_signatures_is_caught_even_without_require(signed):
    rows = lines(signed["log"])
    rows[-1].pop("signature"), rows[-1].pop("key_id")
    write(signed["log"], rows)
    lenient = Kernel(receipt_log=signed["log"], anchor=signed["anchor"], trusted_keys=signed["public"])
    assert lenient.verify() is False


def _material_id(row):
    """What the kernel computes as an entry's id, so an attacker could recompute it too."""
    if "verdict" in row:
        keys = ["version", "previous_receipt_hash", "proposal_hash", "policy_hash", "decision_hash",
                "verdict", "reason_codes", "issued_at"]
    else:
        keys = ["version", "previous_receipt_hash", "decision_receipt_id", "status", "request_sha256",
                "response_sha256", "issued_at"]
    material = json.dumps({k: row[k] for k in keys}, sort_keys=True, separators=(",", ":"))
    return "receipt:sha3-256:" + hashlib.sha3_256(material.encode()).hexdigest()


def test_a_forged_entry_with_every_hash_recomputed_still_fails_without_the_key(signed):
    # Prove the attack is real: recomputing the id satisfies the hash check on its own...
    rows = lines(signed["log"])[:1]
    rows[0]["verdict"] = "deny"
    rows[0]["receipt_id"] = _material_id(rows[0])
    only_first = signed["dir"] / "one.jsonl"
    write(only_first, rows)
    hashes_only = subprocess.run([BINARY, "verify-log", "--log", str(only_first)], capture_output=True, text=True)
    assert hashes_only.returncode == 0, hashes_only.stderr
    # ...and the signature is what stops it.
    signed_check = subprocess.run([BINARY, "verify-log", "--log", str(only_first), "--trusted-keys",
                                   str(signed["public"]), "--require-signatures"], capture_output=True, text=True)
    assert signed_check.returncode != 0 and "does not verify" in signed_check.stderr


def test_editing_an_anchor_record_needs_the_key(signed):
    records = lines(signed["anchor"])
    records[1]["count"] = 99
    write(signed["anchor"], records)
    assert signed["checker"].verify() is False


def test_an_unsigned_writer_cannot_extend_a_signed_log(signed):
    client = FakeClient()
    unsigned = Kernel(receipt_log=signed["log"], anchor=signed["anchor"])
    with pytest.raises(KernelError, match="log is signed"):
        run_turn("sneaky", "groq", unsigned, client=client)
    assert client.calls == 0
    assert signed["checker"].verify() is True


def test_a_key_file_other_users_can_read_is_refused_before_any_model_call(signed):
    os.chmod(signed["private"], 0o644)
    client = FakeClient()
    with pytest.raises(KernelError, match="chmod 600"):
        run_turn("hi", "groq", signed["writer"], client=client)
    assert client.calls == 0


def test_the_key_can_come_from_the_environment(tmp_path, monkeypatch):
    private, public = make_key(tmp_path)
    monkeypatch.setenv("INFINITY_SIGN_KEY", str(private))
    log = tmp_path / "r.jsonl"
    run_turn("hi", "groq", Kernel(receipt_log=log), client=FakeClient())
    assert all("signature" in row for row in lines(log))
    assert Kernel(receipt_log=log, trusted_keys=public, require_signatures=True).verify() is True


def test_keygen_will_not_overwrite_an_existing_key(tmp_path):
    private, public = make_key(tmp_path)
    before = private.read_text()
    again = subprocess.run([BINARY, "keygen", "--out", str(private), "--public-out", str(tmp_path / "x.pub")],
                           capture_output=True, text=True)
    assert again.returncode != 0 and private.read_text() == before and not (tmp_path / "x.pub").exists()
    assert oct(os.stat(private).st_mode & 0o777) == "0o600"


def test_a_log_can_move_to_a_new_key_and_both_are_trusted(signed):
    new_private, new_public = make_key(signed["dir"], "new")
    run_turn("after rotation", "groq", Kernel(receipt_log=signed["log"], anchor=signed["anchor"],
                                              sign_key=new_private), client=FakeClient())
    both = signed["dir"] / "both.pub"
    both.write_text(signed["public"].read_text() + new_public.read_text())
    ok = Kernel(receipt_log=signed["log"], anchor=signed["anchor"], trusted_keys=both, require_signatures=True)
    assert ok.verify() is True
    assert signed["checker"].verify() is False  # the old key alone no longer covers the newest entries


# --- signing does not stop a rollback; the published anchor does ------------------------------

def test_a_rollback_to_an_earlier_genuine_state_passes_locally_but_not_against_the_published_anchor(signed):
    remote = signed["dir"] / "anchors.git"
    subprocess.run(["git", "init", "--bare", "--quiet", str(remote)], check=True)
    anchor_git.publish(signed["anchor"], str(remote), log=signed["log"], trusted_keys=signed["public"],
                       require_signatures=True)
    # Roll the log and the local anchor back by one whole turn (two entries). Every remaining
    # entry is genuine and validly signed, so a local check cannot see anything wrong...
    write(signed["log"], lines(signed["log"])[:-2])
    write(signed["anchor"], lines(signed["anchor"])[:-2])
    assert signed["checker"].verify() is True
    # ...but the copy published earlier still remembers the newer state.
    with pytest.raises(anchor_git.AnchorGitError, match="deleted"):
        anchor_git.verify(signed["log"], str(remote), trusted_keys=signed["public"], require_signatures=True)


def test_publishing_and_verifying_with_signatures(signed):
    remote = signed["dir"] / "anchors.git"
    subprocess.run(["git", "init", "--bare", "--quiet", str(remote)], check=True)
    anchor_git.publish(signed["anchor"], str(remote), log=signed["log"], trusted_keys=signed["public"],
                       require_signatures=True)
    message = anchor_git.verify(signed["log"], str(remote), trusted_keys=signed["public"],
                                require_signatures=True)
    assert "signatures: 6 verified" in message, message
    _, other = make_key(signed["dir"], "other")
    with pytest.raises(anchor_git.AnchorGitError, match="not trusted"):
        anchor_git.verify(signed["log"], str(remote), trusted_keys=other, require_signatures=True)


def test_requiring_signatures_needs_a_trusted_key():
    with pytest.raises(KernelError, match="needs trusted_keys"):
        Kernel(require_signatures=True)
