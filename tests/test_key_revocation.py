"""Retiring and revoking signing keys: `<key> through <receipt>` in the trusted-keys file.

Real logs are written by the real kernel with two different keys, then checked by the Rust verifier
and the standalone Python verifier, which must agree."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from runtime.chat import run_turn
from runtime.kernel import Kernel, KernelError, find_binary

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verifier"))
import ickverify  # noqa: E402

try:
    BINARY = find_binary()
except KernelError:
    pytest.skip("infinityctl not built (run `cargo build`)", allow_module_level=True)


class Client:
    def __call__(self, url, payload, headers):
        return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.delenv("INFINITY_SIGN_KEY", raising=False)


def make_key(directory, name):
    private, public = directory / f"{name}.priv", directory / f"{name}.pub"
    subprocess.run([BINARY, "keygen", "--out", str(private), "--public-out", str(public)],
                   check=True, capture_output=True)
    return private, public.read_text().strip()


def turn(kernel, text="hi"):
    run_turn(text, "groq", kernel, client=Client())


class Rotated:
    """Entries 1-4 signed by the old key, 5-8 by the new one (two turns each; a turn is a decision and
    its outcome)."""

    def __init__(self, tmp_path):
        self.dir = tmp_path
        (tmp_path / "log").mkdir()
        self.log, self.anchor = tmp_path / "log" / "r.jsonl", tmp_path / "anchor.jsonl"
        self.old_priv, self.old_pub = make_key(tmp_path, "old")
        self.new_priv, self.new_pub = make_key(tmp_path, "new")
        old = Kernel(receipt_log=self.log, anchor=self.anchor, sign_key=self.old_priv)
        turn(old, "one"), turn(old, "two")
        new = Kernel(receipt_log=self.log, anchor=self.anchor, sign_key=self.new_priv)
        turn(new, "three"), turn(new, "four")
        self.ids = [json.loads(x)["receipt_id"] for x in self.log.read_text().splitlines()]
        assert len(self.ids) == 8

    def append_with_old_key(self):
        turn(Kernel(receipt_log=self.log, anchor=self.anchor, sign_key=self.old_priv), "forged")
        self.ids = [json.loads(x)["receipt_id"] for x in self.log.read_text().splitlines()]

    def keys(self, old_through=None, new=True, old=True):
        lines = []
        if old:
            lines.append(self.old_pub + (f" through {old_through}" if old_through else ""))
        if new:
            lines.append(self.new_pub)
        path = self.dir / "trusted.txt"
        path.write_text("\n".join(lines) + "\n")
        return path


def rust(log, anchor, keys, require=True):
    cmd = [BINARY, "verify-log", "--log", str(log), "--trusted-keys", str(keys)]
    if anchor is not None:
        cmd += ["--anchor", str(anchor)]
    if require:
        cmd.append("--require-signatures")
    done = subprocess.run(cmd, capture_output=True, text=True)
    return done.returncode == 0, done.stdout + done.stderr


def python(log, anchor, keys, require=True):
    try:
        report = ickverify.verify(log.read_text(encoding="utf-8"),
                                  anchor.read_text(encoding="utf-8") if anchor is not None else None,
                                  keys.read_text(encoding="utf-8"), require)
    except ickverify.Problem as exc:
        return False, str(exc)
    return report["ok"], " ".join(report["errors"])


def both(log, anchor, keys, require=True):
    (a, why_a), (b, why_b) = rust(log, anchor, keys, require), python(log, anchor, keys, require)
    assert a == b, (a, why_a, b, why_b)
    return a, why_a + " | " + why_b


@pytest.fixture
def rot(tmp_path):
    return Rotated(tmp_path)


def test_a_planned_hand_over_verifies_when_the_old_key_is_limited_to_its_last_entry(rot):
    assert both(rot.log, rot.anchor, rot.keys(old_through=rot.ids[3]))[0] is True


def test_an_unlimited_old_key_and_a_limited_one_both_verify_but_a_missing_one_does_not(rot):
    assert both(rot.log, rot.anchor, rot.keys())[0] is True
    ok, why = both(rot.log, rot.anchor, rot.keys(old=False))
    assert ok is False and "not trusted" in why


def test_limiting_a_key_too_early_rejects_the_entries_after_it(rot):
    for early in (0, 1, 2):
        ok, why = both(rot.log, rot.anchor, rot.keys(old_through=rot.ids[early]))
        assert ok is False and "retired or revoked" in why, (early, why)
    assert both(rot.log, rot.anchor, rot.keys(old_through=rot.ids[3]))[0] is True  # one entry later is fine


def test_a_thief_with_the_old_key_cannot_add_trusted_entries_after_the_limit(rot):
    limit = rot.ids[3]
    rot.append_with_old_key()  # genuinely signed with the leaked key, after the hand-over
    assert len(rot.ids) == 10
    unlimited_ok, _ = both(rot.log, rot.anchor, rot.keys())
    assert unlimited_ok is True  # without the limit the forgery is accepted: the problem this feature solves
    ok, why = both(rot.log, rot.anchor, rot.keys(old_through=limit))
    assert ok is False and "retired or revoked" in why


def test_the_anchor_records_of_a_limited_key_are_limited_too(rot):
    # Strip the new key's signatures from the log entries' check by making only the anchor decisive:
    # entries 5-8 are signed by the new key, but anchor record 4 was signed by the old key at count 4.
    assert both(rot.log, rot.anchor, rot.keys(old_through=rot.ids[3]))[0] is True
    ok, why = both(rot.log, rot.anchor, rot.keys(old_through=rot.ids[2]))
    assert ok is False
    anchor_lines = rot.anchor.read_text().splitlines()
    forged = json.loads(anchor_lines[3])  # the old key's record for count 4
    assert forged["count"] == 4 and forged["key_id"]
    # an anchor record signed by the old key for a count beyond the limit is refused on its own
    no_entry_sigs = rot.dir / "log2.jsonl"
    rows = [json.loads(x) for x in rot.log.read_text().splitlines()]
    for r in rows:  # drop every entry signature so only anchors are being judged
        r.pop("signature", None), r.pop("key_id", None)
    no_entry_sigs.write_text("".join(json.dumps(r) + "\n" for r in rows))
    ok, why = both(no_entry_sigs, rot.anchor, rot.keys(old_through=rot.ids[2]), require=False)
    assert ok is False and "anchor line 4" in why and "retired or revoked" in why


def test_a_limit_naming_a_receipt_that_is_not_in_the_log_trusts_nothing_the_key_signed(rot):
    elsewhere = "receipt:sha3-256:" + "9" * 64
    ok, why = both(rot.log, rot.anchor, rot.keys(old_through=elsewhere))
    assert ok is False and "not in this log" in why


def test_a_limit_does_not_matter_for_a_log_the_key_never_signed(tmp_path):
    (tmp_path / "x").mkdir()
    log, anchor = tmp_path / "x" / "r.jsonl", tmp_path / "a.jsonl"
    priv, pub = make_key(tmp_path, "only")
    other_priv, other_pub = make_key(tmp_path, "retired")
    turn(Kernel(receipt_log=log, anchor=anchor, sign_key=priv))
    keys = tmp_path / "t.txt"
    keys.write_text(f"{pub}\n{other_pub} through receipt:sha3-256:{'8' * 64}\n")
    assert both(log, anchor, keys)[0] is True


@pytest.mark.parametrize("line", [
    "{pub} through",
    "{pub} through receipt:sha3-256:short",
    "{pub} through {hex64}",
    "{pub} until receipt:sha3-256:{hex64}",
    "{pub} through receipt:sha3-256:{hex64} extra",
    "{pub} receipt:sha3-256:{hex64}",
    "{pub}\n{pub}",
    "{pub} through receipt:sha3-256:{hex64}\n{pub}",
    "{pub} through RECEIPT:sha3-256:{hex64}",
    "{pub} through receipt:sha3-256:{HEX64}",
])
def test_malformed_limits_are_refused_by_both_verifiers_and_say_nothing_is_checked(rot, line):
    path = rot.dir / "bad.txt"
    path.write_text(line.format(pub=rot.old_pub, hex64="a" * 64, HEX64="A" * 64) + "\n")
    rust_ok, _ = rust(rot.log, rot.anchor, path, require=False)
    py_ok, why = python(rot.log, rot.anchor, path, require=False)
    assert rust_ok is False and py_ok is False and "trusted keys" in why


def test_a_comment_after_the_limit_and_blank_lines_are_fine(rot):
    path = rot.dir / "ok.txt"
    path.write_text(f"# the old key, retired at the hand-over\n\n{rot.old_pub} through {rot.ids[3]}   # retired 2026\n"
                    f"{rot.new_pub}\n")
    assert both(rot.log, rot.anchor, path)[0] is True


def test_the_wrapper_the_operator_screen_and_the_publisher_use_accepts_limits(rot):
    keys = rot.keys(old_through=rot.ids[3])
    checker = Kernel(receipt_log=rot.log, anchor=rot.anchor, trusted_keys=keys, require_signatures=True)
    assert checker.verify() is True
    bad = Kernel(receipt_log=rot.log, anchor=rot.anchor, trusted_keys=rot.keys(old_through=rot.ids[1]),
                 require_signatures=True)
    assert bad.verify() is False


def test_after_a_compromise_the_old_log_stops_being_trusted_at_the_limit_but_a_fresh_log_verifies(rot, tmp_path):
    """The procedure for a stolen key: limit it to the last good entry, archive the old log, start a new one
    with a new key. The old log now fails past the limit (that is the evidence); the new log is clean."""
    limit = rot.ids[3]
    rot.append_with_old_key()
    keys = rot.keys(old_through=limit)
    assert both(rot.log, rot.anchor, keys)[0] is False
    (tmp_path / "fresh").mkdir()
    fresh_log, fresh_anchor = tmp_path / "fresh" / "r.jsonl", tmp_path / "fresh" / "a.jsonl"
    turn(Kernel(receipt_log=fresh_log, anchor=fresh_anchor, sign_key=rot.new_priv), "after the incident")
    assert both(fresh_log, fresh_anchor, keys)[0] is True  # the retired key's limit does not matter here


def test_the_entry_checks_work_on_their_own_without_any_anchor(rot):
    """With no anchor to catch it, the limit must still be enforced on the entries themselves."""
    assert both(rot.log, None, rot.keys(old_through=rot.ids[3]))[0] is True
    ok, why = both(rot.log, None, rot.keys(old_through=rot.ids[1]))
    assert ok is False and "entry 3" in why and "retired or revoked" in why
    ok, why = both(rot.log, None, rot.keys(old_through="receipt:sha3-256:" + "7" * 64))
    assert ok is False and "not in this log" in why
    rot.append_with_old_key()
    assert both(rot.log, None, rot.keys())[0] is True
    ok, why = both(rot.log, None, rot.keys(old_through=rot.ids[3]))
    assert ok is False and "entry 9" in why
