"""The standalone verifier (verifier/ickverify.py) against the Rust verifier, on real and damaged logs."""

import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from runtime.chat import run_turn
from runtime.kernel import Kernel, KernelError, find_binary

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "verifier" / "ickverify.py"
sys.path.insert(0, str(ROOT / "verifier"))
import ickverify  # noqa: E402

try:
    BINARY = find_binary()
except KernelError:
    BINARY = None


# --- the Ed25519 code on its own (RFC 8032 test vector 1, and the strictness the kernel applies) -----

PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
SIG = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


def test_ed25519_accepts_the_rfc_vector_and_rejects_changes():
    assert ickverify.ed25519_verify_strict(PUB, b"", SIG)
    assert not ickverify.ed25519_verify_strict(PUB, b"x", SIG)
    for i in range(64):
        bad = bytearray(SIG)
        bad[i] ^= 1
        assert not ickverify.ed25519_verify_strict(PUB, b"", bytes(bad)), i
    for i in range(32):
        bad = bytearray(PUB)
        bad[i] ^= 1
        assert not ickverify.ed25519_verify_strict(bytes(bad), b"", SIG), i
    assert not ickverify.ed25519_verify_strict(PUB, b"", SIG[:63])
    assert not ickverify.ed25519_verify_strict(PUB[:31], b"", SIG)


def test_ed25519_is_strict_like_the_kernel():
    s = int.from_bytes(SIG[32:], "little")
    assert not ickverify.ed25519_verify_strict(PUB, b"", SIG[:32] + (s + ickverify._L).to_bytes(32, "little"))
    identity = (1).to_bytes(32, "little")  # the identity point: small order
    assert not ickverify.ed25519_verify_strict(identity, b"", identity + bytes(32))
    assert not ickverify.ed25519_verify_strict(PUB, b"", identity + SIG[32:])  # small-order R


# --- against real logs -------------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(BINARY is None, reason="infinityctl not built (run `cargo build`)")


class FakeClient:
    def __call__(self, url, payload, headers):
        return {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.delenv("INFINITY_SIGN_KEY", raising=False)
    # These tests need a completed provider call. Explicit local-dev opt-out, not the default.
    monkeypatch.setenv("WICKET_ALLOW_DIRECT_CALLS", "1")


def make_key(directory, name="key"):
    private, public = directory / f"{name}.priv", directory / f"{name}.pub"
    subprocess.run([BINARY, "keygen", "--out", str(private), "--public-out", str(public)],
                   check=True, capture_output=True)
    return private, public


def build(tmp_path, signed=True, turns=2):
    log, anchor = tmp_path / "log" / "r.jsonl", tmp_path / "safe" / "a.jsonl"
    private, public = make_key(tmp_path)
    kernel = Kernel(receipt_log=log, anchor=anchor, sign_key=private if signed else None)
    for text in ("one", "two", "three")[:turns]:
        run_turn(text, "groq", kernel, client=FakeClient())
    return {"log": log, "anchor": anchor, "public": public, "private": private}


def rust(log, anchor=None, keys=None, require=False):
    cmd = [BINARY, "verify-log", "--log", str(log)]
    if anchor:
        cmd += ["--anchor", str(anchor)]
    if keys:
        cmd += ["--trusted-keys", str(keys)]
        if require:
            cmd += ["--require-signatures"]
    return subprocess.run(cmd, capture_output=True, text=True).returncode == 0


def python(log, anchor=None, keys=None, require=False):
    try:
        return ickverify.verify(
            Path(log).read_text(encoding="utf-8"), Path(anchor).read_text(encoding="utf-8") if anchor else None,
            Path(keys).read_text(encoding="utf-8") if keys else None, require)["ok"]
    except ickverify.Problem:
        return False


def both(log, anchor=None, keys=None, require=False):
    a, b = rust(log, anchor, keys, require), python(log, anchor, keys, require)
    return a, b


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def write(path, rows):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows))


def test_a_good_signed_and_anchored_log_verifies_in_both(tmp_path):
    s = build(tmp_path)
    assert both(s["log"], s["anchor"], s["public"], True) == (True, True)
    report = ickverify.verify(s["log"].read_text(encoding="utf-8"), s["anchor"].read_text(encoding="utf-8"), s["public"].read_text(encoding="utf-8"), True)
    assert report["entries"] == 4 and report["decisions"] == 2 and report["outcomes"] == 2
    assert report["signed_entries"] == 4 and report["anchor_records"] == 4 and report["anchor_covers_entries"] == 4
    assert report["warnings"] == [] and report["verdicts"] == {"allow": 2}


def test_a_plain_unsigned_log_verifies_and_says_what_was_not_checked(tmp_path):
    s = build(tmp_path, signed=False)
    assert both(s["log"], s["anchor"]) == (True, True)
    notes = " ".join(ickverify.verify(s["log"].read_text(encoding="utf-8"))["warnings"])
    assert "no anchor was given" in notes and "signatures were not checked" in notes
    with_keys = ickverify.verify(s["log"].read_text(encoding="utf-8"), s["anchor"].read_text(encoding="utf-8"), s["public"].read_text(encoding="utf-8"))
    assert with_keys["ok"] and any("authenticity is NOT checked" in w for w in with_keys["warnings"])
    assert both(s["log"], s["anchor"], s["public"], True) == (False, False)  # required but absent


def tamper_cases(s, tmp_path):
    """(name, log_rows, anchor_rows, keys_path) variants, each a different way to damage the evidence."""
    log, anchor = lines(s["log"]), lines(s["anchor"])
    rows = [json.loads(x) for x in log]
    other_priv, other_pub = make_key(tmp_path, "other")
    cases = {}

    def edit(i, **changes):
        copy = [dict(r) for r in rows]
        copy[i].update(changes)
        return copy

    cases["edited verdict"] = (edit(0, verdict="deny"), anchor, None)
    cases["edited reason"] = (edit(0, reason_codes=["X"]), anchor, None)
    cases["edited time"] = (edit(1, issued_at="2000-01-01T00:00:00Z"), anchor, None)
    cases["edited outcome status"] = (edit(1, status="failed"), anchor, None)
    cases["edited id"] = (edit(0, receipt_id="receipt:sha3-256:" + "0" * 64), anchor, None)
    cases["broken link"] = (edit(1, previous_receipt_hash="receipt:sha3-256:" + "1" * 64), anchor, None)
    cases["first entry has a predecessor"] = (edit(0, previous_receipt_hash=rows[1]["receipt_id"]), anchor, None)
    cases["deleted middle"] = (log[:1] + log[2:], anchor, None)
    cases["deleted first"] = (log[1:], anchor, None)
    cases["deleted tail"] = (log[:-1], anchor, None)
    cases["deleted tail and its anchors"] = (log[:-1], anchor[:-1], None)
    cases["swapped"] = ([log[1], log[0]] + log[2:], anchor, None)
    cases["duplicated outcome"] = (log + [log[1]], anchor, None)
    cases["outcome for nothing"] = (edit(1, decision_receipt_id="receipt:sha3-256:" + "2" * 64), anchor, None)
    cases["stripped signature"] = ([{k: v for k, v in r.items() if k != "signature"} for r in rows[:1]] + log[1:], anchor, None)
    cases["stripped tail signature"] = (rows[:-1] and [json.dumps(r) for r in rows[:-1]] + [json.dumps({k: v for k, v in rows[-1].items() if k not in ("signature", "key_id")})], anchor, None)
    cases["stripped all signatures"] = ([{k: v for k, v in r.items() if k not in ("signature", "key_id")} for r in rows], anchor, None)
    cases["key id only"] = ([{k: v for k, v in r.items() if k != "signature"} for r in rows], anchor, None)
    cases["wrong key id"] = (edit(0, key_id="key:sha3-256:" + "3" * 64), anchor, None)
    cases["garbage signature"] = (edit(0, signature="ed25519:" + "0" * 128), anchor, None)
    cases["short signature"] = (edit(0, signature="ed25519:abcd"), anchor, None)
    cases["signature from another entry"] = (edit(0, signature=rows[1]["signature"]), anchor, None)
    cases["extra field"] = (edit(0, note="hello"), anchor, None)
    cases["null previous"] = (edit(1, previous_receipt_hash=None), anchor, None)
    cases["unknown receipt version"] = (edit(0, version="infinity.receipt.v9"), anchor, None)
    cases["wrong field type"] = (edit(0, reason_codes="ALLOWED"), anchor, None)
    cases["not json"] = (["{nope"] + log[1:], anchor, None)
    cases["empty log"] = ([], anchor, None)
    cases["empty log no anchor"] = ([], [], None)
    # anchor damage
    a = [json.loads(x) for x in anchor]
    mut = lambda i, **c: [json.dumps({**a[j], **(c if j == i else {})}) for j in range(len(a))]  # noqa: E731
    cases["anchor wrong head"] = (log, mut(1, head_receipt_id=rows[0]["receipt_id"]), None)
    cases["anchor too long"] = (log, mut(3, count=99), None)
    cases["anchor count zero"] = (log, mut(0, count=0), None)
    cases["anchor bad version"] = (log, mut(0, version="infinity.anchor.v2"), None)
    cases["anchor bad signature"] = (log, mut(1, signature="ed25519:" + "0" * 128), None)
    cases["anchor wrong count signed"] = (log, mut(1, count=3, head_receipt_id=rows[2]["receipt_id"]), None)
    cases["anchor unsigned record"] = (log, [json.dumps({k: v for k, v in a[1].items() if k not in ("signature", "key_id")}) if i == 1 else json.dumps(x) for i, x in enumerate(a)], None)
    cases["anchor stripped all"] = (log, [json.dumps({k: v for k, v in x.items() if k not in ("signature", "key_id")}) for x in a], None)
    cases["anchor not json"] = (log, ["nope"] + anchor, None)
    cases["anchor blank lines"] = (log, [""] + anchor + [""], None)
    cases["anchor float count"] = (log, mut(0, count=1.0), None)
    # key problems
    cases["other trusted key"] = (log, anchor, other_pub)
    return cases


CONFIGS = {  # which of the optional inputs are supplied; a check one input makes redundant shows up in another
    "everything required": dict(anchor=True, keys=True, require=True),
    "chain only": dict(anchor=False, keys=False, require=False),
    "anchor only": dict(anchor=True, keys=False, require=False),
    "keys only": dict(anchor=False, keys=True, require=False),
    "keys required, no anchor": dict(anchor=False, keys=True, require=True),
    "anchor and keys, not required": dict(anchor=True, keys=True, require=False),
}


@pytest.mark.parametrize("config", list(CONFIGS))
def test_every_kind_of_damage_gets_the_same_answer_from_both_verifiers(tmp_path, config):
    s = build(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    use = CONFIGS[config]
    disagreements, rejected = [], 0
    for name, (log_rows, anchor_rows, keys) in tamper_cases(s, tmp_path).items():
        write(work / "l.jsonl", log_rows)
        write(work / "a.jsonl", anchor_rows)
        a, b = both(work / "l.jsonl", work / "a.jsonl" if use["anchor"] else None,
                    (keys or s["public"]) if use["keys"] else None, use["require"])
        rejected += not a
        if a != b:
            disagreements.append((name, "rust says", a, "python says", b))
    assert not disagreements, disagreements
    assert rejected >= 8  # a good part of the cases are damage that must be refused, so this is not vacuous


def test_the_undamaged_cases_that_must_pass_do_pass(tmp_path):
    s = build(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    log, anchor = lines(s["log"]), lines(s["anchor"])
    for rows, anchor_rows in ((log, anchor), (log, [""] + anchor), (log, anchor[:2]), (log, anchor[-1:])):
        write(work / "l.jsonl", rows)
        write(work / "a.jsonl", anchor_rows)
        assert both(work / "l.jsonl", work / "a.jsonl", s["public"], True) == (True, True)


def test_random_single_character_damage_never_gets_different_answers(tmp_path):
    s = build(tmp_path, turns=1)
    work = tmp_path / "work"
    work.mkdir()
    rng = random.Random(20261002)
    log_text, anchor_text = s["log"].read_text(encoding="utf-8"), s["anchor"].read_text(encoding="utf-8")
    alphabet = "0123456789abcdefxyz\"{}:,[] "
    disagreements, refused = [], 0
    for n in range(160):
        text, which = (log_text, "log") if n % 2 == 0 else (anchor_text, "anchor")
        i = rng.randrange(len(text))
        damaged = text[:i] + rng.choice(alphabet) + text[i + 1:]
        files = {"log": log_text, "anchor": anchor_text}
        files[which] = damaged
        (work / "l.jsonl").write_bytes(files["log"].encode())
        (work / "a.jsonl").write_bytes(files["anchor"].encode())
        a, b = both(work / "l.jsonl", work / "a.jsonl", s["public"], True)
        refused += not a
        if a != b:
            disagreements.append((which, i, a, b))
    assert not disagreements, disagreements
    assert refused > 60  # a good share of the random damage was real damage


def test_unusual_characters_are_hashed_the_way_the_kernel_writes_them(tmp_path):
    """`issued_at` is caller-supplied text that goes into the hashed material; use awkward text there."""
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "p"}))
    proposal = {"version": "infinity.proposal.v1", "proposal_id": "x", "actor": {"kind": "a", "id": "b"},
                "action": "act", "target": "t", "effect": "read", "risk": "low", "requires_human_approval": False,
                "policy_version": "p", "payload": {}, "evidence_refs": []}
    (tmp_path / "prop.json").write_text(json.dumps(proposal))
    for text in ["plain", "caf\u00e9 \u4e2d\u6587 \U0001f600", 'quote " backslash \\ slash /',
                 "tab\tnl\ncr\rbs\bff\f", "\x01\x1f\x7f", "</script> \u2028 \u2029", ""]:
        log = tmp_path / "u.jsonl"
        log.unlink(missing_ok=True)
        done = subprocess.run([BINARY, "evaluate", "--proposal", str(tmp_path / "prop.json"), "--policy", str(policy),
                               "--log", str(log), "--issued-at", text], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
        assert rust(log) is True
        assert python(log) is True, repr(text)  # our recomputed id equals the kernel's


def test_the_cli_exit_codes_output_and_limits_text(tmp_path):
    s = build(tmp_path)
    cmd = [sys.executable, str(VERIFIER)]
    ok = subprocess.run(cmd + [str(s["log"]), "--anchor", str(s["anchor"]), "--trusted-keys", str(s["public"]),
                               "--require-signatures"], capture_output=True, text=True)
    assert ok.returncode == 0 and ok.stdout.startswith("VERIFIED: 4 entries")
    assert "does NOT show that what was done matched what was asked" in ok.stdout

    damaged = tmp_path / "bad.jsonl"
    write(damaged, lines(s["log"])[:1] + lines(s["log"])[2:])
    bad = subprocess.run(cmd + [str(damaged), "--anchor", str(s["anchor"])], capture_output=True, text=True)
    assert bad.returncode == 1 and "NOT VERIFIED" in bad.stdout and "problem:" in bad.stdout

    as_json = subprocess.run(cmd + [str(s["log"]), "--json"], capture_output=True, text=True)
    report = json.loads(as_json.stdout)
    assert as_json.returncode == 0 and report["ok"] is True and report["entries"] == 4

    missing = subprocess.run(cmd + [str(tmp_path / "nope.jsonl")], capture_output=True, text=True)
    assert missing.returncode == 2 and "cannot check" in missing.stderr
    no_keys = subprocess.run(cmd + [str(s["log"]), "--require-signatures"], capture_output=True, text=True)
    assert no_keys.returncode == 2 and "needs --trusted-keys" in no_keys.stderr
    junk_keys = tmp_path / "keys.txt"
    junk_keys.write_text("ed25519-public:nothex\n")
    assert subprocess.run(cmd + [str(s["log"]), "--trusted-keys", str(junk_keys)],
                          capture_output=True, text=True).returncode == 2
    notes = subprocess.run(cmd + [str(s["log"])], capture_output=True, text=True).stdout
    assert "no anchor was given" in notes and "signatures were not checked (4 entries carry one)" in notes


def test_it_runs_alone_with_nothing_but_python(tmp_path):
    """Copy the one file somewhere empty and run it in isolated mode: no repository, no packages."""
    s = build(tmp_path)
    alone = tmp_path / "alone"
    alone.mkdir()
    shutil.copy(VERIFIER, alone / "ickverify.py")
    done = subprocess.run([sys.executable, "-I", str(alone / "ickverify.py"), str(s["log"]), "--anchor",
                           str(s["anchor"]), "--trusted-keys", str(s["public"])],
                          cwd=alone, capture_output=True, text=True, env={"PATH": os.environ.get("PATH", "")})
    assert done.returncode == 0, done.stderr
    imports = [ln for ln in VERIFIER.read_text(encoding="utf-8").splitlines() if ln.startswith(("import ", "from "))]
    allowed = {"argparse", "base64", "hashlib", "json", "sys", "typing", "__future__"}
    assert {ln.split()[1].split(".")[0] for ln in imports} <= allowed, imports


def test_a_signed_log_of_several_keys_after_a_rotation_verifies_in_both(tmp_path):
    (tmp_path / "a").mkdir()
    first = build(tmp_path / "a")
    log, anchor = first["log"], first["anchor"]
    private2, public2 = make_key(tmp_path, "second")
    run_turn("after rotation", "groq", Kernel(receipt_log=log, anchor=anchor, sign_key=private2), client=FakeClient())
    keys = tmp_path / "both.pub"
    keys.write_text(first["public"].read_text(encoding="utf-8") + "\n" + public2.read_text(encoding="utf-8"))
    assert both(log, anchor, keys, True) == (True, True)
    assert both(log, anchor, first["public"], True) == (False, False)  # the second key is not trusted


def relink(rows):
    """Give hand-built entries correct ids and links (and no signatures), so only the *meaning* is wrong."""
    out, previous = [], None
    for row in rows:
        row = {k: v for k, v in row.items() if k not in ("signature", "key_id", "receipt_id")}
        row["previous_receipt_hash"] = previous
        entry = ickverify.parse_entry(json.dumps({**row, "receipt_id": "x"}))
        row["receipt_id"] = previous = ickverify.expected_id(entry)
        out.append(row)
    return out


def test_correctly_hashed_logs_with_wrong_meaning_are_refused_by_both(tmp_path):
    s = build(tmp_path, signed=False, turns=1)
    decision, outcome = [json.loads(x) for x in lines(s["log"])]
    denied_policy = tmp_path / "deny.json"
    denied_policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-demo-v1",
                                         "denied_effects": ["read"]}))
    deny_log = tmp_path / "deny.jsonl"
    run_turn("blocked", "groq", Kernel(policy=denied_policy, receipt_log=deny_log), client=FakeClient())
    denial = json.loads(lines(deny_log)[0])
    assert denial["verdict"] == "deny"

    second = {**outcome, "status": "failed"}
    cases = {
        "a good pair": ([decision, outcome], True),
        "a second outcome for one allow": ([decision, outcome, second], False),
        "an outcome that answers nothing": ([{**outcome, "decision_receipt_id": "receipt:sha3-256:" + "4" * 64}], False),
        "an outcome that answers a denial": ([denial, {**outcome, "decision_receipt_id": denial["receipt_id"]}], False),
        "an outcome before its allow": ([outcome, decision], False),
        "an allow with no outcome": ([decision], True),
    }
    work = tmp_path / "work"
    work.mkdir()
    for name, (rows, expected) in cases.items():
        write(work / "l.jsonl", relink(rows))
        a, b = both(work / "l.jsonl")
        assert (a, b) == (expected, expected), name
