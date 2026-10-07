#!/usr/bin/env python3
"""Check an Infinity receipt log without trusting Nova, the kernel binary, or anything else that wrote it.

    python ickverify.py LOG [--anchor ANCHOR] [--trusted-keys KEYS] [--require-signatures] [--json]

This is one file with no dependencies beyond the Python standard library (3.8 or newer). It does
not call `infinityctl`: it recomputes every hash and checks every Ed25519 signature itself, so a
bug or a swapped binary in the Rust kernel cannot make a bad log look good here. It is a second,
independent implementation of the same rules, written by the same author from the same
specification, and checked against the Rust verifier on real and tampered logs (see
tests/test_standalone_verifier.py). Two implementations agreeing is better than one; it is not an
independent audit.

What "verified" means, and does not mean, is printed at the end of every run. The short version:
  * It proves the log is internally consistent (every entry's hash is right, each names the one
    before it, every outcome answers an earlier `allow`), that it matches the anchor you gave it,
    and, with trusted keys, that each entry was signed by a key you trust.
  * Deleting the newest entries is only caught if you pass an anchor that the log's writer could
    not edit (a copy you fetched yourself from the published anchor repository).
  * It does NOT show that what was done matched what was asked. A receipt may carry a call_digest;
    this program checks that the field is covered by the hash when it is present. It does not
    recompute that digest from a call, and it does not read a witness log. It also does not show
    that the clock was right, or that a signing key was never stolen.

Exit status: 0 verified, 1 not verified, 2 the inputs could not be read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

RECEIPT_V1 = "infinity.receipt.v1"
RECEIPT_V2 = "infinity.receipt.v2"
OUTCOME_V1 = "infinity.outcome.v1"
ANCHOR_V1 = "infinity.anchor.v1"
ENTRY_DOMAIN = "infinity-core/entry/v1"
ANCHOR_DOMAIN = "infinity-core/anchor/v1"
PUBLIC_PREFIX = "ed25519-public:"
SIGNATURE_PREFIX = "ed25519:"

# Fields each entry kind is built from. Anything else in a line is not covered by the entry's hash.
RECEIPT_FIELDS = {"version", "receipt_id", "previous_receipt_hash", "proposal_hash", "policy_hash",
                  "decision_hash", "verdict", "reason_codes", "issued_at", "call_digest", "key_id",
                  "signature"}
OUTCOME_FIELDS = {"version", "receipt_id", "previous_receipt_hash", "decision_receipt_id", "status",
                  "request_sha256", "response_sha256", "issued_at", "key_id", "signature"}


# --- Ed25519 (RFC 8032), verification only, with the strictness the kernel uses ---------------------
#
# The kernel verifies with ed25519-dalek's `verify_strict`: the signature's S must be below the group
# order, neither the public key nor R may be a small-order point, and the check is the cofactorless
# equation compared on the encoded point. This does the same. It is slow (pure Python integers, a few
# milliseconds per signature), which is fine for a verifier.

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)  # sqrt(-1)


def _recover_x(y: int, sign: int) -> Optional[int]:
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


Point = Tuple[int, int, int, int]
_BY = 4 * pow(5, _P - 2, _P) % _P
_B: Point = (_recover_x(_BY, 0) or 0, _BY, 1, (_recover_x(_BY, 0) or 0) * _BY % _P)
_ZERO: Point = (0, 1, 1, 0)


def _add(a: Point, b: Point) -> Point:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A, B = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    C, D = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s: int, p: Point) -> Point:
    q = _ZERO
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _neg(p: Point) -> Point:
    return ((-p[0]) % _P, p[1], p[2], (-p[3]) % _P)


def _compress(p: Point) -> bytes:
    zi = pow(p[2], _P - 2, _P)
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(s: bytes) -> Optional[Point]:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:  # a non-canonical encoding; stricter than dalek's decoder, which reduces it
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _small_order(p: Point) -> bool:
    x, y, z, _ = _mul(8, p)
    return x % _P == 0 and (y - z) % _P == 0


def ed25519_verify_strict(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decompress(public_key)
    r_bytes, s = signature[:32], int.from_bytes(signature[32:], "little")
    r = _decompress(r_bytes)
    if a is None or r is None or s >= _L or _small_order(a) or _small_order(r):
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _L
    check = _add(_mul(s, _B), _neg(_mul(k, a)))
    return _compress(check) == r_bytes


# --- hashing, exactly as the kernel does it ---------------------------------------------------------

def canonical_json(value: Any) -> str:
    # serde_json writes object keys in sorted order, no spaces, and non-ASCII text as it is.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_value(value: Any) -> str:
    return "sha3-256:" + hashlib.sha3_256(canonical_json(value).encode("utf-8")).hexdigest()


def key_id_for(public_key: bytes) -> str:
    return "key:sha3-256:" + hashlib.sha3_256(public_key).hexdigest()


def _lines(text: str) -> List[str]:
    """Split on newlines only, as Rust's `lines()` does. str.splitlines() would also split on U+2028 and
    other separators, which JSON text may contain unescaped, and so read the same file differently."""
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts.pop()
    return [part[:-1] if part.endswith("\r") else part for part in parts]


def _hex_bytes(text: str, n: int) -> Optional[bytes]:
    if len(text) != 2 * n or any(c not in "0123456789abcdef" for c in text):
        return None
    return bytes.fromhex(text)


# --- reading the files -----------------------------------------------------------------------------

class Problem(Exception):
    """The log, anchor or key file could not be understood at all."""


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _load_json_line(line: str) -> Any:
    return json.loads(line, parse_constant=_reject_constant)


def _opt_str(entry: Dict[str, Any], key: str) -> Optional[str]:
    value = entry.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{key} must be text")
    return value


def _req_str(entry: Dict[str, Any], key: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} is missing or not text")
    return value


def parse_entry(line: str) -> Dict[str, Any]:
    """One log line as the kernel reads it: a decision receipt, or an outcome if its version says so."""
    raw = _load_json_line(line)
    if not isinstance(raw, dict):
        raise ValueError("an entry must be a JSON object")
    version = raw.get("version")
    if isinstance(version, str) and version.startswith("infinity.outcome."):
        kind = "outcome"
        fields = {
            "version": _req_str(raw, "version"), "receipt_id": _req_str(raw, "receipt_id"),
            "previous_receipt_hash": _opt_str(raw, "previous_receipt_hash"),
            "decision_receipt_id": _req_str(raw, "decision_receipt_id"), "status": _req_str(raw, "status"),
            "request_sha256": _opt_str(raw, "request_sha256"), "response_sha256": _opt_str(raw, "response_sha256"),
            "issued_at": _req_str(raw, "issued_at"),
        }
        known = OUTCOME_FIELDS
    else:
        kind = "decision"
        codes = raw.get("reason_codes")
        if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
            raise ValueError("reason_codes must be a list of text")
        fields = {
            "version": _req_str(raw, "version"), "receipt_id": _req_str(raw, "receipt_id"),
            "previous_receipt_hash": _opt_str(raw, "previous_receipt_hash"),
            "proposal_hash": _req_str(raw, "proposal_hash"), "policy_hash": _req_str(raw, "policy_hash"),
            "decision_hash": _req_str(raw, "decision_hash"), "verdict": _req_str(raw, "verdict"),
            "reason_codes": codes, "issued_at": _req_str(raw, "issued_at"),
        }
        if "call_digest" in raw:
            digest = raw["call_digest"]
            if not isinstance(digest, str):
                raise ValueError("call_digest must be text")
            fields["call_digest"] = digest
        known = RECEIPT_FIELDS
    fields["key_id"], fields["signature"] = _opt_str(raw, "key_id"), _opt_str(raw, "signature")
    fields["kind"] = kind
    fields["extra"] = sorted(set(raw) - known)
    return fields


def expected_id(entry: Dict[str, Any]) -> Optional[str]:
    """The id this entry must have (the hash of its fields), or None for a version nobody can verify."""
    if entry["kind"] == "outcome":
        if entry["version"] != OUTCOME_V1:
            return None
        material = {k: entry[k] for k in ("version", "previous_receipt_hash", "decision_receipt_id", "status",
                                          "request_sha256", "response_sha256", "issued_at")}
    else:
        if entry["version"] not in (RECEIPT_V1, RECEIPT_V2):
            return None
        material = {k: entry[k] for k in ("version", "previous_receipt_hash", "proposal_hash", "policy_hash",
                                          "decision_hash", "verdict", "reason_codes")}
        if entry["version"] == RECEIPT_V2:
            material["issued_at"] = entry["issued_at"]
            if "call_digest" in entry:
                material["call_digest"] = entry["call_digest"]
    return "receipt:" + hash_value(material)


def read_log(text: str) -> List[Dict[str, Any]]:
    entries = []
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        try:
            entries.append(parse_entry(line))
        except ValueError as exc:
            raise Problem(f"log line {number}: {exc}")
    return entries


class TrustedKeys(Dict[str, bytes]):
    """key id -> public key, plus `cutoffs`: key id -> the last receipt that key is trusted for."""

    def __init__(self) -> None:
        super().__init__()
        self.cutoffs: Dict[str, str] = {}


def _is_receipt_id(text: str) -> bool:
    return text.startswith("receipt:sha3-256:") and _hex_bytes(text[len("receipt:sha3-256:"):], 32) is not None


def read_trusted_keys(text: str) -> TrustedKeys:
    """One key per line: `ed25519-public:<hex>`, optionally `through receipt:sha3-256:<hex>`."""
    keys = TrustedKeys()
    for number, line in enumerate(_lines(text), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        words = line.split()
        through = None
        if len(words) == 3 and words[1] == "through" and _is_receipt_id(words[2]):
            through = words[2]
        elif len(words) != 1:
            raise Problem(f"trusted keys line {number}: expected {PUBLIC_PREFIX}<64 hex digits>, optionally "
                          "followed by `through receipt:sha3-256:<64 hex digits>`")
        raw = _hex_bytes(words[0][len(PUBLIC_PREFIX):], 32) if words[0].startswith(PUBLIC_PREFIX) else None
        if raw is None:
            raise Problem(f"trusted keys line {number}: expected {PUBLIC_PREFIX}<64 hex digits>")
        if _decompress(raw) is None:
            raise Problem(f"trusted keys line {number}: not a valid Ed25519 public key")
        key_id = key_id_for(raw)
        if key_id in keys:
            raise Problem(f"trusted keys line {number}: this key is listed twice")
        keys[key_id] = raw
        if through is not None:
            keys.cutoffs[key_id] = through
    if not keys:
        raise Problem("the trusted keys file lists no keys")
    return keys


def position_allowed(keys: TrustedKeys, key_id: str, position: int, entries: List[Dict[str, Any]]) -> Optional[str]:
    """None if `key_id` is trusted at 1-based `position`; otherwise why not. A key limited to an earlier
    receipt is trusted only up to it, and if that receipt is not in this log nothing it signed is accepted."""
    receipt = keys.cutoffs.get(key_id)
    if receipt is None:
        return None
    for index, entry in enumerate(entries):
        if entry["receipt_id"] == receipt:
            if position > index + 1:
                return (f"the key {key_id} was retired or revoked after entry {index + 1}, "
                        f"but this is entry {position}")
            return None
    return f"the key {key_id} is trusted only through {receipt}, which is not in this log"


# --- the checks ------------------------------------------------------------------------------------

def check_chain(entries: List[Dict[str, Any]]) -> Optional[str]:
    allows, answered = set(), set()
    for index, entry in enumerate(entries):
        number = index + 1
        if entry["receipt_id"] != expected_id(entry):
            return f"entry {number}: its id does not match its contents (edited, or an unknown version)"
        previous = entries[index - 1]["receipt_id"] if index else None
        if entry["previous_receipt_hash"] != previous:
            return f"entry {number}: it does not follow the entry before it (inserted, removed or reordered)"
        if entry["kind"] == "decision":
            if entry["verdict"] == "allow":
                allows.add(entry["receipt_id"])
        else:
            target = entry["decision_receipt_id"]
            if target not in allows:
                return f"entry {number}: an outcome that answers no earlier allow"
            if target in answered:
                return f"entry {number}: a second outcome for the same allow"
            answered.add(target)
    return None


def _entry_message(key_id: str, receipt_id: str) -> bytes:
    return f"{ENTRY_DOMAIN}\n{key_id}\n{receipt_id}".encode()


def _anchor_message(key_id: str, count: int, head: str) -> bytes:
    return f"{ANCHOR_DOMAIN}\n{key_id}\n{count}\n{head}".encode()


def _signature_ok(keys: Dict[str, bytes], key_id: str, message: bytes, signature: str) -> bool:
    raw = _hex_bytes(signature[len(SIGNATURE_PREFIX):], 64) if signature.startswith(SIGNATURE_PREFIX) else None
    return raw is not None and ed25519_verify_strict(keys[key_id], message, raw)


def check_signatures(entries: List[Dict[str, Any]], keys: TrustedKeys, require: bool) -> Tuple[Optional[str], int]:
    signed = 0
    for index, entry in enumerate(entries):
        number = index + 1
        key_id, signature = entry["key_id"], entry["signature"]
        if key_id is not None and signature is not None:
            if key_id not in keys:
                return f"entry {number}: signed by a key that is not trusted ({key_id})", signed
            if not _signature_ok(keys, key_id, _entry_message(key_id, entry["receipt_id"]), signature):
                return f"entry {number}: its signature does not verify", signed
            why = position_allowed(keys, key_id, number, entries)
            if why:
                return f"entry {number}: {why}", signed
            signed += 1
        elif key_id is None and signature is None:
            if require:
                return f"entry {number}: not signed", signed
            if signed:
                return f"entry {number}: unsigned after signed entries (signatures stripped, or signing switched off)", signed
        else:
            return f"entry {number}: a key id without a signature, or the reverse", signed
    return None, signed


def check_anchors(entries: List[Dict[str, Any]], text: str, keys: Optional[TrustedKeys],
                  require: bool) -> Tuple[Optional[str], int, int]:
    """Returns (problem, records checked, the largest count any record vouches for)."""
    signed_seen, checked, covered = False, 0, 0
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        try:
            record = _load_json_line(line)
        except ValueError as exc:
            return f"anchor line {number}: {exc}", checked, covered
        if not isinstance(record, dict):
            return f"anchor line {number} is malformed", checked, covered
        count = record.get("count")
        count = count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else 0
        head = record.get("head_receipt_id")
        head = head if isinstance(head, str) else ""
        if record.get("version") != ANCHOR_V1 or count == 0 or not head:
            return f"anchor line {number} is malformed", checked, covered
        if keys is not None:
            key_id, signature = record.get("key_id"), record.get("signature")
            key_id = key_id if isinstance(key_id, str) else None
            signature = signature if isinstance(signature, str) else None
            if key_id is not None and signature is not None:
                if key_id not in keys:
                    return f"anchor line {number}: signed by a key that is not trusted ({key_id})", checked, covered
                if not _signature_ok(keys, key_id, _anchor_message(key_id, count, head), signature):
                    return f"anchor line {number}: its signature does not verify", checked, covered
                why = position_allowed(keys, key_id, count, entries)  # the anchor vouches for entries 1..count
                if why:
                    return f"anchor line {number}: {why}", checked, covered
                signed_seen = True
            elif key_id is None and signature is None:
                if require:
                    return f"anchor line {number}: not signed", checked, covered
                if signed_seen:
                    return f"anchor line {number}: unsigned after signed ones", checked, covered
            else:
                return f"anchor line {number}: a key id without a signature, or the reverse", checked, covered
        if count > len(entries):
            return (f"the log has {len(entries)} entries but an anchor expects at least {count}: "
                    "entries were deleted"), checked, covered
        if entries[count - 1]["receipt_id"] != head:
            return f"entry {count} does not match its anchor: the log was rewritten", checked, covered
        checked += 1
        covered = max(covered, count)
    return None, checked, covered


def verify(log_text: str, anchor_text: Optional[str] = None, trusted_keys_text: Optional[str] = None,
           require_signatures: bool = False) -> Dict[str, Any]:
    """Run every check. Returns a report; `report["ok"]` is the verdict. Raises Problem for unreadable input."""
    if require_signatures and trusted_keys_text is None:
        raise Problem("--require-signatures needs --trusted-keys")
    entries = read_log(log_text)
    keys = read_trusted_keys(trusted_keys_text) if trusted_keys_text is not None else None
    errors: List[str] = []
    warnings: List[str] = []

    chain = check_chain(entries)
    if chain:
        errors.append(chain)

    anchor_records, anchor_covers = 0, 0
    if anchor_text is not None:
        problem, anchor_records, anchor_covers = check_anchors(entries, anchor_text, keys, require_signatures)
        if problem:
            errors.append(problem)
        elif anchor_records == 0:
            warnings.append("the anchor file has no records, so nothing was checked against it")
        elif anchor_covers < len(entries):
            warnings.append(f"the newest anchor covers {anchor_covers} of {len(entries)} entries: the last "
                            f"{len(entries) - anchor_covers} are not anchored yet")
    else:
        warnings.append("no anchor was given: deleting the newest entries (a rollback) cannot be detected")

    signed = 0
    if keys is not None:
        problem, signed = check_signatures(entries, keys, require_signatures)
        if problem:
            errors.append(problem)
        elif entries and signed == 0:
            warnings.append(f"none of the {len(entries)} entries are signed, so authenticity is NOT checked")
        elif signed < len(entries):
            warnings.append(f"{len(entries) - signed} entries are unsigned and nothing requires them to be")
    else:
        carrying = sum(1 for e in entries if e["signature"] is not None)
        warnings.append("no trusted keys were given, so signatures were not checked"
                        + (f" ({carrying} entries carry one)" if carrying else ""))

    answered = {e["decision_receipt_id"] for e in entries if e["kind"] == "outcome"}
    open_allows = sum(1 for e in entries if e["kind"] == "decision" and e["verdict"] == "allow"
                      and e["receipt_id"] not in answered)
    if open_allows:
        warnings.append(f"{open_allows} allowed calls have no outcome: still in flight, or never finished")
    extras = sum(1 for e in entries if e["extra"])
    if extras:
        warnings.append(f"{extras} entries carry fields the hash does not cover (for example "
                        f"{entries[next(i for i, e in enumerate(entries) if e['extra'])]['extra'][0]!r}): "
                        "the kernel accepts them, but they prove nothing")

    decisions = sum(1 for e in entries if e["kind"] == "decision")
    verdicts: Dict[str, int] = {}
    for e in entries:
        if e["kind"] == "decision":
            verdicts[e["verdict"]] = verdicts.get(e["verdict"], 0) + 1
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "entries": len(entries),
        "decisions": decisions,
        "outcomes": len(entries) - decisions,
        "verdicts": verdicts,
        "allows_without_outcome": open_allows,
        "signed_entries": signed,
        "anchor_records": anchor_records,
        "anchor_covers_entries": anchor_covers,
        "head_receipt_id": entries[-1]["receipt_id"] if entries else None,
    }


LIMITS = """\
What this does and does not show
  - It shows the entries are unchanged since they were written, in order, with none inserted or
    removed in the middle (and none cut from the end, if the anchor you gave is genuine and current).
  - With trusted keys, it shows each entry was signed by a holder of a key you chose to trust.
  - It does NOT show that what was done matched what was asked. A receipt may carry a call_digest;
    that field is covered by the hash when it is present. This program does not recompute the digest
    from a call, and it does not read a witness log. An outcome is still the caller's claim. It does
    not show that the clock was right, or that a signing key was never stolen. An empty or unsigned
    log can still "verify".
  - The anchor and the trusted keys must come from somewhere the log's writer cannot edit. A copy that
    sits next to the log proves nothing about deleted entries."""


def render(report: Dict[str, Any]) -> str:
    lines = []
    if report["ok"]:
        lines.append(f"VERIFIED: {report['entries']} entries ({report['decisions']} decisions, "
                     f"{report['outcomes']} outcomes)")
    else:
        lines.append("NOT VERIFIED")
        lines += [f"  problem: {e}" for e in report["errors"]]
    if report["entries"]:
        lines.append("  verdicts: " + ", ".join(f"{n} {v}" for v, n in sorted(report["verdicts"].items())))
        lines.append(f"  signed entries: {report['signed_entries']}; anchor records checked: {report['anchor_records']}")
        lines.append(f"  newest entry: {report['head_receipt_id']}")
    lines += [f"  note: {w}" for w in report["warnings"]]
    lines += ["", LIMITS]
    return "\n".join(lines)


def _read(path: str, what: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise Problem(f"cannot read the {what} ({path}): {exc}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="ickverify", description=__doc__.split("\n\n")[0])
    parser.add_argument("log", help="the receipt log (JSON lines)")
    parser.add_argument("--anchor", help="an anchor file you obtained yourself, from a copy the log's writer cannot edit")
    parser.add_argument("--trusted-keys", help="a file of ed25519-public:<hex> lines you chose to trust")
    parser.add_argument("--require-signatures", action="store_true",
                        help="every entry and anchor record must be signed (needs --trusted-keys)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)
    try:
        report = verify(
            _read(args.log, "log"),
            _read(args.anchor, "anchor") if args.anchor else None,
            _read(args.trusted_keys, "trusted keys") if args.trusted_keys else None,
            args.require_signatures,
        )
    except Problem as exc:
        print(f"cannot check: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
