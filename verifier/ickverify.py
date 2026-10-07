#!/usr/bin/env python3
"""Check an Infinity receipt log without trusting Nova, the kernel binary, or anything else that wrote it.

    python ickverify.py LOG [--anchor ANCHOR] [--trusted-keys KEYS] [--require-signatures]
        [--call CALL.json] [--witness-log WITNESS] [--witness-keys KEYS] [--json]

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
  * It does NOT show that what was done matched what was asked, in the sense of observed effect.
    When you pass ``--call``, it recomputes ``call_digest`` from that concrete call and fails if
    the allow's digest was forged or omitted. It cannot invent the call from a digest. With
    ``--witness-log`` it joins executions to allows. It does not show that the clock was right,
    or that a signing key was never stolen.

Exit status: 0 verified, 1 not verified, 2 the inputs could not be read.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

RECEIPT_V1 = "infinity.receipt.v1"
RECEIPT_V2 = "infinity.receipt.v2"
OUTCOME_V1 = "infinity.outcome.v1"
ANCHOR_V1 = "infinity.anchor.v1"
WITNESS_EXECUTION = "infinity.witness.execution.v1"
WITNESS_DIVERGENCE = "infinity.witness.divergence.v1"
_CALL_PREFIX = b"wicket-call/v1\n"
ENTRY_DOMAIN = "infinity-core/entry/v1"
ANCHOR_DOMAIN = "infinity-core/anchor/v1"
PUBLIC_PREFIX = "ed25519-public:"
SIGNATURE_PREFIX = "ed25519:"

# Fields each entry kind is built from. Anything else in a line is not covered by the entry's hash.
RECEIPT_FIELDS = {"version", "receipt_id", "previous_receipt_hash", "proposal_hash", "policy_hash",
                  "decision_hash", "verdict", "reason_codes", "issued_at", "call_digest", "caller_id",
                  "key_id", "signature"}
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
        if "caller_id" in raw:
            caller_id = raw["caller_id"]
            if not isinstance(caller_id, str):
                raise ValueError("caller_id must be text")
            fields["caller_id"] = caller_id
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
            if "caller_id" in entry:
                material["caller_id"] = entry["caller_id"]
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


# --- call_digest, a second implementation of runtime/call_binding.py (stdlib only) ------------
#
# This does not import the runtime. The two are checked against each other. It recomputes a
# digest only from a call you supply. A digest alone is not enough to rebuild the call.

class CallShapeError(Exception):
    """The supplied call is not a shape this verifier can digest."""


_HTTPS_KEYS = {
    "shape", "method", "scheme", "host", "port", "path", "query", "headers",
    "authorization_present", "body", "body_b64",
}
_TOOL_KEYS = {"shape", "tool", "arguments"}
_READ_METHODS = {"GET", "HEAD"}
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_HEADER_NAMES = ("content-type", "content-encoding", "authorization")


def _length_prefixed(parts: List[bytes]) -> bytes:
    out = bytearray()
    for part in parts:
        if len(part) > 0xFFFFFFFF:
            raise CallShapeError("a call field is too long to bind")
        out += len(part).to_bytes(4, "big")
        out += part
    return _CALL_PREFIX + bytes(out)


def _call_text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise CallShapeError(f"{what} must be text")
    return value


def _call_headers(raw: Any) -> Dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise CallShapeError("headers must be an object")
    found: Dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise CallShapeError("header names and values must be text")
        name = key.lower()
        if name not in _HEADER_NAMES or name in found:
            raise CallShapeError("unknown or repeated header")
        if value == "" or any(char in value for char in "\r\n"):
            raise CallShapeError("empty or broken header value")
        found[name] = value
    return found


def _call_body(call: Dict[str, Any]) -> bytes:
    has_text, has_b64 = "body" in call, "body_b64" in call
    if has_text and has_b64:
        raise CallShapeError("send body or body_b64, not both")
    if has_text:
        text = call["body"]
        if not isinstance(text, str):
            raise CallShapeError("body must be text")
        return text.encode("utf-8")
    if has_b64:
        encoded = call["body_b64"]
        if not isinstance(encoded, str):
            raise CallShapeError("body_b64 must be text")
        try:
            return base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise CallShapeError("body_b64 is not base64") from exc
    return b""


def _caller_bytes(caller_id: str) -> bytes:
    if not isinstance(caller_id, str) or caller_id == "" or any(char in caller_id for char in "\r\n\x00"):
        raise CallShapeError("caller id must be text")
    return caller_id.encode("utf-8")


def call_digest(call: Any, caller_id: str) -> str:
    """``sha256:<64 hex>`` over the same bytes ``runtime/call_binding.py`` hashes.

    ``caller_id`` is the second length-prefixed field of both shapes. Raises CallShapeError
    for a shape, field, or encoding that implementation refuses, including a missing caller id.
    """
    if not isinstance(call, dict):
        raise CallShapeError("call must be an object")
    shape = call.get("shape")
    if shape == "https_request":
        if set(call) - _HTTPS_KEYS:
            raise CallShapeError("https_request has a field this registry does not know")
        method = _call_text(call.get("method"), "method").upper()
        if method not in _READ_METHODS and method not in _WRITE_METHODS:
            raise CallShapeError("method is not one this registry derives")
        scheme = _call_text(call.get("scheme"), "scheme").lower()
        if scheme not in ("http", "https"):
            raise CallShapeError("scheme must be http or https")
        host = _call_text(call.get("host"), "host")
        if any(char in host for char in ":/?#@ \t\r\n"):
            raise CallShapeError("host is not a name this registry can bind")
        host = host.lower()
        port = call.get("port")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise CallShapeError("port must be an integer from 1 to 65535")
        path = _call_text(call.get("path"), "path")
        if not path.startswith("/") or any(char in path for char in "?# \t\r\n"):
            raise CallShapeError("path must start with / and carry no query")
        query = call.get("query", "")
        if not isinstance(query, str) or any(char in query for char in "?# \t\r\n"):
            raise CallShapeError("query must be text without a leading ?")
        headers = _call_headers(call.get("headers"))
        present = call.get("authorization_present", False)
        if not isinstance(present, bool):
            raise CallShapeError("authorization_present must be true or false")
        if present != ("authorization" in headers):
            raise CallShapeError("authorization presence does not match the header")
        parts = [
            b"https_request", _caller_bytes(caller_id), method.encode("utf-8"), scheme.encode("utf-8"),
            host.encode("utf-8"),
            str(port).encode("ascii"), path.encode("utf-8"), query.encode("utf-8"),
            headers.get("content-type", "").encode("utf-8"),
            headers.get("content-encoding", "").encode("utf-8"),
            b"1" if present else b"0", _call_body(call),
        ]
    elif shape == "local_model_tool":
        if set(call) - _TOOL_KEYS:
            raise CallShapeError("local_model_tool has a field this registry does not know")
        tool = _call_text(call.get("tool"), "tool")
        if any(char in tool for char in ":/?# \t\r\n"):
            raise CallShapeError("tool name cannot be bound")
        if tool not in ("explain", "status", "code", "wire"):
            raise CallShapeError("tool is not one this registry derives")
        arguments = call.get("arguments")
        if not isinstance(arguments, dict):
            raise CallShapeError("arguments must be an object")
        try:
            encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise CallShapeError("arguments are not JSON") from exc
        parts = [
            b"local_model_tool", _caller_bytes(caller_id), tool.encode("utf-8"), encoded.encode("utf-8"),
        ]
    else:
        raise CallShapeError("call shape is not in the registry")
    return "sha256:" + hashlib.sha256(_length_prefixed(parts)).hexdigest()


def read_call_binds(text: str) -> List[Dict[str, Any]]:
    """``{"receipt_id", "call"}`` or a list of those. The call is not stored in the receipt log."""
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise Problem(f"the call file is not JSON: {exc}") from exc
    if isinstance(raw, dict) and "call" in raw:
        items: Any = [raw]
    elif isinstance(raw, list):
        items = raw
    else:
        raise Problem("the call file must be {receipt_id, call} or a list of those")
    binds = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("receipt_id"), str) or "call" not in item:
            raise Problem("each call binding needs receipt_id and call")
        bind = {"receipt_id": item["receipt_id"], "call": item["call"]}
        if "caller_id" in item:
            bind["caller_id"] = item["caller_id"]
        binds.append(bind)
    return binds


def _witness_material(entry: Dict[str, Any]) -> Dict[str, Any]:
    material = {
        "version": entry["version"],
        "previous_receipt_hash": entry["previous_receipt_hash"],
        "allow_receipt_id": entry["allow_receipt_id"],
        "call_digest": entry["call_digest"],
        "attempt": entry["attempt"],
        "status": entry["status"],
        "divergence": entry["divergence"],
        "issued_at": entry["issued_at"],
    }
    if entry.get("caller_id") is not None:
        material["caller_id"] = entry["caller_id"]
    return material


def parse_witness_entry(line: str) -> Dict[str, Any]:
    raw = _load_json_line(line)
    if not isinstance(raw, dict):
        raise ValueError("a witness entry must be a JSON object")
    attempt = raw.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int):
        raise ValueError("attempt must be an integer")
    return {
        "version": _req_str(raw, "version"),
        "receipt_id": _req_str(raw, "receipt_id"),
        "previous_receipt_hash": _opt_str(raw, "previous_receipt_hash"),
        "allow_receipt_id": _opt_str(raw, "allow_receipt_id"),
        "call_digest": _opt_str(raw, "call_digest"),
        "caller_id": _opt_str(raw, "caller_id"),
        "attempt": attempt,
        "status": _opt_str(raw, "status"),
        "divergence": _opt_str(raw, "divergence"),
        "issued_at": _req_str(raw, "issued_at"),
        "key_id": _opt_str(raw, "key_id"),
        "signature": _opt_str(raw, "signature"),
    }


def read_witness_log(text: str) -> List[Dict[str, Any]]:
    entries = []
    for number, line in enumerate(_lines(text), 1):
        if not line.strip():
            continue
        try:
            entries.append(parse_witness_entry(line))
        except ValueError as exc:
            raise Problem(f"witness log line {number}: {exc}")
    return entries


def read_witness_keys(text: str) -> TrustedKeys:
    """Trusted witness keys. A ``through`` cutoff is refused, matching ``witness-verify``."""
    keys = read_trusted_keys(text)
    if keys.cutoffs:
        raise Problem("witness-verify does not honor `through` cutoffs; refusing a key file that uses them")
    return keys


def check_witness_chain(entries: List[Dict[str, Any]]) -> Optional[str]:
    for index, entry in enumerate(entries):
        number = index + 1
        if entry["version"] not in (WITNESS_EXECUTION, WITNESS_DIVERGENCE):
            return f"witness entry {number}: unknown version"
        expected = "witness:" + hash_value(_witness_material(entry))
        if entry["receipt_id"] != expected:
            return f"witness entry {number}: its id does not match its contents"
        previous = entries[index - 1]["receipt_id"] if index else None
        if entry["previous_receipt_hash"] != previous:
            return f"witness entry {number}: it does not follow the entry before it"
    return None


def check_witness_signatures(entries: List[Dict[str, Any]], keys: TrustedKeys) -> Optional[str]:
    for index, entry in enumerate(entries):
        number = index + 1
        key_id, signature = entry["key_id"], entry["signature"]
        if key_id is None or signature is None:
            return f"witness entry {number}: not signed"
        if key_id not in keys:
            return f"witness entry {number}: signed by a key that is not trusted ({key_id})"
        if not _signature_ok(keys, key_id, _entry_message(key_id, entry["receipt_id"]), signature):
            return f"witness entry {number}: its signature does not verify"
    return None


def _decision_by_id(entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    found = {}
    for entry in entries:
        if entry["kind"] == "decision":
            found[entry["receipt_id"]] = entry
    return found


def call_bind_problems(entries: List[Dict[str, Any]], binds: List[Dict[str, Any]],
                       witness_entries: Optional[List[Dict[str, Any]]]) -> List[str]:
    """Forged or omitted digests, and execution digests that disagree with the recomputed call."""
    problems = []
    decisions = _decision_by_id(entries)
    executions = [row for row in (witness_entries or []) if row["version"] == WITNESS_EXECUTION]
    for bind in binds:
        receipt_id, call = bind["receipt_id"], bind["call"]
        decision = decisions.get(receipt_id)
        if decision is None:
            problems.append(f"call for {receipt_id} does not name a receipt in this log")
            continue
        caller_id = decision.get("caller_id")
        if "call_digest" not in decision:
            problems.append(f"omitted call_digest: bound call has no call_digest on the allow {receipt_id}")
        if not isinstance(caller_id, str) or caller_id == "":
            problems.append(f"omitted caller id: bound call has no caller id on the allow {receipt_id}")
            continue
        stated_caller = bind.get("caller_id")
        if stated_caller is not None and stated_caller != caller_id:
            problems.append(f"forged caller id: receipt {receipt_id} does not match the caller on the call")
        try:
            digest = call_digest(call, caller_id)
        except CallShapeError as exc:
            problems.append(f"call for {receipt_id} is not a known shape ({exc})")
            continue
        if "call_digest" in decision and decision["call_digest"] != digest:
            problems.append(f"forged call_digest: receipt {receipt_id} does not match the concrete call")
        for row in executions:
            if row.get("allow_receipt_id") != receipt_id:
                continue
            if row.get("call_digest") != digest:
                problems.append(
                    f"mismatch: execution digest does not match the recomputed call for {receipt_id}"
                )
            if row.get("caller_id") != caller_id:
                problems.append(
                    f"forged caller id: execution for {receipt_id} does not match the allow"
                )
    return problems


def witness_join_problems(entries: List[Dict[str, Any]], witness_entries: List[Dict[str, Any]]) -> List[str]:
    """Join by allow receipt id. Late is whatever the witness recorded; this invents no clock."""
    problems = []
    decisions = _decision_by_id(entries)
    started: Dict[str, int] = {}
    executed = set()
    for row in witness_entries:
        allow_id = row.get("allow_receipt_id")
        if row["version"] == WITNESS_DIVERGENCE:
            kind = row.get("divergence")
            if kind == "mismatch":
                problems.append(f"mismatch: divergence for {allow_id}")
            elif kind == "unauthorized":
                problems.append(f"unauthorized: divergence for {allow_id}")
            elif kind == "reused":
                problems.append(f"reused: divergence for {allow_id}")
            elif kind == "late":
                problems.append(f"late: divergence for {allow_id}")
            elif kind == "IDENTITY_UNVERIFIED":
                problems.append(f"IDENTITY_UNVERIFIED: divergence for {allow_id}")
            elif kind == "AUTHORITY_DENIED":
                problems.append(f"AUTHORITY_DENIED: divergence for {allow_id}")
            else:
                problems.append(f"witness divergence {kind!r} for {allow_id}")
            continue
        if row["version"] != WITNESS_EXECUTION:
            continue
        if row.get("status") == "started":
            if isinstance(allow_id, str):
                started[allow_id] = started.get(allow_id, 0) + 1
                executed.add(allow_id)
        decision = decisions.get(allow_id) if isinstance(allow_id, str) else None
        if decision is None or decision.get("verdict") != "allow":
            problems.append(f"unauthorized: execution with no allow ({allow_id})")
            continue
        allow_digest = decision.get("call_digest")
        if allow_digest is None or row.get("call_digest") != allow_digest:
            problems.append(f"mismatch: execution digest differs from the allow {allow_id}")
        allow_caller = decision.get("caller_id")
        if isinstance(allow_caller, str) and row.get("caller_id") != allow_caller:
            problems.append(f"forged caller id: execution for {allow_id} does not match the allow")
    for allow_id, count in started.items():
        if count > 1:
            problems.append(f"reused: allow {allow_id} has more than one execution")
    for entry in entries:
        if entry["kind"] != "decision" or entry.get("verdict") != "allow" or "call_digest" not in entry:
            continue
        if entry["receipt_id"] not in executed:
            problems.append(f"missing execution: bound allow {entry['receipt_id']} has no execution")
    return problems


def verify(log_text: str, anchor_text: Optional[str] = None, trusted_keys_text: Optional[str] = None,
           require_signatures: bool = False, call_text: Optional[str] = None,
           witness_log_text: Optional[str] = None, witness_keys_text: Optional[str] = None) -> Dict[str, Any]:
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

    witness_entries: Optional[List[Dict[str, Any]]] = None
    if witness_log_text is not None:
        witness_entries = read_witness_log(witness_log_text)
        chain_problem = check_witness_chain(witness_entries)
        if chain_problem:
            errors.append(chain_problem)
        if witness_keys_text is not None:
            witness_keys = read_witness_keys(witness_keys_text)
            signature_problem = check_witness_signatures(witness_entries, witness_keys)
            if signature_problem:
                errors.append(signature_problem)
        else:
            warnings.append("no witness keys were given, so witness signatures were not checked")
        errors.extend(witness_join_problems(entries, witness_entries))
    if call_text is not None:
        errors.extend(call_bind_problems(entries, read_call_binds(call_text), witness_entries))

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
        "witness_entries": None if witness_entries is None else len(witness_entries),
    }


LIMITS = """\
What this does and does not show
  - It shows the entries are unchanged since they were written, in order, with none inserted or
    removed in the middle (and none cut from the end, if the anchor you gave is genuine and current).
  - With trusted keys, it shows each entry was signed by a holder of a key you chose to trust.
  - It does NOT show that what was done matched what was asked. Observed effect is not proved.
    A receipt may carry a call_digest; that field is covered by the hash when it is present.
    With --call, this program recomputes the digest from the concrete call you supply and fails
    if the allow's digest was forged or omitted. It cannot invent the call from a digest alone.
    The receipt log and the witness log do not store the call body. With --witness-log it joins
    executions to allows (mismatch, unauthorized, reused, late, missing execution) and reports
    divergence entries of those kinds. It does not apply `through` cutoffs to the witness log;
    a witness key file that uses one is refused. It does not require a heartbeat. An outcome on
    the receipt log is still the caller's claim. It does not show that the clock was right, or
    that a signing key was never stolen. An empty or unsigned log can still "verify".
  - The anchor and the trusted keys must come from somewhere the log's writer cannot edit. A copy that
    sits next to the log proves nothing about deleted entries. Witness keys are the same: they are
    not taken from the witness log."""


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
    parser.add_argument("--call", help="JSON file of {receipt_id, call} bindings; the digest is recomputed from each call")
    parser.add_argument("--witness-log", help="the witness log to join to allows by receipt id")
    parser.add_argument("--witness-keys", help="ed25519-public keys for the witness log; `through` cutoffs are refused")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)
    try:
        report = verify(
            _read(args.log, "log"),
            _read(args.anchor, "anchor") if args.anchor else None,
            _read(args.trusted_keys, "trusted keys") if args.trusted_keys else None,
            args.require_signatures,
            _read(args.call, "call file") if args.call else None,
            _read(args.witness_log, "witness log") if args.witness_log else None,
            _read(args.witness_keys, "witness keys") if args.witness_keys else None,
        )
    except Problem as exc:
        print(f"cannot check: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else render(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
