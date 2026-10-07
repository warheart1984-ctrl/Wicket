"""Caller tokens. An Ed25519 signature over the caller id, an expiry, a token id, and the call digest.

The signer and the witness both check this. The caller id that is recorded is the id in the
caller key file for the signing key, not the caller id string inside the token. The digest is
computed with that key-file id before the signature is checked, so a token cannot be moved
onto a different call or a different caller.

The header value is ``Authorization: Wicket <token>``. That is the credential presented to
the signer and the witness. It is not the Authorization value sent to the target, and it is
not hashed. The verified caller id is what the call digest covers.

Used token ids are stored in a file next to the witness log. A new witness object against the
same log directory still sees them. The clock compared with ``exp`` is the witness clock, and
it is not proven.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from runtime.call_binding import UnknownCallShape, derive

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_TOKEN_DOMAIN = b"wicket-caller/v1\n"
_HEADER = "Wicket "
_JTI = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRIVATE_PREFIX = "ed25519-private:"
_PUBLIC_PREFIX = "ed25519-public:"
KEY_FILE_VERSION = "wicket.caller-keys.v1"
# Signed when the call has no derivable digest. A known shape never accepts this stand-in:
# its signature is checked against the digest of that call.
UNKNOWN_SHAPE_DIGEST = "sha256:" + hashlib.sha256(b"wicket-unknown-shape").hexdigest()

Point = tuple[int, int, int, int]


class CallerTokenError(Exception):
    """The caller key file or a private key cannot be used."""


class IdentityFailure(Exception):
    """The credential is not a verified caller. ``reason`` is a short label."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class VerifiedCaller:
    caller_id: str
    call_digest: str | None
    jti: str
    unbound: bool


def _recover_x(y: int, sign: int) -> int | None:
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


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _recover_x(_BY, 0) or 0
_B: Point = (_BX, _BY, 1, _BX * _BY % _P)
_ZERO: Point = (0, 1, 1, 0)


def _add(a: Point, b: Point) -> Point:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa, bb = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    cc, dd = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    ee, ff, gg, hh = bb - aa, dd - cc, dd + cc, bb + aa
    return (ee * ff % _P, gg * hh % _P, ff * gg % _P, ee * hh % _P)


def _mul(scalar: int, point: Point) -> Point:
    result = _ZERO
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _neg(point: Point) -> Point:
    return ((-point[0]) % _P, point[1], point[2], (-point[3]) % _P)


def _compress(point: Point) -> bytes:
    inverse = pow(point[2], _P - 2, _P)
    x, y = point[0] * inverse % _P, point[1] * inverse % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(raw: bytes) -> Point | None:
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _small_order(point: Point) -> bool:
    x, y, z, _ = _mul(8, point)
    return x % _P == 0 and (y - z) % _P == 0


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 verify, with the strictness the kernel uses for receipt signatures."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    point_a = _decompress(public_key)
    r_bytes, s_scalar = signature[:32], int.from_bytes(signature[32:], "little")
    point_r = _decompress(r_bytes)
    if (
        point_a is None
        or point_r is None
        or s_scalar >= _L
        or _small_order(point_a)
        or _small_order(point_r)
    ):
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _L
    check = _add(_mul(s_scalar, _B), _neg(_mul(k, point_a)))
    return _compress(check) == r_bytes


def _clamp(prefix: bytes) -> int:
    scalar = bytearray(prefix)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return int.from_bytes(scalar, "little")


def public_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise CallerTokenError("an Ed25519 seed is 32 bytes")
    digest = hashlib.sha512(seed).digest()
    return _compress(_mul(_clamp(digest[:32]), _B))


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise CallerTokenError("an Ed25519 seed is 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = _clamp(digest[:32])
    public = _compress(_mul(scalar, _B))
    nonce = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % _L
    point_r = _compress(_mul(nonce, _B))
    challenge = int.from_bytes(hashlib.sha512(point_r + public + message).digest(), "little") % _L
    signature_s = (nonce + challenge * scalar) % _L
    return point_r + signature_s.to_bytes(32, "little")


def load_seed(text: str) -> bytes:
    raw = text.strip()
    if not raw.startswith(_PRIVATE_PREFIX):
        raise CallerTokenError("expected ed25519-private:<64 hex>")
    hex_text = raw[len(_PRIVATE_PREFIX):]
    try:
        seed = bytes.fromhex(hex_text)
    except ValueError as exc:
        raise CallerTokenError("the private key is not hex") from exc
    if len(seed) != 32:
        raise CallerTokenError("an Ed25519 seed is 32 bytes")
    return seed


def load_caller_keys(text: str) -> dict[bytes, str]:
    """Public key bytes to the caller id in the key file. Duplicate keys or ids are refused."""
    try:
        raw = json.loads(text)
    except ValueError as exc:
        raise CallerTokenError("the caller key file is not JSON") from exc
    if not isinstance(raw, dict) or raw.get("version") != KEY_FILE_VERSION:
        raise CallerTokenError("the caller key file version is not recognized")
    rows = raw.get("keys")
    if not isinstance(rows, list) or not rows:
        raise CallerTokenError("the caller key file has no keys")
    found: dict[bytes, str] = {}
    seen_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise CallerTokenError("a caller key entry must be an object")
        caller_id = row.get("caller_id")
        public = row.get("public_key")
        if not isinstance(caller_id, str) or caller_id == "" or any(c in caller_id for c in "\r\n\x00"):
            raise CallerTokenError("a caller id must be text")
        if not isinstance(public, str) or not public.startswith(_PUBLIC_PREFIX):
            raise CallerTokenError("a caller public key must be ed25519-public:<64 hex>")
        try:
            key = bytes.fromhex(public[len(_PUBLIC_PREFIX):])
        except ValueError as exc:
            raise CallerTokenError("a caller public key is not hex") from exc
        if len(key) != 32 or caller_id in seen_ids or key in found:
            raise CallerTokenError("caller ids and public keys must be unique")
        found[key] = caller_id
        seen_ids.add(caller_id)
    return found


def caller_id_for_seed(keys_text: str, seed: bytes) -> str:
    keys = load_caller_keys(keys_text)
    caller_id = keys.get(public_from_seed(seed))
    if caller_id is None:
        raise CallerTokenError("this private key is not in the caller key file")
    return caller_id


def token_message(caller_id: str, exp: int, jti: str, call_digest: str, public_hex: str) -> bytes:
    """Length-prefixed fields the signature covers. The caller id here is the one in the token."""
    parts = [
        caller_id.encode("utf-8"),
        str(exp).encode("ascii"),
        jti.encode("ascii"),
        call_digest.encode("ascii"),
        public_hex.encode("ascii"),
    ]
    out = bytearray(_TOKEN_DOMAIN)
    for part in parts:
        out += len(part).to_bytes(4, "big")
        out += part
    return bytes(out)


def mint(seed: bytes, caller_id: str, call_digest: str, *, exp: int, jti: str) -> str:
    """``Wicket <token>`` signed by ``seed``. ``caller_id`` is what the token claims."""
    if not _JTI.fullmatch(jti) or not _DIGEST.fullmatch(call_digest):
        raise CallerTokenError("token id or digest is not usable")
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise CallerTokenError("exp must be a unix second")
    public_hex = public_from_seed(seed).hex()
    signature = sign(seed, token_message(caller_id, exp, jti, call_digest, public_hex))
    body = {
        "call_digest": call_digest,
        "caller_id": caller_id,
        "exp": exp,
        "jti": jti,
        "public_key": public_hex,
        "sig": signature.hex(),
    }
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    token = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return _HEADER + token


def digest_for(call: Any, caller_id: str) -> tuple[str | None, bool]:
    """``(digest, unbound)``. An unknown shape is unbound and has no call digest."""
    try:
        return derive(call, caller_id).call_digest, False
    except UnknownCallShape:
        return None, True


def mint_for_call(
    private_text: str,
    keys_text: str,
    call: Any,
    *,
    now: float,
    claimed_caller_id: str | None = None,
    exp: int | None = None,
    jti: str | None = None,
    call_digest: str | None = None,
) -> str:
    """A token for ``call``. The digest uses the key file's caller id unless one is supplied."""
    seed = load_seed(private_text)
    file_caller = caller_id_for_seed(keys_text, seed)
    claimed = file_caller if claimed_caller_id is None else claimed_caller_id
    if call_digest is None:
        # Honest tokens cover the digest of the key-file caller id. A test that claims another
        # id passes call_digest itself, so the signature covers the digest that attack chose.
        derived, unbound = digest_for(call, file_caller)
        call_digest = UNKNOWN_SHAPE_DIGEST if unbound or derived is None else derived
    return mint(
        seed,
        claimed,
        call_digest,
        exp=int(now) + 7 * 24 * 3600 if exp is None else exp,
        jti=uuid.uuid4().hex if jti is None else jti,
    )


def _b64_json(token: str) -> Any:
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise IdentityFailure("malformed") from exc
    if not isinstance(body, dict):
        raise IdentityFailure("malformed")
    return body


def _parsed(authorization: str | None) -> dict[str, Any]:
    if authorization is None or authorization == "":
        raise IdentityFailure("missing")
    if not isinstance(authorization, str) or not authorization.startswith(_HEADER):
        raise IdentityFailure("malformed")
    token = authorization[len(_HEADER):]
    if token == "" or any(char in token for char in " \t\r\n"):
        raise IdentityFailure("malformed")
    body = _b64_json(token)
    caller_id = body.get("caller_id")
    exp = body.get("exp")
    jti = body.get("jti")
    call_digest = body.get("call_digest")
    public_key = body.get("public_key")
    signature = body.get("sig")
    if (
        not isinstance(caller_id, str)
        or caller_id == ""
        or not isinstance(jti, str)
        or _JTI.fullmatch(jti) is None
        or not isinstance(call_digest, str)
        or _DIGEST.fullmatch(call_digest) is None
        or not isinstance(public_key, str)
        or len(public_key) != 64
        or not isinstance(signature, str)
        or len(signature) != 128
        or isinstance(exp, bool)
        or not isinstance(exp, int)
    ):
        raise IdentityFailure("malformed")
    try:
        public = bytes.fromhex(public_key)
        sig = bytes.fromhex(signature)
    except ValueError as exc:
        raise IdentityFailure("malformed") from exc
    if len(public) != 32 or len(sig) != 64:
        raise IdentityFailure("malformed")
    return {
        "caller_id": caller_id,
        "exp": exp,
        "jti": jti,
        "call_digest": call_digest,
        "public": public,
        "public_hex": public_key,
        "signature": sig,
    }


def verify_authorization(
    authorization: str | None,
    call: Any,
    keys: Mapping[bytes, str],
    *,
    now: float,
    ledger: "TokenLedger | None" = None,
) -> VerifiedCaller:
    """Check the token against ``call`` using the caller id from ``keys``.

    The digest is computed from the key file's caller id first. The signature has to match
    that digest. A token that claims a different caller id is refused after that check.
    """
    parsed = _parsed(authorization)
    file_caller = keys.get(parsed["public"])
    if file_caller is None:
        raise IdentityFailure("unknown-key")
    derived, unbound = digest_for(call, file_caller)
    signed_digest = parsed["call_digest"] if unbound or derived is None else derived
    message = token_message(
        parsed["caller_id"], parsed["exp"], parsed["jti"], signed_digest, parsed["public_hex"]
    )
    if not ed25519_verify(parsed["public"], message, parsed["signature"]):
        raise IdentityFailure("signature")
    if parsed["caller_id"] != file_caller:
        raise IdentityFailure("caller-mismatch")
    if now > parsed["exp"]:
        raise IdentityFailure("expired")
    if ledger is not None and not ledger.commit(parsed["jti"]):
        raise IdentityFailure("replay")
    return VerifiedCaller(
        caller_id=file_caller,
        call_digest=None if unbound else derived,
        jti=parsed["jti"],
        unbound=unbound,
    )


class TokenLedger:
    """Token ids that have already been accepted. The file survives a new Witness object."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def commit(self, jti: str) -> bool:
        """Record ``jti``. False when it was already there or the file cannot be written."""
        if _JTI.fullmatch(jti) is None:
            return False
        with self._lock:
            try:
                if self.path.is_file():
                    existing = self.path.read_text(encoding="utf-8").splitlines()
                    if jti in existing:
                        return False
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(jti + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError:
                return False
        return True


def ledger_path_for(witness_log: Path) -> Path:
    """The durable token-id file next to the witness log."""
    log = Path(witness_log)
    return log.parent / (log.name + ".token-ids")


def present_authorization(call: Any, *, now: float | None = None) -> str | None:
    """Mint a token from ``WICKET_CALLER_KEY`` and ``WICKET_CALLER_KEYS``, or return None."""
    private_path = os.environ.get("WICKET_CALLER_KEY", "").strip()
    keys_path = os.environ.get("WICKET_CALLER_KEYS", "").strip()
    if not private_path or not keys_path:
        return None
    try:
        private_text = Path(private_path).read_text(encoding="utf-8")
        keys_text = Path(keys_path).read_text(encoding="utf-8")
        return mint_for_call(
            private_text,
            keys_text,
            call,
            now=time.time() if now is None else now,
        )
    except (OSError, CallerTokenError, IdentityFailure):
        return None
