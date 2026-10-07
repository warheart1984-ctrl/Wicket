"""Derive effect, target, and call_digest from a concrete call.

Shared by the signer and the witness. ``verifier/ickverify.py`` is a second implementation
of this digest (standard library only; it does not import this module). A bug in either
one is a bypass, which is why tests compare them.

The digest is SHA-256 (``sha256:<64 hex>``), not the SHA3-256 the receipt chain uses. It covers
the call that will be sent. It does not cover what the target does with that call.

Encoding, in order, after the prefix ``wicket-call/v1\\n``. Each field is a 4-byte big-endian
length and then the bytes:

* ``https_request``: shape, method (uppercased), scheme (lowercased), host (lowercased), port
  in decimal, path as sent, query as sent, content-type, content-encoding, authorization
  presence (``1`` or ``0``, never the value), body bytes.
* ``local_model_tool``: shape, tool name, canonical JSON of the arguments (sorted keys, no
  spaces).

The body is the exact bytes that will be sent. This does not decode content-encoding, undo
chunking, or accept a stream. ``body`` is UTF-8 text or ``body_b64`` is the bytes; not both.
An unknown field, an unknown shape, or a header outside content-type, content-encoding, and
authorization is an unknown shape. IPv6 hosts are an unknown shape. GET and HEAD are read;
POST, PUT, PATCH, and DELETE are write; any other method is an unknown shape. For tools,
``explain`` and ``status`` are read; ``code`` and ``wire`` are write.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import urllib.parse
from dataclasses import dataclass
from typing import Any

_PREFIX = b"wicket-call/v1\n"
_HTTPS_KEYS = {
    "shape",
    "method",
    "scheme",
    "host",
    "port",
    "path",
    "query",
    "headers",
    "authorization_present",
    "body",
    "body_b64",
}
_TOOL_KEYS = {"shape", "tool", "arguments"}
_READ_METHODS = {"GET", "HEAD"}
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_READ_TOOLS = {"explain", "status"}
_WRITE_TOOLS = {"code", "wire"}
_HEADER_NAMES = ("content-type", "content-encoding", "authorization")


class UnknownCallShape(Exception):
    """The call is not one this registry can derive. The signer records a deny."""


class BindingError(Exception):
    """The request is not well-formed enough to judge. This is not a recorded deny."""


@dataclass(frozen=True)
class BoundCall:
    effect: str
    target: str
    call_digest: str
    kind: str
    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    tool: str
    arguments_json: str


def _length_prefixed(parts: list[bytes]) -> bytes:
    out = bytearray()
    for part in parts:
        if len(part) > 0xFFFFFFFF:
            raise UnknownCallShape("a call field is too long to bind")
        out += len(part).to_bytes(4, "big")
        out += part
    return _PREFIX + bytes(out)


def _digest(parts: list[bytes]) -> str:
    return "sha256:" + hashlib.sha256(_length_prefixed(parts)).hexdigest()


def _text(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise UnknownCallShape(f"{what} must be text")
    return value


def _https(call: dict[str, Any]) -> BoundCall:
    if set(call) - _HTTPS_KEYS:
        raise UnknownCallShape("https_request has a field this registry does not know")
    method = _text(call.get("method"), "method").upper()
    if method in _READ_METHODS:
        effect = "read"
    elif method in _WRITE_METHODS:
        effect = "write"
    else:
        raise UnknownCallShape("method is not one this registry derives")
    scheme = _text(call.get("scheme"), "scheme").lower()
    if scheme not in ("http", "https"):
        raise UnknownCallShape("scheme must be http or https")
    host = _text(call.get("host"), "host")
    if any(char in host for char in ":/?#@ \t\r\n"):
        raise UnknownCallShape("host is not a name this registry can bind")
    host = host.lower()
    port = call.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise UnknownCallShape("port must be an integer from 1 to 65535")
    path = _text(call.get("path"), "path")
    if not path.startswith("/") or any(char in path for char in "?# \t\r\n"):
        raise UnknownCallShape("path must start with / and carry no query")
    query = call.get("query", "")
    if not isinstance(query, str) or any(char in query for char in "?# \t\r\n"):
        raise UnknownCallShape("query must be text without a leading ?")
    headers = _headers(call.get("headers"))
    present = call.get("authorization_present", False)
    if not isinstance(present, bool):
        raise UnknownCallShape("authorization_present must be true or false")
    if present != ("authorization" in headers):
        raise UnknownCallShape("authorization presence does not match the header")
    body = _body(call)
    content_type = headers.get("content-type", "")
    content_encoding = headers.get("content-encoding", "")
    parts = [
        b"https_request",
        method.encode("utf-8"),
        scheme.encode("utf-8"),
        host.encode("utf-8"),
        str(port).encode("ascii"),
        path.encode("utf-8"),
        query.encode("utf-8"),
        content_type.encode("utf-8"),
        content_encoding.encode("utf-8"),
        b"1" if present else b"0",
        body,
    ]
    url = f"{scheme}://{host}:{port}{path}"
    if query:
        url = f"{url}?{query}"
    send = []
    if content_type:
        send.append(("Content-Type", content_type))
    if content_encoding:
        send.append(("Content-Encoding", content_encoding))
    if present:
        send.append(("Authorization", headers["authorization"]))
    return BoundCall(
        effect=effect,
        target=url,
        call_digest=_digest(parts),
        kind="https_request",
        method=method,
        url=url,
        headers=tuple(send),
        body=body,
        tool="",
        arguments_json="",
    )


def _headers(raw: Any) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise UnknownCallShape("headers must be an object")
    found: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise UnknownCallShape("header names and values must be text")
        name = key.lower()
        if name not in _HEADER_NAMES or name in found:
            raise UnknownCallShape("unknown or repeated header")
        if value == "" or any(char in value for char in "\r\n"):
            raise UnknownCallShape("empty or broken header value")
        found[name] = value
    return found


def _body(call: dict[str, Any]) -> bytes:
    has_text, has_b64 = "body" in call, "body_b64" in call
    if has_text and has_b64:
        raise UnknownCallShape("send body or body_b64, not both")
    if has_text:
        text = call["body"]
        if not isinstance(text, str):
            raise UnknownCallShape("body must be text")
        return text.encode("utf-8")
    if has_b64:
        encoded = call["body_b64"]
        if not isinstance(encoded, str):
            raise UnknownCallShape("body_b64 must be text")
        try:
            return base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise UnknownCallShape("body_b64 is not base64") from exc
    return b""


def _tool(call: dict[str, Any]) -> BoundCall:
    if set(call) - _TOOL_KEYS:
        raise UnknownCallShape("local_model_tool has a field this registry does not know")
    tool = _text(call.get("tool"), "tool")
    if any(char in tool for char in ":/?# \t\r\n"):
        raise UnknownCallShape("tool name cannot be bound")
    if tool in _READ_TOOLS:
        effect = "read"
    elif tool in _WRITE_TOOLS:
        effect = "write"
    else:
        raise UnknownCallShape("tool is not one this registry derives")
    arguments = call.get("arguments")
    if not isinstance(arguments, dict):
        raise UnknownCallShape("arguments must be an object")
    try:
        encoded = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise UnknownCallShape("arguments are not JSON") from exc
    return BoundCall(
        effect=effect,
        target=f"local-model-tool:{tool}",
        call_digest=_digest([b"local_model_tool", tool.encode("utf-8"), encoded.encode("utf-8")]),
        kind="local_model_tool",
        method="",
        url="",
        headers=(),
        body=b"",
        tool=tool,
        arguments_json=encoded,
    )


def describe_https(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> dict[str, Any]:
    """The ``https_request`` object ``derive`` accepts for one request.

    ``User-Agent`` is not part of the digest. It is dropped here. The authorization
    value is kept so the witness can send it; only its presence is hashed.
    """
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    scheme = parts.scheme
    if parts.port is not None:
        port = parts.port
    elif scheme == "https":
        port = 443
    elif scheme == "http":
        port = 80
    else:
        port = 0
    kept: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if key.lower() in ("content-type", "content-encoding", "authorization"):
            kept[key] = value
    call: dict[str, Any] = {
        "shape": "https_request",
        "method": method,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": parts.path or "/",
    }
    if parts.query:
        call["query"] = parts.query
    if kept:
        call["headers"] = kept
    if any(key.lower() == "authorization" for key in kept):
        call["authorization_present"] = True
    if body:
        call["body_b64"] = base64.b64encode(body).decode("ascii")
    return call


def derive(call: Any) -> BoundCall:
    """Effect, target, and digest for a known call. Raises UnknownCallShape otherwise."""
    if not isinstance(call, dict):
        raise UnknownCallShape("call must be an object")
    shape = call.get("shape")
    if shape == "https_request":
        return _https(call)
    if shape == "local_model_tool":
        return _tool(call)
    raise UnknownCallShape("call shape is not in the registry")


def bind_proposal(proposal: dict[str, Any], call: Any) -> dict[str, Any]:
    """Copy of ``proposal`` whose effect, target, and call_digest come from ``call``.

    Agreement clears ``payload.binding_fault``. Disagreement records
    ``DESCRIPTION_DISAGREEMENT`` and still stores the derived effect, target, and digest, so
    the deny describes the call rather than the lie. An unknown shape records
    ``UNKNOWN_CALL_SHAPE`` and drops any caller-supplied digest. The caller's dict is not
    changed.
    """
    if not isinstance(call, dict):
        raise BindingError("call must be an object")
    bound = copy.deepcopy(proposal)
    payload = bound.get("payload")
    if not isinstance(payload, dict):
        raise BindingError("payload must be an object when a call is sent")
    payload = dict(payload)
    try:
        derived = derive(call)
    except UnknownCallShape:
        payload["binding_fault"] = "UNKNOWN_CALL_SHAPE"
        bound["payload"] = payload
        bound.pop("call_digest", None)
        return bound
    stated = bound.get("call_digest")
    disagree = (
        bound.get("effect") != derived.effect
        or bound.get("target") != derived.target
        or (stated is not None and stated != derived.call_digest)
    )
    bound["effect"] = derived.effect
    bound["target"] = derived.target
    bound["call_digest"] = derived.call_digest
    if disagree:
        payload["binding_fault"] = "DESCRIPTION_DISAGREEMENT"
    else:
        payload.pop("binding_fault", None)
    bound["payload"] = payload
    return bound
