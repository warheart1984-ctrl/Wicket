"""Hand a concrete call to the witness. Nova does not hold the witness signing key.

``NOVA_ICK_WITNESS`` is the socket of a witness service (``python -m runtime.witness_service``).
Tests install an in-process witness instead; that object is not Nova's signing key, and the
tests do not claim two operating-system accounts.
"""

from __future__ import annotations

import base64
import json
import os
import socket
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from runtime.witness import Witness

_REPLY_LIMIT = 8 << 20
_installed: "WitnessEndpoint | None" = None


@dataclass(frozen=True)
class WitnessReply:
    dispatched: bool
    divergence: str | None
    status: str | None
    body: bytes | None
    error: str | None


class WitnessEndpoint:
    def execute(
        self, call: dict[str, Any], allow_receipt_id: str, authorization: str | None = None
    ) -> WitnessReply:
        raise NotImplementedError


class InProcessWitness(WitnessEndpoint):
    """The witness object the test constructed. Production Nova uses the socket."""

    def __init__(self, witness: Witness) -> None:
        self._witness = witness

    def execute(
        self, call: dict[str, Any], allow_receipt_id: str, authorization: str | None = None
    ) -> WitnessReply:
        outcome = self._witness.execute(call, allow_receipt_id, authorization=authorization)
        return WitnessReply(
            dispatched=outcome.dispatched,
            divergence=outcome.divergence,
            status=outcome.status,
            body=outcome.body,
            error=outcome.error,
        )


class SocketWitness(WitnessEndpoint):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def execute(
        self, call: dict[str, Any], allow_receipt_id: str, authorization: str | None = None
    ) -> WitnessReply:
        request: dict[str, Any] = {
            "op": "execute", "call": call, "allow_receipt_id": allow_receipt_id,
        }
        if authorization is not None:
            request["authorization"] = authorization
        reply = _call_socket(self.path, request)
        body = reply.get("body_b64")
        raw = base64.b64decode(body) if isinstance(body, str) else None
        return WitnessReply(
            dispatched=reply.get("dispatched") is True,
            divergence=reply.get("divergence") if isinstance(reply.get("divergence"), str) else None,
            status=reply.get("status") if isinstance(reply.get("status"), str) else None,
            body=raw,
            error=reply.get("error") if isinstance(reply.get("error"), str) else None,
        )


def _call_socket(path: Path, request: dict[str, Any], *, timeout: float = 60.0) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(str(path))
        conn.sendall(json.dumps(request).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > _REPLY_LIMIT:
                raise OSError("witness reply too large")
    reply = json.loads(data)
    if not isinstance(reply, dict) or reply.get("ok") is not True or not isinstance(reply.get("result"), dict):
        message = reply.get("error") if isinstance(reply, dict) else "refused"
        raise OSError(f"witness service: {message}")
    return reply["result"]


def current_witness() -> WitnessEndpoint | None:
    if _installed is not None:
        return _installed
    path = (os.environ.get("NOVA_ICK_WITNESS") or "").strip()
    if not path:
        return None
    return SocketWitness(path)


@contextmanager
def witness_installed(endpoint: WitnessEndpoint) -> Iterator[WitnessEndpoint]:
    global _installed
    previous = _installed
    _installed = endpoint
    try:
        yield endpoint
    finally:
        _installed = previous
