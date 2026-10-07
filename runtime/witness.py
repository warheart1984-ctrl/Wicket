"""Executor-mode witness. Nova does not dispatch; this component does.

It recomputes ``call_digest``, checks the allow receipt (the log chains, the receipt exists,
the verdict is allow, the digest matches, the allow is unused, it is not expired), appends a
signed ``started`` entry, and only then performs the call. A mismatch or an unauthorized call
is refused and written as a signed divergence. A mismatch does not consume the allow.

This does not prove the target's resulting state. It proves what this process sent, and the
bytes it got back, under the witness key. One allow is one execution: there is no retry.
``state_ref``, observer mode, and a witness heartbeat are not implemented.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from typing import Any, Callable

from runtime.call_binding import BoundCall, UnknownCallShape, derive

EXECUTION_VERSION = "infinity.witness.execution.v1"
DIVERGENCE_VERSION = "infinity.witness.divergence.v1"
_ISSUED_AT = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"


class WitnessError(Exception):
    """The witness could not record what it decided. ``kind`` is a short label, not a divergence."""

    def __init__(self, kind: str, message: str) -> None:
        self.kind = kind
        super().__init__(message)


@dataclass(frozen=True)
class WitnessOutcome:
    dispatched: bool
    divergence: str | None
    status: str | None
    call_digest: str | None
    entries: tuple[dict[str, Any], ...]
    body: bytes | None
    error: str | None = None


def dispatch_https(bound: BoundCall) -> bytes:
    """Send an ``https_request`` and return the response body. Redirects are not followed."""
    if bound.kind != "https_request":
        raise WitnessError("dispatch", "dispatch_https only sends https_request calls")
    parts = urllib.parse.urlsplit(bound.url)
    if parts.scheme == "https":
        connection: HTTPConnection | HTTPSConnection = HTTPSConnection(
            parts.hostname or "", parts.port, timeout=10
        )
    elif parts.scheme == "http":
        connection = HTTPConnection(parts.hostname or "", parts.port, timeout=10)
    else:
        raise WitnessError("dispatch", "scheme is not http or https")
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    try:
        connection.request(
            bound.method,
            path,
            body=bound.body if bound.body else None,
            headers=dict(bound.headers),
        )
        response = connection.getresponse()
        return response.read()
    except OSError as exc:
        raise WitnessError("dispatch", str(exc)) from exc
    finally:
        connection.close()


class Witness:
    def __init__(
        self,
        *,
        binary: str,
        receipt_log: Path,
        witness_log: Path,
        witness_key: Path,
        receipt_trusted_keys: Path,
        receipt_anchor: Path | None = None,
        dispatch: Callable[[BoundCall], bytes] | None = None,
        allow_ttl: float = 3600,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.binary = binary
        self.receipt_log = Path(receipt_log)
        self.witness_log = Path(witness_log)
        self.witness_key = Path(witness_key)
        self.receipt_trusted_keys = Path(receipt_trusted_keys)
        self.receipt_anchor = Path(receipt_anchor) if receipt_anchor else None
        self.dispatch = dispatch if dispatch is not None else dispatch_https
        self.allow_ttl = allow_ttl
        self.clock = clock if clock is not None else time.time

    def execute(self, call: Any, allow_receipt_id: str) -> WitnessOutcome:
        """Check ``allow_receipt_id``, consume it, then perform ``call``. Refusal does not dispatch."""
        try:
            derived = derive(call)
            digest: str | None = derived.call_digest
        except UnknownCallShape:
            derived = None
            digest = None
        if not self._receipt_log_ok():
            return self._diverge("unauthorized", digest, allow_receipt_id)
        receipt = self._find_receipt(allow_receipt_id)
        if receipt is None or receipt.get("verdict") != "allow":
            return self._diverge("unauthorized", digest, allow_receipt_id)
        if derived is None or digest != receipt.get("call_digest"):
            return self._diverge("mismatch", digest, allow_receipt_id)
        if self._consumed(allow_receipt_id):
            return self._diverge("reused", digest, allow_receipt_id)
        if self._expired(receipt.get("issued_at")):
            return self._diverge("late", digest, allow_receipt_id)
        try:
            started = self._append(self._execution("started", digest, allow_receipt_id))
        except WitnessError as exc:
            if "allow already consumed" in str(exc):
                return self._diverge("reused", digest, allow_receipt_id)
            raise
        try:
            body = self.dispatch(derived)
        except Exception as exc:  # the allow is already consumed; record the failure
            failed = self._append(self._execution("failed", digest, allow_receipt_id))
            return WitnessOutcome(
                dispatched=True,
                divergence=None,
                status="failed",
                call_digest=digest,
                entries=(started, failed),
                body=None,
                error=str(exc),
            )
        completed = self._append(self._execution("completed", digest, allow_receipt_id))
        return WitnessOutcome(
            dispatched=True,
            divergence=None,
            status="completed",
            call_digest=digest,
            entries=(started, completed),
            body=body,
        )

    def _execution(self, status: str, digest: str, allow_receipt_id: str) -> dict[str, Any]:
        return {
            "version": EXECUTION_VERSION,
            "allow_receipt_id": allow_receipt_id,
            "call_digest": digest,
            "attempt": 1,
            "status": status,
            "divergence": None,
            "issued_at": self._issued_at(),
        }

    def _diverge(
        self, kind: str, digest: str | None, allow_receipt_id: str | None
    ) -> WitnessOutcome:
        entry = self._append(
            {
                "version": DIVERGENCE_VERSION,
                "allow_receipt_id": allow_receipt_id,
                "call_digest": digest,
                "attempt": 1,
                "status": None,
                "divergence": kind,
                "issued_at": self._issued_at(),
            }
        )
        return WitnessOutcome(
            dispatched=False,
            divergence=kind,
            status=None,
            call_digest=digest,
            entries=(entry,),
            body=None,
        )

    def _issued_at(self) -> str:
        return datetime.fromtimestamp(int(self.clock()), timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    def _expired(self, issued_at: Any) -> bool:
        if not isinstance(issued_at, str) or re.fullmatch(_ISSUED_AT, issued_at) is None:
            return True
        issued = datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return self.clock() > issued.timestamp() + self.allow_ttl

    def _receipt_log_ok(self) -> bool:
        if not self.receipt_log.is_file():
            return False
        command = [
            self.binary,
            "verify-log",
            "--log",
            str(self.receipt_log),
            "--trusted-keys",
            str(self.receipt_trusted_keys),
            "--require-signatures",
        ]
        if self.receipt_anchor is not None:
            command += ["--anchor", str(self.receipt_anchor)]
        done = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return done.returncode == 0

    def _find_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        for row in self._rows(self.receipt_log):
            if row.get("receipt_id") == receipt_id and "verdict" in row:
                return row
        return None

    def _consumed(self, allow_receipt_id: str) -> bool:
        if not self.witness_log.is_file():
            return False
        for row in self._rows(self.witness_log):
            if (
                row.get("version") == EXECUTION_VERSION
                and row.get("allow_receipt_id") == allow_receipt_id
            ):
                return True
        return False

    def _rows(self, path: Path) -> list[dict[str, Any]]:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise WitnessError("log", f"cannot read {path}: {exc}") from exc
        rows = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise WitnessError("log", f"{path} has a line that is not JSON") from exc
            if not isinstance(row, dict):
                raise WitnessError("log", f"{path} has a line that is not an object")
            rows.append(row)
        return rows

    def _append(self, body: dict[str, Any]) -> dict[str, Any]:
        self.witness_log.parent.mkdir(parents=True, exist_ok=True)
        handle, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as entry_file:
                json.dump(body, entry_file)
            done = subprocess.run(
                [
                    self.binary,
                    "witness-append",
                    "--log",
                    str(self.witness_log),
                    "--sign-key",
                    str(self.witness_key),
                    "--entry",
                    path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        finally:
            os.unlink(path)
        if done.returncode != 0:
            message = done.stderr.strip() or f"witness-append exited {done.returncode}"
            raise WitnessError("append", message)
        try:
            written = json.loads(done.stdout)
        except ValueError as exc:
            raise WitnessError("append", "witness-append did not return JSON") from exc
        if not isinstance(written, dict):
            raise WitnessError("append", "witness-append did not return an object")
        return written
