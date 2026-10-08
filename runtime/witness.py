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

from runtime.call_binding import BoundCall, UnknownCallShape, derive, describe_https
from runtime.caller_auth import grant_covers
from runtime.caller_token import (
    CallerTokenError,
    IdentityFailure,
    TokenLedger,
    ledger_path_for,
    load_caller_keys,
    verify_authorization,
)

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


def dispatch_local_tool(bound: BoundCall) -> bytes:
    """Run a ``local_model_tool`` call. The witness owns this send; Nova does not."""
    if bound.kind != "local_model_tool":
        raise WitnessError("dispatch", "dispatch_local_tool only runs local_model_tool calls")
    try:
        arguments = json.loads(bound.arguments_json)
    except ValueError as exc:
        raise WitnessError("dispatch", "tool arguments are not JSON") from exc
    if not isinstance(arguments, dict):
        raise WitnessError("dispatch", "tool arguments must be an object")
    prompt = arguments.get("prompt")
    model = arguments.get("model")
    if not isinstance(prompt, str) or not isinstance(model, str):
        raise WitnessError("dispatch", "a local model call needs prompt and model text")
    temperature = arguments.get("temperature", 0.2)
    max_tokens = arguments.get("max_tokens", 2048)
    ollama = os.environ.get("NOVA_NODE_OLLAMA_URL", "http://localhost:11434/api/generate")
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }).encode("utf-8")
    try:
        sent = describe_https("POST", ollama, {"Content-Type": "application/json"}, payload)
        raw = dispatch_https(derive(sent, "witness"))
        data = json.loads(raw.decode("utf-8") or "{}")
    except (OSError, ValueError, UnknownCallShape, WitnessError) as exc:
        raise WitnessError("dispatch", str(exc)) from exc
    if not isinstance(data, dict):
        raise WitnessError("dispatch", "the local model did not return an object")
    return str(data.get("response", "")).encode("utf-8")


def dispatch_known(bound: BoundCall) -> bytes:
    """Send a known shape. HTTPS goes out as bound; a local tool is run here."""
    if bound.kind == "https_request":
        return dispatch_https(bound)
    if bound.kind == "local_model_tool":
        return dispatch_local_tool(bound)
    raise WitnessError("dispatch", "this witness cannot send that call shape")


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
        headers = dict(bound.headers)
        # Not part of call_digest. Groq rejects the default Python agent; the digest does not cover it.
        headers.setdefault("User-Agent", "infinity-core/0.1")
        connection.request(
            bound.method,
            path,
            body=bound.body if bound.body else None,
            headers=headers,
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
        caller_keys: Path | None = None,
        policy: Path | None = None,
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
        self.caller_keys = Path(caller_keys) if caller_keys is not None else None
        self.policy = Path(policy) if policy is not None else None
        self.tokens = TokenLedger(ledger_path_for(self.witness_log))

    def execute(
        self, call: Any, allow_receipt_id: str, authorization: str | None = None
    ) -> WitnessOutcome:
        """Check the caller, the grant, and ``allow_receipt_id``, then perform ``call``.

        A refusal is recorded and nothing is sent. Credential failures, including a replay
        and a token that claims another caller, are ``IDENTITY_UNVERIFIED``. A verified
        caller outside its grant is ``AUTHORITY_DENIED``.
        """
        try:
            verified = verify_authorization(
                authorization,
                call,
                self._caller_keys(),
                now=self.clock(),
                ledger=self.tokens,
            )
        except IdentityFailure:
            return self._diverge("IDENTITY_UNVERIFIED", None, allow_receipt_id)
        if verified.unbound or verified.call_digest is None:
            return self._diverge("mismatch", None, allow_receipt_id, verified.caller_id)
        digest = verified.call_digest
        caller_id = verified.caller_id
        try:
            derived = derive(call, caller_id)
        except UnknownCallShape:
            return self._diverge("mismatch", None, allow_receipt_id, caller_id)
        if not self._grant_ok(caller_id, derived.effect, derived.target):
            return self._diverge("AUTHORITY_DENIED", digest, allow_receipt_id, caller_id)
        if not self._receipt_log_ok():
            return self._diverge("unauthorized", digest, allow_receipt_id, caller_id)
        receipt = self._find_receipt(allow_receipt_id)
        if receipt is None or receipt.get("verdict") != "allow":
            return self._diverge("unauthorized", digest, allow_receipt_id, caller_id)
        if digest != receipt.get("call_digest") or receipt.get("caller_id") != caller_id:
            return self._diverge("mismatch", digest, allow_receipt_id, caller_id)
        if self._consumed(allow_receipt_id):
            return self._diverge("reused", digest, allow_receipt_id, caller_id)
        if self._expired(receipt.get("issued_at")):
            return self._diverge("late", digest, allow_receipt_id, caller_id)
        try:
            started = self._append(self._execution("started", digest, allow_receipt_id, caller_id))
        except WitnessError as exc:
            if "allow already consumed" in str(exc):
                return self._diverge("reused", digest, allow_receipt_id, caller_id)
            raise
        try:
            body = self.dispatch(derived)
        except Exception as exc:  # the allow is already consumed; record the failure
            failed = self._append(self._execution("failed", digest, allow_receipt_id, caller_id))
            return WitnessOutcome(
                dispatched=True,
                divergence=None,
                status="failed",
                call_digest=digest,
                entries=(started, failed),
                body=None,
                error=str(exc),
            )
        completed = self._append(self._execution("completed", digest, allow_receipt_id, caller_id))
        return WitnessOutcome(
            dispatched=True,
            divergence=None,
            status="completed",
            call_digest=digest,
            entries=(started, completed),
            body=body,
        )

    def _caller_keys(self) -> dict[bytes, str]:
        if self.caller_keys is None or not self.caller_keys.is_file():
            return {}
        try:
            return load_caller_keys(self.caller_keys.read_text(encoding="utf-8"))
        except (OSError, CallerTokenError):
            return {}

    def _grant_ok(self, caller_id: str, effect: str, target: str) -> bool:
        if self.policy is None or not self.policy.is_file():
            return False
        try:
            policy = json.loads(self.policy.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        if not isinstance(policy, dict):
            return False
        return grant_covers(policy, caller_id, effect, target)

    def _execution(
        self, status: str, digest: str, allow_receipt_id: str, caller_id: str
    ) -> dict[str, Any]:
        return {
            "version": EXECUTION_VERSION,
            "allow_receipt_id": allow_receipt_id,
            "call_digest": digest,
            "caller_id": caller_id,
            "attempt": 1,
            "status": status,
            "divergence": None,
            "issued_at": self._issued_at(),
        }

    def _diverge(
        self,
        kind: str,
        digest: str | None,
        allow_receipt_id: str | None,
        caller_id: str | None = None,
    ) -> WitnessOutcome:
        body: dict[str, Any] = {
            "version": DIVERGENCE_VERSION,
            "allow_receipt_id": allow_receipt_id,
            "call_digest": digest,
            "attempt": 1,
            "status": None,
            "divergence": kind,
            "issued_at": self._issued_at(),
        }
        if caller_id is not None:
            body["caller_id"] = caller_id
        entry = self._append(body)
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
