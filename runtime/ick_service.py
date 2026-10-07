"""A kernel service that owns the signing key, the policy and the receipt log.

    python -m runtime.ick_service serve --socket S --policy P --log L --anchor A \\
        --sign-key K [--approvals F] [--allow-uid N ...]

Why it exists. If the Nova process runs the kernel itself, it can read the signing key, so anyone
who takes over Nova can write receipts that look genuine. Here the key, the policy and the log
belong to a different account, and Nova talks to this process over a Unix socket:

  * `evaluate`        - Nova sends a proposal; this process runs the kernel with ITS policy, ITS
                        log and ITS key and returns the decision and receipt.
  * `record_outcome`  - Nova says how an allowed call ended; the kernel only accepts that for an
                        allow that has no outcome yet.
  * `info`            - the policy id and the key id.

Nova can no longer sign anything, choose the policy, or edit the log. It cannot make a receipt say
`allow` when the policy says otherwise, because the verdict is computed here.

A human approval is checked here too: an approval id is passed to the kernel only if it is in the
human-written approvals file, is bound to THIS request's hash, has not expired and has not been
denied. Nova cannot invent one. (How many times an approval may be used is still counted by Nova
only, so a taken-over Nova can replay an unspent approval until it expires.)

What this does NOT do
  * Without a ``call`` on the request, it cannot tell whether Nova describes its action
    truthfully. A taken-over Nova can still ask "may I do a harmless read?" and then do
    something else. The log proves what was asked and what the policy said, not what was done.
  * With a ``call``, this process derives ``effect`` and ``target`` from a known call shape,
    computes ``call_digest`` itself, and denies a disagreement or an unknown shape. It still
    does not perform the call. Executor mode is ``runtime/witness.py``: a different key and a
    different log. Nova's HTTP routes are not wired through that witness.
  * ``infinityctl evaluate`` on its own still trusts the caller's effect, target, and
    ``call_digest``. Derivation happens here, only when ``call`` is present.
  * An outcome ("completed", "failed", the hashes) is Nova's claim, now signed and chained.
  * It does not stop Nova from stopping to ask at all (see the anchor and its publication).

Setting it up (the part that makes it mean anything)
  * Run this as its own user. The key file, policy file, approvals file and log directory must be
    writable by that user only. Nova's user needs to reach the socket (mode 0660 plus a shared
    group, or `--allow-uid`) and may read the log (read-only is enough for the operator screen).
  * The key file must not be readable by Nova's user. The kernel refuses a key file that others
    can read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import socketserver
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any

from runtime.call_binding import BindingError, bind_proposal
from runtime.kernel import Kernel, KernelError, find_binary

MAX_REQUEST = 1 << 20  # 1 MiB; a proposal is a few hundred bytes plus the request digest
CLIENT_TIMEOUT = 15.0
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECEIPT = re.compile(r"^[A-Za-z0-9:._-]{1,200}$")


class ServiceError(Exception):
    """A request this service will not carry out. The message goes back to the caller."""


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    rows = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


class Service:
    def __init__(self, kernel: Kernel, *, approvals: Path | None = None) -> None:
        self.kernel = kernel
        self.approvals = approvals
        try:
            self.policy_id = str(json.loads(kernel.policy.read_text())["policy_id"])
        except Exception as exc:
            raise KernelError(f"cannot read the policy: {exc}") from exc
        self._lock = threading.Lock()  # one kernel run at a time; the log is append-only

    # --- approvals -------------------------------------------------------------------------

    def _check_approvals(self, ids: list[str], proposal: dict[str, Any], now: float) -> None:
        if not ids:
            return
        if self.approvals is None:
            raise ServiceError("this service has no approvals file, so it accepts no approvals")
        bound = self.kernel.proposal_hash(proposal)
        if self._denied(bound):
            raise ServiceError("a human denied this request")
        known = _read_jsonl(self.approvals)
        for approval_id in ids:
            for entry in known:
                if entry.get("approval_id") != approval_id or entry.get("proposal_hash") != bound:
                    continue
                try:
                    if float(entry["expires_at"]) > now:
                        break
                except (KeyError, TypeError, ValueError):
                    pass
            else:
                raise ServiceError("that approval is not valid for this request")

    def _denied(self, proposal_hash: str) -> bool:
        assert self.approvals is not None
        denials = Path(str(self.approvals) + ".denials")
        try:
            denials.read_text(encoding="utf-8")
        except FileNotFoundError:
            return False
        except OSError:
            return True  # exists but unreadable: fail closed, as Nova's own check does
        return any(row.get("proposal_hash") == proposal_hash for row in _read_jsonl(denials))

    # --- operations ------------------------------------------------------------------------

    def handle(self, request: Any, *, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        if not isinstance(request, dict):
            raise ServiceError("a request is a JSON object")
        op = request.get("op")
        if op == "info":
            return {"policy_id": self.policy_id}
        if op == "evaluate":
            proposal, ids = request.get("proposal"), request.get("approval_ids", [])
            if not isinstance(proposal, dict):
                raise ServiceError("proposal must be an object")
            if not isinstance(ids, list) or not all(isinstance(i, str) and 0 < len(i) <= 200 for i in ids) \
                    or len(ids) > 8:
                raise ServiceError("approval_ids must be a short list of strings")
            if "call" in request:
                try:
                    proposal = bind_proposal(proposal, request.get("call"))
                except BindingError as exc:
                    raise ServiceError(str(exc)) from exc
            with self._lock:
                self._check_approvals(ids, proposal, now)
                return self.kernel.evaluate_raw(proposal, tuple(ids))
        if op == "record_outcome":
            receipt, status = request.get("decision_receipt"), request.get("status")
            if not isinstance(receipt, str) or not _RECEIPT.match(receipt):
                raise ServiceError("decision_receipt is not a receipt id")
            if status not in ("completed", "failed"):
                raise ServiceError("status must be completed or failed")
            hashes: dict[str, str | None] = {}
            for key in ("request_sha256", "response_sha256"):
                value = request.get(key)
                if value is not None and not (isinstance(value, str) and _SHA.match(value)):
                    raise ServiceError(f"{key} must be sha256:<64 hex>")
                hashes[key] = value
            with self._lock:
                outcome = self.kernel.record_outcome(
                    receipt, status=status, request_sha256=hashes["request_sha256"],
                    response_sha256=hashes["response_sha256"])
            return {"outcome": {"receipt_id": outcome}}
        raise ServiceError("unknown op")


class _Handler(socketserver.StreamRequestHandler):
    server: "_Server"

    def handle(self) -> None:
        self.request.settimeout(CLIENT_TIMEOUT)
        try:
            if not self.server.peer_allowed(self.request):
                self._reply({"ok": False, "error": "this account may not use the signer"})
                return
            line = self.rfile.readline(MAX_REQUEST + 1)
            if len(line) > MAX_REQUEST:
                self._reply({"ok": False, "error": "request too large"})
                return
            try:
                request = json.loads(line)
            except ValueError:
                self._reply({"ok": False, "error": "request is not JSON"})
                return
            try:
                self._reply({"ok": True, "result": self.server.service.handle(request)})
            except ServiceError as exc:
                self._reply({"ok": False, "error": str(exc)})
            except KernelError as exc:
                self._reply({"ok": False, "error": f"kernel: {exc}"})
            except Exception as exc:  # never take the service down over one bad request
                self._reply({"ok": False, "error": f"internal error: {type(exc).__name__}"})
        except (OSError, TimeoutError):
            pass

    def _reply(self, payload: dict[str, Any]) -> None:
        self.wfile.write(json.dumps(payload).encode() + b"\n")


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, service: Service, allow_uids: frozenset[int]) -> None:
        self.service = service
        self.allow_uids = allow_uids
        super().__init__(path, _Handler)

    def peer_allowed(self, conn: socket.socket) -> bool:
        if not self.allow_uids:
            return True  # the socket's file permissions are the gate
        try:
            _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                            struct.calcsize("3i")))
        except (OSError, AttributeError):
            return False
        return uid in self.allow_uids or uid == os.getuid()


def make_server(service: Service, path: str | Path, *, mode: int = 0o660,
                allow_uids: frozenset[int] = frozenset()) -> _Server:
    """Bind the socket. A leftover socket file is removed only if nothing is listening on it."""
    path = str(path)
    if os.path.exists(path):
        probe = socket.socket(socket.AF_UNIX)
        try:
            probe.settimeout(2)
            probe.connect(path)
        except OSError:
            os.unlink(path)  # stale
        else:
            raise OSError(f"another service is already listening on {path}")
        finally:
            probe.close()
    if allow_uids and not hasattr(socket, "SO_PEERCRED"):
        raise OSError("--allow-uid needs SO_PEERCRED, which this platform does not have")
    old = os.umask(0o777 ^ mode)  # the socket is never briefly more open than asked
    try:
        server = _Server(path, service, allow_uids)
    finally:
        os.umask(old)
    os.chmod(path, mode)
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="runtime.ick_service", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="listen on a Unix socket")
    serve.add_argument("--socket", required=True)
    serve.add_argument("--policy", required=True)
    serve.add_argument("--log", required=True)
    serve.add_argument("--anchor")
    serve.add_argument("--sign-key", required=True)
    serve.add_argument("--approvals", help="the human-written approvals file (read only)")
    serve.add_argument("--binary")
    serve.add_argument("--socket-mode", default="660", help="octal file mode of the socket (default 660)")
    serve.add_argument("--allow-uid", type=int, action="append", default=[],
                       help="only this uid (and the service's own) may connect; repeatable")
    args = parser.parse_args(argv)
    try:
        mode = int(args.socket_mode, 8)
    except ValueError:
        print("--socket-mode must be an octal number such as 660", file=sys.stderr)
        return 2
    try:
        kernel = Kernel(Path(args.policy), Path(args.log), binary=args.binary or find_binary(),
                        anchor=Path(args.anchor) if args.anchor else None, sign_key=Path(args.sign_key))
        service = Service(kernel, approvals=Path(args.approvals) if args.approvals else None)
        Path(args.log).parent.mkdir(parents=True, exist_ok=True)
        server = make_server(service, args.socket, mode=mode, allow_uids=frozenset(args.allow_uid))
    except (KernelError, OSError) as exc:
        print(f"cannot start: {exc}", file=sys.stderr)
        return 2
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"signer listening on {args.socket} (policy {service.policy_id})", flush=True)
    stop.wait()
    server.shutdown()
    server.server_close()
    try:
        os.unlink(args.socket)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
