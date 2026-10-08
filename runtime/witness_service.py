"""A witness service. Nova sends a call and an allow receipt id; this process performs the call.

Nova does not hold the witness signing key, the witness log, or the receipt trusted keys.
The socket is Unix-only. Importing this module on Windows does not create a Unix server class.

    python -m runtime.witness_service serve --socket S --receipt-log L --witness-log W \\
        --witness-key K --receipt-keys PUB [--receipt-anchor A]
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import socketserver
import sys
from pathlib import Path
from typing import Any

from runtime.kernel import find_binary
from runtime.witness import Witness, WitnessError, dispatch_known

MAX_REQUEST = 1 << 20
CLIENT_TIMEOUT = 60.0


class WitnessService:
    def __init__(self, witness: Witness) -> None:
        self.witness = witness

    def handle(self, request: Any) -> dict[str, Any]:
        if not isinstance(request, dict):
            raise WitnessError("request", "a request is a JSON object")
        if request.get("op") != "execute":
            raise WitnessError("request", "unknown op")
        call, allow_id = request.get("call"), request.get("allow_receipt_id")
        if not isinstance(allow_id, str) or not allow_id:
            raise WitnessError("request", "allow_receipt_id is required")
        authorization = request.get("authorization")
        if authorization is not None and not isinstance(authorization, str):
            authorization = "malformed"
        outcome = self.witness.execute(call, allow_id, authorization=authorization)
        body = base64.b64encode(outcome.body).decode("ascii") if outcome.body else None
        return {
            "dispatched": outcome.dispatched,
            "divergence": outcome.divergence,
            "status": outcome.status,
            "call_digest": outcome.call_digest,
            "body_b64": body,
            "error": outcome.error,
        }


class _Handler(socketserver.StreamRequestHandler):
    server: "_Server"

    def handle(self) -> None:
        self.request.settimeout(CLIENT_TIMEOUT)
        try:
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
            except WitnessError as exc:
                self._reply({"ok": False, "error": str(exc)})
            except Exception as exc:
                self._reply({"ok": False, "error": f"internal error: {type(exc).__name__}"})
        except (OSError, TimeoutError):
            pass

    def _reply(self, payload: dict[str, Any]) -> None:
        self.wfile.write(json.dumps(payload).encode() + b"\n")


_UnixServer = getattr(socketserver, "UnixStreamServer", None)
if _UnixServer is None:
    class _Server:  # type: ignore[no-redef]
        def __init__(self, path: str, service: WitnessService) -> None:
            raise OSError("the witness listens on a Unix socket, which this platform does not have")
else:
    class _Server(socketserver.ThreadingMixIn, _UnixServer):
        daemon_threads = True

        def __init__(self, path: str, service: WitnessService) -> None:
            self.service = service
            super().__init__(path, _Handler)


def make_server(service: WitnessService, path: str | Path, *, mode: int = 0o660) -> _Server:
    path = str(path)
    if os.path.exists(path):
        probe = socket.socket(socket.AF_UNIX)
        try:
            probe.settimeout(2)
            probe.connect(path)
        except OSError:
            os.unlink(path)
        else:
            raise OSError(f"another service is already listening on {path}")
        finally:
            probe.close()
    old = os.umask(0o777 ^ mode)
    try:
        server = _Server(path, service)
    finally:
        os.umask(old)
    os.chmod(path, mode)
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="runtime.witness_service", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="listen on a Unix socket")
    serve.add_argument("--socket", required=True)
    serve.add_argument("--receipt-log", required=True)
    serve.add_argument("--witness-log", required=True)
    serve.add_argument("--witness-key", required=True)
    serve.add_argument("--receipt-keys", required=True)
    serve.add_argument("--receipt-anchor")
    serve.add_argument("--binary")
    serve.add_argument("--allow-ttl", type=float, default=3600)
    serve.add_argument("--socket-mode", default="660")
    serve.add_argument("--caller-keys", help="caller public keys the witness trusts")
    serve.add_argument("--policy", help="policy file; a bound call needs a grant for the caller")
    args = parser.parse_args(argv)
    try:
        mode = int(args.socket_mode, 8)
    except ValueError:
        print("--socket-mode must be an octal number such as 660", file=sys.stderr)
        return 2
    try:
        witness = Witness(
            binary=args.binary or find_binary(),
            receipt_log=Path(args.receipt_log),
            witness_log=Path(args.witness_log),
            witness_key=Path(args.witness_key),
            receipt_trusted_keys=Path(args.receipt_keys),
            receipt_anchor=Path(args.receipt_anchor) if args.receipt_anchor else None,
            dispatch=dispatch_known,
            allow_ttl=args.allow_ttl,
            caller_keys=Path(args.caller_keys) if args.caller_keys else None,
            policy=Path(args.policy) if args.policy else None,
        )
        server = make_server(WitnessService(witness), args.socket, mode=mode)
    except (OSError, WitnessError) as exc:
        print(f"cannot start: {exc}", file=sys.stderr)
        return 2
    print(f"witness listening on {args.socket}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.shutdown()
    server.server_close()
    try:
        os.unlink(args.socket)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
