"""A small operator screen: what Nova is waiting on, whether the receipt log can be trusted,
and Approve and Deny buttons.

    python -m nova.operator_ui --approvals F --state DIR --log LOG [--anchor A] [--nova-url URL]

This is a SEPARATE process from the Nova API (`nova.api`), on its own port, because the Nova
API must never have a route that approves requests. Run it as the human operator's account and
keep the approvals file somewhere the Nova server cannot write (see nova/ick_approvals.py).

How it is locked down:
  * It listens on loopback only; any other address is refused.
  * Every data and action request needs a random token, printed once at startup. The token
    travels in an Authorization header and in the URL *fragment* (which browsers never send
    to a server), so it does not appear in logs or in the Referer header.
  * The Host header must be this server's own loopback address (blocks DNS rebinding) and an
    Origin header, when present, must match (blocks other websites driving it).
  * No cross-origin access is granted, and the page's Content-Security-Policy allows only its
    own script, with a fresh nonce per response.
  * All data reaches the page as JSON and is written with textContent, never as HTML.
It only reads receipts, and the only things it can write are approval and denial records, using the same
rules as `python -m nova.cli approve` and `deny`.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from nova.ick import KernelRefusal, _find_binary, pending_ttl_from
from nova.ick_approvals import DEFAULT_PENDING_TTL, ApprovalStore

MAX_BODY = 4096
MIN_EXPIRES, MAX_EXPIRES = 60, 24 * 3600
MAX_USES = 100
MAX_REASON = 200
RECENT = 25
_NAME = re.compile(r"^[A-Za-z0-9 ._@-]{1,64}$")


@dataclass
class OperatorConfig:
    approvals_file: Path
    state_dir: Path
    log: Path | None = None
    anchor: Path | None = None
    nova_url: str | None = None
    anchor_repo: str | None = None
    # Public keys the log's signatures are checked against. Keep this file where the log's writer
    # cannot change it, or a forger could simply add their own key.
    trusted_keys: Path | None = None
    require_signatures: bool = False
    # The file `python -m runtime.anchor_git watch|publish --status-file` writes. Another process
    # writes it, so everything read from it is treated as data, never trusted for its shape.
    publish_status: Path | None = None
    pending_ttl: float = DEFAULT_PENDING_TTL  # must match Nova's NOVA_ICK_PENDING_TTL
    publish_stale_after: float = 900.0  # seconds without a successful publish before it is "stale"


class OperatorApp:
    def __init__(self, config: OperatorConfig) -> None:
        self.config = config
        self.store = ApprovalStore(config.approvals_file, config.state_dir, pending_ttl=config.pending_ttl)

    # --- reading ---------------------------------------------------------------------------

    def _health(self) -> dict[str, str]:
        if not self.config.nova_url:
            return {"status": "not configured"}
        try:
            with urllib.request.urlopen(self.config.nova_url.rstrip("/") + "/health", timeout=2) as response:
                return {"status": "ok" if response.status == 200 else f"http {response.status}"}
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return {"status": "unreachable", "detail": str(getattr(exc, "reason", exc))[:120]}

    def _log(self) -> dict[str, Any]:
        log = self.config.log
        if log is None or not log.exists():
            return {"present": False}
        receipts: list[dict[str, Any]] = []
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                receipts.append(row)
        verified, message = self._verify(log, self.config.anchor, self.config.trusted_keys,
                                         self.config.require_signatures)
        checked = self.config.trusted_keys is not None
        outcomes = [r for r in receipts if "decision_receipt_id" in r]
        answered = {r["decision_receipt_id"] for r in outcomes}
        allows = [r for r in receipts if r.get("verdict") == "allow"]
        return {
            "present": True,
            "count": len(receipts),
            "outcomes": len(outcomes),
            # an allow with no outcome: still running, or the call never finished or was not recorded
            "allows_without_outcome": sum(1 for r in allows if r.get("receipt_id") not in answered),
            "verified": verified,
            "message": message,
            "anchored": self.config.anchor is not None,
            "signatures": {
                "checked": checked,
                "required": self.config.require_signatures,
                # true only if signatures were checked and at least one entry carried one; a log with
                # no signatures at all passes the hash check but proves nothing about who wrote it
                "authenticated": bool(checked and verified and "NOT checked" not in message),
            },
            "recent": [
                {"n": index + 1, "receipt_id": r.get("receipt_id"),
                 "verdict": r.get("verdict") or f"outcome: {r.get('status')}",
                 "reason_codes": r.get("reason_codes") or [], "proposal_hash": r.get("proposal_hash"),
                 "issued_at": r.get("issued_at")}
                for index, r in list(enumerate(receipts))[-RECENT:][::-1]
            ],
        }

    @staticmethod
    def _verify(log: Path, anchor: Path | None, trusted_keys: Path | None = None,
                require_signatures: bool = False) -> tuple[bool, str]:
        try:
            binary = _find_binary(None)
        except KernelRefusal as exc:
            return False, exc.message
        cmd = [binary, "verify-log", "--log", str(log)]
        if anchor is not None:
            cmd += ["--anchor", str(anchor)]
        if trusted_keys is not None:
            cmd += ["--trusted-keys", str(trusted_keys)]
            if require_signatures:
                cmd += ["--require-signatures"]
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return done.returncode == 0, (done.stdout + done.stderr).strip()[:300]

    @staticmethod
    def _count(value: Any) -> int | None:
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    def _anchor_publishing(self) -> dict[str, Any]:
        """How fresh the copy of the anchor in the separate git repository is."""
        config = self.config
        if config.publish_status is None:
            return {"monitored": False}
        try:
            raw = json.loads(config.publish_status.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = None
        if not isinstance(raw, dict):
            return {"monitored": True, "known": False}
        last = raw.get("last_success_at")
        last = last if isinstance(last, (int, float)) and not isinstance(last, bool) else None
        age = None if last is None else max(0.0, time.time() - last)  # a clock in the future counts as just now
        published = self._count(raw.get("published_records"))
        local = None
        if config.anchor is not None and config.anchor.exists():
            local = sum(1 for line in config.anchor.read_text(encoding="utf-8", errors="replace").splitlines()
                        if line.strip())
        error = raw.get("last_error")
        return {
            "monitored": True,
            "known": True,
            "last_success_at": last,
            "age_seconds": age,
            "stale": age is None or age > config.publish_stale_after,
            # entries written since the last publish: a rollback of these would go unnoticed
            "unpublished_records": max(0, local - published) if local is not None and published is not None else None,
            "consecutive_failures": self._count(raw.get("consecutive_failures")) or 0,
            "last_error": error[:300] if isinstance(error, str) else None,
            "integrity_failure": raw.get("integrity_failure") is True,
        }

    def state(self) -> dict[str, Any]:
        active = self.store.active()
        covered = {row["proposal_hash"] for row in active}
        return {
            "nova": self._health(),
            "log": self._log(),
            "anchor_publish": self._anchor_publishing(),
            "pending": [row for row in self.store.waiting() if row.get("proposal_hash") not in covered],
            "approved": active,
            "expired_pending": self.store.expired_count(),
            "pending_ttl": self.store.pending_ttl,
            "denied": sorted(self.store.denials(), key=lambda r: r.get("denied_at", 0), reverse=True)[:20],
            "can_check_published": bool(self.config.anchor_repo and self.config.log),
            "limits": {"min_expires": MIN_EXPIRES, "max_expires": MAX_EXPIRES, "max_uses": MAX_USES},
        }

    # --- acting ----------------------------------------------------------------------------

    def approve(self, body: dict[str, Any]) -> dict[str, Any]:
        proposal_hash = body.get("proposal_hash")
        expires_in, uses = body.get("expires_in", 3600), body.get("uses", 1)
        by = body.get("approved_by") or "operator"
        if not isinstance(proposal_hash, str) or not proposal_hash:
            raise ValueError("proposal_hash is required")
        if isinstance(expires_in, bool) or not isinstance(expires_in, (int, float)) \
                or not MIN_EXPIRES <= expires_in <= MAX_EXPIRES:
            raise ValueError(f"expires_in must be between {MIN_EXPIRES} and {MAX_EXPIRES} seconds")
        if isinstance(uses, bool) or not isinstance(uses, int) or not 1 <= uses <= MAX_USES:
            raise ValueError(f"uses must be a whole number from 1 to {MAX_USES}")
        if not isinstance(by, str) or not _NAME.match(by):
            raise ValueError("approved_by may use letters, digits and . _ @ - only (64 max)")
        entry = self.store.approve(proposal_hash, approved_by=by, expires_in=expires_in, uses=uses)
        return {"approval_id": entry["approval_id"], "expires_at": entry["expires_at"], "uses": entry["uses"]}

    def deny(self, body: dict[str, Any]) -> dict[str, Any]:
        proposal_hash, reason = body.get("proposal_hash"), body.get("reason") or ""
        by = body.get("denied_by") or "operator"
        if not isinstance(proposal_hash, str) or not proposal_hash:
            raise ValueError("proposal_hash is required")
        if not isinstance(reason, str) or len(reason) > MAX_REASON:
            raise ValueError(f"reason must be text of at most {MAX_REASON} characters")
        if not isinstance(by, str) or not _NAME.match(by):
            raise ValueError("denied_by may use letters, digits and . _ @ - only (64 max)")
        entry = self.store.deny(proposal_hash, denied_by=by, reason=reason)
        return {"denial_id": entry["denial_id"]}

    def check_published(self) -> dict[str, Any]:
        if not (self.config.anchor_repo and self.config.log):
            raise ValueError("no anchor repository is configured")
        root = Path(__file__).resolve().parents[2]  # infinity-core, where runtime/ lives
        sys.path.insert(0, str(root))
        try:
            from runtime.anchor_git import AnchorGitError, verify
        except ImportError as exc:
            return {"ok": False, "message": f"runtime.anchor_git is not available: {exc}"}
        finally:
            sys.path.remove(str(root))
        try:
            return {"ok": True, "message": verify(self.config.log, self.config.anchor_repo)}
        except AnchorGitError as exc:
            return {"ok": False, "message": str(exc)[:300]}


PAGE = (Path(__file__).with_name("operator_ui.html")).read_text(encoding="utf-8") \
    if Path(__file__).with_name("operator_ui.html").exists() else "<h1>operator_ui.html is missing</h1>"


def make_server(config: OperatorConfig, *, host: str = "127.0.0.1", port: int = 0,
                token: str | None = None) -> tuple[ThreadingHTTPServer, str]:
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("the operator screen only listens on loopback (127.0.0.1 or localhost)")
    token = token or secrets.token_urlsafe(32)
    app = OperatorApp(config)

    class Handler(BaseHTTPRequestHandler):
        server_version = "NovaOperator"
        sys_version = ""

        # --- checks every request must pass -----------------------------------------------
        def _allowed_hosts(self) -> set[str]:
            p = self.server.server_address[1]
            return {f"127.0.0.1:{p}", f"localhost:{p}"}

        def _guard(self, *, needs_token: bool) -> bool:
            if (self.headers.get("Host") or "") not in self._allowed_hosts():
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad Host header"})
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin not in {f"http://{h}" for h in self._allowed_hosts()}:
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad Origin"})
                return False
            if needs_token:
                header = self.headers.get("Authorization") or ""
                given = header[7:] if header.lower().startswith("bearer ") else ""
                if not hmac.compare_digest(given.encode(), token.encode()):
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "missing or wrong token"})
                    return False
            return True

        def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload: Any) -> None:
            self._send(int(status), json.dumps(payload).encode(), "application/json; charset=utf-8")

        def _body(self) -> dict[str, Any] | None:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if not 0 <= length <= MAX_BODY:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
                return None
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "body is not JSON"})
                return None
            if not isinstance(data, dict):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "body must be a JSON object"})
                return None
            return data

        # --- routes -----------------------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/":
                if not self._guard(needs_token=False):
                    return
                nonce = secrets.token_urlsafe(16)
                csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
                self._send(200, PAGE.replace("__NONCE__", nonce).encode(), "text/html; charset=utf-8",
                           {"Content-Security-Policy": csp})
            elif self.path == "/api/state":
                if self._guard(needs_token=True):
                    self._json(200, app.state())
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path not in ("/api/approve", "/api/deny", "/api/check-published"):
                self._json(404, {"error": "not found"})
                return
            if not self._guard(needs_token=True):
                return
            body = self._body()
            if body is None:
                return
            try:
                if self.path == "/api/approve":
                    self._json(200, app.approve(body))
                elif self.path == "/api/deny":
                    self._json(200, app.deny(body))
                else:
                    self._json(200, app.check_published())
            except KeyError as exc:
                self._json(404, {"error": str(exc.args[0]) if exc.args else "not found"})
            except ValueError as exc:
                self._json(400, {"error": str(exc)})

        def log_message(self, *args: Any) -> None:  # the token is never in a path, but stay quiet
            pass

    return ThreadingHTTPServer((host, port), Handler), token


def main(argv: list[str] | None = None) -> int:
    env = os.environ.get
    parser = argparse.ArgumentParser(prog="nova.operator_ui", description=__doc__.split("\n\n")[0])
    parser.add_argument("--approvals", default=env("NOVA_ICK_APPROVALS"), help="approvals file")
    parser.add_argument("--state", default=env("NOVA_ICK_STATE") or ".runtime/ick-state")
    parser.add_argument("--log", default=env("NOVA_ICK_LOG"), help="kernel receipt log")
    parser.add_argument("--anchor", default=env("NOVA_ICK_ANCHOR"))
    parser.add_argument("--trusted-keys", default=env("NOVA_ICK_TRUSTED_KEYS"),
                        help="public keys to check signatures against (keep it out of the log writer's reach)")
    parser.add_argument("--require-signatures", action="store_true",
                        help="every entry and anchor record must be signed (needs --trusted-keys)")
    parser.add_argument("--anchor-status", default=env("NOVA_ANCHOR_STATUS"),
                        help="status file written by `python -m runtime.anchor_git watch --status-file`")
    parser.add_argument("--anchor-stale-after", type=float, default=900.0,
                        help="seconds without a successful publish before the screen calls it stale (default 900)")
    parser.add_argument("--pending-ttl", type=float, default=pending_ttl_from(env("NOVA_ICK_PENDING_TTL")),
                        help="seconds an undecided request stays pending (default 604800 = 7 days; "
                             "use the same value as Nova)")
    parser.add_argument("--nova-url", default=env("NOVA_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--anchor-repo", default=env("NOVA_ANCHOR_REPO"), help="git repo holding the published anchor")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if not args.approvals:
        print("set --approvals (or NOVA_ICK_APPROVALS): that is where approvals are written", file=sys.stderr)
        return 2
    if args.require_signatures and not args.trusted_keys:
        print("--require-signatures needs --trusted-keys", file=sys.stderr)
        return 2
    config = OperatorConfig(
        approvals_file=Path(args.approvals), state_dir=Path(args.state),
        log=Path(args.log) if args.log else None, anchor=Path(args.anchor) if args.anchor else None,
        nova_url=args.nova_url, anchor_repo=args.anchor_repo,
        trusted_keys=Path(args.trusted_keys) if args.trusted_keys else None,
        require_signatures=args.require_signatures,
        publish_status=Path(args.anchor_status) if args.anchor_status else None,
        publish_stale_after=args.anchor_stale_after, pending_ttl=args.pending_ttl,
    )
    try:
        server, token = make_server(config, host=args.host, port=args.port)
    except (ValueError, OSError) as exc:
        print(f"cannot start: {exc}", file=sys.stderr)
        return 2
    host, port = server.server_address[:2]
    print(f"Operator screen: http://{host}:{port}/#token={token}")
    print("Open that exact link. The token is shown only here. Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
