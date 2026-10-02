"""Repo-local Nova CLI for the Lawful Nova runtime slice."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from nova.lawful_llm import LawfulLLM


@dataclass(frozen=True)
class Check:
    status: str
    detail: str = ""


def _http_health(url: str) -> Check:
    try:
        request = Request(url.rstrip("/") + "/health", headers={"Accept": "application/json"})
        with urlopen(request, timeout=2) as response:
            body = response.read().decode("utf-8", errors="replace")
        return Check(status="ok", detail=body)
    except (OSError, URLError) as exc:
        return Check(status="warn", detail=str(exc))


def collect_health() -> dict[str, Any]:
    direct_status = "ok"
    direct_detail = ""
    try:
        llm = LawfulLLM(operator_session_id="nova-local-cli", signing_secret="local-dev-secret")
        turn = llm.ask("observe lawful nova health", tenant_id="local", capability="observe")
        direct_detail = turn.voss_runtime["decision"]
    except Exception as exc:  # pragma: no cover - defensive diagnostic
        direct_status = "fail"
        direct_detail = str(exc)

    return {
        "service": "nova_local_cli",
        "repo_root": str(Path.cwd()),
        "direct_lawful_llm": asdict(Check(status=direct_status, detail=direct_detail)),
        "lawful_brain_api": asdict(_http_health("http://127.0.0.1:8791")),
        "operator_kernel_api": asdict(_http_health("http://127.0.0.1:8790")),
    }


def _print(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True))
        return
    for key, value in payload.items():
        if isinstance(value, dict):
            print(f"{key}: {value.get('status')} {value.get('detail', '')}".rstrip())
        else:
            print(f"{key}: {value}")


def health_command(args: argparse.Namespace) -> int:
    payload = collect_health()
    _print(payload, as_json=args.json)
    return 0 if payload["direct_lawful_llm"]["status"] == "ok" else 1


def ask_command(args: argparse.Namespace) -> int:
    llm = LawfulLLM(operator_session_id="nova-local-cli", signing_secret="local-dev-secret")
    turn = llm.ask(
        args.prompt,
        tenant_id=args.tenant,
        capability=args.capability,
    )
    payload = {
        "text": turn.text,
        "receipt_verified": llm.verify_receipt(turn.receipt),
        "decision": turn.voss_runtime["decision"],
    }
    _print(payload, as_json=args.json)
    return 0


def serve_command(args: argparse.Namespace) -> int:
    from nova.api import main

    main()
    return 0


def _approval_store():
    from nova.ick import approval_store_from_env

    store = approval_store_from_env()
    if store is None:
        print("NOVA_ICK_APPROVALS is not set; there is nowhere to record approvals.", file=sys.stderr)
    return store


def approvals_command(args: argparse.Namespace) -> int:
    store = _approval_store()
    if store is None:
        return 2
    now = time.time()
    approved = {row.get("proposal_hash") for row in store.approvals() if float(row.get("expires_at", 0)) > now}
    waiting = [row for row in store.waiting() if row.get("proposal_hash") not in approved]
    if args.json:
        print(json.dumps({"pending": waiting, "approved": store.approvals(),
                          "denied": store.denials()}, indent=2, sort_keys=True))
        return 0
    if not waiting:
        print("nothing is waiting for approval")
    for row in waiting:
        print(f"{row['proposal_hash']}  {row.get('action')} -> {row.get('target')} "
              f"[{row.get('effect')}/{row.get('risk')}]")
    return 0


def approve_command(args: argparse.Namespace) -> int:
    store = _approval_store()
    if store is None:
        return 2
    match = [row for row in store.pending() if row.get("proposal_hash") == args.proposal_hash]
    if not match:
        print(f"no pending request with hash {args.proposal_hash}", file=sys.stderr)
        return 1
    row = match[0]
    print(f"approve: {row.get('action')} -> {row.get('target')} [{row.get('effect')}/{row.get('risk')}] "
          f"for {args.expires_in:g}s, {args.uses} use(s)")
    if not args.yes:
        if not sys.stdin.isatty():
            print("refusing to approve without --yes when not run from a terminal", file=sys.stderr)
            return 1
        if input("type 'yes' to approve: ").strip().lower() != "yes":
            print("not approved")
            return 1
    try:
        entry = store.approve(args.proposal_hash, approved_by=args.by, expires_in=args.expires_in,
                              uses=args.uses)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"approved: {entry['approval_id']} (expires {int(entry['expires_at'])})")
    return 0


def deny_command(args: argparse.Namespace) -> int:
    store = _approval_store()
    if store is None:
        return 2
    match = [row for row in store.pending() if row.get("proposal_hash") == args.proposal_hash]
    if not match:
        print(f"no pending request with hash {args.proposal_hash}", file=sys.stderr)
        return 1
    row = match[0]
    print(f"deny: {row.get('action')} -> {row.get('target')} [{row.get('effect')}/{row.get('risk')}] "
          "(final for this exact request)")
    if not args.yes:
        if not sys.stdin.isatty():
            print("refusing to deny without --yes when not run from a terminal", file=sys.stderr)
            return 1
        if input("type 'yes' to deny: ").strip().lower() != "yes":
            print("not denied")
            return 1
    try:
        entry = store.deny(args.proposal_hash, denied_by=args.by, reason=args.reason)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"denied: {entry['denial_id']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nova", description="Lawful Nova local CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    health = sub.add_parser("health", help="Check local Lawful Nova readiness")
    health.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    health.set_defaults(func=health_command)

    chat = sub.add_parser("chat", help="Ask the local Lawful Nova slice")
    chat.add_argument("prompt", nargs="?", default="observe lawful nova")
    chat.add_argument("--tenant", default="local")
    chat.add_argument("--capability", default="observe")
    chat.add_argument("--json", action="store_true")
    chat.set_defaults(func=ask_command)

    run = sub.add_parser("run", help="Run a one-shot local Lawful Nova prompt")
    run.add_argument("prompt")
    run.add_argument("--tenant", default="local")
    run.add_argument("--capability", default="observe")
    run.add_argument("--json", action="store_true")
    run.set_defaults(func=ask_command)

    serve = sub.add_parser("serve", help="Start the local Lawful Nova /health API")
    serve.set_defaults(func=serve_command)
    approvals = sub.add_parser("approvals", help="List requests waiting for a human approval")
    approvals.add_argument("--json", action="store_true")
    approvals.set_defaults(func=approvals_command)

    approve = sub.add_parser("approve", help="Approve one pending request by its proposal hash")
    approve.add_argument("proposal_hash")
    approve.add_argument("--by", default=os.environ.get("USER", "operator"), help="who is approving")
    approve.add_argument("--expires-in", type=float, default=3600, help="seconds (default 3600)")
    approve.add_argument("--uses", type=int, default=1, help="how many times it may be used (default 1)")
    approve.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    approve.set_defaults(func=approve_command)

    deny = sub.add_parser("deny", help="Deny one pending request by its proposal hash (final)")
    deny.add_argument("proposal_hash")
    deny.add_argument("--by", default=os.environ.get("USER", "operator"), help="who is denying")
    deny.add_argument("--reason", default="", help="why (kept in the denials file)")
    deny.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    deny.set_defaults(func=deny_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
