"""Publish the receipt-log anchor to a separate git repository, and check a log against it.

    python -m runtime.anchor_git publish --anchor A.jsonl --repo URL [--log LOG]
    python -m runtime.anchor_git verify  --log LOG --repo URL

Why: the anchor only helps if whoever can edit the receipt log cannot also edit the anchor.
Git history gives a trail: every published state is a commit, and `publish` never
force-pushes and refuses to publish an anchor that is not a continuation of what is already
there, so rewriting or shortening it leaves evidence (or fails on a protected branch).

Limits, stated plainly:
  * This only helps if the repository is outside the log writer's control (another account,
    or a protected branch where force-pushes and deletions are blocked). Same machine,
    same credentials, same repo owner: they can rewrite it too.
  * It detects tampering up to the last published anchor. Receipts added after the most
    recent `publish` are not covered until the next one, so publish on a schedule.
  * Authentication is whatever git already has; this tool handles no tokens.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from runtime.kernel import KernelError, find_binary

DEFAULT_BRANCH = "anchors"
DEFAULT_NAME = "anchor.jsonl"


class AnchorGitError(RuntimeError):
    pass


class AnchorRefused(AnchorGitError):
    """The publisher refused because what it was given does not add up: the log does not match its
    anchor, or the local anchor does not continue the published one. Unlike a network error this is
    not fixed by retrying, and it may mean tampering, so it is reported differently."""


@dataclass(frozen=True)
class PublishResult:
    message: str
    total_records: int  # anchor records on the remote after this run
    new_records: int
    head_receipt_id: str | None  # the newest published record's head


def _git(*args: str, cwd: Path | None = None) -> str:
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",  # fail instead of waiting for a password
        "GIT_AUTHOR_NAME": os.environ.get("ANCHOR_GIT_NAME", "infinity-anchor"),
        "GIT_AUTHOR_EMAIL": os.environ.get("ANCHOR_GIT_EMAIL", "anchor@localhost"),
        "GIT_COMMITTER_NAME": os.environ.get("ANCHOR_GIT_NAME", "infinity-anchor"),
        "GIT_COMMITTER_EMAIL": os.environ.get("ANCHOR_GIT_EMAIL", "anchor@localhost"),
    }
    done = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    if done.returncode != 0:
        raise AnchorGitError(f"git {args[0]} failed: {(done.stderr or done.stdout).strip()[:400]}")
    return done.stdout


def _lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def _fetch_published(repo: str, branch: str, name: str, into: Path) -> list[str] | None:
    """Clone the branch tip (depth 1) into `into`. Return the published anchor lines, or None
    if the branch does not exist yet."""
    if not _git("ls-remote", "--heads", repo, branch).strip():
        return None
    _git("clone", "--quiet", "--depth", "1", "--branch", branch, repo, str(into))
    published = into / name
    return _lines(published.read_text()) if published.exists() else []


def published_anchor(repo: str, branch: str = DEFAULT_BRANCH, name: str = DEFAULT_NAME) -> list[str] | None:
    with tempfile.TemporaryDirectory() as tmp:
        return _fetch_published(repo, branch, name, Path(tmp) / "repo")


def verify_log_against(
    log: Path,
    anchor: Path,
    trusted_keys: Path | None = None,
    require_signatures: bool = False,
) -> tuple[bool, str]:
    """Run the kernel's verify-log with `anchor`. Returns (ok, message).

    With `trusted_keys` the signatures on the log and the anchor are checked too; the keys must come
    from somewhere the log's writer cannot change."""
    try:
        binary = find_binary()
    except KernelError as exc:
        raise AnchorGitError(str(exc)) from exc
    cmd = [binary, "verify-log", "--log", str(log)]
    if anchor:
        cmd += ["--anchor", str(anchor)]
    if trusted_keys:
        cmd += ["--trusted-keys", str(trusted_keys)]
        if require_signatures:
            cmd += ["--require-signatures"]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return done.returncode == 0, (done.stdout + done.stderr).strip()


def _head_of(line: str) -> str | None:
    try:
        return str(json.loads(line)["head_receipt_id"])
    except (ValueError, KeyError, TypeError):
        return None


def _publish(anchor: Path, repo: str, *, branch: str = DEFAULT_BRANCH, name: str = DEFAULT_NAME,
             log: Path | None = None, trusted_keys: Path | None = None,
             require_signatures: bool = False) -> PublishResult:
    """Push `anchor` to `repo`. Raises AnchorRefused if the data does not add up, AnchorGitError
    for anything else that goes wrong."""
    local = _lines(anchor.read_text()) if anchor.exists() else []
    if not local:
        raise AnchorGitError(f"{anchor} has no anchor records to publish")
    if log is not None:
        ok, message = verify_log_against(log, anchor, trusted_keys, require_signatures)
        if not ok:
            raise AnchorRefused(f"refusing to publish: the log does not match its own anchor ({message})")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        published = _fetch_published(repo, branch, name, work)
        if published is None:
            _git("init", "--quiet", str(work))
            _git("checkout", "--quiet", "--orphan", branch, cwd=work)
            _git("remote", "add", "origin", repo, cwd=work)
            published = []
        if local[: len(published)] != published:
            raise AnchorRefused(
                "refusing to publish: the local anchor does not continue what is already published "
                f"({len(published)} published records, {len(local)} local). It was edited, shortened "
                "or replaced.")
        if len(local) == len(published):
            return PublishResult(f"already up to date ({len(local)} records)", len(local), 0, _head_of(local[-1]))
        (work / name).write_text("\n".join(local) + "\n")
        _git("add", name, cwd=work)
        _git("commit", "--quiet", "-m",
             f"anchor: {len(local)} records (+{len(local) - len(published)})\n\n{local[-1]}", cwd=work)
        _git("push", "--quiet", "origin", f"HEAD:refs/heads/{branch}", cwd=work)  # never forced
        new = len(local) - len(published)
        return PublishResult(f"published {new} new record(s); {len(local)} total on {branch}", len(local), new,
                             _head_of(local[-1]))


def publish(anchor: Path, repo: str, *, branch: str = DEFAULT_BRANCH, name: str = DEFAULT_NAME,
            log: Path | None = None, trusted_keys: Path | None = None,
            require_signatures: bool = False) -> str:
    """Push `anchor` to `repo`. Returns a one-line result. Raises AnchorGitError on refusal."""
    return _publish(anchor, repo, branch=branch, name=name, log=log, trusted_keys=trusted_keys,
                    require_signatures=require_signatures).message


# ---- running it on a schedule -----------------------------------------------------------------

STATUS_VERSION = "infinity.anchor-publish-status.v1"
_CREDENTIALS = re.compile(r"(://)[^/@\s]+@")


def redact(text: str) -> str:
    """Hide any `user:password@` or `token@` part of a URL: git error text can contain the remote."""
    return _CREDENTIALS.sub(r"\1***@", text)


def _one_line(error: BaseException, limit: int = 300) -> str:
    """An error as a single line with any URL credentials hidden, for the log and the status file."""
    return redact(" ".join(str(error).split()))[:limit]


def read_status(status_file: Path) -> dict | None:
    try:
        data = json.loads(Path(status_file).read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _write_status(status_file: Path, status: dict) -> None:
    """Write atomically, so a reader never sees half a file."""
    status_file = Path(status_file)
    status_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = status_file.with_name(status_file.name + ".tmp")
    tmp.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, status_file)


def publish_and_record(anchor: Path, repo: str, *, status_file: Path, now: Callable[[], float] = time.time,
                       **options) -> str:
    """`publish`, and record the outcome in `status_file` (never the repo URL or any credential).

    The status is what lets someone else see that publishing has stopped working, which matters
    because a scheduled job that fails quietly looks exactly like one that is protecting you."""
    previous = read_status(status_file) or {}
    status = {
        "version": STATUS_VERSION,
        "last_attempt_at": int(now()),
        "last_success_at": previous.get("last_success_at"),
        "published_records": previous.get("published_records"),
        "head_receipt_id": previous.get("head_receipt_id"),
        "consecutive_failures": int(previous.get("consecutive_failures") or 0),
        "last_error": None,
        "integrity_failure": False,
    }
    try:
        result = _publish(anchor, repo, **options)
    except AnchorGitError as exc:
        status["consecutive_failures"] += 1
        status["last_error"] = _one_line(exc)
        status["integrity_failure"] = isinstance(exc, AnchorRefused)
        _write_status(status_file, status)
        raise
    status.update(last_success_at=status["last_attempt_at"], published_records=result.total_records,
                  head_receipt_id=result.head_receipt_id, consecutive_failures=0)
    _write_status(status_file, status)
    return result.message


def watch(anchor: Path, repo: str, *, status_file: Path, interval: float = 300.0, max_backoff: float = 1800.0,
          stop: threading.Event | None = None, max_runs: int | None = None,
          wait: Callable[[float], bool] | None = None,
          report: Callable[[str], None] = lambda line: print(line, flush=True), **options) -> int:
    """Publish every `interval` seconds until `stop` is set (or `max_runs` runs have happened).

    Ordinary failures (network, auth) are retried with a growing delay, capped at `max_backoff`.
    A refusal (the data does not add up) is recorded and reported loudly but is not retried any
    faster: it needs a person. The loop never exits on its own because of an error; a stale or
    failing status is how the problem is noticed."""
    stop = stop or threading.Event()
    wait = wait or stop.wait  # returns True when `stop` was set during the wait
    failures = runs = 0
    while not stop.is_set():
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            report(f"{stamp} {publish_and_record(anchor, repo, status_file=status_file, **options)}")
            failures = 0
        except AnchorRefused as exc:
            failures = 0  # not a transient fault, so no backoff, but it stays flagged in the status file
            report(f"{stamp} INTEGRITY REFUSAL (needs a person, not a retry): {_one_line(exc)}")
        except AnchorGitError as exc:
            failures += 1
            report(f"{stamp} publish failed ({failures} in a row): {_one_line(exc)}")
        runs += 1
        if max_runs is not None and runs >= max_runs:
            break
        delay = interval if failures == 0 else min(interval * 2 ** (failures - 1), max_backoff)
        if wait(delay):
            break
    return 0


def verify(log: Path, repo: str, *, branch: str = DEFAULT_BRANCH, name: str = DEFAULT_NAME,
           trusted_keys: Path | None = None, require_signatures: bool = False) -> str:
    """Check `log` against the PUBLISHED anchor only. Raises AnchorGitError if it fails."""
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        published = _fetch_published(repo, branch, name, work)
        if not published:
            raise AnchorGitError(f"nothing published on {branch} yet, so there is nothing to check against")
        ok, message = verify_log_against(log, work / name, trusted_keys, require_signatures)
        if not ok:
            raise AnchorGitError(message)
        return f"{message} (checked against {len(published)} published anchor records)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="runtime.anchor_git", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in ("publish", "verify", "watch"):
        p = sub.add_parser(cmd)
        p.add_argument("--repo", required=True, help="git URL or path of the separate anchor repository")
        p.add_argument("--branch", default=DEFAULT_BRANCH)
        p.add_argument("--name", default=DEFAULT_NAME, help="file name inside the repository")
        p.add_argument("--log", type=Path, required=(cmd == "verify"),
                       help="receipt log" + (" (publish: check it against its anchor first)" if cmd == "publish" else ""))
        p.add_argument("--trusted-keys", type=Path,
                       help="public keys to check signatures against (keep them out of the log writer's reach)")
        p.add_argument("--require-signatures", action="store_true",
                       help="every entry and anchor record must be signed (needs --trusted-keys)")
        if cmd in ("publish", "watch"):
            p.add_argument("--anchor", type=Path, required=True)
        if cmd == "publish":
            p.add_argument("--status-file", type=Path,
                           help="also record the outcome here, so a monitor can see how fresh the published anchor is")
        if cmd == "watch":
            p.add_argument("--status-file", type=Path, required=True,
                           help="where to record each outcome (never the repo URL); the operator screen reads it")
            p.add_argument("--interval", type=float, default=300.0, help="seconds between publishes (default 300)")
            p.add_argument("--max-backoff", type=float, default=None,
                           help="longest wait after repeated failures, in seconds "
                                "(default: 1800, or the interval if that is longer)")
            p.add_argument("--max-runs", type=int, help="stop after this many runs (for testing)")
    args = parser.parse_args(argv)
    if shutil.which("git") is None:
        print("git is not installed", file=sys.stderr)
        return 2
    if args.require_signatures and not args.trusted_keys:
        parser.error("--require-signatures needs --trusted-keys")
    options = dict(branch=args.branch, name=args.name, log=args.log, trusted_keys=args.trusted_keys,
                   require_signatures=args.require_signatures)
    if args.command == "watch":
        if args.interval < 1:
            parser.error("--interval must be at least 1 second")
        if args.max_backoff is None:
            args.max_backoff = max(1800.0, args.interval)
        elif args.max_backoff < args.interval:
            parser.error("--max-backoff must not be shorter than --interval")
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())  # finish cleanly; a run in progress completes first
        print(f"watching: publishing every {args.interval:g}s; Ctrl+C or SIGTERM to stop", flush=True)
        return watch(args.anchor, args.repo, status_file=args.status_file, interval=args.interval,
                     max_backoff=args.max_backoff, stop=stop, max_runs=args.max_runs, **options)
    try:
        if args.command == "publish":
            if args.status_file:
                print(publish_and_record(args.anchor, args.repo, status_file=args.status_file, **options))
            else:
                print(publish(args.anchor, args.repo, **options))
        else:
            print(verify(args.log, args.repo, branch=args.branch, name=args.name,
                         trusted_keys=args.trusted_keys, require_signatures=args.require_signatures))
    except AnchorGitError as exc:
        print(f"anchor_git: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
