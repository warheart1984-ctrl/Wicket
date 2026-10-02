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
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from runtime.kernel import KernelError, find_binary

DEFAULT_BRANCH = "anchors"
DEFAULT_NAME = "anchor.jsonl"


class AnchorGitError(RuntimeError):
    pass


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


def verify_log_against(log: Path, anchor: Path) -> tuple[bool, str]:
    """Run the kernel's verify-log with `anchor`. Returns (ok, message)."""
    try:
        binary = find_binary()
    except KernelError as exc:
        raise AnchorGitError(str(exc)) from exc
    cmd = [binary, "verify-log", "--log", str(log)]
    if anchor:
        cmd += ["--anchor", str(anchor)]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return done.returncode == 0, (done.stdout + done.stderr).strip()


def publish(anchor: Path, repo: str, *, branch: str = DEFAULT_BRANCH, name: str = DEFAULT_NAME,
            log: Path | None = None) -> str:
    """Push `anchor` to `repo`. Returns a one-line result. Raises AnchorGitError on refusal."""
    local = _lines(anchor.read_text()) if anchor.exists() else []
    if not local:
        raise AnchorGitError(f"{anchor} has no anchor records to publish")
    if log is not None:
        ok, message = verify_log_against(log, anchor)
        if not ok:
            raise AnchorGitError(f"refusing to publish: the log does not match its own anchor ({message})")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        published = _fetch_published(repo, branch, name, work)
        if published is None:
            _git("init", "--quiet", str(work))
            _git("checkout", "--quiet", "--orphan", branch, cwd=work)
            _git("remote", "add", "origin", repo, cwd=work)
            published = []
        if local[: len(published)] != published:
            raise AnchorGitError(
                "refusing to publish: the local anchor does not continue what is already published "
                f"({len(published)} published records, {len(local)} local). It was edited, shortened "
                "or replaced.")
        if len(local) == len(published):
            return f"already up to date ({len(local)} records)"
        (work / name).write_text("\n".join(local) + "\n")
        _git("add", name, cwd=work)
        _git("commit", "--quiet", "-m",
             f"anchor: {len(local)} records (+{len(local) - len(published)})\n\n{local[-1]}", cwd=work)
        _git("push", "--quiet", "origin", f"HEAD:refs/heads/{branch}", cwd=work)  # never forced
        return f"published {len(local) - len(published)} new record(s); {len(local)} total on {branch}"


def verify(log: Path, repo: str, *, branch: str = DEFAULT_BRANCH, name: str = DEFAULT_NAME) -> str:
    """Check `log` against the PUBLISHED anchor only. Raises AnchorGitError if it fails."""
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        published = _fetch_published(repo, branch, name, work)
        if not published:
            raise AnchorGitError(f"nothing published on {branch} yet, so there is nothing to check against")
        ok, message = verify_log_against(log, work / name)
        if not ok:
            raise AnchorGitError(message)
        return f"{message} (checked against {len(published)} published anchor records)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="runtime.anchor_git", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in ("publish", "verify"):
        p = sub.add_parser(cmd)
        p.add_argument("--repo", required=True, help="git URL or path of the separate anchor repository")
        p.add_argument("--branch", default=DEFAULT_BRANCH)
        p.add_argument("--name", default=DEFAULT_NAME, help="file name inside the repository")
        p.add_argument("--log", type=Path, required=(cmd == "verify"),
                       help="receipt log" + (" (publish: check it against its anchor first)" if cmd == "publish" else ""))
        if cmd == "publish":
            p.add_argument("--anchor", type=Path, required=True)
    args = parser.parse_args(argv)
    if shutil.which("git") is None:
        print("git is not installed", file=sys.stderr)
        return 2
    try:
        if args.command == "publish":
            print(publish(args.anchor, args.repo, branch=args.branch, name=args.name, log=args.log))
        else:
            print(verify(args.log, args.repo, branch=args.branch, name=args.name))
    except AnchorGitError as exc:
        print(f"anchor_git: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
