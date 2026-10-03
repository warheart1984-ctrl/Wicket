"""Human approvals for kernel `await_human_approval` verdicts.

How it works
  1. The kernel says a request needs approval. Nova refuses it, writes the request's
     proposal hash to `pending.jsonl`, and tells the caller which hash needs approving.
  2. A human runs `python -m nova.cli approve <hash>`. That appends one record to the
     approvals file: bound to that single hash, with an expiry and a use limit.
  3. When the same request comes in again, Nova finds the record, passes its approval id to
     the kernel, and records the use in `used.jsonl`.
  A human can instead DENY a pending request (`python -m nova.cli deny <hash>`). That appends one
  record to the denials file, which sits next to the approvals file and is read-only to Nova in
  the same way. A denial is final for that exact request: it cancels any approval already given
  for it, nothing can approve it afterwards, and Nova refuses it as `KERNEL_DENIED_BY_HUMAN`. A
  request that differs in any way has a different hash and starts again as a new pending one.
  To undo a denial, a human deletes its line from the denials file.
  A pending request that nobody decides expires after `pending_ttl` seconds (default 7 days). An
  expired request is no longer listed, and can no longer be approved or denied, but the file is
  never rewritten. If the same request comes in again it is recorded as a fresh pending request.
  Expiry does not touch approvals (they have their own expiry) or denials (they are final).

Trust boundary (read this)
  * There is deliberately NO HTTP route for approving. A client, or a model with tool
    access, that could call one would be approving its own requests.
  * Nova only ever READS the approvals file. Keep it somewhere the Nova server process
    cannot write (other account, read-only mount, file permissions). If Nova can write it,
    nothing stops it approving itself.
  * This protects against requests that arrive over the API or from model-driven tools. It
    does not protect against someone who can edit Nova's code or the approvals file.
  * The kernel only checks that an approval id is in the list it is given; it cannot tell a
    human from Nova. The binding to one request and the human-only write access come from
    this module and from where you keep the file.
"""

from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

try:  # Unix file locks
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]
try:  # Windows file locks
    import msvcrt
except ImportError:
    msvcrt = None  # type: ignore[assignment]

# How long to wait for the lock that makes "use the last approval" a one-at-a-time action.
LOCK_TIMEOUT = 10.0


class LockTimeout(OSError):
    """The lock could not be taken in time. Callers treat that as "not approved", never as "approved"."""


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL file; a missing file or a malformed line is skipped, never trusted."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _append(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def _try_lock(handle: Any) -> bool:
    """One non-blocking attempt at an exclusive lock on the file; True if we now hold it."""
    try:
        if fcntl:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:  # pragma: no cover - no locking available on this platform
            raise LockTimeout("this platform has no file locking, so approval uses cannot be counted safely")
        return True
    except (BlockingIOError, PermissionError):
        return False
    except OSError as exc:
        if msvcrt and not fcntl:  # Windows reports a held lock as a plain OSError
            return False
        raise exc


def _unlock(handle: Any) -> None:
    if fcntl:
        fcntl.flock(handle, fcntl.LOCK_UN)
    elif msvcrt:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Hold an exclusive lock on a file next to `path` (works across processes on Unix and Windows).
    Waits up to LOCK_TIMEOUT seconds, then raises LockTimeout."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix(path.suffix + ".lock").open("a+") as handle:
        deadline = time.monotonic() + LOCK_TIMEOUT
        while not _try_lock(handle):
            if time.monotonic() >= deadline:
                raise LockTimeout(f"could not lock {path} within {LOCK_TIMEOUT:g} s")
            time.sleep(0.01)
        try:
            yield
        finally:
            _unlock(handle)


DEFAULT_PENDING_TTL = 7 * 24 * 3600.0


class ApprovalStore:
    def __init__(self, approvals_file: str | Path, state_dir: str | Path, *,
                 pending_ttl: float = DEFAULT_PENDING_TTL) -> None:
        if not pending_ttl > 0:
            raise ValueError("pending_ttl must be positive")
        self.pending_ttl = float(pending_ttl)
        self.approvals_file = Path(approvals_file)
        self.denials_file = Path(str(approvals_file) + ".denials")
        self.pending_file = Path(state_dir) / "pending.jsonl"
        self.used_file = Path(state_dir) / "used.jsonl"

    # --- Nova's side: read approvals, write pending and used -------------------------------

    def record_pending(self, *, proposal_hash: str, summary: dict[str, Any],
                       now: float | None = None) -> None:
        now = time.time() if now is None else now
        if any(row.get("proposal_hash") == proposal_hash for row in self._live(now)):
            return  # already waiting; an expired earlier request does not count
        _append(self.pending_file, {"proposal_hash": proposal_hash, "requested_at": int(now), **summary})

    def is_denied(self, proposal_hash: str) -> bool:
        """True if a human denied this request. A denials file that exists but cannot be read
        counts as denying everything: failing open would let a denied request through."""
        try:
            self.denials_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            return False
        except OSError:
            return True
        return any(row.get("proposal_hash") == proposal_hash for row in _read_jsonl(self.denials_file))

    def claim(self, proposal_hash: str, *, now: float | None = None) -> dict[str, Any] | None:
        """Use one approval for `proposal_hash`, or return None. Atomic across processes."""
        now = time.time() if now is None else now
        if self.is_denied(proposal_hash):
            return None
        try:
            with _locked(self.used_file):
                used = _read_jsonl(self.used_file)
                for entry in _read_jsonl(self.approvals_file):
                    if entry.get("proposal_hash") != proposal_hash or not entry.get("approval_id"):
                        continue
                    try:
                        if float(entry["expires_at"]) <= now:
                            continue
                        allowed_uses = int(entry.get("uses", 1))
                    except (KeyError, TypeError, ValueError):
                        continue  # a malformed record never approves anything
                    taken = sum(1 for row in used if row.get("approval_id") == entry["approval_id"])
                    if taken < allowed_uses:
                        _append(self.used_file, {"approval_id": entry["approval_id"],
                                                 "proposal_hash": proposal_hash, "used_at": now})
                        return entry
        except LockTimeout:
            return None  # could not count safely: do not approve
        return None

    # --- the human's side (CLI only) ---------------------------------------------------------

    def _alive(self, row: dict[str, Any], now: float) -> bool:
        """A request is live for `pending_ttl` seconds. A malformed time never counts as live."""
        try:
            return now - float(row["requested_at"]) <= self.pending_ttl
        except (KeyError, TypeError, ValueError):
            return False

    def _live(self, now: float) -> list[dict[str, Any]]:
        latest: dict[str, dict[str, Any]] = {}
        for row in _read_jsonl(self.pending_file):  # a later row for the same request wins
            if isinstance(row.get("proposal_hash"), str):
                latest[row["proposal_hash"]] = row
        return [row for row in latest.values() if self._alive(row, now)]

    def pending(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Requests asked for and not yet expired (one row per request, newest ask)."""
        return self._live(time.time() if now is None else now)

    def expired_count(self, *, now: float | None = None) -> int:
        """How many requests have expired without anyone deciding them."""
        now = time.time() if now is None else now
        approved = {row.get("proposal_hash") for row in self.approvals()}
        live = {row["proposal_hash"] for row in self._live(now)}
        seen = {row.get("proposal_hash") for row in _read_jsonl(self.pending_file)
                if isinstance(row.get("proposal_hash"), str)}
        return sum(1 for h in seen if h not in live and h not in approved and not self.is_denied(h))

    def approvals(self) -> list[dict[str, Any]]:
        return _read_jsonl(self.approvals_file)

    def denials(self) -> list[dict[str, Any]]:
        return _read_jsonl(self.denials_file)

    def waiting(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Pending requests nobody has denied."""
        return [row for row in self.pending(now=now) if not self.is_denied(str(row.get("proposal_hash")))]

    def active(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Approvals that can still be used, each with how many uses are left."""
        now = time.time() if now is None else now
        used = _read_jsonl(self.used_file)
        out: list[dict[str, Any]] = []
        for entry in self.approvals():
            try:
                if float(entry["expires_at"]) <= now or self.is_denied(str(entry.get("proposal_hash"))):
                    continue
                left = int(entry.get("uses", 1)) - sum(
                    1 for row in used if row.get("approval_id") == entry.get("approval_id"))
            except (KeyError, TypeError, ValueError):
                continue
            if left > 0:
                out.append({**entry, "remaining": left})
        return out

    def approve(self, proposal_hash: str, *, approved_by: str, expires_in: float = 3600,
                uses: int = 1, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        if uses < 1 or expires_in <= 0:
            raise ValueError("uses must be at least 1 and expires_in must be positive")
        if not any(row.get("proposal_hash") == proposal_hash for row in self.pending(now=now)):
            raise KeyError(f"no pending request with hash {proposal_hash} (it may have expired)")
        if self.is_denied(proposal_hash):
            raise ValueError("a human already denied this request")
        entry = {
            "approval_id": f"approval-{uuid.uuid4()}",
            "proposal_hash": proposal_hash,
            "approved_by": approved_by,
            "approved_at": int(now),
            "expires_at": int(now + expires_in),
            "uses": int(uses),
        }
        _append(self.approvals_file, entry)
        return entry

    def deny(self, proposal_hash: str, *, denied_by: str, reason: str = "",
             now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        if not any(row.get("proposal_hash") == proposal_hash for row in self.pending(now=now)):
            raise KeyError(f"no pending request with hash {proposal_hash} (it may have expired)")
        if self.is_denied(proposal_hash):
            raise ValueError("a human already denied this request")
        entry = {
            "denial_id": f"denial-{uuid.uuid4()}",
            "proposal_hash": proposal_hash,
            "denied_by": denied_by,
            "denied_at": int(now),
            "reason": reason,
        }
        _append(self.denials_file, entry)
        return entry
