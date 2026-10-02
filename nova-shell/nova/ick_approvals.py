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

try:  # POSIX only; without it, two simultaneous uses of the last approval could both succeed.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]


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


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix(path.suffix + ".lock").open("a") as handle:
        if fcntl:
            fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl:
                fcntl.flock(handle, fcntl.LOCK_UN)


class ApprovalStore:
    def __init__(self, approvals_file: str | Path, state_dir: str | Path) -> None:
        self.approvals_file = Path(approvals_file)
        self.denials_file = Path(str(approvals_file) + ".denials")
        self.pending_file = Path(state_dir) / "pending.jsonl"
        self.used_file = Path(state_dir) / "used.jsonl"

    # --- Nova's side: read approvals, write pending and used -------------------------------

    def record_pending(self, *, proposal_hash: str, summary: dict[str, Any]) -> None:
        if any(row.get("proposal_hash") == proposal_hash for row in _read_jsonl(self.pending_file)):
            return
        _append(self.pending_file, {"proposal_hash": proposal_hash, "requested_at": int(time.time()), **summary})

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
        return None

    # --- the human's side (CLI only) ---------------------------------------------------------

    def pending(self) -> list[dict[str, Any]]:
        return _read_jsonl(self.pending_file)

    def approvals(self) -> list[dict[str, Any]]:
        return _read_jsonl(self.approvals_file)

    def denials(self) -> list[dict[str, Any]]:
        return _read_jsonl(self.denials_file)

    def waiting(self) -> list[dict[str, Any]]:
        """Pending requests nobody has denied."""
        return [row for row in self.pending() if not self.is_denied(str(row.get("proposal_hash")))]

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
        if not any(row.get("proposal_hash") == proposal_hash for row in self.pending()):
            raise KeyError(f"no pending request with hash {proposal_hash}")
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
        if not any(row.get("proposal_hash") == proposal_hash for row in self.pending()):
            raise KeyError(f"no pending request with hash {proposal_hash}")
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
