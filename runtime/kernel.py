"""Ask the ICK kernel (`infinityctl`) to approve an action before it happens."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = ROOT / "demo" / "policy.json"


class KernelError(RuntimeError):
    pass


def sha256_text(text: str) -> str:
    """`sha256:<hex>` of text, the form outcome records use. Only the hash is ever logged."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Decision:
    verdict: str  # "allow", "await_human_approval" or "deny"
    reason_codes: list[str]
    receipt: dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


def find_binary() -> str:
    candidates = [
        os.getenv("INFINITYCTL", ""),
        str(ROOT / "target" / "release" / "infinityctl"),
        str(ROOT / "target" / "debug" / "infinityctl"),
        shutil.which("infinityctl") or "",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise KernelError("infinityctl not found; run `cargo build` or set INFINITYCTL")


class Kernel:
    def __init__(
        self,
        policy: Path = DEFAULT_POLICY,
        receipt_log: Path | None = None,
        binary: str | None = None,
        anchor: Path | None = None,
    ) -> None:
        if anchor and not receipt_log:
            raise KernelError("an anchor needs a receipt log")
        self.policy = Path(policy)
        self.receipt_log = Path(receipt_log) if receipt_log else None
        # Keep the anchor where whoever can edit the receipt log cannot also edit it.
        self.anchor = Path(anchor) if anchor else None
        self.binary = binary or find_binary()

    def evaluate(self, proposal: dict[str, Any]) -> Decision:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proposal.json"
            path.write_text(json.dumps(proposal))
            cmd = [self.binary, "evaluate", "--proposal", str(path), "--policy", str(self.policy)]
            if self.receipt_log:
                self.receipt_log.parent.mkdir(parents=True, exist_ok=True)
                cmd += ["--log", str(self.receipt_log)]  # the CLI chains and appends the receipt
                if self.anchor:
                    self.anchor.parent.mkdir(parents=True, exist_ok=True)
                    cmd += ["--anchor", str(self.anchor)]
            done = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if done.returncode != 0:
            raise KernelError(done.stderr.strip() or f"infinityctl exited {done.returncode}")
        out = json.loads(done.stdout)
        decision, receipt = out["decision"], out["receipt"]
        return Decision(decision["verdict"], list(decision.get("reason_codes") or []), receipt)

    def record_outcome(
        self,
        decision_receipt_id: str,
        *,
        status: str,
        request_sha256: str | None = None,
        response_sha256: str | None = None,
    ) -> str | None:
        """Append an outcome (completed / failed) for an `allow`, chained to the same log.

        Returns the outcome's receipt id, or None if no receipt log is configured. Raises
        KernelError if it cannot be written."""
        if not self.receipt_log:
            return None
        cmd = [self.binary, "record-outcome", "--log", str(self.receipt_log),
               "--decision-receipt", decision_receipt_id, "--status", status]
        if self.anchor:
            cmd += ["--anchor", str(self.anchor)]
        if request_sha256:
            cmd += ["--request-sha256", request_sha256]
        if response_sha256:
            cmd += ["--response-sha256", response_sha256]
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if done.returncode != 0:
            raise KernelError(done.stderr.strip() or f"infinityctl exited {done.returncode}")
        return str(json.loads(done.stdout)["outcome"]["receipt_id"])

    def verify(self) -> bool:
        """True if the receipt log is an unbroken chain that matches its anchor (if any)."""
        if not self.receipt_log or not self.receipt_log.exists():
            raise KernelError("no receipt log to verify")
        cmd = [self.binary, "verify-log", "--log", str(self.receipt_log)]
        if self.anchor:
            cmd += ["--anchor", str(self.anchor)]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).returncode == 0
