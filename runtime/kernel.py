"""Ask the ICK kernel (`infinityctl`) to approve an action before it happens."""

from __future__ import annotations

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
    ) -> None:
        self.policy = Path(policy)
        self.receipt_log = Path(receipt_log) if receipt_log else None
        self.binary = binary or find_binary()

    def evaluate(self, proposal: dict[str, Any]) -> Decision:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proposal.json"
            path.write_text(json.dumps(proposal))
            done = subprocess.run(
                [self.binary, "evaluate", "--proposal", str(path), "--policy", str(self.policy)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        if done.returncode != 0:
            raise KernelError(done.stderr.strip() or f"infinityctl exited {done.returncode}")
        out = json.loads(done.stdout)
        decision, receipt = out["decision"], out["receipt"]
        if self.receipt_log:
            self.receipt_log.parent.mkdir(parents=True, exist_ok=True)
            with self.receipt_log.open("a") as log:
                log.write(json.dumps(receipt, sort_keys=True) + "\n")
        return Decision(decision["verdict"], list(decision.get("reason_codes") or []), receipt)
