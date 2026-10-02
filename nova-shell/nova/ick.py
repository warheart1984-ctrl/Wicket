"""Ask the ICK kernel (`infinityctl`) before Nova calls a model.

Opt-in: set NOVA_ICK_POLICY to a policy file to switch the gate on. Optional:
NOVA_ICK_BIN (path to infinityctl), NOVA_ICK_LOG (chained receipt log) and
NOVA_ICK_ANCHOR (anchor file, needs NOVA_ICK_LOG).

The gate fails closed: once it is on, a missing binary, a kernel error or any verdict other
than `allow` stops the model call. Message text is never sent to the kernel, only sizes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, AsyncIterator, Iterator

from nova.errors import ProviderError

_HERE = Path(__file__).resolve()


class KernelRefusal(ProviderError):
    """The kernel did not allow this model call (or could not be asked)."""

    def __init__(self, *, code: str, message: str, receipt_id: str | None = None) -> None:
        super().__init__(code=code, message=message)
        self.receipt_id = receipt_id


def _find_binary(explicit: str | None) -> str:
    candidates = [explicit or ""]
    for parent in list(_HERE.parents)[:4]:
        candidates += [str(parent / "target" / "release" / "infinityctl"),
                       str(parent / "target" / "debug" / "infinityctl")]
    candidates.append(shutil.which("infinityctl") or "")
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise KernelRefusal(
        code="KERNEL_UNAVAILABLE",
        message="infinityctl not found; build it with `cargo build` or set NOVA_ICK_BIN",
    )


class IckGate:
    def __init__(
        self,
        policy: str | Path,
        *,
        binary: str | None = None,
        log: str | Path | None = None,
        anchor: str | Path | None = None,
    ) -> None:
        if anchor and not log:
            raise ValueError("NOVA_ICK_ANCHOR needs NOVA_ICK_LOG")
        self.policy = Path(policy)
        self.binary = binary
        self.log = Path(log) if log else None
        self.anchor = Path(anchor) if anchor else None

    @classmethod
    def from_env(cls, env: Any = None) -> "IckGate | None":
        env = os.environ if env is None else env
        policy = (env.get("NOVA_ICK_POLICY") or "").strip()
        if not policy:
            return None
        return cls(
            policy,
            binary=(env.get("NOVA_ICK_BIN") or "").strip() or None,
            log=(env.get("NOVA_ICK_LOG") or "").strip() or None,
            anchor=(env.get("NOVA_ICK_ANCHOR") or "").strip() or None,
        )

    def check(self, *, target: str, governed_request: dict[str, Any]) -> dict[str, str]:
        """Return {"verdict", "receipt_id"} if allowed; raise KernelRefusal otherwise."""
        messages = governed_request.get("messages") or []
        try:
            policy_id = json.loads(self.policy.read_text())["policy_id"]
            binary = _find_binary(self.binary)
        except KernelRefusal:
            raise
        except Exception as exc:
            raise KernelRefusal(code="KERNEL_UNAVAILABLE", message=f"cannot read policy: {exc}") from exc
        proposal = {
            "version": "infinity.proposal.v1",
            "proposal_id": f"nova-{uuid.uuid4()}",
            "actor": {"kind": "agent", "id": "nova-shell"},
            "action": "chat_completion",
            "target": target,
            "effect": "read",
            "risk": "low",
            "requires_human_approval": False,
            "policy_version": policy_id,
            # Sizes only; the message text itself never goes into a proposal.
            "payload": {
                "messages": len(messages),
                "message_chars": sum(len(str(m.get("content", ""))) for m in messages),
            },
            "evidence_refs": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proposal.json"
            path.write_text(json.dumps(proposal))
            cmd = [binary, "evaluate", "--proposal", str(path), "--policy", str(self.policy)]
            if self.log:
                self.log.parent.mkdir(parents=True, exist_ok=True)
                cmd += ["--log", str(self.log)]
                if self.anchor:
                    self.anchor.parent.mkdir(parents=True, exist_ok=True)
                    cmd += ["--anchor", str(self.anchor)]
            try:
                done = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as exc:
                raise KernelRefusal(code="KERNEL_UNAVAILABLE", message=str(exc)) from exc
        if done.returncode != 0:
            raise KernelRefusal(
                code="KERNEL_UNAVAILABLE",
                message=done.stderr.strip() or f"infinityctl exited {done.returncode}",
            )
        out = json.loads(done.stdout)
        verdict = str(out["decision"]["verdict"])
        receipt_id = str(out["receipt"]["receipt_id"])
        if verdict == "allow":
            return {"verdict": verdict, "receipt_id": receipt_id}
        codes = ",".join(out["decision"].get("reason_codes") or [])
        raise KernelRefusal(
            code="KERNEL_AWAITING_APPROVAL" if verdict == "await_human_approval" else "KERNEL_DENIED",
            message=f"kernel verdict: {verdict} ({codes})",
            receipt_id=receipt_id,
        )


class IckGatedProvider:
    """Wrap a provider so every model call is approved by the kernel first."""

    def __init__(self, inner: Any, gate: IckGate) -> None:
        self._inner = inner
        self._gate = gate

    def _target(self) -> str:
        name = getattr(self._inner, "provider_id", None) or type(self._inner).__name__
        return f"{name}:{getattr(self._inner, 'model', 'unknown')}"

    def chat_completion(self, governed_request: dict[str, Any]) -> dict[str, Any]:
        ick = self._gate.check(target=self._target(), governed_request=governed_request)
        result = self._inner.chat_completion(governed_request)
        return {**result, "ick": ick}

    async def invoke(self, messages: list[Any], **kwargs: Any) -> Any:
        request = {"messages": [{"content": getattr(m, "content", None) or m.get("content", "")} for m in messages]}
        self._gate.check(target=self._target(), governed_request=request)
        return await self._inner.invoke(messages, **kwargs)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)  # AttributeError if the inner provider lacks it
        if name == "chat_completion_stream":
            def gated(governed_request: dict[str, Any]) -> Iterator[dict[str, Any]]:
                self._gate.check(target=self._target(), governed_request=governed_request)
                yield from attr(governed_request)

            return gated
        return attr


def gate_provider(provider: Any) -> Any:
    """Wrap `provider` if the gate is switched on in the environment."""
    gate = IckGate.from_env()
    return IckGatedProvider(provider, gate) if gate else provider
