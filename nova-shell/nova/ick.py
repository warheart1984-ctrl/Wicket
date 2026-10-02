"""Ask the ICK kernel (`infinityctl`) before Nova calls a model.

Opt-in: set NOVA_ICK_POLICY to a policy file to switch the gate on. Optional:
NOVA_ICK_BIN (path to infinityctl), NOVA_ICK_LOG (chained receipt log) and
NOVA_ICK_ANCHOR (anchor file, needs NOVA_ICK_LOG).

The gate fails closed: once it is on, a missing binary, a kernel error or any verdict other
than `allow` stops the model call. Message text is never sent to the kernel, only sizes.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, AsyncIterator, Iterator

from nova.errors import ProviderError
from nova.ick_approvals import ApprovalStore

_HERE = Path(__file__).resolve()


class KernelRefusal(ProviderError):
    """The kernel did not allow this model call (or could not be asked)."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        receipt_id: str | None = None,
        proposal_hash: str | None = None,
    ) -> None:
        super().__init__(code=code, message=message)
        self.receipt_id = receipt_id
        # Set when a human could approve this request: `python -m nova.cli approve <hash>`.
        self.proposal_hash = proposal_hash


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
        approvals: ApprovalStore | None = None,
    ) -> None:
        if anchor and not log:
            raise ValueError("NOVA_ICK_ANCHOR needs NOVA_ICK_LOG")
        self.approvals = approvals
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
            approvals=approval_store_from_env(env),
        )

    def _run(self, proposal: dict[str, Any], approval_ids: list[str]) -> dict[str, Any]:
        """Ask the kernel once. Any failure to get an answer is a refusal (fail closed)."""
        try:
            binary = _find_binary(self.binary)
        except KernelRefusal:
            raise
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proposal.json"
            path.write_text(json.dumps(proposal))
            cmd = [binary, "evaluate", "--proposal", str(path), "--policy", str(self.policy)]
            for approval_id in approval_ids:
                cmd += ["--approval", approval_id]
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
        return json.loads(done.stdout)

    def check(
        self,
        *,
        target: str,
        governed_request: dict[str, Any] | None = None,
        action: str = "chat_completion",
        effect: str = "read",
        risk: str = "low",
    ) -> dict[str, str]:
        """Return {"verdict", "receipt_id"} if allowed; raise KernelRefusal otherwise.

        The default describes a model call. Other actions pass their own `action`/`effect`.
        A verdict that needs a human is cleared only by a matching approval (see
        nova/ick_approvals.py); otherwise the request is parked as pending and refused.
        """
        try:
            policy_id = json.loads(self.policy.read_text())["policy_id"]
        except Exception as exc:
            raise KernelRefusal(code="KERNEL_UNAVAILABLE", message=f"cannot read policy: {exc}") from exc
        proposal = build_proposal(
            policy_id=policy_id, target=target, governed_request=governed_request,
            action=action, effect=effect, risk=risk,
        )
        out = self._run(proposal, [])
        verdict = str(out["decision"]["verdict"])
        receipt_id = str(out["receipt"]["receipt_id"])
        if verdict == "allow":
            return {"verdict": verdict, "receipt_id": receipt_id}
        proposal_hash = str(out["decision"]["proposal_hash"])
        codes = ",".join(out["decision"].get("reason_codes") or [])
        if verdict == "await_human_approval" and self.approvals is not None:
            self.approvals.record_pending(proposal_hash=proposal_hash, summary={
                "action": action, "target": target, "effect": effect, "risk": risk,
                "payload": proposal["payload"],
            })
            entry = self.approvals.claim(proposal_hash)
            if entry is not None:
                # Same request again, now carrying the human's approval id.
                approved = self._run({**proposal, "approval_id": entry["approval_id"]},
                                     [entry["approval_id"]])
                if str(approved["decision"]["verdict"]) == "allow":
                    return {
                        "verdict": "allow",
                        "receipt_id": str(approved["receipt"]["receipt_id"]),
                        "approval_id": str(entry["approval_id"]),
                        "approved_by": str(entry.get("approved_by", "")),
                    }
        raise KernelRefusal(
            code="KERNEL_AWAITING_APPROVAL" if verdict == "await_human_approval" else "KERNEL_DENIED",
            message=f"kernel verdict: {verdict} ({codes})",
            receipt_id=receipt_id,
            proposal_hash=proposal_hash if verdict == "await_human_approval" else None,
        )


def build_proposal(
    *,
    policy_id: str,
    target: str,
    governed_request: dict[str, Any] | None,
    action: str,
    effect: str,
    risk: str,
) -> dict[str, Any]:
    """A proposal that is identical for an identical request, so its hash is stable.

    That stability is what lets a human approve "this request" and have the approval match
    when it comes back. The text itself is never included, only its size and a SHA-256.
    """
    messages = (governed_request or {}).get("messages") or []
    payload: dict[str, Any] = {}
    if messages:
        texts = [str(m.get("content", "")) for m in messages]
        payload = {
            "messages": len(messages),
            "message_chars": sum(len(t) for t in texts),
            "request_sha256": hashlib.sha256(json.dumps(texts).encode()).hexdigest(),
        }
    identity = json.dumps(
        [action, target, effect, risk, payload], sort_keys=True, separators=(",", ":")
    )
    return {
        "version": "infinity.proposal.v1",
        "proposal_id": "nova-" + hashlib.sha256(identity.encode()).hexdigest()[:32],
        "actor": {"kind": "agent", "id": "nova-shell"},
        "action": action,
        "target": target,
        "effect": effect,
        "risk": risk,
        "requires_human_approval": False,
        "policy_version": policy_id,
        "payload": payload,
        "evidence_refs": [],
    }


def approval_store_from_env(env: Any = None) -> ApprovalStore | None:
    """NOVA_ICK_APPROVALS (the human-written file) switches approvals on."""
    env = os.environ if env is None else env
    approvals = (env.get("NOVA_ICK_APPROVALS") or "").strip()
    if not approvals:
        return None
    state = (env.get("NOVA_ICK_STATE") or "").strip() or ".runtime/ick-state"
    return ApprovalStore(approvals, state)


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


def gate_action(
    *,
    target: str,
    action: str,
    effect: str,
    governed_request: dict[str, Any] | None = None,
    risk: str = "low",
) -> dict[str, str] | None:
    """Ask the kernel about one action. Returns None when the gate is off; raises KernelRefusal."""
    gate = IckGate.from_env()
    if gate is None:
        return None
    return gate.check(
        target=target, governed_request=governed_request, action=action, effect=effect, risk=risk
    )


def gate_provider(provider: Any) -> Any:
    """Wrap `provider` if the gate is switched on in the environment."""
    gate = IckGate.from_env()
    return IckGatedProvider(provider, gate) if gate else provider
