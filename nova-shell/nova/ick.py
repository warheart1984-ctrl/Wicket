"""Ask the ICK kernel (`infinityctl`) before Nova calls a model.

Opt-in: set NOVA_ICK_POLICY to a policy file to switch the gate on. Optional:
NOVA_ICK_BIN (path to infinityctl), NOVA_ICK_LOG (chained receipt log) and
NOVA_ICK_ANCHOR (anchor file, needs NOVA_ICK_LOG).

Or set NOVA_ICK_SERVICE to the socket of a signer service (runtime/ick_service.py). Then the
kernel runs in that other process, with its own policy, key and log, and Nova holds none of them.

The gate fails closed: once it is on, a missing binary, a kernel error or any verdict other
than `allow` stops the model call. Message text is never sent to the kernel, only sizes.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any, AsyncIterator, Iterator

from nova.errors import ProviderError
from nova.ick_approvals import DEFAULT_PENDING_TTL, ApprovalStore

_HERE = Path(__file__).resolve()
_EXE = "infinityctl.exe" if os.name == "nt" else "infinityctl"  # what `cargo build` produces


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


class OutcomeNotRecorded(ProviderError):
    """The model call ran but its outcome could not be written to the receipt log.

    The reply is withheld: no evidence, no answer. (For a stream the text has already gone out,
    so there the gap is reported by `verify-log` as an allow with no outcome instead.)"""

    def __init__(self, message: str) -> None:
        super().__init__(code="KERNEL_OUTCOME_NOT_RECORDED", message=message)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def reply_text(result: Any) -> str:
    """The reply text of a `chat_completion` result, or '' if it has none."""
    try:
        return str(result["completion"]["choices"][0]["message"]["content"] or "")
    except (KeyError, IndexError, TypeError):
        return ""


def delta_text(chunk: Any) -> str:
    """The text carried by one streamed chunk (OpenAI style), or ''."""
    try:
        return str(chunk["choices"][0]["delta"].get("content") or "")
    except (KeyError, IndexError, TypeError, AttributeError):
        return ""


def _find_binary(explicit: str | None) -> str:
    candidates = [explicit or ""]
    for parent in list(_HERE.parents)[:4]:
        candidates += [str(parent / "target" / "release" / _EXE),
                       str(parent / "target" / "debug" / _EXE)]
    candidates.append(shutil.which("infinityctl") or "")
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise KernelRefusal(
        code="KERNEL_UNAVAILABLE",
        message="infinityctl not found; build it with `cargo build` or set NOVA_ICK_BIN",
    )


_SERVICE_REPLY_LIMIT = 4 << 20


def _call_service(path: Path, request: dict[str, Any], *, timeout: float = 30.0) -> dict[str, Any]:
    """One request to the signer service (runtime/ick_service.py). Any failure is a refusal."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(str(path))
            conn.sendall(json.dumps(request).encode() + b"\n")
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
                if len(data) > _SERVICE_REPLY_LIMIT:
                    raise ValueError("reply too large")
        reply = json.loads(data)
        if not isinstance(reply, dict):
            raise ValueError("reply is not an object")
    except (OSError, ValueError) as exc:
        raise KernelRefusal(code="KERNEL_UNAVAILABLE", message=f"signer service: {exc}") from exc
    if reply.get("ok") is not True or not isinstance(reply.get("result"), dict):
        raise KernelRefusal(code="KERNEL_UNAVAILABLE", message=f"signer service: {reply.get('error', 'refused')}")
    return reply["result"]


class IckGate:
    def __init__(
        self,
        policy: str | Path | None = None,
        *,
        service_socket: str | Path | None = None,
        binary: str | None = None,
        log: str | Path | None = None,
        anchor: str | Path | None = None,
        approvals: ApprovalStore | None = None,
        sign_key: str | Path | None = None,
    ) -> None:
        if anchor and not log:
            raise ValueError("NOVA_ICK_ANCHOR needs NOVA_ICK_LOG")
        self.approvals = approvals
        self.service = Path(service_socket) if service_socket else None
        if self.service is not None and (policy or sign_key or binary or log or anchor):
            raise ValueError("with a signer service, the policy, key, log and kernel belong to the "
                             "service: Nova must not be given them")
        if self.service is None and not policy:
            raise ValueError("a policy file (or a signer service socket) is required")
        self._service_policy_id: str | None = None
        # Private key file (mode 0600) used to sign every receipt, outcome and anchor record written.
        self.sign_key = Path(sign_key) if sign_key else None
        self.policy = Path(policy) if policy else Path()
        self.binary = binary
        self.log = Path(log) if log else None
        self.anchor = Path(anchor) if anchor else None

    @classmethod
    def from_env(cls, env: Any = None) -> "IckGate | None":
        env = os.environ if env is None else env
        policy = (env.get("NOVA_ICK_POLICY") or "").strip()
        service = (env.get("NOVA_ICK_SERVICE") or "").strip()
        if service:
            # The service owns the policy, key, log and anchor. Naming them here too would suggest
            # Nova can use them, so it is refused. (NOVA_ICK_LOG/ANCHOR are for the operator screen.)
            if policy or (env.get("NOVA_ICK_SIGN_KEY") or "").strip() or (env.get("NOVA_ICK_BIN") or "").strip():
                raise ValueError("NOVA_ICK_SERVICE is set: remove NOVA_ICK_POLICY, NOVA_ICK_SIGN_KEY and "
                                 "NOVA_ICK_BIN from Nova's environment; the signer service owns them")
            return cls(service_socket=service, approvals=approval_store_from_env(env))
        if not policy:
            return None
        return cls(
            policy,
            binary=(env.get("NOVA_ICK_BIN") or "").strip() or None,
            log=(env.get("NOVA_ICK_LOG") or "").strip() or None,
            anchor=(env.get("NOVA_ICK_ANCHOR") or "").strip() or None,
            approvals=approval_store_from_env(env),
            sign_key=(env.get("NOVA_ICK_SIGN_KEY") or "").strip() or None,
        )

    def _run(self, proposal: dict[str, Any], approval_ids: list[str]) -> dict[str, Any]:
        """Ask the kernel once. Any failure to get an answer is a refusal (fail closed)."""
        if self.service is not None:
            return _call_service(self.service, {"op": "evaluate", "proposal": proposal,
                                                "approval_ids": approval_ids})
        try:
            binary = _find_binary(self.binary)
        except KernelRefusal:
            raise
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "proposal.json"
            path.write_text(json.dumps(proposal))
            cmd = [binary, "evaluate", "--proposal", str(path), "--policy", str(self.policy)]
            if self.sign_key:
                cmd += ["--sign-key", str(self.sign_key)]
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

    def _policy_id(self) -> str:
        if self.service is not None:
            if self._service_policy_id is None:
                policy_id = _call_service(self.service, {"op": "info"}).get("policy_id")
                if not isinstance(policy_id, str) or not policy_id:
                    raise KernelRefusal(code="KERNEL_UNAVAILABLE", message="signer service gave no policy id")
                self._service_policy_id = policy_id
            return self._service_policy_id
        try:
            return str(json.loads(self.policy.read_text())["policy_id"])
        except Exception as exc:
            raise KernelRefusal(code="KERNEL_UNAVAILABLE", message=f"cannot read policy: {exc}") from exc

    def record_outcome(self, ick: dict[str, str], *, status: str, response_text: str | None) -> str | None:
        """Append an outcome entry (completed / failed) for the allow described by `ick`.

        Returns its receipt id, or None when no receipt log is configured (nothing to chain to).
        Raises OutcomeNotRecorded if it cannot be written."""
        if self.service is not None:
            try:
                result = _call_service(self.service, {
                    "op": "record_outcome", "decision_receipt": ick["receipt_id"], "status": status,
                    "request_sha256": ick.get("request_sha256"),
                    "response_sha256": sha256_text(response_text) if response_text is not None else None})
                return str(result["outcome"]["receipt_id"])
            except (KernelRefusal, KeyError, TypeError) as exc:
                raise OutcomeNotRecorded(getattr(exc, "message", None) or str(exc)) from exc
        if self.log is None:
            return None
        try:
            binary = _find_binary(self.binary)
        except KernelRefusal as exc:
            raise OutcomeNotRecorded(exc.message) from exc
        cmd = [binary, "record-outcome", "--log", str(self.log), "--decision-receipt", ick["receipt_id"],
               "--status", status]
        if self.sign_key:
            cmd += ["--sign-key", str(self.sign_key)]
        if self.anchor:
            cmd += ["--anchor", str(self.anchor)]
        if ick.get("request_sha256"):
            cmd += ["--request-sha256", ick["request_sha256"]]
        if response_text is not None:
            cmd += ["--response-sha256", sha256_text(response_text)]
        try:
            done = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as exc:
            raise OutcomeNotRecorded(str(exc)) from exc
        if done.returncode != 0:
            raise OutcomeNotRecorded(done.stderr.strip() or f"infinityctl exited {done.returncode}")
        return str(json.loads(done.stdout)["outcome"]["receipt_id"])

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
        policy_id = self._policy_id()
        proposal = build_proposal(
            policy_id=policy_id, target=target, governed_request=governed_request,
            action=action, effect=effect, risk=risk,
        )
        out = self._run(proposal, [])
        verdict = str(out["decision"]["verdict"])
        receipt_id = str(out["receipt"]["receipt_id"])
        evidence = _evidence(proposal)
        if verdict == "allow":
            return {"verdict": verdict, "receipt_id": receipt_id, **evidence}
        proposal_hash = str(out["decision"]["proposal_hash"])
        codes = ",".join(out["decision"].get("reason_codes") or [])
        if verdict == "await_human_approval" and self.approvals is not None:
            self.approvals.record_pending(proposal_hash=proposal_hash, summary={
                "action": action, "target": target, "effect": effect, "risk": risk,
                "payload": proposal["payload"],
            })
            if self.approvals.is_denied(proposal_hash):
                raise KernelRefusal(
                    code="KERNEL_DENIED_BY_HUMAN",
                    message="a human denied this request",
                    receipt_id=receipt_id,
                )
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
                        **evidence,
                    }
        raise KernelRefusal(
            code="KERNEL_AWAITING_APPROVAL" if verdict == "await_human_approval" else "KERNEL_DENIED",
            message=f"kernel verdict: {verdict} ({codes})",
            receipt_id=receipt_id,
            proposal_hash=proposal_hash if verdict == "await_human_approval" else None,
        )


def _evidence(proposal: dict[str, Any]) -> dict[str, str]:
    """The request's hash, in the `sha256:<hex>` form an outcome record uses (hash only)."""
    digest = proposal["payload"].get("request_sha256")
    return {"request_sha256": "sha256:" + digest} if digest else {}


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
    return ApprovalStore(approvals, state, pending_ttl=pending_ttl_from(env.get("NOVA_ICK_PENDING_TTL")))


def pending_ttl_from(value: Any) -> float:
    """Seconds an undecided request stays pending. Anything unusable falls back to the default
    (7 days), never to "forever"."""
    try:
        ttl = float(value)
    except (TypeError, ValueError):
        return DEFAULT_PENDING_TTL
    return ttl if ttl > 0 and ttl == ttl and ttl != float("inf") else DEFAULT_PENDING_TTL


class IckGatedProvider:
    """Wrap a provider so every model call is approved by the kernel first."""

    def __init__(self, inner: Any, gate: IckGate) -> None:
        self._inner = inner
        self._gate = gate

    def _target(self) -> str:
        name = getattr(self._inner, "provider_id", None) or type(self._inner).__name__
        return f"{name}:{getattr(self._inner, 'model', 'unknown')}"

    def _finish(self, ick: dict[str, str], *, status: str, text: str | None, strict: bool) -> str | None:
        """Record the outcome. A failed call is recorded best-effort, since the real error matters
        more; for a completed one, `strict` raises OutcomeNotRecorded and the reply is withheld."""
        try:
            return self._gate.record_outcome(ick, status=status, response_text=text)
        except OutcomeNotRecorded:
            if strict:
                raise
            return None

    def chat_completion(self, governed_request: dict[str, Any]) -> dict[str, Any]:
        ick = self._gate.check(target=self._target(), governed_request=governed_request)
        try:
            result = self._inner.chat_completion(governed_request)
        except BaseException:
            self._finish(ick, status="failed", text=None, strict=False)
            raise
        outcome = self._finish(ick, status="completed", text=reply_text(result), strict=True)
        return {**result, "ick": {**ick, **({"outcome_receipt_id": outcome} if outcome else {})}}

    async def invoke(self, messages: list[Any], **kwargs: Any) -> Any:
        request = {"messages": [{"content": getattr(m, "content", None) or m.get("content", "")} for m in messages]}
        ick = self._gate.check(target=self._target(), governed_request=request)
        try:
            response = await self._inner.invoke(messages, **kwargs)
        except BaseException:
            self._finish(ick, status="failed", text=None, strict=False)
            raise
        self._finish(ick, status="completed", text=str(getattr(response, "content", "") or ""), strict=True)
        return response

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)  # AttributeError if the inner provider lacks it
        if name == "chat_completion_stream":
            def gated(governed_request: dict[str, Any]) -> Iterator[dict[str, Any]]:
                ick = self._gate.check(target=self._target(), governed_request=governed_request)
                parts: list[str] = []
                finished = False
                try:
                    for chunk in attr(governed_request):
                        parts.append(delta_text(chunk))
                        yield chunk
                    finished = True
                finally:
                    # Text already sent cannot be withdrawn, so a stream never raises here.
                    self._finish(ick, status="completed" if finished else "failed",
                                 text="".join(parts) if finished else None, strict=False)

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


def gate_outcome(
    ick: dict[str, str] | None,
    *,
    status: str,
    response_text: str | None = None,
    strict: bool = True,
) -> str | None:
    """Record what happened after a `gate_action` allow. A no-op when the gate was off."""
    gate = IckGate.from_env()
    if ick is None or gate is None:
        return None
    try:
        return gate.record_outcome(ick, status=status, response_text=response_text)
    except OutcomeNotRecorded:
        if strict:
            raise
        return None


def gate_provider(provider: Any) -> Any:
    """Wrap `provider` if the gate is switched on in the environment."""
    gate = IckGate.from_env()
    return IckGatedProvider(provider, gate) if gate else provider
