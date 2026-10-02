"""One governed chat turn: kernel decides first, the provider is called only on `allow`."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from runtime.kernel import Decision, Kernel, KernelError, sha256_text
from runtime.providers import Client, complete


@dataclass(frozen=True)
class TurnResult:
    verdict: str
    reason_codes: list[str]
    receipt_id: str
    reply: str | None  # None unless the kernel allowed the call
    outcome_receipt_id: str | None = None  # the record of what the model call did (needs a log)


def build_proposal(provider: str, message: str, policy_version: str) -> dict[str, Any]:
    return {
        "version": "infinity.proposal.v1",
        "proposal_id": f"chat-{uuid.uuid4()}",
        "actor": {"kind": "agent", "id": "infinity-core-runtime"},
        "action": "chat_completion",
        "target": provider,
        "effect": "read",
        "risk": "low",
        "requires_human_approval": False,
        "policy_version": policy_version,
        # Only the size is recorded, never the message text itself.
        "payload": {"message_chars": len(message)},
        "evidence_refs": [],
    }


def policy_version_of(kernel: Kernel) -> str:
    import json

    return json.loads(kernel.policy.read_text())["policy_id"]


def run_turn(
    message: str,
    provider: str,
    kernel: Kernel,
    *,
    history: list[dict[str, str]] | None = None,
    client: Client | None = None,
    max_tokens: int = 512,
) -> TurnResult:
    proposal = build_proposal(provider, message, policy_version_of(kernel))
    decision: Decision = kernel.evaluate(proposal)
    receipt_id = str(decision.receipt.get("receipt_id"))
    if not decision.allowed:
        return TurnResult(decision.verdict, decision.reason_codes, receipt_id, None)
    messages = list(history or []) + [{"role": "user", "content": message}]
    request_sha = sha256_text(json.dumps([m["content"] for m in messages]))
    try:
        reply = complete(provider, messages, max_tokens=max_tokens, client=client)
    except Exception:
        try:  # the real error matters more; a missing record shows up as "allowed without an outcome"
            kernel.record_outcome(receipt_id, status="failed", request_sha256=request_sha)
        except KernelError:
            pass
        raise
    # No evidence, no answer: if the outcome cannot be recorded, KernelError propagates and the
    # reply is withheld.
    outcome = kernel.record_outcome(receipt_id, status="completed", request_sha256=request_sha,
                                    response_sha256=sha256_text(reply))
    return TurnResult(decision.verdict, decision.reason_codes, receipt_id, reply, outcome)
