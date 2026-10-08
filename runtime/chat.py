"""One governed chat turn: kernel decides first, the provider is called only on `allow`."""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from runtime.call_binding import derive, describe_https
from runtime.caller_auth import prepare_bound_proposal
from runtime.caller_token import present_authorization
from runtime.kernel import Decision, Kernel, KernelError, sha256_text
from runtime.providers import Client, ProviderError, complete, prepared_request
from runtime.witness import Witness

# Local development only. Unset means a known-shape provider call is not sent unless a
# witness performs it. Never set this in a deploy unit or a production environment.
DIRECT_CALLS_ENV = "WICKET_ALLOW_DIRECT_CALLS"


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
    return json.loads(kernel.policy.read_text())["policy_id"]


def direct_calls_allowed() -> bool:
    """True only when the local-dev opt-out is explicitly set to ``1``. Unset is off."""
    return os.environ.get(DIRECT_CALLS_ENV, "").strip() == "1"


def warn_direct_calls() -> None:
    """Stderr, every time the opt-out sends. Not a debug log."""
    print(
        "WARNING: WICKET_ALLOW_DIRECT_CALLS=1 is sending a provider call with no witness. "
        "Local development only. This is unsafe. Do not set it in production.",
        file=sys.stderr,
    )


def run_turn(
    message: str,
    provider: str,
    kernel: Kernel,
    *,
    history: list[dict[str, str]] | None = None,
    client: Client | None = None,
    max_tokens: int = 512,
    witness: Witness | None = None,
) -> TurnResult:
    """One turn. The provider is called by ``witness``, or not at all.

    ``python -m runtime`` does not attach a witness. With none configured, the kernel may
    still record a decision and the provider client is not called. ``WICKET_ALLOW_DIRECT_CALLS=1``
    is the local-dev opt-out: it sends from this process and warns on stderr. It does not
    derive the call, and it is off unless that variable is exactly ``1``.
    """
    messages = list(history or []) + [{"role": "user", "content": message}]
    proposal = build_proposal(provider, message, policy_version_of(kernel))
    authorization = None
    if witness is not None:
        url, payload, headers = prepared_request(provider, messages, max_tokens=max_tokens)
        call = describe_https("POST", url, headers, json.dumps(payload).encode("utf-8"))
        preview = derive(call, "shape-check")
        proposal["effect"] = preview.effect
        proposal["target"] = preview.target
        authorization = present_authorization(call)
        keys_path = os.environ.get("WICKET_CALLER_KEYS", "").strip()
        keys_text = Path(keys_path).read_text(encoding="utf-8") if keys_path else ""
        proposal = prepare_bound_proposal(
            proposal,
            call,
            authorization,
            kernel.policy.read_text(encoding="utf-8"),
            keys_text,
            time.time(),
        )
    else:
        call = None
    decision: Decision = kernel.evaluate(proposal)
    receipt_id = str(decision.receipt.get("receipt_id"))
    if not decision.allowed:
        return TurnResult(decision.verdict, decision.reason_codes, receipt_id, None)
    if witness is None and not direct_calls_allowed():
        return TurnResult(decision.verdict, decision.reason_codes, receipt_id, None)
    request_sha = sha256_text(json.dumps([m["content"] for m in messages]))
    try:
        if witness is None:
            warn_direct_calls()
            reply = complete(provider, messages, max_tokens=max_tokens, client=client)
        else:
            assert call is not None
            sent = witness.execute(call, receipt_id, authorization=authorization)
            if not sent.dispatched or sent.status == "failed":
                raise ProviderError(sent.error or sent.divergence or "the witness did not send the call")
            parsed = json.loads((sent.body or b"{}").decode("utf-8"))
            choice = (parsed.get("choices") or [{}])[0]
            reply = str((choice.get("message") or {}).get("content") or "").strip()
            if not reply:
                raise ProviderError(f"{provider} returned no text")
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
