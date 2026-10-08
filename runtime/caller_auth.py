"""Bind a call to the verified caller, and apply that caller's grant.

The signer uses this before the kernel runs. Effect and target still come from the call shape.
Risk and action come from the policy grant. A stated risk or action that differs is
``AUTHORITY_DENIED``: the caller cannot raise either one. A missing or bad token is
``IDENTITY_UNVERIFIED``. The kernel does not verify tokens. ``infinityctl evaluate`` does not
either, so a receipt minted there is not executed by the witness.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from runtime.call_binding import BindingError, derive
from runtime.caller_token import (
    CallerTokenError,
    IdentityFailure,
    VerifiedCaller,
    load_caller_keys,
    verify_authorization,
)


def grant_for(policy: dict[str, Any], caller_id: str) -> dict[str, Any] | None:
    callers = policy.get("callers")
    if not isinstance(callers, dict):
        return None
    grant = callers.get(caller_id)
    return grant if isinstance(grant, dict) else None


def grant_covers(policy: dict[str, Any], caller_id: str, effect: str, target: str) -> bool:
    """True when the policy lists ``caller_id`` and this effect and target are inside the grant."""
    grant = grant_for(policy, caller_id)
    if grant is None:
        return False
    effects = grant.get("effects")
    prefixes = grant.get("target_prefixes")
    if not isinstance(effects, list) or effect not in effects:
        return False
    if not isinstance(prefixes, list):
        return False
    return any(isinstance(prefix, str) and prefix != "" and target.startswith(prefix) for prefix in prefixes)


def prepare_bound_proposal(
    proposal: dict[str, Any],
    call: Any,
    authorization: str | None,
    policy_text: str,
    keys_text: str,
    now: float,
) -> dict[str, Any]:
    """Proposal the kernel should judge for one concrete call.

    Identity is checked first. A bad credential is ``IDENTITY_UNVERIFIED`` and carries no
    digest. A known shape stores the key-file caller id and the digest of that id. Risk and
    action are then taken from the grant. No grant, or a stated risk or action that differs,
    is ``AUTHORITY_DENIED``.
    """
    if not isinstance(call, dict):
        raise BindingError("call must be an object")
    if not isinstance(proposal, dict):
        raise BindingError("proposal must be an object")
    bound = copy.deepcopy(proposal)
    payload = bound.get("payload")
    if not isinstance(payload, dict):
        raise BindingError("payload must be an object when a call is sent")
    payload = dict(payload)
    try:
        keys = load_caller_keys(keys_text)
    except CallerTokenError:
        keys = {}
    try:
        verified = verify_authorization(authorization, call, keys, now=now, ledger=None)
    except IdentityFailure:
        payload["identity_fault"] = "IDENTITY_UNVERIFIED"
        payload.pop("binding_fault", None)
        payload.pop("authority_fault", None)
        bound["payload"] = payload
        bound.pop("call_digest", None)
        bound.pop("caller_id", None)
        return bound
    if verified.unbound:
        payload["binding_fault"] = "UNKNOWN_CALL_SHAPE"
        payload.pop("identity_fault", None)
        payload.pop("authority_fault", None)
        bound["payload"] = payload
        bound.pop("call_digest", None)
        bound["caller_id"] = verified.caller_id
        return bound
    _apply_derived(bound, payload, call, verified)
    if payload.get("binding_fault"):
        payload.pop("identity_fault", None)
        payload.pop("authority_fault", None)
        bound["payload"] = payload
        return bound
    _apply_grant(bound, payload, proposal, policy_text, verified.caller_id)
    payload.pop("identity_fault", None)
    bound["payload"] = payload
    return bound


def _apply_derived(
    bound: dict[str, Any], payload: dict[str, Any], call: Any, verified: VerifiedCaller
) -> None:
    derived = derive(call, verified.caller_id)
    stated = bound.get("call_digest")
    disagree = (
        bound.get("effect") != derived.effect
        or bound.get("target") != derived.target
        or (stated is not None and stated != derived.call_digest)
    )
    bound["effect"] = derived.effect
    bound["target"] = derived.target
    bound["call_digest"] = derived.call_digest
    bound["caller_id"] = verified.caller_id
    if disagree:
        payload["binding_fault"] = "DESCRIPTION_DISAGREEMENT"
    else:
        payload.pop("binding_fault", None)


def _apply_grant(
    bound: dict[str, Any],
    payload: dict[str, Any],
    original: dict[str, Any],
    policy_text: str,
    caller_id: str,
) -> None:
    try:
        policy = json.loads(policy_text)
    except ValueError:
        policy = {}
    if not isinstance(policy, dict):
        policy = {}
    grant = grant_for(policy, caller_id)
    stated_risk = original.get("risk")
    stated_action = original.get("action")
    if grant is None:
        payload["authority_fault"] = "AUTHORITY_DENIED"
        return
    grant_risk = grant.get("risk")
    grant_action = grant.get("action")
    if stated_risk != grant_risk or stated_action != grant_action:
        payload["authority_fault"] = "AUTHORITY_DENIED"
    else:
        payload.pop("authority_fault", None)
    if isinstance(grant_risk, str) and grant_risk:
        bound["risk"] = grant_risk
    if isinstance(grant_action, str) and grant_action:
        bound["action"] = grant_action
