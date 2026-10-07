from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request

from nova.ick import IckGate, KernelRefusal, OutcomeNotRecorded, gate_outcome
from nova.node.identity import NodeIdentity, sign_payload, verify_payload_signature
from nova.node.ledger import append_ledger, runtime_dir
from nova.node.policy import load_node_policy
from runtime.call_binding import UnknownCallShape, describe_https, ensure_known_shape

router = APIRouter()


def peers_path() -> Path:
    return Path(os.environ.get("NOVA_NODE_PEERS_PATH", str(runtime_dir() / "peers.json")))


def load_peers() -> list[dict[str, Any]]:
    path = peers_path()
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def gossip_summary() -> dict[str, Any]:
    ident = NodeIdentity.load("./policy.yaml")
    return {
        "node_id": ident.node_id,
        "operator_id": ident.operator_id,
        "timestamp": int(time.time()),
        "policy_hash": ident.policy_hash,
        "capabilities": ["chat", "governance", "audit"],
    }


def signed_gossip_summary() -> dict[str, Any]:
    summary = gossip_summary()
    return {
        "summary": summary,
        "signature": sign_payload(summary),
        "signature_algorithm": "rsa-sha256-digest",
    }


def gossip_to_peers() -> list[dict[str, Any]]:
    """Send each peer's gossip POST through the witness, or not at all.

    The call is an ``https_request``. Effect, target, and ``call_digest`` come from that
    call, the same way Nova's known-shape routes do. No matching allow, no witness, or an
    unknown shape: nothing is sent. This path does not honor ``WICKET_ALLOW_DIRECT_CALLS``.
    """
    summary = signed_gossip_summary()
    body = json.dumps(summary).encode("utf-8")
    results: list[dict[str, Any]] = []
    gate = IckGate.from_env()
    for peer in load_peers():
        peer_id = str(peer.get("peer_id") or "unknown-peer")
        endpoint = str(peer.get("endpoint") or "").rstrip("/")
        if not endpoint:
            results.append({"peer_id": peer_id, "status": "error", "error": "missing endpoint"})
            continue
        call = describe_https(
            "POST", f"{endpoint}/node/gossip", {"Content-Type": "application/json"}, body,
        )
        try:
            ensure_known_shape(call)
        except UnknownCallShape:
            _record_unknown_gossip(gate, call)
            results.append({"peer_id": peer_id, "status": "refused", "error": "UNKNOWN_CALL_SHAPE"})
            continue
        if gate is None:
            results.append({"peer_id": peer_id, "status": "refused", "error": "WITNESS_UNAVAILABLE"})
            continue
        try:
            reply, ick = gate.run_witnessed(
                call, action="gossip_to_peer", source="gossip", risk="low",
            )
        except KernelRefusal as exc:
            results.append({"peer_id": peer_id, "status": "refused", "error": exc.code})
            continue
        if reply.status == "failed" or not reply.dispatched:
            result: dict[str, Any] = {
                "peer_id": peer_id, "status": "error", "error": reply.error or "dispatch failed",
            }
            outcome = "failed"
        else:
            result = {"peer_id": peer_id, "status": "sent"}
            outcome = "completed"
        try:
            gate_outcome(ick, status=outcome)
        except OutcomeNotRecorded as exc:  # the witness already sent; say the record is missing
            result["outcome_error"] = exc.code
        results.append(result)
    return results


def _record_unknown_gossip(gate: IckGate | None, call: dict[str, Any]) -> None:
    """Ask the kernel to deny an unknown shape when a gate is configured. Never sends."""
    if gate is None:
        return
    try:
        gate.check(
            target="unbound", action="gossip_to_peer", effect="read", source="gossip", call=call,
        )
    except KernelRefusal:
        return


@router.post("/node/gossip")
async def receive_gossip(request: Request) -> dict[str, Any]:
    data = await request.json()
    return receive_gossip_payload(data)


def receive_gossip_payload(data: dict[str, Any]) -> dict[str, Any]:
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else data
    signature = data.get("signature")
    signature_valid = verify_payload_signature(summary, signature)
    trust_level = "trusted" if signature_valid else "invalid"
    entry = append_ledger({
        "entry_type": "nodeGossipReceipt",
        "timestamp": int(time.time()),
        "summary": summary,
        "signature_valid": signature_valid,
        "trust_level": trust_level,
    })
    return {
        "ack": True,
        "received_at": entry["timestamp"],
        "signature_valid": signature_valid,
        "trust_level": trust_level,
    }


def node_hello() -> dict[str, Any]:
    policy = load_node_policy()
    payload = {
        "node_id": policy["node_id"],
        "operator_id": policy["operator_id"],
        "policy_version": policy["policy_version"],
        "policy_hash": policy["policy_hash"],
        "capabilities": ["chat", "governance", "audit"],
    }
    return {
        **payload,
        "signature": sign_payload(payload),
        "signature_algorithm": "rsa-sha256-digest",
        "trust_level": "self",
    }


@router.post("/node/hello")
async def hello() -> dict[str, Any]:
    return node_hello()
