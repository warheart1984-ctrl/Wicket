"""In-process witness for Nova tests. No Unix socket, so Windows can run these."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nova.executor import InProcessWitness, witness_installed  # noqa: E402
from nova.ick import _find_binary  # noqa: E402
from runtime.witness import Witness  # noqa: E402

CALLER_ID = "nova-caller"


def grant_caller(policy_path: Path, action: str, caller_id: str = CALLER_ID) -> None:
    """Give ``caller_id`` a grant for the action this test's bound calls state."""
    data = json.loads(policy_path.read_text(encoding="utf-8"))
    data["callers"] = {
        caller_id: {
            "effects": ["read", "write"],
            "target_prefixes": ["http://", "https://", "local-model-tool:"],
            "risk": "low",
            "action": action,
        }
    }
    policy_path.write_text(json.dumps(data), encoding="utf-8")


def arm_caller(monkeypatch, directory: Path) -> Path:
    """Write a caller key the signer and the witness trust, and point Nova at the private key."""
    binary = _find_binary(None)
    private, public = directory / "caller.priv", directory / "caller.pub"
    keys = directory / "caller-keys.json"
    if not private.is_file():
        subprocess.run(
            [binary, "keygen", "--out", str(private), "--public-out", str(public)],
            check=True, capture_output=True,
        )
    if not keys.is_file():
        keys.write_text(json.dumps({
            "version": "wicket.caller-keys.v1",
            "keys": [{"caller_id": CALLER_ID, "public_key": public.read_text(encoding="utf-8").strip()}],
        }), encoding="utf-8")
    monkeypatch.setenv("WICKET_CALLER_KEY", str(private))
    monkeypatch.setenv("WICKET_CALLER_KEYS", str(keys))
    return keys


def install_witness(
    monkeypatch,
    tmp_path: Path,
    dispatch: Callable[..., bytes],
    *,
    anchor: str | None = None,
    action: str = "chat_completion",
):
    """Sign receipts with a new key and install a witness that does not share that key.

    Also arms a caller token and, when the policy file lives under ``tmp_path``, grants that
    caller ``action``. A shared demo policy is not rewritten.
    """
    binary = _find_binary(None)
    signer_priv, signer_pub = tmp_path / "signer.priv", tmp_path / "signer.pub"
    witness_priv = tmp_path / "witness.priv"
    subprocess.run(
        [binary, "keygen", "--out", str(signer_priv), "--public-out", str(signer_pub)],
        check=True, capture_output=True,
    )
    subprocess.run(
        [binary, "keygen", "--out", str(witness_priv), "--public-out", str(tmp_path / "witness.pub")],
        check=True, capture_output=True,
    )
    caller_keys = arm_caller(monkeypatch, tmp_path)
    log = os.environ.get("NOVA_ICK_LOG") or str(tmp_path / "receipts.jsonl")
    monkeypatch.setenv("NOVA_ICK_SIGN_KEY", str(signer_priv))
    monkeypatch.setenv("NOVA_ICK_LOG", log)
    policy_env = os.environ.get("NOVA_ICK_POLICY") or ""
    policy_path = Path(policy_env) if policy_env else tmp_path / "no-policy.json"
    if policy_env:
        resolved = policy_path.resolve()
        root = Path(tmp_path).resolve()
        if resolved == root or root in resolved.parents:
            grant_caller(policy_path, action)
    witness = Witness(
        binary=binary,
        receipt_log=Path(log),
        witness_log=tmp_path / "witness.jsonl",
        witness_key=witness_priv,
        receipt_trusted_keys=signer_pub,
        receipt_anchor=Path(anchor) if anchor else None,
        dispatch=dispatch,
        caller_keys=caller_keys,
        policy=policy_path,
    )
    return witness_installed(InProcessWitness(witness))
