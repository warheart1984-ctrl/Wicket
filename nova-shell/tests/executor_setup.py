"""In-process witness for Nova tests. No Unix socket, so Windows can run these."""

from __future__ import annotations

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


def install_witness(monkeypatch, tmp_path: Path, dispatch: Callable[..., bytes], *, anchor: str | None = None):
    """Sign receipts with a new key and install a witness that does not share that key."""
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
    log = os.environ.get("NOVA_ICK_LOG") or str(tmp_path / "receipts.jsonl")
    monkeypatch.setenv("NOVA_ICK_SIGN_KEY", str(signer_priv))
    monkeypatch.setenv("NOVA_ICK_LOG", log)
    witness = Witness(
        binary=binary,
        receipt_log=Path(log),
        witness_log=tmp_path / "witness.jsonl",
        witness_key=witness_priv,
        receipt_trusted_keys=signer_pub,
        receipt_anchor=Path(anchor) if anchor else None,
        dispatch=dispatch,
    )
    return witness_installed(InProcessWitness(witness))
