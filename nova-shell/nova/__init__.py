"""Lawful Nova LLM runtime package."""

import sys
from pathlib import Path

# The kernel and the witness live in the repository root. Nova-shell tests put only
# this package on the path; the root has to be visible so the gate can bind a call.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if (_REPO_ROOT / "runtime").is_dir():
    _root = str(_REPO_ROOT)
    if _root not in sys.path:
        sys.path.insert(0, _root)
