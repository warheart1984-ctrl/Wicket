"""Usage: python -m runtime "your message" --provider groq"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from runtime.chat import run_turn
from runtime.kernel import DEFAULT_POLICY, Kernel
from runtime.providers import PROVIDERS, ProviderError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="runtime", description="Governed chat turn")
    parser.add_argument("message")
    parser.add_argument("--provider", choices=sorted(PROVIDERS), default="groq")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--receipts", type=Path, default=Path(".runtime/receipts.jsonl"))
    args = parser.parse_args(argv)
    kernel = Kernel(policy=args.policy, receipt_log=args.receipts)
    try:
        result = run_turn(args.message, args.provider, kernel)
    except ProviderError as exc:
        print(f"provider error: {exc}", file=sys.stderr)
        return 2
    print(f"[kernel: {result.verdict} {','.join(result.reason_codes)}] {result.receipt_id}")
    if result.reply is None:
        print("(no model call was made)")
        return 1
    print(result.reply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
