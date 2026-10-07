"""Usage: python -m runtime "your message" --provider groq"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from runtime.chat import run_turn
from runtime.kernel import DEFAULT_POLICY, Kernel, KernelError
from runtime.providers import PROVIDERS, ProviderError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="runtime", description="Governed chat turn")
    parser.add_argument("message")
    parser.add_argument("--provider", choices=sorted(PROVIDERS), default="groq")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--receipts", type=Path, default=Path(".runtime/receipts.jsonl"))
    parser.add_argument(
        "--anchor",
        type=Path,
        help="anchor file; store it where the receipt log's writer cannot also edit it",
    )
    args = parser.parse_args(argv)
    kernel = Kernel(policy=args.policy, receipt_log=args.receipts, anchor=args.anchor)
    try:
        result = run_turn(args.message, args.provider, kernel)
    except ProviderError as exc:
        print(f"provider error: {exc}", file=sys.stderr)
        return 2
    except KernelError as exc:
        print(f"kernel refused: {exc}", file=sys.stderr)
        return 3
    print(f"[kernel: {result.verdict} {','.join(result.reason_codes)}] {result.receipt_id}")
    if result.outcome_receipt_id:
        print(f"[outcome recorded] {result.outcome_receipt_id}")
    if result.reply is None:
        if result.verdict == "allow":
            print("no witness is configured; the provider was not called", file=sys.stderr)
        print("(no model call was made)")
        return 1
    print(result.reply)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
