#!/usr/bin/env python3
"""Measure what one governed decision costs, and how that cost grows as the receipt log grows.

    python scripts/benchmark.py [--binary target/release/infinityctl] [--sizes 1,100,500,1000] [--json]

It times three things on this machine, with a throw-away key, policy and log in a temporary folder:

  1. one `infinityctl evaluate` with no log (the kernel's own work plus starting the program);
  2. one signed, chained, anchored decision appended to a log that already has N entries, for each N;
  3. one decision through the signer service (a Unix socket plus the same program run), at a small log.

Why (2) matters: every append re-checks the whole existing log (hash chain, anchors, signatures) while
holding the log's lock, so the cost of a decision grows in step with the log. The numbers say how fast,
so you can decide when to start a fresh log. Build the release binary first (`cargo build --release`):
a debug build is several times slower and tells you little.

The numbers describe the machine they ran on. Treat them as an order of magnitude, not a promise.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def proposal(policy_id: str) -> dict:
    return {"version": "infinity.proposal.v1", "proposal_id": "bench", "actor": {"kind": "agent", "id": "bench"},
            "action": "get_status", "target": "demo", "effect": "read", "risk": "low",
            "requires_human_approval": False, "policy_version": policy_id, "payload": {}, "evidence_refs": []}


def timed(cmd: list[str]) -> float:
    start = time.perf_counter()
    done = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    if done.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(cmd)}\n{done.stderr}")
    return elapsed * 1000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--binary", default=str(ROOT / "target" / "release" / ("infinityctl.exe" if os.name == "nt" else "infinityctl")))
    parser.add_argument("--sizes", default="1,100,500,1000", help="log lengths to time an append at (comma separated)")
    parser.add_argument("--repeat", type=int, default=30, help="repeats for the no-log and service timings")
    parser.add_argument("--no-service", action="store_true", help="skip the signer-service timing (it needs Unix sockets)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    binary = args.binary
    if not Path(binary).is_file():
        raise SystemExit(f"no kernel binary at {binary}; run `cargo build --release` first")
    sizes = sorted({int(x) for x in args.sizes.split(",") if x.strip()})

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        key, pub = tmp / "k.priv", tmp / "k.pub"
        subprocess.run([binary, "keygen", "--out", str(key), "--public-out", str(pub)], check=True, capture_output=True)
        policy = tmp / "policy.json"
        policy.write_text(json.dumps({"version": "infinity.policy.v1", "policy_id": "policy-bench-v1"}))
        prop = tmp / "proposal.json"
        prop.write_text(json.dumps(proposal("policy-bench-v1")))
        base = [binary, "evaluate", "--proposal", str(prop), "--policy", str(policy)]

        result: dict = {"machine": f"{platform.system()} {platform.machine()}, {os.cpu_count()} cores, Python {platform.python_version()}",
                        "binary": os.path.basename(binary)}
        times = [timed(base) for _ in range(args.repeat)]
        result["no_log_ms"] = {"median": round(statistics.median(times), 2), "p95": round(sorted(times)[int(len(times) * .95) - 1], 2)}

        log, anchor = tmp / "log" / "r.jsonl", tmp / "anchor.jsonl"
        log.parent.mkdir()
        signed = base + ["--log", str(log), "--anchor", str(anchor), "--sign-key", str(key)]
        by_size, length = {}, 0
        for size in sizes:
            while length < size - 1:  # grow the log to size-1 entries, then time the append that makes it `size`
                timed(signed)
                length += 1
            by_size[size] = round(timed(signed), 2)
            length += 1
        result["append_ms_by_log_length"] = by_size
        if len(sizes) >= 2 and sizes[-1] > sizes[0]:
            lo, hi = sizes[0], sizes[-1]
            result["extra_ms_per_100_entries"] = round((by_size[hi] - by_size[lo]) / (hi - lo) * 100, 2)

        if not args.no_service and os.name == "posix":
            sys.path.insert(0, str(ROOT))
            import socket
            import threading

            from runtime.ick_service import Service, make_server
            from runtime.kernel import Kernel

            svc_log, svc_anchor = tmp / "svc" / "r.jsonl", tmp / "svc" / "a.jsonl"
            (tmp / "svc").mkdir()
            kernel = Kernel(policy, svc_log, binary=binary, anchor=svc_anchor, sign_key=key)
            server = make_server(Service(kernel), tmp / "s.sock")
            threading.Thread(target=server.serve_forever, daemon=True).start()
            request = json.dumps({"op": "evaluate", "proposal": proposal("policy-bench-v1"), "approval_ids": []}).encode() + b"\n"
            samples = []
            for _ in range(args.repeat):
                start = time.perf_counter()
                with socket.socket(socket.AF_UNIX) as c:
                    c.connect(str(tmp / "s.sock"))
                    c.sendall(request)
                    data = b""
                    while not data.endswith(b"\n"):
                        data += c.recv(65536)
                samples.append((time.perf_counter() - start) * 1000)
                assert json.loads(data)["ok"]
            server.shutdown()
            result["through_signer_service_ms_small_log"] = {"median": round(statistics.median(samples), 2),
                                                             "log_length_at_end": args.repeat}

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"machine: {result['machine']}  (binary: {result['binary']})")
        print(f"one decision, no log:            median {result['no_log_ms']['median']} ms, 95th percentile {result['no_log_ms']['p95']} ms")
        print("one signed, chained, anchored decision appended to a log that already has N entries:")
        for n, ms in result["append_ms_by_log_length"].items():
            print(f"   N = {n:>6}: {ms:>8} ms")
        if "extra_ms_per_100_entries" in result:
            print(f"   about {result['extra_ms_per_100_entries']} ms more for every 100 entries")
        if "through_signer_service_ms_small_log" in result:
            s = result["through_signer_service_ms_small_log"]
            print(f"through the signer service (small log): median {s['median']} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
