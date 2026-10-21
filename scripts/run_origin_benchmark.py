#!/usr/bin/env python3
"""Run CFUnveil's local TLS-origin acceptance benchmark; no external targets."""
import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cfunveil"))
sys.path.insert(0, str(ROOT / "tests"))
from origin_lab import ORIGIN_IP, run_benchmark


def main():
    parser = argparse.ArgumentParser(
        description="Run isolated 127/8 loopback HTTPS lab (requires OpenSSL)."
    )
    parser.add_argument("--output", help="Optional JSON output file")
    args = parser.parse_args()

    report = asyncio.run(run_benchmark())
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        output.write_text(encoded, encoding="utf-8")
        print(f"Benchmark report saved to {output}")
    else:
        print(encoded, end="")

    statuses = report["verification"]["classification"]
    checks = (
        report["verification"]["baseline_https_valid"]
        and report["verification"]["true_positives"] == 1
        and report["verification"]["false_positives"] == 0
        and statuses[ORIGIN_IP]["confirmed"]
        and report["verification"]["no_out_of_scope_probe"]
        and report["verification"]["no_redirect_following"]
        and report["discovery"]["known_origin_seeded"]
        and report["discovery"]["known_origin_absent_without_evidence"]
    )
    return 0 if checks else 1


if __name__ == "__main__":
    raise SystemExit(main())
