#!/usr/bin/env python3
"""Run the deterministic, network-free discovery evidence benchmark."""
import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "cfunveil"))
sys.path.insert(0, str(ROOT / "tests"))

from discovery_temporal_lab import run_benchmark


def main():
    parser = argparse.ArgumentParser(
        description="Replay historical-DNS, current DNS, and certificate fixtures with no external network requests."
    )
    parser.add_argument("--output", help="Optional JSON report file")
    args = parser.parse_args()

    report = asyncio.run(run_benchmark())
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"Discovery benchmark report saved to {args.output}")
    else:
        print(rendered, end="")

    failures = [name for name, passed in report["checks"].items() if not passed]
    if failures:
        print("FAIL: " + ", ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
