#!/usr/bin/env python3
"""Audit an existing CFUnveil JSON report; makes no provider/network requests.

Examples:
    python cfunveil/audit_evidence.py path/to/report.json
    python cfunveil/audit_evidence.py old-report.json --as-of 2026-10-21T20:00:00Z
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from core.evidence import parse_observation_time
from core.evidence_utility import evaluate_evidence_utility


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only evidence-utility audit of one existing CFUnveil JSON report.",
    )
    parser.add_argument("report", type=Path, help="Saved CFUnveil JSON report")
    parser.add_argument(
        "--as-of", metavar="ISO_DATETIME",
        help="Time for temporal interpretation of older reports lacking embedded correlations; defaults to audit time",
    )
    args = parser.parse_args(argv)
    if args.as_of:
        as_of = parse_observation_time(args.as_of)
        if as_of is None:
            parser.error("--as-of requires a complete ISO date or timestamp")
    else:
        as_of = datetime.now(timezone.utc)

    try:
        with args.report.open("r", encoding="utf-8") as stream:
            report = json.load(stream)
        result = evaluate_evidence_utility(report, as_of=as_of)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        parser.exit(2, f"Evidence audit: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
