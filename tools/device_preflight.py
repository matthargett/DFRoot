#!/usr/bin/env python3
"""Read-only exploitation and profiling preflight for an ADB Android device."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from preflight.checks import evaluate
from preflight.collectors import collect
from preflight.render import render


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial", help="ADB device serial")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--live-cpu", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = evaluate(collect(args.serial, args.timeout, args.live_cpu))
    print(
        json.dumps(
            {
                "schema_version": 2,
                "verdict": report.verdict,
                "snapshot": report.snapshot,
                "findings": [asdict(finding) for finding in report.findings],
            },
            indent=2,
            sort_keys=True,
        )
        if args.format == "json"
        else render(report)
    )
    return 0 if report.verdict in {"already_privileged", "runtime_probe_available"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
