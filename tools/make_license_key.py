#!/usr/bin/env python3
"""Admin helper: create a 30-day Log Sentinel licence key.

Usage:
    py -3 tools/make_license_key.py customer@example.com
    py -3 tools/make_license_key.py customer@example.com --days 30 --device MACHINE_ID
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.licensing import create_license_key


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("email", help="Customer email address")
    parser.add_argument("--days", type=int, default=30, help="Key lifetime")
    parser.add_argument("--plan", default="Monthly", help="Plan name")
    parser.add_argument(
        "--device",
        default="",
        help="Optional Machine ID from the customer's activation screen",
    )
    args = parser.parse_args()

    print(create_license_key(
        args.email,
        days=args.days,
        plan=args.plan,
        device=args.device,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
