#!/usr/bin/env python3
"""
Log Sentinel — Windows Event Log security analyser.

Usage:
    python main.py                  # analyse last 24h, open HTML report
    python main.py --hours 48       # look back 48 hours
    python main.py --no-open        # don't auto-open the browser
    python main.py --json           # also save a JSON report
    python main.py --raw            # also save raw events as JSON
    python main.py --out reports/   # output directory
"""

import argparse
import os
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Allow running as script without installing
sys.path.insert(0, str(Path(__file__).parent))

from src.collector import collect, save_raw
from src.analyzer import analyze
from src.reporter import print_summary, generate_html, generate_json, generate_pdf


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect Windows Event Logs and flag suspicious activity."
    )
    parser.add_argument(
        "--hours", type=int, default=24,
        help="How many hours back to analyse (default: 24)"
    )
    parser.add_argument(
        "--out", default="reports",
        help="Output directory for reports (default: reports/)"
    )
    parser.add_argument(
        "--no-open", action="store_true",
        help="Do not auto-open the HTML report in a browser"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Also save findings as JSON"
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Also save raw collected events as JSON"
    )
    args = parser.parse_args()

    if platform.system() != "Windows":
        print("[!] Log Sentinel relies on Windows Event Log (wevtutil).")
        print("    Run this on a Windows machine for live data.")
        sys.exit(1)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    ts_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # ── Collect ──────────────────────────────────
    events = collect(hours_back=args.hours)

    if not events:
        print("[!] No events collected. "
              "Ensure you are running as Administrator.")
        sys.exit(0)

    if args.raw:
        raw_path = str(out_dir / f"raw_events_{ts_str}.json")
        save_raw(events, raw_path)

    # ── Analyse ──────────────────────────────────
    print(f"\n[*] Analysing {len(events)} events...")
    findings = analyze(events)

    # ── Report ───────────────────────────────────
    print_summary(findings, events)

    html_path = str(out_dir / f"report_{ts_str}.html")
    generate_html(findings, events, html_path, hours_back=args.hours)
    pdf_path = str(out_dir / f"report_{ts_str}.pdf")
    generate_pdf(findings, events, pdf_path, hours_back=args.hours)

    if args.json:
        json_path = str(out_dir / f"findings_{ts_str}.json")
        generate_json(findings, json_path)

    # Auto-open
    if not args.no_open:
        abs_path = Path(html_path).resolve()
        try:
            os.startfile(str(abs_path))
        except Exception:
            print(f"[*] Open manually: {abs_path}")


if __name__ == "__main__":
    main()
