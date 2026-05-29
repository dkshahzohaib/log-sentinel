import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import baseline
from src.system_collector import AutorunEntry, NetConnection


class BaselineTests(unittest.TestCase):
    def test_first_diff_creates_baseline_without_findings(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(baseline, "BASELINE_FILE", Path(td) / "baseline.json"):
                findings = baseline.diff_snapshot(
                    autoruns=[AutorunEntry("HKCU\\Run", "OneDrive", "onedrive.exe")],
                    persist=True,
                )

                self.assertEqual(findings, [])
                self.assertTrue((Path(td) / "baseline.json").exists())

    def test_new_autorun_after_baseline_becomes_high_finding(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(baseline, "BASELINE_FILE", Path(td) / "baseline.json"):
                baseline.save_snapshot(
                    autoruns=[AutorunEntry("HKCU\\Run", "Known", "known.exe")]
                )
                findings = baseline.diff_snapshot(
                    autoruns=[
                        AutorunEntry("HKCU\\Run", "Known", "known.exe"),
                        AutorunEntry("HKCU\\Run", "Strange", "powershell -enc AAA"),
                    ],
                    persist=False,
                )

                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].rule, "baseline_new_autorun")
                self.assertEqual(findings[0].severity, "High")

    def test_new_listener_after_baseline_becomes_low_finding(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(baseline, "BASELINE_FILE", Path(td) / "baseline.json"):
                baseline.save_snapshot(connections=[])
                findings = baseline.diff_snapshot(
                    connections=[
                        NetConnection("TCP", "0.0.0.0", 8081, "0.0.0.0", 0, "LISTENING", 10, "app.exe")
                    ],
                    persist=False,
                )

                self.assertEqual(findings[0].rule, "baseline_new_listener")


if __name__ == "__main__":
    unittest.main()
