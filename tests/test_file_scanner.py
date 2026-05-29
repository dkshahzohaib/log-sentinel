import tempfile
import unittest
from pathlib import Path

from src.file_scanner import scan_paths


class FileScannerTests(unittest.TestCase):
    def test_eicar_style_marker_is_critical(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "sample.txt"
            sample.write_text("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", encoding="utf-8")

            findings = scan_paths([td])

            self.assertTrue(any(f.rule == "test_malware_marker" and f.severity == "Critical" for f in findings))

    def test_suspicious_script_content_is_high(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "download_test.ps1"
            sample.write_text("powershell -enc AAAA DownloadString IEX(", encoding="utf-8")

            findings = scan_paths([td])

            self.assertTrue(any(f.rule == "suspicious_script_file" and f.severity == "High" for f in findings))


if __name__ == "__main__":
    unittest.main()
