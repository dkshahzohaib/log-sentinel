import tempfile
import unittest
from pathlib import Path

from src.reporter import ensure_help_center, generate_pdf


class ReporterTests(unittest.TestCase):
    def test_help_center_and_pdf_are_written(self):
        with tempfile.TemporaryDirectory() as td:
            help_path = ensure_help_center(td)
            pdf_path = Path(td) / "report.pdf"

            generate_pdf([], [], str(pdf_path), hours_back=24)

            self.assertTrue(help_path.exists())
            self.assertIn("Log Sentinel Help", help_path.read_text(encoding="utf-8"))
            self.assertTrue(pdf_path.exists())
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF-1.4"))


if __name__ == "__main__":
    unittest.main()
