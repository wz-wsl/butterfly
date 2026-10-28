import csv
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from butterfly.models import Finding, ScanResult
from butterfly.output import make_report, render, write_output


class OutputTests(unittest.TestCase):
    def test_json_preserves_partial_status_and_sources(self):
        result = ScanResult("port", "https://example.com", checked=1,
                            errors=["443: timeout"], warnings=["third-party query"])
        result.findings.append(Finding("port", result.target, "open", "80", "provider"))
        data = json.loads(render(make_report([result]), "json"))
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["results"][0]["status"], "partial")
        self.assertEqual(data["results"][0]["errors"], ["443: timeout"])
        self.assertEqual(data["results"][0]["findings"][0]["source"], "provider")

    def test_empty_success_differs_from_failure_in_csv(self):
        empty = ScanResult("subdomain", "example.com", checked=1)
        failed = ScanResult("subdomain", "other.example", errors=["invalid response"])
        rows = list(csv.DictReader(io.StringIO(render(make_report([empty, failed]), "csv"))))
        summaries = [row for row in rows if row["record_type"] == "summary"]
        self.assertEqual([row["scan_status"] for row in summaries], ["success", "failed"])
        self.assertEqual(rows[-1]["record_type"], "error")
        self.assertEqual(rows[-1]["message"], "invalid response")

    def test_csv_quotes_multiline_remote_fields(self):
        result = ScanResult("links", "example.com", checked=1)
        result.findings.append(Finding("links", result.target, "discovered", "https://example.com/a",
                                       details={"title": 'a,"b"\nc'}))
        rows = list(csv.DictReader(io.StringIO(render(make_report([result]), "csv"))))
        self.assertEqual(json.loads(rows[1]["details"])["title"], 'a,"b"\nc')

    def test_table_neutralizes_terminal_controls(self):
        result = ScanResult("links", "example.com", errors=["remote\x1b[31m\rerror"])
        text = render(make_report([result]))
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\r", text)

    @unittest.skipIf(os.name != "posix", "POSIX file modes")
    def test_written_report_uses_normal_file_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            fresh = Path(directory) / "new.json"
            umask = os.umask(0o022)
            try:
                write_output(str(fresh), "{}")
            finally:
                os.umask(umask)
            self.assertEqual(fresh.stat().st_mode & 0o777, 0o644)
            existing = Path(directory) / "old.json"
            existing.write_text("old", encoding="utf-8")
            existing.chmod(0o640)
            write_output(str(existing), "new")
            self.assertEqual(existing.stat().st_mode & 0o777, 0o640)
            self.assertEqual(existing.read_text(encoding="utf-8"), "new")

    def test_atomic_write_keeps_existing_file_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            destination.write_text("original", encoding="utf-8")
            with patch("butterfly.output.os.replace", side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    write_output(str(destination), "replacement")
            self.assertEqual(destination.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(Path(directory).iterdir()), [destination])


if __name__ == "__main__":
    unittest.main()
