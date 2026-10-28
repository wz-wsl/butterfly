import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from butterfly.cli import main
from butterfly.models import ScanResult


class CliTests(unittest.TestCase):
    def run_cli(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_legacy_port_options_and_json_stdout(self):
        result = ScanResult("port", "https://example.com", checked=3)
        with patch("butterfly.cli.HttpClient") as client, patch(
            "butterfly.cli.query_ports", return_value=result
        ) as query:
            code, stdout, stderr = self.run_cli([
                "-ps", "example.com", "-psm", "79", "-dsm", "81", "--format", "json"
            ])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(json.loads(stdout)["results"][0]["checked"], 3)
        self.assertEqual(query.call_args.args[2], [79, 80, 81])
        client.assert_called_once_with(timeout=10.0, retries=1, verify=True, max_bytes=2097152)

    def test_invalid_arguments_fail_before_network_access(self):
        cases = [
            ["-ps", "example.com", "-psm", "0", "-dsm", "80"],
            ["-ps", "example.com", "-psm", "81", "-dsm", "80"],
            ["-ps", "example.com", "-psm", "80"],
            ["-ps", "example.com", "--ports", "65536"],
            ["-ps", "example.com", "--ports", "80,,443"],
            ["-ps", "example.com", "--ports", "80", "-psm", "80", "-dsm", "80"],
            ["-js", "example.com", "--ports", "80"],
            ["-js", "example.com", "--timeout", "nan"],
            ["-js", "example.com", "--retries", "-1"],
            ["-ds", "example.com"],
            ["-js", "ftp://example.com"],
            ["-js", "example.com", "--subdomain-wordlist", "missing.txt"],
        ]
        with patch("butterfly.cli.HttpClient") as client:
            for args in cases:
                with self.subTest(args=args), self.assertRaises(SystemExit) as error:
                    self.run_cli(args)
                self.assertEqual(error.exception.code, 2)
            client.assert_not_called()

    def test_directory_wordlist_is_validated_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "words.txt"
            wordlist.write_text("\ufeff# comment\nadmin\n\nadmin\nrobots.txt\n", encoding="utf-8")
            with patch("butterfly.cli.HttpClient"), patch(
                "butterfly.cli.scan_directory", return_value=ScanResult("directory", "example.com")
            ) as scanner:
                self.run_cli(["-ds", "example.com", "-f", str(wordlist)])
            self.assertEqual(scanner.call_args.args[2], ["admin", "robots.txt"])

    def test_default_dictionary_keeps_mail_and_ftp_separate(self):
        with patch("butterfly.cli.HttpClient"), patch(
            "butterfly.cli.query_subdomains", return_value=ScanResult("subdomain", "example.com")
        ) as scanner:
            self.run_cli(["-do", "example.com"])
        prefixes = scanner.call_args.args[2]
        self.assertIn("mail", prefixes)
        self.assertIn("ftp", prefixes)
        self.assertNotIn("mailftp", prefixes)
        self.assertEqual(len(prefixes), len(set(prefixes)))

    def test_failure_returns_nonzero_and_export_preserves_errors(self):
        result = ScanResult("links", "https://example.com", errors=["connection timed out"])
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            with patch("butterfly.cli.HttpClient"), patch(
                "butterfly.cli.extract_links", return_value=result
            ):
                code, stdout, _ = self.run_cli([
                    "-js", "example.com", "--format", "json", "-o", str(destination)
                ])
            self.assertEqual(code, 1)
            self.assertEqual(stdout, "")
            self.assertEqual(json.loads(destination.read_text())["results"][0]["status"], "failed")

    def test_insecure_mode_is_explicit_in_report(self):
        result = ScanResult("links", "https://example.com", checked=1)
        with patch("butterfly.cli.HttpClient") as client, patch(
            "butterfly.cli.extract_links", return_value=result
        ):
            _, stdout, _ = self.run_cli(["-js", "example.com", "--insecure", "--format", "json"])
        self.assertFalse(client.call_args.kwargs["verify"])
        self.assertIn("--insecure", json.loads(stdout)["results"][0]["warnings"][0])


if __name__ == "__main__":
    unittest.main()
