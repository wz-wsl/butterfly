"""Exercise CLI -> scanners/providers -> real urllib processing without sockets."""

import contextlib
from email.message import Message
import io
import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from urllib.request import BaseHandler, ProxyHandler, build_opener
from urllib.response import addinfourl

from butterfly.cli import main
from butterfly.http_client import HttpClient, _NoRedirect


class FixtureTransport(BaseHandler):
    handler_order = 100

    def __init__(self, responder):
        self.responder = responder
        self.requests = []

    def http_open(self, request):
        self.requests.append(request)
        status, body, headers = self.responder(request)
        message = Message()
        for key, value in headers.items():
            message[key] = value
        response = addinfourl(io.BytesIO(body), message, request.full_url, status)
        response.msg = "Fixture response"
        return response

    https_open = http_open


class IntegrationTests(unittest.TestCase):
    def invoke(self, args, responder):
        transport = FixtureTransport(responder)

        def client_factory(**kwargs):
            client = HttpClient(**kwargs)
            # The fixture intercepts every HTTP(S) request; no network is used.
            client._opener = build_opener(ProxyHandler({}), transport, _NoRedirect())
            return client

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("butterfly.cli.HttpClient", side_effect=client_factory):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(args + ["--format", "json", "--retries", "0"])
        return code, json.loads(stdout.getvalue()), transport

    def test_combined_port_and_links_report_through_real_transport(self):
        def respond(request):
            if request.host == "tool.box3.cn":
                form = parse_qs(request.data.decode())
                self.assertEqual(form["data"], ["example.test"])
                state = int(form["port"] == ["80"])
                body = json.dumps({"data": {"is_open": state}}).encode()
                return 200, body, {"Content-Type": "application/json"}
            self.assertEqual(request.full_url, "http://example.test/")
            return 200, b'<html><script src="app.js"></script><a href="/login">Login</a></html>', {
                "Content-Type": "text/html"
            }

        code, report, transport = self.invoke([
            "-ps", "http://example.test", "--ports", "80,443", "-js", "http://example.test/"
        ], respond)
        self.assertEqual(code, 0)
        ports, links = report["results"]
        self.assertEqual([item["status"] for item in ports["findings"]], ["open", "closed"])
        self.assertEqual({item["value"] for item in links["findings"]}, {
            "http://example.test/app.js", "http://example.test/login"
        })
        self.assertEqual(len(transport.requests), 3)

    def test_directory_statuses_and_partial_failure_survive_pipeline(self):
        def respond(request):
            path = urlsplit(request.full_url).path
            if path.startswith("/app/.butterfly-not-found-"):
                return 200, f"Missing page: {path}".encode(), {"Content-Type": "text/html"}
            cases = {
                "/app/ok": (200, b"<html><title>Dashboard</title></html>", {}),
                "/app/secret": (403, b"Forbidden", {}),
                "/app/login": (302, b"", {"Location": "/sso"}),
                "/app/missing": (404, b"Missing", {}),
                "/app/broken": (500, b"Error", {}),
            }
            self.assertIn(path, cases)
            return cases[path]

        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            wordlist = Path(directory) / "paths.txt"
            wordlist.write_text("ok\nsecret\nlogin\nmissing\nbroken\n", encoding="utf-8")
            code, report, transport = self.invoke([
                "-ds", "http://example.test/app/", "-f", str(wordlist)
            ], respond)
        result = report["results"][0]
        self.assertEqual((code, result["status"], result["checked"]), (0, "success", 5))
        self.assertEqual([item["status"] for item in result["findings"]], [
            "found", "restricted", "redirect", "not_found", "server_error"
        ])
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(transport.requests), 7)


if __name__ == "__main__":
    unittest.main()
