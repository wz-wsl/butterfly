"""Regression checks use deterministic in-memory responses, not public sites."""

import unittest
from urllib.parse import urlsplit

from butterfly.http_client import HttpResponse, RequestError
from butterfly.scanners import extract_links, scan_directory
from butterfly.targets import parse_target


def response(url, status=200, body="", headers=None):
    return HttpResponse(status, url, headers or {}, body.encode("utf-8"))


class FakeClient:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url):
        self.calls.append(url)
        return self.handler(url)


class DirectoryTests(unittest.TestCase):
    def setUp(self):
        self.target = parse_target("https://example.com/app")

    def missing(self, url):
        return response(url, 404, "<h1>missing</h1>")

    def test_equal_length_real_page_is_not_hidden(self):
        def handler(url):
            if ".butterfly-not-found-" in url:
                return self.missing(url)
            return response(url, 200, "<h1>present</h1>")

        client = FakeClient(handler)
        result = scan_directory(client, self.target, ["/admin"])
        self.assertEqual(len("<h1>missing</h1>"), len("<h1>present</h1>"))
        self.assertEqual(result.findings[0].status, "found")
        self.assertEqual(result.findings[0].value, "https://example.com/app/admin")
        self.assertEqual(result.checked, 1)

    def test_dynamic_missing_page_is_marked_suspected_not_proven(self):
        def handler(url):
            body = f"<h1>Page not found</h1><p>{urlsplit(url).path}</p><p>1700000000000</p>"
            return response(url, 200, body)

        result = scan_directory(FakeClient(handler), self.target, ["missing"])
        self.assertEqual(result.findings[0].status, "suspected_soft_404")
        self.assertIn("baseline", result.findings[0].details["reason"])

    def test_disagreeing_baselines_disable_similarity(self):
        calls = 0

        def handler(url):
            nonlocal calls
            calls += 1
            if calls == 1:
                return response(url, 200, "<h1>Missing</h1>")
            if calls == 2:
                return response(url, 200, "<h1>Different application</h1>")
            return response(url, 200, "<h1>Missing</h1>")

        result = scan_directory(FakeClient(handler), self.target, ["valid"])
        self.assertEqual(result.findings[0].status, "found")
        self.assertTrue(any("differ" in warning for warning in result.warnings))

    def test_baseline_failure_does_not_hide_successful_check(self):
        def handler(url):
            if ".butterfly-not-found-" in url:
                raise RequestError("timed out", kind="timeout")
            return response(url, 200, "<title>Admin</title>")

        result = scan_directory(FakeClient(handler), self.target, ["admin"])
        self.assertEqual(result.status, "success")
        self.assertEqual(result.findings[0].details["title"], "Admin")
        self.assertTrue(result.warnings)

    def test_statuses_and_redirect_are_preserved_without_following(self):
        def handler(url):
            path = urlsplit(url).path
            if ".butterfly-not-found-" in path:
                return self.missing(url)
            if path.endswith("restricted"):
                return response(url, 403)
            if path.endswith("redirect"):
                return response(url, 302, headers={"Location": "https://elsewhere.example/login"})
            if path.endswith("missing"):
                return self.missing(url)
            return response(url, 503)

        client = FakeClient(handler)
        result = scan_directory(client, self.target, ["restricted", "redirect", "missing", "error"])
        self.assertEqual([item.status for item in result.findings], ["restricted", "redirect", "not_found", "error"])
        self.assertEqual(result.findings[1].details["location"], "https://elsewhere.example/login")
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.checked, 3)
        self.assertEqual(len(client.calls), 6)

    def test_invalid_paths_are_rejected_before_network_access(self):
        client = FakeClient(lambda url: self.fail("unexpected request"))
        result = scan_directory(client, self.target, ["https://elsewhere.example/x", "//elsewhere.example/x", "../escape"])
        self.assertEqual(result.status, "failed")
        self.assertEqual(len(result.errors), 3)
        self.assertEqual(client.calls, [])

    def test_malformed_redirect_location_preserves_progress_and_raw_header(self):
        def handler(url):
            if ".butterfly-not-found-" in url:
                return self.missing(url)
            if url.endswith("redirect"):
                return response(url, 302, headers={"Location": "http://["})
            return response(url, 200, "<h1>Existing page</h1>")

        client = FakeClient(handler)
        result = scan_directory(client, self.target, ["before", "redirect", "after"])
        self.assertEqual(result.status, "success")
        self.assertEqual(result.checked, 3)
        self.assertEqual([item.status for item in result.findings], ["found", "redirect", "found"])
        redirect = result.findings[1]
        self.assertEqual(redirect.details["location"], "http://[")
        self.assertTrue(redirect.details["location_parse_error"])
        self.assertTrue(any("malformed redirect Location" in warning for warning in result.warnings))
        self.assertEqual(client.calls[-1], "https://example.com/app/after")

    def test_empty_dictionary_is_explicit_failure(self):
        client = FakeClient(lambda url: self.fail("unexpected request"))
        result = scan_directory(client, self.target, ["", " # comment "])
        self.assertEqual(result.status, "failed")
        self.assertIn("no paths", result.errors[0])

    def test_duplicate_paths_are_checked_once(self):
        client = FakeClient(self.missing)
        result = scan_directory(client, self.target, ["a", "/a", "a", "# comment"])
        self.assertEqual(result.checked, 1)
        self.assertEqual(len(client.calls), 3)

    def test_request_error_is_not_reported_as_no_findings(self):
        def handler(url):
            if ".butterfly-not-found-" in url:
                return self.missing(url)
            raise RequestError("certificate verification failed", kind="tls")

        result = scan_directory(FakeClient(handler), self.target, ["admin"])
        self.assertEqual(result.status, "failed")
        self.assertIn("certificate", result.errors[0])
        self.assertEqual(result.checked, 0)


class LinkTests(unittest.TestCase):
    def setUp(self):
        self.target = parse_target("https://example.com/app/index.html")

    def html_client(self, body, headers=None):
        headers = {"Content-Type": "text/html; charset=utf-8"} if headers is None else headers
        return FakeClient(lambda url: response(url, 200, body, headers))

    def test_links_are_resolved_deduplicated_and_not_fetched(self):
        html = '''<html><head>
            <script src="../assets/app.js"></script>
            <link href="//cdn.example/styles.css" rel="stylesheet">
            </head><body><a href="../assets/app.js#part">duplicate</a>
            <a href="/help?a=1&amp;b=2">help</a></body></html>'''
        client = self.html_client(html)
        result = extract_links(client, self.target)
        findings = {item.value: item for item in result.findings}
        self.assertEqual(set(findings), {"https://example.com/assets/app.js", "https://cdn.example/styles.css", "https://example.com/help?a=1&b=2"})
        self.assertEqual(findings["https://example.com/assets/app.js"].details["references"], ["script[src]", "a[href]"])
        self.assertFalse(findings["https://example.com/assets/app.js"].details["verified"])
        self.assertEqual(client.calls, [self.target.url])
        self.assertTrue(all(item.status == "discovered" for item in result.findings))

    def test_base_href_and_inline_script_references(self):
        html = '''<base href="/static/"><script src="app.js"></script>
            <script>const api = "/api/items"; const api2 = "https://api.example/v1";</script>'''
        result = extract_links(self.html_client(html), self.target)
        self.assertEqual({item.value for item in result.findings}, {
            "https://example.com/static/app.js", "https://example.com/api/items", "https://api.example/v1",
        })

    def test_non_web_links_fragments_and_credentials_are_ignored(self):
        html = '''<a href="#part">local</a><a href="mailto:a@example.com">mail</a>
            <a href="javascript:alert(1)">script</a><a href="data:text/plain,x">data</a>
            <a href="https://user:password@example.com/">credentials</a>
            <script src="ftp://example.com/x.js"></script>'''
        result = extract_links(self.html_client(html), self.target)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.status, "success")

    def test_non_html_is_an_error(self):
        result = extract_links(self.html_client('{"ok": true}', {"Content-Type": "application/json"}), self.target)
        self.assertEqual(result.status, "failed")
        self.assertIn("not HTML", result.errors[0])

    def test_numeric_non_http_schemes_are_not_coerced_into_hosts(self):
        html = '''<base href="custom:5678"><a href="tel:1234">phone</a>
            <a href="custom:5678">custom</a><a href="http:5678">opaque</a>
            <a href="/help">help</a>'''
        result = extract_links(self.html_client(html), self.target)
        self.assertEqual([item.value for item in result.findings], ["https://example.com/help"])
        self.assertEqual(result.status, "success")

    def test_missing_content_type_requires_html_evidence(self):
        result = extract_links(self.html_client("<html><a href='/help'>help</a></html>", {}), self.target)
        self.assertEqual(result.checked, 1)
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(result.warnings)
        bad = extract_links(self.html_client("plain text", {}), self.target)
        self.assertEqual(bad.status, "failed")

    def test_empty_html_is_successful_with_no_links(self):
        result = extract_links(self.html_client(""), self.target)
        self.assertEqual(result.checked, 1)
        self.assertEqual(result.status, "success")
        self.assertEqual(result.findings, [])

    def test_redirect_is_not_silently_treated_as_empty_html(self):
        client = FakeClient(lambda url: response(url, 302, headers={"Location": "/login"}))
        result = extract_links(client, self.target)
        self.assertEqual(result.status, "failed")
        self.assertIn("redirect not followed", result.errors[0])
        self.assertEqual(client.calls, [self.target.url])

    def test_timeout_has_explicit_failure_state(self):
        def handler(url):
            raise RequestError("timed out", kind="timeout")

        result = extract_links(FakeClient(handler), self.target)
        self.assertEqual(result.status, "failed")
        self.assertIn("timed out", result.errors[0])


if __name__ == "__main__":
    unittest.main()
