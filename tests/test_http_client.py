from email.message import Message
import io
import json
import socket
import ssl
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import BaseHandler, ProxyHandler, build_opener
from urllib.response import addinfourl

from butterfly.http_client import HttpClient, HttpResponse, RequestError, _NoRedirect


class _Response(io.BytesIO):
    def __init__(self, body=b"ok", status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def getcode(self):
        return self.status

    def geturl(self):
        return "https://example.com/"


class HttpClientTests(unittest.TestCase):
    def test_default_ssl_context_verifies_certificates(self):
        with patch("butterfly.http_client.ssl.create_default_context", wraps=ssl.create_default_context) as create:
            with HttpClient() as client:
                self.assertTrue(client.verify)
            create.assert_called_once()

    def test_timeout_is_supplied_and_error_is_distinct(self):
        with HttpClient(timeout=2.5, retries=0) as client:
            with patch.object(client._opener, "open", side_effect=URLError(socket.timeout())) as opened:
                with self.assertRaises(RequestError) as caught:
                    client.get("example.com")
            self.assertEqual(caught.exception.kind, "timeout")
            self.assertEqual(opened.call_args.kwargs["timeout"], 2.5)

    def test_certificate_failure_is_not_retried(self):
        with HttpClient(retries=2) as client:
            with patch.object(client._opener, "open", side_effect=URLError(ssl.SSLCertVerificationError("untrusted"))) as opened:
                with self.assertRaises(RequestError) as caught:
                    client.get("https://example.com")
            self.assertEqual(caught.exception.kind, "tls")
            self.assertEqual(opened.call_count, 1)

    def test_get_retries_temporary_network_failure(self):
        with HttpClient(retries=1) as client:
            with patch.object(client._opener, "open", side_effect=[URLError(ConnectionResetError("reset")), _Response()]) as opened:
                with patch("butterfly.http_client.time.sleep"):
                    result = client.get("https://example.com")
            self.assertEqual(result.content, b"ok")
            self.assertEqual(opened.call_count, 2)

    def test_post_is_not_retried_after_network_failure(self):
        with HttpClient(retries=3) as client:
            with patch.object(client._opener, "open", side_effect=URLError(socket.timeout())) as opened:
                with self.assertRaises(RequestError):
                    client.post("https://example.com", {"query": "value"})
            self.assertEqual(opened.call_count, 1)

    def test_extra_headers_are_sent_and_validated(self):
        with HttpClient(retries=0) as client:
            with patch.object(client._opener, "open", return_value=_Response()) as opened:
                client.post("https://example.com", {"q": "1"}, headers={"Referer": "https://example.com/p"})
            request = opened.call_args.args[0]
            self.assertEqual(request.get_header("Referer"), "https://example.com/p")
            self.assertTrue(request.get_header("User-agent").startswith("butterfly/"))
            for bad in ({"Referer": "a\r\nX-Injected: 1"}, {"Bad Name": "x"}):
                with self.subTest(headers=bad), self.assertRaises(ValueError):
                    client.get("https://example.com", headers=bad)

    def test_retryable_http_status_returns_last_response(self):
        with HttpClient(retries=1) as client:
            with patch.object(client._opener, "open", side_effect=[_Response(status=503), _Response(status=503)]) as opened:
                with patch("butterfly.http_client.time.sleep"):
                    result = client.get("https://example.com")
            self.assertEqual(result.status_code, 503)
            self.assertEqual(opened.call_count, 2)

    def test_http_errors_preserve_status_and_body(self):
        error = HTTPError("https://example.com/", 403, "Forbidden", Message(), io.BytesIO(b"denied"))
        with HttpClient(retries=0) as client:
            with patch.object(client._opener, "open", side_effect=error):
                result = client.get("https://example.com")
        self.assertEqual((result.status_code, result.content), (403, b"denied"))

    def test_response_size_limit_without_content_length(self):
        with HttpClient(max_bytes=8) as client:
            with patch.object(client._opener, "open", return_value=_Response(b"0123456789")):
                with self.assertRaises(RequestError) as caught:
                    client.get("https://example.com")
        self.assertEqual(caught.exception.kind, "response_too_large")

    def test_declared_oversize_is_rejected_before_reading(self):
        response = _Response(b"x", headers={"Content-Length": "100"})
        with HttpClient(max_bytes=8) as client:
            with patch.object(client._opener, "open", return_value=response):
                with patch.object(response, "read", wraps=response.read) as read:
                    with self.assertRaises(RequestError):
                        client.get("https://example.com")
                    read.assert_not_called()

    def test_post_form_encoding(self):
        with HttpClient() as client:
            with patch.object(client._opener, "open", return_value=_Response()) as opened:
                client.post("https://example.com", {"host": "a.example.com", "query": "a b"})
            request = opened.call_args.args[0]
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.data, b"host=a.example.com&query=a+b")

    def test_text_charset_and_invalid_json(self):
        response = HttpResponse(200, "https://example.com", {"Content-Type": "text/plain; charset=iso-8859-1"}, b"caf\xe9")
        self.assertEqual(response.text, "café")
        self.assertIn("content-type", response.headers)
        with self.assertRaises(json.JSONDecodeError):
            response.json()
        unknown_charset = HttpResponse(200, "https://example.com", {"content-type": "text/plain; charset=unknown-charset"}, b"ok")
        self.assertEqual(unknown_charset.text, "ok")

    def test_invalid_configuration(self):
        for kwargs in ({"timeout": 0}, {"timeout": float("nan")}, {"timeout": float("inf")},
                       {"retries": -1}, {"retries": 6}, {"max_bytes": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                HttpClient(**kwargs)


class _FixtureTransport(BaseHandler):
    """Feed HTTP responses through urllib's real status/redirect processors."""

    handler_order = 100

    def __init__(self, status=302, location="/destination"):
        self.requested = []
        self.status = status
        self.location = location

    def http_open(self, request):
        self.requested.append(request.full_url)
        headers = Message()
        if self.location is not None:
            headers["Location"] = self.location
        response = addinfourl(io.BytesIO(b"redirect"), headers, request.full_url, self.status)
        response.msg = "Found"
        return response


class RedirectTransportTests(unittest.TestCase):
    def test_redirect_is_reported_without_following_it(self):
        fixture = _FixtureTransport()
        with HttpClient(retries=0) as client:
            client._opener = build_opener(ProxyHandler({}), fixture, _NoRedirect())
            response = client.get("http://example.test/redirect")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "/destination")
        self.assertEqual(fixture.requested, ["http://example.test/redirect"])

    def test_malformed_redirect_location_preserves_response_for_all_redirect_statuses(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                fixture = _FixtureTransport(status=status, location="http://[")
                with HttpClient(retries=0) as client:
                    client._opener = build_opener(ProxyHandler({}), fixture, _NoRedirect())
                    response = client.get("http://example.test/redirect")
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.headers["location"], "http://[")
                self.assertEqual(response.content, b"redirect")
                self.assertEqual(fixture.requested, ["http://example.test/redirect"])

    def test_redirect_without_location_preserves_status(self):
        fixture = _FixtureTransport(location=None)
        with HttpClient(retries=0) as client:
            client._opener = build_opener(ProxyHandler({}), fixture, _NoRedirect())
            response = client.get("http://example.test/redirect")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("location", response.headers)


if __name__ == "__main__":
    unittest.main()
