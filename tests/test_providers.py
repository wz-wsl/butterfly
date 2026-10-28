"""Offline contract tests for third-party schemas and failure distinctions."""

import json
import unittest
from urllib.parse import parse_qs, urlsplit

from butterfly.http_client import HttpResponse, RequestError
from butterfly.providers import query_ports, query_subdomains
from butterfly.targets import parse_target


def response(payload, status=200):
    return HttpResponse(status, "https://provider.test/", {}, json.dumps(payload).encode())


class FakeClient:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.requests = []

    def _next(self):
        value = next(self.responses)
        if isinstance(value, Exception):
            raise value
        return value

    def post(self, url, data=None):
        self.requests.append(("POST", url, data))
        return self._next()

    def get(self, url):
        self.requests.append(("GET", url, None))
        return self._next()


class PortProviderTests(unittest.TestCase):
    def test_open_closed_and_duplicate_ports(self):
        client = FakeClient(response({"data": {"is_open": "1"}}), response({"is_open": 0}))
        result = query_ports(client, parse_target("example.com:8443"), [80, 80, 443])
        self.assertEqual(result.checked, 2)
        self.assertEqual([f.status for f in result.findings], ["open", "closed"])
        self.assertEqual(client.requests[0][2]["data"], "example.com")
        self.assertEqual(client.requests[0][2]["protocol"], "tcp")
        self.assertTrue(result.warnings)

    def test_unknown_or_ambiguous_schema_is_failure_not_closed(self):
        for payload in ({"message": "maintenance"}, {"is_open": "yes"},
                        {"a": {"is_open": 1}, "b": {"is_open": 0}}, {"is_open": 1.0}):
            with self.subTest(payload=payload):
                result = query_ports(FakeClient(response(payload)), parse_target("example.com"), [80])
                self.assertEqual(result.status, "failed")
                self.assertEqual(result.findings, [])

    def test_timeout_and_http_failure_preserve_partial_status(self):
        client = FakeClient(response({"is_open": False}), RequestError("timed out", kind="timeout"), response({}, 429))
        result = query_ports(client, parse_target("example.com"), [80, 81, 82])
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.checked, 1)
        self.assertIn("timed out", result.errors[0])
        self.assertIn("429", result.errors[1])

    def test_invalid_ports_do_not_make_requests(self):
        client = FakeClient()
        result = query_ports(client, parse_target("example.com"), [0, 65536, True, "80"])
        self.assertEqual(result.checked, 0)
        self.assertEqual(len(result.errors), 4)
        self.assertEqual(client.requests, [])

    def test_non_json_response_is_explicit_failure(self):
        result = query_ports(FakeClient(HttpResponse(200, "https://provider.test", {}, b"<html>oops</html>")),
                             parse_target("example.com"), [80])
        self.assertIn("invalid JSON", result.errors[0])

    def test_explicit_service_failure_overrides_port_field(self):
        for payload in ({"success": False, "data": {"is_open": 0}},
                        {"code": 503, "data": {"is_open": 0}}):
            with self.subTest(payload=payload):
                result = query_ports(FakeClient(response(payload)), parse_target("example.com"), [80])
                self.assertEqual(result.status, "failed")
                self.assertEqual(result.checked, 0)

    def test_consecutive_service_failures_stop_further_port_queries(self):
        client = FakeClient(RequestError("timed out", kind="timeout"),
                            response({}, 503), response({"unexpected": True}))
        result = query_ports(client, parse_target("example.com"), range(80, 90))
        self.assertEqual(len(client.requests), 3)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.checked, 0)
        self.assertIn("remaining TCP ports were not checked", result.warnings[-1])

    def test_successful_port_query_resets_consecutive_failure_counter(self):
        client = FakeClient(response({}, 503), response({}, 503), response({"is_open": 0}),
                            response({}, 503), response({}, 503), response({"is_open": 1}))
        result = query_ports(client, parse_target("example.com"), range(80, 86))
        self.assertEqual(len(client.requests), 6)
        self.assertEqual(result.checked, 2)
        self.assertEqual(result.status, "partial")
        self.assertFalse(any("Stopped after" in warning for warning in result.warnings))

    def test_invalid_ports_do_not_increment_or_reset_service_failure_counter(self):
        client = FakeClient(response({}, 503), response({}, 503), response({}, 503))
        result = query_ports(client, parse_target("example.com"), [80, 0, 81, True, 82, 83])
        self.assertEqual(len(client.requests), 3)
        self.assertEqual(len(result.errors), 5)
        self.assertIn("Stopped after", result.warnings[-1])


class SubdomainProviderTests(unittest.TestCase):
    def test_exact_input_base_is_retained_and_results_deduplicated(self):
        record = {"domain": "www.a.example.co.uk", "status": 200, "ip": "192.0.2.1"}
        client = FakeClient(response({"data": [record]}), response([record]))
        result = query_subdomains(client, parse_target("a.example.co.uk"), ["www", "mail", "www"])
        self.assertEqual(result.checked, 2)
        self.assertEqual(len(result.findings), 1)
        query = parse_qs(urlsplit(client.requests[0][1]).query)
        self.assertEqual(query["domain"], ["a.example.co.uk"])
        self.assertEqual(result.findings[0].details["ip_addresses"], ["192.0.2.1"])

    def test_empty_list_and_record_not_found_are_successful_no_findings(self):
        client = FakeClient(response([]), response({"domain": "mail.example.com", "status": "404", "ip": None}))
        result = query_subdomains(client, parse_target("example.com"), ["www", "mail"])
        self.assertEqual(result.status, "success")
        self.assertEqual(result.checked, 2)
        self.assertEqual(result.findings, [])

    def test_out_of_scope_response_is_failure(self):
        for domain in ("example.com.attacker.test", "notexample.com"):
            result = query_subdomains(FakeClient(response({"domain": domain, "status": 200, "ip": "192.0.2.1"})),
                                      parse_target("example.com"), ["www"])
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.findings, [])

    def test_malformed_service_response_is_not_no_results(self):
        payloads = ({"error": "maintenance"}, {"data": None},
                    {"domain": "www.example.com", "status": 500, "ip": None},
                    {"domain": "www.example.com", "status": 200, "ip": None},
                    {"domain": "www.example.com", "status": True, "ip": "192.0.2.1"},
                    {"domain": "www.example.com", "status": 200, "ip": "not-an-ip"})
        for payload in payloads:
            with self.subTest(payload=payload):
                result = query_subdomains(FakeClient(response(payload)), parse_target("example.com"), ["www"])
                self.assertEqual(result.status, "failed")
                self.assertTrue(result.errors)

    def test_invalid_prefix_and_ip_target_are_rejected_without_requests(self):
        client = FakeClient()
        result = query_subdomains(client, parse_target("example.com"), ["../www", "www.other", "", None])
        self.assertEqual(len(result.errors), 4)
        self.assertEqual(client.requests, [])
        result = query_subdomains(client, parse_target("192.0.2.1"), ["www"])
        self.assertEqual(result.status, "failed")
        self.assertIn("DNS hostname", result.errors[0])
        self.assertEqual(client.requests, [])

    def test_http_503_and_timeout_are_failures(self):
        client = FakeClient(response([], 503), RequestError("request timed out", kind="timeout"))
        result = query_subdomains(client, parse_target("example.com"), ["www", "mail"])
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.checked, 0)
        self.assertEqual(len(result.errors), 2)

    def test_error_envelope_with_empty_data_is_not_no_results(self):
        for payload in ({"code": 503, "data": []}, {"success": False, "data": []},
                        {"error": "maintenance", "data": []}):
            with self.subTest(payload=payload):
                result = query_subdomains(FakeClient(response(payload)), parse_target("example.com"), ["www"])
                self.assertEqual(result.status, "failed")
                self.assertEqual(result.checked, 0)

    def test_consecutive_service_failures_stop_further_subdomain_queries(self):
        client = FakeClient(RequestError("timed out", kind="timeout"),
                            response({}, 503), response({"unexpected": True}))
        result = query_subdomains(client, parse_target("example.com"), ["www", "mail", "api", "dev"])
        self.assertEqual(len(client.requests), 3)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.checked, 0)
        self.assertIn("remaining subdomain prefixes were not checked", result.warnings[-1])

    def test_successful_subdomain_query_resets_consecutive_failure_counter(self):
        client = FakeClient(response({}, 503), response({}, 503), response([]),
                            response({}, 503), response({}, 503), response([]))
        result = query_subdomains(client, parse_target("example.com"),
                                  ["www", "mail", "api", "dev", "test", "ftp"])
        self.assertEqual(len(client.requests), 6)
        self.assertEqual(result.checked, 2)
        self.assertEqual(result.status, "partial")
        self.assertFalse(any("Stopped after" in warning for warning in result.warnings))

    def test_invalid_prefixes_do_not_increment_or_reset_service_failure_counter(self):
        client = FakeClient(response({}, 503), response({}, 503), response({}, 503))
        result = query_subdomains(client, parse_target("example.com"),
                                  ["www", "../bad", "mail", "", "api", "dev"])
        self.assertEqual(len(client.requests), 3)
        self.assertEqual(len(result.errors), 5)
        self.assertIn("Stopped after", result.warnings[-1])


if __name__ == "__main__":
    unittest.main()
