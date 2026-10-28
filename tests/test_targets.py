import unittest

from butterfly.targets import join_path, parse_target


class TargetTests(unittest.TestCase):
    def test_bare_domain_is_preserved(self):
        target = parse_target("example.com")
        self.assertEqual(target.url, "https://example.com/")
        self.assertEqual(target.hostname, "example.com")
        self.assertEqual(target.origin, "https://example.com")

    def test_subdomains_are_not_guessed_or_removed(self):
        for hostname in ("www.example.com", "a.example.co.uk", "localhost"):
            with self.subTest(hostname=hostname):
                self.assertEqual(parse_target(hostname).hostname, hostname)

    def test_port_path_query_and_fragment(self):
        target = parse_target("HTTPS://EXAMPLE.COM:8443/app/?x=1#section")
        self.assertEqual(target.hostname, "example.com")
        self.assertEqual(target.origin, "https://example.com:8443")
        self.assertEqual(target.url, "https://example.com:8443/app/?x=1")

    def test_ip_addresses(self):
        examples = {
            "127.0.0.1:8080": "https://127.0.0.1:8080/",
            "http://[::1]:8000/a": "http://[::1]:8000/a",
            "[2001:0db8::1]": "https://[2001:db8::1]/",
        }
        for value, expected in examples.items():
            with self.subTest(value=value):
                self.assertEqual(parse_target(value).url, expected)

    def test_idna_and_unicode_path(self):
        target = parse_target("https://例子.测试/路径")
        self.assertEqual(target.hostname, "xn--fsqu00a.xn--0zwm56d")
        self.assertEqual(target.url, "https://xn--fsqu00a.xn--0zwm56d/%E8%B7%AF%E5%BE%84")

    def test_rejects_invalid_or_ambiguous_targets(self):
        values = [
            "", "   ", "ftp://example.com", "file:///etc/passwd",
            "https:///example.com", "http://", "https://user:secret@example.com",
            "https://example.com:0", "https://example.com:65536",
            "https://example.com:notaport", "https://example.com:",
            "https://example.com\r\nX-Test:1", "exam ple.com",
            "https://example.com\\@other.example", "http://[::1",
            "999.999.999.999", "a..example.com", "-bad.example.com",
            "::1", "http:example.com", "//example.com", "example.com..",
            "http://[::1]garbage", "http://[::1]garbage:80",
        ]
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_target(value)

    def test_trailing_dns_dot_is_normalized(self):
        self.assertEqual(parse_target("EXAMPLE.COM.").hostname, "example.com")


class DictionaryPathTests(unittest.TestCase):
    def test_entries_stay_under_input_base_path(self):
        target = parse_target("https://example.com/app?discard=this")
        for entry in ("admin", "/admin", "./admin"):
            with self.subTest(entry=entry):
                self.assertEqual(join_path(target, entry), "https://example.com/app/admin")

    def test_preserves_trailing_slash_query_and_unicode(self):
        target = parse_target("example.com/app/")
        self.assertEqual(join_path(target, "admin/?page=1"), "https://example.com/app/admin/?page=1")
        self.assertEqual(join_path(target, "路径"), "https://example.com/app/%E8%B7%AF%E5%BE%84")

    def test_rejects_absolute_offsite_or_parent_paths(self):
        target = parse_target("https://example.com/app/")
        values = [
            "", "https://other.example/x", "//other.example/x", "../admin",
            "a/../../admin", "%2e%2e/admin", "a/%2E%2E/admin",
            "a\\admin", "%5c%5cother.example/x", "admin#fragment",
            "foo:bar", "admin\nother",
        ]
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                join_path(target, value)

    def test_query_urls_do_not_change_origin(self):
        target = parse_target("https://example.com:8443/base/")
        result = join_path(target, "login?next=https://other.example/")
        self.assertEqual(parse_target(result).origin, target.origin)
        self.assertTrue(result.startswith("https://example.com:8443/base/login?"))


if __name__ == "__main__":
    unittest.main()
