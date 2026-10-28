"""Website checks with explicit result states and no recursive crawling."""

from difflib import SequenceMatcher
from html.parser import HTMLParser
import re
from typing import Iterable
from urllib.parse import urldefrag, urljoin, urlsplit
from uuid import uuid4

from .http_client import HttpClient, HttpResponse, RequestError
from .models import Finding, ScanResult
from .targets import Target, join_path, parse_target


_MAX_COMPARISON_CHARS = 32768
_QUOTED_LINK = re.compile(
    r"(?P<quote>['\"])(?P<url>"
    r"(?:https?://|//|/|\./|\.\./)[^'\"\s<>]+"
    r"|[A-Za-z0-9_][A-Za-z0-9_.\-/]*\.(?:js|json|php|asp|aspx|jsp|html?)"
    r"(?:\?[^'\"\s<>]*)?)(?P=quote)",
    re.IGNORECASE,
)


def _header(response: HttpResponse, name: str) -> str:
    return next(
        (value for key, value in response.headers.items() if key.lower() == name.lower()),
        "",
    )


class _PageParser(HTMLParser):
    """Collect only static references and a human-readable page title."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[str, str]] = []
        self.base_href: str | None = None
        self._in_title = False
        self._in_script = False
        self.title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "title":
            self._in_title = True
        if tag == "script":
            self._in_script = True
        if tag == "base" and self.base_href is None and values.get("href"):
            self.base_href = values["href"]
        attribute = {"script": "src", "a": "href", "link": "href"}.get(tag)
        if attribute and values.get(attribute):
            self.references.append((values[attribute], f"{tag}[{attribute}]"))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        if self._in_script:
            self.references.extend(
                (match.group("url"), "inline-script") for match in _QUOTED_LINK.finditer(data)
            )

    @property
    def title(self) -> str:
        return " ".join("".join(self.title_parts).split())[:300]


def _page_title(response: HttpResponse) -> str:
    parser = _PageParser()
    parser.feed(response.text[:_MAX_COMPARISON_CHARS])
    return parser.title


def _comparison_text(response: HttpResponse, requested_url: str) -> str:
    # Error templates often echo the requested path or an incident timestamp.
    # These are heuristics for a *suspected* soft 404, never proof of absence.
    text = response.text[:_MAX_COMPARISON_CHARS]
    path = urlsplit(requested_url).path
    for value in sorted({requested_url, path, path.rsplit("/", 1)[-1]}, key=len, reverse=True):
        if value:
            text = text.replace(value, "<requested-path>")
    text = re.sub(r"\b[0-9a-f]{32}\b", "<request-id>", text, flags=re.IGNORECASE)
    text = re.sub(r"\b\d{10,}\b", "<timestamp>", text)
    return " ".join(text.split())


def _similar(template: str, candidate: str, threshold: float = 0.98) -> bool:
    # quick ratios are cheap upper bounds of ratio(); checking them first gives
    # the same answer while skipping the slow comparison for clearly different pages.
    matcher = SequenceMatcher(None, template, candidate)
    return (matcher.real_quick_ratio() >= threshold
            and matcher.quick_ratio() >= threshold
            and matcher.ratio() >= threshold)


def _baseline(client: HttpClient, target: Target, result: ScanResult) -> str | None:
    samples: list[tuple[int, str]] = []
    for _ in range(2):
        url = join_path(target, f".butterfly-not-found-{uuid4().hex}")
        try:
            response = client.get(url)
        except RequestError as exc:
            result.warnings.append(f"Soft-404 baseline unavailable: {exc}")
            continue
        if response.status_code not in {200, 404, 410}:
            result.warnings.append(
                f"Soft-404 baseline returned HTTP {response.status_code}; similarity checks disabled."
            )
            continue
        text = _comparison_text(response, url)
        if not text:
            result.warnings.append("Soft-404 baseline was empty; similarity checks disabled.")
            continue
        samples.append((response.status_code, text))
    if len(samples) != 2:
        return None
    first, second = samples
    if first[0] != second[0] or first[1] != second[1]:
        # Requiring two agreeing normalized templates avoids learning a changing
        # application page, a rate-limit page, or one exceptional response.
        result.warnings.append("Soft-404 baseline responses differ; similarity checks disabled.")
        return None
    return first[1]


def scan_directory(client: HttpClient, target: Target, entries: Iterable[str]) -> ScanResult:
    """Check dictionary paths relative to the supplied URL's directory path.

    Redirects are recorded rather than followed. All checked paths, including
    explicit 404s, remain available to table/JSON/CSV consumers.
    """
    result = ScanResult("directory", target.url)
    urls: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            url = join_path(target, entry)
        except ValueError as exc:
            result.errors.append(f"Invalid dictionary entry {entry!r}: {exc}")
            continue
        if url not in seen:
            urls.append(url)
            seen.add(url)
    if not urls:
        if not result.errors:
            result.errors.append("The directory dictionary contains no paths.")
        return result

    template = _baseline(client, target, result)
    for url in urls:
        try:
            response = client.get(url)
        except RequestError as exc:
            result.errors.append(f"{url}: {exc}")
            continue
        code = response.status_code
        details = {
            "status_code": code,
            "length": len(response.content),
            "title": _page_title(response),
            "final_url": response.url,
        }
        if code in {404, 410}:
            status, reason = "not_found", f"HTTP {code}"
        elif code in {401, 403}:
            status, reason = "restricted", f"HTTP {code}; existence is not confirmed"
        elif 300 <= code < 400:
            status, reason = "redirect", f"HTTP {code}; redirect not followed"
            location = _header(response, "location")
            try:
                details["location"] = urljoin(response.url, location) if location else ""
            except ValueError:
                details["location"] = location
                details["location_parse_error"] = True
                result.warnings.append(
                    f"{url}: malformed redirect Location; the original header was retained."
                )
        elif 200 <= code < 300:
            candidate = _comparison_text(response, url)
            if template and candidate and _similar(template, candidate):
                status, reason = "suspected_soft_404", "Content resembles two missing-path baseline responses"
            else:
                status, reason = "found", f"HTTP {code}; response differs from the missing-path template"
                if template is None:
                    reason = f"HTTP {code}; no reliable missing-path template was available"
        elif 500 <= code < 600:
            # A server error usually means the path exists but failed to run.
            status, reason = "server_error", f"HTTP {code}; the path may exist but the server failed"
        else:
            result.errors.append(f"{url}: unexpected HTTP {code}")
            details["reason"] = f"Unexpected HTTP {code}"
            result.findings.append(Finding("directory", target.url, "error", url, url, details))
            continue
        details["reason"] = reason
        result.findings.append(Finding("directory", target.url, status, url, url, details))
        result.checked += 1
    return result


def _normalize_link(value: str, base_url: str) -> str | None:
    value = value.strip()
    if not value or value.startswith("#"):
        return None
    try:
        url = urldefrag(urljoin(base_url, value))[0]
        # parse_target also accepts bare host:port CLI input. References have
        # already been resolved, so reject other URI schemes before that step.
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
            return None
        parsed = parse_target(url)
    except ValueError:
        return None
    return parsed.url


def extract_links(client: HttpClient, target: Target) -> ScanResult:
    """Extract static references from one HTML response; do not fetch scripts."""
    result = ScanResult("link", target.url)
    try:
        response = client.get(target.url)
    except RequestError as exc:
        result.errors.append(str(exc))
        return result
    if not 200 <= response.status_code < 300:
        message = f"Entry page returned HTTP {response.status_code}"
        if 300 <= response.status_code < 400:
            message += "; redirect not followed"
        result.errors.append(message)
        return result
    content_type = _header(response, "content-type").split(";", 1)[0].strip().lower()
    if content_type and content_type not in {"text/html", "application/xhtml+xml"}:
        result.errors.append(f"Entry page is not HTML (Content-Type: {content_type})")
        return result
    if not content_type:
        if not re.search(r"<(?:!doctype\s+html|html|head|body|a\b|script\b|link\b)", response.text, re.IGNORECASE):
            result.errors.append("Entry page has no HTML Content-Type and does not look like HTML")
            return result
        result.warnings.append("Entry page omitted Content-Type; parsed as HTML based on its contents.")

    parser = _PageParser()
    parser.feed(response.text)
    parser.close()
    base_url = response.url
    if parser.base_href:
        candidate = _normalize_link(parser.base_href, response.url)
        if candidate:
            base_url = candidate
    findings: dict[str, Finding] = {}
    for value, reference_type in parser.references:
        url = _normalize_link(value, base_url)
        if url is None:
            continue
        if url in findings:
            references = findings[url].details["references"]
            if reference_type not in references:
                references.append(reference_type)
            continue
        findings[url] = Finding(
            "link", target.url, "discovered", url, response.url,
            {"references": [reference_type], "source_url": response.url, "verified": False},
        )
    result.findings.extend(findings.values())
    result.checked = 1
    result.warnings.append("Static references only: linked resources were not fetched or verified.")
    return result
