"""Adapters for the original third-party query services.

These services receive the queried host. They may themselves probe that host;
their use must not be described as guaranteed passive information collection.
"""

from __future__ import annotations

from collections.abc import Iterable
import ipaddress
import re
from typing import Any
from urllib.parse import urlencode

from .http_client import HttpClient, HttpResponse, RequestError
from .models import Finding, ScanResult
from .targets import Target


PORT_PROVIDER = "https://tool.box3.cn/server/port.php"
# The original tool sent this Referer; the service may reject requests without it.
PORT_PROVIDER_REFERER = "https://tool.box3.cn/port.html"
SUBDOMAIN_PROVIDER = "https://phpinfo.me/domain"
_MAX_CONSECUTIVE_FAILURES = 3
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)


def _json_response(response: HttpResponse) -> Any:
    if response.status_code != 200:
        raise ValueError(f"query service returned HTTP {response.status_code}")
    try:
        payload = response.json()
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("query service returned invalid JSON") from exc
    if isinstance(payload, dict):
        if payload.get("success") is False:
            raise ValueError("query service reported failure")
        if payload.get("error") not in (None, "", False, 0, [], {}):
            raise ValueError("query service reported an error")
        # A domain record's status describes that record, not the service.
        if not {"domain", "status", "ip"} <= payload.keys():
            for key in ("status", "status_code", "code"):
                value = payload.get(key)
                if type(value) is int and 400 <= value <= 599:
                    raise ValueError(f"query service reported {key} {value}")
                if isinstance(value, str) and re.fullmatch(r"[45]\d{2}", value):
                    raise ValueError(f"query service reported {key} {value}")
    return payload


def _port_state(payload: Any) -> bool:
    """Accept exactly one explicit is_open field, including nested responses."""
    states: list[Any] = []
    pending = [payload]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            if "is_open" in item:
                states.append(item["is_open"])
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    if len(states) != 1:
        raise ValueError("unrecognized port response: expected one is_open field")
    value = states[0]
    if isinstance(value, bool):
        return value
    if type(value) is int and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value in ("0", "1"):
        return value == "1"
    raise ValueError("unrecognized port response: is_open must be 0 or 1")


def query_ports(
    client: HttpClient, target: Target, ports: Iterable[int]
) -> ScanResult:
    """Query TCP ports through the configured third-party service, serially."""
    result = ScanResult("port", target.url)
    result.warnings.append(
        f"Third-party query: {PORT_PROVIDER} receives host {target.hostname}; "
        "its probing behavior is not verified. Results describe TCP only."
    )
    seen: set[int] = set()
    consecutive_failures = 0
    for port in ports:
        if type(port) is not int or not 1 <= port <= 65535:
            result.errors.append(f"Invalid TCP port: {port!r}; expected 1..65535")
            continue
        if port in seen:
            continue
        seen.add(port)
        try:
            response = client.post(
                PORT_PROVIDER,
                data={
                    "data": target.hostname,
                    "port": port,
                    "protocol": "tcp",
                    "method": "search",
                },
                headers={"Referer": PORT_PROVIDER_REFERER},
            )
            is_open = _port_state(_json_response(response))
        except (RequestError, ValueError) as exc:
            result.errors.append(f"TCP port {port}: {exc}")
            consecutive_failures += 1
            if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                result.warnings.append(
                    "Stopped after 3 consecutive service failures; "
                    "any remaining TCP ports were not checked."
                )
                break
            continue
        consecutive_failures = 0
        result.checked += 1
        result.findings.append(
            Finding(
                "port",
                target.hostname,
                "open" if is_open else "closed",
                str(port),
                PORT_PROVIDER,
                {"protocol": "tcp", "provider_http_status": response.status_code},
            )
        )
    return result


def _domain_records(payload: Any) -> list[dict[str, Any]]:
    """Support explicit records, record lists and conventional wrapper keys."""
    if isinstance(payload, list):
        records: list[dict[str, Any]] = []
        for item in payload:
            records.extend(_domain_records(item))
        return records
    if not isinstance(payload, dict):
        raise ValueError("unrecognized subdomain response: expected records")
    if {"domain", "status", "ip"} <= payload.keys():
        return [payload]
    wrappers = [key for key in ("data", "results", "result") if key in payload]
    if len(wrappers) != 1:
        raise ValueError("unrecognized subdomain response: missing record fields")
    return _domain_records(payload[wrappers[0]])


def _domain_name(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("subdomain response contains an invalid domain")
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("subdomain response contains an invalid domain") from exc
    if len(domain) > 253 or not all(_LABEL.fullmatch(p) for p in domain.split(".")):
        raise ValueError("subdomain response contains an invalid domain")
    return domain


def _record_status(value: Any) -> int:
    if type(value) is int:
        status = value
    elif isinstance(value, str) and re.fullmatch(r"\d{3}", value):
        status = int(value)
    else:
        raise ValueError("subdomain response contains an invalid status")
    if not 100 <= status <= 599:
        raise ValueError(f"subdomain response contains an invalid status {status}")
    return status


def _addresses(value: Any) -> list[str]:
    if value is None:
        return []
    candidates = [value] if isinstance(value, str) else value
    if not isinstance(candidates, list) or not all(isinstance(p, str) for p in candidates):
        raise ValueError("subdomain response contains invalid IP data")
    addresses: list[str] = []
    for candidate in candidates:
        try:
            address = str(ipaddress.ip_address(candidate))
        except ValueError as exc:
            raise ValueError("subdomain response contains an invalid IP address") from exc
        if address not in addresses:
            addresses.append(address)
    return addresses


def query_subdomains(
    client: HttpClient, target: Target, prefixes: Iterable[str]
) -> ScanResult:
    """Query under exactly the supplied hostname; never guess a registrable root."""
    result = ScanResult("subdomain", target.url)
    result.warnings.append(
        f"Third-party query: {SUBDOMAIN_PROVIDER} receives host {target.hostname} "
        "and each prefix; its probing behavior is not verified. "
        "The supplied hostname is retained as the query base."
    )
    try:
        ipaddress.ip_address(target.hostname)
    except ValueError:
        pass
    else:
        result.errors.append("Subdomain queries require a DNS hostname, not an IP address")
        return result
    if target.hostname.startswith("www.") and target.hostname.count(".") >= 2:
        parent = target.hostname[4:]
        result.warnings.append(
            f"Query base is {target.hostname}, so names like mail.{target.hostname} are checked. "
            f"Version 0.1 removed the leading www; to query names under {parent}, pass {parent}."
        )

    seen_prefixes: set[str] = set()
    seen_domains: set[str] = set()
    consecutive_failures = 0
    for raw_prefix in prefixes:
        if not isinstance(raw_prefix, str):
            result.errors.append(f"Invalid subdomain prefix: {raw_prefix!r}")
            continue
        prefix = raw_prefix.strip().lower()
        if not _LABEL.fullmatch(prefix):
            result.errors.append(f"Invalid subdomain prefix: {raw_prefix!r}")
            continue
        if prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)
        url = SUBDOMAIN_PROVIDER + "?" + urlencode(
            {"domain": target.hostname, "q": prefix}
        )
        try:
            response = client.get(url)
            records = _domain_records(_json_response(response))
            validated: list[tuple[str, list[str]]] = []
            for record in records:
                domain = _domain_name(record["domain"])
                if domain != target.hostname and not domain.endswith("." + target.hostname):
                    raise ValueError("subdomain response contains an out-of-scope domain")
                status = _record_status(record["status"])
                addresses = _addresses(record["ip"])
                if status != 200:
                    # The service marks names that do not resolve with a
                    # non-200 record status (typically 500) and "ip": null.
                    # Such a record is a miss, not a service failure.
                    if addresses:
                        raise ValueError("subdomain response has conflicting status and IP data")
                    continue
                if not addresses:
                    raise ValueError("successful subdomain response is missing IP addresses")
                validated.append((domain, addresses))
        except (RequestError, ValueError, RecursionError) as exc:
            result.errors.append(f"Subdomain prefix {prefix}: {exc}")
            consecutive_failures += 1
            if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                result.warnings.append(
                    "Stopped after 3 consecutive service failures; "
                    "any remaining subdomain prefixes were not checked."
                )
                break
            continue
        consecutive_failures = 0
        result.checked += 1
        for domain, addresses in validated:
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            result.findings.append(
                Finding(
                    "subdomain",
                    target.hostname,
                    "found",
                    domain,
                    SUBDOMAIN_PROVIDER,
                    {"ip_addresses": addresses, "query_prefix": prefix},
                )
            )
    return result
