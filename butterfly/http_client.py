"""Bounded HTTP transport using the Python standard library.

``timeout`` is a socket-operation timeout, not an overall scan deadline.
Redirects are returned to callers rather than followed automatically.
"""

from dataclasses import dataclass
from email.message import Message
import http.client
import json
import math
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from . import __version__
from .targets import parse_target


class RequestError(Exception):
    def __init__(self, message: str, *, kind: str = "network") -> None:
        super().__init__(message)
        self.kind = kind


@dataclass
class HttpResponse:
    status_code: int
    url: str
    headers: dict[str, str]
    content: bytes

    def __post_init__(self) -> None:
        self.headers = {key.lower(): value for key, value in self.headers.items()}

    @property
    def text(self) -> str:
        message = Message()
        message["content-type"] = self.headers.get("content-type", "")
        charset = message.get_content_charset() or "utf-8"
        try:
            return self.content.decode(charset, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self.text)


class _NoRedirect(HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        # Return the original response before urllib parses Location. Disabling
        # only redirect_request still lets malformed server URLs raise inside
        # HTTPRedirectHandler, losing the response and aborting the scan.
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpClient:
    RETRY_STATUS = {429, 502, 503, 504}

    def __init__(self, timeout: float = 10, retries: int = 1,
                 verify: bool = True, max_bytes: int = 2_097_152) -> None:
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("请求超时须为有限的正数")
        if isinstance(retries, bool) or not isinstance(retries, int) or not 0 <= retries <= 5:
            raise ValueError("重试次数须为 0 到 5 的整数")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError("响应大小上限须为正整数")
        self.timeout = timeout
        self.retries = retries
        self.verify = verify
        self.max_bytes = max_bytes
        context = ssl.create_default_context() if verify else ssl._create_unverified_context()
        self._opener = build_opener(HTTPSHandler(context=context), _NoRedirect())
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self) -> None:
        self._opener.close()
        self._closed = True

    def get(self, url: str) -> HttpResponse:
        return self.request("GET", url)

    def post(self, url: str, data: dict | None = None) -> HttpResponse:
        return self.request("POST", url, data=data)

    def request(self, method: str, url: str, data: dict | None = None) -> HttpResponse:
        if self._closed:
            raise RequestError("HTTP 客户端已关闭")
        method = method.upper()
        if method not in {"GET", "POST"}:
            raise ValueError("仅支持 GET 和 POST 请求")
        if method == "GET" and data is not None:
            raise ValueError("GET 请求不接受表单数据")
        try:
            url = parse_target(url).url
        except ValueError as exc:
            raise RequestError(str(exc), kind="invalid_url") from None
        payload = urlencode(data or {}).encode("utf-8") if method == "POST" else None
        headers = {"User-Agent": f"butterfly/{__version__}", "Accept-Encoding": "identity"}
        if payload is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        attempts = self.retries + 1 if method == "GET" else 1
        for attempt in range(attempts):
            request = Request(url, data=payload, headers=headers, method=method)
            try:
                response = self._read_response(request)
            except RequestError as exc:
                if attempt + 1 >= attempts or exc.kind not in {"timeout", "network"}:
                    raise
                time.sleep(min(0.25 * (2 ** attempt), 2))
                continue
            if response.status_code not in self.RETRY_STATUS or attempt + 1 >= attempts:
                return response
            retry_after = response.headers.get("retry-after", "")
            try:
                wait = float(retry_after)
                if not math.isfinite(wait):
                    raise ValueError
                wait = min(max(wait, 0), 2)
            except ValueError:
                wait = min(0.25 * (2 ** attempt), 2)
            time.sleep(wait)
        raise AssertionError("unreachable")

    def _read_response(self, request: Request) -> HttpResponse:
        try:
            try:
                response = self._opener.open(request, timeout=self.timeout)
            except HTTPError as exc:
                response = exc
            with response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                try:
                    declared_length = int(headers.get("content-length", "0"))
                except ValueError:
                    declared_length = 0
                if declared_length > self.max_bytes:
                    raise RequestError(f"响应超过 {self.max_bytes} 字节上限", kind="response_too_large")
                content = response.read(self.max_bytes + 1)
                if len(content) > self.max_bytes:
                    raise RequestError(f"响应超过 {self.max_bytes} 字节上限", kind="response_too_large")
                return HttpResponse(response.getcode(), response.geturl(), headers, content)
        except RequestError:
            raise
        except (URLError, OSError, http.client.HTTPException) as exc:
            cause = exc.reason if isinstance(exc, URLError) else exc
            if isinstance(cause, (socket.timeout, TimeoutError)):
                kind, message = "timeout", "网络请求超时"
            elif isinstance(cause, ssl.SSLError):
                kind, message = "tls", f"TLS 验证或连接失败：{cause}"
            else:
                kind, message = "network", f"网络请求失败：{cause}"
            raise RequestError(message, kind=kind) from None
