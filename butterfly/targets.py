"""Normalize targets without guessing or broadening their domain scope."""

from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit


@dataclass(frozen=True)
class Target:
    url: str
    hostname: str
    origin: str


def _reject_control_characters(value: str) -> None:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("地址不能包含控制字符")


def _hostname(value: str) -> str:
    value = value[:-1] if value.endswith(".") else value
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if ":" in value or "%" in value:
            raise ValueError("IPv6 地址须使用方括号，且不能包含区域标识") from None
    try:
        ascii_name = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("域名格式无效") from None
    labels = ascii_name.split(".")
    if (
        len(ascii_name) > 253
        or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                   for label in labels)
        or re.fullmatch(r"[0-9.]+", ascii_name)
    ):
        raise ValueError("主机名或 IP 地址格式无效")
    return ascii_name


def parse_target(value: str) -> Target:
    """Accept HTTP(S) URLs or bare hosts; bare hosts use HTTPS.

    Fragments are omitted because they are never sent to an HTTP server. The
    specified hostname remains the query scope, including any subdomain labels.
    """
    if not isinstance(value, str):
        raise ValueError("目标地址必须是字符串")
    _reject_control_characters(value)
    value = value.strip()
    if not value or any(char.isspace() for char in value) or "\\" in value:
        raise ValueError("请输入不含空白或反斜线的目标地址")
    candidate = value if "://" in value else "https://" + value
    try:
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in {"http", "https"}:
            raise ValueError("仅支持 http 和 https 地址")
        if not parts.hostname:
            raise ValueError("目标地址缺少主机名")
        if parts.username is not None or parts.password is not None:
            raise ValueError("目标地址不能包含用户名或密码")
        if parts.netloc.startswith("["):
            suffix = parts.netloc[parts.netloc.index("]") + 1:]
            if not re.fullmatch(r"(?::[0-9]+)?", suffix):
                raise ValueError("IPv6 方括号后只能指定端口")
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("端口必须在 1 到 65535 之间")
        if parts.netloc.endswith(":"):
            raise ValueError("端口不能为空")
        host = _hostname(parts.hostname)
    except ValueError as exc:
        raise ValueError(f"无效目标地址：{exc}") from None
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    scheme = parts.scheme.lower()
    origin = f"{scheme}://{authority}"
    path = quote(parts.path or "/", safe="/:@-._~!$&'()*+,;=%")
    query = quote(parts.query, safe="/?@:!$&'()*+,;=-._~%")
    return Target(urlunsplit((scheme, authority, path, query, "")), host, origin)


def join_path(target: Target, entry: str) -> str:
    """Resolve a dictionary entry under the target's directory path.

    A single leading slash in an entry is accepted for legacy dictionaries;
    entries still remain under the input base path. Absolute URLs, parent
    navigation and fragment-only entries are not dictionary paths.
    """
    if not isinstance(entry, str):
        raise ValueError("字典条目必须是字符串")
    _reject_control_characters(entry)
    entry = entry.strip()
    if not entry or "\\" in entry or entry.startswith("//"):
        raise ValueError("字典条目不能为空、外域地址或包含反斜线")
    try:
        parts = urlsplit(entry)
    except ValueError:
        raise ValueError("字典路径格式无效") from None
    if parts.scheme or parts.netloc or parts.fragment:
        raise ValueError("字典条目须为路径，不能含协议、主机或片段")
    decoded_path = unquote(parts.path)
    if "\\" in decoded_path or ".." in decoded_path.split("/"):
        raise ValueError("字典路径不能使用父目录跳转或反斜线")
    base = urlsplit(target.url)
    base_url = urlunsplit((base.scheme, base.netloc, base.path.rstrip("/") + "/", "", ""))
    relative = urlunsplit(("", "", quote(parts.path.lstrip("/"), safe="/:@-._~!$&'()*+,;=%"),
                           quote(parts.query, safe="/?@:!$&'()*+,;=-._~%"), ""))
    result = urljoin(base_url, relative)
    joined = urlsplit(result)
    if f"{joined.scheme}://{joined.netloc}" != target.origin:
        raise ValueError("字典路径不能改变目标站点")
    return result
