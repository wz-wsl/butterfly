"""Command-line entry point, including the original single-dash options."""

import argparse
import math
import sys
from importlib.resources import files
from pathlib import Path

from . import __version__
from .http_client import HttpClient
from .output import make_report, render, write_output
from .providers import query_ports, query_subdomains
from .scanners import extract_links, scan_directory
from .targets import parse_target


DEFAULT_PORTS = tuple(dict.fromkeys((
    21, 22, 69, 23, 25, 80, 443, 8080, 53, 68, 67, 110, 139, 143, 161,
    3389, 389, 512, 513, 514, 873, 1080, 1352, 1433, 2181, 5432, 5900,
    6379, 7001, 27017, 9200, 9300, 11211, 8009, 8983, 4848, 7002, 3306,
    1521, 2700, 5000, 995, 993,
)))


def _timeout(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or not 0 < number <= 300:
        raise argparse.ArgumentTypeError("超时必须是 0 到 300 秒之间的有限正数")
    return number


def _retries(value: str) -> int:
    number = int(value)
    if not 0 <= number <= 5:
        raise argparse.ArgumentTypeError("重试次数必须为 0 到 5")
    return number


def _max_bytes(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 100 * 1024 * 1024:
        raise argparse.ArgumentTypeError("响应上限必须在 1 字节到 100 MiB 之间")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Butterfly 网站信息收集：第三方端口/子域名查询、目录检查、页面链接提取",
        epilog="端口和子域名查询会将目标提交给第三方服务；不保证第三方查询完全被动。",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-ps", "--port-target", metavar="TARGET", help="第三方 TCP 端口查询")
    parser.add_argument("-psm", dest="port_start", type=int, help="起始端口，需配合 -dsm")
    parser.add_argument("-dsm", dest="port_end", type=int, help="结束端口，需配合 -psm")
    parser.add_argument("--ports", help="端口列表或闭区间，例如 80,443,8000-8002")
    parser.add_argument("-js", "--links", metavar="TARGET", help="提取入口 HTML 中的链接，不递归抓取 JS")
    parser.add_argument("-ds", "--directory", metavar="TARGET", help="按字典检查目录/文件")
    parser.add_argument("-f", "--wordlist", metavar="FILE", help="目录字典，UTF-8，每行一个相对路径")
    parser.add_argument("-do", "--subdomains", metavar="TARGET", help="第三方子域名查询，保留指定基域")
    parser.add_argument("--subdomain-wordlist", metavar="FILE", help="自定义子域名前缀字典")
    parser.add_argument("--timeout", type=_timeout, default=10.0, help="单次网络操作超时秒数，默认 10")
    parser.add_argument("--retries", type=_retries, default=1, help="GET 暂态失败重试次数，默认 1；POST 不重试")
    parser.add_argument("--max-bytes", type=_max_bytes, default=2 * 1024 * 1024, help="单个响应大小上限，默认 2 MiB")
    parser.add_argument("--insecure", action="store_true", help="显式关闭 HTTPS 证书验证，结果中会记录警告")
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table", help="输出格式")
    parser.add_argument("-o", "--output", metavar="FILE", help="将结果写入指定文件")
    return parser


def _port_list(args: argparse.Namespace) -> list[int]:
    if args.ports is not None:
        if args.port_start is not None or args.port_end is not None:
            raise ValueError("--ports 不能和 -psm/-dsm 同时使用")
        ports = set()
        for item in args.ports.split(","):
            item = item.strip()
            try:
                if "-" in item:
                    parts = item.split("-")
                    if len(parts) != 2:
                        raise ValueError
                    start, end = map(int, parts)
                else:
                    start = end = int(item)
            except ValueError:
                raise ValueError("端口列表包含空项或非数字值；示例：80,443,8000-8002") from None
            if not 1 <= start <= end <= 65535:
                raise ValueError("端口范围必须满足 1 <= start <= end <= 65535")
            ports.update(range(start, end + 1))
        return sorted(ports)
    if args.port_start is not None or args.port_end is not None:
        if args.port_start is None or args.port_end is None:
            raise ValueError("-psm 和 -dsm 必须同时指定")
        if not 1 <= args.port_start <= args.port_end <= 65535:
            raise ValueError("端口范围必须满足 1 <= start <= end <= 65535")
        return list(range(args.port_start, args.port_end + 1))
    return list(DEFAULT_PORTS)


def _wordlist(path: str) -> list[str]:
    with Path(path).open(encoding="utf-8-sig") as stream:
        return _lines(stream)


def _lines(lines) -> list[str]:
    return list(dict.fromkeys(line.strip() for line in lines
                             if line.strip() and not line.lstrip().startswith("#")))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not any((args.port_target, args.links, args.directory, args.subdomains)):
        parser.print_help()
        return 2
    try:
        if (args.ports is not None or args.port_start is not None or args.port_end is not None) and not args.port_target:
            raise ValueError("端口参数需要同时指定 -ps/--port-target")
        if args.wordlist and not args.directory:
            raise ValueError("-f/--wordlist 需要同时指定 -ds/--directory")
        if args.subdomain_wordlist and not args.subdomains:
            raise ValueError("--subdomain-wordlist 需要同时指定 -do/--subdomains")
        targets = {name: parse_target(value) for name, value in (
            ("port", args.port_target), ("links", args.links),
            ("directory", args.directory), ("subdomain", args.subdomains),
        ) if value is not None}
        ports = _port_list(args) if args.port_target else []
        entries = []
        if args.directory:
            if not args.wordlist:
                raise ValueError("目录检查需要用 -f 指定字典")
            entries = _wordlist(args.wordlist)
            if not entries:
                raise ValueError("目录字典没有有效条目")
        prefixes = []
        if args.subdomains:
            if args.subdomain_wordlist:
                prefixes = _wordlist(args.subdomain_wordlist)
            else:
                resource = files("butterfly").joinpath("resources/subdomains.txt")
                prefixes = _lines(resource.read_text(encoding="utf-8").splitlines())
            if not prefixes:
                raise ValueError("子域名字典没有有效条目")
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    results = []
    try:
        with HttpClient(timeout=args.timeout, retries=args.retries, verify=not args.insecure,
                        max_bytes=args.max_bytes) as client:
            if args.port_target:
                results.append(query_ports(client, targets["port"], ports))
            if args.links:
                results.append(extract_links(client, targets["links"]))
            if args.directory:
                results.append(scan_directory(client, targets["directory"], entries))
            if args.subdomains:
                results.append(query_subdomains(client, targets["subdomain"], prefixes))
        if args.insecure:
            for result in results:
                result.warnings.insert(0, "HTTPS 证书验证已通过 --insecure 关闭")
        text = render(make_report(results), args.format)
        if args.output:
            write_output(args.output, text)
            print(f"结果已写入 {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(text)
    except KeyboardInterrupt:
        print("任务已中断", file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1
    return 1 if any(result.errors for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
