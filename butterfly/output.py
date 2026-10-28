"""Render a single report as readable text, JSON or CSV."""

import csv
import io
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import ScanResult


def make_report(results: list[ScanResult]) -> dict:
    return {
        "schema_version": 1,
        "tool": "butterfly",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": [result.to_dict() for result in results],
    }


def _display(value: object) -> str:
    # Remote page titles must not inject terminal control sequences.
    return "".join(char if char.isprintable() else " " for char in str(value))


def render(report: dict, format_name: str = "table") -> str:
    if format_name == "json":
        return json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if format_name == "csv":
        stream = io.StringIO(newline="")
        columns = ["record_type", "kind", "target", "scan_status", "status",
                   "value", "source", "details", "message"]
        writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for result in report["results"]:
            base = {"kind": result["kind"], "target": result["target"],
                    "scan_status": result["status"]}
            writer.writerow({**base, "record_type": "summary",
                             "details": json.dumps({"checked": result["checked"]})})
            for item in result["findings"]:
                writer.writerow({**base, "record_type": "finding",
                                 "status": item["status"], "value": item["value"],
                                 "source": item["source"],
                                 "details": json.dumps(item["details"], ensure_ascii=False)})
            for key, record_type in (("errors", "error"), ("warnings", "warning")):
                for message in result[key]:
                    writer.writerow({**base, "record_type": record_type, "message": message})
        return stream.getvalue()
    if format_name != "table":
        raise ValueError(f"不支持的输出格式: {format_name}")
    lines = []
    for result in report["results"]:
        lines.append(_display(f"[{result['kind']}] {result['target']}"))
        lines.append(f"  status={result['status']} checked={result['checked']} "
                     f"findings={len(result['findings'])}")
        for item in result["findings"]:
            lines.append(_display(f"  {item['status']:<20} {item['value']}"))
            if item["details"]:
                lines.append("    " + _display(json.dumps(item["details"], ensure_ascii=False)))
            if item["source"]:
                lines.append("    source=" + _display(item["source"]))
        for message in result["warnings"]:
            lines.append("  warning: " + _display(message))
        for message in result["errors"]:
            lines.append("  error: " + _display(message))
        lines.append("")
    return "\n".join(lines)


def write_output(path: str, text: str) -> None:
    """Replace the destination only after the entire report is written."""
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="",
                                         dir=destination.parent, delete=False) as stream:
            temporary = stream.name
            stream.write(text)
        # NamedTemporaryFile is created 0600; give the report normal file permissions.
        try:
            mode = destination.stat().st_mode & 0o777
        except FileNotFoundError:
            umask = os.umask(0)
            os.umask(umask)
            mode = 0o666 & ~umask
        os.chmod(temporary, mode)
        os.replace(temporary, destination)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
