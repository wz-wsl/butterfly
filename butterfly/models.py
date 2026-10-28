"""Transport-independent results shared by scanners and output formats."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    kind: str
    target: str
    status: str
    value: str = ""
    source: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    kind: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checked: int = 0

    @property
    def status(self) -> str:
        if self.errors:
            return "partial" if self.checked else "failed"
        return "success"

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "status": self.status}
