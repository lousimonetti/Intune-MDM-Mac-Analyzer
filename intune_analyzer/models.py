"""Core data models shared across collectors, parsers, the analyzer and reports.

Everything here is plain ``dataclass`` based so the whole pipeline can be
serialised to JSON (for the ``--format json`` output and for the test-suite)
without any third-party dependency.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Severity of a :class:`Finding`. Ordered low -> high for sorting."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                 Severity.HIGH, Severity.CRITICAL]
        return order.index(self)


class Level(str, Enum):
    """Normalised log line severity."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    UNKNOWN = "unknown"


class Source(str, Enum):
    """The Microsoft/macOS subsystem a log line came from."""

    INTUNE = "Intune MDM Agent"
    INSTALL = "macOS App Install"
    DEFENDER = "Microsoft Defender"
    AUTOUPDATE = "Microsoft AutoUpdate"
    OFFICE = "Microsoft Office"
    SYSTEM = "macOS System / MDM"


@dataclass
class LogEntry:
    """A single normalised log line."""

    source: Source
    level: Level
    message: str
    timestamp: Optional[_dt.datetime] = None
    component: str = ""
    file: str = ""
    line_no: int = 0
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        d["level"] = self.level.value
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d


@dataclass
class Finding:
    """An actionable observation produced by the analyzer."""

    id: str
    severity: Severity
    source: Source
    title: str
    description: str
    recommendation: str
    category: str = "General"
    count: int = 1
    evidence: list[str] = field(default_factory=list)
    docs_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["source"] = self.source.value
        return d


@dataclass
class SourceSummary:
    """Per-source roll-up of what was parsed."""

    source: Source
    files: list[str] = field(default_factory=list)
    lines_parsed: int = 0
    counts: dict[str, int] = field(default_factory=dict)  # Level.value -> n
    first_seen: Optional[_dt.datetime] = None
    last_seen: Optional[_dt.datetime] = None

    @property
    def errors(self) -> int:
        return self.counts.get(Level.ERROR.value, 0)

    @property
    def warnings(self) -> int:
        return self.counts.get(Level.WARNING.value, 0)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        d["first_seen"] = self.first_seen.isoformat() if self.first_seen else None
        d["last_seen"] = self.last_seen.isoformat() if self.last_seen else None
        return d


@dataclass
class AnalysisResult:
    """The full result of an analysis run; the report's only input."""

    generated_at: _dt.datetime = field(default_factory=_dt.datetime.now)
    hostname: str = ""
    device_info: dict[str, str] = field(default_factory=dict)
    input_path: str = ""
    summaries: list[SourceSummary] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    entries: list[LogEntry] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    # Derived metrics
    # ------------------------------------------------------------------ #
    @property
    def total_files(self) -> int:
        return sum(len(s.files) for s in self.summaries)

    @property
    def total_lines(self) -> int:
        return sum(s.lines_parsed for s in self.summaries)

    @property
    def total_errors(self) -> int:
        return sum(s.errors for s in self.summaries)

    @property
    def total_warnings(self) -> int:
        return sum(s.warnings for s in self.summaries)

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        out: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            out[f.severity].append(f)
        return out

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def health_score(self) -> int:
        """A 0-100 health score. 100 == clean, penalised by findings.

        Weighting roughly mirrors operational impact; the score is clamped
        to the 0-100 range so the report can render it as a gauge.
        """
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 12,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        penalty = sum(weights[f.severity] for f in self.findings)
        return max(0, min(100, 100 - penalty))

    def health_grade(self) -> str:
        score = self.health_score()
        if score >= 90:
            return "Healthy"
        if score >= 75:
            return "Good"
        if score >= 50:
            return "Needs Attention"
        if score >= 25:
            return "At Risk"
        return "Critical"

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "hostname": self.hostname,
            "device_info": self.device_info,
            "input_path": self.input_path,
            "health_score": self.health_score(),
            "health_grade": self.health_grade(),
            "totals": {
                "files": self.total_files,
                "lines": self.total_lines,
                "errors": self.total_errors,
                "warnings": self.total_warnings,
            },
            "severity_counts": self.severity_counts(),
            "summaries": [s.to_dict() for s in self.summaries],
            "findings": [f.to_dict() for f in self.findings],
        }
