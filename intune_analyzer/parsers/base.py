"""Shared parsing helpers.

Microsoft's macOS log formats are not perfectly stable across product
versions, so rather than hard-coding one rigid grammar per file we use a set
of forgiving heuristics:

* try a handful of common timestamp shapes;
* derive a severity level from an explicit ``| E |`` / ``[ERROR]`` style token
  when present, otherwise fall back to keyword detection;
* never drop a line we cannot fully parse - we still keep the raw text so the
  analyzer's keyword rules get a chance to see it.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Iterable, Iterator, Optional

from ..models import Level, LogEntry, Source

# --------------------------------------------------------------------------- #
# Timestamp parsing
# --------------------------------------------------------------------------- #
# Each entry: (compiled regex that matches at the START of a line, strptime fmt).
# ``%f`` handling: Python wants microseconds; many MS logs use ms with ':' or
# '.' separators, which we normalise before parsing.
_TS_PATTERNS: list[tuple[re.Pattern, str]] = [
    # 2024-06-01 10:23:45.123 / 2024-06-01 10:23:45:123
    (re.compile(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[.:]\d{3})"),
     "%Y-%m-%d %H:%M:%S.%f"),
    # 2024-06-01 10:23:45
    (re.compile(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"),
     "%Y-%m-%d %H:%M:%S"),
    # 06/01/2024 10:23:45 or 06/01/24 10:23:45
    (re.compile(r"^(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})"),
     "%m/%d/%Y %H:%M:%S"),
    (re.compile(r"^(\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"),
     "%m/%d/%y %H:%M:%S"),
    # syslog / install.log:  Jun  1 10:23:45  (no year -> assume current)
    (re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})"),
     "%b %d %H:%M:%S"),
]

_LEVEL_TOKENS = {
    "error": Level.ERROR, "err": Level.ERROR, "fatal": Level.ERROR,
    "critical": Level.ERROR, "crit": Level.ERROR,
    "warning": Level.WARNING, "warn": Level.WARNING,
    "info": Level.INFO, "i": Level.INFO, "notice": Level.INFO,
    "debug": Level.DEBUG, "dbg": Level.DEBUG, "verbose": Level.DEBUG,
    "e": Level.ERROR, "w": Level.WARNING, "d": Level.DEBUG,
}

# Tokens like "| E |", "[ERROR]", " <Warning> "
_LEVEL_RE = re.compile(
    r"[\|\[<\(]\s*(error|err|fatal|critical|crit|warning|warn|info|notice|"
    r"debug|dbg|verbose|[ewid])\s*[\|\]>\)]",
    re.IGNORECASE,
)

_ERROR_KEYWORDS = re.compile(
    r"\b(error|failed|failure|fail|exception|denied|cannot|could ?n.?t|"
    r"unable|timed? ?out|timeout|fatal|crash|aborted|rejected|invalid|"
    r"0x[0-9a-f]{6,8})\b",
    re.IGNORECASE,
)
_WARN_KEYWORDS = re.compile(
    r"\b(warn|warning|retry|retrying|deprecated|skipped|missing|"
    r"not found|degraded)\b",
    re.IGNORECASE,
)


def parse_timestamp(text: str, *,
                    default_year: Optional[int] = None) -> Optional[_dt.datetime]:
    """Best-effort timestamp extraction from the start of ``text``."""
    for pattern, fmt in _TS_PATTERNS:
        m = pattern.match(text)
        if not m:
            continue
        raw = m.group(1).replace("T", " ")
        if "%f" in fmt:
            # normalise ms separator ':'/' ' before fractional part to '.'
            raw = re.sub(r"(\d{2}:\d{2}:\d{2})[:](\d{3})", r"\1.\2", raw)
            # pad ms -> microseconds
            raw = re.sub(r"\.(\d{3})$", lambda mm: "." + mm.group(1) + "000", raw)
        try:
            ts = _dt.datetime.strptime(raw, fmt)
        except ValueError:
            continue
        if ts.year == 1900:  # syslog format with no year
            ts = ts.replace(year=default_year or _dt.date.today().year)
        return ts
    return None


def detect_level(text: str) -> Level:
    """Classify a log line's severity from explicit tokens or keywords."""
    m = _LEVEL_RE.search(text)
    if m:
        return _LEVEL_TOKENS.get(m.group(1).lower(), Level.UNKNOWN)
    if _ERROR_KEYWORDS.search(text):
        return Level.ERROR
    if _WARN_KEYWORDS.search(text):
        return Level.WARNING
    return Level.INFO


def iter_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(line_no, stripped_line)`` for non-empty lines."""
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.rstrip("\n\r")
        if line.strip():
            yield i, line


def parse_generic(text: str, source: Source, file: str = "",
                  component: str = "") -> list[LogEntry]:
    """Parse raw ``text`` into :class:`LogEntry` objects using heuristics.

    Multi-line entries (e.g. stack traces) are attached to the preceding
    timestamped entry's raw text so context is not lost.
    """
    entries: list[LogEntry] = []
    for line_no, line in iter_lines(text):
        ts = parse_timestamp(line)
        if ts is None and entries and not _looks_like_new_entry(line):
            # continuation line - append to previous entry
            prev = entries[-1]
            prev.raw += "\n" + line
            if prev.level != Level.ERROR and _ERROR_KEYWORDS.search(line):
                prev.level = Level.ERROR
            continue
        level = detect_level(line)
        message = _strip_prefix(line, ts)
        entries.append(LogEntry(
            source=source, level=level, message=message, timestamp=ts,
            component=component, file=file, line_no=line_no, raw=line,
        ))
    return entries


def _looks_like_new_entry(line: str) -> bool:
    """Heuristic: does this line start a new record rather than continue one?"""
    return bool(_LEVEL_RE.search(line[:40]))


def _strip_prefix(line: str, ts: Optional[_dt.datetime]) -> str:
    """Trim the leading timestamp and level token for a cleaner message."""
    msg = line
    if ts is not None:
        for pattern, _ in _TS_PATTERNS:
            m = pattern.match(msg)
            if m:
                msg = msg[m.end():]
                break
    # drop a leading "| E | 12345 |" style header up to the last pipe burst
    msg = re.sub(r"^[\s\|]*", "", msg)
    return msg.strip() or line.strip()


def merge_into(entries: list[LogEntry], more: Iterable[LogEntry]) -> None:
    entries.extend(more)
