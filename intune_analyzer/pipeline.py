"""High-level orchestration used by both the CLI and the GUI."""

from __future__ import annotations

import datetime as _dt
import platform
import socket
from pathlib import Path
from typing import Optional

from .analyzer import Analyzer
from .collector import Collector, CollectionResult
from .models import AnalysisResult, SourceSummary


def run_analysis(*, input_path: Optional[str] = None, live: bool = False,
                 client_facing: bool = False, verbose: bool = False,
                 ignore: Optional[set[str]] = None,
                 since_hours: Optional[int] = None,
                 ) -> AnalysisResult:
    """Collect logs and analyse them into an :class:`AnalysisResult`.

    Exactly one of ``input_path`` or ``live`` should be supplied; if neither
    is and we are on macOS, live mode is assumed.

    ``since_hours`` (opt-in) drops dated entries older than the cutoff so the
    report scopes to recent activity. Undated lines (multi-line continuations,
    headers, ``mdatp health`` output) are kept because keyword rules still
    need to see them.
    """
    collector = Collector(verbose=verbose)
    device_info = _device_info()

    if input_path:
        collection = collector.collect_path(input_path)
        src_desc = input_path
    elif live or platform.system() == "Darwin":
        collection = collector.collect_live()
        src_desc = "live macOS paths"
    else:
        raise ValueError(
            "No input given. Use --input PATH on non-macOS hosts, or --live "
            "on the managed Mac."
        )

    window_since: Optional[_dt.datetime] = None
    if since_hours is not None and since_hours > 0:
        window_since = _dt.datetime.now() - _dt.timedelta(hours=since_hours)
        _apply_time_window(collection, window_since)

    analyzer = Analyzer(client_facing=client_facing, ignore=ignore)
    result = analyzer.analyze(
        collection,
        hostname=device_info.get("hostname", ""),
        input_path=src_desc,
        device_info=device_info,
    )
    result.window_since = window_since
    result.window_hours = since_hours if window_since else None
    return result


def _apply_time_window(collection: CollectionResult,
                       cutoff: _dt.datetime) -> None:
    """Drop dated entries older than ``cutoff`` and rebuild per-source summaries.

    Mutates ``collection`` in place. Undated entries (no parsed timestamp)
    are retained — keyword rules still depend on seeing the raw text.
    """
    kept = [e for e in collection.entries
            if e.timestamp is None or e.timestamp >= cutoff]
    dropped = len(collection.entries) - len(kept)
    collection.entries = kept

    # Rebuild summaries from the filtered entries; keep the original file
    # lists (the file was read, even if every line in it is now out of window).
    files_by_source: dict = {s: list(summ.files)
                             for s, summ in collection.summaries.items()}
    collection.summaries = {}
    for e in kept:
        summ = collection.summaries.get(e.source)
        if summ is None:
            summ = SourceSummary(source=e.source,
                                 files=list(files_by_source.get(e.source, [])))
            collection.summaries[e.source] = summ
        summ.lines_parsed += 1
        summ.counts[e.level.value] = summ.counts.get(e.level.value, 0) + 1
        if e.timestamp:
            if summ.first_seen is None or e.timestamp < summ.first_seen:
                summ.first_seen = e.timestamp
            if summ.last_seen is None or e.timestamp > summ.last_seen:
                summ.last_seen = e.timestamp
    # Preserve sources that had files read but zero in-window entries, so
    # the "Sources" section still shows them (with lines_parsed=0).
    for src, files in files_by_source.items():
        if src not in collection.summaries:
            collection.summaries[src] = SourceSummary(source=src,
                                                     files=list(files))
    if dropped:
        collection.notes.append(
            f"Time window applied: dropped {dropped} dated entries older "
            f"than {cutoff.isoformat(timespec='seconds')}.")


def _device_info() -> dict[str, str]:
    info: dict[str, str] = {}
    try:
        info["hostname"] = socket.gethostname()
    except OSError:
        pass
    sysname = platform.system()
    if sysname == "Darwin":
        info["os"] = f"macOS {platform.mac_ver()[0]}".strip()
        info["arch"] = platform.machine()
    else:
        info["os"] = f"{sysname} {platform.release()}"
        info["arch"] = platform.machine()
    return {k: v for k, v in info.items() if v}
