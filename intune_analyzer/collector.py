"""Log discovery and ingestion.

Two modes:

* **offline** - point at a directory or ``.zip`` of collected logs (e.g. an
  Intune "Collect logs" bundle, or an ``mdatp diagnostic create`` archive).
  This works on any platform, which is the common case for a support analyst.
* **live** - when run on the managed Mac itself, read the well-known macOS
  paths directly and optionally shell out to ``mdatp``/``log show`` for extra
  context.

The collector is responsible only for turning files into :class:`LogEntry`
objects and :class:`SourceSummary` roll-ups; all judgement lives in the
analyzer.
"""

from __future__ import annotations

import os
import platform
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models import Level, LogEntry, Source, SourceSummary
from .parsers import parse_file

# Well-known macOS locations, expanded for the current user in live mode.
LIVE_PATHS = [
    "/Library/Logs/Microsoft/Intune",
    "~/Library/Logs/Microsoft/Intune",
    "/var/log/install.log",
    "/Library/Logs/Microsoft/mdatp",
    "/Library/Application Support/Microsoft/Defender",
    "/Library/Logs/Microsoft/autoupdate.log",
    "~/Library/Containers",  # Office app containers (filtered by parser)
    "/var/log/system.log",
]

# Extensions we will attempt to read as text logs.
TEXT_SUFFIXES = {".log", ".txt", ".json", ".xml", ".rtf"}

# Skip obviously-binary or huge irrelevant files.
MAX_FILE_BYTES = 64 * 1024 * 1024  # 64 MB safety cap per file


@dataclass
class CollectionResult:
    entries: list[LogEntry] = field(default_factory=list)
    summaries: dict[Source, SourceSummary] = field(default_factory=dict)
    files_read: list[str] = field(default_factory=list)
    files_skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary_list(self) -> list[SourceSummary]:
        return list(self.summaries.values())


class Collector:
    def __init__(self, *, verbose: bool = False):
        self.verbose = verbose
        self.result = CollectionResult()

    # ------------------------------------------------------------------ #
    # Public entry points
    # ------------------------------------------------------------------ #
    def collect_path(self, path: str) -> CollectionResult:
        """Collect from a directory, single file or ``.zip`` archive."""
        p = Path(path).expanduser()
        if not p.exists():
            self.result.notes.append(f"Input path does not exist: {p}")
            return self.result
        if p.is_file() and p.suffix.lower() == ".zip":
            self._collect_zip(p)
        elif p.is_file():
            self._read_file(p)
        else:
            self._collect_dir(p)
        return self.result

    def collect_live(self) -> CollectionResult:
        """Collect from well-known macOS paths on the local machine."""
        if platform.system() != "Darwin":
            self.result.notes.append(
                "Live collection requested on a non-macOS host; only paths "
                "that happen to exist will be read."
            )
        for raw in LIVE_PATHS:
            p = Path(os.path.expanduser(raw))
            if not p.exists():
                continue
            if p.is_dir():
                self._collect_dir(p)
            else:
                self._read_file(p)
        self._collect_live_commands()
        return self.result

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _collect_zip(self, zip_path: Path) -> None:
        try:
            with tempfile.TemporaryDirectory(prefix="intune-analyzer-") as tmp:
                with zipfile.ZipFile(zip_path) as zf:
                    zf.extractall(tmp)
                self._collect_dir(Path(tmp))
            self.result.notes.append(f"Extracted and analysed archive: {zip_path.name}")
        except zipfile.BadZipFile:
            self.result.notes.append(f"Not a valid zip archive: {zip_path}")

    def _collect_dir(self, root: Path) -> None:
        for dirpath, _dirs, files in os.walk(root):
            for name in sorted(files):
                fp = Path(dirpath) / name
                if fp.suffix.lower() in TEXT_SUFFIXES or "log" in name.lower():
                    self._read_file(fp)

    def _read_file(self, fp: Path) -> None:
        try:
            size = fp.stat().st_size
        except OSError:
            return
        if size == 0 or size > MAX_FILE_BYTES:
            self.result.files_skipped.append(str(fp))
            return
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            self.result.files_skipped.append(str(fp))
            return
        # Pass the full path so parsers can use directory context (e.g. an
        # ``mdatp/install.log`` is Defender, not a generic macOS install log).
        source, entries = parse_file(text, str(fp))
        if source is None or not entries:
            self.result.files_skipped.append(str(fp))
            return
        self._ingest(source, str(fp), entries)
        if self.verbose:
            print(f"  read {fp} ({len(entries)} entries, {source.value})")

    def _ingest(self, source: Source, file: str, entries: list[LogEntry]) -> None:
        self.result.entries.extend(entries)
        self.result.files_read.append(file)
        summ = self.result.summaries.get(source)
        if summ is None:
            summ = SourceSummary(source=source)
            self.result.summaries[source] = summ
        if file not in summ.files:
            summ.files.append(file)
        summ.lines_parsed += len(entries)
        for e in entries:
            summ.counts[e.level.value] = summ.counts.get(e.level.value, 0) + 1
            if e.timestamp:
                if summ.first_seen is None or e.timestamp < summ.first_seen:
                    summ.first_seen = e.timestamp
                if summ.last_seen is None or e.timestamp > summ.last_seen:
                    summ.last_seen = e.timestamp

    def _collect_live_commands(self) -> None:
        """On a live Mac, capture a little extra structured context."""
        if platform.system() != "Darwin":
            return
        # mdatp health (Defender) - turned into synthetic log entries so the
        # analyzer's keyword rules can act on an unhealthy agent.
        out = _run(["mdatp", "health"])
        if out:
            for line in out.splitlines():
                lvl = Level.INFO
                low = line.lower()
                if "false" in low and ("healthy" in low or "licensed" in low):
                    lvl = Level.ERROR
                self.result.entries.append(LogEntry(
                    source=Source.DEFENDER, level=lvl,
                    message=line.strip(), component="mdatp health",
                    file="<mdatp health>", raw=line,
                ))
            self.result.notes.append("Captured `mdatp health` output.")


def _run(cmd: list[str]) -> Optional[str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            return proc.stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return None
