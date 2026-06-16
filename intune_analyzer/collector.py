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
import re
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
    # Platform SSO / Microsoft Enterprise SSO extension log (Company Portal).
    "~/Library/Containers/com.microsoft.CompanyPortalMac.ssoextension/Data/"
    "Library/Caches/Logs/Microsoft/SSOExtension",
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

        # app-sso platform -s (Platform SSO registration state) - turned into
        # synthetic PSSO entries so the keyword rules can act on a device that
        # is not registered or whose registration is broken.
        out = _run(["app-sso", "platform", "-s"])
        if out:
            for line in out.splitlines():
                low = line.lower()
                lvl = Level.INFO
                if any(k in low for k in ("error", "fail", "not registered",
                                          "false")):
                    lvl = Level.ERROR
                self.result.entries.append(LogEntry(
                    source=Source.PSSO, level=lvl,
                    message=line.strip(), component="app-sso platform",
                    file="<app-sso platform -s>", raw=line,
                ))
            self.result.notes.append("Captured `app-sso platform -s` output.")

        # system_profiler SPConfigurationProfileDataType — proves which MDM
        # profiles and DDM declarations are *actually installed* on the
        # device, independent of whatever the logs happen to show. We don't
        # ingest the whole dump (several MB); only the lines that prove a
        # Declarative Device Management software-update enforcement
        # declaration is in place, so the CIS-1.1 evaluator can mark the
        # control PASS on positive policy evidence rather than waiting for a
        # runtime scan signal.
        out = _run(["system_profiler", "SPConfigurationProfileDataType",
                    "-detailLevel", "mini"])
        if out:
            self._ingest_ddm_softwareupdate_evidence(
                out, file="<system_profiler SPConfigurationProfileDataType>")

        # `profiles status -type enrollment` — concise MDM enrollment state.
        out = _run(["profiles", "status", "-type", "enrollment"])
        if out:
            for line in out.splitlines():
                if not line.strip():
                    continue
                low = line.lower()
                lvl = Level.INFO
                if "not enrolled" in low or "no enrollment" in low:
                    lvl = Level.ERROR
                self.result.entries.append(LogEntry(
                    source=Source.SYSTEM, level=lvl,
                    message=line.strip(), component="profiles status",
                    file="<profiles status -type enrollment>", raw=line,
                ))
            self.result.notes.append(
                "Captured `profiles status -type enrollment` output.")

    def _ingest_ddm_softwareupdate_evidence(self, dump: str, *, file: str) -> None:
        """Scan a ``system_profiler SPConfigurationProfileDataType`` dump and
        emit one ``Source.SYSTEM`` evidence entry per relevant payload.

        Two classes of evidence:

        1. A **ground-truth marker** that proves the dump itself was
           collected. The CIS evaluator uses this to tell "policy data was
           inspected and nothing was enforced" (=> FAIL) apart from "policy
           data was never collected" (=> not-assessed).
        2. Per-payload lines for the policies CIS-1.1 / CIS-1.2 care about:
           the DDM software-update declarations
           (``com.apple.configuration.softwareupdate.enforcement.specific`` /
           ``…settings``), the legacy ``com.apple.SoftwareUpdate`` MDM
           profile, and ``com.microsoft.autoupdate2`` for MAU.

        We do not ingest the whole dump (multi-MB on a real device); only
        the marker line and any matching payload lines.
        """
        # 1. Always emit the ground-truth marker so the evaluator knows
        #    SPConfigurationProfileDataType *was* inspected, even if no
        #    matching payload is found.
        self.result.entries.append(LogEntry(
            source=Source.SYSTEM, level=Level.INFO,
            message="system_profiler SPConfigurationProfileDataType collected",
            component="system_profiler", file=file,
            raw="system_profiler:SPConfigurationProfileDataType:collected",
        ))

        # 2. Per-payload evidence lines.
        from . import apple_ddm
        markers = (
            apple_ddm.SOFTWAREUPDATE_ENFORCEMENT_TYPE,
            "com.apple.configuration.softwareupdate.settings",
            "softwareupdate.enforcement.specific",
            "com.apple.softwareupdate",  # legacy MDM software-update payload
            "com.microsoft.autoupdate2",
        )
        lines = dump.splitlines()
        seen_payloads: list[str] = []
        # Track every line index that matched the DDM enforcement type so
        # we can scan a window around it for the required schema keys
        # (TargetOSVersion / TargetLocalDateTime per Apple's
        # ``softwareupdate.enforcement.specific.yaml``).
        enforcement_payload_indices: list[int] = []
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue
            low = stripped.lower()
            for m in markers:
                if m in low:
                    self.result.entries.append(LogEntry(
                        source=Source.SYSTEM, level=Level.INFO,
                        message=stripped, component="system_profiler",
                        file=file, raw=stripped,
                    ))
                    seen_payloads.append(m)
                    if m == apple_ddm.SOFTWAREUPDATE_ENFORCEMENT_TYPE:
                        enforcement_payload_indices.append(idx)
                    break

        # 2b. Shape-validate every enforcement.specific payload against the
        # schema's required keys. ``system_profiler`` output groups payload
        # keys in an indented block, so a ±25-line window around the
        # PayloadType line is enough to catch the surrounding keys without
        # bleeding into the next profile.
        for idx in enforcement_payload_indices:
            window = "\n".join(lines[max(0, idx - 25):idx + 25])
            missing = [
                k for k in apple_ddm.SOFTWAREUPDATE_ENFORCEMENT_REQUIRED_KEYS
                if k not in window
            ]
            for k in missing:
                self.result.entries.append(LogEntry(
                    source=Source.SYSTEM, level=Level.ERROR,
                    message=(
                        "DDM softwareupdate enforcement declaration is "
                        f"missing required key {k!r} per Apple schema "
                        "softwareupdate.enforcement.specific.yaml"),
                    component="system_profiler",
                    file=file,
                    raw=f"ddm-validation: missing-key {k}",
                ))

        # 2c. CIS-1.1 key-by-key validation of the legacy
        # ``com.apple.SoftwareUpdate`` MDM payload. system_profiler omits
        # any key left at its macOS default, so "key=value absent from the
        # dump" is the failure signal — the policy is provably not enforcing
        # that setting. Logic mirrors MiniMacTest_v0.0.19.zsh which greps
        # the same dump for each expected key=value pair.
        legacy_present = any(
            "com.apple.softwareupdate" in m and ".configuration." not in m
            for m in seen_payloads
        )
        if legacy_present:
            dump_lower = dump.lower()
            for key, value in (
                apple_ddm.SOFTWAREUPDATE_MDM_RECOMMENDED_KEYS.items()
            ):
                # Tolerate the variations system_profiler uses:
                #   ``AutomaticDownload = 1``
                #   ``AutomaticDownload=1``
                #   ``AutomaticDownload: 1``
                token = re.compile(
                    rf"\b{re.escape(key)}\s*[=:]\s*{re.escape(value)}\b",
                    re.IGNORECASE,
                )
                if not token.search(dump_lower):
                    self.result.entries.append(LogEntry(
                        source=Source.SYSTEM, level=Level.ERROR,
                        message=(
                            "Legacy com.apple.SoftwareUpdate payload is "
                            f"missing CIS-recommended key {key} = {value} "
                            "(system_profiler omits keys at macOS default; "
                            "set the value explicitly in the profile)"),
                        component="system_profiler",
                        file=file,
                        raw=f"mdm-validation: missing-key {key}={value}",
                    ))

        if seen_payloads:
            unique = sorted(set(seen_payloads))
            self.result.notes.append(
                "Detected configuration-profile payloads in "
                "`system_profiler SPConfigurationProfileDataType`: "
                + ", ".join(unique) + ".")
        else:
            self.result.notes.append(
                "`system_profiler SPConfigurationProfileDataType` was "
                "inspected but no software-update or autoupdate2 payload "
                "was found — policy is provably not enforced.")


def _run(cmd: list[str]) -> Optional[str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            return proc.stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return None
