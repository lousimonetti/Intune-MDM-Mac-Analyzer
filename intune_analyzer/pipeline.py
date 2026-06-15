"""High-level orchestration used by both the CLI and the GUI."""

from __future__ import annotations

import platform
import socket
from pathlib import Path
from typing import Optional

from .analyzer import Analyzer
from .collector import Collector
from .models import AnalysisResult


def run_analysis(*, input_path: Optional[str] = None, live: bool = False,
                 client_facing: bool = False, verbose: bool = False,
                 ignore: Optional[set[str]] = None,
                 ) -> AnalysisResult:
    """Collect logs and analyse them into an :class:`AnalysisResult`.

    Exactly one of ``input_path`` or ``live`` should be supplied; if neither
    is and we are on macOS, live mode is assumed.
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

    analyzer = Analyzer(client_facing=client_facing, ignore=ignore)
    return analyzer.analyze(
        collection,
        hostname=device_info.get("hostname", ""),
        input_path=src_desc,
        device_info=device_info,
    )


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
