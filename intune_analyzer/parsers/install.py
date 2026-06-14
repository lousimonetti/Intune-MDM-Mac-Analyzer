"""Parser for the macOS package installer log (``/var/log/install.log``).

This captures app/package deployment activity (including Intune-pushed
``.pkg`` apps and Company Portal installs).
"""

from __future__ import annotations

from ..models import Source
from .base import parse_generic

NAME = "install"
SOURCE = Source.INSTALL


def matches(filename: str) -> bool:
    base = filename.lower()
    return base.endswith("install.log") or base == "install.log" or \
        "install" in base and base.endswith((".log", ".txt")) and "mdatp" not in base


def parse(text: str, filename: str = ""):
    return parse_generic(text, SOURCE, file=filename, component="installd")
