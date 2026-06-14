"""Parser for macOS system / MDM logs.

Covers ``system.log`` and unified-log exports captured via, e.g.::

    log show --predicate 'subsystem == "com.apple.ManagedClient"' --last 1d

as well as generic profile / MDM enrollment traces.
"""

from __future__ import annotations

from ..models import Source
from .base import parse_generic

NAME = "system"
SOURCE = Source.SYSTEM

_HINTS = ("managedclient", "mdmclient", "profiles", "system.log",
          "devicemanagement", "syslog")


def matches(filename: str) -> bool:
    base = filename.lower()
    return any(h in base for h in _HINTS) and base.endswith((".log", ".txt"))


def parse(text: str, filename: str = ""):
    return parse_generic(text, SOURCE, file=filename, component="macOS")
