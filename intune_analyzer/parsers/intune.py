"""Parser for the Intune MDM management agent logs.

Default locations (per Microsoft Learn):
    /Library/Logs/Microsoft/Intune/
    ~/Library/Logs/Microsoft/Intune/
File names: ``IntuneMDMDaemon <date>--<time>.log`` and
``IntuneMDMAgent <date>--<time>.log``.
"""

from __future__ import annotations

import re

from ..models import Source
from .base import parse_generic

NAME = "intune"
SOURCE = Source.INTUNE

_FILE_RE = re.compile(r"intunemdm(daemon|agent)", re.IGNORECASE)


def matches(filename: str) -> bool:
    base = filename.lower()
    return bool(_FILE_RE.search(base)) or (
        "intune" in base and base.endswith((".log", ".txt"))
    )


def parse(text: str, filename: str = ""):
    component = ""
    low = filename.lower()
    if "daemon" in low:
        component = "IntuneMDMDaemon"
    elif "agent" in low:
        component = "IntuneMDMAgent"
    return parse_generic(text, SOURCE, file=filename, component=component)
