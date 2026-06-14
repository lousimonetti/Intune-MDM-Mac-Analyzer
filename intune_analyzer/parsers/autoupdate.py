"""Parser for Microsoft AutoUpdate (MAU) logs.

Default location (per Microsoft Learn):
    /Library/Logs/Microsoft/autoupdate.log
"""

from __future__ import annotations

from ..models import Source
from .base import parse_generic

NAME = "autoupdate"
SOURCE = Source.AUTOUPDATE


def matches(filename: str) -> bool:
    base = filename.lower()
    return "autoupdate" in base or "msupdate" in base or "mau" == base.split(".")[0]


def parse(text: str, filename: str = ""):
    return parse_generic(text, SOURCE, file=filename, component="MAU")
