"""Parser for Microsoft Defender for Endpoint (mdatp) logs.

Default locations (per Microsoft Learn):
    /Library/Logs/Microsoft/mdatp/install.log   (installation log)
    /Library/Logs/Microsoft/mdatp/*.log
    /Library/Application Support/Microsoft/Defender/...
"""

from __future__ import annotations

from ..models import Source
from .base import parse_generic

NAME = "defender"
SOURCE = Source.DEFENDER


def matches(filename: str) -> bool:
    base = filename.lower()
    return (
        "mdatp" in base
        or "wdav" in base
        or "defender" in base
    ) and base.endswith((".log", ".txt", ".json"))


def parse(text: str, filename: str = ""):
    component = "mdatp"
    if "install" in filename.lower():
        component = "mdatp-install"
    return parse_generic(text, SOURCE, file=filename, component=component)
