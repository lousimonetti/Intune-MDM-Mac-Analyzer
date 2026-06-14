"""Parser for Microsoft Office application logs.

Default location:
    ~/Library/Containers/com.microsoft.<app>/Data/Library/Logs/
plus various ``Diagnostics`` folders written by the Office apps.
"""

from __future__ import annotations

from ..models import Source
from .base import parse_generic

NAME = "office"
SOURCE = Source.OFFICE

_APPS = ("word", "excel", "powerpoint", "outlook", "onenote", "teams")


def matches(filename: str) -> bool:
    base = filename.lower()
    if "com.microsoft." in base and base.endswith((".log", ".txt")):
        return True
    if any(app in base for app in _APPS) and base.endswith((".log", ".txt")):
        return True
    return False


def parse(text: str, filename: str = ""):
    component = ""
    low = filename.lower()
    for app in _APPS:
        if app in low:
            component = app.capitalize()
            break
    return parse_generic(text, SOURCE, file=filename, component=component)
