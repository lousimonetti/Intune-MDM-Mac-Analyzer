"""Parser registry and dispatch.

Each parser module exposes ``NAME``, ``SOURCE``, ``matches(filename)`` and
``parse(text, filename)``. ``select`` returns the most specific parser for a
given filename; ordering matters because, e.g., the Defender installation log
is also named ``install.log``.
"""

from __future__ import annotations

from pathlib import Path

from . import autoupdate, defender, install, intune, office, system

# Most specific first; ``install`` is the catch-all for *install.log.
REGISTRY = [intune, defender, autoupdate, office, system, install]

__all__ = ["REGISTRY", "select", "parse_file"]


def _match_hint(filename: str) -> str:
    """The string matchers see: the filename plus its immediate parent dir.

    We deliberately exclude the full path so an unrelated ancestor directory
    (e.g. a repo named ``Intune-MDM-Mac-Analyzer``) cannot masquerade as a
    log source, while still keeping the meaningful subfolder (``mdatp``,
    ``Intune``, ``autoupdate``, ...) that disambiguates same-named files.
    """
    p = Path(filename)
    return f"{p.parent.name}/{p.name}"


def select(filename: str):
    """Return the parser module that best matches ``filename`` or ``None``."""
    hint = _match_hint(filename)
    for mod in REGISTRY:
        try:
            if mod.matches(hint):
                return mod
        except Exception:  # a misbehaving matcher must never abort discovery
            continue
    return None


def parse_file(text: str, filename: str):
    """Parse ``text`` with the parser selected for ``filename``.

    Returns ``(source, entries)`` or ``(None, [])`` if no parser matched.
    """
    mod = select(filename)
    if mod is None:
        return None, []
    return mod.SOURCE, mod.parse(text, filename)
