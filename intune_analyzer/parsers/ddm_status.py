"""Parser for structured Apple MDM / Declarative Device Management artifacts.

Unlike the other parsers (line-oriented logs), this one reads **structured**
JSON (or plist) exports and turns them into synthetic :class:`LogEntry`
objects, the same technique :mod:`intune_analyzer.collector` already uses for
``system_profiler``/``defaults`` output. Two shapes are recognised:

1. **DDM StatusReport** — the JSON body a device sends back on the
   Declarative Management check-in channel, keyed by dotted status-item name
   nested into JSON objects, e.g.::

       {
         "StatusItems": {
           "management": {"declarations": {"activations": [...],
                                            "configurations": [...]}},
           "app": {"managed": {"list": [{"identifier": "...",
                                          "state": "failed", ...}]}},
           "softwareupdate": {"install-state": "failed",
                               "failure-reason": {"count": 1,
                                                   "reason": "...",
                                                   "timestamp": "..."}}
         }
       }

   Confirmed against real StatusReport payloads shared by MDM server
   implementers (kmfddm/micromdm), since Apple's apple/device-management repo
   documents each status item's *value* shape (``declarative/status/*.yaml``)
   but not the enclosing ``StatusItems`` envelope.

2. **MDM command error envelope** — the standard failure shape for any MDM
   command result, ``{"Status": "Error", "ErrorChain": [{"ErrorDomain": ...,
   "ErrorCode": ..., "LocalizedDescription": ...}]}``. Not part of a YAML
   schema file; cross-checked against Apple Developer Forums threads (see
   ``apple_ddm.MDM_ERROR_CODES``).

A file that parses as JSON/plist but matches neither shape yields no
entries, so the collector treats it as skipped rather than misattributing it.
"""

from __future__ import annotations

import json
import plistlib

from ..models import Level, LogEntry, Source
from .. import apple_ddm

NAME = "ddm_status"
SOURCE = Source.SYSTEM

# Filename hints kept specific so this parser never claims an unrelated JSON
# file dropped in a collected bundle (e.g. Defender's real-time-protection
# statistics JSON, which stays with the Defender parser).
_HINTS = (
    "statusreport", "status-report", "status_report",
    "ddmstatus", "ddm-status", "ddm_status",
    "declarativemanagement", "declarative-management", "declarative_management",
    "commandresponse", "command-response", "command_response",
    "mdmerror", "mdm-error", "mdm_error",
    "errorchain", "error-chain", "error_chain",
    "cmdresponse",
)


def matches(filename: str) -> bool:
    base = filename.lower()
    return any(h in base for h in _HINTS) and base.endswith((".json", ".plist"))


def parse(text: str, filename: str = "") -> list[LogEntry]:
    data = _load(text)
    if not isinstance(data, dict):
        return []

    entries: list[LogEntry] = []
    status_items = data.get("StatusItems")
    if isinstance(status_items, dict):
        entries.extend(_parse_status_items(status_items, filename))

    error_chain = _find_error_chain(data)
    if error_chain:
        entries.extend(_parse_error_chain(error_chain, filename))

    return entries


def _load(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    try:
        return plistlib.loads(text.encode("utf-8", "replace"))
    except Exception:
        return None


def _entry(level: Level, msg: str, filename: str) -> LogEntry:
    return LogEntry(source=SOURCE, level=level, message=msg,
                    component="ddm-status", file=filename, raw=msg)


# --------------------------------------------------------------------------- #
# DDM StatusReport.StatusItems
# --------------------------------------------------------------------------- #
def _parse_status_items(items: dict, filename: str) -> list[LogEntry]:
    entries: list[LogEntry] = []

    declarations = _dig(items, "management", "declarations")
    if isinstance(declarations, dict):
        entries.extend(_parse_declarations(declarations, filename))

    app_list = _dig(items, "app", "managed", "list")
    if isinstance(app_list, list):
        entries.extend(_parse_app_list(app_list, filename))

    swupdate = items.get("softwareupdate")
    if isinstance(swupdate, dict):
        entries.extend(_parse_softwareupdate_status(swupdate, filename))

    return entries


def _dig(d: dict, *keys):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def _parse_declarations(declarations: dict, filename: str) -> list[LogEntry]:
    entries: list[LogEntry] = []
    for act in declarations.get("activations") or []:
        if not isinstance(act, dict):
            continue
        ident = act.get("identifier", "<unknown>")
        active = act.get("active")
        valid = act.get("valid", "unknown")
        if active is False or (isinstance(valid, str) and valid != "valid"):
            entries.append(_entry(
                Level.ERROR,
                f"DDM declaration {ident} is inactive/invalid "
                f"(active={active}, valid={valid}) — "
                f"ddm-status: declaration-inactive identifier={ident}",
                filename))
        else:
            entries.append(_entry(
                Level.INFO,
                f"DDM declaration {ident} active={active} valid={valid}",
                filename))

    for cfg in declarations.get("configurations") or []:
        if not isinstance(cfg, dict):
            continue
        ident = cfg.get("identifier", "<unknown>")
        reasons = cfg.get("reasons") or []
        if reasons:
            details = "; ".join(_reason_text(r) for r in reasons)
            entries.append(_entry(
                Level.ERROR,
                f"DDM configuration {ident} failed to apply: {details} — "
                f"ddm-status: declaration-error identifier={ident} "
                f"reasons={len(reasons)}",
                filename))
        else:
            entries.append(_entry(
                Level.INFO, f"DDM configuration {ident} applied cleanly",
                filename))
    return entries


def _reason_text(reason) -> str:
    if isinstance(reason, dict):
        for key in ("description", "details", "reason", "message"):
            if reason.get(key):
                return str(reason[key])
        return ", ".join(f"{k}={v}" for k, v in reason.items())
    return str(reason)


def _parse_app_list(app_list: list, filename: str) -> list[LogEntry]:
    entries: list[LogEntry] = []
    for app in app_list:
        if not isinstance(app, dict):
            continue
        ident = app.get("identifier", app.get("name", "<unknown>"))
        state = app.get("state", "unknown")
        version = app.get("version", "")
        config_state = _dig(app, "config-state", "app-config-state", "state")
        level = Level.ERROR if state in (
            "failed", "prompting-for-login", "prompting-for-management",
            "managed-but-uninstalled",
        ) else Level.INFO
        entries.append(_entry(
            level,
            f"DDM app {ident} version={version} reports state={state} "
            f"config-state={config_state}",
            filename))
    return entries


def _parse_softwareupdate_status(swupdate: dict, filename: str) -> list[LogEntry]:
    entries: list[LogEntry] = []
    install_state = swupdate.get("install-state")
    if install_state:
        human = apple_ddm.SOFTWAREUPDATE_INSTALL_STATES.get(
            install_state, "")
        level = Level.ERROR if install_state == "failed" else Level.INFO
        entries.append(_entry(
            level,
            f"DDM softwareupdate status: install-state={install_state}"
            + (f" ({human})" if human else ""),
            filename))

    failure = swupdate.get("failure-reason")
    if isinstance(failure, dict) and (failure.get("count") or 0) > 0:
        reason = str(failure.get("reason", ""))
        decoded = apple_ddm.decode_failure_reasons(reason)
        decoded_txt = f" [{'; '.join(decoded)}]" if decoded else ""
        entries.append(_entry(
            Level.ERROR,
            f"DDM softwareupdate failure-reason: count={failure.get('count')} "
            f"reason={reason}{decoded_txt} "
            f"timestamp={failure.get('timestamp', '')}",
            filename))
    return entries


# --------------------------------------------------------------------------- #
# MDM command error envelope
# --------------------------------------------------------------------------- #
def _find_error_chain(data):
    """DFS for the first ``ErrorChain`` list, or a lone error dict."""
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if isinstance(node.get("ErrorChain"), list):
                return node["ErrorChain"]
            if "ErrorCode" in node and "ErrorDomain" in node:
                return [node]
            stack.extend(node.values())
        elif isinstance(node, (list, tuple)):
            stack.extend(node)
    return None


def _parse_error_chain(chain: list, filename: str) -> list[LogEntry]:
    entries: list[LogEntry] = []
    for err in chain:
        if not isinstance(err, dict):
            continue
        domain = err.get("ErrorDomain", "<unknown>")
        code = err.get("ErrorCode", "")
        desc = (err.get("LocalizedDescription")
                or err.get("USEnglishDescription") or "")
        decoded = apple_ddm.decode_mdm_error(domain, code)
        text = decoded or desc or "(no description supplied)"
        entries.append(_entry(
            Level.ERROR,
            f"MDM command error: ErrorDomain={domain} ErrorCode={code} "
            f"{text} — mdm-error: domain={domain} code={code}",
            filename))
    return entries
