"""Parser for macOS Platform SSO (PSSO) / Microsoft Enterprise SSO plug-in logs.

Platform SSO is delivered by the **Microsoft Enterprise SSO Extension** that
ships inside the Intune **Company Portal** app
(``com.microsoft.CompanyPortalMac.ssoextension``) and is configured by an Intune
Extensible-SSO (settings-catalog) profile. The two log surfaces we care about:

* **SSO extension log** — written by the Company Portal broker. Saved via
  *Company Portal > Help > Save diagnostic report* (``SSOExtension.log`` inside
  ``CompanyPortal.zip``) or tailed live at::

      ~/Library/Containers/com.microsoft.CompanyPortalMac.ssoextension/Data/Library/Caches/Logs/Microsoft/SSOExtension/*

* **Apple AppSSO / PlatformSSO unified-log exports** — the OS side of the flow
  (``AppSSOAgent``/``AppSSODaemon``, daemon ``swcd`` for associated-domain
  validation), captured via sysdiagnose or::

      log show --predicate 'subsystem == "com.apple.AppSSO"'
      app-sso platform -s        # current PSSO registration state

References (Microsoft Learn):
    entra/identity/devices/troubleshoot-mac-sso-extension-plugin
    entra/identity/devices/troubleshoot-macos-platform-single-sign-on-extension
    intune/device-configuration/settings-catalog/configure-platform-sso-macos
"""

from __future__ import annotations

from ..models import Source
from .base import parse_generic

NAME = "psso"
SOURCE = Source.PSSO

# Tokens (matched against "<parent_dir>/<filename>") that identify a PSSO log.
# Kept specific so we never claim an unrelated Office/container log.
_HINTS = (
    "ssoextension",
    "sso_extension",
    "sso-extension",
    "appsso",
    "app-sso",
    "platformsso",
    "platform-sso",
    "platform_sso",
    "psso",
)


def matches(filename: str) -> bool:
    base = filename.lower()
    return any(h in base for h in _HINTS) and base.endswith((".log", ".txt", ".json"))


def parse(text: str, filename: str = ""):
    low = filename.lower()
    component = "SSOExtension"
    if "appsso" in low or "app-sso" in low or "platformsso" in low \
            or "platform-sso" in low or "platform_sso" in low or "psso" in low:
        component = "AppSSO"
    return parse_generic(text, SOURCE, file=filename, component=component)
