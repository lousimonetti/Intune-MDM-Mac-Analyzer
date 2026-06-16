"""Reference data pulled from the Apple device-management schema.

Source repository:
    https://github.com/apple/device-management

Apple does not accept PRs against that repo (file feedback via Feedback
Assistant); the constants here mirror the schema at a point in time so the
analyzer can validate the shape of DDM declarations and decode the status
codes that appear in macOS / Intune logs. If you bump these values, leave a
pointer to the upstream YAML in the comment so future readers can confirm.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Declarative Device Management — software-update enforcement (specific OS).
#
# Schema:
#   declarative/declarations/configurations/softwareupdate.enforcement.specific.yaml
# ---------------------------------------------------------------------------

# The declaration payload that proves DDM is enforcing a specific OS release.
SOFTWAREUPDATE_ENFORCEMENT_TYPE = (
    "com.apple.configuration.softwareupdate.enforcement.specific"
)

# Keys the schema flags ``presence: required``. A deployed declaration that
# omits either is malformed and the device cannot enforce the update.
SOFTWAREUPDATE_ENFORCEMENT_REQUIRED_KEYS: tuple[str, ...] = (
    "TargetOSVersion",
    "TargetLocalDateTime",
)

# Keys the schema flags ``presence: optional`` — useful for shape inspection
# but not a misconfiguration if missing.
SOFTWAREUPDATE_ENFORCEMENT_OPTIONAL_KEYS: tuple[str, ...] = (
    "TargetBuildVersion",
    "DetailsURL",
)

# ---------------------------------------------------------------------------
# Legacy ``com.apple.SoftwareUpdate`` MDM payload — the pre-DDM way to enforce
# software-update behaviour on macOS via a configuration profile.
#
# system_profiler ``SPConfigurationProfileDataType`` only emits keys that are
# **explicitly set** in the deployed profile. Keys left at their macOS
# default are absent from the output, so "key absent from dump" is treated
# as "policy does not actually enforce this setting" — admins must set
# every value explicitly even when the value matches the macOS default.
#
# The recommended key/value pairs below mirror CIS Apple macOS Benchmark
# §1.1 ("Ensure all Apple-provided software is current"), cross-checked
# against the MiniMacTest_v0.0.19.zsh validator
# (BEGIN_SETTING_DATA — CIS Software Update section). Update both when CIS
# revises the benchmark.
# ---------------------------------------------------------------------------

SOFTWAREUPDATE_LEGACY_PAYLOAD_TYPE = "com.apple.SoftwareUpdate"

SOFTWAREUPDATE_MDM_RECOMMENDED_KEYS: dict[str, str] = {
    "AllowPreReleaseInstallation": "0",
    "AutomaticCheckEnabled": "1",
    "AutomaticDownload": "1",
    "AutomaticallyInstallAppUpdates": "1",
    "AutomaticallyInstallMacOSUpdates": "1",
    "ConfigDataInstall": "1",
    "CriticalUpdateInstall": "1",
}

# ---------------------------------------------------------------------------
# Software-update install state — canonical enum from the schema.
#
# Schema:
#   declarative/status/softwareupdate.install-state.yaml
# ---------------------------------------------------------------------------

# Authoritative install-state values the device may report back. The YAML
# documents ``waiting`` in the prose but lists only the rangelist values
# below; we include both so we can recognise either.
SOFTWAREUPDATE_INSTALL_STATES: dict[str, str] = {
    "none": "No update pending; any previous update succeeded.",
    "waiting": "An update is queued and waiting to start.",
    "downloading": "The device is downloading update data.",
    "prepared": "The update is staged and ready to install.",
    "installing": "The device is installing the update.",
    "failed": "The update failed — see softwareupdate.failure-reason.",
}

# ---------------------------------------------------------------------------
# Software-update failure-reason — the YAML keeps the ``reason`` field as a
# free-form string (no enum), but in practice Apple emits a small set of
# values; pair those with the SUMacController error codes that show up in
# the same log streams so a SWUPDATE-FAIL finding renders something useful
# instead of a bare integer.
#
# Schema:
#   declarative/status/softwareupdate.failure-reason.yaml
# ---------------------------------------------------------------------------

# Keys: lowercase token; values: short human reading. Match by substring.
SOFTWAREUPDATE_REASON_TOKENS: dict[str, str] = {
    # Status item reason values observed in DDM status reports / Intune
    # device-update status:
    "download-failed": "Download failed — re-check Apple CDN reachability.",
    "preparation-failed": "Preparation failed — installer staging error.",
    "staging-failed": "Staging failed — disk space or staging directory issue.",
    "install-failed": "Install failed — installer returned an error.",
    "install-late": "Install was forced after the deadline elapsed.",
    "network-error": "Network error reaching Apple's update servers.",
    "expired": "Update payload expired before it could be applied.",
    "post-restart-cleanup-failed": "Post-restart cleanup failed.",

    # SUMacController error codes from the macOS softwareupdate framework.
    # These appear in MAU and softwareupdated logs as the underlying cause.
    "7301": "ScanNoUpdateFound — the device is up-to-date.",
    "7509": "SUMacControllerErrorAccessLost — benign race between clients.",
    "sumaccontrollererrorscannoupdatefound":
        "ScanNoUpdateFound — the device is up-to-date.",
    "sumaccontrollererroraccesslost":
        "AccessLost — benign race between clients.",
}


def decode_failure_reasons(text: str) -> list[str]:
    """Return distinct human-readable failure-reason strings found in ``text``.

    Used by the analyzer to turn a raw SWUPDATE-FAIL evidence line into a
    short list of decoded reasons the report can chip-render. Matching is
    case-insensitive substring against :data:`SOFTWAREUPDATE_REASON_TOKENS`.
    """
    low = text.lower()
    out: list[str] = []
    seen: set[str] = set()
    for token, human in SOFTWAREUPDATE_REASON_TOKENS.items():
        if token in low and human not in seen:
            seen.add(human)
            out.append(human)
    return out
