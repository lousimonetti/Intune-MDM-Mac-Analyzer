"""CIS Apple macOS Benchmark — Level 1 validation.

This module performs a **log-evidence-based** validation of a device against a
curated subset of **CIS Level 1** controls (the essential, low-impact hardening
baseline: software updates, FileVault, Gatekeeper, the application firewall,
password policy, screen lock, endpoint malware protection and MDM enforcement).

It is deliberately *not* a substitute for a full on-device CIS scan: we can only
judge controls for which the collected Intune / macOS / Defender / Platform SSO
logs carry a signal. Each control is resolved to one of four states:

* ``pass``         — positive evidence in the logs;
* ``configured``   — governing source is present and reports no contrary
                     signal (the control is in place but we have no positive
                     test). Counts toward the pass total but is surfaced
                     separately so reviewers can see where the verdict is
                     inferred rather than observed;
* ``fail``         — contrary evidence (a mapped finding fired or a failure
                     pattern matched in a relevant log);
* ``not-assessed`` — no evidence either way in the collected logs.

The **validation score (KPI)** is the passing share of *assessable* controls
(``(pass + configured) / (pass + configured + fail)``); ``not-assessed``
controls do not dilute it. Per the reporting requirement the KPI is banded
**green ≥ 95 %, yellow 75–95 %, red otherwise** (see
:class:`intune_analyzer.models.CISReport`).

False-positive guarding
-----------------------

Earlier versions matched fail patterns against **any** log line, which produced
loud false positives: an Office telemetry event containing the substring
``autologin`` would fail CIS-2.11, Defender kernel-queue warnings would fail
CIS-2.5.2 / CIS-3.1, and so on. Each :class:`CISCheck` now declares:

* ``fail_sources`` — only entries from these sources can supply a fail signal;
* ``match_word`` — when True, the fail/pass regex is wrapped with ``\\b`` word
  boundaries so a literal ``on`` does not match ``c[on]fig``;
* ``transient_findings`` — finding IDs whose ``transient`` flag we honour by
  treating the failure as a degraded ``configured`` verdict (the control is
  in place; a retry-recoverable error was logged).

Control numbering tracks the CIS Apple macOS Benchmark (Level 1); exact numbers
shift between macOS/benchmark versions, so they are indicative.
Reference: <https://www.cisecurity.org/benchmark/apple_os>
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .models import CISCheckResult, CISReport, Finding, LogEntry, Source

CIS_DOCS = "https://www.cisecurity.org/benchmark/apple_os"
MS_BASELINE = ("https://learn.microsoft.com/intune/solutions/end-to-end-guides/"
               "macos-endpoints-get-started")

# Maximum evidence snippets kept per control.
_MAX_EVIDENCE = 3


@dataclass(frozen=True)
class CISCheck:
    """Declarative spec for one CIS Level 1 control and how to judge it.

    Resolution order: a ``fail`` signal wins (and may be demoted to
    ``configured`` if every contributing finding is transient), then positive
    ``pass`` evidence, then ``pass_if_source`` (governing source present),
    otherwise ``not-assessed``.
    """

    id: str
    title: str
    section: str
    rationale: str
    remediation: str
    fail_findings: tuple[str, ...] = ()
    fail_pattern: Optional[str] = None
    pass_pattern: Optional[str] = None
    pass_if_source: Optional[Source] = None
    # When the ground-truth source (e.g. ``system_profiler``) WAS collected
    # but the pass_pattern did not match, the control flips to ``fail``
    # rather than ``not-assessed`` — we proved the policy isn't deployed.
    # The regex matches a synthetic marker entry the collector emits when
    # the relevant ground-truth dump ran successfully.
    ground_truth_marker: Optional[str] = None
    # Only entries with a source in this set are considered for the fail
    # pattern. Empty set == any source. When ``pass_if_source`` is also set we
    # default ``fail_sources`` to that single source so the control is only
    # judged from logs that should know about it.
    fail_sources: frozenset[Source] = field(default_factory=frozenset)
    # When True, wrap fail/pass regexes with ``\b`` word boundaries.
    match_word: bool = True
    docs_url: str = CIS_DOCS
    remediation_steps: tuple[str, ...] = field(default_factory=tuple)
    false_positive_note: str = ""
    flags: int = re.IGNORECASE


CIS_LEVEL1: list[CISCheck] = [
    # --- 1 Software Updates ------------------------------------------------ #
    CISCheck(
        id="CIS-1.1",
        title="macOS software update policy is enforced (DDM / MDM)",
        section="1 Software Updates",
        rationale="CIS Level 1 requires software updates to be applied. The "
                  "auditable signal for that is policy enforcement: a DDM "
                  "software-update declaration or a legacy "
                  "`com.apple.SoftwareUpdate` MDM payload must be installed "
                  "on the device. Log-level 'is the latest patch on?' "
                  "evidence is not authoritative — the configuration profile "
                  "is.",
        remediation="Deploy a DDM software-update enforcement declaration "
                    "(`com.apple.configuration.softwareupdate.enforcement."
                    "specific`) or, for older fleets, a Microsoft Intune "
                    "software-update configuration profile that maps to "
                    "`com.apple.SoftwareUpdate`. Re-collect with `--live` so "
                    "`system_profiler SPConfigurationProfileDataType` can "
                    "prove the policy is installed.",
        # SWUPDATE-FAIL still drives a FAIL when DDM enforcement itself logs
        # a failure-reason (the DDM declaration is deployed but the device
        # could not apply the update).
        fail_findings=("SWUPDATE-FAIL",),
        fail_sources=frozenset({Source.SYSTEM}),
        # PASS evidence: a DDM software-update declaration or the legacy
        # MDM `com.apple.SoftwareUpdate` payload appears in the
        # system_profiler dump. We intentionally do NOT pass on log-text
        # signals like "up to date" — those say "the device is patched
        # *right now*", not "the policy is enforced". The runtime 7301 /
        # ScanNoUpdateFound signal also says nothing about policy
        # enforcement, so it is no longer accepted here.
        pass_pattern=r"com\.apple\.configuration\.softwareupdate\."
                     r"(enforcement\.specific|settings)|"
                     r"softwareupdate\.enforcement\.specific|"
                     r"\bcom\.apple\.SoftwareUpdate\b",
        # If system_profiler ran successfully but no software-update
        # payload was found, the control is FAIL — not "not-assessed".
        ground_truth_marker=r"system_profiler.*SPConfigurationProfileDataType.*collected",
        match_word=False,
        remediation_steps=(
            "In Intune ▸ **Devices ▸ Configuration profiles**, deploy a "
            "DDM declaration of type "
            "`com.apple.configuration.softwareupdate.enforcement.specific` "
            "(or a settings-catalog software-update profile that maps to "
            "the legacy `com.apple.SoftwareUpdate` payload).",
            "On the Mac, run `system_profiler SPConfigurationProfileDataType "
            "| grep -i softwareupdate` and confirm the payload is present.",
            "If a payload is shown but the device still isn't patching, "
            "check **Intune ▸ Devices ▸ macOS ▸ Update declaration status** "
            "for the per-device reason.",
            "Re-collect with `--live` and re-run the analyzer to confirm "
            "the control returns to PASS.",
        ),
        false_positive_note=(
            "This control is now a *policy-enforcement* check, not a "
            "patch-level check. It will be **not-assessed** on offline "
            "bundles that don't include `system_profiler "
            "SPConfigurationProfileDataType` output — collect with `--live` "
            "or paste the dump into the bundle to get a real verdict. "
            "`SUMacControllerErrorAccessLost (7509)` and "
            "`SUMacControllerErrorScanNoUpdateFound (7301)` are runtime "
            "scan signals and don't affect this control."),
    ),
    CISCheck(
        id="CIS-1.2",
        title="Microsoft AutoUpdate (MAU) policy is enforced",
        section="1 Software Updates",
        rationale="Microsoft/Office apps must be patched without user "
                  "action. The auditable signal is a "
                  "`com.microsoft.autoupdate2` configuration profile "
                  "deployed by MDM — not whether the MAU binary happens "
                  "to be running on the device.",
        remediation="Deploy a settings-catalog profile for "
                    "`com.microsoft.autoupdate2` with "
                    "`HowToCheck = AutomaticDownload`. Re-collect with "
                    "`--live` so `system_profiler "
                    "SPConfigurationProfileDataType` can prove the profile "
                    "is installed.",
        # MAU-DISABLED still flips to FAIL — if MAU is logging that auto
        # updates are off, the profile is either missing or misconfigured.
        # MAU-UPDATE-FAIL is intentionally NOT in fail_findings: a
        # transient CDN error does not mean the policy isn't enforced.
        fail_findings=("MAU-DISABLED",),
        fail_sources=frozenset({Source.SYSTEM, Source.AUTOUPDATE}),
        # PASS evidence: the autoupdate2 profile is detected in
        # system_profiler. We deliberately drop the previous
        # ``pass_if_source=Source.AUTOUPDATE`` fallback — having MAU logs
        # only proves MAU is installed, not that policy is enforced.
        pass_pattern=r"com\.microsoft\.autoupdate2",
        ground_truth_marker=r"system_profiler.*SPConfigurationProfileDataType.*collected",
        match_word=False,
        remediation_steps=(
            "In Intune ▸ **Devices ▸ Configuration profiles**, deploy a "
            "settings-catalog profile for `com.microsoft.autoupdate2` with "
            "`HowToCheck = AutomaticDownload`.",
            "On the Mac, run `system_profiler SPConfigurationProfileDataType "
            "| grep -i autoupdate2` and confirm the payload is present.",
            "Spot-check the enforced value: `defaults read "
            "com.microsoft.autoupdate2 HowToCheck` should return "
            "`AutomaticDownload`.",
            "Re-collect with `--live` and re-run the analyzer to confirm "
            "the control returns to PASS.",
        ),
        false_positive_note=(
            "This control is now a *policy-enforcement* check, not a "
            "MAU-is-installed check. It will be **not-assessed** on offline "
            "bundles that don't include `system_profiler "
            "SPConfigurationProfileDataType` output, and it will be **FAIL** "
            "in live runs that show the dump but no `autoupdate2` payload. "
            "Transient `-1100` CDN download failures from MAU do not affect "
            "this verdict."),
    ),

    # --- 2 System Settings & Hardening ------------------------------------ #
    CISCheck(
        id="CIS-2.5.1",
        title="Enable FileVault full-disk encryption",
        section="2 System Settings",
        rationale="FileVault protects data at rest; it is a core CIS Level 1 "
                  "control and a common Intune compliance requirement.",
        remediation="Assign a FileVault disk-encryption policy in Intune with "
                    "key escrow, and confirm encryption completes on the device.",
        fail_pattern=r"filevault.*(not enabled|disabled|is off|not turned on)",
        pass_pattern=r"filevault.*(enabled|is on|turned on|: ?true)",
        match_word=False,
        # FileVault status lines come from installer/system logs.
        fail_sources=frozenset({Source.INSTALL, Source.SYSTEM, Source.INTUNE}),
        remediation_steps=(
            "Intune ▸ **Endpoint security ▸ Disk encryption** ▸ assign a "
            "FileVault profile with key escrow.",
            "On the device, run `fdesetup status` — it must return `FileVault "
            "is On`.",
            "Confirm the recovery key has uploaded: Intune ▸ this device ▸ "
            "**Recovery keys**.",
        ),
        docs_url=MS_BASELINE,
    ),
    CISCheck(
        id="CIS-2.5.2",
        title="Enable Gatekeeper",
        section="2 System Settings",
        rationale="Gatekeeper blocks unsigned/un-notarised code from running, a "
                  "Level 1 protection against untrusted applications.",
        remediation="Enforce Gatekeeper via configuration profile "
                    "(com.apple.systempolicy.control) so it cannot be disabled.",
        # Word-bounded regex so a literal ``on`` substring inside other words
        # (``config``, ``connection``, …) cannot match. Restricted to the
        # system log so e.g. Defender's kernel-queue messages cannot flip it.
        fail_pattern=r"gatekeeper\b.*\b(disabled|off|not enabled|"
                     r"assessments disabled)\b",
        pass_pattern=r"gatekeeper\b.*\b(enabled|on|assessments enabled)\b",
        fail_sources=frozenset({Source.SYSTEM, Source.INSTALL}),
        remediation_steps=(
            "Run `spctl --status` on the device — `assessments enabled` is the "
            "PASS state.",
            "Deploy a com.apple.systempolicy.control profile pinning "
            "`AllowIdentifiedDevelopers = true` so users cannot disable it.",
            "If the device is in **Developer Mode**, that is fine — Gatekeeper "
            "remains active.",
        ),
        false_positive_note=(
            "This control is only evaluated against `system` and `install` "
            "logs. If neither contains a Gatekeeper line the control reports "
            "**not assessed** — that is the honest result, not a failure."),
    ),
    CISCheck(
        id="CIS-2.5.3",
        title="Enable the macOS application firewall",
        section="2 System Settings",
        rationale="The application firewall limits inbound connections; CIS "
                  "Level 1 requires it enabled (with stealth mode).",
        remediation="Deploy a firewall configuration profile "
                    "(com.apple.security.firewall) enabling the firewall and "
                    "stealth mode.",
        fail_pattern=r"\b(application )?firewall\b.*\b(disabled|off|not "
                     r"enabled|could ?n.?t enable)\b",
        pass_pattern=r"\b(application )?firewall\b.*\b(enabled|is on|"
                     r"is active)\b",
        fail_sources=frozenset({Source.SYSTEM, Source.INSTALL}),
        remediation_steps=(
            "On the device, run `defaults read /Library/Preferences/"
            "com.apple.alf globalstate` — `1` (or `2` for stealth) is PASS.",
            "Deploy a com.apple.security.firewall settings-catalog profile "
            "with **Enable Firewall = true** and **Enable Stealth Mode = "
            "true**.",
        ),
    ),
    CISCheck(
        id="CIS-2.11",
        title="Disable automatic login",
        section="2 System Settings",
        rationale="Automatic login bypasses authentication at boot, defeating "
                  "disk-encryption and account controls.",
        remediation="Set com.apple.loginwindow DisableAutoLoginItems / "
                    "DisableFDEAutoLogin via Intune so auto-login is off.",
        # Word-bounded — old regex matched ``c[on]fig`` because ``on`` had no
        # boundary. Restricted to system/install logs so MSAL feature-flag
        # checks (which include the literal string ``autologin``) are not
        # mistaken for an actual login policy signal.
        fail_pattern=r"\bautomatic login\b.*\b(enabled|on|: ?true)\b|"
                     r"\bautologin\b.*\b(enabled|true)\b",
        pass_pattern=r"\bautomatic login\b.*\b(disabled|off|: ?false)\b",
        fail_sources=frozenset({Source.SYSTEM, Source.INSTALL}),
        remediation_steps=(
            "On the device, run `defaults read /Library/Preferences/"
            "com.apple.loginwindow autoLoginUser` — the value should be "
            "**absent** or empty.",
            "Deploy a com.apple.loginwindow profile with `DisableFDEAutoLogin "
            "= true`.",
        ),
        false_positive_note=(
            "MSAL writes lines like `Checking for feature flag "
            "disable_explicit_app_prompt_and_autologin` to its log — those "
            "are feature-flag probes, not policy statements. The control is "
            "now scoped to system/install logs so they cannot trigger a "
            "FAIL."),
    ),

    # --- 3 Logging & Auditing --------------------------------------------- #
    CISCheck(
        id="CIS-3.1",
        title="Enable security auditing",
        section="3 Logging & Auditing",
        rationale="System auditing (auditd) provides the forensic trail CIS "
                  "Level 1 expects for incident response.",
        remediation="Ensure auditd is enabled and audit logs are retained per "
                    "the CIS retention guidance.",
        fail_pattern=r"\bauditd\b.*\b(disabled|not running|stopped)\b|"
                     r"security auditing.*\b(disabled|off)\b",
        pass_pattern=r"\bauditd\b.*\b(enabled|running)\b|"
                     r"security auditing.*\benabled\b",
        fail_sources=frozenset({Source.SYSTEM, Source.INSTALL}),
        remediation_steps=(
            "Run `sudo launchctl print system/com.apple.auditd` — `state = "
            "running` is PASS.",
            "If stopped, start it: `sudo launchctl bootstrap system "
            "/System/Library/LaunchDaemons/com.apple.auditd.plist`.",
            "Confirm `/etc/security/audit_control` retains 60 days "
            "(`expire-after:60d`).",
        ),
    ),

    # --- 5 System Access, Authentication & Authorization ------------------ #
    CISCheck(
        id="CIS-5.2",
        title="Enforce password / passcode policy",
        section="5 Authentication",
        rationale="A strong, enforced password policy is a Level 1 control; "
                  "weak or mismatched policy undermines all other protections.",
        remediation="Align the Intune passcode-complexity policy with the "
                    "Microsoft Entra password policy so requirements match and "
                    "sync succeeds.",
        fail_findings=("PSSO-PASSWORD-SYNC",),
        fail_pattern=r"passcode.*\b(not compliant|complexity (mismatch|"
                     r"exceeds))\b|"
                     r"password policy.*\b(fail|not met|too weak)\b",
        pass_pattern=r"passcode.*\bcompliant\b|"
                     r"password policy.*\b(applied|met|enforced)\b",
        match_word=False,
        fail_sources=frozenset({Source.SYSTEM, Source.INTUNE, Source.PSSO}),
        remediation_steps=(
            "Align the Intune passcode-complexity policy (minimum length, "
            "history, complex chars) with Microsoft Entra ID password "
            "settings — divergence breaks Platform SSO password sync.",
            "If the device shows `passcode.is-compliant = false` in DDM "
            "status, prompt the user to update their passcode.",
        ),
    ),
    CISCheck(
        id="CIS-5.8",
        title="Require a password to wake from sleep or screen saver",
        section="5 Authentication",
        rationale="Locking the screen and requiring a password prevents "
                  "unauthorised access to an unattended Mac.",
        remediation="Deploy a screen-saver / lock policy "
                    "(askForPassword + askForPasswordDelay = 0) via Intune.",
        fail_pattern=r"\bscreen ?(saver|lock)\b.*\b(disabled|off|no password)\b|"
                     r"require password.*\b(disabled|off|not required)\b",
        pass_pattern=r"\bscreen ?(saver|lock)\b.*\b(enabled|on)\b|"
                     r"require password.*\b(enabled|immediately)\b",
        fail_sources=frozenset({Source.SYSTEM, Source.INTUNE}),
        remediation_steps=(
            "Deploy a com.apple.screensaver profile with `askForPassword = 1` "
            "and `askForPasswordDelay = 0`.",
            "Confirm on-device: `defaults -currentHost read com.apple."
            "screensaver askForPassword` returns `1`.",
        ),
    ),

    # --- 6 Applications & Endpoint Protection ----------------------------- #
    CISCheck(
        id="CIS-6.3",
        title="Ensure endpoint malware protection is healthy",
        section="6 Applications",
        rationale="Active, up-to-date anti-malware protection is required at "
                  "Level 1; here satisfied by a healthy Microsoft Defender.",
        remediation="Resolve Defender health (system extension / full-disk "
                    "access approvals), re-enable real-time protection and "
                    "update security intelligence.",
        # ``DEFENDER-INSTALL-FAIL`` is intentionally **not** in fail_findings
        # any more — under the new rule it only matches the actual install
        # log, so when it fires it is a legitimate install failure. We still
        # honour the strong health signals.
        fail_findings=("DEFENDER-UNHEALTHY", "DEFENDER-RTP-OFF",
                       "DEFENDER-DEFS-STALE"),
        pass_if_source=Source.DEFENDER,
        remediation_steps=(
            "On the device, run `mdatp health --details` — every field should "
            "be `true` and `healthy: true`.",
            "If `real_time_protection_enabled: false`, deploy a Defender "
            "preferences profile setting `enableRealTimeProtection = true`.",
            "If `licensed: false`, ensure the user has an MDE plan and "
            "re-onboard via Company Portal.",
        ),
        docs_url="https://learn.microsoft.com/defender-endpoint/mac-resources",
        false_positive_note=(
            "Generic `[error]` lines from `microsoft_defender_core.log` are "
            "operational telemetry, not health failures. Only "
            "`DEFENDER-UNHEALTHY`, `DEFENDER-RTP-OFF` or `DEFENDER-DEFS-STALE`"
            " flip this control to FAIL."),
    ),

    # --- Management foundation (CIS controls are enforced via MDM) -------- #
    CISCheck(
        id="CIS-MDM",
        title="Device is enrolled and managed by MDM",
        section="Management foundation",
        rationale="Without healthy MDM enrollment none of the CIS Level 1 "
                  "settings can be enforced or attested on the device.",
        remediation="Confirm the MDM profile is installed and approved and that "
                    "the Intune agent enrolls and checks in successfully.",
        fail_findings=("INTUNE-ENROLL-FAIL", "MDM-PROFILE-FAIL",
                       "MDM-ENROLL-WELLKNOWN"),
        pass_if_source=Source.INTUNE,
        remediation_steps=(
            "System Settings ▸ General ▸ Device Management — confirm the "
            "**Management Profile** is present and ‘Verified’.",
            "Company Portal ▸ Devices ▸ this Mac ▸ **Check status** — confirm "
            "a recent successful sync.",
            "If `MDM-ENROLL-WELLKNOWN` fired but enrollment is otherwise "
            "healthy, suppress it with `--ignore MDM-ENROLL-WELLKNOWN` — the "
            "rule is intentionally noisy because account-driven enrollment "
            "errors are sparse but important.",
        ),
        docs_url="https://learn.microsoft.com/intune/intune-service/enrollment/"
                 "macos-enroll",
        false_positive_note=(
            "If `INTUNE-ENROLL-FAIL` or `MDM-PROFILE-FAIL` are listed but the "
            "device clearly checks in (Intune logs are present and recent), "
            "the failures were historical. Re-collect a fresh log set after "
            "a successful sync and re-run — this control will then pass."),
    ),
]


def _format_evidence(entry: LogEntry) -> str:
    ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else "?"
    snippet = (entry.message or entry.raw).strip()
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."
    loc = f" [{entry.file.split('/')[-1]}:{entry.line_no}]" if entry.file else ""
    return f"{ts}{loc}  {snippet}"


def _compile(pattern: str | None, *, word: bool, flags: int) -> re.Pattern | None:
    if not pattern:
        return None
    # ``word=True`` only wraps the *outer* expression; rules that already
    # embed ``\b`` work either way.
    if word and not pattern.startswith(r"\b"):
        pattern = rf"(?:{pattern})"
    return re.compile(pattern, flags)


def evaluate(findings: list[Finding], entries: list[LogEntry],
             summaries: set[Source], *,
             ignore: set[str] | None = None) -> CISReport:
    """Validate the analysis against the CIS Level 1 subset.

    ``findings``/``entries`` come from the analyzer; ``summaries`` is the set of
    sources that produced any data. ``ignore`` is the set of finding/CIS IDs
    that the user has explicitly suppressed for this run.
    """
    ignore = ignore or set()
    by_id: dict[str, Finding] = {f.id: f for f in findings if f.id not in ignore}
    checks: list[CISCheckResult] = []

    for spec in CIS_LEVEL1:
        if spec.id in ignore:
            # User suppressed this control entirely — surface it but as
            # not-assessed so it does not count toward the score.
            checks.append(CISCheckResult(
                id=spec.id, title=spec.title, section=spec.section,
                status="not-assessed", rationale=spec.rationale,
                remediation=spec.remediation,
                evidence=[f"Suppressed via --ignore {spec.id}."],
                docs_url=spec.docs_url, confidence="low",
                remediation_steps=list(spec.remediation_steps),
                false_positive_note=spec.false_positive_note,
            ))
            continue

        status = "not-assessed"
        confidence = "high"
        evidence: list[str] = []
        triggering_finding_ids: list[str] = []

        # Default fail_sources to the governing source when not explicit.
        fail_sources = (spec.fail_sources or
                        (frozenset({spec.pass_if_source}) if spec.pass_if_source
                         else frozenset()))

        # 1. Fail via a mapped finding.
        for fid in spec.fail_findings:
            f = by_id.get(fid)
            if f is not None:
                status = "fail"
                triggering_finding_ids.append(fid)
                head = f"{f.id}: {f.title}"
                if f.evidence:
                    head += f" — {f.evidence[0]}"
                evidence.append(head)

        # 1b. Fail via a direct log pattern, restricted to the rule's sources.
        fail_rx = _compile(spec.fail_pattern, word=spec.match_word,
                           flags=spec.flags)
        if fail_rx is not None:
            for e in entries:
                if fail_sources and e.source not in fail_sources:
                    continue
                if fail_rx.search(e.raw or e.message):
                    status = "fail"
                    if len(evidence) < _MAX_EVIDENCE:
                        evidence.append(_format_evidence(e))

        # 2. Otherwise, pass via positive evidence.
        pass_rx = _compile(spec.pass_pattern, word=spec.match_word,
                           flags=spec.flags)
        if status != "fail" and pass_rx is not None:
            for e in entries:
                if fail_sources and e.source not in fail_sources:
                    continue
                if pass_rx.search(e.raw or e.message):
                    status = "pass"
                    if len(evidence) < _MAX_EVIDENCE:
                        evidence.append(_format_evidence(e))

        # 3. Otherwise, pass if the governing source is present.
        if status == "not-assessed" and spec.pass_if_source in summaries:
            # Distinguish "configured" (source present, no positive test) from
            # "pass" (positive test ran and succeeded).
            status = "configured"
            confidence = "low"
            evidence.append(
                f"{spec.pass_if_source.value} logs present with no contrary "
                "signal for this control.")

        # 3b. Ground-truth marker. When the collector proved it inspected the
        # authoritative data (e.g. ``system_profiler``) but no pass evidence
        # was found, the policy is provably *not* enforced — flip to FAIL.
        if status == "not-assessed" and spec.ground_truth_marker:
            marker_rx = re.compile(spec.ground_truth_marker, spec.flags)
            for e in entries:
                if marker_rx.search(e.raw or e.message):
                    status = "fail"
                    evidence.insert(0, (
                        "Authoritative policy data was inspected "
                        f"({e.file or 'ground-truth source'}) but the "
                        "required policy / DDM declaration was not found "
                        "— policy is not enforced."))
                    break

        # 4. Demote a "fail" verdict to "configured" if every contributing
        # finding was transient (e.g. one-off MAU CDN retry).
        if status == "fail" and triggering_finding_ids:
            triggering = [by_id[i] for i in triggering_finding_ids
                          if i in by_id]
            if triggering and all(getattr(t, "transient", False)
                                  for t in triggering):
                status = "configured"
                confidence = "low"
                evidence.insert(0, (
                    "Triggering finding(s) are flagged transient (retry / "
                    "self-healing); CIS verdict demoted from FAIL to "
                    "CONFIGURED."))

        checks.append(CISCheckResult(
            id=spec.id,
            title=spec.title,
            section=spec.section,
            status=status,
            rationale=spec.rationale,
            remediation=spec.remediation,
            evidence=evidence[:_MAX_EVIDENCE],
            docs_url=spec.docs_url,
            confidence=confidence,
            remediation_steps=list(spec.remediation_steps),
            false_positive_note=spec.false_positive_note,
        ))

    return CISReport(checks=checks)
