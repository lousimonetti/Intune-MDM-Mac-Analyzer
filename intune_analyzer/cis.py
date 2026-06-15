"""CIS Apple macOS Benchmark — Level 1 validation.

This module performs a **log-evidence-based** validation of a device against a
curated subset of **CIS Level 1** controls (the essential, low-impact hardening
baseline: software updates, FileVault, Gatekeeper, the application firewall,
password policy, screen lock, endpoint malware protection and MDM enforcement).

It is deliberately *not* a substitute for a full on-device CIS scan: we can only
judge controls for which the collected Intune / macOS / Defender / Platform SSO
logs carry a signal. Each control is therefore resolved to one of three states:

* ``pass``         — positive evidence, or the governing source is present and
                     reports no contrary signal;
* ``fail``         — contrary evidence (a mapped finding fired or a failure line
                     was logged);
* ``not-assessed`` — no evidence either way in the collected logs.

The **validation score (KPI)** is the passing share of *assessable* controls
(``pass / (pass + fail)``); ``not-assessed`` controls do not dilute it. Per the
reporting requirement the KPI is banded **green ≥ 95 %, yellow 75–95 %, red
otherwise** (see :class:`intune_analyzer.models.CISReport`).

Control numbering tracks the CIS Apple macOS Benchmark (Level 1); exact numbers
shift between macOS/benchmark versions, so they are indicative.
Reference: <https://www.cisecurity.org/benchmark/apple_os>
"""

from __future__ import annotations

import re
from dataclasses import dataclass
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

    Resolution order: a ``fail`` signal wins, then positive ``pass`` evidence,
    then ``pass_if_source`` (governing source present and not failing),
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
    docs_url: str = CIS_DOCS
    flags: int = re.IGNORECASE


CIS_LEVEL1: list[CISCheck] = [
    # --- 1 Software Updates ------------------------------------------------ #
    CISCheck(
        id="CIS-1.1",
        title="Ensure all Apple-provided software is current",
        section="1 Software Updates",
        rationale="Running the latest OS and security responses closes known "
                  "vulnerabilities; CIS Level 1 requires updates to be applied.",
        remediation="Enforce macOS update installation via an Intune update "
                    "policy / DDM softwareupdate declaration and confirm the "
                    "device can reach Apple's update servers.",
        fail_findings=("SWUPDATE-FAIL",),
        fail_pattern=r"software ?update.*(fail|error)|os update.*fail",
        pass_pattern=r"software ?update.*(installed|up to date|succeeded)",
    ),
    CISCheck(
        id="CIS-1.2",
        title="Ensure automatic application updates are enabled",
        section="1 Software Updates",
        rationale="Automatic updates keep Microsoft/Office apps patched without "
                  "user action, reducing exposure window.",
        remediation="Deploy a com.microsoft.autoupdate2 profile set to "
                    "AutomaticDownload and confirm Microsoft AutoUpdate health.",
        fail_findings=("MAU-DISABLED", "MAU-UPDATE-FAIL"),
        pass_if_source=Source.AUTOUPDATE,
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
        fail_pattern=r"gatekeeper.*(disabled|off|not enabled)",
        pass_pattern=r"gatekeeper.*(enabled|on|assessments enabled)",
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
        fail_pattern=r"firewall.*(disabled|off|not enabled|could ?n.?t enable)",
        pass_pattern=r"firewall.*(enabled|is on|is active)",
    ),
    CISCheck(
        id="CIS-2.11",
        title="Disable automatic login",
        section="2 System Settings",
        rationale="Automatic login bypasses authentication at boot, defeating "
                  "disk-encryption and account controls.",
        remediation="Set com.apple.loginwindow DisableAutoLoginItems / "
                    "DisableFDEAutoLogin via Intune so auto-login is off.",
        fail_pattern=r"automatic login.*(enabled|on|: ?true)|autologin.*(enabled|on)",
        pass_pattern=r"automatic login.*(disabled|off|: ?false)",
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
        fail_pattern=r"auditd.*(disabled|not running|stopped)|"
                     r"security auditing.*(disabled|off)",
        pass_pattern=r"auditd.*(enabled|running)|security auditing.*enabled",
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
        fail_pattern=r"passcode.*(not compliant|complexity (mismatch|exceeds))|"
                     r"password policy.*(fail|not met|too weak)",
        pass_pattern=r"passcode.*compliant|password policy.*(applied|met|enforced)",
    ),
    CISCheck(
        id="CIS-5.8",
        title="Require a password to wake from sleep or screen saver",
        section="5 Authentication",
        rationale="Locking the screen and requiring a password prevents "
                  "unauthorised access to an unattended Mac.",
        remediation="Deploy a screen-saver / lock policy "
                    "(askForPassword + askForPasswordDelay = 0) via Intune.",
        fail_pattern=r"screen ?(saver|lock).*(disabled|off|no password)|"
                     r"require password.*(disabled|off|not required)",
        pass_pattern=r"screen ?(saver|lock).*(enabled|on)|"
                     r"require password.*(enabled|immediately)",
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
        fail_findings=("DEFENDER-UNHEALTHY", "DEFENDER-RTP-OFF",
                       "DEFENDER-DEFS-STALE", "DEFENDER-INSTALL-FAIL"),
        pass_if_source=Source.DEFENDER,
        docs_url="https://learn.microsoft.com/defender-endpoint/mac-resources",
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
        docs_url="https://learn.microsoft.com/intune/intune-service/enrollment/"
                 "macos-enroll",
    ),
]


def _format_evidence(entry: LogEntry) -> str:
    ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else "?"
    snippet = (entry.message or entry.raw).strip()
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."
    loc = f" [{entry.file.split('/')[-1]}:{entry.line_no}]" if entry.file else ""
    return f"{ts}{loc}  {snippet}"


def evaluate(findings: list[Finding], entries: list[LogEntry],
             summaries: set[Source]) -> CISReport:
    """Validate the analysis against the CIS Level 1 subset.

    ``findings``/``entries`` come from the analyzer; ``summaries`` is the set of
    sources that produced any data.
    """
    by_id: dict[str, Finding] = {f.id: f for f in findings}
    checks: list[CISCheckResult] = []

    for spec in CIS_LEVEL1:
        status = "not-assessed"
        evidence: list[str] = []

        # 1. Fail via a mapped finding.
        for fid in spec.fail_findings:
            f = by_id.get(fid)
            if f is not None:
                status = "fail"
                head = f"{f.title}"
                if f.evidence:
                    head += f" — {f.evidence[0]}"
                evidence.append(head)
        # 1b. Fail via a direct log pattern.
        if spec.fail_pattern:
            rx = re.compile(spec.fail_pattern, spec.flags)
            for e in entries:
                if rx.search(e.raw or e.message):
                    status = "fail"
                    if len(evidence) < _MAX_EVIDENCE:
                        evidence.append(_format_evidence(e))

        # 2. Otherwise, pass via positive evidence.
        if status != "fail" and spec.pass_pattern:
            rx = re.compile(spec.pass_pattern, spec.flags)
            for e in entries:
                if rx.search(e.raw or e.message):
                    status = "pass"
                    if len(evidence) < _MAX_EVIDENCE:
                        evidence.append(_format_evidence(e))

        # 3. Otherwise, pass if the governing source is present and not failing.
        if status == "not-assessed" and spec.pass_if_source in summaries:
            status = "pass"
            evidence.append(
                f"{spec.pass_if_source.value} logs present with no contrary "
                "signal for this control.")

        checks.append(CISCheckResult(
            id=spec.id,
            title=spec.title,
            section=spec.section,
            status=status,
            rationale=spec.rationale,
            remediation=spec.remediation,
            evidence=evidence[:_MAX_EVIDENCE],
            docs_url=spec.docs_url,
        ))

    return CISReport(checks=checks)
