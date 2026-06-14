"""Declarative detection rules.

Each :class:`Rule` matches log entries (by source + message regex) and is
collapsed by the analyzer into a single :class:`Finding` carrying the match
count and a few evidence samples. Keeping the knowledge here - separate from
the matching engine - makes it easy to extend with new signatures.

Signatures are drawn from documented Intune / macOS / Defender / Microsoft
AutoUpdate / Office failure modes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity, Source


@dataclass(frozen=True)
class Rule:
    id: str
    source: Source | None  # None == any source
    pattern: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    category: str = "General"
    docs_url: str = ""
    flags: int = re.IGNORECASE

    def regex(self) -> re.Pattern:
        return re.compile(self.pattern, self.flags)


D = "https://learn.microsoft.com"

RULES: list[Rule] = [
    # ------------------------------------------------------------------ #
    # Intune MDM agent
    # ------------------------------------------------------------------ #
    Rule(
        id="INTUNE-ENROLL-FAIL",
        source=Source.INTUNE,
        pattern=r"enroll(ment)?\s+(failed|error)|failed to enroll|"
                r"device enrollment failed",
        severity=Severity.CRITICAL,
        title="Intune enrollment failures detected",
        description="The management agent logged one or more enrollment "
                    "failures. An unenrolled device cannot receive policies, "
                    "apps or compliance evaluation.",
        recommendation="Re-run Company Portal enrollment, confirm the device "
                       "has a valid MDM profile (System Settings > Device "
                       "Management) and that the user has an Intune licence.",
        category="Enrollment",
        docs_url=f"{D}/intune/intune-service/enrollment/macos-enroll",
    ),
    Rule(
        id="INTUNE-CHECKIN-FAIL",
        source=Source.INTUNE,
        pattern=r"failed to check ?in|check ?in failed|sync failed|"
                r"failed to contact (the )?service",
        severity=Severity.HIGH,
        title="Agent check-in / sync failures",
        description="The Intune agent failed to check in with the service. "
                    "Check-ins normally occur about every 8 hours; failures "
                    "delay policy and app delivery.",
        recommendation="Verify network connectivity to Intune service "
                       "endpoints and that system time is correct. Trigger a "
                       "manual sync from Company Portal.",
        category="Connectivity",
    ),
    Rule(
        id="INTUNE-AAD-TOKEN",
        source=Source.INTUNE,
        pattern=r"\b(aad|entra|adal|msal)\b.*(token|auth).*(fail|error|expired|"
                r"invalid)|failed to acquire token|401 unauthorized|403 forbidden",
        severity=Severity.HIGH,
        title="Microsoft Entra (Azure AD) token / authentication errors",
        description="Token acquisition or authentication errors block the "
                    "agent from authenticating to the Intune service.",
        recommendation="Confirm the user can sign in, that the device is "
                       "registered in Entra ID, and that conditional access "
                       "policies are not blocking the management traffic.",
        category="Authentication",
    ),
    Rule(
        id="INTUNE-POLICY-FAIL",
        source=Source.INTUNE,
        pattern=r"polic(y|ies).*(failed|error|not applied|could ?n.?t apply)|"
                r"failed to (apply|process) (the )?(policy|profile|configuration)",
        severity=Severity.HIGH,
        title="Configuration policy / profile application failures",
        description="One or more configuration policies or profiles failed to "
                    "apply, leaving the device partially configured.",
        recommendation="Review the failing policy in the Intune admin center "
                       "device configuration report and check for conflicting "
                       "settings or unsupported keys on this macOS version.",
        category="Policy",
    ),
    Rule(
        id="INTUNE-COMPLIANCE",
        source=Source.INTUNE,
        pattern=r"not compliant|compliance.*(failed|error)|device is non-?compliant",
        severity=Severity.MEDIUM,
        title="Device compliance issues",
        description="The device evaluated as non-compliant or a compliance "
                    "check failed, which can block conditional-access "
                    "protected resources.",
        recommendation="Open the compliance policy report for this device and "
                       "remediate the failing settings (FileVault, OS version, "
                       "password policy, etc.).",
        category="Compliance",
    ),
    Rule(
        id="INTUNE-APP-INSTALL-FAIL",
        source=Source.INTUNE,
        pattern=r"(app|application|package).*(install|deployment).*(fail|error)|"
                r"failed to (install|download).*(app|pkg|package)",
        severity=Severity.HIGH,
        title="Intune-managed app install failures",
        description="The agent failed to install or download one or more "
                    "managed applications.",
        recommendation="Verify the .pkg includes a valid CFBundleVersion and an "
                       "install-location under /Applications, and confirm the "
                       "app is assigned (required) to this device/user.",
        category="Apps",
        docs_url=f"{D}/troubleshoot/mem/intune/app-management/macos-lob-apps-not-deployed",
    ),
    Rule(
        id="INTUNE-CERT-FAIL",
        source=Source.INTUNE,
        pattern=r"(scep|pkcs|certificate).*(failed|error|denied|invalid)|"
                r"failed to (request|install|renew) (a )?cert",
        severity=Severity.MEDIUM,
        title="Certificate deployment problems (SCEP/PKCS)",
        description="Certificate provisioning errors can break Wi-Fi, VPN and "
                    "authentication profiles that depend on the certificate.",
        recommendation="Check the certificate connector health and the SCEP/"
                       "PKCS profile assignment; confirm the NDES/connector is "
                       "reachable.",
        category="Certificates",
    ),

    # ------------------------------------------------------------------ #
    # macOS app install / PackageKit
    # ------------------------------------------------------------------ #
    Rule(
        id="INSTALL-FAIL",
        source=Source.INSTALL,
        pattern=r"install(ation)? failed|PackageKit:.*fail|"
                r"failed to install|returned non-?zero|exit code [1-9]",
        severity=Severity.HIGH,
        title="Package installation failures",
        description="macOS recorded one or more failed package installations.",
        recommendation="Inspect the failing package's pre/post-install scripts "
                       "and disk space; for Intune apps confirm the package "
                       "format is a supported flat .pkg.",
        category="Apps",
    ),
    Rule(
        id="INSTALL-DOWNGRADE",
        source=None,
        pattern=r"downgrade.*not supported|older version.*already installed",
        severity=Severity.MEDIUM,
        title="Attempted downgrade blocked",
        description="An installer attempted to install an older version than "
                    "what is already present, which macOS blocks.",
        recommendation="Increment the package/app version in Intune so the "
                       "deployed build is newer than the installed one.",
        category="Apps",
    ),

    # ------------------------------------------------------------------ #
    # Microsoft Defender for Endpoint
    # ------------------------------------------------------------------ #
    Rule(
        id="DEFENDER-UNHEALTHY",
        source=Source.DEFENDER,
        pattern=r"healthy\s*[:=]\s*false|health.*unhealthy|product is unhealthy",
        severity=Severity.CRITICAL,
        title="Microsoft Defender reports unhealthy",
        description="`mdatp health` indicates the product is unhealthy; the "
                    "device may be unprotected.",
        recommendation="Run `mdatp health` to see the failing field, confirm "
                       "system extensions and full-disk-access are approved, "
                       "and re-onboard if needed.",
        category="Security",
        docs_url=f"{D}/defender-endpoint/mac-resources",
    ),
    Rule(
        id="DEFENDER-RTP-OFF",
        source=Source.DEFENDER,
        pattern=r"real_time_protection_enabled\s*[:=]\s*false|"
                r"real-?time protection.*(disabled|off)",
        severity=Severity.HIGH,
        title="Defender real-time protection disabled",
        description="Real-time protection is turned off, reducing the device's "
                    "active malware defence.",
        recommendation="Re-enable real-time protection via policy "
                       "(`mdatp config real-time-protection --value enabled`) "
                       "and confirm no MDM profile is disabling it.",
        category="Security",
    ),
    Rule(
        id="DEFENDER-DEFS-STALE",
        source=Source.DEFENDER,
        pattern=r"definitions?_status\s*[:=]\s*[\"']?(out.?of.?date|outdated)|"
                r"signature.*(out of date|outdated|failed to update)",
        severity=Severity.HIGH,
        title="Defender security intelligence out of date",
        description="Antivirus definitions are outdated, lowering detection "
                    "quality.",
        recommendation="Force an update (`mdatp definitions update`) and verify "
                       "connectivity to the update endpoints.",
        category="Security",
    ),
    Rule(
        id="DEFENDER-INSTALL-FAIL",
        source=Source.DEFENDER,
        pattern=r"\[ERROR\]|preinstall.*fail|installation failed",
        severity=Severity.HIGH,
        title="Defender installation errors",
        description="The mdatp install log contains errors from a failed or "
                    "partial installation.",
        recommendation="Review /Library/Logs/Microsoft/mdatp/install.log for "
                       "the [ERROR] line, resolve the stated cause and "
                       "reinstall.",
        category="Security",
        docs_url=f"{D}/defender-endpoint/mac-support-install",
    ),
    Rule(
        id="DEFENDER-CONN-FAIL",
        source=Source.DEFENDER,
        pattern=r"connectivity test.*fail|cannot connect|connection (failed|refused)|"
                r"unable to reach",
        severity=Severity.MEDIUM,
        title="Defender connectivity failures",
        description="The agent could not reach one or more cloud endpoints, "
                    "affecting cloud-delivered protection and reporting.",
        recommendation="Run `mdatp connectivity test`; allow the required "
                       "Defender URLs through proxy/firewall.",
        category="Connectivity",
    ),
    Rule(
        id="DEFENDER-THREAT",
        source=Source.DEFENDER,
        pattern=r"threat (detected|found)|malware detected|quarantine[d]?\b",
        severity=Severity.HIGH,
        title="Threat detections recorded",
        description="Defender detected and/or quarantined one or more threats "
                    "on this device.",
        recommendation="Review `mdatp threat list`, confirm remediation, and "
                       "investigate the source of the detection.",
        category="Security",
    ),

    # ------------------------------------------------------------------ #
    # Microsoft AutoUpdate (MAU)
    # ------------------------------------------------------------------ #
    Rule(
        id="MAU-UPDATE-FAIL",
        source=Source.AUTOUPDATE,
        pattern=r"(update|download).*(failed|error)|failed to (install|download) "
                r"(the )?update|installation.*unsuccessful",
        severity=Severity.MEDIUM,
        title="Microsoft AutoUpdate failures",
        description="One or more Office/Microsoft app updates failed to "
                    "download or install, leaving apps out of date.",
        recommendation="Check MAU update channel/policy and connectivity to "
                       "the Office CDN; run `msupdate --install` to retry.",
        category="Updates",
    ),
    Rule(
        id="MAU-DISABLED",
        source=Source.AUTOUPDATE,
        pattern=r"automatic.*updates?.*(disabled|off)|HowToCheck.*Manual",
        severity=Severity.LOW,
        title="Automatic updates not fully enabled",
        description="MAU is not configured for automatic download/install, so "
                    "devices may lag on security fixes.",
        recommendation="Set the MAU policy to 'AutomaticDownload' via an Intune "
                       "configuration profile for com.microsoft.autoupdate2.",
        category="Updates",
    ),

    # ------------------------------------------------------------------ #
    # Microsoft Office apps
    # ------------------------------------------------------------------ #
    Rule(
        id="OFFICE-ACTIVATION",
        source=Source.OFFICE,
        pattern=r"activation (failed|error)|license.*(failed|expired|invalid)|"
                r"not licensed|sign-?in.*failed",
        severity=Severity.MEDIUM,
        title="Office activation / licensing problems",
        description="Office apps logged activation or licensing failures, which "
                    "lead to reduced-functionality mode for the user.",
        recommendation="Confirm the user has an assigned Microsoft 365 licence "
                       "and can sign in; clear cached licences if needed.",
        category="Licensing",
    ),
    Rule(
        id="OFFICE-CRASH",
        source=Source.OFFICE,
        pattern=r"\bcrash(ed|ing)?\b|unexpectedly (quit|terminated)|segfault|"
                r"abnormal termination",
        severity=Severity.MEDIUM,
        title="Office application crashes",
        description="One or more Office applications recorded crashes.",
        recommendation="Confirm apps are updated via MAU; collect the crash "
                       "report and check for problematic add-ins.",
        category="Stability",
    ),

    # ------------------------------------------------------------------ #
    # Cross-cutting macOS / MDM
    # ------------------------------------------------------------------ #
    Rule(
        id="MDM-PROFILE-FAIL",
        source=Source.SYSTEM,
        pattern=r"profile.*(failed to install|removed|not installed)|"
                r"mdm.*(error|failed)|managedclient.*error",
        severity=Severity.HIGH,
        title="MDM profile installation problems",
        description="macOS reported problems installing or retaining MDM "
                    "profiles, which underpins all Intune management.",
        recommendation="Confirm the MDM profile is present and approved; "
                       "re-push the profile or re-enroll if it was removed.",
        category="MDM",
    ),
]
