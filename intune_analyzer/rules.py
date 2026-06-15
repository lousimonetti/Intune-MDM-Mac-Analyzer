"""Declarative detection rules.

Each :class:`Rule` matches log entries (by source + message regex) and is
collapsed by the analyzer into a single :class:`Finding` carrying the match
count and a few evidence samples. Keeping the knowledge here - separate from
the matching engine - makes it easy to extend with new signatures.

Signatures are drawn from documented Intune / macOS / Defender / Microsoft
AutoUpdate / Office failure modes.

Rule writing guidelines (lessons learned the hard way)
------------------------------------------------------

* **Prefer ``source=`` over a permissive regex.** A rule that fires against any
  source must be exceptionally narrow; otherwise unrelated telemetry (Outlook
  ``Hx.Heartbeat``, Defender kernel-queue warnings, …) will trip it.
* **Anchor weak alternations.** ``(failed|403)`` will match the literal ``403``
  anywhere in a JSON line; require a word boundary or an HTTP context.
* **Restrict by ``file_pattern`` for log-specific rules.** ``[ERROR]`` is a
  perfectly normal phrase in Defender's runtime log; it only indicates an
  installation problem in ``mdatp/install.log``.
* **Set ``transient=True`` for retry-recoverable failures** (CDN ``-1100``,
  ``SUMacControllerErrorAccessLost``, ``SUMacControllerErrorScanNoUpdateFound``).
  Transient findings are downgraded by the CIS evaluator so a single retry does
  not drag a configured baseline to ``FAIL``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

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
    # Optional extras used by the analyzer to suppress obvious false positives.
    # ``file_pattern``   : only fire when the parsed file name (basename) matches.
    # ``exclude_pattern``: a second regex; if it matches, the line is dropped.
    # ``transient``      : the failure mode is normally self-healing (retry,
    #                      race, transient CDN/network) so it should not by
    #                      itself fail a CIS control.
    # ``remediation_steps`` : ordered, concrete remediation actions.
    # ``false_positive_note``: surfaced in the report so users can decide
    #                          whether to ignore the finding.
    file_pattern: str = ""
    exclude_pattern: str = ""
    transient: bool = False
    remediation_steps: tuple[str, ...] = field(default_factory=tuple)
    false_positive_note: str = ""
    # ``subject_pattern``: a regex with one capture group that pulls the
    #                      thing the rule is about (an app name, a policy
    #                      ID, a profile) out of each matching log line.
    #                      Distinct values are de-duplicated and surfaced on
    #                      the finding so the report can say *which* app or
    #                      policy is failing, not just "something failed".
    # ``subject_label``  : short noun for the report header (e.g. "Apps",
    #                      "Policies", "Profiles").
    subject_pattern: str = ""
    subject_label: str = ""

    def regex(self) -> re.Pattern:
        return re.compile(self.pattern, self.flags)

    def file_regex(self) -> re.Pattern | None:
        return re.compile(self.file_pattern, self.flags) if self.file_pattern else None

    def exclude_regex(self) -> re.Pattern | None:
        return (re.compile(self.exclude_pattern, self.flags)
                if self.exclude_pattern else None)

    def subject_regex(self) -> re.Pattern | None:
        return (re.compile(self.subject_pattern, self.flags)
                if self.subject_pattern else None)


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
        remediation_steps=(
            "Open System Settings ▸ General ▸ Device Management and confirm "
            "the **Management Profile** is present and ‘Verified’.",
            "Sign in to Company Portal and run **Check status**; if the device "
            "is missing, choose **Enroll** to re-enroll.",
            "In the Intune admin centre, confirm the user is licensed for "
            "Intune (Microsoft 365 ▸ Users ▸ Licenses).",
            "If enrollment still fails, capture `/Library/Logs/Microsoft/Intune/"
            "IntuneMDMDaemon*.log` plus a sysdiagnose and open a Microsoft "
            "support case.",
        ),
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
        remediation_steps=(
            "Check the device clock is correct (skewed time breaks TLS).",
            "Confirm reachability of `*.manage.microsoft.com` and "
            "`login.microsoftonline.com` (curl them; exempt from TLS "
            "inspection if a proxy is present).",
            "In Company Portal choose **Devices ▸ Sync**, then watch a fresh "
            "`IntuneMDMDaemon*.log` for a successful check-in.",
            "If failures persist, restart the Intune agent: "
            "`sudo launchctl kickstart -k system/com.microsoft.intune.mdm.daemon`.",
        ),
        category="Connectivity",
        false_positive_note=(
            "A single retry after a Wi-Fi handoff is normal; treat this as "
            "actionable only when failures cluster within a check-in cycle."),
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
        remediation_steps=(
            "Have the user sign in to `https://myaccount.microsoft.com` to "
            "confirm the account itself is healthy.",
            "Check Microsoft Entra ▸ **Sign-in logs** and **Devices** for "
            "Conditional Access blocks or stale device registrations.",
            "Run `app-sso platform -s` on the Mac to confirm Platform SSO "
            "registration; re-register from Company Portal if needed.",
            "If MFA is required at every check-in, exempt the device-trust "
            "flow via a Conditional Access policy targeting the Intune app.",
        ),
        category="Authentication",
    ),
    Rule(
        id="INTUNE-POLICY-FAIL",
        source=Source.INTUNE,
        # Tightened: require the literal "policy/profile" object in the failure
        # phrase. The previous pattern matched ``Policy measurement. Error:
        # StorageError.unableToWriteRecord(...)`` which is an internal storage
        # retry, not an applied-policy failure.
        pattern=r"polic(y|ies)\s+(application|apply|assignment|evaluation)?.*"
                r"(failed|error|not applied|could ?n.?t apply)|"
                r"failed to (apply|process|evaluate) (the )?(policy|profile|"
                r"configuration)|"
                r"profile\s+(install|installation)\s+failed",
        exclude_pattern=r"storageerror|policy measurement|telemetry",
        severity=Severity.HIGH,
        title="Configuration policy / profile application failures",
        description="One or more configuration policies or profiles failed to "
                    "apply, leaving the device partially configured.",
        recommendation="Review the failing policy in the Intune admin center "
                       "device configuration report and check for conflicting "
                       "settings or unsupported keys on this macOS version.",
        remediation_steps=(
            "Open Intune ▸ **Devices ▸ macOS ▸ <this device> ▸ Device "
            "configuration** and note the failing policy/setting and its "
            "error code.",
            "Cross-reference the setting against the macOS settings catalog "
            "(some keys require a specific macOS major version).",
            "Look for two profiles changing the same payload (conflict). "
            "Remove the older Device-Features profile if a Settings-Catalog "
            "profile is replacing it.",
            "Trigger a fresh sync from Company Portal; if the failure "
            "persists, duplicate the policy with one setting at a time to "
            "isolate the offender.",
        ),
        category="Policy",
        false_positive_note=(
            "Internal agent storage retries (`StorageError.unableToWriteRecord`)"
            " are not policy failures — they are excluded from this rule."),
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
        remediation_steps=(
            "Intune ▸ **Devices ▸ Compliance** ▸ select the device ▸ note the "
            "failing setting (FileVault, OS version, password policy, etc.).",
            "Remediate the underlying setting — e.g. enable FileVault via the "
            "endpoint security disk-encryption policy.",
            "Force a compliance re-evaluation from Company Portal ▸ Devices "
            "▸ Check status.",
        ),
        category="Compliance",
    ),
    Rule(
        id="INTUNE-APP-INSTALL-FAIL",
        source=Source.INTUNE,
        pattern=r"(app|application|package).*(install|deployment).*(fail|error)|"
                r"failed to (install|download).*(app|pkg|package)",
        # Intune agent logs the app name as a quoted token, typically after
        # "for" (e.g. ``Application install failed for 'Acme VPN Client':``).
        # We capture quoted strings of 1-80 chars so the report can list the
        # specific apps instead of just the generic failure title.
        subject_pattern=r"['\"]([^'\"\n]{1,80})['\"]",
        subject_label="Apps",
        severity=Severity.HIGH,
        title="Intune-managed app install failures",
        description="The agent failed to install or download one or more "
                    "managed applications.",
        recommendation="Verify the .pkg includes a valid CFBundleVersion and an "
                       "install-location under /Applications, and confirm the "
                       "app is assigned (required) to this device/user.",
        remediation_steps=(
            "In Intune ▸ **Apps ▸ All apps ▸ <app> ▸ Device install status** "
            "find this device and read the **status code**.",
            "Rebuild the package with a flat `.pkg` containing a valid "
            "`CFBundleVersion` and an install location under `/Applications`.",
            "If the failure mentions `bundleNotFound`, the agent could not "
            "verify the app installed — fix the bundle identifier in the "
            "Intune app definition to match the installed app.",
            "Re-assign as **Required** (not Available) for this user / device "
            "group and trigger a sync.",
        ),
        category="Apps",
        docs_url=f"{D}/troubleshoot/mem/intune/app-management/macos-lob-apps-not-deployed",
        false_positive_note=(
            "`bundleNotFound` warnings during detection are normal on first "
            "install and clear once the app is present; treat as actionable "
            "only when the same `PolicyID` keeps failing across check-ins."),
    ),
    Rule(
        id="INTUNE-CERT-FAIL",
        source=Source.INTUNE,
        pattern=r"\b(scep|pkcs)\b.*(failed|error|denied|invalid)|"
                r"certificate (request|enrollment|deployment).*(failed|error|denied|"
                r"invalid)|"
                r"failed to (request|install|renew) (a )?certificate",
        severity=Severity.MEDIUM,
        title="Certificate deployment problems (SCEP/PKCS)",
        description="Certificate provisioning errors can break Wi-Fi, VPN and "
                    "authentication profiles that depend on the certificate.",
        recommendation="Check the certificate connector health and the SCEP/"
                       "PKCS profile assignment; confirm the NDES/connector is "
                       "reachable.",
        remediation_steps=(
            "Intune ▸ **Tenant administration ▸ Connectors and tokens ▸ "
            "Certificate connectors** — confirm the connector reports "
            "**Active**.",
            "Inspect the SCEP/PKCS profile’s subject template and EKU for "
            "syntax that the NDES policy module rejects.",
            "On the Mac, run `security find-certificate -a -p` and check the "
            "expected cert appears; missing chain certs break trust.",
            "If only Wi-Fi/VPN profiles are affected, confirm the certificate "
            "profile is delivered **before** the network profile (Intune "
            "applies them in upload order).",
        ),
        category="Certificates",
    ),

    # ------------------------------------------------------------------ #
    # macOS app install / PackageKit
    # ------------------------------------------------------------------ #
    Rule(
        id="INSTALL-FAIL",
        source=Source.INSTALL,
        # Tightened: real package-failure phrases. The previous rule treated
        # ``PackageKit:.*fail`` as failure, but PackageKit logs many benign
        # "Failed to set hosted team responsibility" lines that simply mean
        # the responsible-team handoff was skipped — the package still installs.
        pattern=r"install(ation)? failed|installer\[\d+\]:\s+install failed|"
                r"failed to install|"
                r"package.*(install|deploy).*(failed|error)|"
                r"PackageKit:.*(install (failed|error)|aborted)|"
                r"returned non-?zero|exit code [1-9]",
        exclude_pattern=r"failed to set hosted team responsibility|"
                        r"failed to enumerate plug-?in",
        severity=Severity.HIGH,
        title="Package installation failures",
        description="macOS recorded one or more failed package installations.",
        recommendation="Inspect the failing package's pre/post-install scripts "
                       "and disk space; for Intune apps confirm the package "
                       "format is a supported flat .pkg.",
        remediation_steps=(
            "Open `/var/log/install.log` (or the captured copy) and read "
            "context around each `install failed` line — the preceding "
            "`PackageKit:` lines name the script and exit code.",
            "Confirm free disk space (>10 GB recommended for OS updates).",
            "If the failing package is from Intune, re-upload as a flat `.pkg` "
            "with embedded scripts under `/Applications`.",
            "For repeated failures from the same package, suppress this "
            "finding (`--ignore INSTALL-FAIL`) and track it via Intune’s app "
            "install-status report instead.",
        ),
        category="Apps",
        false_positive_note=(
            "macOS prints `Failed to set hosted team responsibility for "
            "install to team:(…)` for **every** install; it is informational, "
            "not a failure — it is excluded from this rule."),
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
    Rule(
        # Surfaced separately at LOW severity so the signal is visible
        # without inflating the critical/high count — installs still
        # succeed, and the underlying cause is how the .pkg declares its
        # signing team / hosted responsibility (developer-ID team mismatch
        # between the package and the responsible team). Worth tracking and
        # fixing during repackaging, but not a deployment blocker.
        id="INSTALL-TEAM-RESPONSIBILITY",
        source=Source.INSTALL,
        pattern=r"PackageKit:\s*Failed to set hosted team responsibility for "
                r"install to team:\(?[A-Z0-9]+\)?",
        severity=Severity.LOW,
        title="PackageKit could not set hosted team responsibility on install",
        description="macOS PackageKit logged 'Failed to set hosted team "
                    "responsibility for install to team:(<TEAMID>)' for one or "
                    "more installs. This typically means the package's signing "
                    "team ID does not match the team macOS would assign as the "
                    "owning ('responsible') team for the install. The install "
                    "still succeeds; the consequence is mainly that "
                    "TCC/responsibility attribution falls back to the "
                    "installer process instead of the named developer team.",
        recommendation="Track these for the next repackaging pass — they are "
                       "non-blocking but indicate the .pkg signing / "
                       "responsible-team metadata is worth cleaning up.",
        remediation_steps=(
            "Note the team ID in parentheses (e.g. `UL6CGN7MAL`) and confirm "
            "it matches the Developer ID team that signs the .pkg.",
            "When repackaging, sign the outer .pkg with `productsign --sign "
            "\"Developer ID Installer: <Company> (<TEAMID>)\"` and confirm "
            "the embedded payload binaries are signed with the same team.",
            "If the .pkg uses pre/post-install scripts that spawn helper "
            "binaries, ensure those binaries carry the same team ID — "
            "PackageKit assigns responsibility based on the embedded "
            "developer-ID metadata.",
            "If the package is a third-party `.pkg` you cannot resign, "
            "suppress with `--ignore INSTALL-TEAM-RESPONSIBILITY` once "
            "you have decided it is acceptable.",
        ),
        category="Apps",
        false_positive_note=(
            "This warning is **informational** — it does not stop the "
            "install from completing. Treat it as a packaging-quality "
            "signal rather than a deployment failure. Common on third-"
            "party Intune-deployed `.pkg` files whose signing team does "
            "not match macOS's expected responsible team."),
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
        remediation_steps=(
            "Run `mdatp health --details` to see the exact failing field.",
            "Open **System Settings ▸ Privacy & Security ▸ Full Disk Access** "
            "and confirm `Microsoft Defender` and its system-extension are "
            "enabled.",
            "If `licensed: false`, ensure the user has a Defender plan and "
            "re-onboard with the WorkplaceJoinKey via Company Portal.",
            "If `real_time_protection_enabled: false`, deploy an "
            "MDE-preferences profile setting `enableRealTimeProtection = true`.",
        ),
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
        # Tightened: `[ERROR]` is a normal token in Defender's runtime logs and
        # only indicates an install problem when it comes from install.log.
        pattern=r"preinstall.*fail|installation failed|"
                r"installer (returned|exit) (non-?zero|[1-9])|"
                r"failed to install\s+(microsoft )?defender",
        # Only the actual install log is in scope. Avoids matching every
        # `[error]` line from microsoft_defender_core.log etc.
        file_pattern=r"(^|/)install\.log$|mdatp[-_]install",
        severity=Severity.HIGH,
        title="Defender installation errors",
        description="The mdatp install log contains errors from a failed or "
                    "partial installation.",
        recommendation="Review /Library/Logs/Microsoft/mdatp/install.log for "
                       "the [ERROR] line, resolve the stated cause and "
                       "reinstall.",
        remediation_steps=(
            "Open `/Library/Logs/Microsoft/mdatp/install.log` and find the "
            "first `[ERROR]` line.",
            "If a system-extension/KEXT approval is missing, approve it under "
            "**System Settings ▸ Privacy & Security ▸ Allow**.",
            "Re-run the installer (`installer -pkg <wdav>.pkg -target /`) and "
            "confirm `mdatp health` afterward.",
        ),
        category="Security",
        docs_url=f"{D}/defender-endpoint/mac-support-install",
        false_positive_note=(
            "Runtime `[error]` lines in `microsoft_defender_core.log` /"
            " `_diagnostic.log` are normal operational telemetry, not install "
            "problems — this rule is scoped to install.log only."),
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
        # Tightened: require the explicit `threat_detected` / `threat found`
        # phrase or an explicit quarantine action. Bare ``quarantine`` matches
        # innocuous lines like ``crash uploader … quarantine path``.
        pattern=r"threat[_\s]+(detected|found|name)|malware detected|"
                r"quarantine[d]?\s+(file|threat)|"
                r"threat_id\s*[:=]",
        severity=Severity.HIGH,
        title="Threat detections recorded",
        description="Defender detected and/or quarantined one or more threats "
                    "on this device.",
        recommendation="Review `mdatp threat list`, confirm remediation, and "
                       "investigate the source of the detection.",
        remediation_steps=(
            "Run `mdatp threat list` to see active and historical detections.",
            "Run `mdatp threat get --id <id>` for full context (path, "
            "process, action taken).",
            "If quarantine action was successful, no further work is required "
            "— investigate the **delivery vector** (browser download, USB, "
            "email) so it can be blocked upstream.",
        ),
        category="Security",
        false_positive_note=(
            "Defender uses signature names like `Trojan:JS/ShaiWorm.SA` "
            "internally when **loading** rules; that is signature metadata, "
            "not a detection. Confirm with `mdatp threat list` before "
            "acting."),
    ),

    # ------------------------------------------------------------------ #
    # Microsoft AutoUpdate (MAU)
    # ------------------------------------------------------------------ #
    Rule(
        id="MAU-UPDATE-FAIL",
        source=Source.AUTOUPDATE,
        pattern=r"(update|download).*(failed|error)|failed to (install|download) "
                r"(the )?update|installation.*unsuccessful",
        severity=Severity.LOW,  # downgraded — MAU retries CDN errors itself
        title="Microsoft AutoUpdate transient download failures",
        description="Microsoft AutoUpdate logged one or more failed update "
                    "downloads or installs. MAU retries automatically; this "
                    "is only meaningful when failures persist over many days.",
        recommendation="Check MAU update channel/policy and connectivity to "
                       "the Office CDN; run `msupdate --install` to retry.",
        remediation_steps=(
            "Run `msupdate --list` to see pending updates and "
            "`msupdate --install` to force a retry.",
            "Confirm reachability of `officecdn.microsoft.com` and "
            "`res.public.onecdn.static.microsoft` (exempt from TLS "
            "inspection).",
            "If failures persist > 7 days, confirm a com.microsoft.autoupdate2 "
            "profile is deployed with `HowToCheck = AutomaticDownload`.",
        ),
        transient=True,
        category="Updates",
        false_positive_note=(
            "Error `-1100` is an HTTP 404 from the CDN — common when the "
            "package has rolled to a newer build between MAU’s check and "
            "fetch. A single occurrence is normal; clusters of failures over "
            "many days indicate a real connectivity or policy issue."),
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
        # Tightened: require an *Office* licensing-failure phrase. The old
        # pattern matched ``Not licensed for Copilot DAB`` which is a feature
        # gate, not an Office activation failure.
        pattern=r"office\s+(activation|licens(e|ing)).*(failed|error|expired|invalid)|"
                r"activation (failed|error)|"
                r"\bOLicense\b.*(failed|error)|"
                r"sign-?in.*failed.*\b(office|outlook|word|excel|powerpoint)\b",
        exclude_pattern=r"not licensed for (copilot|loop|designer|clipchamp|"
                        r"viva|premium)",
        severity=Severity.MEDIUM,
        title="Office activation / licensing problems",
        description="Office apps logged activation or licensing failures, which "
                    "lead to reduced-functionality mode for the user.",
        recommendation="Confirm the user has an assigned Microsoft 365 licence "
                       "and can sign in; clear cached licences if needed.",
        remediation_steps=(
            "Confirm the user has an Office/Microsoft 365 licence assigned in "
            "Microsoft 365 admin ▸ Users.",
            "From a Terminal, clear cached licences: "
            "`cd ~/Library/Group\\ Containers/UBF8T346G9.Office/ && "
            "rm -f Licenses/*` then reopen Word.",
            "Sign in again from any Office app and complete activation.",
        ),
        category="Licensing",
        false_positive_note=(
            "Feature gates such as `Not licensed for Copilot DAB` are "
            "tracked separately — they do not put Office into reduced-"
            "functionality mode and are excluded from this rule."),
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

    # ------------------------------------------------------------------ #
    # Apple declarative device management (DDM) & account-driven enrollment.
    # Signatures validated against apple/device-management schema:
    #   declarative/status/app.managed.list.yaml
    #   declarative/status/softwareupdate.failure-reason.yaml
    #   mdm/errors/{well-known.failed,psso.required,unrecognized.device}.yaml
    # ------------------------------------------------------------------ #
    Rule(
        id="MDM-ENROLL-WELLKNOWN",
        # Tightened scope: account-driven enrollment errors are surfaced by
        # the OS (system / installer logs) and by the Intune agent, never by
        # Office telemetry. We also require the literal Apple error envelope
        # so a stray ``well known … 403`` in random JSON cannot trip the rule.
        source=None,
        pattern=r"com\.apple\.(well-?known\.failed|psso\.required|"
                r"unrecognized\.device)|"
                r"well-?known\.failed\b|"
                r"\bhttp(s)? 403\b.*well-?known|"
                r"platform ?sso (registration )?required (for|before) enrollment|"
                r"unrecognized device.*enroll",
        exclude_pattern=r"telemetry|sendevent|heartbeat|featurequery|"
                        r"experimentation|outlook|powerpoint|excel|word",
        severity=Severity.HIGH,
        title="Account-driven enrollment / service-discovery failure",
        description="Apple reported a well-known service-discovery or "
                    "Platform SSO error (e.g. com.apple.well-known.failed, "
                    "psso.required). These block account-driven Intune "
                    "enrollment.",
        recommendation="Verify the organisation's service-discovery (.well-known) "
                       "endpoint and, if required, that Platform SSO is "
                       "registered before enrollment proceeds.",
        remediation_steps=(
            "Confirm the tenant’s `.well-known/com.apple.remotemanagement` "
            "endpoint returns HTTP 200 (404/403 here blocks enrollment).",
            "If `psso.required` is the error, ensure Platform SSO is "
            "registered first (Company Portal ▸ Help ▸ Platform SSO).",
            "If `unrecognized.device` appears, the device serial is not in "
            "Apple Business Manager / Intune’s assigned token — assign it "
            "and retry.",
        ),
        category="Enrollment",
        docs_url="https://developer.apple.com/documentation/devicemanagement",
        false_positive_note=(
            "Office telemetry events frequently contain the literal string "
            "`WellKnown…` deep inside JSON; this rule excludes telemetry / "
            "Office sources to avoid false positives."),
    ),
    Rule(
        id="DDM-APP-STATE",
        source=None,
        pattern=r"\b(prompting-for-login|prompting-for-management|"
                r"managed-but-uninstalled)\b|app\b.*\bstate\b.*\bfailed\b",
        severity=Severity.MEDIUM,
        title="Managed app stuck awaiting user action",
        description="A declaratively-managed app reported a state that needs "
                    "user interaction or did not reach 'managed' (e.g. "
                    "prompting-for-login, managed-but-uninstalled, failed).",
        recommendation="Confirm the user is signed into the App Store / has a "
                       "VPP licence assigned; for required apps verify the "
                       "AppStoreID/BundleID and assignment.",
        category="Apps",
        docs_url="https://github.com/apple/device-management/blob/release/"
                 "declarative/status/app.managed.list.yaml",
    ),
    Rule(
        id="SWUPDATE-FAIL",
        # Tightened: only meaningful on the system / install logs, and exclude
        # the well-known transient errors (race-condition AccessLost 7509,
        # ScanNoUpdateFound 7301 which literally means "no update available").
        source=None,
        pattern=r"softwareupdate.*failure-?reason|"
                r"software ?update.*\b(install|download)\b.*(fail|failure|error)|"
                r"failed to (download|install).*(os update|macos update)|"
                r"SUOSUServiceDaemon.*Error\s+installing",
        exclude_pattern=r"SUMacControllerErrorAccessLost|7509|"
                        r"SUMacControllerErrorScanNoUpdateFound|7301|"
                        r"no update (found|available)|"
                        r"network connection.*lost",
        severity=Severity.LOW,
        title="macOS software update enforcement failures",
        description="A managed macOS software update failed to download or "
                    "install (DDM softwareupdate.failure-reason). Devices left "
                    "on older OS builds drift out of compliance.",
        recommendation="Check the update enforcement declaration/policy, free "
                       "disk space, and network reachability to Apple's "
                       "software-update servers.",
        remediation_steps=(
            "Run `softwareupdate --list` to see what macOS currently offers.",
            "Check disk free space (`df -h /`); the installer needs ~20 GB.",
            "Confirm reachability of `swcdn.apple.com` and `swscan.apple.com`.",
            "If a DDM declaration is enforcing the update, inspect the device "
            "in **Intune ▸ Devices ▸ macOS ▸ Update declaration status**.",
        ),
        transient=True,
        category="Updates",
        docs_url="https://github.com/apple/device-management/blob/release/"
                 "declarative/status/softwareupdate.failure-reason.yaml",
        false_positive_note=(
            "`SUMacControllerErrorAccessLost (7509)` is a benign race between "
            "two clients calling softwareupdated; `ScanNoUpdateFound (7301)` "
            "literally means **the device is up to date**. Both are filtered "
            "out of this rule."),
    ),

    # ------------------------------------------------------------------ #
    # Platform SSO (PSSO) / Microsoft Enterprise SSO plug-in.
    # ------------------------------------------------------------------ #
    Rule(
        id="PSSO-REGISTER-FAIL",
        source=Source.PSSO,
        pattern=r"(platform ?sso|psso).*(registration|register).*(fail|error)|"
                r"registration (failed|error|incomplete)|"
                r"re-?registration (required|prompt)|device (join|registration) failed|"
                r"failed to register (the )?(device|platform sso)|"
                r"WorkPlaceJoin\(PlatformSSO\).*errorCode:-?\d+",
        severity=Severity.HIGH,
        title="Platform SSO device registration failures",
        description="The Enterprise SSO plug-in logged a Platform SSO "
                    "registration failure. Until registration completes the "
                    "device has no Secure Enclave / password-synced credential, "
                    "so SSO and device-based Conditional Access do not work.",
        recommendation="Confirm the user is allow-listed to join Microsoft "
                       "Entra (Devices > Device Settings), retry registration "
                       "from System Settings > Users & Groups (Repair) or the "
                       "Company Portal, and check `app-sso platform -s` state.",
        remediation_steps=(
            "Run `app-sso platform -s` and capture the state JSON.",
            "Microsoft Entra ▸ **Devices ▸ Device Settings** — confirm "
            "‘Users may join devices’ allows this user.",
            "In Company Portal, choose **Help ▸ Get help** ▸ register Platform "
            "SSO again; if needed, **System Settings ▸ Users & Groups ▸ "
            "<user> ▸ Repair**.",
            "If macOS 15.0–15.2 is in use, update to 15.3+ (Apple fixed the "
            "AppSSOAgent/AppSSODaemon concurrency bug that breaks "
            "registration).",
        ),
        category="Authentication",
        docs_url=f"{D}/entra/identity/devices/"
                 "troubleshoot-macos-platform-single-sign-on-extension",
    ),
    Rule(
        id="PSSO-CONFIG-CORRUPT",
        source=Source.PSSO,
        pattern=r"com\.apple\.PlatformSSO Code=-1001|"
                r"error deserializing device config|"
                r"garbage at end around line",
        severity=Severity.HIGH,
        title="Corrupted Platform SSO device configuration (re-registration loop)",
        description="A known macOS 15 (Sequoia) concurrency issue between "
                    "AppSSOAgent and AppSSODaemon can corrupt the PSSO device "
                    "config (com.apple.PlatformSSO Code=-1001 'Error "
                    "deserializing device config.'), triggering repeated "
                    "re-registration prompts.",
        recommendation="Update to macOS 15.3 or later where Apple's fix is "
                       "deployed; if the prompts persist, capture a sysdiagnose "
                       "and engage Apple support.",
        category="Authentication",
        docs_url=f"{D}/entra/identity/devices/"
                 "troubleshoot-macos-platform-single-sign-on-extension",
    ),
    Rule(
        id="PSSO-PAYLOAD-MISCONFIG",
        source=Source.PSSO,
        pattern=r"\b1000[12]\b.*(ssoe|payload)|"
                r"misconfiguration in the ssoe payload|"
                r"multiple ssoe payloads|"
                r"(ssoe|sso ?extension) payload.*(conflict|misconfigur)",
        severity=Severity.HIGH,
        title="Platform SSO profile (SSOe payload) misconfiguration",
        description="The SSO extension reported a payload error: 10001 "
                    "(a required setting is missing or not applicable for the "
                    "redirect payload) or 10002 (multiple conflicting SSO "
                    "extension profiles are applied).",
        recommendation="Ensure exactly one settings-catalog SSO profile is "
                       "assigned (unassign any legacy Device-Features SSO "
                       "profile) and that macOS 13/14 authentication settings "
                       "are configured in the same policy.",
        category="Policy",
        docs_url=f"{D}/intune/device-configuration/settings-catalog/"
                 "configure-platform-sso-macos",
    ),
    Rule(
        id="PSSO-EXTENSION-INACTIVE",
        source=Source.PSSO,
        pattern=r"pluginkit code=16|other version in use|\b4s8qh\b|"
                r"invalid team identifier of the extension|"
                r"extension .*(not (loaded|running|activated)|failed to (load|launch))",
        severity=Severity.HIGH,
        title="Enterprise SSO extension not loaded / activated",
        description="The operating system failed to launch the Microsoft "
                    "Enterprise SSO extension (e.g. PlugInKit Code=16 'other "
                    "version in use', error tag '4s8qh' on macOS 15.3/iOS "
                    "18.1.1, or 'invalid team identifier' when SIP is disabled). "
                    "Authentication then fails across all Entra-integrated apps.",
        recommendation="Reboot the device to recover from the PlugInKit "
                       "regression; verify System Integrity Protection (SIP) is "
                       "enabled and the extension is "
                       "com.microsoft.CompanyPortalMac.ssoextension (UBF8T346G9).",
        category="Authentication",
        docs_url=f"{D}/entra/identity/devices/troubleshoot-mac-sso-extension-plugin",
    ),
    Rule(
        id="PSSO-PRT-TOKEN",
        source=Source.PSSO,
        # Tightened: require either the MSAL ``invalid_grant`` family or a
        # broker-level PRT acquire/refresh failure phrase. The previous
        # ``token acquisition failed`` was too generic and matched normal MSAL
        # interactive-fallback prompts.
        # ``requires user interaction`` is NOT a failure — it is the broker
        # asking for an interactive step (CA policy, MFA, expired session,
        # initial sign-in). It is handled by the INFO rule
        # PSSO-PRT-INTERACTION-REQUIRED below and excluded from this HIGH
        # rule entirely. ``invalid_grant`` on its own (without PRT context)
        # is also benign on macOS SSO; we only flag it when paired with PRT
        # acquire/refresh phrasing.
        pattern=r"primary refresh token.*(fail|error|expired|invalid)|"
                r"\bPRT\b.*(fail|error|expired|invalid|missing)|"
                r"acquire(_| )prt.*(fail|error)|"
                r"refresh(_| )prt.*(fail|error)",
        exclude_pattern=r"requires user interaction",
        severity=Severity.HIGH,
        title="Platform SSO token / Primary Refresh Token errors",
        description="The SSO broker could not acquire or refresh the Primary "
                    "Refresh Token (PRT), so single sign-on and device-based "
                    "Conditional Access break for the user.",
        recommendation="Confirm the user can sign in to Entra ID, that the "
                       "device registration is healthy (`app-sso platform -s`), "
                       "and that no Conditional Access policy is blocking the "
                       "device.",
        remediation_steps=(
            "Have the user sign in to `https://myaccount.microsoft.com` "
            "interactively to refresh the credential.",
            "Run `app-sso platform -s` to confirm the device registration is "
            "**Active** and the PRT exists.",
            "Review Entra ▸ **Sign-in logs** for the user — a Conditional "
            "Access block (require compliant device, require MFA, etc.) "
            "explains a stuck PRT.",
            "If PRT refresh keeps failing despite Active registration, reset "
            "the credential: `app-sso platform -d` then re-register from "
            "Company Portal.",
        ),
        category="Authentication",
        docs_url=f"{D}/entra/identity/devices/troubleshoot-mac-sso-extension-plugin",
    ),
    Rule(
        id="PSSO-PRT-INTERACTION-REQUIRED",
        source=Source.PSSO,
        # ``Token request with PRT requires user interaction`` (with or
        # without a trailing ``: invalid_grant``) is emitted by the SSO
        # broker every time it needs an interactive step — Conditional
        # Access satisfaction, MFA prompt, expired session, initial
        # sign-in, etc. The PRT itself is healthy. This is INFO so it
        # doesn't dent the health score and is dropped from client-facing
        # reports, while still being visible to engineers in technical mode.
        pattern=r"\bPRT\b.*requires user interaction|"
                r"requires user interaction.*\bPRT\b",
        severity=Severity.INFO,
        title="Platform SSO — interactive sign-in required (expected)",
        description="The SSO broker logged that a token request needs an "
                    "interactive step (Conditional Access satisfaction, MFA "
                    "prompt, expired session, initial sign-in). This is the "
                    "normal protocol signal Entra ID returns whenever a "
                    "silent token cannot be issued; the Primary Refresh "
                    "Token itself is intact and no action is required.",
        recommendation="No action required. Investigate only if users report "
                       "being prompted far more often than the CA / "
                       "sign-in-frequency policy intends.",
        remediation_steps=(
            "If prompt cadence seems wrong, open Entra ▸ **Sign-in logs** "
            "for the user and confirm which policy is triggering the "
            "interactive step.",
            "Review session controls (sign-in frequency, persistent browser "
            "session) on the matching Conditional Access policy.",
        ),
        category="Authentication",
        docs_url=f"{D}/entra/identity/devices/troubleshoot-macos-platform-single-sign-on-extension",
        false_positive_note=(
            "These lines are 100% normal — they appear every time the broker "
            "needs an interactive step. Suppress with "
            "`--ignore PSSO-PRT-INTERACTION-REQUIRED` if you don't want them "
            "in the report at all."),
    ),
    Rule(
        id="PSSO-ASSOCIATED-DOMAIN",
        source=Source.PSSO,
        pattern=r"associated domain.*(fail|error|not approved)|"
                r"\b(swcd|swcutil)\b.*(fail|error)|"
                r"apple-app-site-association.*(fail|error|denied)|"
                r"(login\.microsoftonline\.com|cdn-apple\.com).*(fail|error|denied)",
        severity=Severity.MEDIUM,
        title="Associated-domain validation failures (likely TLS inspection)",
        description="The associated-domain check used by the SSO extension "
                    "failed. This commonly indicates TLS/HTTPS interception "
                    "breaking validation of Apple's app-site-association or "
                    "Microsoft login domains.",
        recommendation="Exempt *.cdn-apple.com, *.networking.apple and "
                       "login.microsoftonline.com from TLS inspection; reset "
                       "with `sudo killall swcd` then `sudo swcutil reset`.",
        category="Connectivity",
        docs_url=f"{D}/entra/identity/devices/troubleshoot-mac-sso-extension-plugin",
    ),
    Rule(
        id="PSSO-PASSWORD-SYNC",
        source=Source.PSSO,
        pattern=r"password (sync|synchroni[sz]ation).*(fail|error)|"
                r"failed to (sync|synchroni[sz]e) (the )?password|"
                r"passcode policy.*(mismatch|complexity)|"
                r"per-?user mfa",
        severity=Severity.MEDIUM,
        title="Platform SSO password synchronization failures",
        description="Password sync between Microsoft Entra ID and the local "
                    "account failed. Common causes are a local passcode policy "
                    "stricter than the Entra password, per-user MFA on the "
                    "account, or temporary passwords from a reset.",
        recommendation="Align the MDM passcode-complexity policy with Entra "
                       "password rules, replace per-user MFA with Conditional "
                       "Access MFA, and have users complete resets via the SSO "
                       "extension prompt.",
        category="Authentication",
        docs_url=f"{D}/entra/identity/devices/"
                 "troubleshoot-macos-platform-single-sign-on-extension",
    ),
]
