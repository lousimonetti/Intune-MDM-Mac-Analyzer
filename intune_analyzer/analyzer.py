"""The analysis engine.

Turns collected :class:`LogEntry` objects into :class:`Finding` objects via:

1. **Signature rules** (:mod:`intune_analyzer.rules`) - pattern matches
   collapsed per rule, with evidence samples and counts.
2. **Aggregate heuristics** - things you can only see across the whole data
   set: missing data sources, high error ratios, stale logs, and positive
   "opportunity for improvement" observations.
"""

from __future__ import annotations

import datetime as _dt

from . import cis as cis_module
from .collector import CollectionResult
from .models import (AnalysisResult, Finding, Level, Severity, Source,
                     SourceSummary)
from .rules import RULES

# Maximum evidence snippets stored per finding.
MAX_EVIDENCE = 5

# All sources we expect to find something for; absence is itself a signal.
EXPECTED_SOURCES = [Source.INTUNE, Source.DEFENDER, Source.AUTOUPDATE]


class Analyzer:
    def __init__(self, *, client_facing: bool = False):
        # client_facing trims noisy INFO-level opportunity findings.
        self.client_facing = client_facing

    def analyze(self, collection: CollectionResult, *,
                hostname: str = "", input_path: str = "",
                device_info: dict[str, str] | None = None) -> AnalysisResult:
        result = AnalysisResult(
            hostname=hostname,
            input_path=input_path,
            device_info=device_info or {},
            summaries=collection.summary_list(),
            entries=collection.entries,
        )
        findings: list[Finding] = []
        findings.extend(self._apply_rules(collection.entries))
        findings.extend(self._aggregate(result))
        # Sort: highest severity first, then by count desc.
        findings.sort(key=lambda f: (-f.severity.rank, -f.count, f.id))
        # CIS Level 1 validation runs on the full finding set (before the
        # client-facing trim) so the KPI is identical in both modes.
        result.cis = cis_module.evaluate(
            findings, result.entries,
            {s.source for s in result.summaries})
        if self.client_facing:
            findings = [f for f in findings if f.severity != Severity.INFO]
        result.findings = findings
        return result

    # ------------------------------------------------------------------ #
    # Signature rules
    # ------------------------------------------------------------------ #
    def _apply_rules(self, entries) -> list[Finding]:
        out: list[Finding] = []
        for rule in RULES:
            rx = rule.regex()
            matches = []
            for e in entries:
                if rule.source is not None and e.source != rule.source:
                    continue
                hay = e.raw or e.message
                if rx.search(hay):
                    matches.append(e)
            if not matches:
                continue
            evidence = []
            for e in matches[:MAX_EVIDENCE]:
                ts = e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "?"
                snippet = (e.message or e.raw).strip()
                if len(snippet) > 200:
                    snippet = snippet[:197] + "..."
                loc = f" [{e.file.split('/')[-1]}:{e.line_no}]" if e.file else ""
                evidence.append(f"{ts}{loc}  {snippet}")
            out.append(Finding(
                id=rule.id,
                severity=rule.severity,
                source=rule.source or matches[0].source,
                title=rule.title,
                description=rule.description,
                recommendation=rule.recommendation,
                category=rule.category,
                count=len(matches),
                evidence=evidence,
                docs_url=rule.docs_url,
            ))
        return out

    # ------------------------------------------------------------------ #
    # Aggregate heuristics
    # ------------------------------------------------------------------ #
    def _aggregate(self, result: AnalysisResult) -> list[Finding]:
        out: list[Finding] = []
        summaries = {s.source: s for s in result.summaries}

        # 1. Missing expected data sources.
        for src in EXPECTED_SOURCES:
            if src not in summaries:
                out.append(Finding(
                    id=f"NODATA-{src.name}",
                    severity=Severity.LOW,
                    source=src,
                    title=f"No {src.value} logs found",
                    description=f"No log data was discovered for {src.value}. "
                                "This may mean the component is not installed, "
                                "logs were not collected, or logging is "
                                "disabled.",
                    recommendation=f"Confirm {src.value} is deployed and that "
                                   "its logs were included in the collection.",
                    category="Coverage",
                ))

        # 2. High error ratio per source.
        for summ in result.summaries:
            total = max(summ.lines_parsed, 1)
            ratio = summ.errors / total
            if summ.errors >= 5 and ratio >= 0.15:
                out.append(Finding(
                    id=f"ERRORRATE-{summ.source.name}",
                    severity=Severity.MEDIUM,
                    source=summ.source,
                    title=f"Elevated error rate in {summ.source.value}",
                    description=f"{summ.errors} of {summ.lines_parsed} parsed "
                                f"lines ({ratio:.0%}) were errors.",
                    recommendation="Investigate the dominant error pattern; a "
                                   "high sustained error rate usually points to "
                                   "a single root cause worth fixing first.",
                    category="Reliability",
                ))

        # 3. Stale logs (last activity well in the past).
        now = _dt.datetime.now()
        for summ in result.summaries:
            if summ.last_seen and (now - summ.last_seen) > _dt.timedelta(days=7):
                age = (now - summ.last_seen).days
                out.append(Finding(
                    id=f"STALE-{summ.source.name}",
                    severity=Severity.LOW,
                    source=summ.source,
                    title=f"{summ.source.value} logs are {age} days old",
                    description=f"The most recent {summ.source.value} entry is "
                                f"{age} days old, so this report may not "
                                "reflect the device's current state.",
                    recommendation="Re-collect fresh logs to confirm the "
                                   "current health of this component.",
                    category="Coverage",
                ))

        # 4. Opportunities / positive confirmations (suppressed in client mode).
        out.extend(self._opportunities(result, summaries))
        return out

    def _opportunities(self, result: AnalysisResult,
                       summaries: dict[Source, SourceSummary]) -> list[Finding]:
        out: list[Finding] = []
        # If Defender present, surface a tuning opportunity.
        if Source.DEFENDER in summaries:
            out.append(Finding(
                id="OPP-DEFENDER-REVIEW",
                severity=Severity.INFO,
                source=Source.DEFENDER,
                title="Review Defender exclusions and performance tuning",
                description="Defender logs are present. Even when healthy, "
                            "real-time-protection scan hotspots are a common "
                            "optimisation opportunity on developer Macs.",
                recommendation="Use real-time-protection statistics to find the "
                               "top scanned paths and add targeted exclusions.",
                category="Optimization",
                docs_url="https://learn.microsoft.com/defender-endpoint/mac-support-perf",
            ))
        if Source.AUTOUPDATE in summaries:
            out.append(Finding(
                id="OPP-MAU-CHANNEL",
                severity=Severity.INFO,
                source=Source.AUTOUPDATE,
                title="Confirm a managed MAU update channel",
                description="Standardising the Microsoft AutoUpdate channel "
                            "(e.g. Current) across the fleet reduces version "
                            "drift and support variance.",
                recommendation="Deploy a com.microsoft.autoupdate2 configuration "
                               "profile pinning the channel and enabling "
                               "automatic updates.",
                category="Optimization",
            ))
        if Source.PSSO in summaries:
            out.append(Finding(
                id="OPP-PSSO-METHOD",
                severity=Severity.INFO,
                source=Source.PSSO,
                title="Confirm the Platform SSO authentication method",
                description="Platform SSO logs are present. Choosing Secure "
                            "Enclave (or passkey) over password authentication "
                            "strengthens the credential and unlocks phishing-"
                            "resistant sign-in.",
                recommendation="Review the settings-catalog SSO profile's "
                               "authentication method and enable Keyvault "
                               "recovery so data is recoverable after a "
                               "password reset.",
                category="Optimization",
                docs_url="https://learn.microsoft.com/intune/device-configuration/"
                         "settings-catalog/configure-platform-sso-macos",
            ))
        if Source.INTUNE in summaries:
            out.append(Finding(
                id="OPP-INTUNE-BASELINE",
                severity=Severity.INFO,
                source=Source.INTUNE,
                title="Consider a macOS security baseline",
                description="Intune management is active. A documented security "
                            "baseline (FileVault, firewall, Gatekeeper, OS "
                            "update enforcement) makes compliance auditable.",
                recommendation="Assign a settings-catalog baseline and a "
                               "matching compliance policy if not already in "
                               "place.",
                category="Optimization",
            ))
        return out
