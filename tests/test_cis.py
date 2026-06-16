from pathlib import Path

from intune_analyzer import cis
from intune_analyzer.models import (CISCheckResult, CISReport, Finding, Level,
                                    LogEntry, Severity, Source)
from intune_analyzer.pipeline import run_analysis

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _check(status):
    return CISCheckResult(id="X", title="t", section="s", status=status,
                          rationale="r", remediation="m")


def test_score_banding_green_yellow_red():
    # 20 pass / 0 fail -> 100% green
    rep = CISReport(checks=[_check("pass")] * 20)
    assert rep.score() == 100 and rep.status() == "green"
    # 8 pass / 2 fail -> 80% yellow
    rep = CISReport(checks=[_check("pass")] * 8 + [_check("fail")] * 2)
    assert rep.score() == 80 and rep.status() == "yellow"
    # exactly 95 -> green (boundary)
    rep = CISReport(checks=[_check("pass")] * 19 + [_check("fail")])
    assert rep.score() == 95 and rep.status() == "green"
    # 7 pass / 3 fail -> 70% red
    rep = CISReport(checks=[_check("pass")] * 7 + [_check("fail")] * 3)
    assert rep.score() == 70 and rep.status() == "red"


def test_not_assessed_excluded_from_score():
    rep = CISReport(checks=[_check("pass"), _check("fail")]
                    + [_check("not-assessed")] * 8)
    # Only 2 assessable; 1 passes -> 50%.
    assert rep.assessed == 2 and rep.score() == 50
    assert rep.not_assessed == 8 and rep.total == 10


def test_no_assessable_controls_is_red():
    rep = CISReport(checks=[_check("not-assessed")] * 5)
    assert rep.score() == 0 and rep.status() == "red"


def _entry(msg):
    return LogEntry(source=Source.SYSTEM, level=Level.INFO, message=msg, raw=msg)


def test_evaluate_pass_if_source_and_finding_fail():
    # Defender present, no failing finding -> CIS-6.3 reports CONFIGURED
    # (governing source present, no contrary evidence). Both "pass" and
    # "configured" count toward the passed total.
    rep = cis.evaluate([], [], {Source.DEFENDER})
    by_id = {c.id: c for c in rep.checks}
    assert by_id["CIS-6.3"].status == "configured"
    assert by_id["CIS-6.3"].confidence == "low"
    assert rep.passed >= 1  # configured counts toward the pass total
    # A Defender health finding flips it to fail.
    f = Finding(id="DEFENDER-UNHEALTHY", severity=Severity.CRITICAL,
                source=Source.DEFENDER, title="unhealthy", description="d",
                recommendation="r", evidence=["2026-01-01  healthy: false"])
    rep = cis.evaluate([f], [], {Source.DEFENDER})
    by_id = {c.id: c for c in rep.checks}
    assert by_id["CIS-6.3"].status == "fail"
    assert by_id["CIS-6.3"].evidence  # carries the finding evidence


def test_transient_finding_demotes_fail_to_configured():
    # When a transient SWUPDATE-FAIL is the only signal, the FAIL verdict
    # for CIS-1.1 must be demoted to CONFIGURED (self-healing retry, not a
    # real policy break).
    f = Finding(id="SWUPDATE-FAIL", severity=Severity.LOW,
                source=Source.SYSTEM, title="macOS update transient failure",
                description="d", recommendation="r",
                evidence=["2026-06-05  retry softwareupdated -1100"],
                transient=True)
    rep = cis.evaluate([f], [], {Source.SYSTEM})
    by_id = {c.id: c for c in rep.checks}
    assert by_id["CIS-1.1"].status == "configured"
    assert by_id["CIS-1.1"].status != "fail"


def test_ignore_suppresses_finding_and_control():
    # Suppress a fail finding -> the control should not fail because of it.
    f = Finding(id="DEFENDER-UNHEALTHY", severity=Severity.CRITICAL,
                source=Source.DEFENDER, title="unhealthy", description="d",
                recommendation="r")
    rep = cis.evaluate([f], [], {Source.DEFENDER},
                       ignore={"DEFENDER-UNHEALTHY"})
    by_id = {c.id: c for c in rep.checks}
    assert by_id["CIS-6.3"].status != "fail"
    # Suppress the control itself.
    rep = cis.evaluate([], [], {Source.DEFENDER}, ignore={"CIS-6.3"})
    by_id = {c.id: c for c in rep.checks}
    assert by_id["CIS-6.3"].status == "not-assessed"


def test_unrelated_log_does_not_fail_autologin_or_gatekeeper():
    # MSAL feature-flag probe contains the literal substring ``autologin``.
    # It must not fail CIS-2.11 because the line is from PSSO logs and
    # the regex is word-bounded.
    msal_line = ("Checking for feature flag "
                 "disable_explicit_app_prompt_and_autologin, value in "
                 "config (null), value type (null)")
    psso_entry = LogEntry(source=Source.PSSO, level=Level.INFO,
                          message=msal_line, raw=msal_line)
    # Defender kernel-queue warning includes ``dropped pktseq`` — must not
    # fail Gatekeeper (CIS-2.5.2).
    def_line = ("Kernel message queue full, dropped pktseq: "
                "[9267650,9267651,9267652]")
    def_entry = LogEntry(source=Source.DEFENDER, level=Level.WARNING,
                         message=def_line, raw=def_line)
    rep = cis.evaluate([], [psso_entry, def_entry],
                       {Source.PSSO, Source.DEFENDER})
    by_id = {c.id: c.status for c in rep.checks}
    assert by_id["CIS-2.11"] == "not-assessed"
    assert by_id["CIS-2.5.2"] == "not-assessed"


def test_evaluate_pattern_pass_fail_and_not_assessed():
    fail = cis.evaluate([], [_entry("FileVault is not enabled")], set())
    assert {c.id: c.status for c in fail.checks}["CIS-2.5.1"] == "fail"

    ok = cis.evaluate([], [_entry("FileVault is enabled")], set())
    assert {c.id: c.status for c in ok.checks}["CIS-2.5.1"] == "pass"

    # No signal at all -> gatekeeper not assessed.
    none = cis.evaluate([], [], set())
    assert {c.id: c.status for c in none.checks}["CIS-2.5.2"] == "not-assessed"


def test_cis_1_1_passes_on_ddm_softwareupdate_payload():
    # Policy-enforcement check: the DDM software-update declaration shows up
    # in system_profiler -> PASS.
    marker = LogEntry(
        source=Source.SYSTEM, level=Level.INFO,
        message="system_profiler SPConfigurationProfileDataType collected",
        raw="system_profiler:SPConfigurationProfileDataType:collected",
        file="<system_profiler SPConfigurationProfileDataType>",
    )
    payload = LogEntry(
        source=Source.SYSTEM, level=Level.INFO,
        message="PayloadType: com.apple.configuration.softwareupdate."
                "enforcement.specific",
        raw="PayloadType: com.apple.configuration.softwareupdate."
            "enforcement.specific",
        file="<system_profiler SPConfigurationProfileDataType>",
    )
    rep = cis.evaluate([], [marker, payload], {Source.SYSTEM})
    assert {c.id: c.status for c in rep.checks}["CIS-1.1"] == "pass"


def test_cis_1_1_fails_when_system_profiler_collected_but_no_payload():
    # Ground-truth marker fires but no software-update payload is present
    # in the system_profiler dump -> policy is provably not enforced ->
    # FAIL (not "not-assessed").
    marker = LogEntry(
        source=Source.SYSTEM, level=Level.INFO,
        message="system_profiler SPConfigurationProfileDataType collected",
        raw="system_profiler:SPConfigurationProfileDataType:collected",
        file="<system_profiler SPConfigurationProfileDataType>",
    )
    rep = cis.evaluate([], [marker], {Source.SYSTEM})
    assert {c.id: c.status for c in rep.checks}["CIS-1.1"] == "fail"


def test_cis_1_1_not_assessed_without_system_profiler_evidence():
    # Offline bundle without a system_profiler dump -> control is honestly
    # not-assessed (not falsely PASS, not falsely FAIL).
    rep = cis.evaluate([], [], set())
    assert {c.id: c.status for c in rep.checks}["CIS-1.1"] == "not-assessed"


def test_cis_1_2_passes_on_autoupdate2_payload():
    marker = LogEntry(
        source=Source.SYSTEM, level=Level.INFO,
        message="system_profiler SPConfigurationProfileDataType collected",
        raw="system_profiler:SPConfigurationProfileDataType:collected",
        file="<system_profiler SPConfigurationProfileDataType>",
    )
    payload = LogEntry(
        source=Source.SYSTEM, level=Level.INFO,
        message="PayloadIdentifier: com.microsoft.autoupdate2.policy",
        raw="PayloadIdentifier: com.microsoft.autoupdate2.policy",
        file="<system_profiler SPConfigurationProfileDataType>",
    )
    rep = cis.evaluate([], [marker, payload], {Source.SYSTEM})
    assert {c.id: c.status for c in rep.checks}["CIS-1.2"] == "pass"


def test_cis_1_2_fails_when_autoupdate2_profile_absent():
    marker = LogEntry(
        source=Source.SYSTEM, level=Level.INFO,
        message="system_profiler SPConfigurationProfileDataType collected",
        raw="system_profiler:SPConfigurationProfileDataType:collected",
        file="<system_profiler SPConfigurationProfileDataType>",
    )
    rep = cis.evaluate([], [marker], {Source.SYSTEM})
    assert {c.id: c.status for c in rep.checks}["CIS-1.2"] == "fail"


def test_collector_extracts_marker_and_relevant_payloads_only():
    # The system_profiler dump is large; we must ingest *only* a single
    # marker line + the lines that prove a relevant payload is installed.
    # Unrelated profiles (firewall, generic MDM) must not be ingested.
    from intune_analyzer.collector import Collector
    dump = (
        "Configuration Profiles:\n"
        "    Name: Intune MDM Profile\n"
        "    PayloadType: com.apple.mdm\n"
        "    Name: macOS Update Enforcement\n"
        "    PayloadType: com.apple.configuration.softwareupdate."
        "enforcement.specific\n"
        "    TargetOSVersion: 14.5\n"
        "    TargetLocalDateTime: 2026-07-01T18:00:00\n"
        "    Name: MAU Auto-Update\n"
        "    PayloadIdentifier: com.microsoft.autoupdate2.policy\n"
        "    HowToCheck: AutomaticDownload\n"
        "    Name: Firewall Baseline\n"
        "    PayloadType: com.apple.security.firewall\n"
    )
    c = Collector()
    c._ingest_ddm_softwareupdate_evidence(dump, file="<system_profiler>")
    sources = {e.source for e in c.result.entries}
    assert sources == {Source.SYSTEM}
    # 1 marker + 1 DDM softwareupdate line + 1 autoupdate2 line = 3. The
    # declaration is well-formed so no missing-key error entries appear.
    # Firewall and generic MDM lines must NOT be ingested.
    assert len(c.result.entries) == 3
    msgs = " | ".join(e.message for e in c.result.entries)
    assert "SPConfigurationProfileDataType collected" in msgs
    assert "softwareupdate.enforcement.specific" in msgs
    assert "com.microsoft.autoupdate2" in msgs
    assert "firewall" not in msgs.lower()
    err = [e for e in c.result.entries if e.level.value == "error"]
    assert err == []


def test_collector_emits_missing_key_error_for_incomplete_declaration():
    # When a softwareupdate.enforcement.specific PayloadType is present but
    # neither TargetOSVersion nor TargetLocalDateTime appears in the
    # surrounding lines, the collector must emit an ERROR-level synthetic
    # entry per missing required key. Apple's schema flags both as required:
    # github.com/apple/device-management/.../softwareupdate.enforcement.specific.yaml
    from intune_analyzer.collector import Collector
    dump = (
        "Configuration Profiles:\n"
        "    Name: macOS Update Enforcement\n"
        "    PayloadType: com.apple.configuration.softwareupdate."
        "enforcement.specific\n"
        "    DetailsURL: https://example.com\n"
        "    (declaration body is incomplete here)\n"
    )
    c = Collector()
    c._ingest_ddm_softwareupdate_evidence(dump, file="<system_profiler>")
    err_entries = [e for e in c.result.entries if e.level.value == "error"]
    assert len(err_entries) == 2
    missing = {e.raw for e in err_entries}
    assert any("TargetOSVersion" in r for r in missing)
    assert any("TargetLocalDateTime" in r for r in missing)


def test_collector_does_not_flag_complete_declaration():
    # A well-formed declaration with both required keys present must NOT
    # emit any error entries.
    from intune_analyzer.collector import Collector
    dump = (
        "Configuration Profiles:\n"
        "    Name: macOS Update Enforcement\n"
        "    PayloadType: com.apple.configuration.softwareupdate."
        "enforcement.specific\n"
        "    TargetOSVersion: 14.5\n"
        "    TargetLocalDateTime: 2026-07-01T18:00:00\n"
        "    DetailsURL: https://example.com\n"
    )
    c = Collector()
    c._ingest_ddm_softwareupdate_evidence(dump, file="<system_profiler>")
    err_entries = [e for e in c.result.entries if e.level.value == "error"]
    assert err_entries == []


def test_swupdate_fail_decodes_human_reasons(tmp_path):
    # SWUPDATE-FAIL evidence should be decoded through the Apple-DDM
    # failure-reason table so the report shows human-readable causes.
    install = tmp_path / "system"
    install.mkdir()
    (install / "install.log").write_text(
        "Jun 15 12:00:01 mac softwareupdated[101]: "
        "softwareupdate.failure-reason: download-failed\n"
        "Jun 15 12:00:02 mac softwareupdated[101]: "
        "softwareupdate.failure-reason: install-failed\n"
    )
    res = run_analysis(input_path=str(install))
    by_id = {f.id: f for f in res.findings}
    assert "SWUPDATE-FAIL" in by_id
    f = by_id["SWUPDATE-FAIL"]
    assert f.subject_label == "Failure reasons"
    joined = " | ".join(f.impacted)
    assert "Download failed" in joined
    assert "Install failed" in joined


def test_collector_emits_marker_even_when_no_payload_found():
    # Empty profile inventory still emits the ground-truth marker so the
    # evaluator can flip CIS-1.1 / CIS-1.2 to FAIL (policy not enforced).
    from intune_analyzer.collector import Collector
    dump = "Configuration Profiles:\n    (none)\n"
    c = Collector()
    c._ingest_ddm_softwareupdate_evidence(dump, file="<system_profiler>")
    assert len(c.result.entries) == 1
    assert "SPConfigurationProfileDataType collected" in c.result.entries[0].message


def test_analysis_result_has_cis_and_client_mode_matches():
    res = run_analysis(input_path=str(SAMPLES))
    assert res.cis is not None
    assert 0 <= res.cis.score() <= 100
    assert res.cis.total == len(cis.CIS_LEVEL1)
    # CIS KPI must be identical regardless of client-facing trimming.
    client = run_analysis(input_path=str(SAMPLES), client_facing=True)
    assert client.cis.score() == res.cis.score()
    assert client.cis.status() == res.cis.status()
