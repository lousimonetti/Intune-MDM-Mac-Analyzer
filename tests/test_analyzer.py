from pathlib import Path

import pytest

from intune_analyzer.analyzer import Analyzer
from intune_analyzer.collector import Collector
from intune_analyzer.models import Severity, Source
from intune_analyzer.pipeline import run_analysis

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(scope="module")
def result():
    return run_analysis(input_path=str(SAMPLES))


def test_all_sources_discovered(result):
    found = {s.source for s in result.summaries}
    for src in (Source.INTUNE, Source.DEFENDER, Source.AUTOUPDATE,
                Source.OFFICE, Source.INSTALL, Source.PSSO):
        assert src in found, f"missing {src}"


def test_key_findings_present(result):
    ids = {f.id for f in result.findings}
    for expected in {"INTUNE-AAD-TOKEN", "INTUNE-CHECKIN-FAIL",
                     "DEFENDER-UNHEALTHY", "DEFENDER-RTP-OFF",
                     "MAU-UPDATE-FAIL", "OFFICE-ACTIVATION", "INSTALL-FAIL",
                     "PSSO-REGISTER-FAIL", "PSSO-CONFIG-CORRUPT",
                     "PSSO-PRT-TOKEN"}:
        assert expected in ids, f"missing finding {expected}"


def test_findings_sorted_by_severity(result):
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_health_score_bounds(result):
    assert 0 <= result.health_score() <= 100


def test_client_mode_drops_info():
    res = run_analysis(input_path=str(SAMPLES), client_facing=True)
    assert all(f.severity != Severity.INFO for f in res.findings)


def test_evidence_capped(result):
    for f in result.findings:
        assert len(f.evidence) <= 5


def test_missing_source_flagged(tmp_path):
    # A directory with only an Intune log should flag missing Defender/MAU.
    (tmp_path / "Intune").mkdir()
    (tmp_path / "Intune" / "IntuneMDMAgent.log").write_text(
        "2026-06-10 09:00:00 | I | all good\n")
    res = run_analysis(input_path=str(tmp_path))
    ids = {f.id for f in res.findings}
    assert "NODATA-DEFENDER" in ids
    assert "NODATA-AUTOUPDATE" in ids


def test_well_known_rule_does_not_match_outlook_telemetry(tmp_path):
    # Regression: a previous regex `well-?known.*(failed|403)` falsely
    # matched Outlook telemetry whose JSON happened to contain the literal
    # ``well-known`` token and a sequence number including ``403``.
    office = tmp_path / "office"
    office.mkdir()
    (office / "Primary123_Outlook.log").write_text(
        "2026-06-10 00:22:50 OUTLOOK Telemetry Event biyhq Medium SendEvent "
        '{"EventName":"Office.Outlook.Hx.Heartbeat",'
        '"Flags":28147506277843201,'
        '"InternalSequenceNumber":40320,'
        '"WellKnownTokenName":"hx",'
        '"Time":"2026-06-10T00:22:50Z"}\n')
    # Drop in an Intune log so MDM-ENROLL-WELLKNOWN is not the only signal.
    (tmp_path / "Intune").mkdir()
    (tmp_path / "Intune" / "IntuneMDMAgent.log").write_text(
        "2026-06-10 09:00:00 | I | all good\n")
    res = run_analysis(input_path=str(tmp_path))
    ids = {f.id for f in res.findings}
    assert "MDM-ENROLL-WELLKNOWN" not in ids, (
        "well-known rule false-positive on Outlook telemetry")


def test_defender_runtime_errors_do_not_fail_install(tmp_path):
    # Regression: DEFENDER-INSTALL-FAIL used to fire on every `[error]` token
    # in any Defender log. It must only consider the actual install log.
    mdatp = tmp_path / "mdatp"
    mdatp.mkdir()
    (mdatp / "microsoft_defender_core.log").write_text(
        "[546][2026-06-15 15:26:22 UTC][error]: kernel queue full\n")
    res = run_analysis(input_path=str(tmp_path))
    ids = {f.id for f in res.findings}
    assert "DEFENDER-INSTALL-FAIL" not in ids


def test_defender_install_demoted_when_running(tmp_path):
    # Historical install errors should drop to LOW when Defender is
    # currently logging and no live health rule fired.
    mdatp = tmp_path / "mdatp"
    mdatp.mkdir()
    # An old install error.
    (mdatp / "install.log").write_text(
        "2025-01-01 09:00:00 [ERROR] preinstall failed: kext not approved\n")
    # And a current runtime log — proves the daemon is running.
    (mdatp / "microsoft_defender_core.log").write_text(
        "2026-06-15 09:00:00 [info]: scan engine ready\n")
    res = run_analysis(input_path=str(tmp_path))
    by_id = {f.id: f for f in res.findings}
    assert "DEFENDER-INSTALL-FAIL" in by_id
    assert by_id["DEFENDER-INSTALL-FAIL"].severity == Severity.LOW
    assert "currently running" in by_id["DEFENDER-INSTALL-FAIL"].title.lower()


def test_defender_install_stays_high_when_unhealthy(tmp_path):
    # If Defender is actually unhealthy, install errors keep their HIGH
    # severity — we don't want to mask a real outage.
    mdatp = tmp_path / "mdatp"
    mdatp.mkdir()
    (mdatp / "install.log").write_text(
        "2026-06-14 12:00:00 [ERROR] installation failed\n")
    (mdatp / "microsoft_defender.log").write_text(
        "2026-06-15 09:00:00 [info]: healthy: false\n")
    res = run_analysis(input_path=str(tmp_path))
    by_id = {f.id: f for f in res.findings}
    assert "DEFENDER-UNHEALTHY" in by_id
    assert by_id["DEFENDER-INSTALL-FAIL"].severity == Severity.HIGH


def test_packagekit_hosted_team_is_low_not_high(tmp_path):
    # "Failed to set hosted team responsibility" must surface as its own
    # LOW-severity finding (packaging quality signal), not as a HIGH
    # INSTALL-FAIL.
    (tmp_path / "install.log").write_text(
        "2026-06-05 15:47:49 MAC installer[6359]: "
        "PackageKit: Failed to set hosted team responsibility for install "
        "to team:(UL6CGN7MAL)\n")
    res = run_analysis(input_path=str(tmp_path))
    by_id = {f.id: f for f in res.findings}
    assert "INSTALL-FAIL" not in by_id, "must not flip to a HIGH install failure"
    assert "INSTALL-TEAM-RESPONSIBILITY" in by_id
    assert by_id["INSTALL-TEAM-RESPONSIBILITY"].severity == Severity.LOW


def test_since_hours_drops_old_dated_entries_keeps_undated(tmp_path):
    # Opt-in time window: dated entries older than the cutoff are dropped;
    # undated lines (e.g. multi-line continuations) are retained so keyword
    # rules still see them.
    import datetime as _dt
    intune = tmp_path / "Intune"
    intune.mkdir()
    now = _dt.datetime.now()
    recent = now - _dt.timedelta(hours=1)
    old = now - _dt.timedelta(hours=48)
    (intune / "IntuneMDMAgent.log").write_text(
        f"{old.strftime('%Y-%m-%d %H:%M:%S')}.000 | IntuneMDMAgent | 1 | E | "
        "Failed to apply configuration profile 'Old-Stale-Policy'\n"
        f"{recent.strftime('%Y-%m-%d %H:%M:%S')}.000 | IntuneMDMAgent | 1 | E | "
        "Application install failed for 'Recent App': download failed\n"
        "    continuation line with no timestamp — undated\n")
    # Without the window, both errors should drive their rules.
    base = run_analysis(input_path=str(intune))
    assert "INTUNE-POLICY-FAIL" in {f.id for f in base.findings}
    assert "INTUNE-APP-INSTALL-FAIL" in {f.id for f in base.findings}
    # With a 24h window, the old policy-fail line is gone, the recent
    # app-install one stays, and window metadata is set.
    scoped = run_analysis(input_path=str(intune), since_hours=24)
    ids = {f.id for f in scoped.findings}
    assert "INTUNE-APP-INSTALL-FAIL" in ids
    assert "INTUNE-POLICY-FAIL" not in ids
    assert scoped.window_hours == 24
    assert scoped.window_since is not None


def test_errorrate_finding_surfaces_top_defender_patterns(tmp_path):
    # The aggregate ERRORRATE finding must (a) actually list the dominant
    # error patterns instead of telling the user to "investigate", and
    # (b) hand back Defender-specific remediation commands when the source
    # is Defender.
    mdatp = tmp_path / "mdatp"
    mdatp.mkdir()
    lines = []
    # 8 copies of the same connectivity error (varying timestamps/PIDs).
    for i in range(8):
        lines.append(f"2026-06-15 12:00:{i:02d} [ERROR] [WCD] "
                     f"Connection refused to events.data.microsoft.com "
                     f"(pid={1000+i})")
    # 4 copies of a different error pattern.
    for i in range(4):
        lines.append(f"2026-06-15 12:01:{i:02d} [ERROR] [Definitions] "
                     f"signature update failed (code={300+i})")
    # A couple of healthy lines so the ratio is realistic but still > 15%.
    for i in range(3):
        lines.append(f"2026-06-15 12:02:{i:02d} [INFO] mdatp health "
                     f"refreshed")
    (mdatp / "mdatp_health.log").write_text("\n".join(lines) + "\n")
    res = run_analysis(input_path=str(tmp_path))
    by_id = {f.id: f for f in res.findings}
    assert "ERRORRATE-DEFENDER" in by_id, by_id.keys()
    f = by_id["ERRORRATE-DEFENDER"]
    # Top pattern dominates and is named explicitly in the description.
    assert "Connection refused" in f.description
    # Both patterns surface as impacted items, collapsed across pid/code.
    assert any("Connection refused" in p for p in f.impacted)
    assert any("signature update failed" in p for p in f.impacted)
    # Defender-specific remediation, not the old generic line.
    assert "mdatp health" in " ".join(f.remediation_steps)
    assert "investigate the dominant error pattern" not in f.recommendation.lower()


def test_apps_and_office_penalties_are_capped():
    # Pile up enough Apps + Office findings to blow past the caps; the
    # health score must still reflect *at most* APPS_PENALTY_CAP +
    # OFFICE_PENALTY_CAP from these two groups combined.
    from intune_analyzer.models import AnalysisResult, Finding, Severity, Source
    apps_findings = [
        Finding(id=f"APP-{i}", severity=Severity.HIGH, source=Source.INTUNE,
                title="x", description="x", recommendation="x",
                category="Apps")
        for i in range(5)  # 5 * 12 = 60 raw, capped to 15
    ]
    office_findings = [
        Finding(id=f"OFF-{i}", severity=Severity.MEDIUM, source=Source.OFFICE,
                title="x", description="x", recommendation="x",
                category="Licensing")
        for i in range(4)  # 4 * 5 = 20 raw, capped to 8
    ]
    res = AnalysisResult(findings=apps_findings + office_findings)
    # Capped total penalty = 15 + 8 = 23; score = 100 - 23 = 77.
    assert res.health_score() == 77


def test_intune_app_install_fail_extracts_app_names(tmp_path):
    # The finding must identify *which* apps are failing, not just say
    # "something failed". Names are extracted from quoted tokens in the
    # Intune agent log.
    intune = tmp_path / "Intune"
    intune.mkdir()
    (intune / "IntuneMDMAgent.log").write_text(
        "2026-06-10 09:15:45.660 | IntuneMDMAgent | 4821 | E | "
        "Application install failed for 'Acme VPN Client': "
        "downgrade not supported, newer version already installed\n"
        "2026-06-10 09:16:01.110 | IntuneMDMAgent | 4821 | E | "
        "Application install failed for 'Globex Antivirus': "
        "package download failed\n"
        "2026-06-10 09:16:30.500 | IntuneMDMAgent | 4821 | E | "
        "Application install failed for 'Acme VPN Client': retrying\n")
    res = run_analysis(input_path=str(intune))
    by_id = {f.id: f for f in res.findings}
    assert "INTUNE-APP-INSTALL-FAIL" in by_id
    finding = by_id["INTUNE-APP-INSTALL-FAIL"]
    assert finding.subject_label == "Apps"
    # Two distinct apps, deduplicated, order preserved.
    assert finding.impacted == ["Acme VPN Client", "Globex Antivirus"]


def test_ignore_flag_suppresses_finding(tmp_path):
    mdatp = tmp_path / "mdatp"
    mdatp.mkdir()
    (mdatp / "install.log").write_text(
        "2026-06-15 12:00:00 [ERROR] installation failed: missing kext\n")
    base = run_analysis(input_path=str(tmp_path))
    assert "DEFENDER-INSTALL-FAIL" in {f.id for f in base.findings}
    suppressed = run_analysis(input_path=str(tmp_path),
                              ignore={"DEFENDER-INSTALL-FAIL"})
    assert "DEFENDER-INSTALL-FAIL" not in {f.id for f in suppressed.findings}
    assert "DEFENDER-INSTALL-FAIL" in suppressed.ignored


def test_empty_input(tmp_path):
    res = run_analysis(input_path=str(tmp_path))
    # No data => perfect-ish score but coverage findings exist.
    assert res.total_lines == 0
    assert any(f.id.startswith("NODATA-") for f in res.findings)
