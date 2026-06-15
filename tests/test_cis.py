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
    # MAU is configured (logs present); the only signal is a transient
    # download failure — control should land at CONFIGURED, not FAIL.
    f = Finding(id="MAU-UPDATE-FAIL", severity=Severity.LOW,
                source=Source.AUTOUPDATE, title="MAU update failure",
                description="d", recommendation="r",
                evidence=["2026-06-05  download failed -1100"],
                transient=True)
    # Note: in the current CIS spec MAU-UPDATE-FAIL is no longer a fail
    # mapping for CIS-1.2 (we treat MAU presence as the control); confirm
    # the result is configured, not fail.
    rep = cis.evaluate([f], [], {Source.AUTOUPDATE})
    by_id = {c.id: c for c in rep.checks}
    assert by_id["CIS-1.2"].status == "configured"
    assert by_id["CIS-1.2"].status != "fail"


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


def test_analysis_result_has_cis_and_client_mode_matches():
    res = run_analysis(input_path=str(SAMPLES))
    assert res.cis is not None
    assert 0 <= res.cis.score() <= 100
    assert res.cis.total == len(cis.CIS_LEVEL1)
    # CIS KPI must be identical regardless of client-facing trimming.
    client = run_analysis(input_path=str(SAMPLES), client_facing=True)
    assert client.cis.score() == res.cis.score()
    assert client.cis.status() == res.cis.status()
