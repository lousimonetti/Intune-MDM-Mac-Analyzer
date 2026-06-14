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


def test_empty_input(tmp_path):
    res = run_analysis(input_path=str(tmp_path))
    # No data => perfect-ish score but coverage findings exist.
    assert res.total_lines == 0
    assert any(f.id.startswith("NODATA-") for f in res.findings)
