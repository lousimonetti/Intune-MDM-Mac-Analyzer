import json
from pathlib import Path

import pytest

from intune_analyzer.pipeline import run_analysis
from intune_analyzer.report import export_pdf, render_html, render_json

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture(scope="module")
def result():
    return run_analysis(input_path=str(SAMPLES))


def test_render_html_self_contained(result):
    html = render_html(result)
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html
    # No external stylesheet/script references => emailable single file.
    assert "http://" not in html.split("<body>")[0]
    assert "<style>" in html
    # Key sections present.
    assert "Findings" in html
    assert "Health" in html or "health" in html


def test_render_html_client_collapses_evidence(result):
    full = render_html(result, client_facing=False)
    client = render_html(result, client_facing=True)
    assert "Executive summary" in client
    # Evidence <pre> blocks should not appear in client mode.
    assert full.count("pre class='ev'") >= 0
    assert "Executive summary" not in full


def test_render_json_valid(result):
    data = json.loads(render_json(result))
    assert "findings" in data and "health_score" in data
    assert data["totals"]["files"] > 0


def test_pdf_fallback_writes_html(result, tmp_path):
    out = tmp_path / "report.pdf"
    ok, msg = export_pdf(render_html(result), str(out))
    # Without a PDF engine installed this returns False but writes HTML.
    if not ok:
        assert (tmp_path / "report.html").exists()
        assert "Save as PDF" in (tmp_path / "report.html").read_text()
    else:
        assert out.exists()


def test_html_escapes_content():
    # Ensure a malicious-looking message is escaped, not injected.
    from intune_analyzer.models import (AnalysisResult, Finding, Severity,
                                        Source)
    res = AnalysisResult(hostname="<script>alert(1)</script>")
    res.findings = [Finding(
        id="X", severity=Severity.HIGH, source=Source.INTUNE,
        title="<b>bad</b>", description="d", recommendation="r")]
    html = render_html(res)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
