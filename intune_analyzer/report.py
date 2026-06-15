"""Report generation: enhanced self-contained HTML, JSON, and PDF export.

The HTML report is a single file with inline CSS/SVG and **no external
dependencies**, so it renders identically when emailed to a client or opened
offline. A "Save as PDF" button uses the browser's print pipeline (print CSS
included). For headless/automated PDF generation we optionally use
``weasyprint`` if it is installed, falling back to ``wkhtmltopdf`` on PATH.

A ``client_facing`` flag produces a simplified, less technical document
suitable for handing to a customer (executive summary + prioritised actions,
with raw log evidence collapsed).
"""

from __future__ import annotations

import html
import json
import shutil
import subprocess
from pathlib import Path

from .models import AnalysisResult, Severity, Source
from .version import __version__

SEV_COLORS = {
    Severity.CRITICAL: "#b00020",
    Severity.HIGH: "#e8590c",
    Severity.MEDIUM: "#f08c00",
    Severity.LOW: "#1c7ed6",
    Severity.INFO: "#5f6c7b",
}
GRADE_COLORS = {
    "Healthy": "#2f9e44",
    "Good": "#66a80f",
    "Needs Attention": "#f08c00",
    "At Risk": "#e8590c",
    "Critical": "#b00020",
}


def _e(text) -> str:
    return html.escape(str(text), quote=True)


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def render_json(result: AnalysisResult, *, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, default=str)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def render_html(result: AnalysisResult, *, client_facing: bool = False,
                title: str = "Intune macOS Health Report") -> str:
    score = result.health_score()
    grade = result.health_grade()
    grade_color = GRADE_COLORS.get(grade, "#5f6c7b")
    sev_counts = result.severity_counts()

    parts = [_HEAD.format(title=_e(title), css=_CSS),
             _header(result, title, client_facing),
             _gauge(score, grade, grade_color),
             _summary_cards(result, sev_counts),
             _severity_bar(sev_counts)]

    if result.cis is not None:
        parts.append(_cis_section(result, client_facing))

    if client_facing:
        parts.append(_exec_summary(result))

    parts.append(_findings_section(result, client_facing))
    parts.append(_sources_section(result))
    if not client_facing:
        parts.append(_coverage_section(result))
    parts.append(_footer(result))
    parts.append(_SCRIPT)
    parts.append("</body></html>")
    return "\n".join(parts)


def _header(result: AnalysisResult, title: str, client_facing: bool) -> str:
    host = _e(result.hostname or result.device_info.get("hostname", "Unknown device"))
    gen = result.generated_at.strftime("%Y-%m-%d %H:%M:%S")
    sub = "Client Report" if client_facing else "Technical Analysis"
    dev_rows = "".join(
        f"<span class='chip'>{_e(k)}: {_e(v)}</span>"
        for k, v in result.device_info.items()
    )
    return f"""
<div class="topbar">
  <div>
    <h1>{_e(title)}</h1>
    <div class="subtitle">{sub} &middot; {host}</div>
    <div class="chips">{dev_rows}</div>
  </div>
  <div class="actions">
    <button class="btn" onclick="window.print()">🖨 Save as PDF</button>
    <div class="genstamp">Generated {gen}</div>
  </div>
</div>"""


def _gauge(score: int, grade: str, color: str) -> str:
    # Simple SVG arc gauge (semi-circle) driven by score 0-100.
    import math
    frac = score / 100.0
    angle = math.pi * (1 - frac)  # pi -> 0
    cx, cy, r = 110, 110, 90
    x = cx + r * math.cos(angle)
    y = cy - r * math.sin(angle)
    large = 0
    sweep = 1
    bg_path = f"M {cx - r} {cy} A {r} {r} 0 0 1 {cx + r} {cy}"
    fg_path = f"M {cx - r} {cy} A {r} {r} 0 {large} {sweep} {x:.1f} {y:.1f}"
    return f"""
<section class="gauge-wrap">
  <svg viewBox="0 0 220 130" class="gauge" role="img" aria-label="Health score {score}">
    <path d="{bg_path}" class="gauge-bg"/>
    <path d="{fg_path}" stroke="{color}" class="gauge-fg"/>
    <text x="110" y="95" class="gauge-score" fill="{color}">{score}</text>
    <text x="110" y="118" class="gauge-label">/ 100</text>
  </svg>
  <div class="grade" style="color:{color}">{_e(grade)}</div>
  <div class="grade-sub">Overall device health</div>
</section>"""


def _summary_cards(result: AnalysisResult, sev_counts: dict) -> str:
    cards = [
        ("Log files", result.total_files, "#1c7ed6"),
        ("Lines analysed", f"{result.total_lines:,}", "#5f3dc4"),
        ("Errors", result.total_errors, "#e8590c"),
        ("Warnings", result.total_warnings, "#f08c00"),
        ("Findings", len(result.findings), "#0c8599"),
        ("Critical / High",
         sev_counts["critical"] + sev_counts["high"], "#b00020"),
    ]
    cells = "".join(
        f"<div class='card'><div class='card-num' style='color:{c}'>{v}</div>"
        f"<div class='card-label'>{_e(label)}</div></div>"
        for label, v, c in cards
    )
    return f"<section class='cards'>{cells}</section>"


def _severity_bar(sev_counts: dict) -> str:
    total = sum(sev_counts.values()) or 1
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
             Severity.LOW, Severity.INFO]
    segs = []
    legend = []
    for sev in order:
        n = sev_counts[sev.value]
        if n == 0:
            continue
        pct = n / total * 100
        color = SEV_COLORS[sev]
        segs.append(f"<div class='seg' style='width:{pct:.1f}%;background:{color}' "
                    f"title='{sev.value}: {n}'></div>")
        legend.append(f"<span class='lg'><i style='background:{color}'></i>"
                      f"{sev.value.capitalize()} ({n})</span>")
    if not segs:
        return "<section class='sevbar-wrap'><p class='ok'>No findings — nothing to prioritise.</p></section>"
    return (f"<section class='sevbar-wrap'><h2>Findings by severity</h2>"
            f"<div class='sevbar'>{''.join(segs)}</div>"
            f"<div class='legend'>{''.join(legend)}</div></section>")


def _exec_summary(result: AnalysisResult) -> str:
    sev = result.severity_counts()
    top = [f for f in result.findings
           if f.severity in (Severity.CRITICAL, Severity.HIGH)][:5]
    if top:
        items = "".join(f"<li><b>{_e(f.title)}</b> — {_e(f.recommendation)}</li>"
                        for f in top)
        body = (f"<p>This device scored <b>{result.health_score()}/100</b> "
                f"({_e(result.health_grade())}). We identified "
                f"<b>{sev['critical']} critical</b> and <b>{sev['high']} high</b> "
                "priority items requiring attention. The recommended actions, "
                "in priority order, are:</p><ol>" + items + "</ol>")
    else:
        body = (f"<p>This device scored <b>{result.health_score()}/100</b> "
                f"({_e(result.health_grade())}). No critical or high-priority "
                "issues were found. The detailed observations below are "
                "low-priority or optimisation opportunities.</p>")
    return f"<section class='exec'><h2>Executive summary</h2>{body}</section>"


def _findings_section(result: AnalysisResult, client_facing: bool) -> str:
    if not result.findings:
        return "<section><h2>Findings</h2><p class='ok'>No issues detected.</p></section>"
    rows = []
    for f in result.findings:
        color = SEV_COLORS[f.severity]
        docs = (f"<a href='{_e(f.docs_url)}' target='_blank' rel='noopener'>"
                "Microsoft documentation ↗</a>") if f.docs_url else ""
        evidence = ""
        if f.evidence and not client_facing:
            ev_items = "".join(f"<pre class='ev'>{_e(s)}</pre>" for s in f.evidence)
            evidence = (f"<details class='evidence'><summary>Evidence "
                        f"({f.count} match{'es' if f.count != 1 else ''})</summary>"
                        f"{ev_items}</details>")
        count_badge = (f"<span class='count'>×{f.count}</span>"
                       if f.count > 1 and not client_facing else "")
        rows.append(f"""
<article class="finding" style="border-left-color:{color}">
  <div class="finding-head">
    <span class="sev" style="background:{color}">{f.severity.value.upper()}</span>
    <span class="cat">{_e(f.category)}</span>
    <span class="src">{_e(f.source.value)}</span>
    {count_badge}
  </div>
  <h3>{_e(f.title)}</h3>
  <p class="desc">{_e(f.description)}</p>
  <p class="rec"><b>Recommended action:</b> {_e(f.recommendation)}</p>
  {docs}
  {evidence}
</article>""")
    return f"<section><h2>Findings &amp; recommendations</h2>{''.join(rows)}</section>"


def _sources_section(result: AnalysisResult) -> str:
    if not result.summaries:
        return ""
    rows = []
    for s in sorted(result.summaries, key=lambda x: x.source.value):
        span = "—"
        if s.first_seen and s.last_seen:
            span = (f"{s.first_seen.strftime('%Y-%m-%d')} → "
                    f"{s.last_seen.strftime('%Y-%m-%d')}")
        rows.append(f"""
<tr>
  <td>{_e(s.source.value)}</td>
  <td class="num">{len(s.files)}</td>
  <td class="num">{s.lines_parsed:,}</td>
  <td class="num err">{s.errors}</td>
  <td class="num warn">{s.warnings}</td>
  <td>{span}</td>
</tr>""")
    return f"""
<section><h2>Log sources analysed</h2>
<table class="srctable">
  <thead><tr><th>Source</th><th>Files</th><th>Lines</th>
  <th>Errors</th><th>Warnings</th><th>Time span</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table></section>"""


CIS_STATUS_COLORS = {"green": "#2f9e44", "yellow": "#f08c00", "red": "#b00020"}
CIS_CHECK_COLORS = {"pass": "#2f9e44", "fail": "#b00020", "not-assessed": "#94a3b8"}
CIS_CHECK_LABELS = {"pass": "PASS", "fail": "FAIL", "not-assessed": "N/A"}


def _cis_section(result: AnalysisResult, client_facing: bool) -> str:
    cis = result.cis
    color = CIS_STATUS_COLORS.get(cis.status(), "#94a3b8")
    score = cis.score()
    assessed_note = (f"{cis.passed} of {cis.assessed} assessable controls pass"
                     if cis.assessed else "No controls could be assessed from "
                     "the collected logs")

    kpi = f"""
<div class="cis-kpi">
  <div class="cis-score" style="border-color:{color};color:{color}">
    <span class="cis-pct">{score}%</span>
    <span class="cis-band">{_e(cis.status_label())}</span>
  </div>
  <div class="cis-meta">
    <p class="cis-headline">CIS Level 1 match: <b style="color:{color}">{score}%</b></p>
    <p class="hint">{_e(assessed_note)}. Banding: ≥ 95% green · 75–95% yellow · &lt; 75% red.</p>
    <div class="cis-counts">
      <span class="cis-c pass">✓ {cis.passed} pass</span>
      <span class="cis-c fail">✗ {cis.failed} fail</span>
      <span class="cis-c na">— {cis.not_assessed} not assessed</span>
      <span class="cis-c tot">{cis.total} controls</span>
    </div>
  </div>
</div>"""

    rows = []
    for c in cis.checks:
        ccol = CIS_CHECK_COLORS[c.status]
        clabel = CIS_CHECK_LABELS[c.status]
        evidence = ""
        if c.evidence and not client_facing:
            ev_items = "".join(f"<pre class='ev'>{_e(s)}</pre>" for s in c.evidence)
            evidence = (f"<details class='evidence'><summary>Evidence &amp; "
                        f"remediation</summary>"
                        f"<p class='rec'><b>Remediation:</b> {_e(c.remediation)}</p>"
                        f"{ev_items}</details>")
        elif not client_facing:
            evidence = (f"<details class='evidence'><summary>Remediation</summary>"
                        f"<p class='rec'>{_e(c.remediation)}</p></details>")
        docs = (f" <a href='{_e(c.docs_url)}' target='_blank' rel='noopener'>↗</a>"
                if c.docs_url else "")
        rows.append(f"""
<tr>
  <td class="cis-id">{_e(c.id)}{docs}</td>
  <td><b>{_e(c.title)}</b><div class="cis-rat">{_e(c.rationale)}</div>{evidence}</td>
  <td class="cis-sec">{_e(c.section)}</td>
  <td class="cis-st"><span class="cis-pill" style="background:{ccol}">{clabel}</span></td>
</tr>""")

    table = f"""
<table class="cistable">
  <thead><tr><th>Control</th><th>Title</th><th>Section</th><th>Status</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>"""

    return (f"<section class='cis'><h2>CIS Level 1 validation</h2>{kpi}{table}"
            "<p class='hint'>Evidence-based validation against a curated subset "
            "of CIS Apple macOS Benchmark <b>Level 1</b> controls. Controls "
            "without a signal in the collected logs are reported as "
            "<em>not assessed</em> and excluded from the match score — this is "
            "not a substitute for a full on-device CIS scan.</p></section>")


def _coverage_section(result: AnalysisResult) -> str:
    found = {s.source for s in result.summaries}
    all_sources = list(Source)
    items = []
    for src in all_sources:
        ok = src in found
        icon = "✓" if ok else "—"
        cls = "cov-ok" if ok else "cov-miss"
        items.append(f"<li class='{cls}'><span>{icon}</span> {_e(src.value)}</li>")
    return (f"<section><h2>Coverage</h2><ul class='coverage'>{''.join(items)}</ul>"
            "<p class='hint'>Sources marked “—” had no logs in this "
            "collection.</p></section>")


def _footer(result: AnalysisResult) -> str:
    return f"""
<footer>
  <div>Intune MDM Mac Analyzer v{__version__}</div>
  <div>Input: {_e(result.input_path or 'n/a')}</div>
  <div>This report was generated automatically from device logs.</div>
</footer>"""


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #
def export_pdf(html_content: str, out_path: str) -> tuple[bool, str]:
    """Try to render ``html_content`` to a PDF at ``out_path``.

    Returns ``(success, message)``. Tries weasyprint then wkhtmltopdf; if
    neither is available, writes the HTML alongside and explains the
    browser-based fallback rather than failing hard.
    """
    out = Path(out_path)
    # 1. weasyprint (pure-python, best fidelity for our CSS)
    try:
        from weasyprint import HTML  # type: ignore
        HTML(string=html_content).write_pdf(str(out))
        return True, f"PDF written via weasyprint: {out}"
    except ImportError:
        pass
    except Exception as exc:  # weasyprint present but failed
        return False, f"weasyprint failed: {exc}"

    # 2. wkhtmltopdf on PATH
    wk = shutil.which("wkhtmltopdf")
    if wk:
        tmp_html = out.with_suffix(".tmp.html")
        tmp_html.write_text(html_content, encoding="utf-8")
        try:
            proc = subprocess.run(
                [wk, "--quiet", "--enable-local-file-access",
                 str(tmp_html), str(out)],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode == 0:
                return True, f"PDF written via wkhtmltopdf: {out}"
            return False, f"wkhtmltopdf failed: {proc.stderr.strip()}"
        finally:
            tmp_html.unlink(missing_ok=True)

    # 3. Fallback: write HTML and instruct.
    fallback = out.with_suffix(".html")
    fallback.write_text(html_content, encoding="utf-8")
    return False, (
        "No PDF engine found (install 'weasyprint' or 'wkhtmltopdf'). "
        f"Wrote HTML to {fallback} — open it and use the browser's "
        "'Save as PDF' button instead."
    )


# --------------------------------------------------------------------------- #
# Static assets (inlined)
# --------------------------------------------------------------------------- #
_HEAD = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{css}</style>
</head><body>"""

_CSS = """
:root {
  --bg:#f4f6fb; --panel:#ffffff; --ink:#1d2433; --muted:#5f6c7b;
  --line:#e2e8f0; --accent:#0b5fff;
}
* { box-sizing:border-box; }
body { margin:0; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',
  Roboto,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--ink);
  line-height:1.5; }
h1 { font-size:1.6rem; margin:0; }
h2 { font-size:1.2rem; margin:0 0 .8rem; padding-bottom:.4rem;
  border-bottom:2px solid var(--line); }
h3 { font-size:1.05rem; margin:.2rem 0 .4rem; }
section, footer { background:var(--panel); margin:1rem auto; padding:1.4rem 1.8rem;
  max-width:980px; border-radius:12px; box-shadow:0 1px 3px rgba(16,24,40,.06); }
.topbar { display:flex; justify-content:space-between; align-items:flex-start;
  gap:1rem; background:linear-gradient(135deg,#0b3d91,#0b5fff); color:#fff;
  padding:1.6rem 1.8rem; max-width:980px; margin:1rem auto 0; border-radius:12px; }
.subtitle { opacity:.9; margin-top:.2rem; }
.chips { margin-top:.6rem; display:flex; flex-wrap:wrap; gap:.4rem; }
.chip { background:rgba(255,255,255,.18); padding:.15rem .55rem; border-radius:999px;
  font-size:.78rem; }
.actions { text-align:right; }
.btn { background:#fff; color:#0b3d91; border:0; padding:.55rem 1rem;
  border-radius:8px; font-weight:600; cursor:pointer; }
.btn:hover { background:#eef2ff; }
.genstamp { font-size:.75rem; opacity:.85; margin-top:.6rem; }
.gauge-wrap { text-align:center; }
.gauge { width:240px; height:auto; }
.gauge-bg { fill:none; stroke:#e9ecf2; stroke-width:16; stroke-linecap:round; }
.gauge-fg { fill:none; stroke-width:16; stroke-linecap:round; }
.gauge-score { font-size:42px; font-weight:700; text-anchor:middle; }
.gauge-label { font-size:13px; fill:#94a3b8; text-anchor:middle; }
.grade { font-size:1.4rem; font-weight:700; margin-top:-.4rem; }
.grade-sub { color:var(--muted); font-size:.85rem; }
.cards { display:grid; grid-template-columns:repeat(6,1fr); gap:.8rem; }
.card { text-align:center; padding:.8rem .4rem; background:#f8fafc;
  border:1px solid var(--line); border-radius:10px; }
.card-num { font-size:1.6rem; font-weight:700; }
.card-label { font-size:.72rem; color:var(--muted); text-transform:uppercase;
  letter-spacing:.04em; }
.sevbar { display:flex; height:22px; border-radius:6px; overflow:hidden; }
.seg { height:100%; }
.legend { margin-top:.6rem; display:flex; flex-wrap:wrap; gap:1rem;
  font-size:.82rem; color:var(--muted); }
.lg i { display:inline-block; width:11px; height:11px; border-radius:3px;
  margin-right:.35rem; vertical-align:middle; }
.exec ol { padding-left:1.2rem; } .exec li { margin:.3rem 0; }
.finding { border:1px solid var(--line); border-left:5px solid; border-radius:10px;
  padding:1rem 1.2rem; margin-bottom:1rem; }
.finding-head { display:flex; align-items:center; gap:.6rem; flex-wrap:wrap;
  font-size:.74rem; margin-bottom:.2rem; }
.sev { color:#fff; padding:.12rem .5rem; border-radius:5px; font-weight:700;
  letter-spacing:.03em; }
.cat,.src { background:#eef2f7; color:var(--muted); padding:.12rem .5rem;
  border-radius:5px; }
.count { margin-left:auto; color:var(--muted); font-weight:600; }
.desc { margin:.3rem 0; }
.rec { margin:.3rem 0; background:#f1f8ff; border:1px solid #d0e2ff;
  padding:.5rem .7rem; border-radius:8px; }
.evidence { margin-top:.6rem; } .evidence summary { cursor:pointer; color:var(--accent);
  font-size:.85rem; }
pre.ev { background:#0d1117; color:#c9d1d9; padding:.6rem .8rem; border-radius:8px;
  overflow-x:auto; font-size:.78rem; margin:.4rem 0; white-space:pre-wrap;
  word-break:break-word; }
table.srctable { width:100%; border-collapse:collapse; font-size:.9rem; }
.srctable th,.srctable td { text-align:left; padding:.5rem .6rem;
  border-bottom:1px solid var(--line); }
.srctable .num { text-align:right; } .srctable .err { color:#e8590c; font-weight:600; }
.srctable .warn { color:#f08c00; }
.cis-kpi { display:flex; gap:1.4rem; align-items:center; flex-wrap:wrap;
  margin-bottom:1rem; }
.cis-score { display:flex; flex-direction:column; align-items:center;
  justify-content:center; width:128px; height:128px; border:8px solid;
  border-radius:50%; flex:0 0 auto; }
.cis-pct { font-size:2rem; font-weight:800; line-height:1; }
.cis-band { font-size:.8rem; font-weight:700; text-transform:uppercase;
  letter-spacing:.04em; margin-top:.2rem; }
.cis-meta { flex:1; min-width:240px; }
.cis-headline { font-size:1.05rem; margin:0 0 .3rem; }
.cis-counts { display:flex; flex-wrap:wrap; gap:.5rem; margin-top:.5rem; }
.cis-c { font-size:.8rem; padding:.2rem .6rem; border-radius:999px;
  background:#f1f5f9; color:var(--muted); font-weight:600; }
.cis-c.pass { background:#e6f4ea; color:#2f9e44; }
.cis-c.fail { background:#fdecec; color:#b00020; }
table.cistable { width:100%; border-collapse:collapse; font-size:.88rem; }
.cistable th,.cistable td { text-align:left; padding:.5rem .6rem;
  border-bottom:1px solid var(--line); vertical-align:top; }
.cis-id { white-space:nowrap; font-weight:600; color:var(--muted); }
.cis-sec { color:var(--muted); white-space:nowrap; font-size:.82rem; }
.cis-rat { color:var(--muted); font-size:.82rem; margin-top:.2rem; }
.cis-st { text-align:right; }
.cis-pill { color:#fff; padding:.15rem .55rem; border-radius:5px;
  font-weight:700; font-size:.74rem; letter-spacing:.03em; }
.coverage { list-style:none; padding:0; display:grid;
  grid-template-columns:repeat(2,1fr); gap:.4rem; }
.coverage li { padding:.4rem .6rem; border-radius:8px; background:#f8fafc; }
.cov-ok span { color:#2f9e44; font-weight:700; } .cov-miss { color:var(--muted); }
.hint { color:var(--muted); font-size:.82rem; }
.ok { color:#2f9e44; font-weight:600; }
a { color:var(--accent); }
footer { color:var(--muted); font-size:.8rem; text-align:center; }
@media (max-width:720px){ .cards{grid-template-columns:repeat(2,1fr);}
  .coverage{grid-template-columns:1fr;} .topbar{flex-direction:column;}
  .actions{text-align:left;} }
@media print {
  body { background:#fff; }
  .btn { display:none; }
  .topbar { background:#0b3d91 !important; -webkit-print-color-adjust:exact;
    print-color-adjust:exact; }
  section, footer, .topbar { box-shadow:none; max-width:100%; margin:.5rem 0;
    break-inside:avoid; }
  .finding, .seg, .sevbar, .cis-pill, .cis-score, .cis-c {
    -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  details.evidence { display:none; }
}
"""

_SCRIPT = """
<script>
// Expand all evidence before printing so PDF includes it, then restore.
window.addEventListener('beforeprint', function () {
  document.querySelectorAll('details.evidence').forEach(function (d) {
    d.dataset.wasOpen = d.open ? '1' : '0';
  });
});
</script>"""
