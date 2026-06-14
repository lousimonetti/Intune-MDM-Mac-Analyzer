# Intune MDM Mac Analyzer

Analyze the health of **Microsoft Intune** management on macOS devices by
parsing the logs that matter — Intune MDM agent, macOS app installs, assigned
policies, **Microsoft Defender for Endpoint**, **Microsoft AutoUpdate (MAU)**
and **Microsoft Office** — and turn them into an **enhanced HTML health report**
with one-click **PDF** export and a simplified **client-facing** mode.

Runs as a **CLI** *or* a **GUI** from the same codebase. The core has **zero
required dependencies** (Python standard library only), so it runs on the
managed Mac itself or on an analyst's machine against collected logs.

---

## What it analyzes

| Source | Default location(s) | What we look for |
| --- | --- | --- |
| **Intune MDM agent** | `/Library/Logs/Microsoft/Intune/`, `~/Library/Logs/Microsoft/Intune/` (`IntuneMDMDaemon`/`IntuneMDMAgent` logs) | Enrollment, check-in/sync, Entra (AAD) token/auth, policy & profile application, app deployment, compliance, SCEP/PKCS certs |
| **macOS app install** | `/var/log/install.log` | PackageKit install failures, blocked downgrades |
| **Microsoft Defender** | `/Library/Logs/Microsoft/mdatp/`, `/Library/Application Support/Microsoft/Defender/`, `mdatp health` (live) | Unhealthy agent, real-time protection off, stale definitions, connectivity, install errors, threat detections |
| **Microsoft AutoUpdate** | `/Library/Logs/Microsoft/autoupdate.log` | Update/download failures, automatic updates disabled |
| **Microsoft Office** | `~/Library/Containers/com.microsoft.*/Data/Library/Logs/` | Activation/licensing failures, app crashes |
| **macOS / MDM** | `system.log`, unified-log exports (`ManagedClient`/`mdmclient`) | Profile install problems, MDM errors |

Beyond signature matching, the analyzer adds **aggregate insight**: missing log
sources (coverage gaps), elevated error rates, stale logs, and **opportunities
for improvement** (Defender tuning, MAU channel standardisation, security
baselines).

Log locations follow Microsoft Learn documentation for
[shell-script log collection](https://learn.microsoft.com/intune/device-management/tools/run-shell-scripts-macos),
[Defender on macOS](https://learn.microsoft.com/defender-endpoint/mac-resources),
and MAU/Office diagnostics.

---

## Install

```bash
git clone <this-repo>
cd Intune-MDM-Mac-Analyzer
pip install -e .            # core tool, no extra dependencies
pip install -e ".[pdf]"     # optional: headless PDF export via weasyprint
```

No install is required to try it — `python3 -m intune_analyzer ...` works from
the repo root.

---

## CLI usage

```bash
# Analyze a collected log bundle (folder or .zip) and write an HTML report
intune-analyzer --input ./logs --html report.html

# Run live on the managed Mac, open the report, and export a PDF
intune-analyzer --live --html report.html --pdf report.pdf --open

# Simplified client-facing report + machine-readable JSON
intune-analyzer --input bundle.zip --client --html client.html --json out.json

# Try it now against the bundled samples
python3 -m intune_analyzer --input samples --html report.html
```

Key flags: `--input PATH` (dir/zip) or `--live`; `--html`, `--pdf`, `--json`;
`--client` (customer-friendly); `--title`; `--open`; `--fail-on SEVERITY`
(non-zero exit for CI gating); `--gui`.

### Exit codes
`0` success · `1` `--fail-on` threshold met · `2` bad input · `3` GUI
unavailable.

---

## GUI usage

```bash
intune-analyzer --gui          # or: intune-analyzer-gui
```

Pick a log folder/zip (or choose **Live**), run the analysis, browse findings
with details and recommendations, then export **HTML / PDF / JSON**. The GUI is
a thin shell over the same engine, so CLI and GUI always produce identical
results.

---

## The report

A single, self-contained HTML file (inline CSS/SVG, **no external requests** —
safe to email):

- **Health score gauge** (0–100) and grade (Healthy → Critical)
- **Summary cards** (files, lines, errors, warnings, findings)
- **Findings by severity** bar + prioritised findings with **recommended
  actions**, doc links and collapsible **evidence** (raw log lines)
- **Per-source breakdown** and **coverage** map
- **"Save as PDF"** button (browser print pipeline, print CSS included)
- **`--client` mode**: executive summary, evidence hidden, info-level noise
  removed — suitable to hand to a customer

### PDF export
`--pdf` uses `weasyprint` if installed, otherwise `wkhtmltopdf` on `PATH`. If
neither is present it writes the HTML and points you at the browser's built-in
"Save as PDF" — so PDF output is always achievable.

---

## How it fits together

```
collector  ->  parsers/*  ->  analyzer (rules + heuristics)  ->  report (HTML/PDF/JSON)
 (discover &    (normalise     (Finding objects with              (render)
  read logs)     log lines)     severity + recommendations)
```

- `collector.py` — offline (dir/zip) or live (macOS paths + `mdatp health`)
- `parsers/` — forgiving, format-tolerant log parsing per source
- `rules.py` — declarative detection signatures (easy to extend)
- `analyzer.py` — collapses matches into findings, adds aggregate insight
- `report.py` — HTML / JSON / PDF rendering
- `cli.py`, `gui.py` — two front ends over `pipeline.run_analysis`

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

Add a new detection by appending a `Rule` to `intune_analyzer/rules.py`; add a
new log source by dropping a module in `intune_analyzer/parsers/` that exposes
`NAME`, `SOURCE`, `matches()` and `parse()`, and registering it in
`parsers/__init__.py`.

## License

MIT
