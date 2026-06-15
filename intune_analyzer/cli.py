"""Command-line interface.

Examples
--------
Analyse a collected log bundle and write an HTML report::

    intune-analyzer --input ./logs --html report.html

Run live on the managed Mac, open the report and also export a PDF::

    intune-analyzer --live --html report.html --pdf report.pdf --open

Produce a simplified client-facing report and machine-readable JSON::

    intune-analyzer --input bundle.zip --client --html client.html --json out.json

Launch the graphical interface::

    intune-analyzer --gui
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from .pipeline import run_analysis
from .report import export_pdf, render_html, render_json
from .models import Severity
from .version import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="intune-analyzer",
        description="Analyze Intune / macOS / Defender / AutoUpdate / Office "
                    "logs and produce an enhanced HTML or PDF health report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("-i", "--input", metavar="PATH",
                     help="Directory or .zip of collected logs to analyse.")
    src.add_argument("--live", action="store_true",
                     help="Read well-known macOS log paths on this machine.")

    p.add_argument("--gui", action="store_true",
                   help="Launch the graphical interface instead of the CLI.")
    p.add_argument("--html", metavar="FILE",
                   help="Write the HTML report to FILE.")
    p.add_argument("--pdf", metavar="FILE",
                   help="Also export the report as a PDF to FILE.")
    p.add_argument("--json", metavar="FILE",
                   help="Write machine-readable JSON results to FILE.")
    p.add_argument("--client", action="store_true",
                   help="Produce a simplified, client-facing report "
                        "(executive summary, evidence collapsed).")
    p.add_argument("--title", default="Intune macOS Health Report",
                   help="Report title.")
    p.add_argument("--open", action="store_true", dest="open_report",
                   help="Open the generated HTML report in a browser.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print each file as it is read.")
    p.add_argument("--fail-on", choices=[s.value for s in Severity],
                   help="Exit non-zero if any finding at or above this "
                        "severity exists (useful in CI).")
    p.add_argument("--ignore", metavar="ID", action="append", default=[],
                   help="Suppress a finding or CIS control by ID. Repeatable. "
                        "Example: --ignore MAU-UPDATE-FAIL --ignore CIS-2.5.2. "
                        "Comma-separated lists are also accepted: "
                        "--ignore MAU-UPDATE-FAIL,DEFENDER-THREAT.")
    p.add_argument("--version", action="version",
                   version=f"intune-analyzer {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.gui:
        from .gui import launch
        return launch()

    ignore: set[str] = set()
    for item in args.ignore:
        for piece in item.split(","):
            piece = piece.strip()
            if piece:
                ignore.add(piece)

    try:
        result = run_analysis(
            input_path=args.input,
            live=args.live,
            client_facing=args.client,
            verbose=args.verbose,
            ignore=ignore,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    _print_console_summary(result)

    wrote_something = False
    if args.html:
        html = render_html(result, client_facing=args.client, title=args.title)
        Path(args.html).write_text(html, encoding="utf-8")
        print(f"HTML report written: {args.html}")
        wrote_something = True
        if args.open_report:
            webbrowser.open(Path(args.html).resolve().as_uri())

    if args.pdf:
        html = render_html(result, client_facing=args.client, title=args.title)
        ok, msg = export_pdf(html, args.pdf)
        print(("PDF: " if ok else "PDF (fallback): ") + msg)
        wrote_something = True

    if args.json:
        Path(args.json).write_text(render_json(result), encoding="utf-8")
        print(f"JSON written: {args.json}")
        wrote_something = True

    if not wrote_something:
        # Default behaviour: emit HTML to stdout so the tool is useful with no
        # output flags (e.g. piped to a file).
        if not sys.stdout.isatty():
            sys.stdout.write(render_html(result, client_facing=args.client,
                                         title=args.title))
        else:
            print("\nTip: add --html report.html (or --pdf / --json) to save "
                  "a report, or --gui for the graphical interface.")

    if args.fail_on:
        threshold = Severity(args.fail_on)
        worst = max((f.severity for f in result.findings),
                    key=lambda s: s.rank, default=None)
        if worst is not None and worst.rank >= threshold.rank:
            print(f"fail-on: found {worst.value} >= {threshold.value}",
                  file=sys.stderr)
            return 1
    return 0


def _print_console_summary(result) -> None:
    sev = result.severity_counts()
    print("=" * 60)
    print(f"  Intune macOS Health Report  —  {result.hostname or 'device'}")
    print("=" * 60)
    print(f"  Health score : {result.health_score()}/100 "
          f"({result.health_grade()})")
    print(f"  Files / lines: {result.total_files} / {result.total_lines:,}")
    print(f"  Errors / warn: {result.total_errors} / {result.total_warnings}")
    print(f"  Findings     : {len(result.findings)}  "
          f"(crit {sev['critical']}, high {sev['high']}, "
          f"med {sev['medium']}, low {sev['low']}, info {sev['info']})")
    if result.cis is not None:
        cis = result.cis
        print(f"  CIS Level 1  : {cis.score()}% match "
              f"({cis.status_label()}) — {cis.passed} pass / {cis.failed} fail "
              f"/ {cis.not_assessed} n/a")
    print("-" * 60)
    for f in result.findings:
        if f.severity in (Severity.INFO,):
            continue
        print(f"  [{f.severity.value.upper():8}] {f.title}  (×{f.count})")
    print("=" * 60)


if __name__ == "__main__":
    raise SystemExit(main())
