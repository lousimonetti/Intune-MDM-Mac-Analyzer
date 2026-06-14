"""Intune MDM Mac Analyzer.

Analyse Intune, macOS, app-install, Microsoft Defender, Microsoft AutoUpdate
and Office logs on managed Macs and produce an enhanced HTML / PDF report.
"""

from __future__ import annotations

from .models import AnalysisResult, Finding, Severity, Source
from .pipeline import run_analysis
from .report import export_pdf, render_html, render_json
from .version import __version__

__all__ = [
    "run_analysis",
    "render_html",
    "render_json",
    "export_pdf",
    "AnalysisResult",
    "Finding",
    "Severity",
    "Source",
    "__version__",
]
