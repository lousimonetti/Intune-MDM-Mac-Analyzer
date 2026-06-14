"""Tkinter graphical interface.

Deliberately self-contained and dependency-free (tkinter ships with CPython).
The GUI is a thin shell over :func:`intune_analyzer.pipeline.run_analysis` and
the report renderers, so CLI and GUI always produce identical results.
"""

from __future__ import annotations

import threading
import webbrowser
from pathlib import Path


def launch() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except Exception as exc:  # pragma: no cover - headless environments
        print(f"GUI unavailable: {exc}\nUse the CLI instead "
              "(intune-analyzer --input PATH --html report.html).")
        return 3

    from .pipeline import run_analysis
    from .report import export_pdf, render_html, render_json
    from .models import Severity
    from .version import __version__

    SEV_COLORS = {
        "critical": "#b00020", "high": "#e8590c", "medium": "#f08c00",
        "low": "#1c7ed6", "info": "#5f6c7b",
    }

    app = tk.Tk()
    app.title(f"Intune MDM Mac Analyzer v{__version__}")
    app.geometry("860x640")
    app.minsize(720, 520)

    state = {"result": None, "html": None}

    # ---- top: source selection ------------------------------------------- #
    top = ttk.Frame(app, padding=12)
    top.pack(fill="x")
    ttk.Label(top, text="Intune MDM Mac Analyzer",
              font=("Helvetica", 16, "bold")).grid(row=0, column=0,
                                                   columnspan=4, sticky="w")
    ttk.Label(top, text="Analyze Intune, macOS, Defender, AutoUpdate and "
                        "Office logs.").grid(row=1, column=0, columnspan=4,
                                             sticky="w", pady=(0, 8))

    mode = tk.StringVar(value="input")
    path_var = tk.StringVar()
    client_var = tk.BooleanVar(value=False)

    ttk.Radiobutton(top, text="Analyze collected logs (folder or .zip)",
                    variable=mode, value="input").grid(row=2, column=0,
                                                        columnspan=2, sticky="w")
    ttk.Radiobutton(top, text="Live (scan this Mac's log paths)",
                    variable=mode, value="live").grid(row=2, column=2,
                                                       columnspan=2, sticky="w")

    entry = ttk.Entry(top, textvariable=path_var, width=64)
    entry.grid(row=3, column=0, columnspan=2, sticky="we", pady=6)

    def pick_dir():
        d = filedialog.askdirectory(title="Select log folder")
        if d:
            path_var.set(d); mode.set("input")

    def pick_zip():
        f = filedialog.askopenfilename(title="Select log .zip",
                                       filetypes=[("Zip archives", "*.zip"),
                                                  ("All files", "*.*")])
        if f:
            path_var.set(f); mode.set("input")

    ttk.Button(top, text="Folder…", command=pick_dir).grid(row=3, column=2,
                                                            padx=4)
    ttk.Button(top, text="Zip…", command=pick_zip).grid(row=3, column=3)
    ttk.Checkbutton(top, text="Client-facing report (simplified)",
                    variable=client_var).grid(row=4, column=0, columnspan=2,
                                              sticky="w")
    top.columnconfigure(0, weight=1)

    # ---- action row ------------------------------------------------------ #
    actions = ttk.Frame(app, padding=(12, 0))
    actions.pack(fill="x")
    run_btn = ttk.Button(actions, text="▶ Run analysis")
    run_btn.pack(side="left")
    status = ttk.Label(actions, text="Ready.")
    status.pack(side="left", padx=10)

    # ---- summary bar ----------------------------------------------------- #
    summary = ttk.Label(app, text="", padding=(12, 6),
                        font=("Helvetica", 11, "bold"))
    summary.pack(fill="x")

    # ---- findings list --------------------------------------------------- #
    mid = ttk.Frame(app, padding=12)
    mid.pack(fill="both", expand=True)
    cols = ("severity", "source", "title", "count")
    tree = ttk.Treeview(mid, columns=cols, show="headings", height=14)
    for c, w in zip(cols, (90, 170, 480, 60)):
        tree.heading(c, text=c.capitalize())
        tree.column(c, width=w, anchor="w" if c != "count" else "center")
    for sev, color in SEV_COLORS.items():
        tree.tag_configure(sev, foreground=color)
    vsb = ttk.Scrollbar(mid, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")

    detail = tk.Text(app, height=7, wrap="word", padx=10, pady=8)
    detail.pack(fill="x", padx=12, pady=(0, 8))
    detail.insert("1.0", "Select a finding to see details and the recommended "
                         "action.")
    detail.configure(state="disabled")

    def on_select(_evt=None):
        sel = tree.selection()
        if not sel or not state["result"]:
            return
        idx = int(sel[0])
        f = state["result"].findings[idx]
        detail.configure(state="normal")
        detail.delete("1.0", "end")
        detail.insert("end", f"{f.title}\n", "h")
        detail.insert("end", f"{f.description}\n\n")
        detail.insert("end", f"Recommended action: {f.recommendation}\n")
        if f.docs_url:
            detail.insert("end", f"Docs: {f.docs_url}\n")
        if f.evidence:
            detail.insert("end", "\nEvidence:\n")
            for ev in f.evidence:
                detail.insert("end", f"  • {ev}\n")
        detail.tag_configure("h", font=("Helvetica", 11, "bold"))
        detail.configure(state="disabled")

    tree.bind("<<TreeviewSelect>>", on_select)

    # ---- export buttons -------------------------------------------------- #
    exports = ttk.Frame(app, padding=12)
    exports.pack(fill="x")

    def _ensure_result():
        if not state["result"]:
            messagebox.showinfo("Run first", "Run an analysis before exporting.")
            return False
        return True

    def save_html():
        if not _ensure_result():
            return
        f = filedialog.asksaveasfilename(defaultextension=".html",
                                         filetypes=[("HTML", "*.html")])
        if not f:
            return
        html = render_html(state["result"], client_facing=client_var.get())
        Path(f).write_text(html, encoding="utf-8")
        webbrowser.open(Path(f).resolve().as_uri())
        status.config(text=f"Saved {f}")

    def save_pdf():
        if not _ensure_result():
            return
        f = filedialog.asksaveasfilename(defaultextension=".pdf",
                                         filetypes=[("PDF", "*.pdf")])
        if not f:
            return
        html = render_html(state["result"], client_facing=client_var.get())
        ok, msg = export_pdf(html, f)
        (messagebox.showinfo if ok else messagebox.showwarning)("PDF export", msg)
        status.config(text=msg)

    def save_json():
        if not _ensure_result():
            return
        f = filedialog.asksaveasfilename(defaultextension=".json",
                                         filetypes=[("JSON", "*.json")])
        if not f:
            return
        Path(f).write_text(render_json(state["result"]), encoding="utf-8")
        status.config(text=f"Saved {f}")

    ttk.Button(exports, text="Save HTML & open", command=save_html).pack(side="left")
    ttk.Button(exports, text="Export PDF", command=save_pdf).pack(side="left", padx=6)
    ttk.Button(exports, text="Export JSON", command=save_json).pack(side="left")

    # ---- run logic ------------------------------------------------------- #
    def do_run():
        run_btn.config(state="disabled")
        status.config(text="Analyzing…")
        tree.delete(*tree.get_children())
        try:
            result = run_analysis(
                input_path=path_var.get() if mode.get() == "input" else None,
                live=mode.get() == "live",
                client_facing=client_var.get(),
            )
        except Exception as exc:
            app.after(0, lambda: messagebox.showerror("Error", str(exc)))
            app.after(0, lambda: status.config(text="Failed."))
            app.after(0, lambda: run_btn.config(state="normal"))
            return
        state["result"] = result

        def render():
            sev = result.severity_counts()
            cis_txt = ""
            if result.cis is not None:
                cis_txt = (f"   |   CIS L1 {result.cis.score()}% "
                           f"({result.cis.status_label()})")
            summary.config(
                text=f"Health {result.health_score()}/100 "
                     f"({result.health_grade()})   |   "
                     f"{result.total_files} files, {result.total_lines:,} lines, "
                     f"{result.total_errors} errors   |   "
                     f"crit {sev['critical']}  high {sev['high']}  "
                     f"med {sev['medium']}  low {sev['low']}{cis_txt}")
            for i, f in enumerate(result.findings):
                tree.insert("", "end", iid=str(i),
                            values=(f.severity.value.upper(), f.source.value,
                                    f.title, f"×{f.count}"),
                            tags=(f.severity.value,))
            status.config(text="Done.")
            run_btn.config(state="normal")
        app.after(0, render)

    def run_threaded():
        threading.Thread(target=do_run, daemon=True).start()

    run_btn.config(command=run_threaded)

    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch())
