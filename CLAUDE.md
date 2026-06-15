# CLAUDE.md — Project Memory

Working memory for AI/code sessions on **Intune MDM Mac Analyzer**. Read this
first: it captures the architecture, the non-obvious lessons learned, the
validation done against Apple's official schema, and every documentation source
used so they don't have to be rediscovered.

---

## 1. What this project is

A Python tool that analyzes the logs that govern **Microsoft Intune management
of macOS devices** — Intune MDM agent, **Platform SSO / Microsoft Enterprise SSO
extension**, macOS app installs, assigned policies, **Microsoft Defender for
Endpoint**, **Microsoft AutoUpdate (MAU)** and **Microsoft Office** — and
produces an **enhanced, self-contained HTML report** — including a **CIS Level 1
validation score (KPI)** — with **PDF** and **client-facing** export. It runs as
both a **CLI** and a **GUI** from one shared engine.

Design tenets (do not regress these):
- **Stdlib-only core.** No required third-party dependency. `weasyprint` is an
  *optional* extra for headless PDF; the GUI uses stdlib `tkinter`.
- **CLI and GUI are thin shells** over `pipeline.run_analysis`; they must always
  produce identical results.
- **Self-contained HTML.** Inline CSS/SVG, **zero external requests** — the
  report must stay safe to email and open offline.

---

## 2. Architecture map

```
collector  ->  parsers/*  ->  rules + analyzer  ->  report (HTML/PDF/JSON)
```

| File | Responsibility |
| --- | --- |
| `collector.py` | Discover & read logs. Offline (folder/`.zip`) or `--live` (macOS paths + `mdatp health` + `app-sso platform -s`). |
| `parsers/base.py` | Format-tolerant line parsing: timestamp heuristics, level detection, multi-line continuation. |
| `parsers/*.py` | One module per source; each exposes `NAME`, `SOURCE`, `matches()`, `parse()`. |
| `parsers/__init__.py` | `select()` dispatch — **matches on filename + immediate parent dir only** (see Lesson L1). |
| `rules.py` | Declarative `Rule` signatures (the domain knowledge). |
| `cis.py` | CIS Level 1 control specs + evidence-based validation → `CISReport` (match-score KPI). |
| `analyzer.py` | Collapses rule matches into `Finding`s + aggregate heuristics + health score; runs `cis.evaluate`. |
| `report.py` | HTML / JSON / PDF renderers. PDF tries weasyprint -> wkhtmltopdf -> browser fallback. |
| `cli.py` / `gui.py` | Front ends. |
| `models.py` | Dataclasses (`LogEntry`, `Finding`, `SourceSummary`, `AnalysisResult`). |

**Extending:** add a detection = append a `Rule` to `rules.py`. Add a source =
new module in `parsers/` + register in `REGISTRY` (order matters; most specific
first, `install` is the catch-all for `*install.log`).

Run `pytest` (25 tests). Try it: `python3 -m intune_analyzer --input samples`.

---

## 3. Lessons learned (important — re-reading saves time)

- **L1 — Path contamination in parser dispatch.** Matching source by substring
  over the *full path* is dangerous: the repo directory is literally named
  `Intune-MDM-Mac-Analyzer`, so the Intune matcher greedily claimed **every**
  `.log` file under the tree (all 48 sample lines became "Intune"). Fix:
  `parsers.select()` matches only against `"<parent_dir>/<filename>"`. This also
  correctly routes `mdatp/install.log` → Defender (not the generic macOS
  installer) using the parent directory as the disambiguator. Keep matchers
  parent-dir-aware; never reintroduce full-path substring matching.
- **L2 — Microsoft macOS log formats are not stable.** Timestamp and level
  tokens vary across product versions (`| E |`, `[ERROR]`, `<Warning>`, ms with
  `:` vs `.`). The parser is deliberately forgiving and **never drops a line** —
  unparseable lines keep their raw text so keyword rules still see them. Don't
  hard-code one rigid grammar.
- **L3 — PDF must never hard-fail.** Many environments lack a PDF engine.
  `export_pdf()` degrades: weasyprint → wkhtmltopdf on PATH → write HTML and
  point the user at the browser's "Save as PDF". The HTML report itself carries
  a print button + print CSS, so PDF is always achievable.
- **L4 — Always escape report content.** Log lines are untrusted input rendered
  into HTML; everything goes through `html.escape`. There is a regression test
  (`test_html_escapes_content`). Keep it green.
- **L5 — Health score is cumulative penalty, clamped 0–100.** A heavily-seeded
  device can hit 0; that's expected. Weights live in `models.AnalysisResult.health_score`.
- **L6 — Platform SSO shares a `com.microsoft.*` container with Office.** The
  Enterprise SSO extension log lives under
  `com.microsoft.CompanyPortalMac.ssoextension/...`, which the Office matcher
  (`"com.microsoft." in base`) would otherwise claim. `psso` is therefore
  registered **before** `office` in `REGISTRY`, and the `psso` matcher uses
  *specific* tokens (`ssoextension`, `appsso`, `platformsso`, `psso`, …) rather
  than the broad container prefix. PSSO is **not** in `EXPECTED_SOURCES` — it is
  optional (only orgs that deploy it have logs), so absence must not raise a
  `NODATA-PSSO` coverage finding.
- **L7 — CIS validation is log-evidence-based, four-state, and the KPI ignores
  unknowns.** `cis.evaluate` resolves each control to `pass` / `configured` /
  `fail` / `not-assessed`. `pass` requires positive evidence; `configured`
  means the governing source is present and reports no contrary signal
  (control is in place but only *inferred*); both count toward the pass total
  but are surfaced separately so reviewers can see where the verdict was
  *observed* vs *inferred*. The **match-score KPI = (pass + configured) /
  (pass + configured + fail)** so `not-assessed` controls never dilute it.
  Banding is fixed by requirement: **≥ 95 green, 75–95 yellow, < 75 red**
  (`CISReport.status`); 95 is green (inclusive lower bound of the top band).
  CIS runs on the **full** finding set *before* the client-facing INFO trim so
  the KPI is identical in technical and client modes. It is **not** a
  substitute for a full on-device CIS scan — say so in any output.
- **L8 — Guard against substring-regex false positives.** The previous CIS
  fail patterns used unbounded alternations (`gatekeeper.*off`,
  `autologin.*(enabled|on)`, `well-?known.*(failed|403)`) which matched
  unrelated logs by accident: `off` inside other words, `403` as part of
  `InternalSequenceNumber":40320`, `on` inside `config`. The fix is two-fold:
  (a) each `CISCheck` now declares `fail_sources` so only entries from
  relevant sources can supply a fail signal, and (b) `match_word` wraps the
  regex with `\b` word boundaries. The `Rule` model gained the same powers:
  `file_pattern` (only fire on matching basenames — e.g.
  `DEFENDER-INSTALL-FAIL` only runs against `mdatp/install.log`),
  `exclude_pattern` (drop lines that match this second regex first), and
  `transient=True` (failures the CIS evaluator demotes to `configured`).
  Regression coverage: `test_well_known_rule_does_not_match_outlook_telemetry`,
  `test_defender_runtime_errors_do_not_fail_install`,
  `test_unrelated_log_does_not_fail_autologin_or_gatekeeper`,
  `test_transient_finding_demotes_fail_to_configured`.
- **L9 — Users need triage tools.** Every `Finding` and `CISCheckResult`
  carries `remediation_steps` (rendered as a numbered checklist) and a
  `false_positive_note` (rendered as an expandable callout with a
  copy-paste-able `--ignore <ID>` suggestion). The CLI `--ignore ID` flag
  (repeatable, comma-separated) suppresses a finding or CIS control by ID;
  suppressed IDs are listed in a dedicated report section so the suppression
  is transparent. Suppressed findings are excluded from the CIS evaluator's
  fail signals (regression: `test_ignore_flag_suppresses_finding`,
  `test_ignore_suppresses_finding_and_control`).
- **L10 — Severity must reflect live impact, not log volume.** A finding's
  severity should answer "is this an active problem right now?" — not "how
  scary does the log line look?". Two patterns to keep applying:
  1. **Split benign-looking signals into their own LOW-severity rule** rather
     than burying them under a HIGH rule. Example:
     `PackageKit: Failed to set hosted team responsibility for install to
     team:(<TEAMID>)` is informational — installs still complete — so it
     lives in its own rule `INSTALL-TEAM-RESPONSIBILITY` (LOW) and is
     `exclude_pattern`-d out of `INSTALL-FAIL` (HIGH). The line is still
     visible; it just doesn't inflate the critical/high count
     (regression: `test_packagekit_hosted_team_is_low_not_high`).
  2. **Demote historical errors when the live product is healthy.** Done in
     `Analyzer._adjust_severity()`: if Defender logs are present AND no live
     health rule fired (`DEFENDER-UNHEALTHY` / `DEFENDER-RTP-OFF` /
     `DEFENDER-DEFS-STALE`), `DEFENDER-INSTALL-FAIL` is rewritten to a LOW
     "Historical … (product currently running)" finding with the rationale
     baked into the title. The original evidence is preserved so the user
     can still see what happened; the priority just no longer pretends the
     box is on fire. The opposite case (Defender unhealthy) keeps the HIGH
     severity so we never mask a real outage (regressions:
     `test_defender_install_demoted_when_running`,
     `test_defender_install_stays_high_when_unhealthy`).
  When adding a new rule, ask both questions: *Is this a live failure, or a
  cosmetic / historical signal?* and *What other finding would prove the
  product is healthy now?* If the answer to the second is "this other rule
  in `RULES`", add the cross-check to `_adjust_severity`.

---

## 4. Validation against Apple's official schema

Checked the analyzer's macOS/MDM assumptions against
**[apple/device-management](https://github.com/apple/device-management)** (the
authoritative MDM + Declarative Device Management schema; Apple does **not**
accept PRs — file feedback via Feedback Assistant). Repo layout: `mdm/`
(commands, check-in, errors), `declarative/` (declarations + status items),
`docs/`, `other/`. Payloads/commands are defined in **YAML**.

**Confirmed correct:**
- **App install / downgrade logic.** `declarative/status/app.managed.list.yaml`
  defines a `failed` state, and Apple documents that *if a newer version is
  already present the device reports an app status failure* — this validates the
  `INSTALL-DOWNGRADE` and `INTUNE-APP-INSTALL-FAIL` rules.
- **Compliance signals.** Status items `passcode.is-compliant`,
  `diskmanagement.filevault.enabled`, `security.certificate.list` confirm the
  `INTUNE-COMPLIANCE` rule's emphasis on FileVault / passcode / certs.

**Added as a result of the review (grounded in the repo):**
- `MDM-ENROLL-WELLKNOWN` — account-driven enrollment / service-discovery and
  Platform SSO failures, from `mdm/errors/{well-known.failed, psso.required,
  unrecognized.device}.yaml`. `com.apple.well-known.failed` is a 403 returned
  during account-driven enrollment (iOS 17.5+/macOS 14.5+).
- `DDM-APP-STATE` — managed app stuck awaiting user action, using the real
  `app.managed.list` enum: `optional, queued, not-present,
  prompting-for-consent, prompting-for-login, prompting-for-management,
  downloading, installing, managed, managed-but-uninstalled, failed` (and
  update-states `available … updating, failed`).
- `SWUPDATE-FAIL` — DDM-enforced macOS software update failures, from
  `declarative/status/softwareupdate.failure-reason.yaml` (fields: `count`,
  `reason`, `timestamp`).

**Platform SSO (PSSO) — grounded in Microsoft Learn, not the Apple schema.**
PSSO is delivered by the **Microsoft Enterprise SSO extension** inside the
Company Portal app (`com.microsoft.CompanyPortalMac.ssoextension`, team
`UBF8T346G9`) and configured by an Intune settings-catalog Extensible-SSO
profile. Parser `parsers/psso.py` (`Source.PSSO`) reads two surfaces: the broker
log `SSOExtension.log` (Company Portal *Help > Save diagnostic report*, or live
under `…/ssoextension/Data/Library/Caches/Logs/Microsoft/SSOExtension/`) and
Apple `com.apple.AppSSO`/`PlatformSSO` unified-log exports (`AppSSOAgent`,
`AppSSODaemon`, `swcd`; `app-sso platform -s` for state). Rules added:
- `PSSO-REGISTER-FAIL` — registration / device-join failures, re-registration prompts.
- `PSSO-CONFIG-CORRUPT` — `com.apple.PlatformSSO Code=-1001 "Error deserializing
  device config."`, the macOS 15 Sequoia AppSSOAgent/AppSSODaemon concurrency bug
  that triggers a re-registration loop (Apple fix in 15.3).
- `PSSO-PAYLOAD-MISCONFIG` — SSOe payload errors `10001` (missing/inapplicable
  setting) and `10002` (multiple conflicting SSO profiles).
- `PSSO-EXTENSION-INACTIVE` — extension not launched: `PlugInKit Code=16 "other
  version in use"` / tag `4s8qh` (macOS 15.3/iOS 18.1.1), or `invalid team
  identifier` when SIP is disabled.
- `PSSO-PRT-TOKEN` — Primary Refresh Token acquire/refresh failures.
- `PSSO-ASSOCIATED-DOMAIN` — `swcd`/`swcutil`/app-site-association failures, the
  classic symptom of TLS inspection breaking PSSO.
- `PSSO-PASSWORD-SYNC` — Entra↔local password-sync failures (passcode-complexity
  mismatch, per-user MFA, temporary passwords).
Plus `OPP-PSSO-METHOD` (INFO) suggesting Secure Enclave / passkey + Keyvault
recovery when PSSO logs are present.

**CIS Level 1 validation (`cis.py`) — grounded in the CIS Apple macOS
Benchmark.** A curated, log-evidence-based subset of **CIS Level 1** controls
(the essential, low-impact hardening baseline). Each `CISCheck` is declarative:
`fail_findings` (finding IDs that mean fail), `fail_pattern`/`pass_pattern`
(regexes over log lines), and `pass_if_source` (governing source present + no
contrary signal ⇒ pass). Resolution order: fail → positive pass → source-present
pass → not-assessed. Controls implemented (numbers track CIS, shift per OS/bench
version, so indicative):
- `CIS-1.1` Apple software current · `CIS-1.2` automatic app updates (MAU).
- `CIS-2.5.1` FileVault · `CIS-2.5.2` Gatekeeper · `CIS-2.5.3` application
  firewall · `CIS-2.11` disable automatic login.
- `CIS-3.1` security auditing (auditd).
- `CIS-5.2` password/passcode policy · `CIS-5.8` screen-lock password.
- `CIS-6.3` endpoint malware protection (Defender healthy).
- `CIS-MDM` device enrolled & managed (foundation; without it nothing is
  enforceable).
The map ties CIS to our existing signals (e.g. `DEFENDER-*` → `CIS-6.3`,
`MDM-ENROLL-WELLKNOWN`/`INTUNE-ENROLL-FAIL` → `CIS-MDM`, the
`FileVault is not enabled` compliance line → `CIS-2.5.1`). Exposed in HTML (KPI
ring + per-control table), the CLI summary line, the GUI status bar, and the
`cis` key of `--json`. **Future work:** when DDM status-report JSON or the MDM
error envelope is parsed, add structured CIS controls (firewall/Gatekeeper
state, audit config) instead of relying on log-text signals.

**Known gaps / future work:**
- We parse **text logs**, not DDM **status-report JSON**. Intune increasingly
  uses Declarative Device Management; a dedicated parser for DDM status reports
  (`management.declarations`, `app.managed.list`, `softwareupdate.*`) would let
  us read structured state instead of regexing log text.
- The standard MDM error envelope (`ErrorChain`/`ErrorCode`/`ErrorDomain`/
  `LocalizedDescription`) is not yet parsed; worth a structured plist/JSON
  parser if those payloads appear in collected bundles.

---

## 5. Documentation links used

### Apple
- Device management overview & DDM: <https://developer.apple.com/documentation/devicemanagement>
- apple/device-management schema repo: <https://github.com/apple/device-management>
  - App:Managed declaration: <https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/app.managed.yaml>
  - app.managed.list status: <https://github.com/apple/device-management/blob/release/declarative/status/app.managed.list.yaml>
  - softwareupdate.failure-reason status: <https://github.com/apple/device-management/blob/release/declarative/status/softwareupdate.failure-reason.yaml>
  - well-known.failed error: <https://github.com/apple/device-management/blob/release/mdm/errors/well-known.failed.yaml>
  - MDM errors dir: <https://github.com/apple/device-management/tree/release/mdm/errors>
  - Declarative status items dir: <https://github.com/apple/device-management/tree/release/declarative/status>

### Microsoft Learn (log locations & failure modes)
- Shell scripts on macOS + **log collection** (confirms Intune agent log paths
  `/Library/Logs/Microsoft/Intune` & `~/Library/Logs/Microsoft/Intune`, files
  `IntuneMDMDaemon`/`IntuneMDMAgent`): <https://learn.microsoft.com/intune/device-management/tools/run-shell-scripts-macos>
- macOS LOB apps not deployed (CFBundleVersion / install-location requirement):
  <https://learn.microsoft.com/troubleshoot/mem/intune/app-management/macos-lob-apps-not-deployed>
- Set up macOS enrollment: <https://learn.microsoft.com/intune/intune-service/enrollment/macos-enroll>
- Microsoft Enterprise SSO extension troubleshooting (confirms SSO extension log
  path `~/Library/Containers/com.microsoft.CompanyPortalMac.ssoextension/Data/
  Library/Caches/Logs/Microsoft/SSOExtension/`, `SSOExtension.log`, SIP/team-id
  errors, associated-domain/TLS failures, PlugInKit `4s8qh`):
  <https://learn.microsoft.com/entra/identity/devices/troubleshoot-mac-sso-extension-plugin>
- macOS Platform SSO known issues & troubleshooting (`app-sso platform -s`,
  `com.apple.AppSSO` debug logging, Code=-1001 config-corruption loop, password
  sync, per-user MFA): <https://learn.microsoft.com/entra/identity/devices/troubleshoot-macos-platform-single-sign-on-extension>
- Configure Platform SSO for macOS in Intune (settings-catalog profile, error
  codes 10001/10002, auth methods, Keyvault recovery):
  <https://learn.microsoft.com/intune/device-configuration/settings-catalog/configure-platform-sso-macos>
- Microsoft Enterprise SSO plug-in for Apple devices (extension identifier
  `com.microsoft.CompanyPortalMac.ssoextension (UBF8T346G9)`, feature flags):
  <https://learn.microsoft.com/entra/identity-platform/apple-sso-plugin>
- Defender for Endpoint on macOS — resources (`mdatp health`,
  `/Library/Logs/Microsoft/mdatp/`, diagnostic/quarantine paths):
  <https://learn.microsoft.com/defender-endpoint/mac-resources>
- Defender macOS install troubleshooting (`/Library/Logs/Microsoft/mdatp/install.log`,
  `[ERROR]` prefix): <https://learn.microsoft.com/defender-endpoint/mac-support-install>
- Defender macOS performance / RTP exclusions: <https://learn.microsoft.com/defender-endpoint/mac-support-perf>
- Defender macOS troubleshooting mode (profile paths, `managed_by`): <https://learn.microsoft.com/defender-endpoint/mac-troubleshoot-mode>
- Defender macOS privacy (confirms `/Library/Logs/Microsoft/autoupdate.log` &
  `com.microsoft.autoupdate2.plist`): <https://learn.microsoft.com/defender-endpoint/mac-privacy>
- Defender client analyzer on macOS (report.html precedent): <https://learn.microsoft.com/defender-endpoint/run-analyzer-macos>
- SCEP / PKCS certificate troubleshooting: <https://learn.microsoft.com/troubleshoot/mem/intune/certificates/troubleshoot-scep-certificate-profiles>
- Secure your macOS endpoints (Intune FileVault / firewall / Gatekeeper / update
  enforcement; the controls the CIS validation maps to): <https://learn.microsoft.com/intune/solutions/end-to-end-guides/macos-endpoints-get-started>
- macOS endpoint protection settings reference (FileVault / firewall / Gatekeeper
  payloads): <https://learn.microsoft.com/intune/device-configuration/endpoint-security/ref-endpoint-protection-macos>

### CIS (Center for Internet Security)
- CIS Apple macOS Benchmarks (Level 1 / Level 2 hardening controls; the basis
  for `cis.py`): <https://www.cisecurity.org/benchmark/apple_os>

---

## 6. Quick commands

```bash
python3 -m intune_analyzer --input samples --html report.html       # demo
python3 -m intune_analyzer --live --html r.html --pdf r.pdf --open  # on a Mac
python3 -m intune_analyzer --input bundle.zip --client --json o.json
python3 -m intune_analyzer --gui
pytest -q
```
