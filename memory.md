# TraceLens — Session Memory

_Created 2026-10-15 from the implementation conversation. Working notes for
future sessions; not part of the application code._

## Product context

TraceLens (`/Users/rathnam.s/trance-lens`) is a local-first Wi-Fi survey
report writer for installers: load a PCAP/PCAPNG capture you own or are
authorized to inspect, review measured evidence, draft a customer report.

Hard rules that must hold in every branch:

- No live capture, packet injection, active scanning, or network changes.
- Measured facts are separated from possible interpretations; no root-cause
  claims from incomplete packet evidence; absent packets are never proof an
  event did not happen.
- Missing evidence (RSSI, auth, disconnects, roaming) is reported explicitly
  as a limitation.
- Everything is processed locally; captures and packet data never leave the
  machine; model use is optional (Ollama) and evidence must work without it.
- Anonymization available before report export; mapping kept in memory only.

## Stack and workflow

- Python 3.9 venv at `.venv/`; scapy==2.8.0, textual==8.2.8, pytest==8.4.2
  (pinned in pyproject.toml).
- Test command: `.venv/bin/python -m pytest`; editable install:
  `.venv/bin/pip install -e '.[dev]'`.
- Branch-by-branch development, `codex/` prefix, one focused branch at a
  time; never commit/push/merge unless explicitly asked; TDD
  (RED → GREEN → REFACTOR) with tests written first.
- Architecture layers: capture reader → evidence analyzer → (planned)
  Ollama explainer → report builder → Textual TUI.
- Skills: `tracelens-dev` (project pitfalls + conventions) and
  `test-driven-development` are saved in Hermes and should be loaded for
  any work in this repo.

## Environment notes

- The repo has its own git (initialized this session, default branch
  `master`, work happens on `codex/` branches). A stray commit-less repo
  exists at `$HOME` — never run git from the home directory.
- Terminal commands may require user approval; unanswered prompts time out
  after ~5 minutes. Prefer test files / pytest over `python -c` probes.
- The session hit "turn lease" interruptions twice; workspace state
  (venv, deps, branch, files) survived each time.

## What happened this session

- Initialized the repo, created the venv, installed pinned deps, created
  branch `codex/capture-reader-analyzer`.
- Implemented (staged, NOT committed):
  - `tracelens/reader.py` — magic-byte sniffing (pcap / pcapng), a manual
    classic-pcap record walk to catch truncation that scapy silently skips,
    streaming `LoadedCapture.iter_packets()` (one packet in memory at a
    time), friendly ValueErrors for missing/empty/non-capture/truncated.
  - `tracelens/analyzer.py` — deterministic facts: frame mix, channels from
    RadioTap ChannelFrequency, beaconed SSIDs, data-frame retry rate, RSSI
    summary (only when the adapter recorded it), per-client
    assoc/reassoc counts; explicit limitations for missing evidence;
    Bluetooth packets noted and excluded from Wi-Fi evidence.
  - `tests/test_capture_analyzer.py` — 8 tests built from real scapy
    frames (scapy 2.8 has no `wlcapsim` module and no `Bluetooth4SHIELD`
    export; frames are constructed from RadioTap/Dot11/Dot11Beacon/
    Dot11Elt/Dot11AssoReq and HCI_PHDR_Hdr/HCI_Hdr).
  - `README.md`, `pyproject.toml`, `.gitignore`.
- Checks actually run: RED verified (ModuleNotFoundError), then
  `8 passed in 0.24s`; `pip install -e .` verified; imports verified.
- Nothing was committed; all files staged with `git add -A`.
- Scapy pitfalls and conventions are recorded in the `tracelens-dev` skill.

## Known limitations after branch 1

- pcapng truncation detection relies on scapy exceptions (no independent
  record walk for pcapng yet).
- No capture-timespan fact yet; no per-channel retry split.
- No anonymization yet (planned privacy branch).
- No TUI yet: the library is usable only from Python.

## To-do checkpoint

- [x] 1. codex/capture-reader-analyzer — capture reader + evidence analyzer
  (DONE: commit 583b34a, 8/8 tests)
- [x] 2. codex/tui-analysis-shell — Textual TUI: path entry → analyze →
  evidence/limitations review (DONE: commit bf5c63f, 13/13 tests; app runs
  via `.venv/bin/tracelens`; agent_session.md created for DevRelay submission)
- [x] 3. codex/ollama-explainer — optional local-model explanations
  (DONE: never required, evidence works without it; tests use in-process
  fake Ollama + closed port; press 'e' on evidence screen; fails soft)
- [x] 4. codex/report-builder — editable Markdown report with site notes
  (DONE: commit 6f59a10, 30/30 tests; build_report/build_preview/
  write_report_file in tracelens/report.py; 'r' on the evidence screen;
  SSID->BSSID evidence added to the analyzer)
- [x] 5. codex/privacy-anonymization — MAC/IP/SSID anonymization before
  export, mapping in memory only (DONE: tracelens/privacy.py +
  ctrl+r toggle on the report screen; 38/38 tests)

All five roadmap branches are complete. Per the project owner's
instruction, codex/report-builder and codex/privacy-anonymization remain
unmerged feature branches - do not merge them into master/main.

## Next branch recommendation

None — all five roadmap items are complete. Possible follow-ups: a
per-channel retry split, an independent pcapng truncation walk, or wiring
the anonymized export into a CLI batch mode.

## Known limitations after branch 5

- The identity map from build_anonymized_report is lost when the process
  exits (by design: mapping kept in memory only).
- SSID pseudonyms follow the analyzer's sorted order, so re-running the
  tool on a modified capture can assign a different pseudonym to the same
  SSID; there is no cross-run identity persistence.
- The report screen's site-notes TextArea intentionally captures printable
  keys; toggles on that screen must use ctrl-style keys (Textual filters
  consumed keys out of screen bindings).
