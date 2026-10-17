# TraceLens

TraceLens is a local-first Wi-Fi survey report writer for installers. Load a
Wi-Fi packet capture you own or are authorized to inspect, review the evidence
extracted from it, and draft a clear customer-facing report — all on your own
machine.

TraceLens is under active development. The current build provides the
capture-analysis core (reader + evidence analyzer) as a tested Python
package plus a terminal UI (Textual) for the load → analyze → review
evidence/limitations flow; local-model explanations and report export
arrive in upcoming branches.

## What it does today

- Opens PCAP and PCAPNG files **read-only**, locally, with clear errors for
  missing, empty, non-capture, or truncated files.
- Extracts deterministic, packet-backed evidence:
  - frame mix (management / control / data counts),
  - channels observed (from RadioTap channel frequency),
  - beaconed SSIDs,
  - retry rate among data frames (Frame Control retry bit),
  - signal strength summary (RadioTap RSSI, only when the capturing adapter
    recorded it),
  - client association / reassociation activity (per client MAC).
- Separates **measured facts** from **limitations**: if the capture has no
  RSSI, no auth/association frames, no disconnects, or no roaming evidence,
  TraceLens says so explicitly instead of guessing. Absent packets are never
  treated as proof that something did not happen.
- Flags non-Wi-Fi content it recognizes (e.g. Bluetooth HCI packets in an
  associated capture) instead of mixing it into Wi-Fi evidence.

## What it never does

- No live capture, packet injection, network scanning, or joining networks.
- No uploads: captures are processed locally and never sent to any remote
  service.
- No claims of root cause from incomplete packet evidence.

## Setup

Requires Python 3.9+.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

## Running the tests

```bash
.venv/bin/python -m pytest
```

## Using the terminal UI

```bash
.venv/bin/tracelens
```

Then:

1. Type the path to a capture you own or are authorized to inspect
   (PCAP or PCAPNG) and press Enter.
2. TraceLens validates the file read-only and analyzes it locally.
3. The evidence screen lists measured facts (frame mix, channels, SSIDs,
   retry rate, RSSI when present, client association activity) and the
   limitations of this capture — what it cannot support, stated explicitly.
4. Press Escape to go back and analyze another capture.

Reader/analyzer failures (missing file, wrong format, truncation) are shown
on the entry screen as friendly messages; the app never crashes on a bad
path.

## Using the library

```python
from tracelens.reader import load_capture
from tracelens.analyzer import analyze_capture

analysis = analyze_capture(load_capture("site-survey.pcapng"))
for fact in analysis["facts"]:
    print(fact["kind"], fact["detail"])
for limitation in analysis["limitations"]:
    print("LIMITATION:", limitation)
```

`analysis` is a plain dict: `capture_info` (path, format, packet count),
`facts` (each with a `kind` and a `detail` dict), `limitations`, and `notes`.
Facts are safe to serialize to JSON.

## Known limitations

- Evidence quality depends entirely on the capture: a survey capture taken
  with a monitor-mode adapter and RadioTap headers supports far more
  conclusions than a wired-side capture.
- Channels come from RadioTap metadata; captures without RadioTap (or without
  the Channel field) report no channel evidence.
- Retry rate counts frames whose retry bit is set — a proxy for busy air or
  marginal links, not proof of either.
- Client MACs are reported as captured; anonymization before report export is
  planned for a dedicated privacy branch.

## Roadmap

1. ~~Terminal UI (Textual): pick a capture, review evidence and limitations.~~
2. Optional local-model explanations via Ollama (never required; evidence
   works without it).
3. Editable Markdown report export with site notes and anonymization.
