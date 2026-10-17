"""TraceLens terminal UI: path entry → analyze → evidence/limitations review.

Read-only by design: the app opens user-supplied capture files through the
reader, extracts evidence with the analyzer, and displays it. It never
touches the network and never writes to the capture.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import (
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Static,
    TextArea,
)

from tracelens.explainer import (
    DEFAULT_MODEL as DEFAULT_EXPLAINER_MODEL,
    DEFAULT_OLLAMA_URL as DEFAULT_EXPLAINER_URL,
    ExplainerUnavailable,
    explain_analysis,
)
from tracelens.privacy import build_anonymized_report
from tracelens.report import build_report, write_report_file
from tracelens.tui.service import (
    AnalysisError,
    AnalysisResult,
    TraceLensService,
)

_KIND_TITLES = {
    "capture_summary": "Frame mix",
    "channel_usage": "Channels observed",
    "beaconed_ssids": "Beaconed SSIDs",
    "retry_rate": "Data-frame retry rate",
    "signal_strength": "Signal strength (RSSI)",
    "client_auth_frames": "Client association activity",
}

DEFAULT_OLLAMA_URL = DEFAULT_EXPLAINER_URL
DEFAULT_MODEL = DEFAULT_EXPLAINER_MODEL


def _fact_lines(fact: Dict[str, Any]) -> List[str]:
    """Render one analyzer fact as human-readable evidence lines."""
    kind = fact["kind"]
    detail = fact.get("detail", {})
    if kind == "capture_summary":
        return [
            "packets analyzed: {packets_analyzed}, Wi-Fi frames: "
            "{frames_with_wlan} (mgmt {management_frames} / ctrl "
            "{control_frames} / data {data_frames})".format(**detail)
        ]
    if kind == "channel_usage":
        counts = detail["channel_counts"]
        return [
            ", ".join(
                "channel {c}: {n} frames".format(c=c, n=counts[c])
                for c in detail["channels"]
            )
        ]
    if kind == "beaconed_ssids":
        counts = detail["ssid_counts"]
        return [
            ", ".join(
                "{s} ({n} beacons)".format(s=s, n=counts[s])
                for s in detail["ssids"]
            )
        ]
    if kind == "retry_rate":
        checked = detail["data_frames_checked"]
        retried = detail["data_frames_with_retry_flag"]
        return [
            "{r} of {c} data frames had the retry bit set "
            "({p}%)".format(
                r=retried,
                c=checked,
                p=round(100 * retried / checked, 1) if checked else 0,
            )
        ]
    if kind == "signal_strength":
        return [
            "RSSI {min} to {max} dBm, average {avg} dBm "
            "({n} frames)".format(
                min=detail["rssi_min_dbm"],
                max=detail["rssi_max_dbm"],
                avg=detail["rssi_avg_dbm"],
                n=detail["frames_with_rssi"],
            )
        ]
    if kind == "client_auth_frames":
        per_client = detail["per_client"]
        return [
            "{client}: {counts}".format(
                client=client,
                counts=", ".join(
                    "{k}: {v}".format(k=k, v=v) for k, v in counts.items()
                ),
            )
            for client, counts in per_client.items()
        ]
    return ["{kind}: {json}".format(kind=kind, json=detail)]


class PathEntryScreen(Screen):
    """Enter a capture path and start the read-only analysis."""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(
            "[b]TraceLens[/] — local-first Wi-Fi survey evidence",
            id="entry-title",
        )
        yield Label(
            "Load a PCAP/PCAPNG capture you own or are authorized to inspect. "
            "Everything stays on this machine.",
            id="entry-help",
        )
        yield Input(
            placeholder="/path/to/site-survey.pcap",
            id="capture-path",
        )
        yield Static("", id="entry-status")
        yield Footer()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "capture-path":
            app = self.app
            if isinstance(app, TraceLensApp):
                app.analyze_capture(event.value)

    def refresh_status(self, message: str) -> None:
        self.query_one("#entry-status", Static).content = message


class AnalysisScreen(Screen):
    """Review the measured evidence and explicit limitations."""

    BINDINGS = [
        ("escape", "app.pop_screen", "Back to path entry"),
        ("e", "app.request_explanation", "Explain (local model)"),
        ("r", "app.open_report", "Build report"),
    ]

    def __init__(self, result: AnalysisResult) -> None:
        super().__init__()
        self.result = result

    def compose(self) -> ComposeResult:
        info = self.result.analysis["capture_info"]
        yield Header()
        yield Label(
            "[b]Evidence[/] — {path} ({fmt}, {n} packets)".format(
                path=info["path"], fmt=info["format"], n=info["packet_count"]
            ),
            id="analysis-title",
        )
        yield Static("[b]Measured evidence[/b]", id="facts-heading")
        yield ListView(id="facts-list")
        yield Static("[b]Limitations of this capture[/b]", id="limits-heading")
        yield ListView(id="limitations-list")
        yield Static("", id="explanation-box")
        yield Footer()

    def on_mount(self) -> None:
        facts_list = self.query_one("#facts-list", ListView)
        limits_list = self.query_one("#limitations-list", ListView)
        for fact in self.result.analysis["facts"]:
            title = _KIND_TITLES.get(fact["kind"], fact["kind"])
            facts_list.append(ListItem(Label("[b]{t}[/b]".format(t=title))))
            for line in _fact_lines(fact):
                facts_list.append(ListItem(Label("  " + line)))
        limitations = self.result.analysis["limitations"]
        if not limitations:
            limits_list.append(
                ListItem(Label("No survey-topic limitations recorded."))
            )
        for limitation in limitations:
            limits_list.append(ListItem(Label(limitation)))


class ReportScreen(Screen):
    """Preview the Markdown report, edit site notes, and save it.

    Press "ctrl+r" to toggle anonymization: the preview re-renders redacted
    (MACs/IPs/SSIDs replaced with placeholders, capture path neutralized)
    and saving writes the anonymized copy. The identity map stays in
    memory on the screen; it is never written to disk.
    """

    BINDINGS = [
        ("escape", "app.pop_screen", "Back to evidence"),
        Binding(
            "ctrl+r",
            "app.toggle_anonymization",
            "Toggle anonymization",
        ),
    ]

    def __init__(self, result: AnalysisResult) -> None:
        super().__init__()
        self.result = result
        self.anonymized = False
        self.report: Dict[str, Any] = {}
        self.identity_map: Dict[str, Dict[str, str]] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Label(
            "[b]Report[/] — read-only preview; edit site notes, type a .md "
            "path and press Enter (or s) to save. ctrl+r toggles "
            "anonymization.",
            id="report-title",
        )
        yield Static("", id="report-preview")
        yield Label("Site notes (editable):", id="notes-label")
        yield TextArea("", id="site-notes")
        yield Input(
            placeholder="/path/to/survey-report.md",
            id="report-path",
        )
        yield Static("", id="report-status")
        yield Footer()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Enter in the save-path field saves the report."""
        if event.input.id == "report-path":
            app = self.app
            if isinstance(app, TraceLensApp):
                app.action_save_report()

    def on_mount(self) -> None:
        self._rebuild_report()

    def _rebuild_report(self) -> None:
        """Render the report (plain or anonymized) into the preview."""
        site_notes = self.query_one("#site-notes", TextArea).text
        if self.anonymized:
            self.report, self.identity_map = build_anonymized_report(
                self.result.analysis,
                site_notes=site_notes,
            )
        else:
            self.report = build_report(
                self.result.analysis, site_notes=site_notes
            )
            self.identity_map = {}
        self.query_one("#report-preview", Static).content = self.report[
            "markdown"
        ]
        mode = "anonymized" if self.anonymized else "plain"
        self.refresh_status(
            "Report mode: {mode} (ctrl+r toggles).".format(mode=mode)
        )

    def refresh_status(self, message: str) -> None:
        self.query_one("#report-status", Static).content = message


class TraceLensApp(App[None]):
    TITLE = "TraceLens"
    CSS = """
    #entry-title {
        padding: 1 2;
    }
    #entry-help {
        padding: 0 2 1 2;
        color: $text-muted;
    }
    #capture-path {
        margin: 0 2;
    }
    #entry-status {
        padding: 1 2;
    }
    #analysis-title, #facts-heading, #limits-heading {
        padding: 0 2;
    }
    #facts-list, #limitations-list {
        height: 1fr;
    }
    """

    def __init__(
        self,
        explainer_url: str = DEFAULT_OLLAMA_URL,
        explainer_model: str = DEFAULT_MODEL,
    ) -> None:
        super().__init__()
        self.analysis: Optional[AnalysisResult] = None
        self.error_message: Optional[str] = None
        self._analyzing = False
        self.service = TraceLensService()
        self.explainer_url = explainer_url
        self.explainer_model = explainer_model
        self.explanation: Optional[str] = None
        self.explainer_error: Optional[str] = None

    def get_default_screen(self) -> Screen:
        """The entry screen is the base of the screen stack."""
        return PathEntryScreen()

    def compose(self) -> ComposeResult:
        # Single-screen stack: push/pop manages navigation; never yield a
        # Screen inside App.compose().
        yield from []

    def on_mount(self) -> None:
        # PathEntryScreen is already the default/base screen; nothing to push.
        self._entry_ready = True

    def action_back_to_entry(self) -> None:
        self.pop_screen()

    def action_open_report(self) -> None:
        """Open the report preview screen for the current analysis."""
        if self.analysis is None:
            return
        self.push_screen(ReportScreen(self.analysis))

    def action_toggle_anonymization(self) -> None:
        """Flip the report screen between plain and anonymized modes."""
        screen = self.screen
        if isinstance(screen, ReportScreen):
            screen.anonymized = not screen.anonymized
            screen._rebuild_report()

    def action_save_report(self) -> None:
        """Save the report as Markdown using the path typed on the screen.

        Fail-soft: a bad path shows a friendly message on the report
        screen, which stays fully usable.
        """
        screen = self.screen
        if not isinstance(screen, ReportScreen):
            return
        path_text = ""
        try:
            path_text = screen.query_one("#report-path", Input).value.strip()
        except Exception:  # noqa: BLE001 - screen may not be mounted yet
            pass
        if not path_text:
            screen.refresh_status("Enter a .md file path to save the report.")
            return

        # Rebuild with the site notes currently in the editor so the saved
        # report reflects what the user reviewed on screen; the screen's
        # anonymization mode decides whether identifiers are redacted.
        site_notes = screen.query_one("#site-notes", TextArea).text
        identity_map = {}
        if screen.anonymized:
            report, identity_map = build_anonymized_report(
                screen.result.analysis,
                site_notes=site_notes,
            )
        else:
            report = build_report(
                screen.result.analysis,
                site_notes=site_notes,
            )
        try:
            written = write_report_file(report, Path(path_text))
        except Exception as err:  # noqa: BLE001 - fail soft, keep the screen
            screen.refresh_status(
                "Could not save the report: {err}. "
                "Check the path (a .md file) and try again.".format(err=err)
            )
            return
        screen.refresh_status("Report saved: {path}".format(path=written))

    def action_request_explanation(self) -> None:
        """Ask the user's local Ollama model for plain-language notes.

        Strictly optional and fails soft: on any explainer error the
        evidence screen stays fully usable and the box shows a friendly
        message instead of a traceback. The model only ever receives the
        already-extracted facts and limitations, never raw packets.
        """
        if self.analysis is None or self.explanation is not None:
            return
        self.explainer_error = None
        box = self._explanation_box()
        if box is not None:
            box.content = "Asking the local model…"
        try:
            result = explain_analysis(
                self.analysis.analysis,
                model=self.explainer_model,
                url=self.explainer_url,
            )
        except ExplainerUnavailable as err:
            self.explainer_error = str(err)
            if box is not None:
                box.content = str(err)
            return
        self.explanation = result.text
        if box is not None:
            box.content = (
                "[b]Plain-language notes (local model, optional):[/b]\n"
                + result.text
            )

    def _explanation_box(self) -> Optional[Static]:
        screen = self.screen
        if not isinstance(screen, AnalysisScreen):
            return None
        try:
            return screen.query_one("#explanation-box", Static)
        except Exception:  # noqa: BLE001 - screen may not be mounted yet
            return None

    def analyze_capture(self, path: str) -> None:
        """Analyze the capture at ``path`` read-only and show the evidence.

        Analysis is synchronous and fast (local disk read), so it runs inline;
        failures are displayed on the entry screen instead of crashing the UI.
        """
        if self._analyzing:
            return
        self.analysis = None
        self.error_message = None
        self._analyzing = True
        try:
            result = self.service.analyze(path)
        except AnalysisError as err:
            self._analyzing = False
            self._show_error(str(err))
            return
        except Exception as err:  # noqa: BLE001 - keep the UI alive
            self._analyzing = False
            self._show_error(str(err))
            return
        self._analyzing = False
        self.analysis = result
        self.push_screen(AnalysisScreen(result))

    def _show_error(self, message: str) -> None:
        self.error_message = message
        screen = self.screen
        if isinstance(screen, PathEntryScreen):
            screen.refresh_status(message)