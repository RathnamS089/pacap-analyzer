"""TraceLens terminal UI: path entry → analyze → evidence/limitations review.

Read-only by design: the app opens user-supplied capture files through the
reader, extracts evidence with the analyzer, and displays it. It never
touches the network and never writes to the capture.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import (
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Static,
)

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

    BINDINGS = [("escape", "app.pop_screen", "Back to path entry")]

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

    def __init__(self) -> None:
        super().__init__()
        self.analysis: Optional[AnalysisResult] = None
        self.error_message: Optional[str] = None
        self._analyzing = False
        self.service = TraceLensService()

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