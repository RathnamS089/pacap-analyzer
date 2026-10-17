"""TUI tests for the report flow.

Branch goal (codex/report-builder) UI half: from the evidence screen, "r"
opens a report screen with a read-only Markdown preview, an editable
site-notes TextArea, and a save action ("s") that writes the composed
front-matter + body document to a .md file chosen via the path Input.
Fail-soft: a bad save path shows a friendly message and stays usable.
"""

import asyncio
from pathlib import Path
from typing import Any, Callable

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.utils import wrpcap
from textual.widgets import Input, Static, TextArea

from tracelens.tui.app import AnalysisScreen, ReportScreen, TraceLensApp

AP_MAC = "aa:bb:cc:dd:ee:02"
SCENARIO_TIMEOUT_S = 45


def _beacon_capture(tmp_path: Path) -> Path:
    capture = tmp_path / "site.pcap"
    beacon = (
        RadioTap(
            present="TSFT+Flags+Rate+Channel+dBm_AntSignal+Antenna",
            ChannelFrequency=2412,
            dBm_AntSignal=-52,
        )
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=AP_MAC,
            addr3=AP_MAC,
        )
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, info=b"SiteNet")
        / Dot11Elt(ID=3, info=bytes([1]))
    )
    wrpcap(str(capture), [beacon])
    return capture


def _run(coro: Any) -> None:
    asyncio.run(asyncio.wait_for(coro, timeout=SCENARIO_TIMEOUT_S))


async def _open_analysis(pilot: Any, capture: Path) -> None:
    entry = pilot.app.query_one("#capture-path")
    entry.focus()
    entry.value = str(capture)
    await pilot.pause()
    await pilot.press("enter")
    await pilot.pause()
    for _ in range(200):
        if pilot.app.analysis is not None:
            return
        await asyncio.sleep(0.05)
        await pilot.pause()
    raise AssertionError("analysis never completed")


async def _wait_until(predicate: Callable[[], bool], pilot: Any) -> None:
    for _ in range(200):
        if predicate():
            return
        await asyncio.sleep(0.05)
        await pilot.pause()
    raise AssertionError("condition never met")


def test_press_r_opens_report_screen_with_preview(tmp_path: Path) -> None:
    capture = _beacon_capture(tmp_path)

    async def scenario() -> None:
        app = TraceLensApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await _open_analysis(pilot, capture)
            assert isinstance(app.screen, AnalysisScreen)

            await pilot.press("r")
            await pilot.pause()

            assert isinstance(app.screen, ReportScreen)
            preview_text = str(app.screen.query_one("#report-preview").render())
            assert "SiteNet" in preview_text
            assert "Measured Evidence" in preview_text
            assert "Site Notes" in preview_text

    _run(scenario())


def test_site_notes_and_save_write_markdown_file(tmp_path: Path) -> None:
    capture = _beacon_capture(tmp_path)
    out_path = tmp_path / "survey-report.md"

    async def scenario() -> None:
        app = TraceLensApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await _open_analysis(pilot, capture)

            await pilot.press("r")
            await pilot.pause()
            assert isinstance(app.screen, ReportScreen)

            notes = app.screen.query_one("#site-notes", TextArea)
            notes.focus()
            notes.text = "Lobby AP mounted too low."
            await pilot.pause()

            save_entry = app.screen.query_one("#report-path", Input)
            save_entry.focus()
            save_entry.value = str(out_path)
            await pilot.pause()

            await pilot.press("enter")  # Enter in the path field saves.
            await _wait_until(lambda: out_path.exists(), pilot)

            text = out_path.read_text(encoding="utf-8")
            assert text.startswith("---\n")
            assert "# Wi-Fi Survey Report" in text
            assert "## Site Notes" in text
            assert "Lobby AP mounted too low." in text
            assert "SiteNet" in text
            # Friendly confirmation on screen.
            status = str(app.screen.query_one("#report-status").render())
            assert str(out_path) in status
            # Escape returns to the evidence screen, which stays usable.
            await pilot.press("escape")
            await pilot.pause()
            assert isinstance(app.screen, AnalysisScreen)

    _run(scenario())


def test_bad_save_path_fails_soft_with_message(tmp_path: Path) -> None:
    capture = _beacon_capture(tmp_path)

    async def scenario() -> None:
        app = TraceLensApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await _open_analysis(pilot, capture)

            await pilot.press("r")
            await pilot.pause()
            assert isinstance(app.screen, ReportScreen)

            save_entry = app.screen.query_one("#report-path", Input)
            save_entry.focus()
            # A directory cannot be written as the report file.
            save_entry.value = str(tmp_path)
            await pilot.pause()

            await pilot.press("enter")  # Enter in the path field saves.
            await _wait_until(
                lambda: "could not" in str(
                    app.screen.query_one("#report-status").render()
                ).lower(),
                pilot,
            )
            # The report screen stays open and usable.
            assert isinstance(app.screen, ReportScreen)

    _run(scenario())
