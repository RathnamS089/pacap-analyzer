"""Tests for the TraceLens terminal UI (Textual app).

Branch goal (codex/tui-analysis-shell): path entry → analyze (read-only) →
evidence/limitations review. The app is driven headless through Textual's
Pilot; every scenario is bounded so a hang fails fast instead of stalling
the suite.
"""

import asyncio
from pathlib import Path
from typing import Any, Callable, List

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.utils import wrpcap

from tracelens.tui.app import AnalysisScreen, PathEntryScreen, TraceLensApp

AP_MAC = "aa:bb:cc:dd:ee:02"

SCENARIO_TIMEOUT_S = 45


def _beacon_only_capture(tmp_path: Path) -> Path:
    capture = tmp_path / "site.pcap"
    beacon = (
        RadioTap(
            present="TSFT+Flags+Rate+Channel+dBm_AntSignal+Antenna",
            ChannelFrequency=2412,  # 2.4 GHz, channel 1
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
        / Dot11Elt(ID=0, info=b"SiteNet")  # SSID
        / Dot11Elt(ID=3, info=bytes([1]))  # DS parameter set (channel)
    )
    wrpcap(str(capture), [beacon])
    return capture


def _run(coro: Any) -> None:
    asyncio.run(asyncio.wait_for(coro, timeout=SCENARIO_TIMEOUT_S))


async def _submit_path(pilot: Any, path: str) -> None:
    """Type a capture path into the entry screen and press Enter."""
    entry = pilot.app.query_one("#capture-path")
    entry.focus()
    entry.value = path
    await pilot.pause()
    await pilot.press("enter")
    await pilot.pause()


async def _wait_until(predicate: Callable[[], bool], pilot: Any) -> bool:
    """Poll a predicate while pumping the Textual message loop."""
    for _ in range(200):  # Bounded: ~10 s at 50 ms per step.
        if predicate():
            return True
        await asyncio.sleep(0.05)
        await pilot.pause()
    return False


def _list_texts(list_view: Any) -> List[str]:
    texts: List[str] = []
    for item in list_view.children:
        for child in item.children:
            texts.append(str(child.render()))
    return texts


def test_enter_path_shows_evidence_and_limitations(tmp_path: Path) -> None:
    capture = _beacon_only_capture(tmp_path)

    async def scenario() -> None:
        app = TraceLensApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await _submit_path(pilot, str(capture))
            assert await _wait_until(lambda: app.analysis is not None, pilot), (
                "analysis never completed"
            )

            assert isinstance(app.screen, AnalysisScreen)
            assert app.screen.result.capture_format == "pcap"
            assert app.screen.result.packet_count == 1

            fact_texts = _list_texts(app.screen.query_one("#facts-list"))
            assert any("SiteNet" in text for text in fact_texts)
            assert any("channel" in text.lower() for text in fact_texts)

            limitation_texts = _list_texts(
                app.screen.query_one("#limitations-list")
            )
            assert limitation_texts == [
                "Auth/association frames: not present in this capture.",
                "Disconnect (deauth/disassoc) frames: not present in this "
                "capture.",
                "Roaming: cannot be assessed because no client reassociation "
                "frames are present in this capture.",
            ]

    _run(scenario())


def test_missing_file_shows_friendly_error_on_entry_screen(tmp_path: Path) -> None:
    async def scenario() -> None:
        app = TraceLensApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await _submit_path(pilot, str(tmp_path / "nope.pcap"))
            assert await _wait_until(
                lambda: app.error_message is not None, pilot
            ), "error never surfaced"

            assert "not found" in app.error_message
            assert isinstance(app.screen, PathEntryScreen)
            assert app.analysis is None
            assert "not found" in str(
                app.query_one("#entry-status").render()
            )

    _run(scenario())


def test_escape_from_analysis_returns_to_path_entry(tmp_path: Path) -> None:
    capture = _beacon_only_capture(tmp_path)

    async def scenario() -> None:
        app = TraceLensApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await _submit_path(pilot, str(capture))
            assert await _wait_until(lambda: app.analysis is not None, pilot), (
                "analysis never completed"
            )

            await pilot.press("escape")
            await pilot.pause()

            assert isinstance(app.screen, PathEntryScreen)
            assert app.query_one("#capture-path").value == str(capture)

    _run(scenario())