"""TUI tests for the anonymization toggle on the report screen.

Branch goal (codex/privacy-anonymization) UI half: on the report screen,
"a" toggles anonymization; the preview immediately re-renders redacted,
and saving while the toggle is on writes a report free of MACs/SSIDs and
the operator's directory structure.
"""

import asyncio
from pathlib import Path
from typing import Any, Callable

from scapy.layers.dot11 import Dot11, Dot11AssoReq, Dot11Beacon, Dot11Elt, RadioTap
from scapy.utils import wrpcap
from textual.widgets import Input, Static

from tracelens.tui.app import ReportScreen, TraceLensApp

AP_MAC = "aa:bb:cc:dd:ee:02"
CLIENT_MAC = "aa:bb:cc:dd:ee:04"
SITE_SSID = "SiteNet"
SCENARIO_TIMEOUT_S = 45

_RADIOTAP = dict(
    present="TSFT+Flags+Rate+Channel+dBm_AntSignal+Antenna",
    ChannelFrequency=2412,
    dBm_AntSignal=-52,
)


def _capture_with_client(tmp_path: Path) -> Path:
    capture = tmp_path / "site.pcap"
    beacon = (
        RadioTap(**_RADIOTAP)
        / Dot11(
            type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP_MAC, addr3=AP_MAC
        )
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, info=SITE_SSID.encode())
        / Dot11Elt(ID=3, info=bytes([1]))
    )
    assoc_req = (
        RadioTap(**_RADIOTAP)
        / Dot11(type=0, subtype=0, addr1=AP_MAC, addr2=CLIENT_MAC, addr3=AP_MAC)
        / Dot11AssoReq(cap="ESS", listen_interval=1)
        / Dot11Elt(ID=0, info=SITE_SSID.encode())
    )
    wrpcap(str(capture), [beacon, assoc_req])
    return capture


def _run(coro: Any) -> None:
    asyncio.run(asyncio.wait_for(coro, timeout=SCENARIO_TIMEOUT_S))


async def _open_report(pilot: Any, capture: Path) -> None:
    entry = pilot.app.query_one("#capture-path")
    entry.focus()
    entry.value = str(capture)
    await pilot.pause()
    await pilot.press("enter")
    await pilot.pause()
    for _ in range(200):
        if pilot.app.analysis is not None:
            break
        await asyncio.sleep(0.05)
        await pilot.pause()
    await pilot.press("r")
    await pilot.pause()
    assert isinstance(pilot.app.screen, ReportScreen)


async def _wait_until(predicate: Callable[[], bool], pilot: Any) -> None:
    for _ in range(200):
        if predicate():
            return
        await asyncio.sleep(0.05)
        await pilot.pause()
    raise AssertionError("condition never met")


def test_toggle_a_redacts_preview_and_save(tmp_path: Path) -> None:
    capture = _capture_with_client(tmp_path)
    out_path = tmp_path / "customer-report.md"

    async def scenario() -> None:
        app = TraceLensApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await _open_report(pilot, capture)

            preview = str(app.screen.query_one("#report-preview").render())
            assert AP_MAC in preview  # plain mode shows identifiers

            # Toggle anonymization on; ctrl+r works from the report screen.
            await pilot.press("ctrl+r")
            await pilot.pause()

            redacted = str(app.screen.query_one("#report-preview").render())
            assert AP_MAC not in redacted
            assert CLIENT_MAC not in redacted
            assert SITE_SSID not in redacted
            assert "Site 1" in redacted
            assert "MAC-01" in redacted

            # Saving the anonymized report keeps the file clean, including
            # the front-matter capture path.
            save_entry = app.screen.query_one("#report-path", Input)
            save_entry.focus()
            save_entry.value = str(out_path)
            await pilot.pause()
            await pilot.press("enter")
            await _wait_until(lambda: out_path.exists(), pilot)

            text = out_path.read_text(encoding="utf-8")
            assert AP_MAC not in text
            assert CLIENT_MAC not in text
            assert SITE_SSID not in text
            assert str(tmp_path) not in text
            assert "MAC-01" in text

    _run(scenario())


def test_toggle_off_restores_plain_report(tmp_path: Path) -> None:
    capture = _capture_with_client(tmp_path)

    async def scenario() -> None:
        app = TraceLensApp()
        async with app.run_test(size=(100, 40)) as pilot:
            await _open_report(pilot, capture)

            await pilot.press("ctrl+r")
            await pilot.pause()
            redacted = str(app.screen.query_one("#report-preview").render())
            assert AP_MAC not in redacted

            await pilot.press("ctrl+r")
            await pilot.pause()
            plain = str(app.screen.query_one("#report-preview").render())
            assert AP_MAC in plain
            assert SITE_SSID in plain

    _run(scenario())
