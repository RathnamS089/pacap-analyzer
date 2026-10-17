"""TUI tests for the optional local-model explanation action.

Branch goal (codex/ollama-explainer) UI half: on the evidence screen, "e"
asks the user's own local Ollama model for plain-language notes. The action
is optional and fails soft: when Ollama is unavailable the evidence screen
stays fully usable and shows a friendly message.
"""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.utils import wrpcap
from textual.widgets import Static

from tracelens.tui.app import AnalysisScreen, TraceLensApp

AP_MAC = "aa:bb:cc:dd:ee:02"
SCENARIO_TIMEOUT_S = 45

EXPLANATION_TEXT = "One network was visible on channel 1 with steady signal."


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


class FakeOllama:
    """In-process stand-in for Ollama's HTTP API; records every request."""

    def __init__(self, response_text: str = EXPLANATION_TEXT) -> None:
        self.captured: List[Dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                outer.captured.append(json.loads(self.rfile.read(length)))
                body = json.dumps(
                    {"model": "fake-model", "response": response_text, "done": True}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_address[1]
        self._thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture()
def fake_ollama() -> Iterator[FakeOllama]:
    server = FakeOllama()
    yield server
    server.stop()


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


async def _wait_until(predicate: Any, pilot: Any) -> None:
    for _ in range(200):
        if predicate():
            return
        await asyncio.sleep(0.05)
        await pilot.pause()
    raise AssertionError("condition never met")


def test_press_e_shows_local_model_explanation(
    tmp_path: Path, fake_ollama: FakeOllama
) -> None:
    capture = _beacon_capture(tmp_path)

    async def scenario() -> None:
        app = TraceLensApp(explainer_url=fake_ollama.url, explainer_model="fake-model")
        async with app.run_test(size=(100, 40)) as pilot:
            await _open_analysis(pilot, capture)
            assert isinstance(app.screen, AnalysisScreen)

            await pilot.press("e")
            await _wait_until(lambda: app.explanation is not None, pilot)

            box = app.screen.query_one("#explanation-box", Static)
            assert EXPLANATION_TEXT in str(box.content)
            # The model saw the extracted facts, never raw packets.
            request = fake_ollama.captured[-1]
            assert "SiteNet" in request["prompt"]
            assert "packets_analyzed" in request["prompt"]

    _run(scenario())


def test_press_e_fails_soft_when_ollama_unreachable(tmp_path: Path) -> None:
    capture = _beacon_capture(tmp_path)

    async def scenario() -> None:
        app = TraceLensApp(explainer_url="http://127.0.0.1:1")
        async with app.run_test(size=(100, 40)) as pilot:
            await _open_analysis(pilot, capture)

            await pilot.press("e")
            await _wait_until(lambda: app.explainer_error is not None, pilot)

            box_text = str(app.screen.query_one("#explanation-box").render())
            assert "not reachable" in box_text
            assert "optional" in box_text
            # Evidence review stays fully usable.
            assert app.analysis is not None
            assert app.explanation is None
            fact_texts = [
                str(child.render())
                for item in app.screen.query_one("#facts-list").children
                for child in item.children
            ]
            assert any("SiteNet" in text for text in fact_texts)

    _run(scenario())
