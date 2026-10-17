"""Tests for the TUI service layer.

Branch goal (codex/tui-analysis-shell): a thin, UI-independent service the
Textual app calls to open and analyze a capture, mapping reader errors to a
friendly AnalysisError so the UI never has to know about scapy internals.
"""

from pathlib import Path

import pytest
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.utils import wrpcap

from tracelens.tui.service import AnalysisError, AnalysisResult, TraceLensService

AP_MAC = "aa:bb:cc:dd:ee:02"


def _beacon_frame():
    return (
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


def test_service_analyzes_valid_capture(tmp_path: Path) -> None:
    capture = tmp_path / "site.pcap"
    wrpcap(str(capture), [_beacon_frame()])

    result = TraceLensService().analyze(str(capture))

    assert isinstance(result, AnalysisResult)
    assert result.capture_path == str(capture)
    assert result.capture_format == "pcap"
    assert result.packet_count == 1
    assert result.analysis["capture_info"]["path"] == str(capture)
    fact_kinds = [fact["kind"] for fact in result.analysis["facts"]]
    assert "beaconed_ssids" in fact_kinds


def test_service_maps_reader_errors_to_friendly_analysis_error(
    tmp_path: Path,
) -> None:
    service = TraceLensService()

    with pytest.raises(AnalysisError) as missing:
        service.analyze(str(tmp_path / "nope.pcap"))
    assert "not found" in str(missing.value)

    photo = tmp_path / "photo.bin"
    photo.write_bytes(b"\x89PNG not a capture at all" * 8)
    with pytest.raises(AnalysisError) as bad:
        service.analyze(str(photo))
    assert "not a capture" in str(bad.value)
