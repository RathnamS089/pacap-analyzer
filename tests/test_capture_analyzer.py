"""Tests for the capture reader and evidence analyzer.

Branch goal (codex/capture-reader-analyzer): safely open a user-supplied
PCAP/PCAPNG capture and deterministically extract survey evidence, reporting
an explicit limitation whenever evidence for a survey topic is missing.
"""

import struct
from pathlib import Path

import pytest
from scapy.layers.bluetooth import HCI_Hdr, HCI_PHDR_Hdr
from scapy.layers.dns import DNS
from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap, wrpcapng

from tracelens.analyzer import analyze_capture
from tracelens.reader import load_capture

AP_MAC = "aa:bb:cc:dd:ee:02"
CLIENT_MAC = "aa:bb:cc:dd:ee:04"
SITE_SSID = "SiteNet"
OTHER_MAC = "aa:bb:cc:dd:ee:06"
OTHER_SSID = "OtherNet"

_RADIOTAP = dict(
    present="TSFT+Flags+Rate+Channel+dBm_AntSignal+Antenna",
    ChannelFrequency=2412,  # 2.4 GHz, channel 1
    dBm_AntSignal=-52,
)


def _wlan_frames():
    """One AP beacon, one retried data frame, one client association request."""
    beacon = (
        RadioTap(**_RADIOTAP)
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=AP_MAC,
            addr3=AP_MAC,
        )
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, info=SITE_SSID.encode())  # SSID
        / Dot11Elt(ID=3, info=bytes([1]))  # DS parameter set (channel)
    )
    retried_data = RadioTap(**_RADIOTAP) / Dot11(
        type=2,
        subtype=0,
        FCfield="to_DS+retry",
        addr1=AP_MAC,
        addr2=CLIENT_MAC,
        addr3=AP_MAC,
    )
    assoc_req = (
        RadioTap(**_RADIOTAP)
        / Dot11(type=0, subtype=0, addr1=AP_MAC, addr2=CLIENT_MAC, addr3=AP_MAC)
        / Dot11AssoReq(cap="ESS", listen_interval=1)
        / Dot11Elt(ID=0, info=SITE_SSID.encode())
    )
    return [beacon, retried_data, assoc_req]


def test_wlan_pcap_full_analysis(tmp_path: Path) -> None:
    capture = tmp_path / "site-a.pcap"
    wrpcap(str(capture), _wlan_frames())

    loaded = load_capture(capture)
    analysis = analyze_capture(loaded)

    assert analysis == {
        "capture_info": {
            "path": str(capture),
            "format": "pcap",
            "packet_count": 3,
        },
        "facts": [
            {
                "kind": "capture_summary",
                "detail": {
                    "packets_analyzed": 3,
                    "frames_with_wlan": 3,
                    "data_frames": 1,
                    "management_frames": 2,
                    "control_frames": 0,
                },
            },
            {
                "kind": "channel_usage",
                "detail": {"channels": ["1"], "channel_counts": {"1": 3}},
            },
            {
                "kind": "beaconed_ssids",
                "detail": {
                    "ssids": [SITE_SSID],
                    "ssid_counts": {SITE_SSID: 1},
                    "ssid_bssids": {SITE_SSID: [AP_MAC]},
                },
            },
            {
                "kind": "retry_rate",
                "detail": {
                    "data_frames_with_retry_flag": 1,
                    "data_frames_checked": 1,
                },
            },
            {
                "kind": "signal_strength",
                "detail": {
                    "frames_with_rssi": 3,
                    "rssi_min_dbm": -52,
                    "rssi_max_dbm": -52,
                    "rssi_avg_dbm": -52.0,
                },
            },
            {
                "kind": "client_auth_frames",
                "detail": {
                    "clients": [CLIENT_MAC],
                    "per_client": {CLIENT_MAC: {"assoc_requests": 1}},
                },
            },
        ],
        "limitations": [
            "Disconnect (deauth/disassoc) frames: not present in this capture.",
            "Roaming: cannot be assessed because no client reassociation "
            "frames are present in this capture.",
        ],
        "notes": [],
    }


def test_wlan_pcapng_full_analysis(tmp_path: Path) -> None:
    capture = tmp_path / "site-b.pcapng"
    wrpcapng(str(capture), _wlan_frames())

    loaded = load_capture(capture)
    analysis = analyze_capture(loaded)

    assert analysis["capture_info"] == {
        "path": str(capture),
        "format": "pcapng",
        "packet_count": 3,
    }
    assert analysis["facts"][0]["detail"]["packets_analyzed"] == 3
    assert analysis["facts"][1]["detail"]["channels"] == ["1"]


def test_bssid_mapped_per_ssid_across_channels(tmp_path: Path) -> None:
    """Same SSID beaconed by two BSSIDs; a second SSID on another channel."""
    capture = tmp_path / "multi-bssid.pcap"
    frames = [
        RadioTap(**_RADIOTAP)
        / Dot11(
            type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP_MAC, addr3=AP_MAC
        )
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, info=SITE_SSID.encode())
        / Dot11Elt(ID=3, info=bytes([1])),
        RadioTap(present="TSFT+Flags+Rate+Channel+dBm_AntSignal", ChannelFrequency=5180, dBm_AntSignal=-40)
        / Dot11(
            type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=AP_MAC, addr3=AP_MAC
        )
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, info=SITE_SSID.encode())
        / Dot11Elt(ID=3, info=bytes([36])),
        RadioTap(present="TSFT+Flags+Rate+Channel+dBm_AntSignal", ChannelFrequency=2437, dBm_AntSignal=-60)
        / Dot11(
            type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=OTHER_MAC, addr3=OTHER_MAC
        )
        / Dot11Beacon(cap="ESS")
        / Dot11Elt(ID=0, info=OTHER_SSID.encode())
        / Dot11Elt(ID=3, info=bytes([6])),
    ]
    wrpcap(str(capture), frames)

    analysis = analyze_capture(load_capture(capture))

    ssid_fact = next(
        fact for fact in analysis["facts"] if fact["kind"] == "beaconed_ssids"
    )
    assert ssid_fact["detail"]["ssid_bssids"] == {
        SITE_SSID: [AP_MAC],
        OTHER_SSID: [OTHER_MAC],
    }
    channel_fact = next(
        fact for fact in analysis["facts"] if fact["kind"] == "channel_usage"
    )
    assert channel_fact["detail"]["channels"] == ["1", "6", "36"]


def test_ethernet_capture_reports_no_wlan_evidence(tmp_path: Path) -> None:
    capture = tmp_path / "wired.pcap"
    packets = [
        Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / UDP() / DNS(),
        Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / TCP(),
    ]
    wrpcap(str(capture), packets)

    loaded = load_capture(capture)
    analysis = analyze_capture(loaded)

    assert analysis["capture_info"]["packet_count"] == 2
    assert analysis["facts"] == [
        {
            "kind": "capture_summary",
            "detail": {
                "packets_analyzed": 2,
                "frames_with_wlan": 0,
                "data_frames": 0,
                "management_frames": 0,
                "control_frames": 0,
            },
        }
    ]
    assert analysis["limitations"] == [
        "No Wi-Fi (802.11) frames found: this looks like a wired capture.",
        "RSSI / signal strength: not present in this capture.",
        "Auth/association frames: not present in this capture.",
        "Disconnect (deauth/disassoc) frames: not present in this capture.",
        "Roaming: cannot be assessed because no client reassociation "
        "frames are present in this capture.",
    ]
    assert analysis["notes"] == []


def test_bluetooth_capture_reports_bluetooth_note(tmp_path: Path) -> None:
    capture = tmp_path / "bt.pcap"
    wrpcap(str(capture), [HCI_PHDR_Hdr() / HCI_Hdr()])

    loaded = load_capture(capture)
    analysis = analyze_capture(loaded)

    assert analysis["facts"] == [
        {
            "kind": "capture_summary",
            "detail": {
                "packets_analyzed": 1,
                "frames_with_wlan": 0,
                "data_frames": 0,
                "management_frames": 0,
                "control_frames": 0,
            },
        }
    ]
    assert analysis["notes"] == [
        "Bluetooth packets present (not Wi-Fi); they are excluded from Wi-Fi evidence."
    ]
    assert analysis["limitations"] == [
        "RSSI / signal strength: not present in this capture.",
        "Auth/association frames: not present in this capture.",
        "Disconnect (deauth/disassoc) frames: not present in this capture.",
        "Roaming: cannot be assessed because no client reassociation "
        "frames are present in this capture.",
    ]


def test_reader_rejects_empty_file(tmp_path: Path) -> None:
    capture = tmp_path / "empty.pcap"
    capture.write_bytes(b"")

    with pytest.raises(ValueError) as excinfo:
        load_capture(capture)
    assert "empty" in str(excinfo.value)


def test_reader_rejects_non_capture_file_with_friendly_error(tmp_path: Path) -> None:
    capture = tmp_path / "photo.bin"
    capture.write_bytes(b"\x89PNG not a capture at all" * 10)

    with pytest.raises(ValueError) as excinfo:
        load_capture(capture)
    assert "not a capture" in str(excinfo.value)
    assert "unsupported" not in str(excinfo.value)


def test_reader_rejects_truncated_pcap_with_friendly_error(tmp_path: Path) -> None:
    """A valid global header followed by garbage must give a clear error."""
    capture = tmp_path / "truncated.pcap"
    capture.write_bytes(
        struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0, 1) + b"\x01\x02"
    )

    with pytest.raises(ValueError) as excinfo:
        load_capture(capture)
    assert "truncated" in str(excinfo.value)


def test_reader_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError) as excinfo:
        load_capture(tmp_path / "does-not-exist.pcap")
    assert "not found" in str(excinfo.value)
