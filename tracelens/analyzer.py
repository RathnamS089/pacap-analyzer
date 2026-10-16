"""Deterministic evidence extraction from an opened capture.

Every fact here is computed directly from packets in the file. When the
capture lacks the information needed for a survey topic (signal strength,
auth/association, disconnects, roaming), that is reported explicitly as a
limitation instead of being guessed. This module never proposes root causes
and never interprets absent packets as proof that an event did not happen.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional

from scapy.layers.bluetooth import HCI_Hdr, HCI_PHDR_Hdr
from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11Beacon,
    Dot11Elt,
    Dot11ReassoReq,
    RadioTap,
)

# 802.11 frame type numbers (IEEE 802.11-2020 9.2.4.1.3).
_MGMT_TYPE = 0
_CTRL_TYPE = 1
_DATA_TYPE = 2

# 802.11 management subtypes relevant to the survey evidence.
_SUBTYPE_ASSOC_REQ = 0
_SUBTYPE_REASSOC_REQ = 2
_SUBTYPE_DISASSOC = 10
_SUBTYPE_DEAUTH = 12
_BEACON_SUBTYPE = 8

# Frame Control field bit for "retry" (802.11-2020 9.2.4.1.2).
_FC_RETRY_BIT = 0x08


def _freq_to_channel(freq_mhz: int) -> Optional[int]:
    """Map a RadioTap channel frequency (MHz) to an 802.11 channel number."""
    if freq_mhz == 2484:  # 2.4 GHz channel 14 (Japan)
        return 14
    if 2412 <= freq_mhz <= 2472:  # 2.4 GHz channels 1-13
        return (freq_mhz - 2407) // 5
    if 4910 <= freq_mhz <= 4980:  # 4.9 GHz public safety
        return (freq_mhz - 4000) // 5
    if 5160 <= freq_mhz <= 5885:  # 5 GHz channels
        return (freq_mhz - 5000) // 5
    if 5955 <= freq_mhz <= 7115:  # 6 GHz channels (Wi-Fi 6E/7)
        return (freq_mhz - 5950) // 5
    return None


def _channel_sort_key(channel: str) -> tuple:
    try:
        return (0, int(channel), "")
    except ValueError:
        return (1, 0, channel)


def _iter_elements(dot11: Packet):
    """Yield each 802.11 information element of a management frame."""
    element = dot11.getlayer(Dot11Elt)
    while element is not None:
        yield element
        element = element.payload.getlayer(Dot11Elt)


def analyze_capture(loaded) -> Dict[str, Any]:
    """Extract survey evidence from a :class:`~tracelens.reader.LoadedCapture`.

    Returns a dict with ``capture_info``, ``facts`` (measured, packet-backed),
    ``limitations`` (topics the capture cannot support) and ``notes``.
    """
    summary = {
        "packets_analyzed": 0,
        "frames_with_wlan": 0,
        "data_frames": 0,
        "management_frames": 0,
        "control_frames": 0,
    }
    channel_counts: Counter = Counter()
    ssid_counts: Counter = Counter()
    retry_frames = 0
    data_frames_checked = 0
    rssi_values: List[int] = []
    assoc_requests: Counter = Counter()
    reassoc_requests: Counter = Counter()
    disconnect_events = 0
    bluetooth_packets = 0

    stream = loaded.iter_packets()
    try:
        for packet in stream:
            summary["packets_analyzed"] += 1

            if packet.haslayer(HCI_PHDR_Hdr) or packet.haslayer(HCI_Hdr):
                bluetooth_packets += 1
                continue

            dot11 = packet.getlayer(Dot11)
            if dot11 is None:
                continue  # Not a Wi-Fi frame (e.g. plain Ethernet).
            summary["frames_with_wlan"] += 1

            if dot11.type == _MGMT_TYPE:
                summary["management_frames"] += 1
            elif dot11.type == _CTRL_TYPE:
                summary["control_frames"] += 1
            elif dot11.type == _DATA_TYPE:
                summary["data_frames"] += 1

            radiotap = packet.getlayer(RadioTap)
            if radiotap is not None:
                # Channel frequency is per-frame RadioTap metadata recorded
                # by the capturing adapter, not information inside the frame.
                freq = int(getattr(radiotap, "ChannelFrequency", 0) or 0)
                if freq:
                    channel = _freq_to_channel(freq)
                    if channel is not None:
                        channel_counts[str(channel)] += 1
                # RSSI is only present when the adapter recorded it.
                present = getattr(radiotap, "present", None)
                if present is not None and getattr(present, "dBm_AntSignal", 0):
                    rssi_values.append(int(radiotap.dBm_AntSignal))

            if dot11.type == _DATA_TYPE:
                data_frames_checked += 1
                if dot11.FCfield & _FC_RETRY_BIT:
                    retry_frames += 1

            if dot11.type == _MGMT_TYPE:
                if dot11.subtype == _BEACON_SUBTYPE and packet.haslayer(
                    Dot11Beacon
                ):
                    for element in _iter_elements(dot11):
                        if element.ID == 0:  # SSID parameter set
                            ssid = bytes(element.info).decode("utf-8", "replace")
                            if ssid:
                                ssid_counts[ssid] += 1
                elif dot11.subtype == _SUBTYPE_ASSOC_REQ and packet.haslayer(
                    Dot11AssoReq
                ):
                    if dot11.addr2:
                        assoc_requests[dot11.addr2.lower()] += 1
                elif dot11.subtype == _SUBTYPE_REASSOC_REQ and packet.haslayer(
                    Dot11ReassoReq
                ):
                    if dot11.addr2:
                        reassoc_requests[dot11.addr2.lower()] += 1
                elif dot11.subtype in (_SUBTYPE_DEAUTH, _SUBTYPE_DISASSOC):
                    disconnect_events += 1
    finally:
        stream.close()

    facts: List[Dict[str, Any]] = [{"kind": "capture_summary", "detail": summary}]

    if channel_counts:
        ordered = sorted(channel_counts, key=_channel_sort_key)
        facts.append(
            {
                "kind": "channel_usage",
                "detail": {
                    "channels": ordered,
                    "channel_counts": {
                        channel: channel_counts[channel] for channel in ordered
                    },
                },
            }
        )

    if ssid_counts:
        ordered_ssids = sorted(ssid_counts)
        facts.append(
            {
                "kind": "beaconed_ssids",
                "detail": {
                    "ssids": ordered_ssids,
                    "ssid_counts": {
                        ssid: ssid_counts[ssid] for ssid in ordered_ssids
                    },
                },
            }
        )

    if data_frames_checked:
        facts.append(
            {
                "kind": "retry_rate",
                "detail": {
                    "data_frames_with_retry_flag": retry_frames,
                    "data_frames_checked": data_frames_checked,
                },
            }
        )

    if rssi_values:
        facts.append(
            {
                "kind": "signal_strength",
                "detail": {
                    "frames_with_rssi": len(rssi_values),
                    "rssi_min_dbm": min(rssi_values),
                    "rssi_max_dbm": max(rssi_values),
                    "rssi_avg_dbm": round(sum(rssi_values) / len(rssi_values), 1),
                },
            }
        )

    if assoc_requests or reassoc_requests:
        per_client: Dict[str, Dict[str, int]] = {}
        for client in sorted(set(assoc_requests) | set(reassoc_requests)):
            entry: Dict[str, int] = {}
            if assoc_requests.get(client):
                entry["assoc_requests"] = assoc_requests[client]
            if reassoc_requests.get(client):
                entry["reassoc_requests"] = reassoc_requests[client]
            per_client[client] = entry
        facts.append(
            {
                "kind": "client_auth_frames",
                "detail": {"clients": sorted(per_client), "per_client": per_client},
            }
        )

    limitations: List[str] = []
    if (
        summary["frames_with_wlan"] == 0
        and summary["packets_analyzed"] > bluetooth_packets
    ):
        limitations.append(
            "No Wi-Fi (802.11) frames found: this looks like a wired capture."
        )
    if not rssi_values:
        limitations.append("RSSI / signal strength: not present in this capture.")
    if not (assoc_requests or reassoc_requests):
        limitations.append(
            "Auth/association frames: not present in this capture."
        )
    if disconnect_events == 0:
        limitations.append(
            "Disconnect (deauth/disassoc) frames: not present in this capture."
        )
    if not reassoc_requests:
        limitations.append(
            "Roaming: cannot be assessed because no client reassociation "
            "frames are present in this capture."
        )

    notes: List[str] = []
    if bluetooth_packets:
        notes.append(
            "Bluetooth packets present (not Wi-Fi); they are excluded from "
            "Wi-Fi evidence."
        )

    return {
        "capture_info": {
            "path": loaded.path,
            "format": loaded.format,
            "packet_count": loaded.packet_count,
        },
        "facts": facts,
        "limitations": limitations,
        "notes": notes,
    }
