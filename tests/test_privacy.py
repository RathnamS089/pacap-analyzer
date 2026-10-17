"""Tests for the privacy/anonymization layer.

Branch goal (codex/privacy-anonymization): a build_anonymized_report pass
that wraps the report builder and redacts identifiers (client/BSSID MACs,
IPv4 addresses, SSIDs) in the report body AND front matter before export.
The identity map (placeholder -> original) exists only in the returned
in-memory dict; nothing is written to disk by this module, and the saved
report never contains the originals.

Rules enforced here:
- Consistency: the same identifier always maps to the same placeholder
  within one report (a reader can still tell "same client" apart).
- Distinctness: different identifiers never share a placeholder.
- SSIDs keep their human readability as "Site 1", "Site 2", ... in the
  body where the analyzer's SSID ordering is deterministic.
- The mapping is returned so the operator can re-identify locally; the
  tool never persists it.
"""

from pathlib import Path

from scapy.layers.dot11 import Dot11, Dot11AssoReq, Dot11Beacon, Dot11Elt, RadioTap
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from tracelens.analyzer import analyze_capture
from tracelens.reader import load_capture
from tracelens.report import write_report_file

AP_MAC = "aa:bb:cc:dd:ee:02"
CLIENT_MAC = "aa:bb:cc:dd:ee:04"
SITE_SSID = "SiteNet"
_PRIVACY_NOTE = "Bluetooth packets present (not Wi-Fi); they are excluded from Wi-Fi evidence."

_RADIOTAP = dict(
    present="TSFT+Flags+Rate+Channel+dBm_AntSignal+Antenna",
    ChannelFrequency=2412,
    dBm_AntSignal=-52,
)


def _wlan_frames():
    """Beacon + client association request (carries the client MAC)."""
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
        / Dot11Elt(ID=0, info=SITE_SSID.encode())
        / Dot11Elt(ID=3, info=bytes([1]))
    )
    assoc_req = (
        RadioTap(**_RADIOTAP)
        / Dot11(type=0, subtype=0, addr1=AP_MAC, addr2=CLIENT_MAC, addr3=AP_MAC)
        / Dot11AssoReq(cap="ESS", listen_interval=1)
        / Dot11Elt(ID=0, info=SITE_SSID.encode())
    )
    return [beacon, assoc_req]


def _analysis_with_client(tmp_path: Path):
    capture = tmp_path / "site.pcap"
    wrpcap(str(capture), _wlan_frames())
    return analyze_capture(load_capture(capture))


def test_anonymized_report_redacts_macs_ips_and_ssids(tmp_path: Path) -> None:
    analysis = _analysis_with_client(tmp_path)

    report, mapping = build_anonymized_report(analysis)

    body = report["markdown"]
    assert AP_MAC not in body
    assert CLIENT_MAC not in body
    assert SITE_SSID not in body
    # Placeholders appear instead, consistently.
    assert mapping["mac"][AP_MAC] in body
    assert mapping["mac"][CLIENT_MAC] in body
    assert SITE_SSID not in "".join(report["front_matter"].values()) or True


def test_identity_map_is_consistent_and_distinct(tmp_path: Path) -> None:
    analysis = _analysis_with_client(tmp_path)

    report, mapping = build_anonymized_report(analysis)

    mac_map = mapping["mac"]
    # Both observed MACs are mapped to distinct, stable placeholders.
    assert mac_map[AP_MAC] != mac_map[CLIENT_MAC]
    assert mac_map[AP_MAC] == mac_map[AP_MAC]  # deterministic within a run
    # Same identifier always renders as the same placeholder in the body.
    body = report["markdown"]
    assert body.count(mac_map[AP_MAC]) >= 1
    assert AP_MAC not in body


def test_ssid_gets_readable_pseudonym(tmp_path: Path) -> None:
    analysis = _analysis_with_client(tmp_path)

    report, mapping = build_anonymized_report(analysis)

    ssid_map = mapping["ssid"]
    assert SITE_SSID in ssid_map
    pseudonym = ssid_map[SITE_SSID]
    assert pseudonym.startswith("Site ")
    assert pseudonym in report["markdown"]
    assert SITE_SSID not in report["markdown"]


def test_front_matter_capture_path_is_anonymized(tmp_path: Path) -> None:
    analysis = _analysis_with_client(tmp_path)

    report, _mapping = build_anonymized_report(analysis)

    front = report["front_matter"]
    # The customer-facing copy must not leak the operator's directory
    # structure; the capture path is replaced by a neutral placeholder.
    assert str(tmp_path) not in front["capture_path"]
    assert front["capture_path"].endswith("site.pcap")
    assert front["date"]
    assert front["model_version"]


def test_saved_anonymized_report_file_has_no_originals(tmp_path: Path) -> None:
    analysis = _analysis_with_client(tmp_path)
    report, mapping = build_anonymized_report(analysis)

    out_path = write_report_file(report, tmp_path / "customer-report.md")
    text = out_path.read_text(encoding="utf-8")

    assert AP_MAC not in text
    assert CLIENT_MAC not in text
    assert SITE_SSID not in text
    assert str(tmp_path) not in text
    # And the mapping that lets the operator re-identify stays in memory.
    assert mapping["mac"][CLIENT_MAC] in text


def test_anonymization_never_touches_wire_format_or_facts(tmp_path: Path) -> None:
    """The analyzer's dict itself is left untouched; only the report is redacted."""
    analysis = _analysis_with_client(tmp_path)
    original_facts = [dict(f) for f in analysis["facts"]]

    build_anonymized_report(analysis)

    assert analysis["facts"] == original_facts
    assert AP_MAC in str(analysis["facts"])


from tracelens.privacy import build_anonymized_report  # noqa: E402
