"""Tests for the report builder.

Branch goal (codex/report-builder): a stateless generator that turns the
analyzer's JSON evidence into an editable Markdown report — a title, YAML
front matter (capture path, date, model version), a body with measured
facts and explicit limitations, and an editable site-notes section — plus
a read-only preview for the TUI and a save-to-file helper.

No UI dependency: the builder is pure Python returning plain dicts/strings
so the TUI can compose them into Textual widgets. Anonymization is
deliberately NOT part of this branch; the privacy branch
(codex/privacy-anonymization) wraps or extends this builder.
"""

from pathlib import Path

import pytest
from scapy.layers.dot11 import Dot11, Dot11AssoReq, Dot11Beacon, Dot11Elt, RadioTap
from scapy.utils import wrpcap

from tracelens.analyzer import analyze_capture
from tracelens.reader import load_capture
from tracelens.report import build_preview, build_report, write_report_file

AP_MAC = "aa:bb:cc:dd:ee:02"
CLIENT_MAC = "aa:bb:cc:dd:ee:04"
SITE_SSID = "SiteNet"

_RADIOTAP = dict(
    present="TSFT+Flags+Rate+Channel+dBm_AntSignal+Antenna",
    ChannelFrequency=2412,  # 2.4 GHz, channel 1
    dBm_AntSignal=-52,
)


def _wlan_frames():
    """Beacon + retried data frame + client association request."""
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


def _sample_analysis(tmp_path: Path):
    capture = tmp_path / "site.pcap"
    wrpcap(str(capture), _wlan_frames())
    return analyze_capture(load_capture(capture))


def test_build_report_has_front_matter_and_evidence(tmp_path: Path) -> None:
    analysis = _sample_analysis(tmp_path)
    report = build_report(analysis)

    assert report["title"] == "Wi-Fi Survey Report"
    front = report["front_matter"]
    assert front["capture_path"].endswith("site.pcap")
    assert front["date"]  # ISO-8601 timestamp
    assert front["model_version"]  # e.g. tracelens/0.1.0

    body = report["markdown"]
    # Key evidence items are all present in the markdown body.
    assert "SiteNet" in body
    assert "channel 1" in body
    assert "-52" in body  # RSSI
    assert "retry" in body.lower()
    assert "## Limitations" in body


def test_report_includes_bssid_evidence(tmp_path: Path) -> None:
    """The AP radio (BSSID) seen beaconing each SSID is reported."""
    analysis = _sample_analysis(tmp_path)
    report = build_report(analysis)

    assert AP_MAC in report["markdown"]


def test_build_preview_returns_body_without_front_matter(tmp_path: Path) -> None:
    analysis = _sample_analysis(tmp_path)
    report = build_report(analysis)
    preview = build_preview(analysis)

    assert preview == report["markdown"]
    assert "SiteNet" in preview
    assert "Limitations" in preview
    # The preview is the body only: no YAML front matter and no H1 title
    # line (the H1 is added by write_report_file, not by the builder).
    assert not preview.startswith("# ")


def test_site_notes_section_is_editable(tmp_path: Path) -> None:
    analysis = _sample_analysis(tmp_path)

    with_notes = build_report(
        analysis, site_notes="Lobby AP mounted too low; spare cable needed."
    )
    assert "## Site Notes" in with_notes["markdown"]
    assert "Lobby AP mounted too low" in with_notes["markdown"]

    without_notes = build_report(analysis)
    assert "## Site Notes" in without_notes["markdown"]
    assert "None recorded" in without_notes["markdown"]


def test_write_report_file_composes_front_matter_and_body(tmp_path: Path) -> None:
    analysis = _sample_analysis(tmp_path)
    report = build_report(
        analysis, site_notes="Second floor coverage looks thin."
    )

    out_path = tmp_path / "survey-report.md"
    written = write_report_file(report, out_path)

    assert written == out_path
    text = out_path.read_text(encoding="utf-8")
    # YAML front matter at the top, then the editable report body.
    assert text.startswith("---\n")
    assert 'capture_path: "%s"' % (tmp_path / "site.pcap") in text
    assert "date:" in text
    assert "model_version:" in text
    assert "---\n" in text[4:]  # closing delimiter
    assert "# Wi-Fi Survey Report" in text
    assert "## Measured Evidence" in text
    assert "## Site Notes" in text
    assert "Second floor coverage looks thin." in text
    assert AP_MAC in text
    assert text.endswith("\n")


def test_write_report_file_rejects_non_markdown_path(tmp_path: Path) -> None:
    analysis = _sample_analysis(tmp_path)
    report = build_report(analysis)

    with pytest.raises(ValueError) as excinfo:
        write_report_file(report, tmp_path / "report.txt")
    assert ".md" in str(excinfo.value)
    assert not (tmp_path / "report.txt").exists()
