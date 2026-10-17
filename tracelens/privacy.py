"""Privacy/anonymization pass for TraceLens reports.

Wraps the report builder and redacts identifiers — MAC addresses, IPv4
addresses, SSIDs, and the capture path — in both the body and the front
matter before a report leaves the operator's organization.

Design rules (enforced by tests):

- The identity map (original -> placeholder) is returned to the caller and
  lives only in memory; this module never writes it anywhere.
- Mapping is consistent within one report: the same identifier always gets
  the same placeholder, and distinct identifiers never collide, so a reader
  can still tell two different clients apart.
- SSIDs become readable pseudonyms ("Site 1", "Site 2", ...) following the
  analyzer's deterministic SSID ordering.
- The analyzer's dict is treated as read-only: the pass never mutates
  measured evidence.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tracelens.report import MODEL_VERSION, build_report

# MAC address: aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff
_MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b")

# IPv4 address
_IPV4_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b"
)

# Broadcast is not an identifier; leave it readable.
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

_PLACEHOLDER_PREFIX = "MAC-"


def _collect_macs(analysis: Dict[str, Any]) -> List[str]:
    """Every MAC the analyzer surfaced, in a deterministic order."""
    macs: List[str] = []

    def _add(value: str) -> None:
        normalized = value.lower()
        if normalized != _BROADCAST_MAC and normalized not in macs:
            macs.append(normalized)

    for fact in analysis.get("facts", []):
        kind = fact.get("kind", "")
        detail = fact.get("detail", {})
        if kind == "beaconed_ssids":
            for bssids in detail.get("ssid_bssids", {}).values():
                for bssid in bssids:
                    _add(bssid)
        elif kind == "client_auth_frames":
            for client in detail.get("clients", []):
                _add(client)

    # Any further MACs that ended up in rendered body text (defensive; the
    # regex pass below would catch strays anyway).
    return macs


def _collect_ssids(analysis: Dict[str, Any]) -> List[str]:
    """SSIDs in the analyzer's deterministic (sorted) order."""
    for fact in analysis.get("facts", []):
        if fact.get("kind") == "beaconed_ssids":
            return list(fact.get("detail", {}).get("ssids", []))
    return []


def build_anonymized_report(
    analysis: Dict[str, Any],
    site_notes: str = "",
    model_version: str = MODEL_VERSION,
) -> Tuple[Dict[str, Any], Dict[str, Dict[str, str]]]:
    """Build a customer-safe report plus the in-memory identity map.

    Returns
    -------
    (report, mapping) where ``report`` is the same structure
    :func:`tracelens.report.build_report` returns (fully redacted), and
    ``mapping`` is ``{"mac": {original: placeholder}, "ssid": {original:
    placeholder}}`` — kept in memory only; this module never persists it.
    """
    mac_map: Dict[str, str] = {}
    for index, mac in enumerate(_collect_macs(analysis), start=1):
        mac_map[mac] = "{prefix}{index:02d}".format(
            prefix=_PLACEHOLDER_PREFIX, index=index
        )

    ssid_map: Dict[str, str] = {
        ssid: "Site {n}".format(n=index)
        for index, ssid in enumerate(_collect_ssids(analysis), start=1)
    }

    # Build the plain report first, then redact a deep copy so the
    # analyzer's dict and the builder's output conventions stay untouched.
    report = build_report(
        analysis, site_notes=site_notes, model_version=model_version
    )

    front = dict(report["front_matter"])
    original_path = str(front.get("capture_path", ""))
    safe_name = Path(original_path).name or "capture"
    front["capture_path"] = "./" + safe_name

    body = report["markdown"]

    def _redact_line(line: str) -> str:
        # SSIDs first (they may contain MAC-like or numeric substrings),
        # longest first so one SSID that is a prefix of another still maps
        # to its own pseudonym.
        for ssid in sorted(ssid_map, key=len, reverse=True):
            line = line.replace(ssid, ssid_map[ssid])
        line = _IPV4_RE.sub("<IP-REDACTED>", line)
        line = _MAC_RE.sub(
            lambda match: mac_map.get(
                match.group(0).lower(), "<MAC-REDACTED>"
            ),
            line,
        )
        return line

    redacted_body = "\n".join(
        _redact_line(line) for line in body.splitlines()
    )
    if body.endswith("\n"):
        redacted_body += "\n"

    anonymized = {
        "title": report["title"],
        "front_matter": front,
        "markdown": redacted_body,
        "preview": redacted_body,
    }
    return anonymized, {"mac": mac_map, "ssid": ssid_map}
