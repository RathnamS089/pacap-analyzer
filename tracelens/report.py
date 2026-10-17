"""Stateless report builder for TraceLens.

Turns the analyzer's JSON evidence into an editable Markdown report:
a title, YAML front matter (capture path, date, model version), a body
with measured facts and explicit limitations, and a site-notes section
the installer can edit before sending the report to the customer.

All fields are plain Python strings/dicts so the TUI can compose them
into Textual widgets without importing Textual itself. ``write_report_file``
composes the final ``.md`` document; everything stays on this machine.

Anonymization is deliberately out of scope here — the privacy branch
(codex/privacy-anonymization) will add redaction of MACs/SSIDs before
export, keeping the mapping in memory only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Report version written into the front matter; matches the package version.
MODEL_VERSION = "tracelens/0.1.0"

_REPORT_TITLE = "Wi-Fi Survey Report"


def _iso_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Body rendering helpers.
# ---------------------------------------------------------------------------

def _render_fact(fact: Dict[str, Any]) -> List[str]:
    """Render one analyzer fact as Markdown lines for the report body."""
    kind = fact.get("kind", "")
    detail = fact.get("detail", {})
    lines: List[str] = []

    if kind == "capture_summary":
        lines.append(
            "Analyzed {packets_analyzed} packet(s), of which {frames_with_wlan} "
            "were Wi-Fi frames (management: {management_frames}, "
            "control: {control_frames}, data: {data_frames}).".format(**detail)
        )

    elif kind == "channel_usage":
        counts = detail.get("channel_counts", {})
        if counts:
            parts = [
                "channel {c} ({n} frames)".format(c=c, n=counts[c])
                for c in detail.get("channels", sorted(counts))
            ]
            lines.append("Observed on " + ", ".join(parts) + ".")

    elif kind == "beaconed_ssids":
        ssids = detail.get("ssids", [])
        counts = detail.get("ssid_counts", {})
        bssids = detail.get("ssid_bssids", {})
        if ssids:
            parts = []
            for ssid in ssids:
                entry = "{s} ({n} beacons)".format(
                    s=ssid, n=counts.get(ssid, "?")
                )
                observed = bssids.get(ssid, [])
                if observed:
                    entry += " — BSSID {m}".format(m=", ".join(observed))
                parts.append(entry)
            lines.append("Beaconed SSIDs: " + ", ".join(parts) + ".")

    elif kind == "retry_rate":
        checked = detail.get("data_frames_checked", 0)
        retried = detail.get("data_frames_with_retry_flag", 0)
        pct = round(100 * retried / checked, 1) if checked else 0
        lines.append(
            "Data-frame retry rate: {r} of {c} data frames had the retry "
            "bit set ({p}%).".format(r=retried, c=checked, p=pct)
        )

    elif kind == "signal_strength":
        lines.append(
            "Signal strength (RSSI): {mn} to {mx} dBm, average {avg} dBm "
            "({n} frames with RSSI recorded).".format(
                mn=detail.get("rssi_min_dbm"),
                mx=detail.get("rssi_max_dbm"),
                avg=detail.get("rssi_avg_dbm"),
                n=detail.get("frames_with_rssi"),
            )
        )

    elif kind == "client_auth_frames":
        per_client = detail.get("per_client", {})
        for client in detail.get("clients", sorted(per_client)):
            counts = per_client.get(client, {})
            parts = ["{k}: {v}".format(k=k, v=v) for k, v in counts.items()]
            lines.append(
                "Client {client} association activity — {parts}.".format(
                    client=client, parts=", ".join(parts)
                )
            )

    return lines


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------

def build_report(
    analysis: Dict[str, Any],
    site_notes: str = "",
    model_version: str = MODEL_VERSION,
) -> Dict[str, Any]:
    """Build an editable report dict from analyzer output.

    Parameters
    ----------
    analysis:
        The dict returned by :func:`tracelens.analyzer.analyze_capture`.
    site_notes:
        Installer's editable observations about the site, written into the
        ``## Site Notes`` section. Kept strictly separate from measured
        evidence; it is user content, not packet-backed fact.
    model_version:
        Value for the ``model_version`` front-matter field.

    Returns
    -------
    Dict with keys:

    - ``title``: the report title.
    - ``front_matter``: plain dict with ``capture_path``, ``date``, and
      ``model_version`` (serialized to YAML only by ``write_report_file``).
    - ``markdown``: the full report body, editable before saving.
    - ``preview``: the same body for the read-only TUI preview screen.
    """
    capture_path = analysis["capture_info"]["path"]
    facts = analysis.get("facts", [])
    limitations = analysis.get("limitations", [])
    notes = analysis.get("notes", [])

    body_parts: List[str] = ["## Measured Evidence", ""]

    for fact in facts:
        body_parts.extend(_render_fact(fact))

    body_parts.append("")
    body_parts.append("## Limitations")
    body_parts.append("")
    if limitations:
        for limitation in limitations:
            body_parts.append("- " + limitation)
    else:
        body_parts.append(
            "- None recorded: every surveyed topic found supporting packets."
        )

    if notes:
        body_parts.append("")
        body_parts.append("## Notes")
        body_parts.append("")
        for note in notes:
            body_parts.append("- " + note)

    body_parts.append("")
    body_parts.append("## Site Notes")
    body_parts.append("")
    body_parts.append(site_notes.strip() if site_notes.strip() else "None recorded.")

    markdown_body = "\n".join(body_parts) + "\n"

    return {
        "title": _REPORT_TITLE,
        "front_matter": {
            "capture_path": str(capture_path),
            "date": _iso_now(),
            "model_version": model_version,
        },
        "markdown": markdown_body,
        "preview": markdown_body,
    }


def build_preview(analysis: Dict[str, Any]) -> str:
    """Build the read-only preview: the report body without front matter."""
    return build_report(analysis)["markdown"]


def write_report_file(report: Dict[str, Any], out_path: Path) -> Path:
    """Compose front matter, title, and body into a Markdown file.

    The front matter is rendered as a YAML ``---`` block so the saved file
    stays plain Markdown, editable in any text editor.
    """
    out_path = Path(out_path)
    if out_path.suffix.lower() != ".md":
        raise ValueError(
            "Report files must be written as Markdown (.md), got: %s"
            % (out_path.name or out_path)
        )

    front = report["front_matter"]
    yaml_block = "\n".join(
        [
            "---",
            'title: "{title}"'.format(title=report["title"]),
            'capture_path: "{path}"'.format(path=front["capture_path"]),
            'date: "{date}"'.format(date=front["date"]),
            'model_version: "{model}"'.format(model=front["model_version"]),
            "---",
            "",
            "# {title}".format(title=report["title"]),
            "",
        ]
    )
    document = yaml_block + report["markdown"]
    if not document.endswith("\n"):
        document += "\n"

    out_path.write_text(document, encoding="utf-8")
    return out_path
