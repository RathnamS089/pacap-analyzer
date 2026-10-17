"""UI-independent analysis service for the TraceLens terminal UI.

The Textual app talks only to this layer: it never imports scapy or the
reader directly, and every capture-opening failure arrives as a friendly
:class:`AnalysisError` it can show to the user.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from tracelens.analyzer import analyze_capture
from tracelens.reader import CaptureReadError, load_capture


class AnalysisError(Exception):
    """A capture could not be opened or analyzed; message is user-facing."""


@dataclass
class AnalysisResult:
    """Flattened analysis outcome the UI can render without dict digging."""

    capture_path: str
    capture_format: str
    packet_count: int
    analysis: Dict[str, Any]  # Full result dict from tracelens.analyzer.


class TraceLensService:
    """Open a capture file and extract survey evidence, read-only."""

    def analyze(self, capture_path: str) -> AnalysisResult:
        """Analyze the capture at ``capture_path``.

        Raises :class:`AnalysisError` (never a scapy/reader exception) when
        the file is missing, empty, not a capture, or truncated.
        """
        try:
            loaded = load_capture(capture_path)
            analysis = analyze_capture(loaded)
        except CaptureReadError as err:
            raise AnalysisError(str(err)) from err
        info = analysis["capture_info"]
        return AnalysisResult(
            capture_path=info["path"],
            capture_format=info["format"],
            packet_count=info["packet_count"],
            analysis=analysis,
        )
