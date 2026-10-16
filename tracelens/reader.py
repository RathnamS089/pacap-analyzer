"""Safe, read-only opening of user-supplied capture files.

The reader never writes to the capture, never opens a network socket, and
keeps no packet payload data in memory: it validates the file, counts the
packets, and hands the analyzer a fresh streaming iterator on demand.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Iterator

from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.utils import PcapReader, PcapNgReader

# Capture-file magic numbers as they appear in the first 4 bytes on disk.
_PCAP_MAGICS = frozenset(
    [
        b"\xd4\xc3\xb2\xa1",  # pcap, little-endian
        b"\xa1\xb2\xc3\xd4",  # pcap, big-endian
        b"\x4d\x3c\xb2\xa1",  # pcap with nanosecond timestamps, little-endian
        b"\xa1\xb2\x3c\x4d",  # pcap with nanosecond timestamps, big-endian
    ]
)
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # pcapng Section Header Block

# Classic pcap layout: 24-byte global header, then per packet a 16-byte
# record header (timestamp_sec, timestamp_usec, caplen, wirelen) followed by
# caplen bytes of frame data.
_PCAP_GLOBAL_HEADER_LEN = 24
_PCAP_RECORD_HEADER_LEN = 16
# No real 802.11/Ethernet frame approaches this size; a larger "caplen"
# means the file is malformed rather than merely truncated.
_MAX_SANE_CAPLEN = 4 * 1024 * 1024


class CaptureReadError(ValueError):
    """Raised when a file cannot be opened as a PCAP/PCAPNG capture."""


@dataclass
class LoadedCapture:
    """A capture file validated for streaming analysis.

    Only lightweight metadata is kept; packet data is streamed from disk on
    each :meth:`iter_packets` call so large captures stay memory-friendly.
    """

    path: str
    format: str  # "pcap" or "pcapng"
    packet_count: int

    def iter_packets(self) -> Iterator[Packet]:
        """Stream packets from the capture file (one pass per call)."""
        stream = _open_reader(self.path, self.format)
        try:
            for packet in stream:
                yield packet
        finally:
            stream.close()


def _sniff_format(header: bytes) -> str | None:
    if header[:4] in _PCAP_MAGICS:
        return "pcap"
    if header[:4] == _PCAPNG_MAGIC:
        return "pcapng"
    return None


def _open_reader(path: str, fmt: str):
    reader_cls = PcapReader if fmt == "pcap" else PcapNgReader
    try:
        return reader_cls(path)
    except Scapy_Exception as err:
        raise CaptureReadError(
            f"Could not open capture '{os.path.basename(path)}': {err}"
        ) from err


def _validate_classic_pcap(path: str) -> None:
    """Walk classic pcap record headers to catch truncation or bad caplens.

    Scapy's reader silently skips packet data that the file does not contain,
    so a truncated capture would otherwise pass unnoticed.
    """
    with open(path, "rb") as handle:
        header = handle.read(_PCAP_GLOBAL_HEADER_LEN)
        if len(header) < _PCAP_GLOBAL_HEADER_LEN:
            raise CaptureReadError(
                f"Capture is truncated: missing pcap global header "
                f"({len(header)} of 24 bytes present)."
            )
        magic = header[:4]
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" or magic == b"\x4d\x3c\xb2\xa1" else ">"
        offset = _PCAP_GLOBAL_HEADER_LEN
        packet_count = 0
        while True:
            record = handle.read(_PCAP_RECORD_HEADER_LEN)
            if len(record) == 0:
                return  # Clean end of file.
            if len(record) < _PCAP_RECORD_HEADER_LEN:
                raise CaptureReadError(
                    f"Capture appears truncated: packet {packet_count + 1} "
                    f"record header is cut off "
                    f"({len(record)} of 16 bytes present)."
                )
            (caplen,) = struct.unpack(endian + "I", record[8:12])
            if caplen > _MAX_SANE_CAPLEN:
                raise CaptureReadError(
                    f"Capture is malformed: packet {packet_count + 1} "
                    f"declares an impossible size ({caplen} bytes)."
                )
            if handle.seek(caplen, 1) != offset + _PCAP_RECORD_HEADER_LEN + caplen:
                raise CaptureReadError(
                    f"Capture appears truncated: packet {packet_count + 1} "
                    f"data is cut off (need {caplen} bytes)."
                )
            offset += _PCAP_RECORD_HEADER_LEN + caplen
            packet_count += 1


def load_capture(path: str | os.PathLike) -> LoadedCapture:
    """Open a user-supplied capture file locally, read-only.

    Validates that the file exists, is a real PCAP/PCAPNG capture, and is not
    truncated, then returns metadata plus a packet stream. Packet contents
    are never held in memory beyond one packet at a time.
    """
    file_path = os.fspath(path)
    if not os.path.exists(file_path):
        raise CaptureReadError(f"Capture file not found: {file_path}")
    if os.path.isdir(file_path):
        raise CaptureReadError(
            f"Expected a capture file but found a directory: {file_path}"
        )
    try:
        if os.path.getsize(file_path) == 0:
            raise CaptureReadError(f"Capture file is empty: {file_path}")
        with open(file_path, "rb") as handle:
            header = handle.read(4)
    except OSError as err:
        raise CaptureReadError(f"Could not read capture file: {err}") from err

    fmt = _sniff_format(header)
    if fmt is None:
        raise CaptureReadError(
            f"'{os.path.basename(file_path)}' is not a capture file "
            "(expected PCAP or PCAPNG). Choose a .pcap or .pcapng file "
            "saved by a packet capture tool."
        )

    # Full validation pass: a broken/truncated capture should fail here,
    # with a friendly message, before any analysis starts.
    if fmt == "pcap":
        _validate_classic_pcap(file_path)
    stream = _open_reader(file_path, fmt)
    packet_count = 0
    try:
        for _ in stream:
            packet_count += 1
    except (Scapy_Exception, EOFError, struct.error, OSError) as err:
        raise CaptureReadError(
            f"Capture appears truncated or corrupt after {packet_count} "
            f"packets: {err}"
        ) from err
    finally:
        stream.close()

    return LoadedCapture(path=file_path, format=fmt, packet_count=packet_count)
