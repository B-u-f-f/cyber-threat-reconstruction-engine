"""Read-only parser for the NTFS change journal ($UsnJrnl:$J).

Parses USN_RECORD_V2 records, the format used by virtually all live NTFS
volumes. The journal is an append-only, kernel-maintained log of filesystem
changes, which makes it an excellent cross-check against the user-facing
timestamps stored in the $MFT.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .filetime import filetime_to_datetime
from datetime import datetime

# USN reason flags (subset that matters for the timeline).
REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000800: "RENAME_OLD_NAME",
    0x00001000: "RENAME_NEW_NAME",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00080000: "CLOSE",
    0x00020000: "SECURITY_CHANGE",
}


def decode_reasons(reason: int) -> list[str]:
    return [name for bit, name in REASON_FLAGS.items() if reason & bit]


@dataclass
class UsnRecord:
    usn: int
    file_ref: int            # full 64-bit file reference (number + sequence)
    parent_ref: int
    timestamp: datetime | None
    reasons: list[str]
    file_attributes: int
    name: str

    @property
    def file_record_number(self) -> int:
        # Low 48 bits are the MFT record number; high 16 are the sequence.
        return self.file_ref & 0x0000FFFFFFFFFFFF


@dataclass
class UsnJournal:
    records: list[UsnRecord] = field(default_factory=list)

    def by_record_number(self) -> dict[int, list[UsnRecord]]:
        out: dict[int, list[UsnRecord]] = {}
        for r in self.records:
            out.setdefault(r.file_record_number, []).append(r)
        for recs in out.values():
            recs.sort(key=lambda r: r.usn)
        return out


def parse_usnjrnl(path: str) -> UsnJournal:
    """Parse a $UsnJrnl:$J stream (the $J data stream extracted to a file)."""
    journal = UsnJournal()
    with open(path, "rb") as fh:
        data = fh.read()

    offset = 0
    n = len(data)
    while offset + 4 <= n:
        (record_len,) = struct.unpack_from("<I", data, offset)
        if record_len == 0:
            # Runs of zero bytes are sparse padding between journal pages.
            offset += 8
            continue
        if record_len < 60 or offset + record_len > n:
            break
        major, minor = struct.unpack_from("<HH", data, offset + 4)
        if major != 2:
            # Only V2 is handled; skip anything else cleanly.
            offset += record_len
            continue
        file_ref, parent_ref, usn, ts = struct.unpack_from(
            "<QQQQ", data, offset + 8
        )
        reason = struct.unpack_from("<I", data, offset + 40)[0]
        file_attrs = struct.unpack_from("<I", data, offset + 52)[0]
        name_len, name_off = struct.unpack_from("<HH", data, offset + 56)
        name = ""
        nstart = offset + name_off
        if 0 < name_len and nstart + name_len <= offset + record_len:
            name = data[nstart:nstart + name_len].decode("utf-16-le", "replace")
        journal.records.append(
            UsnRecord(
                usn=usn,
                file_ref=file_ref,
                parent_ref=parent_ref,
                timestamp=filetime_to_datetime(ts),
                reasons=decode_reasons(reason),
                file_attributes=file_attrs,
                name=name,
            )
        )
        offset += record_len
    return journal
