"""Minimal, read-only NTFS $MFT parser.

Parses enough of each MFT FILE record to recover the two timestamp sets that
matter for timestomping analysis:

  * $STANDARD_INFORMATION (attribute type 0x10) - the timestamps shown to users
    and most easily altered by anti-forensic tools.
  * $FILE_NAME (attribute type 0x30) - timestamps the kernel updates and that
    are harder to tamper with from user space.

Only resident attributes are read. The parser applies the update-sequence
(fixup) array and is deliberately tolerant: a malformed record is skipped
rather than aborting the run, because evidence files are untrusted input.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .filetime import filetime_to_datetime
from datetime import datetime

SECTOR_SIZE = 512
ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_END = 0xFFFFFFFF

# MFT record flags
FLAG_IN_USE = 0x0001
FLAG_DIRECTORY = 0x0002


@dataclass
class Timestamps:
    created: datetime | None = None
    modified: datetime | None = None
    mft_changed: datetime | None = None
    accessed: datetime | None = None
    # Raw FILETIME ints retained so detectors can inspect sub-second precision.
    raw_created: int = 0
    raw_modified: int = 0
    raw_mft_changed: int = 0
    raw_accessed: int = 0


@dataclass
class MftEntry:
    record_number: int
    in_use: bool
    is_directory: bool
    sequence: int
    name: str | None = None
    si: Timestamps | None = None       # $STANDARD_INFORMATION
    fn: Timestamps | None = None       # $FILE_NAME
    parse_errors: list[str] = field(default_factory=list)


def _apply_fixup(record: bytes, record_size: int) -> bytes | None:
    """Apply the NTFS update-sequence array to a record.

    Returns the corrected bytes, or None if the record is not a valid FILE
    record. The last two bytes of every sector are replaced with the values
    stored in the update-sequence array.
    """
    if len(record) < 48 or record[:4] != b"FILE":
        return None
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if usa_count == 0:
        return bytes(record)
    end = usa_offset + usa_count * 2
    if end > len(record):
        return None
    usn = record[usa_offset:usa_offset + 2]
    fixups = record[usa_offset + 2:end]
    buf = bytearray(record)
    for i in range(usa_count - 1):
        sector_end = (i + 1) * SECTOR_SIZE
        if sector_end > record_size or sector_end > len(buf):
            break
        # The two bytes before each sector boundary must match the USN.
        if bytes(buf[sector_end - 2:sector_end]) != usn:
            # Signature mismatch: record is torn/corrupt; keep going anyway.
            pass
        buf[sector_end - 2:sector_end] = fixups[i * 2:i * 2 + 2]
    return bytes(buf)


def _parse_standard_information(data: bytes) -> Timestamps:
    c, m, ch, a = struct.unpack_from("<QQQQ", data, 0)
    return Timestamps(
        created=filetime_to_datetime(c),
        modified=filetime_to_datetime(m),
        mft_changed=filetime_to_datetime(ch),
        accessed=filetime_to_datetime(a),
        raw_created=c, raw_modified=m, raw_mft_changed=ch, raw_accessed=a,
    )


def _parse_file_name(data: bytes) -> tuple[Timestamps, str | None]:
    # Layout: 8 parent ref, then 4 FILETIMEs, alloc/real size, flags, reparse,
    # name length (1 byte), namespace (1 byte), name (UTF-16LE).
    c, m, ch, a = struct.unpack_from("<QQQQ", data, 8)
    ts = Timestamps(
        created=filetime_to_datetime(c),
        modified=filetime_to_datetime(m),
        mft_changed=filetime_to_datetime(ch),
        accessed=filetime_to_datetime(a),
        raw_created=c, raw_modified=m, raw_mft_changed=ch, raw_accessed=a,
    )
    name = None
    try:
        name_len = data[64]
        name = data[66:66 + name_len * 2].decode("utf-16-le", "replace")
    except (IndexError, UnicodeDecodeError):
        pass
    return ts, name


def _parse_record(record: bytes, record_size: int) -> MftEntry | None:
    fixed = _apply_fixup(record, record_size)
    if fixed is None:
        return None
    (flags,) = struct.unpack_from("<H", fixed, 22)
    first_attr_off = struct.unpack_from("<H", fixed, 20)[0]
    seq = struct.unpack_from("<H", fixed, 16)[0]
    rec_no = struct.unpack_from("<I", fixed, 44)[0]
    entry = MftEntry(
        record_number=rec_no,
        in_use=bool(flags & FLAG_IN_USE),
        is_directory=bool(flags & FLAG_DIRECTORY),
        sequence=seq,
    )

    off = first_attr_off
    guard = 0
    while off + 4 <= len(fixed) and guard < 256:
        guard += 1
        (attr_type,) = struct.unpack_from("<I", fixed, off)
        if attr_type == ATTR_END:
            break
        if off + 16 > len(fixed):
            break
        attr_len = struct.unpack_from("<I", fixed, off + 4)[0]
        if attr_len == 0 or off + attr_len > len(fixed):
            entry.parse_errors.append(f"bad attr length at {off}")
            break
        non_resident = fixed[off + 8]
        if non_resident == 0:
            content_len = struct.unpack_from("<I", fixed, off + 16)[0]
            content_off = struct.unpack_from("<H", fixed, off + 20)[0]
            start = off + content_off
            content = fixed[start:start + content_len]
            try:
                if attr_type == ATTR_STANDARD_INFORMATION and len(content) >= 32:
                    entry.si = _parse_standard_information(content)
                elif attr_type == ATTR_FILE_NAME and len(content) >= 66:
                    fn_ts, fn_name = _parse_file_name(content)
                    entry.fn = fn_ts
                    if fn_name:
                        entry.name = fn_name
            except struct.error as exc:
                entry.parse_errors.append(f"attr 0x{attr_type:x}: {exc}")
        off += attr_len
    return entry


def parse_mft(path: str, record_size: int = 1024) -> list[MftEntry]:
    """Parse an $MFT file into a list of entries.

    `path` is opened read-only. Records that fail to parse are skipped.
    """
    entries: list[MftEntry] = []
    with open(path, "rb") as fh:
        while True:
            record = fh.read(record_size)
            if len(record) < record_size:
                break
            if record[:4] != b"FILE":
                continue
            try:
                entry = _parse_record(record, record_size)
            except struct.error:
                continue
            if entry is not None:
                entries.append(entry)
    return entries
