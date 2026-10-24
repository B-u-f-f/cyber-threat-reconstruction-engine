"""Generate synthetic, self-consistent forensic artifacts for demos/tests.

Everything produced here is fabricated in-memory and written to disk in the
real on-disk structures that CTRE's parsers read back, so the generator and
parsers validate each other. One file in the synthetic $MFT is deliberately
"timestomped" so the detectors have something to find, and the capture
contains a large outbound transfer timed to line up with a disk change.

No real evidence, no network access, no host state touched.
"""

from __future__ import annotations

import os
import struct
from datetime import datetime, timedelta, timezone

from .filetime import datetime_to_filetime

SECTOR = 512
MFT_RECORD_SIZE = 1024


# --------------------------------------------------------------------------- #
# $MFT
# --------------------------------------------------------------------------- #
def _resident_attr(attr_type: int, content: bytes, attr_id: int) -> bytes:
    header_len = 24
    total = header_len + len(content)
    total = (total + 7) & ~7  # 8-byte align
    buf = bytearray(total)
    struct.pack_into("<I", buf, 0, attr_type)
    struct.pack_into("<I", buf, 4, total)
    buf[8] = 0                       # resident
    struct.pack_into("<H", buf, 16, len(content))
    struct.pack_into("<H", buf, 20, header_len)  # content offset
    struct.pack_into("<H", buf, 14, attr_id)
    buf[header_len:header_len + len(content)] = content
    return bytes(buf)


def _standard_information(created, modified, changed, accessed) -> bytes:
    return struct.pack(
        "<QQQQ",
        datetime_to_filetime(created), datetime_to_filetime(modified),
        datetime_to_filetime(changed), datetime_to_filetime(accessed),
    ) + b"\x00" * 40  # flags/version/etc. padding (unused by parser)


def _file_name(parent_ref, name, created, modified, changed, accessed) -> bytes:
    name_utf16 = name.encode("utf-16-le")
    body = struct.pack("<Q", parent_ref)
    body += struct.pack(
        "<QQQQ",
        datetime_to_filetime(created), datetime_to_filetime(modified),
        datetime_to_filetime(changed), datetime_to_filetime(accessed),
    )
    body += struct.pack("<QQ", 0, 0)      # alloc + real size
    body += struct.pack("<II", 0, 0)      # flags + reparse
    body += struct.pack("<BB", len(name), 1)  # name length + namespace
    body += name_utf16
    return body


def _build_mft_record(rec_no, name, si_times, fn_times, parent=5) -> bytes:
    si = _resident_attr(0x10, _standard_information(*si_times), 1)
    fn = _resident_attr(0x30, _file_name(parent, name, *fn_times), 2)
    first_attr = 56
    attrs = si + fn + struct.pack("<I", 0xFFFFFFFF)
    used = first_attr + len(attrs)

    rec = bytearray(MFT_RECORD_SIZE)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 4, 48)   # usa offset
    struct.pack_into("<H", rec, 6, 3)    # usa count (1 USN + 2 fixups)
    struct.pack_into("<H", rec, 16, 1)   # sequence number
    struct.pack_into("<H", rec, 18, 1)   # hard link count
    struct.pack_into("<H", rec, 20, first_attr)
    struct.pack_into("<H", rec, 22, 0x0001)  # in-use, not directory
    struct.pack_into("<I", rec, 24, used)
    struct.pack_into("<I", rec, 28, MFT_RECORD_SIZE)
    struct.pack_into("<H", rec, 40, 3)   # next attr id
    struct.pack_into("<I", rec, 44, rec_no)
    rec[first_attr:first_attr + len(attrs)] = attrs

    # Update-sequence (fixup) array: stash the real sector-end bytes, then
    # stamp the USN marker where the parser expects it.
    usn_marker = b"\x01\x00"
    fixups = bytearray()
    for i in range(2):
        end = (i + 1) * SECTOR
        fixups += bytes(rec[end - 2:end])
        rec[end - 2:end] = usn_marker
    struct.pack_into("<H", rec, 48, struct.unpack("<H", usn_marker)[0])
    rec[50:54] = fixups
    return bytes(rec)


# --------------------------------------------------------------------------- #
# $UsnJrnl:$J
# --------------------------------------------------------------------------- #
def _usn_record(usn, file_ref, parent_ref, ts, reason, name) -> bytes:
    name_utf16 = name.encode("utf-16-le")
    name_off = 60
    record_len = name_off + len(name_utf16)
    record_len = (record_len + 7) & ~7
    buf = bytearray(record_len)
    struct.pack_into("<I", buf, 0, record_len)
    struct.pack_into("<HH", buf, 4, 2, 0)          # version 2.0
    struct.pack_into("<Q", buf, 8, file_ref)
    struct.pack_into("<Q", buf, 16, parent_ref)
    struct.pack_into("<Q", buf, 24, usn)
    struct.pack_into("<Q", buf, 32, datetime_to_filetime(ts))
    struct.pack_into("<I", buf, 40, reason)
    struct.pack_into("<I", buf, 52, 0x20)          # FILE_ATTRIBUTE_ARCHIVE
    struct.pack_into("<HH", buf, 56, len(name_utf16), name_off)
    buf[name_off:name_off + len(name_utf16)] = name_utf16
    return bytes(buf)


# --------------------------------------------------------------------------- #
# .pcap
# --------------------------------------------------------------------------- #
def _ipv4(proto, src, dst, payload) -> bytes:
    import socket
    total_len = 20 + len(payload)
    hdr = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, total_len, 1, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return hdr + payload


def _eth(payload) -> bytes:
    return (b"\xaa\xbb\xcc\x00\x00\x01" b"\xaa\xbb\xcc\x00\x00\x02"
            + struct.pack(">H", 0x0800) + payload)


def _tcp(sport, dport, payload) -> bytes:
    hdr = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x18, 1024, 0, 0)
    return hdr + payload


def _udp(sport, dport, payload) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns_query(qname) -> bytes:
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in qname.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 1, 1)
    return q


def _client_hello(sni) -> bytes:
    name = sni.encode()
    sni_ext = (struct.pack(">H", len(name) + 3) + b"\x00"
               + struct.pack(">H", len(name)) + name)
    ext = struct.pack(">HH", 0x0000, len(sni_ext)) + sni_ext
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"          # ver+random+sid_len
            + struct.pack(">H", 2) + b"\x00\x2f"          # ciphers
            + b"\x01\x00"                                  # comp
            + struct.pack(">H", len(ext)) + ext)
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def _pcap_packet(ts: datetime, l4: bytes) -> bytes:
    frame = _eth(l4)
    sec = int(ts.timestamp())
    usec = ts.microsecond
    return struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame


def generate(out_dir: str) -> dict[str, str]:
    """Write mft.bin, usnjrnl.bin and capture.pcap into out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    base = datetime(2026, 10, 20, 9, 0, 0, 500000, tzinfo=timezone.utc)

    # ---- $MFT: a normal file and a timestomped file -------------------- #
    normal_t = base
    normal = _build_mft_record(
        64, "report.docx",
        si_times=(normal_t, normal_t + timedelta(minutes=5),
                  normal_t, normal_t + timedelta(minutes=5)),
        fn_times=(normal_t, normal_t, normal_t, normal_t),
    )
    # Timestomped: SI pushed back to 2019 with zeroed sub-seconds; FN stays
    # at the real creation time in 2026.
    stomp_real = base + timedelta(hours=2)
    stomp_fake = datetime(2019, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)
    stomped = _build_mft_record(
        65, "svchost.exe",
        si_times=(stomp_fake, stomp_fake, stomp_fake, stomp_fake),
        fn_times=(stomp_real, stomp_real, stomp_real, stomp_real),
    )
    mft_path = os.path.join(out_dir, "mft.bin")
    with open(mft_path, "wb") as fh:
        fh.write(normal + stomped)

    # ---- $UsnJrnl: creation + change records --------------------------- #
    ref64 = lambda n: (1 << 48) | n
    usn_path = os.path.join(out_dir, "usnjrnl.bin")
    records = b"".join([
        _usn_record(0x1000, ref64(64), ref64(5), normal_t, 0x100, "report.docx"),
        _usn_record(0x1100, ref64(64), ref64(5),
                    normal_t + timedelta(minutes=5), 0x002, "report.docx"),
        # svchost.exe really first appears in 2026, contradicting its SI time.
        _usn_record(0x1200, ref64(65), ref64(5), stomp_real, 0x100,
                    "svchost.exe"),
        _usn_record(0x1300, ref64(65), ref64(5),
                    stomp_real + timedelta(minutes=1), 0x001, "svchost.exe"),
    ])
    with open(usn_path, "wb") as fh:
        fh.write(records)

    # ---- .pcap: DNS, TLS SNI, and a large outbound transfer ------------ #
    pcap_path = os.path.join(out_dir, "capture.pcap")
    packets = []
    t = stomp_real + timedelta(seconds=30)  # just after svchost.exe changes
    packets.append(_pcap_packet(
        t, _ipv4(17, "10.0.0.5", "10.0.0.1", _udp(50000, 53,
                 _dns_query("exfil.example.net")))))
    packets.append(_pcap_packet(
        t + timedelta(seconds=1),
        _ipv4(6, "10.0.0.5", "203.0.113.9",
              _tcp(50001, 443, _client_hello("exfil.example.net")))))
    # ~150 KB leaving the client toward the C2 host, in chunks.
    for i in range(120):
        packets.append(_pcap_packet(
            t + timedelta(seconds=2, milliseconds=i * 10),
            _ipv4(6, "10.0.0.5", "203.0.113.9",
                  _tcp(50001, 443, b"\x17\x03\x03" + b"A" * 1300))))
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    with open(pcap_path, "wb") as fh:
        fh.write(header + b"".join(packets))

    return {"mft": mft_path, "usnjrnl": usn_path, "pcap": pcap_path}


if __name__ == "__main__":  # pragma: no cover
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "sample_artifacts"
    paths = generate(out)
    for k, v in paths.items():
        print(f"{k}: {v}")
