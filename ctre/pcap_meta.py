"""Read-only network *metadata* extraction from a classic .pcap file.

This module deliberately performs NO decryption. It reads only information
that is already observable in a capture without any keys:

  * per-connection flow records (endpoints, ports, packet/byte counts,
    direction, start/end time);
  * DNS query names (UDP port 53);
  * TLS ClientHello SNI server names (the hostname is sent in cleartext).

Pure standard library, so there is nothing to install and the behaviour is
easy to audit. Only the classic libpcap format and Ethernet/IPv4 are handled;
anything else is skipped.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone

PCAP_MAGIC_US = 0xA1B2C3D4   # microsecond, little/big endian handled below
PCAP_MAGIC_NS = 0xA1B23C4D   # nanosecond
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101

ETH_TYPE_IPV4 = 0x0800
IPPROTO_TCP = 6
IPPROTO_UDP = 17


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    packets: int = 0
    bytes_src_to_dst: int = 0
    bytes_dst_to_src: int = 0
    sni: str | None = None

    @property
    def key(self) -> tuple:
        # Canonical (endpoint-order-independent) 5-tuple.
        a = (self.src, self.sport)
        b = (self.dst, self.dport)
        lo, hi = sorted([a, b])
        return (lo, hi, self.proto)

    @property
    def total_bytes(self) -> int:
        return self.bytes_src_to_dst + self.bytes_dst_to_src


@dataclass
class DnsQuery:
    timestamp: datetime | None
    src: str
    qname: str


@dataclass
class PcapResult:
    flows: list[Flow] = field(default_factory=list)
    dns: list[DnsQuery] = field(default_factory=list)
    packet_count: int = 0


def _read_header(data: bytes):
    if len(data) < 24:
        raise ValueError("file too short to be a pcap")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
        endian, nano = "<", magic == PCAP_MAGIC_NS
    else:
        magic_be = struct.unpack_from(">I", data, 0)[0]
        if magic_be in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            endian, nano = ">", magic_be == PCAP_MAGIC_NS
        else:
            raise ValueError("not a classic pcap file")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    return endian, nano, linktype


def _parse_dns_qname(payload: bytes) -> str | None:
    # Skip the 12-byte DNS header, then read the QNAME label sequence.
    if len(payload) < 13:
        return None
    qdcount = struct.unpack_from(">H", payload, 4)[0]
    if qdcount < 1:
        return None
    labels = []
    off = 12
    guard = 0
    while off < len(payload) and guard < 128:
        guard += 1
        length = payload[off]
        if length == 0:
            break
        if length & 0xC0:  # compression pointer; unusual in a question
            break
        off += 1
        if off + length > len(payload):
            return None
        labels.append(payload[off:off + length].decode("ascii", "replace"))
        off += length
    return ".".join(labels) if labels else None


def _parse_tls_sni(payload: bytes) -> str | None:
    # Expect a TLS record (handshake, ClientHello) carrying an SNI extension.
    if len(payload) < 43 or payload[0] != 0x16:
        return None
    try:
        # Record header 5 bytes; handshake type at offset 5 must be 1 (CH).
        if payload[5] != 0x01:
            return None
        pos = 43  # past record+handshake headers and 32-byte random
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        cipher_len = struct.unpack_from(">H", payload, pos)[0]
        pos += 2 + cipher_len
        comp_len = payload[pos]
        pos += 1 + comp_len
        ext_total = struct.unpack_from(">H", payload, pos)[0]
        pos += 2
        end = min(len(payload), pos + ext_total)
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from(">HH", payload, pos)
            pos += 4
            if ext_type == 0x0000:  # server_name
                # server_name_list(2) + name_type(1) + name_len(2) + name
                name_len = struct.unpack_from(">H", payload, pos + 3)[0]
                start = pos + 5
                return payload[start:start + name_len].decode("ascii", "replace")
            pos += ext_len
    except (struct.error, IndexError):
        return None
    return None


def parse_pcap(path: str) -> PcapResult:
    """Parse a classic .pcap into flow + DNS + SNI metadata (read-only)."""
    with open(path, "rb") as fh:
        data = fh.read()

    endian, nano, linktype = _read_header(data)
    result = PcapResult()
    flows: dict[tuple, Flow] = {}

    off = 24
    n = len(data)
    while off + 16 <= n:
        ts_sec, ts_frac, incl_len, _orig = struct.unpack_from(
            endian + "IIII", data, off
        )
        off += 16
        if off + incl_len > n:
            break
        pkt = data[off:off + incl_len]
        off += incl_len
        result.packet_count += 1
        micros = ts_frac // 1000 if nano else ts_frac
        ts = datetime.fromtimestamp(ts_sec + micros / 1_000_000, tz=timezone.utc)

        ip = _strip_link_layer(pkt, linktype)
        if ip is None or len(ip) < 20:
            continue
        if (ip[0] >> 4) != 4:
            continue  # IPv4 only
        ihl = (ip[0] & 0x0F) * 4
        proto = ip[9]
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        l4 = ip[ihl:]

        if proto == IPPROTO_TCP and len(l4) >= 20:
            sport, dport = struct.unpack_from(">HH", l4, 0)
            data_off = (l4[12] >> 4) * 4
            payload = l4[data_off:]
            _record_flow(flows, src, dst, sport, dport, "TCP", ts, len(pkt))
            if payload and (dport == 443 or sport == 443):
                sni = _parse_tls_sni(payload)
                if sni:
                    f = flows[_canon_key(src, dst, sport, dport, "TCP")]
                    f.sni = f.sni or sni
        elif proto == IPPROTO_UDP and len(l4) >= 8:
            sport, dport = struct.unpack_from(">HH", l4, 0)
            payload = l4[8:]
            _record_flow(flows, src, dst, sport, dport, "UDP", ts, len(pkt))
            if dport == 53 and payload:
                qname = _parse_dns_qname(payload)
                if qname:
                    result.dns.append(DnsQuery(ts, src, qname))

    result.flows = list(flows.values())
    result.flows.sort(key=lambda f: (f.first_seen or datetime.max.replace(
        tzinfo=timezone.utc)))
    return result


def _strip_link_layer(pkt: bytes, linktype: int) -> bytes | None:
    if linktype == LINKTYPE_RAW:
        return pkt
    if linktype == LINKTYPE_ETHERNET:
        if len(pkt) < 14:
            return None
        eth_type = struct.unpack_from(">H", pkt, 12)[0]
        if eth_type != ETH_TYPE_IPV4:
            return None
        return pkt[14:]
    return None


def _canon_key(src, dst, sport, dport, proto) -> tuple:
    a, b = sorted([(src, sport), (dst, dport)])
    return (a, b, proto)


def _record_flow(flows, src, dst, sport, dport, proto, ts, nbytes):
    key = _canon_key(src, dst, sport, dport, proto)
    f = flows.get(key)
    if f is None:
        f = Flow(src=src, dst=dst, sport=sport, dport=dport, proto=proto,
                 first_seen=ts, last_seen=ts)
        flows[key] = f
    f.packets += 1
    if f.first_seen is None or ts < f.first_seen:
        f.first_seen = ts
    if f.last_seen is None or ts > f.last_seen:
        f.last_seen = ts
    # Attribute bytes by matching against the flow's stored "src".
    if (src, sport) == (f.src, f.sport):
        f.bytes_src_to_dst += nbytes
    else:
        f.bytes_dst_to_src += nbytes
