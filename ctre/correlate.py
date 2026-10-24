"""Cross-artifact correlation and unified timeline.

Builds a single chronological list of events from disk and network artifacts
and links them where they fall close together in time. The headline
correlation is an outbound network transfer that lines up with a nearby disk
modification -- a possible stage-and-exfiltrate pattern -- surfaced from
metadata alone (no payload decryption).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .mft import MftEntry
from .pcap_meta import PcapResult, Flow
from .usnjrnl import UsnJournal, UsnRecord


@dataclass
class TimelineEvent:
    timestamp: datetime
    source: str      # "usnjrnl" | "mft" | "network" | "dns"
    summary: str
    detail: dict = field(default_factory=dict)


@dataclass
class Correlation:
    timestamp: datetime
    summary: str
    network: dict
    disk: dict


def _large_outbound_flows(pcap: PcapResult, min_bytes: int) -> list[Flow]:
    out = []
    for f in pcap.flows:
        # Treat the higher, dynamic port as the local (client) side; bytes
        # leaving that side are "outbound".
        if f.sport > f.dport:
            outbound = f.bytes_src_to_dst
        else:
            outbound = f.bytes_dst_to_src
        if outbound >= min_bytes:
            out.append(f)
    return out


def build_timeline(
    entries: list[MftEntry],
    journal: UsnJournal,
    pcap: PcapResult,
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []

    for rec in journal.records:
        if rec.timestamp:
            events.append(TimelineEvent(
                rec.timestamp, "usnjrnl",
                f"{rec.name}: {', '.join(rec.reasons) or 'change'}",
                {"record": rec.file_record_number, "usn": rec.usn},
            ))

    for e in entries:
        if e.si and e.si.created:
            events.append(TimelineEvent(
                e.si.created, "mft",
                f"{e.name or e.record_number}: MFT SI created",
                {"record": e.record_number},
            ))

    for f in pcap.flows:
        if f.first_seen:
            label = f.sni or f.dst
            events.append(TimelineEvent(
                f.first_seen, "network",
                f"{f.proto} {f.src}:{f.sport} -> {label}:{f.dport} "
                f"({f.total_bytes} bytes)",
                {"sni": f.sni, "dst": f.dst, "bytes": f.total_bytes},
            ))
    for q in pcap.dns:
        if q.timestamp:
            events.append(TimelineEvent(
                q.timestamp, "dns", f"DNS query {q.qname} from {q.src}",
                {"qname": q.qname},
            ))

    events.sort(key=lambda ev: ev.timestamp)
    return events


def correlate_exfil(
    journal: UsnJournal,
    pcap: PcapResult,
    window: timedelta = timedelta(minutes=5),
    min_bytes: int = 100_000,
) -> list[Correlation]:
    """Link large outbound flows to disk changes within a time window."""
    correlations: list[Correlation] = []
    disk_changes = [r for r in journal.records if r.timestamp]

    for flow in _large_outbound_flows(pcap, min_bytes):
        if not flow.first_seen:
            continue
        for rec in disk_changes:
            if abs(rec.timestamp - flow.first_seen) <= window:
                label = flow.sni or flow.dst
                correlations.append(Correlation(
                    timestamp=flow.first_seen,
                    summary=(
                        f"Outbound transfer to {label} "
                        f"({flow.total_bytes} bytes) within "
                        f"{window} of disk change to '{rec.name}' "
                        f"({', '.join(rec.reasons) or 'change'})."
                    ),
                    network={"dst": flow.dst, "sni": flow.sni,
                             "bytes": flow.total_bytes, "dport": flow.dport},
                    disk={"name": rec.name,
                          "record": rec.file_record_number,
                          "reasons": rec.reasons,
                          "time": str(rec.timestamp)},
                ))
    correlations.sort(key=lambda c: c.timestamp)
    return correlations
