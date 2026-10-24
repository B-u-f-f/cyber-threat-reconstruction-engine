"""Analysis service: runs the full pipeline and returns JSON-ready results.

Shared by the web UI and the CLI so both produce identical findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import __version__
from .correlate import build_timeline, correlate_exfil
from .mft import parse_mft
from .pcap_meta import PcapResult, parse_pcap
from .report import render_report
from .timestomp import analyze
from .usnjrnl import UsnJournal, parse_usnjrnl


@dataclass
class Options:
    min_exfil_bytes: int = 100_000
    window_minutes: float = 5.0
    mft_record_size: int = 1024


@dataclass
class Analysis:
    """Raw pipeline output, kept so the HTML report can be rendered later."""
    findings: list = field(default_factory=list)
    correlations: list = field(default_factory=list)
    timeline: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    sources: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "summary": self.summary,
            "sources": self.sources,
            "findings": [
                {"record": f.record_number, "name": f.name, "rule": f.rule,
                 "severity": f.severity, "explanation": f.explanation,
                 "detail": f.detail}
                for f in self.findings
            ],
            "correlations": [
                {"time": _iso(c.timestamp), "summary": c.summary,
                 "network": c.network, "disk": c.disk}
                for c in self.correlations
            ],
            "timeline": [
                {"time": _iso(e.timestamp), "source": e.source,
                 "summary": e.summary, "detail": e.detail}
                for e in self.timeline
            ],
        }

    def report_html(self) -> str:
        return render_report(
            findings=self.findings, correlations=self.correlations,
            timeline=self.timeline, sources=self.sources,
        )


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def run_analysis(paths: dict[str, str], options: Options | None = None,
                 names: dict[str, str] | None = None) -> Analysis:
    """Run the pipeline on whichever of mft/usnjrnl/pcap are in `paths`.

    `names` optionally maps each kind to a display name (e.g. the original
    upload filename) for the report.
    """
    opts = options or Options()
    names = names or {}
    if not any(paths.get(k) for k in ("mft", "usnjrnl", "pcap")):
        raise ValueError("provide at least one artifact ($MFT, $UsnJrnl or pcap)")

    entries = (parse_mft(paths["mft"], record_size=opts.mft_record_size)
               if paths.get("mft") else [])
    journal = parse_usnjrnl(paths["usnjrnl"]) if paths.get("usnjrnl") else None
    pcap = parse_pcap(paths["pcap"]) if paths.get("pcap") else None

    findings = (analyze(entries, journal.by_record_number() if journal else {})
                if entries else [])
    correlations = (correlate_exfil(
        journal, pcap,
        window=timedelta(minutes=opts.window_minutes),
        min_bytes=opts.min_exfil_bytes,
    ) if journal and pcap else [])
    timeline = build_timeline(entries, journal or UsnJournal(),
                              pcap or PcapResult())

    severities = {s: sum(1 for f in findings if f.severity == s)
                  for s in ("high", "medium", "low")}
    summary = {
        "mft_entries": len(entries),
        "usn_records": len(journal.records) if journal else 0,
        "packets": pcap.packet_count if pcap else 0,
        "flows": len(pcap.flows) if pcap else 0,
        "dns_queries": len(pcap.dns) if pcap else 0,
        "findings": len(findings),
        "severity": severities,
        "correlations": len(correlations),
        "timeline_events": len(timeline),
        "flagged_files": sorted({f.name for f in findings}),
    }
    sources = {
        "engine_version": __version__,
        "$MFT": names.get("mft") or paths.get("mft") or "(not provided)",
        "$UsnJrnl": (names.get("usnjrnl") or paths.get("usnjrnl")
                     or "(not provided)"),
        "pcap": names.get("pcap") or paths.get("pcap") or "(not provided)",
    }
    return Analysis(findings, correlations, timeline, summary, sources)
