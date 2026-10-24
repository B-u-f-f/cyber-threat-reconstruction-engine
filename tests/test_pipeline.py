"""End-to-end and unit tests covering the full CTRE pipeline.

The generator writes real on-disk structures, so these tests also validate
that every parser reads back exactly what was written (round-trip).
"""

import os
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ctre.correlate import build_timeline, correlate_exfil
from ctre.filetime import (datetime_to_filetime, filetime_to_datetime,
                           subsecond_is_zero)
from ctre.gen_testdata import generate
from ctre.mft import parse_mft
from ctre.pcap_meta import parse_pcap
from ctre.report import render_report
from ctre.timestomp import analyze
from ctre.usnjrnl import parse_usnjrnl


def _artifacts(tmp):
    return generate(tmp)


def test_filetime_roundtrip():
    dt = datetime(2026, 10, 20, 9, 0, 0, 500000, tzinfo=timezone.utc)
    assert filetime_to_datetime(datetime_to_filetime(dt)) == dt
    assert filetime_to_datetime(0) is None


def test_subsecond_zero():
    whole = datetime(2019, 1, 1, tzinfo=timezone.utc)
    assert subsecond_is_zero(datetime_to_filetime(whole))
    frac = datetime(2019, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc)
    assert not subsecond_is_zero(datetime_to_filetime(frac))


def test_mft_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        paths = _artifacts(tmp)
        entries = parse_mft(paths["mft"])
        assert len(entries) == 2
        names = {e.name for e in entries}
        assert names == {"report.docx", "svchost.exe"}
        for e in entries:
            assert e.si is not None and e.fn is not None
            assert e.si.created is not None


def test_usnjrnl_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        paths = _artifacts(tmp)
        journal = parse_usnjrnl(paths["usnjrnl"])
        assert len(journal.records) == 4
        by_rec = journal.by_record_number()
        assert 64 in by_rec and 65 in by_rec
        reasons = {r for rec in journal.records for r in rec.reasons}
        assert "FILE_CREATE" in reasons


def test_pcap_metadata():
    with tempfile.TemporaryDirectory() as tmp:
        paths = _artifacts(tmp)
        pcap = parse_pcap(paths["pcap"])
        assert pcap.packet_count > 100
        assert any(q.qname == "exfil.example.net" for q in pcap.dns)
        assert any(f.sni == "exfil.example.net" for f in pcap.flows)
        big = max(f.total_bytes for f in pcap.flows)
        assert big > 100_000


def test_timestomp_detection():
    with tempfile.TemporaryDirectory() as tmp:
        paths = _artifacts(tmp)
        entries = parse_mft(paths["mft"])
        journal = parse_usnjrnl(paths["usnjrnl"])
        findings = analyze(entries, journal.by_record_number())
        rules = {f.rule for f in findings}
        # The timestomped svchost.exe should trip multiple detectors.
        assert "SI_BEFORE_FN" in rules
        assert "SI_BEFORE_JRNL" in rules
        assert "ZERO_SUBSECOND" in rules
        stomped = [f for f in findings if f.name == "svchost.exe"]
        assert stomped and any(f.severity == "high" for f in stomped)
        # The normal file should not be flagged high.
        normal = [f for f in findings if f.name == "report.docx"]
        assert not any(f.severity == "high" for f in normal)


def test_exfil_correlation_and_timeline():
    with tempfile.TemporaryDirectory() as tmp:
        paths = _artifacts(tmp)
        entries = parse_mft(paths["mft"])
        journal = parse_usnjrnl(paths["usnjrnl"])
        pcap = parse_pcap(paths["pcap"])
        corr = correlate_exfil(journal, pcap)
        assert corr, "expected a large outbound flow correlated to disk change"
        assert any("svchost.exe" in c.summary for c in corr)
        timeline = build_timeline(entries, journal, pcap)
        assert timeline == sorted(timeline, key=lambda e: e.timestamp)
        assert any(e.source == "network" for e in timeline)


def test_report_escaping():
    html = render_report(
        findings=[], correlations=[], timeline=[],
        sources={"engine_version": "0.1.0", "note": "<script>x</script>"},
    )
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html
