"""Command-line entry point for the Cyber Threat Reconstruction Engine."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .correlate import build_timeline, correlate_exfil
from .gen_testdata import generate
from .mft import parse_mft
from .pcap_meta import parse_pcap
from .report import write_report
from .timestomp import analyze
from .usnjrnl import parse_usnjrnl


def _cmd_gen(args) -> int:
    paths = generate(args.out_dir)
    print("Wrote synthetic artifacts:")
    for k, v in paths.items():
        print(f"  {k:9} {v}")
    return 0


def _cmd_analyze(args) -> int:
    entries, journal, pcap = [], None, None

    if args.mft:
        entries = parse_mft(args.mft, record_size=args.mft_record_size)
        print(f"[+] Parsed {len(entries)} MFT entries from {args.mft}")
    if args.usnjrnl:
        journal = parse_usnjrnl(args.usnjrnl)
        print(f"[+] Parsed {len(journal.records)} USN records from "
              f"{args.usnjrnl}")
    if args.pcap:
        pcap = parse_pcap(args.pcap)
        print(f"[+] Parsed {pcap.packet_count} packets / {len(pcap.flows)} "
              f"flows from {args.pcap}")

    jrnl_by_rec = journal.by_record_number() if journal else {}
    findings = analyze(entries, jrnl_by_rec) if entries else []
    print(f"[+] Timestomping findings: {len(findings)}")
    for f in findings:
        print(f"    [{f.severity.upper():6}] {f.name}: {f.rule}")

    correlations = []
    if journal and pcap:
        correlations = correlate_exfil(
            journal, pcap,
            min_bytes=args.min_exfil_bytes,
        )
        print(f"[+] Exfil correlations: {len(correlations)}")

    timeline = []
    if journal or entries or pcap:
        from .usnjrnl import UsnJournal
        from .pcap_meta import PcapResult
        timeline = build_timeline(
            entries, journal or UsnJournal(), pcap or PcapResult()
        )

    if args.report:
        write_report(
            args.report,
            findings=findings,
            correlations=correlations,
            timeline=timeline,
            sources={
                "engine_version": __version__,
                "$MFT": args.mft or "(not provided)",
                "$UsnJrnl": args.usnjrnl or "(not provided)",
                "pcap": args.pcap or "(not provided)",
            },
        )
        print(f"[+] Wrote HTML report to {args.report}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ctre",
        description="Offline, read-only DFIR artifact correlation engine "
                    "(no TLS key extraction, no traffic decryption).",
    )
    p.add_argument("--version", action="version",
                   version=f"ctre {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("gen", help="generate synthetic sample artifacts")
    g.add_argument("out_dir", nargs="?", default="sample_artifacts")
    g.set_defaults(func=_cmd_gen)

    a = sub.add_parser("analyze", help="analyze artifacts and build a report")
    a.add_argument("--mft", help="path to an extracted $MFT file")
    a.add_argument("--usnjrnl", help="path to an extracted $UsnJrnl:$J stream")
    a.add_argument("--pcap", help="path to a classic .pcap capture")
    a.add_argument("--report", help="path to write the HTML report")
    a.add_argument("--mft-record-size", type=int, default=1024)
    a.add_argument("--min-exfil-bytes", type=int, default=100_000,
                   help="outbound byte threshold for exfil correlation")
    a.set_defaults(func=_cmd_analyze)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not (getattr(args, "mft", None) or getattr(args, "usnjrnl", None)
            or getattr(args, "pcap", None) or args.command == "gen"):
        print("error: provide at least one of --mft/--usnjrnl/--pcap",
              file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
