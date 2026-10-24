# Cyber Threat Reconstruction Engine (CTRE)

An offline, read-only DFIR toolkit that cross-correlates **NTFS filesystem
artifacts** (`$MFT`, `$UsnJrnl:$J`) with **network capture metadata** (`.pcap`)
to build a single chronological threat timeline, detect **timestomping**, and
link large outbound transfers to disk activity.

Built for a cyber-forensics course. Everything runs on pre-collected artifacts,
opens every input read-only, and needs no third-party packages.

## Scope and safety

CTRE works **only** on evidence that is already observable:

- NTFS `$MFT` and `$UsnJrnl` records parsed from extracted artifact files.
- Network **metadata** from a capture: endpoints, ports, timing, byte volumes,
  DNS query names, and TLS SNI (all cleartext in the capture).

**Out of scope by design:** CTRE does **not** read TLS session secrets out of
memory dumps and does **not** decrypt captured network traffic. That capability
is a general-purpose traffic-decryption tool regardless of how it is packaged,
so it is deliberately excluded. The engine demonstrates the full correlation
workflow without it.

## What it detects

**Timestomping** (`ctre/timestomp.py`):

| Rule | Meaning |
| --- | --- |
| `SI_BEFORE_FN` | `$STANDARD_INFORMATION` created time earlier than `$FILE_NAME` created time |
| `SI_BEFORE_JRNL` | SI creation time predates the file's first `$UsnJrnl` record |
| `ZERO_SUBSECOND` | Multiple SI timestamps have all sub-second precision zeroed |
| `NO_JRNL_FOR_CHANGE` | SI modified time newer than any journal entry for the file |

**Exfil correlation** (`ctre/correlate.py`): large outbound flows that line up
in time with a disk modification in the journal.

## Install

No dependencies beyond the Python standard library (Python 3.10+).

```bash
python -m pytest -q        # run the test suite
```

## Usage

Generate self-consistent synthetic artifacts (includes a planted timestomped
file and a timed exfil transfer), then analyze them:

```bash
python -m ctre gen sample_artifacts
python -m ctre analyze \
    --mft sample_artifacts/mft.bin \
    --usnjrnl sample_artifacts/usnjrnl.bin \
    --pcap sample_artifacts/capture.pcap \
    --report sample_artifacts/report.html
```

Open `report.html` in a browser for the findings tables and the filterable
unified timeline.

### Using real artifacts

Extract the raw streams with your tooling of choice (e.g. a forensic imager or
`icat`/`fls`-style extraction) and point the same flags at them. The `$MFT`
record size defaults to 1024 bytes (`--mft-record-size` to override).

## Layout

```
ctre/
  filetime.py     Windows FILETIME <-> datetime helpers
  mft.py          $MFT FILE-record parser (fixups, SI/FN timestamps)
  usnjrnl.py      $UsnJrnl:$J (USN_RECORD_V2) parser
  timestomp.py    timestamp-manipulation detectors
  pcap_meta.py    classic-pcap metadata extractor (no decryption)
  correlate.py    unified timeline + exfil correlation
  report.py       static, self-contained HTML report
  gen_testdata.py synthetic artifact generator
  cli.py          command-line interface
tests/
  test_pipeline.py  round-trip + end-to-end tests
```

## License

MIT
