"""Timestomping detection.

Combines $MFT timestamps with the $UsnJrnl history to flag anti-forensic
timestamp manipulation. Each finding carries a severity and a plain-language
explanation so the output is useful in a report rather than just a boolean.

Heuristics implemented:

  1. SI_BEFORE_FN   - $STANDARD_INFORMATION created time is earlier than the
                      $FILE_NAME created time. $FILE_NAME is harder to tamper,
                      so SI < FN is a classic sign the SI times were pushed
                      backwards.
  2. SI_BEFORE_JRNL - the file's SI creation time predates its first journal
                      record. A file cannot have been created before the
                      journal first saw it come into existence.
  3. ZERO_SUBSECOND - SI timestamps with all sub-second precision zeroed, which
                      most timestomping utilities produce.
  4. NO_JRNL_FOR_CHANGE - SI modified time is newer than the newest journal
                      entry for the file, i.e. a modification the journal never
                      recorded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .filetime import subsecond_is_zero
from .mft import MftEntry
from .usnjrnl import UsnRecord

# Tolerance for "equal" timestamps; journal and MFT writes are not atomic.
_SKEW = timedelta(seconds=2)

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    record_number: int
    name: str
    rule: str
    severity: str
    explanation: str
    detail: dict = field(default_factory=dict)


def _first_create(records: list[UsnRecord]) -> datetime | None:
    for r in records:
        if "FILE_CREATE" in r.reasons and r.timestamp:
            return r.timestamp
    return records[0].timestamp if records else None


def _latest_journal_ts(records: list[UsnRecord]) -> datetime | None:
    stamps = [r.timestamp for r in records if r.timestamp]
    return max(stamps) if stamps else None


def analyze(
    entries: list[MftEntry],
    journal_by_record: dict[int, list[UsnRecord]],
) -> list[Finding]:
    findings: list[Finding] = []

    for entry in entries:
        if entry.si is None:
            continue
        name = entry.name or f"<record {entry.record_number}>"
        si = entry.si
        fn = entry.fn
        jrnl = journal_by_record.get(entry.record_number, [])

        # Rule 1: SI created earlier than FN created.
        if fn and si.created and fn.created and si.created + _SKEW < fn.created:
            findings.append(Finding(
                entry.record_number, name, "SI_BEFORE_FN", "high",
                "$STANDARD_INFORMATION creation time is earlier than "
                "$FILE_NAME creation time, which is a hallmark of backdated "
                "(timestomped) SI timestamps.",
                {"si_created": str(si.created), "fn_created": str(fn.created)},
            ))

        # Rule 2: SI created before the journal first saw the file.
        first_create = _first_create(jrnl)
        if si.created and first_create and si.created + _SKEW < first_create:
            findings.append(Finding(
                entry.record_number, name, "SI_BEFORE_JRNL", "high",
                "File's SI creation time predates its first $UsnJrnl record. "
                "The journal cannot record a file before it exists, so the SI "
                "time appears to have been set into the past.",
                {"si_created": str(si.created),
                 "first_journal": str(first_create)},
            ))

        # Rule 3: zeroed sub-second precision on SI timestamps.
        zeroed = [label for label, raw in (
            ("created", si.raw_created),
            ("modified", si.raw_modified),
            ("accessed", si.raw_accessed),
        ) if subsecond_is_zero(raw)]
        if len(zeroed) >= 2:
            findings.append(Finding(
                entry.record_number, name, "ZERO_SUBSECOND", "medium",
                "Multiple SI timestamps have all sub-second precision set to "
                "zero. Normal filesystem activity rarely produces whole-second "
                "times; many timestomping tools do.",
                {"zeroed_fields": zeroed},
            ))

        # Rule 4: SI modified newer than the whole journal history for the file.
        latest = _latest_journal_ts(jrnl)
        if si.modified and latest and si.modified > latest + _SKEW:
            findings.append(Finding(
                entry.record_number, name, "NO_JRNL_FOR_CHANGE", "medium",
                "SI modified time is newer than the most recent $UsnJrnl entry "
                "for this file, i.e. a modification the change journal never "
                "recorded.",
                {"si_modified": str(si.modified),
                 "latest_journal": str(latest)},
            ))

    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 0), f.record_number),
        reverse=True,
    )
    return findings
