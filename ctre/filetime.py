"""Windows FILETIME helpers.

A FILETIME is the number of 100-nanosecond intervals since 1601-01-01 UTC.
These helpers convert to/from timezone-aware datetimes so every module in the
engine works in a single, explicit time base (UTC).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

# 1601-01-01 is the FILETIME epoch.
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_HUNDREDS_OF_NS = 10_000_000  # per second


def filetime_to_datetime(ft: int) -> datetime | None:
    """Convert a raw FILETIME integer to a UTC datetime.

    Returns None for a zero (unset) FILETIME.
    """
    if ft <= 0:
        return None
    return _EPOCH + timedelta(microseconds=ft // 10)


def datetime_to_filetime(dt: datetime) -> int:
    """Convert a timezone-aware datetime to a raw FILETIME integer."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    delta = dt.astimezone(timezone.utc) - _EPOCH
    seconds = delta.days * 86400 + delta.seconds
    return seconds * _HUNDREDS_OF_NS + delta.microseconds * 10


def subsecond_is_zero(ft: int) -> bool:
    """True when a FILETIME has all sub-second precision zeroed.

    Many timestomping tools write times at whole-second (or coarser)
    resolution, leaving the sub-second component as exactly zero. Genuine
    filesystem activity almost never does.
    """
    if ft <= 0:
        return False
    return (ft % _HUNDREDS_OF_NS) == 0
