"""Cyber Threat Reconstruction Engine (CTRE).

An offline, read-only DFIR correlation toolkit.

Scope note: CTRE intentionally does NOT extract TLS session secrets from
memory dumps and does NOT decrypt captured network traffic. It operates only
on metadata that is already visible in a capture (hosts, ports, timing, byte
volumes, DNS queries, TLS SNI) and on NTFS filesystem artifacts ($MFT and
$UsnJrnl). All inputs are treated as untrusted evidence and opened read-only.
"""

__version__ = "0.1.0"
