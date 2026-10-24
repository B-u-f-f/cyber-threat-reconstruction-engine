"""Self-contained HTML report generator.

Produces a single static HTML file (no external assets, no scripts fetched
from the network) summarising timestomping findings, exfil correlations and
the unified timeline. All dynamic values are HTML-escaped because they derive
from untrusted evidence.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .correlate import Correlation, TimelineEvent
from .timestomp import Finding

_SEV_COLOR = {"high": "#c0392b", "medium": "#e67e22",
              "low": "#f1c40f", "info": "#3498db"}
_SRC_COLOR = {"usnjrnl": "#2980b9", "mft": "#8e44ad",
              "network": "#16a085", "dns": "#27ae60"}


def _esc(value) -> str:
    return html.escape(str(value))


def _findings_section(findings: list[Finding]) -> str:
    if not findings:
        return "<p class='ok'>No timestomping indicators detected.</p>"
    rows = []
    for f in findings:
        color = _SEV_COLOR.get(f.severity, "#777")
        detail = ", ".join(f"{k}={v}" for k, v in f.detail.items())
        rows.append(
            f"<tr>"
            f"<td><span class='badge' style='background:{color}'>"
            f"{_esc(f.severity.upper())}</span></td>"
            f"<td>{_esc(f.name)}</td>"
            f"<td><code>{_esc(f.rule)}</code></td>"
            f"<td>{_esc(f.explanation)}<br><small>{_esc(detail)}</small></td>"
            f"</tr>"
        )
    return (
        "<table><thead><tr><th>Severity</th><th>File</th><th>Rule</th>"
        "<th>Explanation</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
    )


def _correlations_section(correlations: list[Correlation]) -> str:
    if not correlations:
        return "<p class='ok'>No network/disk exfil correlations found.</p>"
    rows = []
    for c in correlations:
        rows.append(
            f"<tr><td>{_esc(c.timestamp)}</td>"
            f"<td>{_esc(c.summary)}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Time (UTC)</th><th>Correlation</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
    )


def _timeline_section(events: list[TimelineEvent]) -> str:
    rows = []
    for ev in events:
        color = _SRC_COLOR.get(ev.source, "#777")
        rows.append(
            f"<tr data-source='{_esc(ev.source)}'>"
            f"<td>{_esc(ev.timestamp)}</td>"
            f"<td><span class='tag' style='background:{color}'>"
            f"{_esc(ev.source)}</span></td>"
            f"<td>{_esc(ev.summary)}</td></tr>"
        )
    filters = "".join(
        f"<label><input type='checkbox' checked data-src='{s}'> {s}</label> "
        for s in _SRC_COLOR
    )
    script = """
<script>
document.querySelectorAll('.filters input').forEach(cb => {
  cb.addEventListener('change', () => {
    const src = cb.dataset.src;
    const show = cb.checked;
    document.querySelectorAll('tr[data-source="' + src + '"]').forEach(r => {
      r.style.display = show ? '' : 'none';
    });
  });
});
</script>
"""
    return (
        f"<div class='filters'>Filter: {filters}</div>"
        "<table><thead><tr><th>Time (UTC)</th><th>Source</th>"
        "<th>Event</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>" + script
    )


def render_report(
    findings: list[Finding],
    correlations: list[Correlation],
    timeline: list[TimelineEvent],
    sources: dict[str, str],
) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    src_rows = "".join(
        f"<li><b>{_esc(k)}</b>: {_esc(v)}</li>" for k, v in sources.items()
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTRE Threat Reconstruction Report</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font-family: system-ui, sans-serif; margin: 0; padding: 2rem;
        line-height: 1.5; max-width: 1100px; margin: 0 auto; }}
 h1 {{ border-bottom: 3px solid #16a085; padding-bottom: .3rem; }}
 h2 {{ margin-top: 2.5rem; border-left: 4px solid #16a085; padding-left: .6rem; }}
 table {{ border-collapse: collapse; width: 100%; margin-top: 1rem;
          font-size: .92rem; }}
 th, td {{ border: 1px solid #ccc; padding: .5rem .6rem; text-align: left;
           vertical-align: top; }}
 th {{ background: rgba(22,160,133,.12); }}
 code {{ background: rgba(127,127,127,.18); padding: 0 .3rem; border-radius: 3px; }}
 .badge, .tag {{ color: #fff; padding: .1rem .5rem; border-radius: 10px;
                 font-size: .78rem; white-space: nowrap; }}
 .ok {{ color: #16a085; font-weight: 600; }}
 .filters {{ margin-top: 1rem; font-size: .9rem; }}
 .filters label {{ margin-right: .4rem; }}
 .meta {{ background: rgba(127,127,127,.1); padding: 1rem; border-radius: 6px; }}
 footer {{ margin-top: 3rem; font-size: .8rem; color: #888; }}
</style></head><body>
<h1>Cyber Threat Reconstruction Report</h1>
<div class="meta">
 <p>Generated: {generated}</p>
 <p>Mode: offline, read-only. No TLS secrets were extracted and no network
    traffic was decrypted; network findings use capture metadata only.</p>
 <ul>{src_rows}</ul>
</div>

<h2>1. Timestomping findings ({len(findings)})</h2>
{_findings_section(findings)}

<h2>2. Network / disk correlations ({len(correlations)})</h2>
{_correlations_section(correlations)}

<h2>3. Unified timeline ({len(timeline)} events)</h2>
{_timeline_section(timeline)}

<footer>Generated by CTRE {_esc(sources.get('engine_version', ''))}.
 All values escaped; report is static and offline.</footer>
</body></html>"""


def write_report(path: str, **kwargs) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_report(**kwargs))
