"""Compliance report / dashboard generator.

Produces a single self-contained HTML file (inline CSS, no assets) that
aggregates findings from every scan type, the policy violations, and an optional
GDPR erasure summary into a CISO-facing posture report. The HTML is print
-optimized, so "export to PDF" works via the browser or any HTML→PDF renderer;
`to_pdf()` wires WeasyPrint when it's installed.

A full interactive SPA (Next.js) is the productionization path; this static
report is the shareable, dependency-free artifact and the data contract the SPA
would consume.
"""

from __future__ import annotations

import html
import json
from typing import Optional

from vecshield.models import ScanJob, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO]
_SEV_COLOR = {
    Severity.CRITICAL: "#b3001b",
    Severity.HIGH: "#e8590c",
    Severity.MEDIUM: "#f08c00",
    Severity.LOW: "#1c7ed6",
    Severity.INFO: "#868e96",
}


def _esc(s) -> str:
    return html.escape(str(s))


def _scan_scope(job: ScanJob) -> tuple[str, str, str]:
    """What one scan checked, over which collection, and how much of it.

    Every scan of one store carries the same store name, so the check and the
    collection are what tell the rows of the Scans table apart.
    """
    stats = job.stats or {}
    check = str(stats.get("check") or "scan").replace("_", " ")
    collection = stats.get("collection")
    if not collection:
        # A store-wide scan records how many collections it covered.
        count = stats.get("collections")
        collection = (f"all {count} collections" if isinstance(count, int)
                      and not isinstance(count, bool) and count > 1 else "(store)")
    coverage = (stats.get("coverage") or {}).get("status") or "unknown"
    return check, str(collection), str(coverage)


def _collect_findings(jobs: list[ScanJob]) -> list:
    out = []
    for j in jobs:
        out.extend(j.findings)
    return out


def build_report(
    jobs: list[ScanJob],
    *,
    title: str = "VecShield Posture Report",
    violations: Optional[list] = None,
    erasure: Optional[object] = None,
    generated_at: str = "",
    assessment: Optional[dict] = None,
) -> str:
    findings = _collect_findings(jobs)
    violations = violations or []

    # severity summary
    sev_counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    # collection x severity heatmap
    collections = sorted({f.collection or "(store)" for f in findings})
    heat = {c: {s: 0 for s in _SEV_ORDER} for c in collections}
    for f in findings:
        heat[f.collection or "(store)"][f.severity] += 1

    parts: list[str] = []
    parts.append(_HEAD.replace("{{TITLE}}", _esc(title)))
    parts.append(f"<h1>{_esc(title)}</h1>")
    if generated_at:
        parts.append(f'<p class="muted">Generated {_esc(generated_at)}</p>')

    parts.append("<h2>Assessment scope and coverage</h2>")
    parts.append("<p>Findings describe observed technical signals. An absence of "
                 "findings does not establish regulatory compliance or prove that "
                 "untested data is free of sensitive content.</p>")
    if assessment:
        parts.append(f"<p>Audit <code>{_esc(assessment['id'])}</code> · "
                     f"observed {_esc(assessment.get('started_at', ''))} through "
                     f"{_esc(assessment.get('finished_at', ''))} · execution "
                     f"{_esc(assessment.get('status', 'unknown'))}</p>")
        parts.append("<details><summary>Frozen scope and configuration</summary><pre>"
                     + _esc(json.dumps(assessment.get("scope", {}), indent=2))
                     + "</pre></details>")
    outcomes = (assessment or {}).get("check_outcomes") or [
        outcome for job in jobs for outcome in job.stats.get("check_outcomes", [])
    ]
    if outcomes:
        parts.append("<table><tr><th>Check</th><th>Collection</th><th>Outcome</th>"
                     "<th>Coverage</th><th>Limitations</th></tr>")
        for outcome in outcomes:
            parts.append("<tr>" + "".join(f"<td>{_esc(value)}</td>" for value in (
                outcome.get("check", "unknown"), outcome.get("collection") or "(store)",
                outcome.get("outcome", "inconclusive"),
                outcome.get("coverage", {}).get("status", "unknown"),
                outcome.get("reason", ""),
            )) + "</tr>")
        parts.append("</table>")
    else:
        parts.append("<p>Coverage unknown: this snapshot has no structured check outcomes.</p>")

    # summary chips
    parts.append('<div class="chips">')
    for s in _SEV_ORDER:
        parts.append(
            f'<div class="chip" style="border-color:{_SEV_COLOR[s]}">'
            f'<span class="chip-n" style="color:{_SEV_COLOR[s]}">{sev_counts[s]}</span>'
            f'<span class="chip-l">{s.value.upper()}</span></div>'
        )
    parts.append("</div>")

    # scans covered
    parts.append("<h2>Scans</h2><table><tr><th>Scan</th><th>Collection</th>"
                 "<th>Store</th><th>Coverage</th><th>Findings</th>"
                 "<th>Top severity</th></tr>")
    for j in jobs:
        check, collection, coverage = _scan_scope(j)
        # A scan with no findings has no top severity; an INFO badge would
        # read as one informational finding.
        top = _sev_badge(j.max_severity) if j.findings else "-"
        parts.append(
            f"<tr><td>{_esc(check)}</td><td>{_esc(collection)}</td>"
            f"<td>{_esc(j.store)}</td><td>{_esc(coverage)}</td>"
            f"<td>{len(j.findings)}</td><td>{top}</td></tr>"
        )
    parts.append("</table>")

    # heatmap
    if collections:
        parts.append("<h2>Risk heatmap (collection × severity)</h2>")
        parts.append("<table class='heat'><tr><th>Collection</th>"
                     + "".join(f"<th>{s.value.upper()}</th>" for s in _SEV_ORDER)
                     + "</tr>")
        for c in collections:
            row = [f"<td class='name'>{_esc(c)}</td>"]
            for s in _SEV_ORDER:
                n = heat[c][s]
                bg = _SEV_COLOR[s] if n else "transparent"
                fg = "#fff" if n else "#555"
                row.append(f"<td style='background:{bg};color:{fg}'>{n or ''}</td>")
            parts.append("<tr>" + "".join(row) + "</tr>")
        parts.append("</table>")

    # policy violations
    if violations:
        parts.append("<h2>Policy violations</h2><table><tr><th>Severity</th>"
                     "<th>Policy</th><th>Action</th><th>Collection</th></tr>")
        for v in sorted(violations, key=lambda x: -x.severity.rank):
            parts.append(
                f"<tr><td>{_sev_badge(v.severity)}</td><td>{_esc(v.policy_id)}"
                f"<div class='muted'>{_esc(v.description)}</div></td>"
                f"<td><code>{_esc(v.action)}</code></td>"
                f"<td>{_esc(v.collection or '-')}</td></tr>"
            )
        parts.append("</table>")

    # findings
    suppressed_n = sum(1 for f in findings if (f.evidence or {}).get("suppressed"))
    heading = "<h2>Findings</h2>"
    if suppressed_n:
        heading += (f"<p class='muted'>{suppressed_n} finding(s) are allow-listed "
                    f"or suppressed; they remain listed below for the record but "
                    f"are excluded from alerts and gate decisions.</p>")
    parts.append(heading + "<table><tr><th>Severity</th><th>Category</th>"
                 "<th>Collection</th><th>Finding</th><th>Status</th></tr>")
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        ev = f.evidence or {}
        if ev.get("suppressed"):
            sup = ev.get("suppression") or {}
            reason = sup.get("reason") or ""
            status = ("<span class='muted'>suppressed</span>"
                      + (f"<div class='muted'>{_esc(reason)}</div>" if reason else ""))
        else:
            status = "-"
        parts.append(
            f"<tr><td>{_sev_badge(f.severity)}</td><td>{_esc(f.category)}</td>"
            f"<td>{_esc(f.collection or '-')}</td>"
            f"<td>{_esc(f.title)}<div class='muted'>{_esc(f.description)}</div></td>"
            f"<td>{status}</td>"
            f"</tr>"
        )
    parts.append("</table>")

    # erasure
    if erasure is not None:
        d = erasure.to_dict()
        parts.append("<h2>GDPR erasure impact</h2>")
        parts.append(f"<p>Discovery coverage: {_esc(d.get('coverage_status', 'unknown'))}. "
                     "Zero observed matches requires complete coverage before verification.</p>")
        parts.append(
            f"<p>Subject <code>{_esc(d['subject'])}</code>: "
            f"<b>{d['chunks_to_delete']}</b> chunk(s) to delete across "
            f"<b>{len(d['collections_affected'])}</b> collection(s); "
            f"reindex cost ≈ <b>{d['reindex_chunk_cost']}</b> chunks.</p>"
        )
        if d["collections_affected"]:
            parts.append("<table><tr><th>Collection</th><th>Chunks to delete</th></tr>")
            for c, n in sorted(d["collections_affected"].items()):
                parts.append(f"<tr><td>{_esc(c)}</td><td>{n}</td></tr>")
            parts.append("</table>")

    parts.append("</body></html>")
    return "\n".join(parts)


def build_audit_report(result, *, title: str = "VecShield Posture Report") -> str:
    """Render once at persistence time; later downloads reuse the stored bytes."""
    from datetime import datetime, timezone

    return build_report(result.jobs, title=title, violations=result.violations,
                        generated_at=datetime.now(timezone.utc).isoformat(),
                        assessment=result.to_dict())


def _sev_badge(s: Severity) -> str:
    return (f"<span class='badge' style='background:{_SEV_COLOR[s]}'>"
            f"{s.value.upper()}</span>")


def write_report(path: str, html_str: str) -> None:
    with open(path, "w") as f:
        f.write(html_str)


def to_pdf(html_str: str, path: str) -> None:
    """Render the HTML report to PDF via WeasyPrint, if available.

    WeasyPrint also needs native libs (pango/cairo); both a missing package and
    missing system libs surface here as a single friendly error. The HTML report
    is always print-to-PDF capable as a fallback.
    """
    try:
        from weasyprint import HTML  # type: ignore

        HTML(string=html_str).write_pdf(path)
    except Exception as e:  # ImportError or OSError (missing native libs)
        raise RuntimeError(
            "PDF export needs WeasyPrint and its native deps (pango/cairo). "
            "Install them, or open the HTML report and print to PDF."
        ) from e


_HEAD = """<!doctype html><html><head><meta charset="utf-8">
<title>{{TITLE}}</title>
<style>
 body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a;background:#fff}
 h1{margin-bottom:0}h2{margin-top:2rem;border-bottom:2px solid #eee;padding-bottom:.3rem}
 .muted{color:#777;font-size:.85em}
 table{border-collapse:collapse;width:100%;margin-top:.5rem;font-size:.9em}
 th,td{border:1px solid #e3e3e3;padding:.45rem .6rem;text-align:left;vertical-align:top}
 th{background:#f7f7f7}
 .chips{display:flex;gap:.75rem;margin-top:1rem}
 .chip{border:2px solid;border-radius:8px;padding:.5rem 1rem;text-align:center;min-width:70px}
 .chip-n{display:block;font-size:1.6rem;font-weight:700}
 .chip-l{font-size:.7rem;letter-spacing:.05em;color:#555}
 .badge{color:#fff;padding:.1rem .5rem;border-radius:4px;font-size:.75em;font-weight:600}
 .heat td{text-align:center;font-weight:600}.heat .name{text-align:left;font-weight:400}
 code{background:#f1f3f5;padding:.05rem .3rem;border-radius:3px}
 @media print{body{margin:.5rem}h2{page-break-after:avoid}tr{page-break-inside:avoid}}
</style></head><body>"""
