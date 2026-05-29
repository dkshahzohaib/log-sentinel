"""Generate console, HTML, JSON, PDF, and help artifacts for scan results."""

from __future__ import annotations

import json
import socket
import textwrap
from datetime import datetime
from html import escape
from pathlib import Path

from .analyzer import Finding, SEVERITY_ORDER
from .collector import LogEvent


SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High": "#e67e22",
    "Medium": "#f1c40f",
    "Low": "#3498db",
    "Info": "#95a5a6",
}

SEVERITY_ICONS = {
    "Critical": "[!!!]",
    "High": "[!! ]",
    "Medium": "[ ! ]",
    "Low": "[ . ]",
    "Info": "[   ]",
}


def print_summary(findings: list[Finding], events: list[LogEvent]) -> None:
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print("\n" + "=" * 60)
    print("  LOG SENTINEL - ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"  Host     : {socket.gethostname()}")
    print(f"  Analysed : {len(events)} events")
    print(f"  Findings : {len(findings)} total")
    print()
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        n = counts.get(sev, 0)
        icon = SEVERITY_ICONS[sev]
        bar = "#" * min(n, 40)
        print(f"  {icon}  {sev:<10} {n:>4}  {bar}")
    print("=" * 60)

    if findings:
        print("\n  Top findings:")
        for f in findings[:10]:
            icon = SEVERITY_ICONS.get(f.severity, "")
            print(f"  {icon} [{f.severity}] {f.title}")
    else:
        print("\n  No suspicious activity detected.")
    print()


def _badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#999")
    return (
        f'<span class="badge" style="background:{color};">'
        f"{escape(severity)}</span>"
    )


def _finding_html(f: Finding, idx: int) -> str:
    color = SEVERITY_COLORS.get(f.severity, "#999")
    ts = f.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    event_rows = ""
    for e in f.events[:5]:
        row_ts = e.timestamp.strftime("%H:%M:%S")
        event_rows += (
            f"<tr><td>{row_ts}</td><td>{escape(e.channel)}</td>"
            f"<td>{e.event_id}</td><td>{escape(e.user or '-')}</td>"
            f'<td class="break">{escape(e.message[:200])}</td></tr>'
        )

    more = ""
    if len(f.events) > 5:
        more = f'<p class="muted">... and {len(f.events) - 5} more events</p>'

    details = ""
    if event_rows:
        details = f"""
<details>
  <summary>Show {len(f.events)} related event(s)</summary>
  <table>
    <thead><tr><th>Time</th><th>Channel</th><th>ID</th><th>User</th><th>Detail</th></tr></thead>
    <tbody>{event_rows}</tbody>
  </table>
  {more}
</details>"""

    return f"""
<div class="finding" data-sev="{escape(f.severity)}" style="border-left-color:{color};">
  <div class="finding-head">
    <span class="num">#{idx}</span>
    {_badge(f.severity)}
    <strong>{escape(f.title)}</strong>
    <span class="time">{ts}</span>
  </div>
  <p>{escape(f.description)}</p>
  {details}
</div>"""


def generate_html(
    findings: list[Finding],
    events: list[LogEvent],
    output_path: str,
    hours_back: int = 24,
    health_score=None,
) -> None:
    output = Path(output_path)
    help_path = ensure_help_center(output.parent)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    host = socket.gethostname()

    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    stat_cards = ""
    for sev, color in SEVERITY_COLORS.items():
        n = counts.get(sev, 0)
        stat_cards += f"""
<div class="stat" style="background:{color};">
  <div class="stat-num">{n}</div>
  <div>{sev}</div>
</div>"""

    filter_btns = '<button onclick="filterAll()" class="fbtn active" data-sev="ALL">All</button>'
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        color = SEVERITY_COLORS[sev]
        n = counts.get(sev, 0)
        filter_btns += (
            f'<button onclick="filterSev(\'{sev}\')" class="fbtn" '
            f'data-sev="{sev}" style="border-color:{color};color:{color};">'
            f"{sev} ({n})</button>"
        )

    finding_html = "".join(_finding_html(f, i) for i, f in enumerate(findings, 1))
    if not finding_html:
        finding_html = '<p class="good">No suspicious activity detected in the analysed window.</p>'

    channel_counts: dict[str, int] = {}
    for e in events:
        channel_counts[e.channel] = channel_counts.get(e.channel, 0) + 1
    breakdown = " | ".join(f"{escape(ch)}: <strong>{n}</strong>" for ch, n in sorted(channel_counts.items()))

    health_block = ""
    if health_score:
        health_block = f"""
<section class="section health">
  <div class="gauge" style="border-color:{health_score.color};">
    <div class="score" style="color:{health_score.color};">{health_score.score}</div>
    <div>Grade {escape(health_score.grade)}</div>
  </div>
  <div>
    <div class="eyebrow">PC HEALTH</div>
    <h2 style="color:{health_score.color};">{escape(health_score.verdict)}</h2>
    <p>{escape(health_score.detail)}</p>
  </div>
</section>"""

    pdf_name = output.with_suffix(".pdf").name
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log Sentinel Report - {escape(host)}</title>
<style>
*{{box-sizing:border-box}}body{{font-family:Segoe UI,Arial,sans-serif;background:#f0f2f5;color:#333;margin:0;line-height:1.5}}
.header{{background:#111827;color:#fff;padding:30px 44px}}.header h1{{margin:0 0 8px;font-size:28px}}.meta,.muted{{color:#6b7280;font-size:14px}}.header .meta{{color:#cbd5e1}}
.actions{{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}}.action{{background:#ed7700;color:#fff;border:0;border-radius:6px;padding:10px 14px;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}}.action.secondary{{background:#374151}}
.container{{max-width:1100px;margin:0 auto;padding:30px 24px}}.section{{background:#fff;border-radius:10px;padding:24px 28px;margin-bottom:22px;box-shadow:0 2px 8px #00000012}}.section h2{{margin:0 0 14px;color:#111827}}
.health{{display:grid;grid-template-columns:190px 1fr;gap:28px;align-items:center}}.gauge{{width:170px;height:170px;border:12px solid;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-direction:column}}.score{{font-size:44px;font-weight:800;line-height:1}}.eyebrow{{font-size:12px;font-weight:800;color:#6b7280;letter-spacing:1.4px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}}.stat{{color:#fff;border-radius:8px;padding:16px 24px;min-width:105px;text-align:center}}.stat-num{{font-size:30px;font-weight:800}}
.plain-help{{background:#fff7e8;border-left:4px solid #ed7700;padding:14px;border-radius:6px;margin-top:16px;color:#46320f}}
.fbtn{{border:2px solid #999;background:#fff;color:#777;padding:7px 14px;border-radius:20px;cursor:pointer;font-size:13px;margin:2px;font-weight:700}}.fbtn.active,.fbtn:hover{{background:#111827!important;border-color:#111827!important;color:#fff!important}}
.finding{{margin:16px 0;padding:14px 16px;background:#fff;border-radius:6px;border-left:4px solid;box-shadow:0 1px 3px #00000014}}.finding-head{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}.badge{{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:800}}.num,.time{{color:#6b7280;font-size:13px}}.time{{margin-left:auto}}.break{{word-break:break-all;font-size:13px}}table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}}th,td{{padding:5px 8px;border-bottom:1px solid #e5e7eb;text-align:left}}thead{{background:#f9fafb}}summary{{cursor:pointer;color:#374151;font-weight:700}}.good{{text-align:center;color:#15803d;font-size:18px}}
@media print{{body{{background:#fff}}.header{{background:#111827!important;color:#fff!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}.section{{box-shadow:none;border:1px solid #ddd;page-break-inside:avoid}}.actions,.fbtn,button{{display:none!important}}}}
</style>
</head>
<body>
<header class="header">
  <h1>Log Sentinel Security Report</h1>
  <div class="meta">Host: <strong>{escape(host)}</strong> | Generated: <strong>{now}</strong> | Window: last <strong>{hours_back}h</strong></div>
  <div class="actions">
    <button class="action" onclick="window.print()">Download / Save as PDF</button>
    <a class="action secondary" href="{escape(help_path.name)}">Search Help</a>
    <a class="action secondary" href="{escape(pdf_name)}">Open PDF Copy</a>
  </div>
</header>
<main class="container">
  {health_block}
  <section class="section">
    <h2>Overview</h2>
    <div class="cards">{stat_cards}</div>
    <p class="meta">Events analysed: <strong>{len(events)}</strong> {breakdown}</p>
    <div class="plain-help"><strong>Where is my report?</strong> This browser report is the easy-to-read version. A PDF copy named <strong>{escape(pdf_name)}</strong> is saved in the same folder. Use <strong>Search Help</strong> if you do not know what a feature or alert means.</div>
  </section>
  <section class="section">
    <h2>Findings ({len(findings)})</h2>
    <div>{filter_btns}</div>
    <div id="findings-list">{finding_html}</div>
  </section>
  <p class="muted" style="text-align:center">Generated by Log Sentinel. Keep this report private because it may contain usernames, hostnames, process names, and security details.</p>
</main>
<script>
function filterAll(){{
 document.querySelectorAll('.finding').forEach(el=>el.style.display='');
 document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));
 document.querySelector('[data-sev="ALL"]').classList.add('active');
}}
function filterSev(sev){{
 document.querySelectorAll('.finding').forEach(el=>{{el.style.display=el.dataset.sev===sev?'':'none';}});
 document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));
 document.querySelector('[data-sev="'+sev+'"]').classList.add('active');
}}
</script>
</body>
</html>"""
    output.write_text(html, encoding="utf-8")
    try:
        (output.parent / "latest_report.html").write_text(html, encoding="utf-8")
    except OSError:
        pass
    print(f"[+] HTML report saved: {output_path}")


def generate_json(findings: list[Finding], output_path: str) -> None:
    data = [
        {
            "rule": f.rule,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "timestamp": f.timestamp.isoformat(),
            "event_count": len(f.events),
        }
        for f in findings
    ]
    Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] JSON report saved: {output_path}")


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_lines(findings: list[Finding], events: list[LogEvent], hours_back: int, health_score=None) -> list[str]:
    lines = [
        "Log Sentinel Security Report",
        f"Host: {socket.gethostname()}",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Window: last {hours_back}h",
        f"Events analysed: {len(events)}",
        f"Findings: {len(findings)}",
        "",
    ]
    if health_score:
        lines.extend([
            f"Health score: {health_score.score} / 100, Grade {health_score.grade}",
            health_score.verdict,
            "",
        ])
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines.append("Severity summary:")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        lines.append(f"- {sev}: {counts.get(sev, 0)}")
    lines.extend(["", "Plain-English next steps:"])
    if counts.get("Critical", 0):
        lines.append("- Critical means stop and investigate now. Do not ignore it.")
    if counts.get("High", 0):
        lines.append("- High means fix soon. Check whether you recognize the activity.")
    lines.append("- If unsure, disconnect from the internet and ask for help.")
    lines.extend(["", "Findings:"])
    if not findings:
        lines.append("No suspicious activity detected in the analysed window.")
    for i, f in enumerate(findings, 1):
        lines.append(f"{i}. [{f.severity}] {f.title}")
        for wrapped in textwrap.wrap(f.description.replace("\n", " "), width=92):
            lines.append(f"   {wrapped}")
        lines.append("")
    return lines


def generate_pdf(
    findings: list[Finding],
    events: list[LogEvent],
    output_path: str,
    hours_back: int = 24,
    health_score=None,
) -> None:
    """Generate a simple dependency-free PDF summary."""
    lines = _pdf_lines(findings, events, hours_back, health_score)
    pages = [lines[i:i + 46] for i in range(0, len(lines), 46)] or [[]]
    objects: list[str] = []

    def add_obj(body: str) -> int:
        objects.append(body)
        return len(objects)

    font_id = add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: list[int] = []
    for page_lines in pages:
        content = ["BT", "/F1 10 Tf", "50 760 Td", "14 TL"]
        for line in page_lines:
            content.append(f"({_pdf_escape(line[:110])}) Tj")
            content.append("T*")
        content.append("ET")
        stream = "\n".join(content)
        content_id = add_obj(f"<< /Length {len(stream.encode('latin-1', errors='replace'))} >>\nstream\n{stream}\nendstream")
        page_id = add_obj(
            f"<< /Type /Page /Parent 0 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
        )
        page_ids.append(page_id)

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    pages_id = add_obj(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>")
    for pid in page_ids:
        objects[pid - 1] = objects[pid - 1].replace("/Parent 0 0 R", f"/Parent {pages_id} 0 R")
    catalog_id = add_obj(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

    chunks = ["%PDF-1.4\n"]
    offsets = [0]
    for idx, body in enumerate(objects, 1):
        offsets.append(sum(len(c.encode("latin-1", errors="replace")) for c in chunks))
        chunks.append(f"{idx} 0 obj\n{body}\nendobj\n")
    xref_offset = sum(len(c.encode("latin-1", errors="replace")) for c in chunks)
    chunks.append(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n")
    for off in offsets[1:]:
        chunks.append(f"{off:010d} 00000 n \n")
    chunks.append(f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n")
    Path(output_path).write_bytes("".join(chunks).encode("latin-1", errors="replace"))
    print(f"[+] PDF report saved: {output_path}")


def ensure_help_center(output_dir: str | Path = "reports") -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "help.html"
    html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Log Sentinel Help</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f5f6f8;color:#20242a;margin:0;line-height:1.55}
header{background:#111827;color:#fff;padding:28px 40px}main{max-width:980px;margin:0 auto;padding:26px}
input{width:100%;padding:14px 16px;border:2px solid #d1d5db;border-radius:8px;font-size:16px;margin:16px 0 22px}
.card{background:#fff;border-radius:8px;padding:18px 20px;margin:14px 0;border-left:4px solid #ed7700;box-shadow:0 1px 4px #0001}
.tag{display:inline-block;background:#eef2ff;color:#3730a3;padding:2px 8px;border-radius:99px;font-size:12px;font-weight:700}
h2{margin:8px 0;color:#111827}.hide{display:none}.simple{color:#4b5563}
</style></head><body>
<header><h1>Log Sentinel Help</h1><p>Search a feature. Written for normal people, not security specialists.</p></header>
<main>
<input id="search" placeholder="Search: report, PDF, panic, firewall, password, health score, baseline...">
<section class="card" data-keys="report pdf export browser download save"><span class="tag">Reports</span><h2>Where do I find my report?</h2><p class="simple">When you export a report, Log Sentinel saves an HTML report and a PDF copy in the location you choose. The browser opens the HTML version because it is easy to read. The PDF is for sending to someone else.</p></section>
<section class="card" data-keys="critical high danger alert finding"><span class="tag">Alerts</span><h2>What does Critical mean?</h2><p class="simple">Critical means look now. It does not always mean you are hacked, but it means the signal is serious enough that you should check it before banking, typing passwords, or working with sensitive files.</p></section>
<section class="card" data-keys="health score grade a b c d f"><span class="tag">Health Score</span><h2>What is the health score?</h2><p class="simple">It is a 0-100 score. Critical findings remove more points than Low findings. Start with Critical and High, then clean up Medium and Low later.</p></section>
<section class="card" data-keys="panic ransomware disconnect network isolate"><span class="tag">Panic</span><h2>When should I use Panic?</h2><p class="simple">Use Panic if you think something is actively spreading, stealing data, or controlling your PC. It turns off network adapters so the machine cannot talk out or spread.</p></section>
<section class="card" data-keys="firewall block ip website domain hosts"><span class="tag">Firewall</span><h2>How does blocking work?</h2><p class="simple">IP and port blocking uses Windows Firewall. Website blocking edits the Windows hosts file. Changes are recorded in the local change log.</p></section>
<section class="card" data-keys="baseline changed new autorun service task listener"><span class="tag">Baseline</span><h2>What means new since last baseline?</h2><p class="simple">The first scan learns what normal looks like. Later scans compare against that. New startup items, services, scheduled tasks, or listening ports are worth checking.</p></section>
<section class="card" data-keys="password strength checker store vault"><span class="tag">Passwords</span><h2>Does Log Sentinel store passwords?</h2><p class="simple">No. The password checker should inspect strength and forget the password. Storing passwords would turn this into a vault, which is a different and riskier product.</p></section>
<section class="card" data-keys="fake virus eicar test lab malware"><span class="tag">Testing</span><h2>What is the fake malware lab?</h2><p class="simple">It contains harmless text files that look suspicious to the scanner. They are for testing alerts safely. They are not real malware.</p></section>
</main>
<script>
const q=document.getElementById('search');
q.addEventListener('input',()=>{const s=q.value.toLowerCase();document.querySelectorAll('.card').forEach(c=>{const hay=(c.innerText+' '+c.dataset.keys).toLowerCase();c.classList.toggle('hide',s&&!hay.includes(s));});});
</script></body></html>"""
    path.write_text(html, encoding="utf-8")
    return path
