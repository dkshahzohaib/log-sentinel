"""
Modern Log Sentinel web UI.

This keeps the existing Python collectors and detection engine, but serves a
fast local browser interface instead of building the main experience with
thousands of Tk widgets.
"""

from __future__ import annotations

import json
import socket
import threading
import webbrowser
from dataclasses import asdict, is_dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from src.analyzer import SEVERITY_ORDER
from src.collector import collect as collect_events
from src.detection_pipeline import run_detection
from src.health_score import calculate as calc_health
from src.plain_english import explain
from src.reporter import generate_html, generate_json, generate_pdf
from src.system_collector import (
    collect_autoruns,
    collect_dns_cache,
    collect_installed_software,
    collect_network,
    collect_processes,
    collect_recent_files,
    collect_scheduled_tasks,
    collect_services,
    collect_system_info,
    collect_usb_history,
)
from src import demo_data, system_monitor as sysmon


APP_DIR = Path(__file__).resolve().parent
REPORT_DIR = APP_DIR / "reports"


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    return str(value)


class ModernState:
    def __init__(self):
        self.lock = threading.RLock()
        self.scanning = False
        self.status = "Ready"
        self.error = ""
        self.hours = 24
        self.last_scan = ""
        self.events = []
        self.findings = []
        self.processes = []
        self.connections = []
        self.services = []
        self.tasks = []
        self.autoruns = []
        self.dns_entries = []
        self.usb_devices = []
        self.software = []
        self.recent_files = []
        self.system_info = None

    def set_status(self, message: str):
        with self.lock:
            self.status = message

    def snapshot(self) -> dict:
        with self.lock:
            findings = list(self.findings)
            events = list(self.events)
            processes = list(self.processes)
            connections = list(self.connections)
            services = list(self.services)
            tasks = list(self.tasks)
            autoruns = list(self.autoruns)
            dns_entries = list(self.dns_entries)
            usb_devices = list(self.usb_devices)
            software = list(self.software)
            recent_files = list(self.recent_files)
            system_info = self.system_info
            scanning = self.scanning
            status = self.status
            error = self.error
            last_scan = self.last_scan
            hours = self.hours

        counts = {sev: 0 for sev in ["Critical", "High", "Medium", "Low", "Info"]}
        category_counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
            cat = explain(finding.rule).user_category
            category_counts[cat] = category_counts.get(cat, 0) + 1
        health = calc_health(findings)
        mem = sysmon.get_memory()
        disks = sysmon.get_disks()
        battery = sysmon.get_battery()
        primary_disk = next((d for d in disks if d.drive.upper().startswith("C:")),
                            disks[0] if disks else None)
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            local_ip = ""

        top_findings = []
        for finding in findings[:80]:
            pe = explain(finding.rule)
            top_findings.append({
                "rule": finding.rule,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description,
                "category": pe.user_category,
                "problem": pe.problem,
                "why": pe.why_matters,
                "action": pe.what_to_do,
                "timestamp": getattr(finding, "timestamp", datetime.utcnow()).isoformat(),
            })

        return {
            "scanning": scanning,
            "status": status,
            "error": error,
            "hours": hours,
            "last_scan": last_scan,
            "counts": counts,
            "health": asdict(health),
            "categoryCounts": category_counts,
            "findings": top_findings,
            "events": [_event_to_dict(e) for e in events[:250]],
            "processes": [_obj_to_dict(p) for p in processes[:250]],
            "connections": [_obj_to_dict(c) for c in connections[:250]],
            "services": [_obj_to_dict(s) for s in services[:250]],
            "tasks": [_obj_to_dict(t) for t in tasks[:250]],
            "autoruns": [_obj_to_dict(a) for a in autoruns[:250]],
            "dns": [_obj_to_dict(d) for d in dns_entries[:250]],
            "usb": [_obj_to_dict(u) for u in usb_devices[:250]],
            "software": [_obj_to_dict(s) for s in software[:250]],
            "recentFiles": [_obj_to_dict(r) for r in recent_files[:250]],
            "system": _obj_to_dict(system_info) if system_info else {},
            "live": {
                "memory": _obj_to_dict(mem),
                "disk": _obj_to_dict(primary_disk) if primary_disk else {},
                "battery": _obj_to_dict(battery),
                "localIp": local_ip,
            },
            "totals": {
                "logs": len(events),
                "processes": len(processes),
                "connections": len(connections),
                "services": len(services),
                "tasks": len(tasks),
                "autoruns": len(autoruns),
            },
        }

    def start_scan(self, hours: int = 24) -> bool:
        with self.lock:
            if self.scanning:
                return False
            self.scanning = True
            self.error = ""
            self.hours = hours
            self.status = "Starting scan..."
        threading.Thread(target=self._scan_worker, args=(hours,), daemon=True).start()
        return True

    def load_demo(self):
        with self.lock:
            self.system_info = demo_data.synthetic_system_info()
            self.processes = demo_data.synthetic_processes()
            self.connections = demo_data.synthetic_connections()
            self.services = demo_data.synthetic_services()
            self.tasks = demo_data.synthetic_tasks()
            self.autoruns = demo_data.synthetic_autoruns()
            self.dns_entries = demo_data.synthetic_dns()
            self.usb_devices = demo_data.synthetic_usb()
            self.software = demo_data.synthetic_software()
            self.recent_files = demo_data.synthetic_recent_files()
            self.events = demo_data.synthetic_events()
            self.findings = sorted(
                demo_data.synthetic_findings(),
                key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
                reverse=True,
            )
            self.last_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.status = "Demo data loaded"
            self.error = ""
            self.scanning = False

    def export_report(self, kind: str) -> Path:
        REPORT_DIR.mkdir(exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        with self.lock:
            findings = list(self.findings)
            events = list(self.events)
            hours = self.hours
        health = calc_health(findings)
        if kind == "pdf":
            path = REPORT_DIR / f"log-sentinel-report-{stamp}.pdf"
            generate_pdf(findings, events, str(path), hours_back=hours, health_score=health)
        elif kind == "json":
            path = REPORT_DIR / f"log-sentinel-report-{stamp}.json"
            generate_json(findings, str(path))
        else:
            path = REPORT_DIR / f"log-sentinel-report-{stamp}.html"
            generate_html(findings, events, str(path), hours_back=hours, health_score=health)
        return path

    def _scan_worker(self, hours: int):
        try:
            self.set_status("Collecting system information")
            system_info = collect_system_info()
            self.set_status("Collecting processes")
            processes = collect_processes()
            self.set_status("Collecting network connections")
            connections = collect_network()
            self.set_status("Collecting services")
            services = collect_services()
            self.set_status("Collecting scheduled tasks")
            tasks = collect_scheduled_tasks()
            self.set_status("Collecting autoruns")
            autoruns = collect_autoruns()
            self.set_status("Collecting DNS cache")
            dns_entries = collect_dns_cache()
            self.set_status("Collecting USB history")
            usb_devices = collect_usb_history()
            self.set_status("Collecting installed software")
            software = collect_installed_software()
            self.set_status("Collecting recent files")
            recent_files = collect_recent_files()
            self.set_status(f"Collecting Windows logs, last {hours}h")
            events = collect_events(hours_back=hours)
            self.set_status("Running detection rules")
            findings = run_detection(
                events=events,
                processes=processes,
                connections=connections,
                autoruns=autoruns,
                services=services,
                tasks=tasks,
            )
            with self.lock:
                self.system_info = system_info
                self.processes = processes
                self.connections = connections
                self.services = services
                self.tasks = tasks
                self.autoruns = autoruns
                self.dns_entries = dns_entries
                self.usb_devices = usb_devices
                self.software = software
                self.recent_files = recent_files
                self.events = events
                self.findings = findings
                self.last_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.status = f"Scan complete: {len(events)} logs, {len(findings)} findings"
        except Exception as exc:
            with self.lock:
                self.error = str(exc)
                self.status = "Scan failed"
        finally:
            with self.lock:
                self.scanning = False


def _obj_to_dict(value) -> dict:
    if value is None:
        return {}
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return value
    return {
        key: getattr(value, key)
        for key in dir(value)
        if not key.startswith("_") and not callable(getattr(value, key))
    }


def _event_to_dict(event) -> dict:
    return {
        "timestamp": event.timestamp.isoformat(),
        "channel": event.channel,
        "event_id": event.event_id,
        "source": event.source,
        "user": event.user,
        "message": event.message[:600],
    }


STATE = ModernState()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(INDEX_HTML)
        elif parsed.path == "/api/state":
            self._send_json(STATE.snapshot())
        elif parsed.path.startswith("/api/report/"):
            kind = parsed.path.rsplit("/", 1)[-1]
            try:
                path = STATE.export_report(kind)
                self._send_json({"ok": True, "path": str(path), "name": path.name})
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
        else:
            self._send_json({"error": "Not found"}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/api/scan":
            hours = int(qs.get("hours", ["24"])[0] or 24)
            started = STATE.start_scan(hours)
            self._send_json({"started": started})
        elif parsed.path == "/api/demo":
            STATE.load_demo()
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "Not found"}, status=404)

    def log_message(self, _fmt, *_args):
        return

    def _send_json(self, data, status: int = 200):
        raw = json.dumps(data, default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, html: str):
        raw = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log Sentinel Modern</title>
<style>
:root{--bg:#07111d;--panel:#0d1b2a;--card:#10243a;--line:#203d5a;--text:#eff7ff;--muted:#93a9bd;--blue:#2f91ff;--green:#5bd36a;--red:#ff4757;--orange:#ff9f1a;--yellow:#f6d743;--purple:#a875ff}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font-family:Segoe UI,Inter,Arial,sans-serif;font-size:14px} button,input,select{font:inherit}
.app{display:grid;grid-template-columns:240px 1fr;min-height:100vh}.side{background:#06101b;border-right:1px solid var(--line);padding:22px 16px;position:sticky;top:0;height:100vh}.brand{display:flex;gap:12px;align-items:center;margin-bottom:24px}.logo{width:48px;height:48px;border:2px solid #73b8ff;border-radius:12px;display:grid;place-items:center;color:#73b8ff;font-weight:800}.brand h1{font-size:20px;margin:0}.brand p{margin:2px 0 0;color:var(--muted);font-size:12px}.nav button{width:100%;display:flex;align-items:center;gap:10px;padding:11px 12px;margin:3px 0;border:1px solid transparent;border-radius:8px;background:transparent;color:var(--muted);text-align:left;cursor:pointer}.nav button.active,.nav button:hover{background:#123252;color:var(--text);border-color:#244f78}.main{padding:22px;min-width:0}.top{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:18px}.top h2{margin:0;font-size:24px}.sub{color:var(--muted);margin-top:4px}.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{border:1px solid #2b557a;border-radius:8px;background:#13283d;color:var(--text);padding:10px 13px;cursor:pointer}.btn.primary{background:linear-gradient(135deg,#1464dc,#2f91ff);border-color:#2f91ff}.btn.danger{background:#7d1d28;border-color:#c73546}.btn:hover{filter:brightness(1.12)}.grid{display:grid;gap:12px}.metrics{grid-template-columns:repeat(4,minmax(160px,1fr));margin-bottom:14px}.card{background:linear-gradient(180deg,#10243a,#0d1d2f);border:1px solid var(--line);border-radius:8px;padding:16px;min-width:0}.metric .label{color:var(--muted);font-weight:700}.metric .value{font-size:30px;font-weight:800;margin-top:8px}.metric .detail{color:var(--muted);margin-top:4px}.layout{grid-template-columns:1.15fr 1fr 1fr}.layout2{grid-template-columns:1fr 1fr 1fr;margin-top:12px}.card h3{margin:0 0 12px;font-size:15px}.healthHero{display:grid;grid-template-columns:220px 1fr;gap:20px;align-items:center}.score{width:190px;height:190px;border-radius:50%;display:grid;place-items:center;border:18px solid #283f72;color:var(--text);font-size:46px;font-weight:900}.score small{display:block;font-size:13px;color:var(--muted);font-weight:600}.verdict{font-size:32px;font-weight:900;margin-bottom:8px}.chips{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.chip{border:1px solid var(--line);border-radius:8px;padding:14px;background:#0b1a2a}.chip strong{display:block;font-size:24px;margin-top:6px}.list{display:grid;gap:8px}.finding{border-left:4px solid var(--blue);background:#0b1a2a;border-radius:8px;padding:12px}.finding.Critical{border-color:var(--red)}.finding.High{border-color:var(--orange)}.finding.Medium{border-color:var(--yellow)}.finding .meta{color:var(--muted);font-size:12px;margin-top:4px}.tableWrap{overflow:auto;border:1px solid var(--line);border-radius:8px}table{width:100%;border-collapse:collapse;min-width:720px}th,td{padding:10px;border-bottom:1px solid #18324d;text-align:left;vertical-align:top}th{color:#9fc8ef;background:#0b1a2a;position:sticky;top:0}td{color:#dbeaff}.muted{color:var(--muted)}.bar{height:8px;background:#18324d;border-radius:99px;overflow:hidden}.bar span{display:block;height:100%;background:var(--blue)}.status{padding:9px 12px;border:1px solid var(--line);background:#0b1a2a;border-radius:8px;color:var(--muted)}.hidden{display:none!important}
@media(max-width:1100px){.app{grid-template-columns:78px 1fr}.brand h1,.brand p,.nav span{display:none}.side{padding:14px 10px}.metrics,.layout,.layout2{grid-template-columns:1fr 1fr}.healthHero{grid-template-columns:1fr}.chips{grid-template-columns:1fr 1fr}}
@media(max-width:760px){.metrics,.layout,.layout2,.chips{grid-template-columns:1fr}.main{padding:14px}.top{display:block}.actions{margin-top:12px}.score{width:150px;height:150px}.verdict{font-size:24px}}
</style>
</head>
<body>
<div class="app">
<aside class="side"><div class="brand"><div class="logo">LS</div><div><h1>Log Sentinel</h1><p>Modern SOC Console</p></div></div><nav class="nav" id="nav"></nav></aside>
<main class="main">
<div class="top"><div><h2 id="pageTitle">Dashboard</h2><div class="sub" id="status">Ready</div></div><div class="actions"><select class="btn" id="hours"><option>6</option><option selected>24</option><option>72</option><option>168</option></select><button class="btn primary" onclick="scan()">Run Scan</button><button class="btn" onclick="demo()">Demo Data</button><button class="btn" onclick="report('html')">HTML Report</button><button class="btn danger" onclick="report('pdf')">PDF</button></div></div>
<section id="dashboard" class="page"></section><section id="health" class="page hidden"></section><section id="findings" class="page hidden"></section><section id="logs" class="page hidden"></section><section id="system" class="page hidden"></section><section id="network" class="page hidden"></section><section id="processes" class="page hidden"></section><section id="persistence" class="page hidden"></section><section id="reports" class="page hidden"></section>
</main></div>
<script>
const tabs=[['dashboard','Dashboard'],['health','Health Check'],['findings','Findings'],['logs','Logs'],['system','System Info'],['network','Network'],['processes','Processes'],['persistence','Persistence'],['reports','Reports']];
let state={}, active='dashboard';
document.getElementById('nav').innerHTML=tabs.map(([id,name])=>`<button onclick="show('${id}')" id="nav-${id}"><b>${name[0]}</b><span>${name}</span></button>`).join('');
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
function show(id){active=id;document.querySelectorAll('.page').forEach(p=>p.classList.add('hidden'));document.getElementById(id).classList.remove('hidden');document.querySelectorAll('.nav button').forEach(b=>b.classList.remove('active'));document.getElementById('nav-'+id).classList.add('active');document.getElementById('pageTitle').textContent=tabs.find(t=>t[0]===id)[1];render()}
async function load(){state=await fetch('/api/state').then(r=>r.json());document.getElementById('status').textContent=state.status+(state.scanning?' ...':'');render()}
async function scan(){let h=document.getElementById('hours').value;await fetch('/api/scan?hours='+h,{method:'POST'});load()}
async function demo(){await fetch('/api/demo',{method:'POST'});load()}
async function report(kind){let r=await fetch('/api/report/'+kind).then(r=>r.json());alert(r.ok?'Saved: '+r.path:'Report failed: '+r.error)}
function metric(label,value,detail){return `<div class="card metric"><div class="label">${label}</div><div class="value">${value}</div><div class="detail">${detail||''}</div></div>`}
function render(){if(!state.health)return;renderDashboard();renderHealth();renderFindings();renderLogs();renderSystem();renderNetwork();renderProcesses();renderPersistence();renderReports()}
function renderDashboard(){let c=state.counts||{}, h=state.health||{}, live=state.live||{}, disk=live.disk||{}, mem=live.memory||{};document.getElementById('dashboard').innerHTML=`<div class="grid metrics">${metric('Total Findings',Object.values(c).reduce((a,b)=>a+b,0),`${c.Critical||0} Critical · ${c.High||0} High`)}${metric('System Health',(h.score??0)+' /100',esc(h.grade||''))}${metric('Logs Analyzed',state.totals?.logs||0,'Windows Event Logs')}${metric('Last Scan',state.last_scan||'Not scanned','')}</div><div class="grid layout"><div class="card"><h3>Severity Overview</h3>${severityHtml()}</div><div class="card"><h3>Top Categories</h3>${categoryHtml()}</div><div class="card"><h3>Recent Findings</h3>${findingList(state.findings?.slice(0,5)||[])}</div></div><div class="grid layout2"><div class="card"><h3>Live System</h3><p>RAM: ${mem.used_pct?.toFixed?mem.used_pct.toFixed(0):0}% used</p><p>Disk: ${disk.used_pct?.toFixed?disk.used_pct.toFixed(0):'--'}% used</p><p>Local IP: ${esc(live.localIp||'')}</p></div><div class="card"><h3>Quick Actions</h3><button class="btn primary" onclick="scan()">Run Scan</button> <button class="btn" onclick="show('findings')">View Findings</button></div><div class="card"><h3>Reports</h3><button class="btn" onclick="report('html')">HTML</button> <button class="btn" onclick="report('pdf')">PDF</button> <button class="btn" onclick="report('json')">JSON</button></div></div>`}
function renderHealth(){let h=state.health||{}, c=state.counts||{};document.getElementById('health').innerHTML=`<div class="card healthHero"><div class="score">${h.score??0}<small>${esc(h.grade||'')}</small></div><div><div class="verdict">${esc(h.verdict||'Run a scan')}</div><p class="muted">${esc(h.detail||'Run a scan to calculate health and recommended actions.')}</p><div class="actions"><button class="btn primary" onclick="scan()">Scan</button><button class="btn" onclick="show('findings')">Actions</button><button class="btn" onclick="report('pdf')">PDF Report</button></div></div></div><div class="chips" style="margin:14px 0">${['Critical','High','Medium','Low'].map(s=>`<div class="chip"><span>${s}</span><strong>${c[s]||0}</strong></div>`).join('')}</div><div class="card"><h3>Recommended Actions</h3>${findingList(state.findings||[])}</div>`}
function renderFindings(){document.getElementById('findings').innerHTML=`<div class="card"><h3>All Findings</h3>${findingList(state.findings||[])}</div>`}
function renderLogs(){document.getElementById('logs').innerHTML=table(state.events||[],['timestamp','channel','event_id','source','user','message'])}
function renderSystem(){let s=state.system||{}, live=state.live||{};document.getElementById('system').innerHTML=`<div class="grid layout"><div class="card"><h3>Computer</h3>${kv(s)}</div><div class="card"><h3>Live</h3>${kv(live.memory||{})}${kv(live.disk||{})}</div><div class="card"><h3>Battery</h3>${kv(live.battery||{})}</div></div><div class="card" style="margin-top:12px"><h3>Software</h3>${tableHtml(state.software||[],['name','version','publisher','install_date'])}</div>`}
function renderNetwork(){document.getElementById('network').innerHTML=table(state.connections||[],['local_addr','local_port','remote_addr','remote_port','state','process_name','pid'])}
function renderProcesses(){document.getElementById('processes').innerHTML=table(state.processes||[],['pid','name','user','path','cmdline'])}
function renderPersistence(){document.getElementById('persistence').innerHTML=`<div class="grid layout"><div class="card"><h3>Autoruns</h3>${tableHtml(state.autoruns||[],['name','command','location','user'])}</div><div class="card"><h3>Tasks</h3>${tableHtml(state.tasks||[],['name','state','task_path','action'])}</div><div class="card"><h3>Services</h3>${tableHtml(state.services||[],['name','display_name','state','start_mode'])}</div></div>`}
function renderReports(){document.getElementById('reports').innerHTML=`<div class="card"><h3>Export Reports</h3><p class="muted">Reports save into the project reports folder.</p><button class="btn" onclick="report('html')">Export HTML</button> <button class="btn danger" onclick="report('pdf')">Export PDF</button> <button class="btn" onclick="report('json')">Export JSON</button></div>`}
function severityHtml(){let c=state.counts||{}, total=Math.max(1,Object.values(c).reduce((a,b)=>a+b,0));return ['Critical','High','Medium','Low','Info'].map(s=>`<p>${s} <b>${c[s]||0}</b></p><div class="bar"><span style="width:${(c[s]||0)/total*100}%"></span></div>`).join('')}
function categoryHtml(){let cc=state.categoryCounts||{}, keys=Object.keys(cc);return keys.length?keys.map(k=>`<p>${esc(k)} <b>${cc[k]}</b></p>`).join(''):'<p class="muted">Run a scan to see categories.</p>'}
function findingList(items){return `<div class="list">${items.length?items.map(f=>`<div class="finding ${esc(f.severity)}"><b>${esc(f.title||f.problem)}</b><div class="meta">${esc(f.severity)} · ${esc(f.category)} · ${esc(f.timestamp||'')}</div><p>${esc(f.action||f.description||'')}</p></div>`).join(''):'<p class="muted">No findings yet.</p>'}</div>`}
function kv(o){return Object.entries(o||{}).slice(0,18).map(([k,v])=>`<p><b>${esc(k)}</b>: ${esc(typeof v==='object'?JSON.stringify(v):v)}</p>`).join('')||'<p class="muted">No data yet.</p>'}
function table(rows,cols){return `<div class="card">${tableHtml(rows,cols)}</div>`}
function tableHtml(rows,cols){return `<div class="tableWrap"><table><thead><tr>${cols.map(c=>`<th>${c}</th>`).join('')}</tr></thead><tbody>${(rows||[]).map(r=>`<tr>${cols.map(c=>`<td>${esc(r[c])}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`}
show('dashboard');load();setInterval(load, state.scanning?1200:4000);
</script>
</body></html>"""


def run(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True):
    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}"
    print(f"Log Sentinel Modern UI running at {url}")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    server.serve_forever()


if __name__ == "__main__":
    run()
