#!/usr/bin/env python3
import argparse, html, ipaddress, json, socket, subprocess, sys
from pathlib import Path
from urllib.parse import urlparse


def fail(msg):
    print(f"[VibeSec DAST] ERROR: {msg}", file=sys.stderr); raise SystemExit(2)


def validate_target(raw):
    p=urlparse(raw)
    if p.scheme not in {"http","https"} or not p.hostname or p.username or p.password: fail("Target must be an HTTP(S) URL without embedded credentials")
    try: answers=socket.getaddrinfo(p.hostname.rstrip('.'),p.port or (443 if p.scheme=='https' else 80),type=socket.SOCK_STREAM)
    except socket.gaierror as e: fail(f"Target hostname could not be resolved: {e}")
    for value in {x[4][0] for x in answers}:
        if not ipaddress.ip_address(value).is_global: fail(f"Target resolves to non-public address {value}")
    return raw


def run(cmd,path,timeout):
    try:
        with path.open('w',encoding='utf-8') as h: return subprocess.run(cmd,stdout=h,stderr=subprocess.STDOUT,text=True,check=False,timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        with path.open('a',encoding='utf-8') as h: h.write('\n[VibeSec] time budget reached\n')
        return 124


def jsonl(path):
    out=[]
    if not path.exists(): return out
    for line in path.read_text(errors='replace').splitlines():
        try:
            if line.lstrip().startswith('{'): out.append(json.loads(line))
        except json.JSONDecodeError: pass
    return out


def nuclei_findings(path):
    out=[]
    for x in jsonl(path):
        i=x.get('info') or {}; c=i.get('classification') or {}
        out.append({'engine':'Nuclei','name':i.get('name') or x.get('template-id') or 'Finding','severity':(i.get('severity') or 'unknown').lower(),'url':x.get('matched-at') or x.get('host'),'description':i.get('description'),'cve':c.get('cve-id'),'cwe':c.get('cwe-id')})
    return out


def zap_findings(path):
    if not path.exists(): return []
    try: data=json.loads(path.read_text(errors='replace'))
    except Exception: return []
    out=[]
    riskmap={'3':'high','2':'medium','1':'low','0':'info'}
    for site in data.get('site',[]):
        for a in site.get('alerts',[]):
            sev=riskmap.get(str(a.get('riskcode')),str(a.get('riskdesc','unknown')).split()[0].lower())
            inst=a.get('instances') or [{}]
            out.append({'engine':'OWASP ZAP','name':a.get('alert') or a.get('name') or 'ZAP finding','severity':sev,'url':inst[0].get('uri') or site.get('@name'),'description':a.get('desc'),'cwe':a.get('cweid')})
    return out


def counts(findings):
    c={k:0 for k in ['critical','high','medium','low','info','unknown']}
    for f in findings: c[f['severity'] if f['severity'] in c else 'unknown']+=1
    return c


def md(report):
    c=report['summary']; status=report['status']; engines=', '.join(report['engines'])
    lines=['# VibeSec DAST Summary','',f"**Target:** {report['target']}",f"**Status:** {status}",f"**Engines:** {engines}",'','## Findings',f"- Critical: {c['critical']}",f"- High: {c['high']}",f"- Medium: {c['medium']}",f"- Low / informational: {c['low']+c['info']}",'']
    important=[f for f in report['findings'] if f['severity'] in {'critical','high','medium'}][:20]
    if important:
        lines+=['## Priority findings']+[f"- **{f['severity'].upper()} · {f['engine']}** — {f['name']} — {f.get('url') or 'target'}" for f in important]
    else: lines+=['No medium/high/critical findings were recorded. This is not proof that the application is vulnerability-free.']
    lines+=['','> VibeSec correlates automated scanner evidence. Findings require validation; absence of findings is not assurance of security.']
    return '\n'.join(lines)+'\n'


def html_report(r):
    cards=''.join(f"<div class=m><small>{k.title()}</small><b>{r['summary'][k]}</b></div>" for k in ['critical','high','medium','low'])
    fs=''.join(f"<article><span>{html.escape(f['severity'].upper())} · {html.escape(f['engine'])}</span><h3>{html.escape(f['name'])}</h3><p>{html.escape(f.get('url') or '')}</p><p>{html.escape((f.get('description') or 'No scanner description.')[:800])}</p></article>" for f in r['findings'][:50]) or '<p>No findings recorded.</p>'
    return f"""<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'><meta charset=utf-8><title>VibeSec DAST</title><style>body{{font-family:-apple-system,sans-serif;background:#0b1220;color:#f8fafc;margin:0}}main{{max-width:760px;margin:auto;padding:20px}}p{{color:#b8c1d1;line-height:1.5}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}}.m,article{{background:#111b2e;border:1px solid #26344f;border-radius:16px;padding:15px;margin:10px 0}}.m small{{display:block;color:#9fb0c9}}.m b{{font-size:1.8rem}}article span{{font-size:.75rem;font-weight:800;color:#93c5fd}}@media(max-width:520px){{.grid{{grid-template-columns:1fr 1fr}}}}</style><main><h1>VibeSec DAST</h1><p>{html.escape(r['target'])}</p><p><b>Status:</b> {r['status']} · <b>Engines:</b> {html.escape(', '.join(r['engines']))}</p><div class=grid>{cards}</div><h2>Findings</h2>{fs}<p>Automated evidence requires validation. Zero findings is not proof of security.</p></main>"""


def build_report(target,out):
    nf=nuclei_findings(out/'nuclei.jsonl'); zf=zap_findings(out/'zap.json'); findings=nf+zf
    state={}
    try: state=json.loads((out/'scan-state.json').read_text())
    except Exception: pass
    engines=['httpx','Nuclei']+(['OWASP ZAP'] if (out/'zap.json').exists() else [])
    partial=state.get('nuclei_exit_code')==124 or not (out/'zap.json').exists()
    report={'schema_version':'0.4','target':target,'status':'PARTIAL' if partial else 'COMPLETE','engines':engines,'summary':counts(findings),'findings':findings,'tool_status':state}
    (out/'vibesec-dast-report.json').write_text(json.dumps(report,indent=2))
    (out/'vibesec-dast-summary.md').write_text(md(report))
    (out/'vibesec-dast-report.html').write_text(html_report(report))


def main():
    p=argparse.ArgumentParser(); p.add_argument('--target',required=True); p.add_argument('--output',default='dast-results'); p.add_argument('--time-budget',type=int,default=240); p.add_argument('--report-only',action='store_true'); a=p.parse_args()
    target=validate_target(a.target.strip()); out=Path(a.output); out.mkdir(parents=True,exist_ok=True)
    if not a.report_only:
        hrc=run(['httpx','-u',target,'-json','-silent','-status-code','-title','-tech-detect','-server','-follow-redirects','-timeout','10'],out/'httpx.jsonl',60)
        nrc=run(['nuclei','-u',target,'-jsonl','-silent','-severity','low,medium,high,critical','-exclude-tags','dos,bruteforce','-rate-limit','15','-bulk-size','8','-timeout','8','-retries','0'],out/'nuclei.jsonl',a.time_budget)
        (out/'scan-state.json').write_text(json.dumps({'httpx_exit_code':hrc,'nuclei_exit_code':nrc,'nuclei_timed_out':nrc==124},indent=2))
    build_report(target,out)

if __name__=='__main__': main()
