#!/usr/bin/env python3

import argparse
import html
import ipaddress
import json
import socket
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


def fail(message: str) -> None:
    print(f"[VibeSec DAST] ERROR: {message}", file=sys.stderr)
    raise SystemExit(2)


def validate_target(raw_target: str) -> str:
    parsed = urlparse(raw_target)
    if parsed.scheme not in {"http", "https"}:
        fail("Target must use http:// or https://")
    if not parsed.hostname:
        fail("Target must include a hostname")
    if parsed.username or parsed.password:
        fail("Credentials in target URLs are not permitted")

    host = parsed.hostname.rstrip(".")
    try:
        answers = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        fail(f"Target hostname could not be resolved: {exc}")

    resolved = sorted({item[4][0] for item in answers})
    if not resolved:
        fail("Target hostname resolved to no addresses")

    for value in resolved:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            fail(f"Target resolves to a non-public address ({ip}); VibeSec DAST refuses this target")

    print(f"[VibeSec DAST] Validated target {raw_target} -> {', '.join(resolved)}")
    return raw_target


def run(command: list[str], output_path: Path, timeout: int | None = None) -> int:
    print("[VibeSec DAST] Running:", " ".join(command))
    try:
        with output_path.open("w", encoding="utf-8") as handle:
            completed = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT, text=True, check=False, timeout=timeout)
        return completed.returncode
    except subprocess.TimeoutExpired:
        with output_path.open("a", encoding="utf-8") as handle:
            handle.write("\n[VibeSec DAST] Scan stopped after reaching the configured time budget.\n")
        return 124


def read_jsonl(path: Path) -> list[dict]:
    items: list[dict] = []
    if not path.exists():
        return items
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def normalise_nuclei(item: dict) -> dict:
    info = item.get("info") or {}
    classification = info.get("classification") or {}
    return {
        "source": "nuclei",
        "template_id": item.get("template-id"),
        "name": info.get("name") or item.get("template-id") or "Nuclei finding",
        "severity": (info.get("severity") or "unknown").lower(),
        "matched_at": item.get("matched-at") or item.get("host"),
        "description": info.get("description"),
        "tags": info.get("tags") or [],
        "cve_id": classification.get("cve-id"),
        "cwe_id": classification.get("cwe-id"),
    }


def render_markdown(report: dict) -> str:
    s = report["summary"]
    timed_out = report["tool_status"]["nuclei_timed_out"]
    lines = [
        "# VibeSec DAST Summary",
        "",
        f"**Target:** {report['target']}",
        f"**Status:** {'PARTIAL — time budget reached' if timed_out else 'Completed'}",
        "",
        "## Findings",
        f"- Critical: {s['critical']}",
        f"- High: {s['high']}",
        f"- Medium: {s['medium']}",
        "",
    ]
    findings = report["findings"][:20]
    if findings:
        lines.append("## Top findings")
        for f in findings:
            lines.append(f"- **{f['severity'].upper()}** — {f['name']} — {f.get('matched_at') or 'target'}")
    else:
        lines.append("No medium/high/critical Nuclei findings were recorded in this run.")
    lines += ["", "> DAST findings are scanner evidence, not proof of exploitability. Validate consequential findings manually."]
    return "\n".join(lines) + "\n"


def render_html(report: dict) -> str:
    s = report["summary"]
    timed_out = report["tool_status"]["nuclei_timed_out"]
    cards = "".join(
        f"<div class='metric'><b>{label}</b><span>{s[key]}</span></div>"
        for key, label in [("critical", "Critical"), ("high", "High"), ("medium", "Medium")]
    )
    finding_html = "".join(
        "<article><div class='sev {sev}'>{sev}</div><h3>{name}</h3><p>{where}</p><p>{desc}</p></article>".format(
            sev=html.escape(f["severity"]),
            name=html.escape(f["name"]),
            where=html.escape(f.get("matched_at") or ""),
            desc=html.escape(f.get("description") or "No description supplied by template."),
        )
        for f in report["findings"][:30]
    ) or "<p class='muted'>No medium/high/critical findings were recorded in this run.</p>"
    status = "Partial — scan time budget reached" if timed_out else "Completed"
    return f"""<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'><meta charset='utf-8'><title>VibeSec DAST Report</title><style>body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#0b1220;color:#f8fafc}}main{{max-width:760px;margin:auto;padding:24px}}.muted,p{{color:#b8c1d1;line-height:1.55}}.metrics{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:20px 0}}.metric,article{{background:#111b2e;border:1px solid #26344f;border-radius:18px;padding:16px}}.metric b{{display:block;color:#9fb0c9;font-size:.8rem}}.metric span{{font-size:2rem;font-weight:800}}article{{margin:12px 0}}h1{{font-size:2rem;margin-bottom:6px}}h3{{margin:8px 0}}.sev{{display:inline-block;padding:5px 9px;border-radius:999px;background:#26344f;font-size:.75rem;font-weight:800;text-transform:uppercase}}.critical{{background:#7f1d1d}}.high{{background:#9a3412}}.medium{{background:#854d0e}}@media(max-width:520px){{.metrics{{grid-template-columns:1fr}}}}</style></head><body><main><h1>VibeSec DAST</h1><p>{html.escape(report['target'])}</p><p><b>Status:</b> {status}</p><div class='metrics'>{cards}</div><h2>Findings</h2>{finding_html}<p class='muted'>Scanner evidence is not proof of exploitability. Validate consequential findings manually.</p></main></body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description="VibeSec optional safe DAST verification")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", default="dast-results")
    parser.add_argument("--time-budget", type=int, default=420)
    args = parser.parse_args()

    target = validate_target(args.target.strip())
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    httpx_raw = output_dir / "httpx.jsonl"
    nuclei_raw = output_dir / "nuclei.jsonl"

    httpx_rc = run(["httpx", "-u", target, "-json", "-silent", "-status-code", "-title", "-tech-detect", "-server", "-tls-grab", "-follow-redirects", "-timeout", "10"], httpx_raw, timeout=60)
    nuclei_rc = run(["nuclei", "-u", target, "-jsonl", "-silent", "-severity", "medium,high,critical", "-exclude-tags", "fuzz,dos,bruteforce,headless", "-rate-limit", "20", "-bulk-size", "10", "-timeout", "8", "-retries", "0"], nuclei_raw, timeout=args.time_budget)

    httpx = read_jsonl(httpx_raw)
    nuclei = [normalise_nuclei(item) for item in read_jsonl(nuclei_raw)]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for finding in nuclei:
        severity = finding.get("severity", "unknown")
        counts[severity if severity in counts else "unknown"] += 1

    report = {"schema_version": "0.3", "mode": "optional-safe-dast", "target": target, "time_budget_seconds": args.time_budget, "tool_status": {"httpx_exit_code": httpx_rc, "nuclei_exit_code": nuclei_rc, "nuclei_timed_out": nuclei_rc == 124}, "summary": counts, "http_observations": httpx, "findings": nuclei}
    (output_dir / "vibesec-dast-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (output_dir / "vibesec-dast-summary.md").write_text(render_markdown(report), encoding="utf-8")
    (output_dir / "vibesec-dast-report.html").write_text(render_html(report), encoding="utf-8")
    print(f"[VibeSec DAST] Reports written to {output_dir}")


if __name__ == "__main__":
    main()
