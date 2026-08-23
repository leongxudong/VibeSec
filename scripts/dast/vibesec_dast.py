#!/usr/bin/env python3

import argparse
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
        answers = socket.getaddrinfo(
            host,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
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
            completed = subprocess.run(
                command,
                stdout=handle,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=timeout,
            )
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


def main() -> None:
    parser = argparse.ArgumentParser(description="VibeSec optional safe DAST verification")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", default="dast-results")
    parser.add_argument("--time-budget", type=int, default=420, help="Nuclei time budget in seconds")
    args = parser.parse_args()

    target = validate_target(args.target.strip())
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    httpx_raw = output_dir / "httpx.jsonl"
    nuclei_raw = output_dir / "nuclei.jsonl"

    httpx_rc = run(
        [
            "httpx",
            "-u", target,
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-tls-grab",
            "-follow-redirects",
            "-timeout", "10",
        ],
        httpx_raw,
        timeout=60,
    )

    nuclei_rc = run(
        [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-silent",
            "-severity", "medium,high,critical",
            "-exclude-tags", "fuzz,dos,bruteforce,headless",
            "-rate-limit", "20",
            "-bulk-size", "10",
            "-timeout", "8",
            "-retries", "0",
        ],
        nuclei_raw,
        timeout=args.time_budget,
    )

    httpx = read_jsonl(httpx_raw)
    nuclei = [normalise_nuclei(item) for item in read_jsonl(nuclei_raw)]

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for finding in nuclei:
        severity = finding.get("severity", "unknown")
        counts[severity if severity in counts else "unknown"] += 1

    report = {
        "schema_version": "0.2",
        "mode": "optional-safe-dast",
        "target": target,
        "time_budget_seconds": args.time_budget,
        "tool_status": {
            "httpx_exit_code": httpx_rc,
            "nuclei_exit_code": nuclei_rc,
            "nuclei_timed_out": nuclei_rc == 124,
        },
        "summary": counts,
        "http_observations": httpx,
        "findings": nuclei,
    }

    report_path = output_dir / "vibesec-dast-report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[VibeSec DAST] Report written to {report_path}")


if __name__ == "__main__":
    main()
