from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


@dataclass
class TriageFinding:
    source: str
    rule_id: str
    title: str
    severity: str
    file: str
    line: int | None
    message: str
    occurrences: int = 1

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}" if self.line else self.file

    def fix_prompt(self) -> str:
        return (
            "You are fixing a security finding in an existing repository.\n\n"
            f"Finding: {self.title}\n"
            f"Severity: {self.severity.upper()}\n"
            f"Scanner evidence: {self.source} / {self.rule_id}\n"
            f"Location: {self.location}\n"
            f"Message: {self.message}\n\n"
            "Instructions:\n"
            "- Validate that the finding is applicable before changing code.\n"
            "- Preserve existing architecture and security controls.\n"
            "- Make the smallest safe change that addresses the root cause.\n"
            "- Add or update tests that demonstrate the unsafe behavior is rejected.\n"
            "- Do not make unrelated refactors.\n"
            "Return the proposed diff, tests, and a short explanation of residual risk."
        )


def _severity(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    aliases = {
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "note": "low",
        "moderate": "medium",
        "negligible": "low",
    }
    text = aliases.get(text, text)
    return text if text in SEVERITY_ORDER else "unknown"


def _clean_title(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "Security finding").strip()
    return text[:180] or "Security finding"


def _clean_message(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()[:800]


def parse_semgrep(data: dict[str, Any], source: str) -> list[TriageFinding]:
    findings: list[TriageFinding] = []
    for item in data.get("results", []):
        extra = item.get("extra", {}) or {}
        findings.append(TriageFinding(
            source=source,
            rule_id=str(item.get("check_id") or "semgrep"),
            title=_clean_title(extra.get("metadata", {}).get("shortlink") or item.get("check_id") or extra.get("message") or "Semgrep finding"),
            severity=_severity(extra.get("severity")),
            file=str(item.get("path") or "unknown"),
            line=(item.get("start") or {}).get("line"),
            message=_clean_message(extra.get("message")),
        ))
    return findings


def parse_sarif(data: dict[str, Any], source: str) -> list[TriageFinding]:
    findings: list[TriageFinding] = []
    for run in data.get("runs", []):
        rules = {}
        driver = ((run.get("tool") or {}).get("driver") or {})
        for rule in driver.get("rules", []) or []:
            rules[str(rule.get("id"))] = rule
        tool_name = driver.get("name") or source
        for result in run.get("results", []) or []:
            rule_id = str(result.get("ruleId") or "sarif")
            rule = rules.get(rule_id, {})
            title = ((rule.get("shortDescription") or {}).get("text") or
                     (rule.get("fullDescription") or {}).get("text") or
                     rule_id)
            message = (result.get("message") or {}).get("text") or title
            locations = result.get("locations") or [{}]
            physical = ((locations[0].get("physicalLocation") or {}))
            artifact = (physical.get("artifactLocation") or {}).get("uri") or "unknown"
            line = (physical.get("region") or {}).get("startLine")
            severity = _severity(result.get("level"))
            properties = result.get("properties") or {}
            if properties.get("security-severity"):
                try:
                    score = float(properties["security-severity"])
                    severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
                except (TypeError, ValueError):
                    pass
            findings.append(TriageFinding(
                source=str(tool_name), rule_id=rule_id, title=_clean_title(title),
                severity=severity, file=str(artifact), line=line,
                message=_clean_message(message),
            ))
    return findings


def parse_trivy(data: dict[str, Any], source: str) -> list[TriageFinding]:
    findings: list[TriageFinding] = []
    for result in data.get("Results", []) or []:
        target = str(result.get("Target") or "unknown")
        for item in result.get("Vulnerabilities", []) or []:
            findings.append(TriageFinding(
                source=source,
                rule_id=str(item.get("VulnerabilityID") or "trivy-vuln"),
                title=_clean_title(item.get("Title") or item.get("VulnerabilityID") or "Dependency vulnerability"),
                severity=_severity(item.get("Severity")),
                file=target,
                line=None,
                message=_clean_message(item.get("Description") or item.get("PkgName") or ""),
            ))
        for item in result.get("Misconfigurations", []) or []:
            cause = item.get("CauseMetadata") or {}
            findings.append(TriageFinding(
                source=source,
                rule_id=str(item.get("ID") or "trivy-misconfig"),
                title=_clean_title(item.get("Title") or item.get("ID") or "Misconfiguration"),
                severity=_severity(item.get("Severity")),
                file=str(cause.get("Resource") or target),
                line=cause.get("StartLine"),
                message=_clean_message(item.get("Message") or item.get("Description") or ""),
            ))
        for item in result.get("Secrets", []) or []:
            findings.append(TriageFinding(
                source=source,
                rule_id=str(item.get("RuleID") or "trivy-secret"),
                title=_clean_title(item.get("Title") or "Potential secret exposure"),
                severity=_severity(item.get("Severity") or "high"),
                file=target,
                line=item.get("StartLine"),
                message=_clean_message(item.get("Match") or "Potential secret detected"),
            ))
    return findings


def parse_vibesec(data: dict[str, Any], source: str) -> list[TriageFinding]:
    findings: list[TriageFinding] = []
    for item in data.get("findings", []) or []:
        findings.append(TriageFinding(
            source=source,
            rule_id=str(item.get("id") or "vibesec"),
            title=_clean_title(item.get("title") or "VibeSec finding"),
            severity=_severity(item.get("severity")),
            file=str(item.get("file") or "unknown"),
            line=item.get("line"),
            message=_clean_message(item.get("impact") or item.get("evidence") or ""),
        ))
    return findings


def load_findings(path: Path) -> list[TriageFinding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    source = path.stem
    if isinstance(data, dict) and "runs" in data:
        return parse_sarif(data, source)
    if isinstance(data, dict) and "results" in data and any(isinstance(x, dict) and "check_id" in x for x in data.get("results", [])):
        return parse_semgrep(data, source)
    if isinstance(data, dict) and "Results" in data:
        return parse_trivy(data, source)
    if isinstance(data, dict) and "findings" in data:
        return parse_vibesec(data, source)
    raise ValueError(f"Unsupported scanner JSON format: {path}")


def _dedupe(findings: list[TriageFinding]) -> list[TriageFinding]:
    merged: dict[tuple[str, str, int | None], TriageFinding] = {}
    for finding in findings:
        normalized_title = re.sub(r"[^a-z0-9]+", " ", finding.title.lower()).strip()
        key = (finding.file.lower(), normalized_title, finding.line)
        if key not in merged:
            merged[key] = finding
            continue
        existing = merged[key]
        existing.occurrences += 1
        sources = {x.strip() for x in existing.source.split(",") if x.strip()}
        sources.add(finding.source)
        existing.source = ", ".join(sorted(sources))
        if SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[existing.severity]:
            existing.severity = finding.severity
        if len(finding.message) > len(existing.message):
            existing.message = finding.message
    return list(merged.values())


def triage(paths: list[Path], limit: int = 10) -> list[TriageFinding]:
    all_findings: list[TriageFinding] = []
    for path in paths:
        all_findings.extend(load_findings(path))
    deduped = _dedupe(all_findings)
    deduped.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.occurrences, f.file, f.line or 0))
    return deduped[:limit]


def render_markdown(findings: list[TriageFinding], input_count: int) -> str:
    lines = [
        "# VibeSec Security Triage",
        "",
        f"**Scanner outputs ingested:** {input_count}",
        f"**Prioritised findings shown:** {len(findings)}",
        "",
        "> VibeSec triages scanner evidence; it does not treat third-party findings as proven vulnerabilities. Validate applicability before remediation.",
        "",
    ]
    if not findings:
        lines.append("No supported findings were present in the supplied scanner outputs.")
        return "\n".join(lines) + "\n"
    for index, finding in enumerate(findings, 1):
        lines += [
            f"## {index}. {finding.severity.upper()} — {finding.title}",
            "",
            f"**Location:** `{finding.location}`  ",
            f"**Evidence source:** {finding.source}  ",
            f"**Rule:** `{finding.rule_id}`  ",
            f"**Corroborating occurrences:** {finding.occurrences}",
            "",
            finding.message or "No additional scanner message supplied.",
            "",
            "### Copy-ready coding-agent prompt",
            "",
            "```text",
            finding.fix_prompt(),
            "```",
            "",
        ]
    return "\n".join(lines)


def write_triage(findings: list[TriageFinding], out_dir: Path, input_count: int) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "vibesec-triage.md"
    js = out_dir / "vibesec-triage.json"
    md.write_text(render_markdown(findings, input_count), encoding="utf-8")
    js.write_text(json.dumps({"findings": [asdict(f) for f in findings]}, indent=2), encoding="utf-8")
    return md, js
