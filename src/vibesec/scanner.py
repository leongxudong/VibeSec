from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


TEXT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".toml", ".yaml", ".yml", ".env", ".md"}
SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", ".venv", "venv", "__pycache__"}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    status: str
    file: str
    line: int | None
    evidence: str
    impact: str
    recommendation: str
    ai_fix_prompt: str
    verification_prompt: str


@dataclass
class Control:
    name: str
    evidence: str


@dataclass
class ScanResult:
    target: str
    stack: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    controls: list[Control] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "stack": self.stack,
            "findings": [asdict(x) for x in self.findings],
            "controls": [asdict(x) for x in self.controls],
        }


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name.startswith(".env") or path.suffix.lower() in TEXT_EXTENSIONS or path.name in {"Dockerfile", "requirements.txt", "package-lock.json"}:
            yield path


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _prompt(title: str, file: str, evidence: str, fix: str) -> str:
    return f"""You are fixing a security finding in an existing application.\n\nFinding: {title}\nFile: {file}\nEvidence: {evidence}\n\nRequired remediation:\n{fix}\n\nConstraints:\n- Preserve the application's existing architecture and public behavior unless the security fix requires otherwise.\n- Do not remove or weaken existing authentication, authorization, validation, logging, or rate limiting controls.\n- Make the smallest safe change.\n- Add or update tests that prove the vulnerable behavior is rejected and legitimate behavior still works.\n- Do not make unrelated refactors.\n\nReturn the proposed diff, tests, and any configuration changes required."""


def _verify_prompt(fid: str, title: str, file: str) -> str:
    return f"""Verify remediation of VibeSec finding {fid}: {title}.\nReview the changes affecting {file}, run the relevant tests, and confirm whether the original security condition is no longer present. Check for regressions or weakened controls. Do not make unrelated changes. Report RESOLVED, PARTIALLY RESOLVED, or UNRESOLVED with evidence."""


def _add_pattern_finding(result: ScanResult, root: Path, path: Path, text: str, *, fid: str, title: str, severity: str, confidence: str, pattern: str, impact: str, recommendation: str, flags: int = 0) -> None:
    match = re.search(pattern, text, flags)
    if not match:
        return
    rel = str(path.relative_to(root))
    evidence = match.group(0).strip().replace("\n", " ")[:240]
    result.findings.append(Finding(
        id=fid,
        title=title,
        severity=severity,
        confidence=confidence,
        status="review",
        file=rel,
        line=_line_for(text, match.start()),
        evidence=evidence,
        impact=impact,
        recommendation=recommendation,
        ai_fix_prompt=_prompt(title, rel, evidence, recommendation),
        verification_prompt=_verify_prompt(fid, title, rel),
    ))


def detect_stack(root: Path) -> list[str]:
    stack: set[str] = set()
    names = {p.name for p in root.rglob("*") if p.is_file()}
    if "package.json" in names:
        stack.add("Node.js")
        package_files = list(root.rglob("package.json"))
        content = "\n".join(_read(x) for x in package_files)
        if '"next"' in content:
            stack.add("Next.js")
        if '"react"' in content:
            stack.add("React")
        if "supabase" in content.lower():
            stack.add("Supabase")
    py = "\n".join(_read(x) for x in [*root.rglob("pyproject.toml"), *root.rglob("requirements.txt")])
    if py:
        stack.add("Python")
    if "fastapi" in py.lower() or any("from fastapi" in _read(x) for x in root.rglob("*.py")):
        stack.add("FastAPI")
    if any(p.name.startswith("Dockerfile") for p in root.rglob("*")) or "docker-compose.yml" in names:
        stack.add("Docker")
    all_text = "\n".join(_read(x) for x in list(_iter_files(root))[:500])
    if "supabase" in all_text.lower():
        stack.add("Supabase")
    if "vercel" in all_text.lower():
        stack.add("Vercel")
    return sorted(stack)


def scan_path(root: Path, target_label: str | None = None) -> ScanResult:
    root = root.resolve()
    result = ScanResult(target=target_label or str(root), stack=detect_stack(root))

    seen_controls: set[str] = set()
    for path in _iter_files(root):
        text = _read(path)
        if not text:
            continue

        _add_pattern_finding(
            result, root, path, text,
            fid="VSEC-001", title="JWT audience validation disabled", severity="medium", confidence="high",
            pattern=r"verify_aud[\"']?\s*[:=]\s*False|[\"']verify_aud[\"']\s*:\s*False",
            impact="A correctly signed token may be accepted without confirming that it was issued for the intended audience.",
            recommendation="Enable audience validation using the application's intended audience. Also validate the expected issuer where the identity provider supports it, while preserving signature and expiry validation.",
        )
        _add_pattern_finding(
            result, root, path, text,
            fid="VSEC-002", title="TLS certificate verification disabled", severity="high", confidence="high",
            pattern=r"verify\s*=\s*False",
            impact="Outbound HTTPS traffic can become vulnerable to man-in-the-middle interception.",
            recommendation="Remove the TLS verification bypass and use the platform trust store or a narrowly scoped trusted CA bundle.",
        )
        _add_pattern_finding(
            result, root, path, text,
            fid="VSEC-003", title="Potential command injection via shell execution", severity="high", confidence="medium",
            pattern=r"shell\s*=\s*True",
            impact="If attacker-controlled input reaches a shell command, arbitrary command execution may be possible.",
            recommendation="Avoid shell=True. Pass commands as an argument list and strictly validate any user-controlled values before invocation.",
        )
        _add_pattern_finding(
            result, root, path, text,
            fid="VSEC-004", title="Dynamic code execution detected", severity="high", confidence="medium",
            pattern=r"\b(eval|exec)\s*\(",
            impact="Dynamic evaluation can turn attacker-controlled data into code execution.",
            recommendation="Replace dynamic evaluation with explicit parsing or a safe data format. If unavoidable, ensure the evaluated input cannot be influenced by untrusted users.",
        )
        _add_pattern_finding(
            result, root, path, text,
            fid="VSEC-005", title="Possible privileged Supabase key exposed to client code", severity="critical", confidence="medium",
            pattern=r"NEXT_PUBLIC_[A-Z0-9_]*(SERVICE_ROLE|SERVICE_KEY)|VITE_[A-Z0-9_]*(SERVICE_ROLE|SERVICE_KEY)",
            impact="A privileged Supabase service key in browser-accessible configuration can bypass row-level security and expose or modify backend data.",
            recommendation="Remove privileged Supabase credentials from client-visible environment variables. Keep service-role operations server-side only and rotate any exposed credential.",
            flags=re.I,
        )
        _add_pattern_finding(
            result, root, path, text,
            fid="VSEC-006", title="Wildcard CORS with credentials", severity="high", confidence="high",
            pattern=r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\][\s\S]{0,300}?allow_credentials\s*=\s*True",
            impact="Credentialed cross-origin requests may be accepted from untrusted origins depending on framework/browser behavior and surrounding configuration.",
            recommendation="Use an explicit allowlist of trusted production origins and keep credential support only where required.",
            flags=re.I,
        )
        _add_pattern_finding(
            result, root, path, text,
            fid="VSEC-007", title="Development authentication bypass present", severity="medium", confidence="medium",
            pattern=r"ALLOW_ANONYMOUS_LOCAL|allow_anonymous_local",
            impact="A development authentication bypass becomes high impact if accidentally enabled in production.",
            recommendation="Fail closed in production: reject startup or requests when the bypass is enabled outside an explicit local/development environment. Keep the flag false by default and document the deployment guardrail.",
            flags=re.I,
        )

        if re.search(r"@(?:limiter\.)?limit\(|\.limit\([\"']\d+/(?:minute|second|hour)", text):
            if "rate-limit" not in seen_controls:
                result.controls.append(Control("Rate limiting detected", str(path.relative_to(root))))
                seen_controls.add("rate-limit")
        if "CORSMiddleware" in text and "allow_origins" in text:
            if "cors" not in seen_controls:
                result.controls.append(Control("CORS middleware/configuration detected", str(path.relative_to(root))))
                seen_controls.add("cors")
        if re.search(r"jwt\.decode|PyJWKClient|JWKS", text, re.I):
            if "jwt" not in seen_controls:
                result.controls.append(Control("JWT signature validation logic detected", str(path.relative_to(root))))
                seen_controls.add("jwt")
        if re.search(r"admin.*(Depends|role|user_ids|secret)", text, re.I | re.S):
            if "admin" not in seen_controls:
                result.controls.append(Control("Administrative authorization logic detected", str(path.relative_to(root))))
                seen_controls.add("admin")
        if re.search(r"Field\([^\)]*max_length\s*=", text):
            if "input-bounds" not in seen_controls:
                result.controls.append(Control("Input length constraints detected", str(path.relative_to(root))))
                seen_controls.add("input-bounds")

    dedup: dict[tuple[str, str], Finding] = {}
    for f in result.findings:
        dedup[(f.id, f.file)] = f
    result.findings = sorted(dedup.values(), key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 9), f.id, f.file))
    return result


def materialize_target(target: str) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    path = Path(target)
    if path.exists():
        return path, None
    if target.startswith("https://github.com/"):
        temp = tempfile.TemporaryDirectory(prefix="vibesec-")
        subprocess.run(["git", "clone", "--depth", "1", target, temp.name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return Path(temp.name), temp
    raise ValueError("Target must be an existing local path or a public GitHub HTTPS repository URL")


def render_markdown(result: ScanResult) -> str:
    lines = [f"# VibeSec Security Review", "", f"**Target:** `{result.target}`", f"**Detected stack:** {', '.join(result.stack) or 'Unknown'}", "", "## Executive summary", ""]
    sev_counts = {s: sum(1 for f in result.findings if f.severity == s) for s in ("critical", "high", "medium", "low")}
    lines.append(f"VibeSec identified **{len(result.findings)} review items**: {sev_counts['critical']} critical, {sev_counts['high']} high, {sev_counts['medium']} medium, {sev_counts['low']} low. Findings are hypotheses from static evidence and should be validated before being treated as confirmed vulnerabilities.")
    lines += ["", "## Detected controls", ""]
    if result.controls:
        lines += [f"- **{c.name}** — `{c.evidence}`" for c in result.controls]
    else:
        lines.append("- No supported controls detected by the current POC rules.")
    lines += ["", "## Findings", ""]
    if not result.findings:
        lines.append("No supported findings detected. This does not mean the application is vulnerability-free.")
    for f in result.findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines += [
            f"### {f.id} — {f.title}", "",
            f"**Severity:** {f.severity.upper()}  ",
            f"**Confidence:** {f.confidence.upper()}  ",
            f"**Status:** {f.status.upper()}  ",
            f"**Location:** `{loc}`", "",
            f"**Evidence:** `{f.evidence}`", "",
            f"**Why it matters:** {f.impact}", "",
            f"**Practical fix:** {f.recommendation}", "",
            "#### Copy-ready AI fix prompt", "", "```text", f.ai_fix_prompt, "```", "",
            "#### Verification prompt", "", "```text", f.verification_prompt, "```", "",
        ]
    lines += ["## Scope and limitations", "", "VibeSec POC v0.1 performs deterministic static checks and stack/control detection. It does not execute target application code, actively exploit deployed services, prove exploitability, or replace manual review. Only scan repositories and systems you are authorized to assess.", ""]
    return "\n".join(lines)


def write_reports(result: ScanResult, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "vibesec-report.md"
    js = out_dir / "vibesec-report.json"
    md.write_text(render_markdown(result), encoding="utf-8")
    js.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return md, js
