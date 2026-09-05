# VibeSec

VibeSec is an open-source **security triage and remediation-handoff tool for AI-assisted software development**.

Its primary job is no longer to compete with mature SAST engines. Instead, VibeSec ingests findings from established scanners, reduces the output to a short prioritised list, and produces copy-ready remediation prompts for coding agents such as Codex, Claude Code, Copilot, Cursor and Windsurf.

> **Problem:** security scanners can produce more findings than a fast-moving developer can reasonably interpret before merge.
>
> **VibeSec's question:** *Which findings deserve attention first, what evidence supports them, and what exactly should I ask my coding agent to fix?*

## Current status

**POC / v0.2.**

The useful path in v0.2 is `vibesec triage`. It currently understands:

- SARIF (for example CodeQL and other SARIF-producing tools)
- Semgrep JSON
- Trivy JSON, including vulnerabilities, misconfigurations and secrets
- VibeSec's legacy deterministic JSON output

The original `vibesec scan` command remains available as a small deterministic POC, but its seven pattern checks are **not positioned as a replacement for established SAST/SCA tooling**.

## Intended workflow

```text
AI-assisted PR / repository
        ↓
Established scanners
(CodeQL / Semgrep / Trivy / others)
        ↓
JSON / SARIF outputs
        ↓
VibeSec triage
        ↓
Normalize + deduplicate + prioritise
        ↓
Short evidence-backed report
        ↓
Copy-ready coding-agent remediation prompt
        ↓
Developer validates and applies fix
        ↓
Re-run scanners before merge
```

## Quick start

Install locally with Python 3.11+:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e . pytest
```

Triage one or more scanner outputs:

```bash
vibesec triage semgrep.json codeql.sarif trivy.json --out ./reports
```

Limit the report to the five highest-priority items:

```bash
vibesec triage semgrep.json codeql.sarif --limit 5 --out ./reports
```

Outputs:

```text
reports/
├── vibesec-triage.md
└── vibesec-triage.json
```

Each prioritised finding includes:

1. severity
2. source scanner and rule identifier
3. file and line where available
4. scanner message/evidence
5. number of corroborating duplicate occurrences
6. a copy-ready coding-agent prompt that explicitly tells the agent to validate applicability, preserve existing controls, make the smallest safe change, and add tests

## Why use established scanners underneath?

VibeSec is deliberately a **decision layer**, not another broad detection engine.

Mature tools already invest heavily in language parsing, taint analysis, dependency intelligence, vulnerability databases and rule maintenance. Re-implementing that with a small set of regular expressions creates false confidence.

VibeSec instead focuses on the handoff problem that becomes more important with AI-assisted development: converting scanner evidence into a small, understandable remediation queue that a human can validate and a coding agent can act on.

## Legacy deterministic scan

The original POC remains available:

```bash
vibesec scan ./some-repo --out ./reports
```

It performs a narrow set of deterministic checks for patterns such as:

- disabled JWT audience validation
- TLS verification bypasses
- shell-based command execution
- dynamic `eval` / `exec`
- client-visible privileged Supabase keys
- wildcard credentialed CORS
- development authentication bypasses

It also detects a few existing controls such as rate limiting, JWT validation logic and CORS configuration. These checks are retained for experimentation and regression testing, not as a claim of comprehensive application-security coverage.

## Security model

VibeSec triage reads scanner report files only. The legacy scan path reads source files but does not install target dependencies, execute target code, start containers or attack deployed endpoints.

A scanner finding is still a **hypothesis**, not proof of exploitability. VibeSec's generated coding-agent prompts therefore instruct the agent to validate the finding before changing code.

## Roadmap

The next useful increments are:

- GitHub Actions example that runs established scanners and then VibeSec triage on a pull request
- stronger cross-scanner correlation beyond exact file/title deduplication
- suppression/baseline support for accepted findings
- verification reports comparing pre-fix and post-fix scanner output
- compact PR comment output rather than a long standalone report

## Responsible use

Only assess repositories and systems you own or are authorised to review. VibeSec is intended for defensive secure-development workflows.

## License

Apache License 2.0. See [LICENSE](LICENSE).
