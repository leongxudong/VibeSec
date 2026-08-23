# VibeSec

VibeSec is an open-source, explainable security-review tool for rapidly developed and AI-assisted web applications.

The goal is **not** to produce hundreds of generic scanner alerts. VibeSec tries to answer a more practical question:

> What are the few security mistakes in this repository that matter most, what controls already exist, and what exactly should I ask my coding AI to change?

VibeSec is currently a **POC / v0.1**. It performs deterministic static analysis only. It does not actively exploit deployed applications.

## Why VibeSec exists

The ecosystem already has strong projects covering adjacent ground:

| Project | Strength | Where VibeSec differs |
| --- | --- | --- |
| [vibescan](https://github.com/Armur-Ai/vibescan) | Broad orchestration of many security tools, SAST/DAST and AI-assisted fixes | VibeSec deliberately starts narrower: stack-aware reasoning, control detection, short high-signal reports and remediation handoff |
| [isitsecure](https://github.com/jaurakunal/isitsecure) | SAST + DAST + LLM review, fix plans and PR-oriented workflows | VibeSec focuses on architecture-aware remediation prompts constrained by controls already present in the repository |
| [CodeMoat](https://github.com/SYCO7/codemoat) | Rules aimed at common AI-generated-code mistakes | VibeSec correlates weaknesses with detected controls and generates implementation + verification prompts rather than only rule findings |
| [repo-security-review](https://github.com/Consensys/repo-security-review) | Broad Claude-driven repository security review | VibeSec is designed to be deterministic-first and usable without an LLM API; AI is the remediation consumer, not the source of truth |
| [Shor](https://github.com/tr4m0ryp/shor) | Source-aware offensive validation and exploit-oriented testing | VibeSec v0.1 is intentionally non-invasive and repository-first, aimed at developers who want a fast remediation path |

The intended workflow is:

```text
Repository
   ↓
Stack fingerprinting
   ↓
Security-control detection
   ↓
Deterministic security hypotheses
   ↓
Short evidence-backed report
   ↓
Exact practical remediation
   ↓
Copy-ready AI coding prompt
   ↓
Verification prompt / re-scan
```

A future VibeSec release may add optional safe verification and LLM-assisted correlation, but the deterministic evidence remains the source of truth.

## What v0.1 checks

The initial POC detects a small set of high-value patterns including:

- disabled JWT audience validation
- TLS verification bypasses
- shell-based command execution
- dynamic `eval` / `exec`
- client-visible privileged Supabase keys
- wildcard credentialed CORS patterns
- development authentication bypasses that require production guardrails

It also identifies selected **existing controls**, including:

- rate limiting
- JWT signature-verification logic
- CORS middleware/configuration
- administrative authorization logic
- request length constraints

That distinction matters. VibeSec should not label an endpoint insecure merely because it is sensitive; it should recognize the protection already present and report only the remaining concern.

## AI remediation handoff

Each finding includes:

1. evidence and source location
2. why the finding matters
3. practical remediation steps
4. a copy-ready prompt for Claude Code, Codex, Copilot, Cursor, Windsurf or another coding agent
5. a second verification prompt for checking the resulting change

The generated prompt tells the coding agent to preserve the application's existing architecture and security controls, make the smallest safe change, add tests and avoid unrelated refactoring.

## Quick start with Docker

Build locally:

```bash
docker build -t vibesec .
```

Scan a public GitHub repository:

```bash
docker run --rm \
  -v "$PWD/reports:/work/reports" \
  vibesec scan https://github.com/NaqibL/salary-matching --out /work/reports
```

Or scan a repository you already cloned, mounted read-only:

```bash
docker run --rm \
  -v "$PWD/target:/target:ro" \
  -v "$PWD/reports:/reports" \
  vibesec scan /target --out /reports
```

The second pattern is recommended for private or untrusted repositories because VibeSec does not need to execute the target application.

## GitHub Container Registry

The included GitHub Actions workflow tests VibeSec and publishes the latest successful `main` build to GHCR:

```bash
docker pull ghcr.io/leongxudong/vibesec:latest
```

Then run:

```bash
docker run --rm \
  -v "$PWD/reports:/work/reports" \
  ghcr.io/leongxudong/vibesec:latest \
  scan https://github.com/NaqibL/salary-matching --out /work/reports
```

If the GHCR package has not appeared yet, check the repository's **Actions** tab for the first workflow run.

## POC benchmark: Lowball

The first reference target is the public [`NaqibL/salary-matching`](https://github.com/NaqibL/salary-matching) repository behind the Lowball salary-checking project.

It is a useful benchmark because it represents a modern AI-assisted stack with FastAPI, Next.js, Supabase, JWT authentication, Docker, rate limiting, public API routes and administrative routes. The purpose is **not** to characterize Lowball as insecure. It is a public reference application for testing whether VibeSec can distinguish existing controls from review-worthy weaknesses.

Example:

```bash
vibesec scan https://github.com/NaqibL/salary-matching --out ./reports
```

Outputs:

```text
reports/
├── vibesec-report.md
└── vibesec-report.json
```

## Local development

Python 3.11+:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e . pytest
pytest -q
vibesec scan ./some-repo
```

## Security model

VibeSec v0.1 reads source files. It does **not** install target dependencies, run target build scripts, start target containers, execute application code or attack deployed endpoints.

Repositories should still be treated as untrusted input. Future dynamic-testing functionality should be isolated and explicitly authorization-gated.

## Limitations

A VibeSec finding is a security hypothesis based on static evidence, not proof of exploitability. Absence of a finding does not mean an application is secure. Manual review remains necessary for consequential applications.

## Responsible use

Only assess repositories and systems you own or are authorized to test. VibeSec is intended for defensive security review, education and secure-development workflows.

## License

Apache License 2.0. See [LICENSE](LICENSE).
