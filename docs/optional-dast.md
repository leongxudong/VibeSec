# Optional DAST mode

VibeSec is repository-first by default. This optional mode adds safe, authorised verification against a deployed HTTP/HTTPS application.

## Scope

The DAST workflow currently uses:

- `httpx` for basic HTTP/TLS/technology observations
- `Nuclei` for medium/high/critical findings only
- explicit exclusion of fuzzing, DoS, brute-force and headless templates
- a bounded Nuclei execution budget so partial findings are still reported

## Run

From **Actions → VibeSec Optional DAST → Run workflow** provide:

- an authorised HTTP/HTTPS target
- the confirmation `I AM AUTHORIZED`

The workflow uploads a `vibesec-dast-*` artifact containing the structured report.

## Product boundary

VibeSec owns application security: source-code review plus optional deployed-web verification. Network/service discovery belongs in QuickSec.
