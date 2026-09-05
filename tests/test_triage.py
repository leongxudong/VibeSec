import json
from pathlib import Path

from vibesec.triage import triage


def test_semgrep_and_sarif_prioritisation(tmp_path: Path):
    semgrep = tmp_path / "semgrep.json"
    semgrep.write_text(json.dumps({
        "results": [{
            "check_id": "python.lang.security.audit.dangerous-system-call",
            "path": "app.py",
            "start": {"line": 10},
            "extra": {"severity": "ERROR", "message": "Potential command execution"},
        }]
    }), encoding="utf-8")

    sarif = tmp_path / "codeql.sarif"
    sarif.write_text(json.dumps({
        "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": [{
                "id": "py/sql-injection",
                "shortDescription": {"text": "SQL query built from user-controlled sources"},
            }]}},
            "results": [{
                "ruleId": "py/sql-injection",
                "level": "error",
                "message": {"text": "User-controlled data reaches a SQL query."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "db.py"},
                    "region": {"startLine": 42},
                }}],
            }],
        }]
    }), encoding="utf-8")

    findings = triage([semgrep, sarif], limit=10)
    assert len(findings) == 2
    assert all(f.severity == "high" for f in findings)
    assert {f.file for f in findings} == {"app.py", "db.py"}


def test_duplicate_findings_are_collapsed(tmp_path: Path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    payload = {
        "findings": [{
            "id": "VSEC-001",
            "title": "JWT audience validation disabled",
            "severity": "medium",
            "file": "auth.py",
            "line": 12,
            "impact": "Audience is not validated.",
        }]
    }
    first.write_text(json.dumps(payload), encoding="utf-8")
    second.write_text(json.dumps(payload), encoding="utf-8")

    findings = triage([first, second], limit=10)
    assert len(findings) == 1
    assert findings[0].occurrences == 2
