from pathlib import Path

from vibesec.scanner import scan_path


def test_detects_jwt_audience_bypass(tmp_path: Path):
    app = tmp_path / "auth.py"
    app.write_text('payload = jwt.decode(token, key, algorithms=["RS256"], options={"verify_aud": False})')
    result = scan_path(tmp_path)
    assert any(f.id == "VSEC-001" for f in result.findings)


def test_detects_controls(tmp_path: Path):
    app = tmp_path / "server.py"
    app.write_text('from fastapi.middleware.cors import CORSMiddleware\n@limiter.limit("10/minute")\ndef x(): pass\n')
    result = scan_path(tmp_path)
    names = {c.name for c in result.controls}
    assert "Rate limiting detected" in names
