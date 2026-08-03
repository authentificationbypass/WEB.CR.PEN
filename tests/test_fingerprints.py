from app.analysis.fingerprints import detect_fingerprint_findings, score_script_signals
from app.models import ScriptRecord


def test_score_script_signals_detects_canvas() -> None:
    source = "var canvas = document.createElement('canvas'); canvas.toDataURL();"
    signals, suspicious = score_script_signals(source)
    assert "canvas" in signals


def test_score_script_signals_flags_suspicious() -> None:
    source = "var data = atob('encoded'); eval(data);"
    signals, suspicious = score_script_signals(source)
    assert suspicious is True


def test_detect_fingerprint_findings() -> None:
    scripts = [
        ScriptRecord(
            source="https://cdn.example/lib.js",
            script_type="text/javascript",
            inline=False,
            fingerprint_signals=["canvas", "webgl"],
            suspicious=True,
        ),
        ScriptRecord(
            source="<inline>",
            script_type="text/javascript",
            inline=True,
            fingerprint_signals=["audio"],
            suspicious=False,
        ),
    ]
    findings = detect_fingerprint_findings(scripts)
    assert len(findings) >= 2
    assert any(f.technique == "canvas" for f in findings)
    assert any(f.technique == "audio" for f in findings)
