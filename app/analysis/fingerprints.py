from __future__ import annotations

from app.models import FingerprintFinding, ScriptRecord


SIGNALS = {
    "canvas": ["toDataURL(", "getImageData(", "measureText(", "fingerprintjs"],
    "webgl": ["webgl", "experimental-webgl", "getParameter(", "renderer", "vendor"],
    "audio": ["audiocontext", "offlineaudiocontext", "createoscillator("],
    "fonts": ["font", "document.fonts", "offsetwidth", "offsetheight"],
}


def detect_fingerprint_findings(scripts: list[ScriptRecord]) -> list[FingerprintFinding]:
    findings: list[FingerprintFinding] = []
    seen: set[tuple[str, str]] = set()
    for script in scripts:
        evidence = script.source[:120] if script.source else "inline script"
        for technique in script.fingerprint_signals:
            if technique in SIGNALS:
                key = (technique, evidence)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    FingerprintFinding(
                        technique=technique,
                        evidence=evidence,
                        severity="high" if technique in {"canvas", "webgl"} else "medium",
                    )
                )
    return findings


def score_script_signals(source: str) -> tuple[list[str], bool]:
    lowered = source.lower()
    hits = [technique for technique, markers in SIGNALS.items() if any(marker.lower() in lowered for marker in markers)]
    suspicious = any(token in lowered for token in ["eval(", "atob(", "fromcharcode(", "beacon", "track"])
    return hits, suspicious
