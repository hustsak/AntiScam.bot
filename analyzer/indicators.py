from pathlib import Path


SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd",
    ".ps1", ".vbs", ".vbe", ".js",
    ".jse", ".lnk", ".dll", ".msi",
    ".hta", ".apk",
}


def detect_suspicious_extension(filename: str) -> bool:
    return Path(filename).suffix.lower() in SUSPICIOUS_EXTENSIONS


def detect_double_extension(filename: str) -> bool:
    parts = Path(filename).name.lower().split(".")

    if len(parts) < 3:
        return False

    suspicious = {
        "exe", "scr", "bat", "cmd",
        "ps1", "vbs", "js", "lnk", "msi"
    }

    return parts[-1] in suspicious


def analyze_filename(filename: str) -> list[dict]:
    findings = []

    if detect_suspicious_extension(filename):
        findings.append({
            "type": "suspicious_extension",
            "severity": "high",
            "message": f"Suspicious file extension: {filename}"
        })

    if detect_double_extension(filename):
        findings.append({
            "type": "double_extension",
            "severity": "high",
            "message": f"Possible double-extension deception: {filename}"
        })

    return findings
