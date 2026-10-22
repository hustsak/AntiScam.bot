from pathlib import Path
import subprocess


CLAMAV_DIR = Path(
    r"D:\Downloads\clamav-1.4.6.win.x64\clamav-1.4.6.win.x64"
)

CLAMSCAN = CLAMAV_DIR / "clamscan.exe"
DATABASE = CLAMAV_DIR / "database"


def scan_with_clamav(file_path: str) -> list[dict]:
    """
    Scan a file using ClamAV.
    Returns findings compatible with KhmerShield risk scoring.
    """

    if not CLAMSCAN.exists():
        return [{
            "type": "clamav_error",
            "severity": "medium",
            "message": f"ClamAV not found: {CLAMSCAN}",
        }]

    if not DATABASE.exists():
        return [{
            "type": "clamav_error",
            "severity": "medium",
            "message": f"ClamAV database not found: {DATABASE}",
        }]

    try:
        result = subprocess.run(
            [
                str(CLAMSCAN),
                f"--database={DATABASE}",
                "--no-summary",
                file_path,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

    except subprocess.TimeoutExpired:
        return [{
            "type": "clamav_timeout",
            "severity": "medium",
            "message": "ClamAV scan timed out.",
        }]

    except Exception as error:
        return [{
            "type": "clamav_error",
            "severity": "medium",
            "message": f"ClamAV scan failed: {error}",
        }]

    output = (result.stdout + "\n" + result.stderr).strip()

    # ClamAV exit code:
    # 0 = clean
    # 1 = virus found
    # 2 = error

    if result.returncode == 1:
        return [{
            "type": "clamav_detection",
            "severity": "critical",
            "message": output or "ClamAV detected a threat.",
        }]

    if result.returncode != 0:
        return [{
            "type": "clamav_error",
            "severity": "medium",
            "message": output or "ClamAV returned an error.",
        }]

    return []