from analyzer.clamav_scan import scan_with_clamav
from analyzer.yara_scan import scan_with_yara
from pathlib import Path
import tempfile

from fastapi import FastAPI, File, UploadFile, HTTPException

from analyzer.hash import calculate_sha256
from analyzer.file_info import get_file_info
from analyzer.indicators import analyze_filename
from analyzer.risk import calculate_risk
from analyzer.archive import analyze_zip


app = FastAPI(
    title="KhmerShield AI",
    description="Telegram Scam & Suspicious File Detector",
    version="0.1.0"
)


ALLOWED_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".pdf",
    ".exe",
    ".apk",
    ".txt",
}


MAX_FILE_SIZE = 50 * 1024 * 1024


@app.get("/")
def root():
    return {
        "project": "KhmerShield AI",
        "status": "online",
        "version": "0.1.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "analyzer": "ready"
    }


@app.post("/api/scan")
async def scan_file(file: UploadFile = File(...)):

    filename = file.filename or "unknown"

    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {extension}"
        )

    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File exceeds 50 MB limit."
        )

    temp_path = None

    try:

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=extension
        ) as temp_file:

            temp_file.write(content)
            temp_path = temp_file.name

        file_info = get_file_info(temp_path)

        sha256 = calculate_sha256(temp_path)

        findings = analyze_filename(filename)
        yara_findings = scan_with_yara(temp_path)
        findings.extend(yara_findings)

	clamav_findings = scan_with_clamav(temp_path)
	findings.extend(clamav_findings)

        archive_result = None

        if extension == ".zip":

            archive_result = analyze_zip(temp_path)

            findings.extend(
                archive_result.get("findings", [])
            )

        risk = calculate_risk(findings)

        return {
            "filename": filename,
            "sha256": sha256,
            "file": file_info,
            "archive": archive_result,
            "risk": risk,
            "findings": findings
        }

    finally:

        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
