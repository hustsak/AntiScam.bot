from pathlib import Path
from zipfile import ZipFile, BadZipFile
import hashlib

from intelligence.extract import extract_indicators


MAX_FILES = 1000
MAX_FILE_SIZE = 20 * 1024 * 1024
MAX_TOTAL_SIZE = 200 * 1024 * 1024

TEXT_EXTENSIONS = {
    ".txt",
    ".html",
    ".htm",
    ".js",
    ".json",
    ".xml",
    ".csv",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".py",
}


def analyze_zip_content(file_path: str) -> dict:
    results = []
    all_urls = set()
    all_domains = set()
    all_ips = set()

    total_size = 0

    try:
        with ZipFile(file_path, "r") as archive:
            entries = archive.infolist()

            if len(entries) > MAX_FILES:
                return {
                    "status": "limited",
                    "files_analyzed": 0,
                    "findings": [],
                    "indicators": {
                        "urls": [],
                        "domains": [],
                        "ips": [],
                    },
                    "message": "Archive exceeds file-count limit."
                }

            for info in entries:
                if info.is_dir():
                    continue

                filename = info.filename
                extension = Path(filename).suffix.lower()

                total_size += info.file_size

                if total_size > MAX_TOTAL_SIZE:
                    break

                if info.file_size > MAX_FILE_SIZE:
                    continue

                if extension not in TEXT_EXTENSIONS:
                    continue

                # Read the member in memory only.
                with archive.open(info, "r") as member:
                    content = member.read(MAX_FILE_SIZE + 1)

                if len(content) > MAX_FILE_SIZE:
                    continue

                sha256 = hashlib.sha256(content).hexdigest()

                text = content.decode(
                    "utf-8",
                    errors="ignore"
                )

                indicators = extract_indicators(text)

                all_urls.update(indicators["urls"])
                all_domains.update(indicators["domains"])
                all_ips.update(indicators["ips"])

                results.append({
                    "filename": filename,
                    "sha256": sha256,
                    "size_bytes": len(content),
                    "indicators": indicators,
                })

    except BadZipFile:
        return {
            "status": "invalid",
            "files_analyzed": 0,
            "findings": [],
            "indicators": {
                "urls": [],
                "domains": [],
                "ips": [],
            },
            "message": "Invalid ZIP archive."
        }

    return {
        "status": "completed",
        "files_analyzed": len(results),
        "findings": results,
        "indicators": {
            "urls": sorted(all_urls),
            "domains": sorted(all_domains),
            "ips": sorted(all_ips),
        }
    }