from pathlib import Path
from zipfile import ZipFile, BadZipFile

from analyzer.indicators import analyze_filename


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".dll",
    ".hta",
    ".apk",
}


MAX_FILES = 1000
MAX_TOTAL_UNCOMPRESSED_SIZE = 200 * 1024 * 1024


def is_path_traversal(filename: str) -> bool:
    normalized = filename.replace("\\", "/")

    if normalized.startswith("/"):
        return True

    parts = normalized.split("/")

    return ".." in parts


def analyze_zip(file_path: str) -> dict:

    files = []
    findings = []

    total_uncompressed_size = 0

    try:

        with ZipFile(file_path, "r") as archive:

            entries = archive.infolist()

            # Protect against archives containing huge numbers of files
            if len(entries) > MAX_FILES:
                findings.append({
                    "type": "too_many_files",
                    "severity": "high",
                    "message": (
                        f"Archive contains {len(entries)} files. "
                        f"Limit is {MAX_FILES}."
                    )
                })

            for info in entries:

                filename = info.filename

                total_uncompressed_size += info.file_size

                files.append({
                    "filename": filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                })

                # -------------------------------------------------
                # Path traversal detection
                # -------------------------------------------------

                if is_path_traversal(filename):

                    findings.append({
                        "type": "path_traversal",
                        "severity": "critical",
                        "message": (
                            f"Suspicious archive path detected: {filename}"
                        )
                    })

                # -------------------------------------------------
                # Suspicious filename analysis
                # -------------------------------------------------

                filename_findings = analyze_filename(filename)

                findings.extend(filename_findings)

                # -------------------------------------------------
                # Suspicious executable/script extension
                # -------------------------------------------------

                extension = Path(filename).suffix.lower()

                if extension in SUSPICIOUS_EXTENSIONS:

                    findings.append({
                        "type": "executable_in_archive",
                        "severity": "high",
                        "message": (
                            f"Executable or script found: {filename}"
                        )
                    })

                # -------------------------------------------------
                # Encrypted archive entry
                # -------------------------------------------------

                if info.flag_bits & 0x1:

                    findings.append({
                        "type": "encrypted_archive_entry",
                        "severity": "medium",
                        "message": (
                            f"Encrypted archive entry: {filename}"
                        )
                    })

                # -------------------------------------------------
                # Suspicious compression ratio
                # -------------------------------------------------

                if info.compress_size > 0:

                    compression_ratio = (
                        info.file_size / info.compress_size
                    )

                    if compression_ratio > 100:

                        findings.append({
                            "type": "high_compression_ratio",
                            "severity": "high",
                            "message": (
                                f"Very high compression ratio for: "
                                f"{filename}"
                            )
                        })

            # -----------------------------------------------------
            # Total archive expansion protection
            # -----------------------------------------------------

            if total_uncompressed_size > MAX_TOTAL_UNCOMPRESSED_SIZE:

                findings.append({
                    "type": "archive_expansion_limit",
                    "severity": "critical",
                    "message": (
                        "Archive contains more than "
                        "200 MB of uncompressed data."
                    )
                })

    except BadZipFile:

        return {
            "valid": False,
            "files": [],
            "findings": [
                {
                    "type": "invalid_archive",
                    "severity": "medium",
                    "message": "Invalid ZIP archive."
                }
            ]
        }

    return {
        "valid": True,
        "files": files,
        "findings": findings,
        "total_uncompressed_size": total_uncompressed_size,
    }