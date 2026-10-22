import hashlib
from pathlib import Path


def calculate_sha256(file_path: str) -> str:
    """Calculate SHA-256 using memory-efficient chunks."""

    sha256 = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        while chunk := file.read(1024 * 1024):
            sha256.update(chunk)

    return sha256.hexdigest()
