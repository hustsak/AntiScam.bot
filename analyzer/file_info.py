from pathlib import Path
import mimetypes


def get_file_info(file_path: str) -> dict:
    path = Path(file_path)

    mime_type, _ = mimetypes.guess_type(path.name)

    return {
        "filename": path.name,
        "extension": path.suffix.lower(),
        "size_bytes": path.stat().st_size,
        "mime_type": mime_type or "application/octet-stream",
    }
