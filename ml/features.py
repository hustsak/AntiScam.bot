from pathlib import Path
import math
import hashlib


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".apk",
    ".msi",
    ".dll",
}


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    frequency = [0] * 256

    for byte in data:
        frequency[byte] += 1

    entropy = 0.0
    length = len(data)

    for count in frequency:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def extract_features(file_path: str) -> dict:
    path = Path(file_path)

    data = path.read_bytes()

    filename = path.name.lower()
    extension = path.suffix.lower()

    sha256 = hashlib.sha256(data).hexdigest()

    features = {
        "file_size": len(data),

        "filename_length": len(filename),

        "extension_length": len(extension),

        "is_executable": int(
            extension in SUSPICIOUS_EXTENSIONS
        ),

        "has_double_extension": int(
            len(path.name.split(".")) > 2
        ),

        "contains_payment_keyword": int(
            any(
                word in filename
                for word in [
                    "payment",
                    "invoice",
                    "receipt",
                    "verify",
                    "refund",
                    "bank",
                    "account",
                ]
            )
        ),

        "contains_urgent_keyword": int(
            any(
                word in filename
                for word in [
                    "urgent",
                    "important",
                    "warning",
                    "update",
                    "security",
                ]
            )
        ),

        "entropy": calculate_entropy(data),

        "ascii_ratio": (
            sum(
                32 <= byte <= 126
                for byte in data
            )
            / len(data)
            if data
            else 0
        ),

        "sha256_length": len(sha256),
    }

    return features