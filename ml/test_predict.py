from pathlib import Path

from ml.predict import predict_file


PROJECT_ROOT = Path(__file__).resolve().parents[1]

TEST_FILES = [
    PROJECT_ROOT / "samples" / "safe_test" / "hello.txt",
    PROJECT_ROOT / "samples" / "safe_test" / "photo.jpg",
    PROJECT_ROOT / "samples" / "suspicious_test" / "document.txt",
    PROJECT_ROOT / "samples" / "suspicious_test" / "invoice.pdf.exe",
    PROJECT_ROOT / "samples" / "suspicious_test" / "update.ps1",
]


def main():

    print("=" * 60)
    print("KhmerShield-AI ML Prediction Test")
    print("=" * 60)

    for file_path in TEST_FILES:

        result = predict_file(str(file_path))

        print()
        print(f"File: {file_path.name}")
        print(f"Verdict: {result['verdict']}")
        print(
            f"Suspicious probability: "
            f"{result['suspicious_probability']:.2%}"
        )


if __name__ == "__main__":
    main()