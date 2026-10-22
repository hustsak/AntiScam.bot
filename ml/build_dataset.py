from pathlib import Path
import pandas as pd

from ml.features import extract_features


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SAFE_DIR = PROJECT_ROOT / "samples" / "safe_test"
SUSPICIOUS_DIR = PROJECT_ROOT / "samples" / "suspicious_test"

OUTPUT = PROJECT_ROOT / "ml" / "dataset.csv"


def collect_files(directory, label):
    rows = []

    for file_path in directory.rglob("*"):

        if not file_path.is_file():
            continue

        try:
            features = extract_features(
                str(file_path)
            )

            features["label"] = label
            features["filename"] = file_path.name

            rows.append(features)

        except Exception as e:
            print(
                f"Skipped {file_path}: {e}"
            )

    return rows


def main():

    rows = []

    # SAFE = 0
    rows.extend(
        collect_files(
            SAFE_DIR,
            0
        )
    )

    # SUSPICIOUS = 1
    rows.extend(
        collect_files(
            SUSPICIOUS_DIR,
            1
        )
    )

    df = pd.DataFrame(rows)

    df.to_csv(
        OUTPUT,
        index=False
    )

    print()
    print("=" * 60)
    print("KhmerShield-AI ML Dataset")
    print("=" * 60)
    print(f"Samples: {len(df)}")
    print()
    print(df["label"].value_counts())
    print()
    print(f"Saved: {OUTPUT}")


if __name__ == "__main__":
    main()