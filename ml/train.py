from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET = PROJECT_ROOT / "ml" / "dataset.csv"
MODEL_OUTPUT = PROJECT_ROOT / "ml" / "model.joblib"


FEATURE_COLUMNS = [
    "file_size",
    "filename_length",
    "extension_length",
    "is_executable",
    "has_double_extension",
    "contains_payment_keyword",
    "contains_urgent_keyword",
    "entropy",
    "ascii_ratio",
    "sha256_length",
]


def main():

    print("=" * 60)
    print("KhmerShield-AI ML Training")
    print("=" * 60)

    df = pd.read_csv(DATASET)

    print(f"Dataset samples: {len(df)}")

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    print()
    print("Label distribution:")
    print(y.value_counts())

    # Temporary development model.
    # Do NOT treat its accuracy as meaningful with only 5 samples.
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced"
    )

    model.fit(X, y)

    joblib.dump(
        {
            "model": model,
            "features": FEATURE_COLUMNS,
        },
        MODEL_OUTPUT
    )

    print()
    print("Model trained successfully.")
    print(f"Saved: {MODEL_OUTPUT}")
    print()
    print("WARNING:")
    print("This model is only a pipeline test.")
    print("The current dataset is too small for real-world predictions.")


if __name__ == "__main__":
    main()