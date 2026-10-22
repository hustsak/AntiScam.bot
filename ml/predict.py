from pathlib import Path

import joblib
import pandas as pd

from ml.features import extract_features


PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = PROJECT_ROOT / "ml" / "model.joblib"


def predict_file(file_path: str) -> dict:

    package = joblib.load(MODEL_PATH)

    model = package["model"]
    feature_columns = package["features"]

    features = extract_features(file_path)

    X = pd.DataFrame(
        [[features[column] for column in feature_columns]],
        columns=feature_columns
    )

    prediction = int(model.predict(X)[0])

    probabilities = model.predict_proba(X)[0]

    probability_map = {
        int(label): float(probability)
        for label, probability
        in zip(model.classes_, probabilities)
    }

    suspicious_probability = probability_map.get(1, 0.0)

    if prediction == 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "prediction": prediction,
        "verdict": verdict,
        "suspicious_probability": round(
            suspicious_probability,
            4
        ),
    }