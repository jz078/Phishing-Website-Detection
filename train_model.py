from pathlib import Path
import json
import time

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "Dataset" / "phishing_site_urls.csv"
MODEL_PATH = BASE_DIR / "phishing_url_pipeline.joblib"
METRICS_PATH = BASE_DIR / "model_metrics.json"


def build_pipeline() -> Pipeline:
    features = FeatureUnion(
        transformer_list=[
            (
                "char_tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(2, 5),
                    min_df=2,
                    sublinear_tf=True,
                    max_features=350000,
                ),
            ),
            (
                "token_tfidf",
                TfidfVectorizer(
                    analyzer="word",
                    token_pattern=r"[^\\/?=&.:_-]+",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=100000,
                ),
            ),
        ]
    )

    return Pipeline(
        steps=[
            ("features", features),
            ("classifier", LinearSVC(class_weight="balanced")),
        ]
    )


def main():
    start_time = time.time()
    dataset = pd.read_csv(DATASET_PATH).dropna(subset=["URL", "Label"])

    x_train, x_test, y_train, y_test = train_test_split(
        dataset["URL"],
        dataset["Label"],
        test_size=0.2,
        random_state=42,
        stratify=dataset["Label"],
    )

    pipeline = build_pipeline()
    pipeline.fit(x_train, y_train)

    predictions = pipeline.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)
    phishing_f1 = f1_score(y_test, predictions, pos_label="bad")
    report = classification_report(y_test, predictions, output_dict=True)

    joblib.dump(pipeline, MODEL_PATH)

    metrics = {
        "dataset_rows": int(len(dataset)),
        "train_rows": int(len(x_train)),
        "test_rows": int(len(x_test)),
        "accuracy": round(float(accuracy), 6),
        "f1_bad": round(float(phishing_f1), 6),
        "classification_report": report,
        "trained_at_epoch": int(time.time()),
        "elapsed_seconds": round(time.time() - start_time, 2),
        "model_file": MODEL_PATH.name,
    }

    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(json.dumps(metrics, indent=2))
    print(f"Saved model to {MODEL_PATH}")
    print(f"Saved metrics to {METRICS_PATH}")


if __name__ == "__main__":
    main()
