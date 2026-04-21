import math
import os
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
from flask import Flask, render_template, request

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
PIPELINE_FILENAME = BASE_DIR / "phishing_url_pipeline.joblib"

pipeline = None


def load_pipeline():
    if not PIPELINE_FILENAME.exists():
        return None

    try:
        return joblib.load(PIPELINE_FILENAME)
    except Exception as exc:
        print(f"Failed to load pipeline: {exc}")
        return None


pipeline = load_pipeline()


def normalize_url(url: str) -> str:
    if not url:
        return ""

    return url.strip()


def extract_risk_flags(url: str) -> list[str]:
    flags = []
    lowered = url.lower().strip()
    parsed = urlparse(lowered if re.match(r"^[a-zA-Z]+://", lowered) else f"http://{lowered}")
    hostname = parsed.netloc or parsed.path.split("/")[0]
    path_and_query = f"{parsed.path}?{parsed.query}"

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
        flags.append("Uses a raw IP address instead of a normal domain.")
    if "@" in lowered:
        flags.append("Contains '@', which can hide the real destination.")
    if hostname.count(".") >= 3:
        flags.append("Has many subdomains, which is common in deceptive URLs.")
    if len(lowered) > 75:
        flags.append("The URL is unusually long.")
    if re.search(r"(login|verify|update|secure|banking|confirm|signin|password)", path_and_query):
        flags.append("Contains urgency or credential-themed keywords.")
    if re.search(r"https?.*https", lowered) or "http-" in lowered or "https-" in lowered:
        flags.append("Looks like it is trying to imitate a trusted protocol string.")
    if hostname.count("-") >= 3:
        flags.append("Contains multiple hyphens, often used in spoofed domains.")

    return flags[:4]


def margin_to_confidence(score: float) -> int:
    probability_like = 1.0 / (1.0 + math.exp(-abs(score)))
    return max(50, min(99, int(round(probability_like * 100))))


def predict_url(url: str) -> dict:
    normalized_url = normalize_url(url)
    if not normalized_url:
        return {
            "error": "Please enter a valid website URL.",
            "url": "",
            "prediction": "",
            "confidence": None,
            "risk_flags": [],
            "is_phishing": None,
            "status_label": "",
        }

    if pipeline is None:
        return {
            "error": "Model file missing. Run train_model.py to generate phishing_url_pipeline.joblib.",
            "url": normalized_url,
            "prediction": "",
            "confidence": None,
            "risk_flags": [],
            "is_phishing": None,
            "status_label": "",
        }

    prediction = pipeline.predict([normalized_url])[0]
    score = 0.0
    if hasattr(pipeline, "decision_function"):
        raw_score = pipeline.decision_function([normalized_url])[0]
        score = float(raw_score[0] if hasattr(raw_score, "__len__") else raw_score)

    is_phishing = prediction == "bad"
    confidence = margin_to_confidence(score)
    is_uncertain = abs(score) < 0.8

    if is_phishing and is_uncertain:
        prediction_text = "Suspicious URL, manual review advised"
        status_label = "Needs Review"
    elif is_phishing:
        prediction_text = "Potential phishing website"
        status_label = "High Risk"
    elif is_uncertain:
        prediction_text = "Likely legitimate, but confidence is limited"
        status_label = "Moderate Confidence"
    else:
        prediction_text = "Likely legitimate website"
        status_label = "Lower Risk"

    return {
        "error": "",
        "url": normalized_url,
        "prediction": prediction_text,
        "confidence": confidence,
        "risk_flags": extract_risk_flags(normalized_url),
        "is_phishing": is_phishing,
        "status_label": status_label,
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result = {
        "error": "",
        "url": "",
        "prediction": "",
        "confidence": None,
        "risk_flags": [],
        "is_phishing": None,
        "status_label": "",
    }

    if request.method == "POST":
        url = request.form.get("url", "")
        result = predict_url(url)

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
