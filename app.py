import os
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
from flask import Flask, render_template, request

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
PIPELINE_FILENAME = BASE_DIR / "phishing_url_pipeline.joblib"
TRUSTED_DOMAINS = {
    "google.com",
    "microsoft.com",
    "openai.com",
    "wikipedia.org",
    "github.com",
    "amazon.in",
    "amazon.com",
    "facebook.com",
    "youtube.com",
    "apple.com",
    "linkedin.com",
}

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

    cleaned = url.strip()
    cleaned = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE)
    return cleaned.rstrip("/")


def parse_parts(url: str) -> tuple[str, str, str]:
    lowered = url.lower().strip()
    parsed = urlparse(lowered if re.match(r"^[a-zA-Z]+://", lowered) else f"http://{lowered}")
    hostname = (parsed.netloc or parsed.path.split("/")[0]).strip(".")
    path = parsed.path if parsed.netloc else "/" + "/".join(parsed.path.split("/")[1:])
    query = parsed.query
    return hostname, path or "/", query


def extract_risk_flags(url: str) -> list[str]:
    flags = []
    lowered = url.lower().strip()
    hostname, path, query = parse_parts(lowered)
    path_and_query = f"{path}?{query}"

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


def get_model_score(url: str) -> float:
    if pipeline is None or not hasattr(pipeline, "decision_function"):
        return 0.0

    raw_score = pipeline.decision_function([url])[0]
    return float(raw_score[0] if hasattr(raw_score, "__len__") else raw_score)


def build_verdict(url: str, score: float, risk_flags: list[str]) -> tuple[str, str, str]:
    hostname, path, query = parse_parts(url)
    base_hostname = hostname[4:] if hostname.startswith("www.") else hostname
    clean_root_domain = path in ("", "/") and not query
    flag_count = len(risk_flags)

    if base_hostname in TRUSTED_DOMAINS and flag_count == 0:
        return "Good", "This website looks safe for normal browsing.", "safe"

    if flag_count >= 2 or score <= -1.35:
        return "Bad", "This website shows strong phishing-like behavior.", "risk"

    if clean_root_domain and flag_count == 0 and score >= -0.45:
        return "Good", "This website looks safe for normal browsing.", "safe"

    if clean_root_domain and flag_count <= 1:
        return "Medium", "This website is not clearly dangerous, but it should be checked carefully.", "medium"

    if flag_count == 0 and score >= 0.25:
        return "Good", "This website looks safe for normal browsing.", "safe"

    return "Medium", "The website needs manual review before it can be trusted.", "medium"


def predict_url(url: str) -> dict:
    normalized_url = normalize_url(url)
    if not normalized_url:
        return {
            "error": "Please enter a valid website URL.",
            "url": "",
            "verdict": "",
            "summary": "",
            "risk_flags": [],
            "card_tone": "",
        }

    if pipeline is None:
        return {
            "error": "Model file missing. Run train_model.py to generate phishing_url_pipeline.joblib.",
            "url": normalized_url,
            "verdict": "",
            "summary": "",
            "risk_flags": [],
            "card_tone": "",
        }

    risk_flags = extract_risk_flags(normalized_url)
    score = get_model_score(normalized_url)
    verdict, summary, card_tone = build_verdict(normalized_url, score, risk_flags)

    return {
        "error": "",
        "url": normalized_url,
        "verdict": verdict,
        "summary": summary,
        "risk_flags": risk_flags,
        "card_tone": card_tone,
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result = {
        "error": "",
        "url": "",
        "verdict": "",
        "summary": "",
        "risk_flags": [],
        "card_tone": "",
    }

    if request.method == "POST":
        url = request.form.get("url", "")
        result = predict_url(url)

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
