# Phishing Website Detection

A final year machine learning project that detects whether a submitted website URL is likely to be a phishing website or a legitimate one.

This project includes:
- a Flask-based web application
- an upgraded machine learning pipeline for URL classification
- a modern UI for live phishing checks
- a reproducible training script for retraining the model

## Team

Built by:
- Jishu Mahato
- Harsh Raj
- Karan Shaw
- Bidyut Maji

## Project Overview

Phishing websites often imitate trusted brands, login portals, banking pages, and payment gateways to trick users into entering sensitive information. This project focuses on phishing detection from URL patterns using machine learning.

The user enters a URL in the web interface, and the application predicts whether the URL is:
- `Potential phishing website`
- `Likely legitimate website`
- or a lower-confidence review state when the model is less certain

The application also displays:
- a confidence score
- risk hints based on suspicious URL patterns
- a clean demo-friendly interface for project presentation

## ML Model

The project was improved from a weaker baseline model to a stronger Support Vector Machine based pipeline.

Current pipeline:
- `FeatureUnion`
- character-level `TF-IDF`
- token-level `TF-IDF`
- `LinearSVC` classifier with class balancing

Why this model:
- phishing URLs often contain suspicious character patterns, obfuscated text, spoofed brand names, and deceptive path structures
- character n-grams capture subtle URL manipulation
- token features capture suspicious words like `login`, `verify`, `secure`, and related patterns
- `LinearSVC` performed significantly better than the earlier baseline models on the dataset

## Model Performance

The upgraded model was trained on the dataset in `Dataset/phishing_site_urls.csv`.

Held-out test metrics:
- Accuracy: `98.8241%`
- Phishing class F1 score: `0.979374`

Saved evaluation output is available in:
- `model_metrics.json`

## Project Structure

```text
Phishing-Website-Detection/
|-- app.py
|-- train_model.py
|-- requirements.txt
|-- run.bat
|-- model_metrics.json
|-- phishing_url_pipeline.joblib
|-- templates/
|   |-- index.html
|-- Dataset/
|   |-- phishing_site_urls.csv
|-- Phishing website detection system.ipynb
|-- word2vec.ipynb
```

## Features

- Detects phishing websites from URL input
- Uses an upgraded machine learning model
- Displays confidence score
- Shows suspicious URL hints
- Includes hidden developer credits in the UI
- Works locally through Flask
- Can be deployed on Render

## Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/jz078/Phishing-Website-Detection.git
cd Phishing-Website-Detection
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the application

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Quick Start on Windows

You can also run the project using:

```text
run.bat
```

This batch file:
- installs required dependencies
- starts the Flask application

## Retraining the Model

To retrain the phishing detection model:

```bash
python train_model.py
```

This will generate:
- `phishing_url_pipeline.joblib`
- `model_metrics.json`

## Render Deployment

This project can be deployed on Render as a Python web service.

Recommended settings:
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn app:app`

For deployment, make sure `gunicorn` is included in `requirements.txt`.

## Important Notes

- This project is primarily a URL-based phishing detector.
- URL-only detection is useful, but no phishing model is perfect.
- Some legitimate domains may still fall into a lower-confidence review state.
- For real-world production-grade protection, URL analysis should be combined with SSL checks, domain age, page content analysis, and reputation services.

## Future Improvements

- Add domain age and WHOIS-based features
- Add SSL certificate checks
- Add HTML and form-based phishing indicators
- Add screenshot or visual similarity analysis
- Improve probability calibration for better confidence reporting
- Add API endpoint support for external integrations

## Tech Stack

- Python
- Flask
- scikit-learn
- pandas
- joblib
- HTML
- CSS

## License

This project is for academic and educational use.
