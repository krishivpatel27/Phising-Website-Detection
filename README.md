# PhishGuard — Phishing Website Detector

A machine learning web application that analyzes URLs in real-time and classifies them as **Phishing** or **Legitimate** using a trained Random Forest model.

---

## Overview

PhishGuard extracts up to 25 URL and page-level features from a submitted link, runs them through a pre-trained Random Forest classifier, and returns a prediction with a confidence score, risk level, and a human-readable list of suspicious (or trustworthy) characteristics.

---

## Project Structure

```
Phising-website-detection/
├── app.py                   # Flask backend — prediction API & static file serving
├── feature_extractor.py     # Live feature extraction logic
├── requirements.txt         # Python dependencies
├── models/
│   └── random_forest_model.pkl   # Pre-trained Random Forest model
├── frontend/
│   ├── index.html           # UI — single-page scanner interface
│   ├── script.js            # Frontend logic (form submission, result rendering)
│   └── styles.css           # Styling
├── dataset/
│   ├── Dataset Phising Website.xls    # Raw dataset
│   └── preprocessed_data.xls         # Cleaned/processed dataset
├── notebook/
│   ├── preprocessing.ipynb           # Data preprocessing steps
│   ├── init-model-training.ipynb     # Initial model training
│   └── retraining.ipynb              # Model retraining experiments
└── result/
    └── final_csv.xls        # Final processed results used for training
```

---

## Features Extracted

The model uses 25 features derived from the URL structure and page content:

| Feature | Description |
|---|---|
| `having_IP_Address` | Whether the URL uses a raw IP address |
| `URL_Length` | Length of the URL (short / medium / long) |
| `Shortining_Service` | Whether a URL shortener (bit.ly, tinyurl, etc.) is used |
| `having_At_Symbol` | Presence of `@` in the URL |
| `Prefix_Suffix` | Hyphens (`-`) in the domain name |
| `having_Sub_Domain` | Number of subdomains |
| `SSLfinal_State` | Whether the page is served over HTTPS |
| `Domain_registeration_length` | Domain registration duration |
| `HTTPS_token` | Whether "https" appears in the domain itself |
| `Request_URL` | Ratio of external resources loaded |
| `URL_of_Anchor` | Ratio of suspicious anchor `<a href>` links |
| `Links_in_tags` | Ratio of external `<link>` / `<script>` / `<meta>` tags |
| `SFH` | Server Form Handler — where form data is sent |
| `Submitting_to_email` | Whether any form submits via `mailto:` |
| `Abnormal_URL` | Whether the domain name appears in the URL |
| `Redirect` | Number of redirects |
| `on_mouseover` | Status bar manipulation via mouseover events |
| `popUpWidnow` | Presence of pop-up windows |
| `age_of_domain` | Age of the registered domain |
| `DNSRecord` | Whether a valid DNS record exists |
| `web_traffic` | Site traffic rank |
| `Page_Rank` | Google PageRank score |
| `Google_Index` | Whether the page is indexed by Google |
| `Links_pointing_to_page` | Number of external links pointing to the page |
| `Statistical_report` | Whether the host is flagged in known phishing reports |

Feature values are encoded as `1` (legitimate), `0` (suspicious), or `-1` (phishing indicator).

---

## Risk Classification

| Phishing Probability | Prediction | Risk Level |
|---|---|---|
| ≥ 80% | Phishing | Critical |
| 60–79% | Phishing | High |
| 40–59% | Legitimate | Medium |
| < 40% | Legitimate | Low |

---

## Installation

**Requirements:** Python 3.8+

1. Clone or download the repository.

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the Flask server:
   ```bash
   python app.py
   ```

4. Open your browser and go to:
   ```
   http://localhost:5000
   ```

---

## Usage

1. Enter any URL into the input field (e.g. `https://example.com`).
2. Click **Analyze**.
3. The app will:
   - Extract features from the URL live (with a 3-second page fetch timeout)
   - Run the Random Forest model
   - Display the prediction, confidence percentage, risk level, and key identified characteristics

---

## API

The backend exposes a single endpoint:

### `POST /predict`

**Request body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "prediction": "Phishing",
  "confidence": "87%",
  "risk_level": "Critical",
  "reasons": [
    "Invalid SSL State / Missing HTTPS",
    "IP Address used in URL",
    "Short Domain Registration Length"
  ]
}
```

---

## Model

The classifier is a **Random Forest** model trained on a labeled phishing website dataset. The pre-trained model is stored at `models/random_forest_model.pkl` and loaded at server startup via `joblib`.

To retrain or experiment with the model, refer to the Jupyter notebooks in the `notebook/` directory:

- `preprocessing.ipynb` — data cleaning and feature engineering
- `init-model-training.ipynb` — initial model training and evaluation
- `retraining.ipynb` — retraining experiments and comparisons

---

## Dependencies

```
flask
flask-cors
pandas
scikit-learn
requests
beautifulsoup4
tldextract
joblib
```

---

## Notes

- Features that require live DNS lookups, WHOIS data, or traffic rank APIs (e.g. `age_of_domain`, `web_traffic`, `Page_Rank`) are defaulted to `1` (legitimate) during live extraction to keep response times fast. These were used during training from the dataset but are not actively queried at runtime.
- If the page fetch times out or fails, `SSLfinal_State` and `URL_of_Anchor` are set to `-1` (phishing indicator), as unreachable pages are a common characteristic of phishing sites.
