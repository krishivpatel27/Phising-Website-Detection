import os
import random
import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from feature_extractor import extract_features_live

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)

@app.route('/')
def index():
    return app.send_static_file('index.html')

# Load the model
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models', 'random_forest_model.pkl')
try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

# Mapping of feature names to human-readable negative reasons
REASON_MAPPING = {
    'having_IP_Address': 'IP Address used in URL',
    'URL_Length': 'Suspicious URL Length',
    'Shortining_Service': 'URL Shortening Service Used',
    'having_At_Symbol': 'Contains @ Symbol in URL',
    'Prefix_Suffix': 'Prefix or Suffix (dash) in Domain',
    'having_Sub_Domain': 'Suspicious Subdomain usage',
    'SSLfinal_State': 'Invalid SSL State / Missing HTTPS',
    'Domain_registeration_length': 'Short Domain Registration Length',
    'HTTPS_token': 'HTTPS token in Domain name',
    'Request_URL': 'High ratio of external objects loaded',
    'URL_of_Anchor': 'Suspicious Anchor URLs',
    'Links_in_tags': 'Suspicious Links in HTML tags',
    'SFH': 'Suspicious Server Form Handler (SFH)',
    'Submitting_to_email': 'Information submitted directly to Email',
    'Abnormal_URL': 'Abnormal URL Structure',
    'Redirect': 'Unusual Redirects',
    'on_mouseover': 'Status Bar Customized via Mouseover',
    'popUpWidnow': 'Uses Pop-up Windows',
    'age_of_domain': 'Newly Registered Domain',
    'DNSRecord': 'No valid DNS Records',
    'web_traffic': 'Low Web Traffic',
    'Page_Rank': 'Low Page Rank',
    'Google_Index': 'Not Indexed by Google',
    'Links_pointing_to_page': 'Few or No Links Pointing to Page',
    'Statistical_report': 'Host Flagged in Statistical Reports'
}

@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({'error': 'Server model not properly initialized.'}), 500

    data = request.json
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'URL is required.'}), 400

    # Live extraction!
    try:
        features_df = extract_features_live(url)
    except Exception as e:
        print(f"Extraction error: {e}")
        return jsonify({'error': 'Failed to extract features from URL.'}), 500

    # Get model prediction and probability
    probabilities = model.predict_proba(features_df)[0]
    
    classes = list(model.classes_)
    if -1 in classes:
        phishing_idx = classes.index(-1)
        legit_idx = classes.index(1)
    else:
        phishing_idx = 1
        legit_idx = 0

    phishing_prob = probabilities[phishing_idx]
    
    # Calculate Confidence and Risk Level
    confidence = round(phishing_prob * 100)
    
    if confidence >= 80:
        prediction = "Phishing"
        risk_level = "Critical"
    elif confidence >= 60:
        prediction = "Phishing"
        risk_level = "High"
    elif confidence >= 40:
        prediction = "Legitimate"
        risk_level = "Medium"
    else:
        prediction = "Legitimate"
        risk_level = "Low"

    display_confidence = confidence if prediction == "Phishing" else round(probabilities[legit_idx] * 100)

    # Mapping for POSITIVE features (when value is 1)
    POSITIVE_REASON_MAPPING = {
        'SSLfinal_State': 'Valid SSL Certificate',
        'URL_of_Anchor': 'Safe Anchor URLs',
        'having_IP_Address': 'No IP Address in URL',
        'URL_Length': 'Standard URL Length',
        'Shortining_Service': 'No URL Shorteners Used',
        'Prefix_Suffix': 'No Suspicious Hyphens in Domain',
        'having_Sub_Domain': 'Standard Subdomain Structure',
        'Links_in_tags': 'Safe Script/Link Tags'
    }

    # Generate reasons based on the ACTUALLY EXTRACTED features
    reasons = []
    feature_series = features_df.iloc[0]
    
    if prediction == "Phishing":
        for col, value in feature_series.items():
            if value == -1 and col in REASON_MAPPING:
                reasons.append(REASON_MAPPING[col])
    else:
        # If Legitimate, show the positive things it found!
        for col, value in feature_series.items():
            if value == 1 and col in POSITIVE_REASON_MAPPING:
                reasons.append(POSITIVE_REASON_MAPPING[col])
            
    # Limit to top 5 reasons to keep UI clean
    if len(reasons) > 5:
        reasons = random.sample(reasons, 5)
    elif len(reasons) == 0 and prediction == "Phishing":
        reasons = ["Suspicious Domain Activity", "Unknown Threats Detected"]
    elif len(reasons) == 0 and prediction == "Legitimate":
        reasons = ["Website appears to be operating normally.", "No immediate threats detected."]

    return jsonify({
        'prediction': prediction,
        'confidence': f"{display_confidence}%",
        'risk_level': risk_level,
        'reasons': reasons
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
