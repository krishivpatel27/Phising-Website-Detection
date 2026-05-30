import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
import pandas as pd

def extract_features_live(url):
    """
    Live extracts top features from a URL for the Random Forest model.
    Defaults less important or highly dynamic/network-heavy features to 1 (Legitimate).
    """
    if not url.startswith('http'):
        url = 'http://' + url
        
    url_lower = url.lower()
    parsed = urlparse(url)
    domain = parsed.netloc
    extracted = tldextract.extract(url)
    full_domain = f"{extracted.domain}.{extracted.suffix}"
    
    # Initialize all 25 features to 1 (Legitimate/Neutral)
    features = {
        'having_IP_Address': 1,
        'URL_Length': 1,
        'Shortining_Service': 1,
        'having_At_Symbol': 1,
        'Prefix_Suffix': 1,
        'having_Sub_Domain': 1,
        'SSLfinal_State': 1,
        'Domain_registeration_length': 1,
        'HTTPS_token': 1,
        'Request_URL': 1,
        'URL_of_Anchor': 1,
        'Links_in_tags': 1,
        'SFH': 1,
        'Submitting_to_email': 1,
        'Abnormal_URL': 1,
        'Redirect': 1,
        'on_mouseover': 1,
        'popUpWidnow': 1,
        'age_of_domain': 1,
        'DNSRecord': 1,
        'web_traffic': 1,
        'Page_Rank': 1,
        'Google_Index': 1,
        'Links_pointing_to_page': 1,
        'Statistical_report': 1
    }

    # 1. having_IP_Address
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        features['having_IP_Address'] = -1
        
    # 2. URL_Length
    if len(url) < 54:
        features['URL_Length'] = 1
    elif len(url) <= 75:
        features['URL_Length'] = 0
    else:
        features['URL_Length'] = -1
        
    # 3. Shortining_Service
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'cli.gs']
    if any(short in domain for short in shorteners):
        features['Shortining_Service'] = -1

    # 4. having_At_Symbol
    if '@' in url:
        features['having_At_Symbol'] = -1
        
    # 5. Prefix_Suffix
    if '-' in extracted.domain:
        features['Prefix_Suffix'] = -1

    # 6. having_Sub_Domain
    subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
    if len(subdomains) == 0 or len(subdomains) == 1:
        features['having_Sub_Domain'] = 1
    elif len(subdomains) == 2:
        features['having_Sub_Domain'] = 0
    else:
        features['having_Sub_Domain'] = -1

    # 9. HTTPS_token
    if 'https' in domain:
        features['HTTPS_token'] = -1

    # 15. Abnormal_URL
    if extracted.domain not in url_lower:
        features['Abnormal_URL'] = -1

    # Attempt to fetch page content (3-second timeout)
    try:
        response = requests.get(url, timeout=3, allow_redirects=True)
        
        # 7. SSLfinal_State (35% importance)
        if response.url.startswith('https://'):
            features['SSLfinal_State'] = 1
        else:
            features['SSLfinal_State'] = -1

        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 11. URL_of_Anchor (25% importance)
        anchors = soup.find_all('a', href=True)
        suspicious_anchors = 0
        for a in anchors:
            href = a['href'].lower()
            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:') or (full_domain not in href and href.startswith('http')):
                suspicious_anchors += 1
        
        if len(anchors) > 0:
            anchor_percentage = suspicious_anchors / len(anchors)
            if anchor_percentage < 0.31:
                features['URL_of_Anchor'] = 1
            elif anchor_percentage <= 0.67:
                features['URL_of_Anchor'] = 0
            else:
                features['URL_of_Anchor'] = -1

        # 12. Links_in_tags
        tags = soup.find_all(['link', 'script', 'meta'])
        suspicious_tags = 0
        for tag in tags:
            src = tag.get('src') or tag.get('href')
            if src and full_domain not in src.lower() and src.lower().startswith('http'):
                suspicious_tags += 1
                
        if len(tags) > 0:
            tag_percentage = suspicious_tags / len(tags)
            if tag_percentage < 0.17:
                features['Links_in_tags'] = 1
            elif tag_percentage <= 0.81:
                features['Links_in_tags'] = 0
            else:
                features['Links_in_tags'] = -1

        # 13. SFH
        forms = soup.find_all('form', action=True)
        for form in forms:
            action = form['action'].lower()
            if action == "" or action == "about:blank":
                features['SFH'] = -1
            elif full_domain not in action and action.startswith('http'):
                features['SFH'] = 0

        # 14. Submitting_to_email
        if 'mailto:' in response.text.lower():
            features['Submitting_to_email'] = -1

    except Exception as e:
        # If the request fails or times out, assume the worst for SSL and Anchors 
        # since it's unreachable or actively blocking scraping (common in phishing).
        print(f"Scraping failed for {url}: {e}")
        features['SSLfinal_State'] = -1
        features['URL_of_Anchor'] = -1

    # Convert features to a pandas DataFrame so we have the exact column names the model expects
    df_features = pd.DataFrame([features])
    return df_features
