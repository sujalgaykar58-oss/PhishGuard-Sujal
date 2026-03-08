
"""
PhishGuard - Phishing Page Detector
Flask Backend API
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import urllib.parse
import socket

app = Flask(__name__)
CORS(app)

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'banking', 'paypal', 'amazon', 'google', 'microsoft', 'apple',
    'netflix', 'facebook', 'password', 'confirm', 'wallet', 'crypto'
]

BRAND_SPOOF = [
    'paypa1', 'g00gle', 'amaz0n', 'micros0ft', 'app1e', 'netf1ix',
    'faceb00k', 'lnstagram', 'paypai', 'arnazon', 'miicrosoft'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
    '.loan', '.download', '.accountant', '.stream', '.gdn', '.bid'
]

TRUSTED_DOMAINS = [
    'google.com', 'gmail.com', 'youtube.com', 'facebook.com',
    'amazon.com', 'microsoft.com', 'apple.com', 'github.com',
    'wikipedia.org', 'reddit.com', 'twitter.com', 'linkedin.com'
]

URL_SHORTENERS = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']

def analyze_url(url: str) -> dict:
    risk_score = 0
    flags = []
    info = []
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ''
    except Exception:
        return {'verdict': 'danger', 'score': 90, 'flags': [{'color': 'red', 'label': 'INVALID URL', 'detail': 'Cannot parse URL structure'}], 'info': []}
    full_url = url.lower()
    hostname = hostname.lower()
    is_trusted = any(hostname == d or hostname.endswith('.' + d) for d in TRUSTED_DOMAINS)
    if is_trusted:
        info.append({'color': 'green', 'label': 'TRUSTED DOMAIN', 'detail': 'Known legitimate website'})
    if parsed.scheme == 'http':
        risk_score += 20
        flags.append({'color': 'yellow', 'label': 'NO HTTPS', 'detail': 'Connection is not encrypted'})
    else:
        info.append({'color': 'green', 'label': 'HTTPS SECURE', 'detail': 'Encrypted connection detected'})
    if re.compile(r'^(\d{1,3}\.){3}\d{1,3}$').match(hostname):
        risk_score += 40
        flags.append({'color': 'red', 'label': 'IP ADDRESS URL', 'detail': 'Legitimate sites use domain names'})
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            risk_score += 25
            flags.append({'color': 'red', 'label': 'SUSPICIOUS TLD', 'detail': f'"{tld}" commonly used in phishing'})
            break
    for spoof in BRAND_SPOOF:
        if spoof in hostname:
            risk_score += 50
            flags.append({'color': 'red', 'label': 'BRAND SPOOFING', 'detail': f'Fake brand detected: "{spoof}"'})
            break
    parts = hostname.split('.')
    if len(parts) - 2 > 2:
        risk_score += 15
        flags.append({'color': 'yellow', 'label': 'EXCESSIVE SUBDOMAINS', 'detail': 'Too many subdomains'})
    if not is_trusted:
        found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
        if len(found_kw) >= 2:
            risk_score += min(len(found_kw) * 8, 30)
            flags.append({'color': 'yellow', 'label': 'SUSPICIOUS KEYWORDS', 'detail': f'Found: {", ".join(found_kw[:3])}'})
    if len(url) > 100:
        risk_score += 15
        flags.append({'color': 'yellow', 'label': 'LONG URL', 'detail': 'Hides true destination'})
    if '@' in url:
        risk_score += 35
        flags.append({'color': 'red', 'label': '@ SYMBOL DETECTED', 'detail': 'Classic phishing redirect trick'})
    if 'xn--' in url:
        risk_score += 30
        flags.append({'color': 'red', 'label': 'PUNYCODE DETECTED', 'detail': 'Possible homoglyph domain'})
    if any(s in hostname for s in URL_SHORTENERS):
        risk_score += 20
        flags.append({'color': 'yellow', 'label': 'URL SHORTENER', 'detail': 'Hides the real destination'})
    if is_trusted:
        risk_score = max(0, risk_score - 40)
    risk_score = min(risk_score, 100)
    verdict = 'danger' if risk_score >= 50 else 'warning' if risk_score >= 20 else 'safe'
    if not flags and verdict == 'safe':
        info.append({'color': 'green', 'label': 'NO THREATS FOUND', 'detail': 'URL appears clean'})
    return {'verdict': verdict, 'score': risk_score, 'flags': flags, 'info': info, 'url': url}

@app.route('/')
def home():
    return jsonify({'message': 'PhishGuard API is running', 'version': '1.0'})

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Please provide a URL'}), 400
    result = analyze_url(data['url'].strip())
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

Copy karke paste karo, phir **"Commit changes"** click karo! ✅
