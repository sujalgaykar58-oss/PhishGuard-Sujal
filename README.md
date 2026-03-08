# 🛡️ PhishGuard — Phishing Page Detector
Built by **Sujal**

A full-stack cybersecurity tool to detect phishing URLs using pattern analysis.

## 📁 Project Structure
- `index.html` — Frontend (open in browser)
- `app.py` — Flask Backend API
- `requirements.txt` — Python dependencies

## 🔍 What We Detect
- IP Address URLs
- Fake brand names (paypa1, g00gle)
- Suspicious TLDs (.tk, .ml, .xyz)
- No HTTPS / insecure connections
- @ symbol redirect trick
- URL shorteners
- Punycode/homoglyph attacks
- Excessive subdomains

## 📊 Verdict Scoring
- 0-19 → ✅ SAFE
- 20-49 → ⚠️ SUSPICIOUS
- 50+ → 🚨 DANGER / PHISHING

## 🛠️ Tech Stack
- Frontend: HTML5, CSS3, JavaScript
- Backend: Python 3, Flask

## 🚀 How to Run
Open `index.html` in browser — works standalone!

## ⚠️ Disclaimer
For educational purposes only.
