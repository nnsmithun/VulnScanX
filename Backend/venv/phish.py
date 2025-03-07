# Backend: phish.py
from flask import Flask, request, jsonify
import requests
import whois
import ssl
import socket
from bs4 import BeautifulSoup
from langdetect import detect
from urllib.parse import urlparse
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# === Extract domain from URL ===
def extract_domain(url):
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc if parsed_url.netloc else parsed_url.path
    except Exception as e:
        return f"Domain extraction error: {str(e)}"

# === WHOIS Lookup ===
def get_domain_info(url):
    domain = extract_domain(url)
    try:
        domain_info = whois.whois(domain)
        return {
            "Domain Name": domain_info.domain_name,
            "Registrar": domain_info.registrar,
            "Creation Date": str(domain_info.creation_date),
            "Expiration Date": str(domain_info.expiration_date),
            "Registrant Country": domain_info.country
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}

# === Website Content Analysis ===
def analyze_website_content(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        pages = ["about", "contact"]
        missing_pages = [page for page in pages if not soup.find("a", href=lambda href: href and page in href)]
        text = soup.get_text()[:1000]
        detected_language = detect(text)

        return {
            "Missing Pages": missing_pages if missing_pages else "None",
            "Detected Language": detected_language
        }
    except Exception as e:
        return {"error": f"Content analysis failed: {str(e)}"}

# === SSL Certificate Check ===
def check_ssl_certificate(url):
    domain = extract_domain(url)
    try:
        context = ssl.create_default_context()
        ip_address = socket.gethostbyname(domain)
        with socket.create_connection((ip_address, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(item[0] for item in cert.get("issuer", []))
                return {"SSL Issuer": issuer.get("organizationName", "Unknown")}
    except Exception as e:
        return {"error": f"SSL check failed: {str(e)}"}

# === Classify Website ===
def classify_website(result):
    whois_info = result.get("WHOIS Info", {})
    content_analysis = result.get("Website Content Analysis", {})
    ssl_info = result.get("SSL Certificate Info", {})

    is_suspicious = False
    reasons = []

    if "error" in whois_info:
        is_suspicious = True
        reasons.append(whois_info["error"])
    elif not whois_info.get("Registrar"):
        is_suspicious = True
        reasons.append("Domain has no registrar information.")
    elif "Creation Date" in whois_info and "Expiration Date" in whois_info:
        try:
            creation_date = datetime.strptime(whois_info["Creation Date"][:10], "%Y-%m-%d")
            expiration_date = datetime.strptime(whois_info["Expiration Date"][:10], "%Y-%m-%d")
            if (datetime.now() - creation_date).days < 365:
                is_suspicious = True
                reasons.append("Domain is newly registered (less than a year old).")
            if expiration_date < datetime.now():
                is_suspicious = True
                reasons.append("Domain is expired.")
        except:
            pass

    if isinstance(content_analysis, dict) and "Missing Pages" in content_analysis:
        if content_analysis["Missing Pages"] != "None":
            is_suspicious = True
            reasons.append(f"Missing important pages: {', '.join(content_analysis['Missing Pages'])}")

    if "error" in ssl_info:
        is_suspicious = True
        reasons.append(ssl_info["error"])

    return {"status": "Phishing", "reasons": reasons} if is_suspicious else {"status": "Legitimate"}

# === Flask API Route ===
@app.route('/api/check-url', methods=['POST'])
def check_url():
    try:
        data = request.json
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL is required"}), 400

        result = {
            "WHOIS Info": get_domain_info(url),
            "Website Content Analysis": analyze_website_content(url),
            "SSL Certificate Info": check_ssl_certificate(url),
        }
        
        classification = classify_website(result)
        result["Final Classification"] = classification

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5002)  # Changed to port 5002
