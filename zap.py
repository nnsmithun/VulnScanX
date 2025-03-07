from zapv2 import ZAPv2
import time
import json
import requests

# ZAP Configuration
ZAP_API_KEY = "ia1oiksa776kva4un204hjhm9f"
TARGET_URL = " http://www.webscantest.com"
ZAP_PROXY = "http://127.0.0.1:8080"

# Gemini API Key (Replace this)
GEMINI_API_KEY = "AIzaSyAozqwsB9_FD0EGaj-FGTd8o7gnx8tXjpw"

zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

# 1️⃣ Spider (Explore App)
print("Starting Spider...")
scan_id = zap.spider.scan(TARGET_URL)
while int(zap.spider.status(scan_id)) < 100:
    print(f"Spider progress: {zap.spider.status(scan_id)}%")
    time.sleep(5)
print("Spider completed!")

# 2️⃣ Passive Scan
print("Waiting for Passive Scan to complete...")
while int(zap.pscan.records_to_scan) > 0:
    print(f"Records remaining: {zap.pscan.records_to_scan}")
    time.sleep(5)
print("Passive Scan completed!")

# 3️⃣ Active Scan
print("Starting Active Scan...")
scan_id = zap.ascan.scan(TARGET_URL)
while int(zap.ascan.status(scan_id)) < 100:
    print(f"Active Scan progress: {zap.ascan.status(scan_id)}%")
    time.sleep(10)
print("Active Scan completed!")

# 4️⃣ Fetch Scan Results
print("Fetching vulnerabilities...")
alerts = zap.core.alerts(baseurl=TARGET_URL)

# Save scan results as JSON
with open("zap_report.json", "w") as f:
    json.dump(alerts, f, indent=4)

print("Scan results saved to zap_report.json")

# 5️⃣ Generate AI Security Report using Gemini API
def generate_ai_report(vulnerabilities):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flask:generateContent?key={GEMINI_API_KEY}"
    
    # Prompt for AI report
    prompt = f"""
    You are a cybersecurity expert. Analyze the following vulnerability scan results from OWASP ZAP 
    and generate a professional security report. Provide a summary, list vulnerabilities by severity, 
    and suggest remediation steps.

    Vulnerabilities Data:
    {json.dumps(vulnerabilities, indent=4)}

    Format the report with clear headings, bullet points, and recommendations.
    """

    # API Request payload
    data = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }

    headers = {"Content-Type": "application/json"}
    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 200:
        report = response.json()
        return report.get("candidates", [{}])[0].get("content", "No response from Gemini API")
    else:
        return f"Error {response.status_code}: {response.text}"

print("Generating AI-powered security report...")
ai_report = generate_ai_report(alerts)

# Save AI-generated report as text
with open("security_report.txt", "w") as f:
    f.write(ai_report)

print("AI-generated security report saved to security_report.txt")