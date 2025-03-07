from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO
from zapv2 import ZAPv2
import time
import json
import os
from pymongo import MongoClient

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*")

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)
db = client["security_scans"]
reports_collection = db["scan_reports"]

# ZAP Configuration
ZAP_PROXY = "http://127.0.0.1:8080"
ZAP_API_KEY = "ia1oiksa776kva4un204hjhm9f"
zap = ZAPv2(apikey=ZAP_API_KEY, proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY})

# Report Storage
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_FOLDER = os.path.join(BASE_DIR, "reports")

if not os.path.exists(REPORT_FOLDER):
    os.makedirs(REPORT_FOLDER)

def send_log(message):
    """Send logs to the frontend via WebSockets"""
    socketio.emit('log', message)

@app.route('/scan', methods=['POST'])
def scan():
    """Run a security scan and store results in MongoDB"""
    data = request.json
    target_url = data.get("url")
    scan_type = data.get("scanType", "full")

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    send_log(f"Starting {scan_type} scan for {target_url}...")

    # Spider Scan
    scan_id = zap.spider.scan(target_url)
    while zap.spider.status(scan_id) != '100':
        send_log(f"Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(5)

    send_log("Spider scan completed. Starting Passive Scan...")

    # Passive Scan
    while int(zap.pscan.records_to_scan) > 0:
        send_log(f"Records remaining: {zap.pscan.records_to_scan}")
        time.sleep(5)

    send_log("Passive Scan completed.")

    # Active Scan (Only for full scan)
    if scan_type == "full":
        send_log("Starting Active Scan...")
        scan_id = zap.ascan.scan(target_url)
        
        if scan_id.isdigit():
            while zap.ascan.status(scan_id) != '100':
                send_log(f"Active Scan progress: {zap.ascan.status(scan_id)}%")
                time.sleep(10)
            send_log("Active Scan completed!")
        else:
            send_log("Error: Active scan did not start properly.")

    # Generate Report
    send_log("Fetching results...")
    alerts = zap.core.alerts(baseurl=target_url)

    if not alerts:
        send_log("No vulnerabilities found. Report not created.")
        return jsonify({"message": "Scan complete", "report": None})

    report_filename = f"zap_report_{scan_type}.json"
    report_path = os.path.join(REPORT_FOLDER, report_filename)

    with open(report_path, "w") as f:
        json.dump(alerts, f, indent=4)

    send_log(f"{scan_type.capitalize()} Scan complete! Storing report in database...")

    # Save to MongoDB
    report_data = {
        "url": target_url,
        "scanType": scan_type,
        "alerts": alerts
    }
    report_id = reports_collection.insert_one(report_data).inserted_id

    send_log("Report successfully stored in database.")

    return jsonify({
        "message": "Scan complete",
        "report": f"/download?scanType={scan_type}",
        "report_id": str(report_id)
    })

@app.route('/download', methods=['GET'])
def download_report():
    """Download the scan report"""
    scan_type = request.args.get("scanType", "full")
    report_filename = f"zap_report_{scan_type}.json"
    report_path = os.path.abspath(os.path.join(REPORT_FOLDER, report_filename))

    if not report_path.startswith(os.path.abspath(REPORT_FOLDER)):
        return jsonify({"error": "Invalid file path"}), 400

    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=True)
    
    return jsonify({"error": f"Report '{scan_type}' not found"}), 404

if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
