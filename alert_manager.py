import json
import os
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERT_FILE = os.path.join(BASE_DIR, "alerts.json")

def log_alert(alert_data):
    alert = {
        "time": alert_data.get("time", time.strftime("%Y-%m-%d %H:%M:%S")),
        "src_ip": alert_data.get("src_ip", "Unknown"),
        "dst_ip": alert_data.get("dst_ip", "Flask Login Server"),
        "port": alert_data.get("port", 5000),
        "attack": alert_data.get("attack", "Unknown"),
        "severity": alert_data.get("severity", "HIGH"),
        "status": alert_data.get("status", "DETECTED")
    }

    with open(ALERT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")

    print("[INFO] Alert saved to alerts.json")