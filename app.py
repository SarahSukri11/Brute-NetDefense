from flask import Flask, render_template, request, redirect, url_for, session, send_file
from datetime import datetime
from flask_socketio import SocketIO
import json
import os
import csv
import threading
import time
import random
import subprocess
import sys

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOGIN_LOG_FILE = os.path.join(LOG_DIR, "login_attempts.csv")
TRAFFIC_CSV_FILE = os.path.join(LOG_DIR, "traffic_records.csv")
RESPONSE_CSV_FILE = os.path.join(LOG_DIR, "response_logs.csv")
USERS_CSV_FILE = os.path.join(LOG_DIR, "users.csv")
TRAFFIC_JSON_FILE = os.path.join(BASE_DIR, "traffic_logs.json")
ALERT_JSON_FILE = os.path.join(BASE_DIR, "alerts.json")

app.secret_key = "brutenetdefense_secret"
socketio = SocketIO(app, cors_allowed_origins="*")


class MonitorState:
    monitoring_active = False


monitor_state = MonitorState()
blocked_ips = set()
capture_process = None


def ensure_csv_headers():
    if not os.path.exists(LOGIN_LOG_FILE):
        with open(LOGIN_LOG_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "ip_address", "username", "password", "status"])

    if not os.path.exists(TRAFFIC_CSV_FILE):
        with open(TRAFFIC_CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "source_ip",
                "destination_ip",
                "destination_port",
                "protocol",
                "failed_attempt",
                "status"
            ])

    if not os.path.exists(RESPONSE_CSV_FILE):
        with open(RESPONSE_CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "source_ip",
                "attack",
                "severity",
                "action",
                "status"
            ])

    if not os.path.exists(USERS_CSV_FILE):
        with open(USERS_CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password"])
            writer.writerow(["admin", "admin123"])


ensure_csv_headers()

def is_valid_password(password):
    if len(password) < 8:
        return False

    has_letter = any(char.isalpha() for char in password)
    has_number = any(char.isdigit() for char in password)

    return has_letter and has_number


def user_exists(username):
    if not os.path.exists(USERS_CSV_FILE):
        return False

    with open(USERS_CSV_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            if row["username"] == username:
                return True

    return False


def check_user_login(username, password):
    if not os.path.exists(USERS_CSV_FILE):
        return False

    with open(USERS_CSV_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            if row["username"] == username and row["password"] == password:
                return True

    return False


def parse_report_datetime(time_value):
    if not time_value:
        return None

    time_value = str(time_value).strip()

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f"
    ]

    for fmt in formats:
        try:
            return datetime.strptime(time_value, fmt)
        except:
            pass

    try:
        return datetime.fromisoformat(time_value)
    except:
        return None

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if check_user_login(username, password):
            with open(LOGIN_LOG_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([datetime.now(), request.remote_addr, username, password, "SUCCESS"])

            session["user"] = username
            return redirect(url_for("dashboard"))

        else:
            with open(LOGIN_LOG_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([datetime.now(), request.remote_addr, username, password, "FAILED"])

            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if not username or not password:
            return render_template("register.html", error="Please fill in all fields.")

        if user_exists(username):
            return render_template("register.html", error="Username already exists.")

        if not is_valid_password(password):
            return render_template(
                "register.html",
                error="Password must be at least 8 characters and contain both letters and numbers."
            )

        with open(USERS_CSV_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([username, password])

        return render_template("register.html", success="Account created successfully. You can now login.")

    return render_template("register.html")

    
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    alerts_data = []

    if os.path.exists(ALERT_JSON_FILE):
        try:
            with open(ALERT_JSON_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        alerts_data.append(json.loads(line))
        except Exception as e:
            print("Error reading alerts:", e)

    total_packets = len(alerts_data)
    failed_attempts = len(alerts_data)
    detected_attacks = len(alerts_data)

    return render_template(
        "dashboard.html",
        total_packets=total_packets,
        failed_attempts=failed_attempts,
        detected_attacks=detected_attacks,
        monitoring_active=session.get("monitoring_active", False)
    )


@app.route("/live")
def live():
    if "user" not in session:
        return redirect(url_for("login"))

    traffic_data = []

    if os.path.exists(TRAFFIC_JSON_FILE):
        try:
            with open(TRAFFIC_JSON_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        traffic_data.append(record)
        except Exception as e:
            print("Error reading traffic logs:", e)

    return render_template("live.html", traffic_data=traffic_data)


@app.route("/alerts")
def alerts():
    if "user" not in session:
        return redirect(url_for("login"))

    selected_severity = request.args.get("severity", "all")
    response_message = session.pop("response_message", None)

    alerts_data = []

    if os.path.exists(ALERT_JSON_FILE):
        try:
            with open(ALERT_JSON_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        severity = alert.get("severity", "HIGH").upper()

                        alerts_data.append({
                            "severity": severity,
                            "ip": alert.get("src_ip", alert.get("ip", "Unknown")),
                            "time": alert.get("time", "Unknown"),
                            "attack": alert.get("attack", "Brute Force Attack")
                        })
        except Exception as e:
            print("Error reading alerts:", e)

    critical_count = sum(1 for a in alerts_data if a["severity"] == "CRITICAL")
    high_count = sum(1 for a in alerts_data if a["severity"] == "HIGH")
    low_count = sum(1 for a in alerts_data if a["severity"] == "LOW")
    total_count = len(alerts_data)

    if selected_severity != "all":
        alerts_data = [a for a in alerts_data if a["severity"] == selected_severity]

    return render_template(
        "alerts.html",
        alerts=alerts_data,
        selected_severity=selected_severity,
        critical_count=critical_count,
        high_count=high_count,
        low_count=low_count,
        total_count=total_count,
        response_message=response_message
    )


@app.route("/respond/<ip>", methods=["POST"])
def respond_alert(ip):
    if "user" not in session:
        return redirect(url_for("login"))

    blocked_ips.add(ip)

    try:
        with open(RESPONSE_CSV_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now(),
                ip,
                "Brute Force Attack",
                "HIGH",
                "Blocked IP",
                "SUCCESS"
            ])

        session["response_message"] = f"IP {ip} has been blocked successfully."

    except PermissionError:
        session["response_message"] = "Please close response_logs.csv in Excel and try again."

    return redirect(url_for("alerts"))


@app.route("/unblock/<ip>", methods=["POST"])
def unblock_ip(ip):
    if "user" not in session:
        return redirect(url_for("login"))

    blocked_ips.discard(ip)

    try:
        with open(RESPONSE_CSV_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now(),
                ip,
                "Manual Response",
                "INFO",
                "Unblocked IP",
                "SUCCESS"
            ])

        session["response_message"] = f"IP {ip} has been unblocked successfully."

    except PermissionError:
        session["response_message"] = "Please close response_logs.csv in Excel and try again."

    return redirect(url_for("alerts"))


@app.route("/api/traffic")
def api_traffic():
    traffic_data = []

    if os.path.exists(TRAFFIC_JSON_FILE):
        try:
            with open(TRAFFIC_JSON_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        traffic_data.append(json.loads(line))
        except Exception as e:
            print("Error reading traffic API:", e)

    return traffic_data


@app.route("/api/dashboard_traffic")
def api_dashboard_traffic():
    if not session.get("monitoring_active", False):
        return []

    traffic_data = []

    if os.path.exists(TRAFFIC_JSON_FILE):
        try:
            with open(TRAFFIC_JSON_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        traffic_data.append(json.loads(line))
        except Exception as e:
            print("Error reading dashboard traffic:", e)

    return traffic_data


@app.route("/api/alerts")
def api_alerts():
    alerts_data = []

    if os.path.exists(ALERT_JSON_FILE):
        try:
            with open(ALERT_JSON_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        alerts_data.append(json.loads(line))
        except Exception as e:
            print("Error reading alerts API:", e)

    return alerts_data


@app.route("/alert", methods=["POST"])
def alert():
    data = request.json

    timestamp = data.get("timestamp", data.get("time", str(datetime.now())))
    source_ip = data.get("source_ip", data.get("src_ip", data.get("ip", "Unknown")))

    # BLOCKED IP CHECK
    if source_ip in blocked_ips:
        return {
            "status": "blocked",
            "message": f"Alert from {source_ip} ignored because IP is blocked."
        }

    attack = data.get("attack", "Brute Force Attack")
    severity = data.get("severity", "HIGH").upper()
    status = data.get("status", "Detected")

    normalized_alert = {
        "time": timestamp,
        "src_ip": source_ip,
        "attack": attack,
        "severity": severity,
        "status": status
    }

    print("[REAL-TIME ALERT RECEIVED]", normalized_alert)

    with open(ALERT_JSON_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(normalized_alert) + "\n")

    with open(RESPONSE_CSV_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp,
            source_ip,
            attack,
            severity,
            "Detected",
            status
        ])

    socketio.emit("new_alert", normalized_alert)

    return {"status": "ok"}

@app.route("/save_traffic", methods=["POST"])
def save_traffic():
    data = request.json

    timestamp = data.get("timestamp", data.get("time", str(datetime.now())))
    source_ip = data.get("source_ip", data.get("src_ip", "Unknown"))

    if source_ip in blocked_ips:
        return {
            "status": "blocked",
            "message": f"Traffic from {source_ip} ignored because IP is blocked."
        }
    destination_ip = data.get("destination_ip", data.get("dst_ip", "Unknown"))
    destination_port = data.get("destination_port", data.get("dst_port", "Unknown"))
    protocol = data.get("protocol", "Unknown")
    failed_attempt = data.get("failed_attempt", 0)
    status = data.get("status", "Normal")

    normalized_traffic = {
        "time": timestamp,
        "src_ip": source_ip,
        "dst_ip": destination_ip,
        "dst_port": destination_port,
        "protocol": protocol,
        "failed_attempt": failed_attempt,
        "status": status
    }

    with open(TRAFFIC_CSV_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            timestamp,
            source_ip,
            destination_ip,
            destination_port,
            protocol,
            failed_attempt,
            status
        ])

    with open(TRAFFIC_JSON_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(normalized_traffic) + "\n")

    socketio.emit("new_traffic", normalized_traffic)

    return {"status": "saved"}

@app.route("/export_traffic_logs")
def export_traffic_logs():
    if "user" not in session:
        return redirect(url_for("login"))

    if not os.path.exists(TRAFFIC_CSV_FILE) or os.path.getsize(TRAFFIC_CSV_FILE) == 0:
        return "No traffic logs available to export."

    return send_file(
        TRAFFIC_CSV_FILE,
        as_attachment=True,
        download_name="BruteNetDefense_Traffic_Logs.csv",
        mimetype="text/csv"
    )


@app.route("/export_traffic")
def export_traffic():
    return export_traffic_logs()

@app.route("/export_response_logs")
def export_response_logs():
    if "user" not in session:
        return redirect(url_for("login"))

    if not os.path.exists(RESPONSE_CSV_FILE) or os.path.getsize(RESPONSE_CSV_FILE) == 0:
        return "No response logs available to export."

    return send_file(
        RESPONSE_CSV_FILE,
        as_attachment=True,
        download_name="BruteNetDefense_Response_Logs.csv",
        mimetype="text/csv"
    )


@app.route("/export_alerts")
def export_alerts():
    if "user" not in session:
        return redirect(url_for("login"))

    if not os.path.exists(ALERT_JSON_FILE):
        return "No alert logs available to export."

    return send_file(
        ALERT_JSON_FILE,
        as_attachment=True,
        download_name="BruteNetDefense_Alert_Logs.json"
    )

@app.route("/start_monitoring")
def start_monitoring():
    global capture_process

    if "user" not in session:
        return redirect(url_for("login"))

    if capture_process is None or capture_process.poll() is not None:
        capture_process = subprocess.Popen(
            [sys.executable, "-m", "detection.live_packet_capture"],
            cwd=BASE_DIR
        )
        print("[INFO] Live packet capture started")

    session["monitoring_active"] = True
    return redirect(url_for("dashboard"))
@app.route("/stop_monitoring")
def stop_monitoring():
    global capture_process

    if "user" not in session:
        return redirect(url_for("login"))

    if capture_process is not None:
        capture_process.terminate()
        capture_process = None
        print("[INFO] Live packet capture stopped")

    session["monitoring_active"] = False
    return redirect(url_for("dashboard"))

@app.route("/reports")
def reports():
    if "user" not in session:
        return redirect(url_for("login"))

    report_type = request.args.get("type", "weekly")

    traffic_data = []
    alerts_data = []

    if os.path.exists(TRAFFIC_JSON_FILE):
        with open(TRAFFIC_JSON_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    traffic_data.append(json.loads(line))

    if os.path.exists(ALERT_JSON_FILE):
        with open(ALERT_JSON_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    alerts_data.append(json.loads(line))

    report_summary = {}

    for item in traffic_data:
        time_value = item.get("time", "")
        dt = parse_report_datetime(time_value)

        if dt is None:
            continue

        if report_type == "monthly":
            key = dt.strftime("%B %Y")
        else:
            week_number = dt.isocalendar()[1]
            key = f"Week {week_number} - {dt.year}"

        if key not in report_summary:
            report_summary[key] = {
                "period": key,
                "total_traffic": 0,
                "failed_login": 0,
                "brute_force": 0
            }

        report_summary[key]["total_traffic"] += 1
        report_summary[key]["failed_login"] += int(item.get("failed_attempt", 0))

        status = str(item.get("status", "")).lower()
        if "brute" in status or "attack" in status:
            report_summary[key]["brute_force"] += 1

    reports = list(report_summary.values())

    return render_template(
        "reports.html",
        report_type=report_type,
        reports=reports
    )

@app.route("/export_report/<report_type>")
def export_report(report_type):
    if "user" not in session:
        return redirect(url_for("login"))

    traffic_data = []

    if os.path.exists(TRAFFIC_JSON_FILE):
        with open(TRAFFIC_JSON_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    traffic_data.append(json.loads(line))

    report_summary = {}

    for item in traffic_data:
        time_value = item.get("time", "")
        dt = parse_report_datetime(time_value)

        if dt is None:
            continue

        if report_type == "monthly":
            key = dt.strftime("%B %Y")
        else:
            week_number = dt.isocalendar()[1]
            key = f"Week {week_number} - {dt.year}"

        if key not in report_summary:
            report_summary[key] = {
                "period": key,
                "total_traffic": 0,
                "failed_login": 0,
                "brute_force": 0
            }

        report_summary[key]["total_traffic"] += 1
        report_summary[key]["failed_login"] += int(item.get("failed_attempt", 0))

        status = str(item.get("status", "")).lower()
        if "brute" in status or "attack" in status:
            report_summary[key]["brute_force"] += 1

    export_file = os.path.join(LOG_DIR, f"{report_type}_security_report.csv")

    with open(export_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Period", "Total Traffic", "Failed Login", "Brute Force Attack"])

        for report in report_summary.values():
            writer.writerow([
                report["period"],
                report["total_traffic"],
                report["failed_login"],
                report["brute_force"]
            ])

    return send_file(
        export_file,
        as_attachment=True,
        download_name=f"BruteNetDefense_{report_type}_report.csv",
        mimetype="text/csv"
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/get_stats")
def get_stats():
    if not session.get("monitoring_active", False):
        return {
            "total_packets": 0,
            "failed_attempts": 0,
            "detected_attacks": 0
        }

    traffic_data = []
    alerts_data = []

    if os.path.exists(TRAFFIC_JSON_FILE):
        try:
            with open(TRAFFIC_JSON_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        traffic_data.append(json.loads(line))
        except Exception as e:
            print("Error reading traffic stats:", e)

    if os.path.exists(ALERT_JSON_FILE):
        try:
            with open(ALERT_JSON_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        alerts_data.append(json.loads(line))
        except Exception as e:
            print("Error reading alert stats:", e)

    total_packets = len(traffic_data)
    failed_attempts = sum(1 for t in traffic_data if str(t.get("status", "")).lower() != "normal")
    detected_attacks = len(alerts_data)

    return {
        "total_packets": total_packets,
        "failed_attempts": failed_attempts,
        "detected_attacks": detected_attacks
    }


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)