import time
import os
import pandas as pd
import requests
from collections import defaultdict

from model.load_model import load_rf_model
from detection.alert_manager import log_alert
from detection.response_engine import block_ip, auto_unblock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGIN_FILE = os.path.join(BASE_DIR, "logs", "login_attempts.csv")

print("[DEBUG] Reading login file from:", LOGIN_FILE)

login_tracker = defaultdict(list)
blocked_ips = set()
alert_cooldown = {}
ALERT_COOLDOWN_SECONDS = 30

try:
    model = load_rf_model()
    print("[INFO] Random Forest model loaded")
except Exception as e:
    print("[ERROR] Model loading failed:", e)
    exit()


def send_alert(ip, attack_type, severity="HIGH"):
    try:
        requests.post(
            "http://127.0.0.1:5000/alert",
            json={
                "src_ip": ip,
                "attack": attack_type,
                "severity": severity,
                "time": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            timeout=1
        )
    except Exception as e:
        print("[ERROR] Alert send failed:", e)


def read_login_attempts():
    try:
        with open(LOGIN_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            #print("[DEBUG] Total login lines:", len(lines))
            return lines
    except FileNotFoundError:
        print("[ERROR] login_attempts.csv not found at:", LOGIN_FILE)
        return []


def monitor_login_attempts():
    seen_lines = len(read_login_attempts())

    while True:
        lines = read_login_attempts()
        new_lines = lines[seen_lines:]
        seen_lines = len(lines)

        for line in new_lines:
            parts = line.strip().split(",")

            if len(parts) < 5:
                continue

            timestamp, ip, username, password, status = parts

            if status.strip().upper() == "FAILED":
                login_tracker[ip].append({
                    "time": time.time(),
                    "username": username,
                    "password": password
                })

        current_time = time.time()

        for ip, attempts in list(login_tracker.items()):
            recent = [
                a for a in attempts
                if current_time - a["time"] <= 30
            ]

            login_tracker[ip] = recent

            if len(recent) == 0:
                continue

            request_count_5s = len(recent)
            failed_login_count_5s = len(recent)

            usernames = set(a["username"] for a in recent)
            same_username_count = max(
                sum(1 for a in recent if a["username"] == u)
                for u in usernames
            )

            unique_password_count = len(set(a["password"] for a in recent))

            times = [a["time"] for a in recent]

            if len(times) > 1:
                intervals = [
                    times[i] - times[i - 1]
                    for i in range(1, len(times))
                ]
                avg_time_between_attempts = sum(intervals) / len(intervals)
            else:
                avg_time_between_attempts = 5.0

            login_attempt_rate = request_count_5s / 30
            destination_port = 5000

            X = pd.DataFrame([{
                "request_count_5s": request_count_5s,
                "failed_login_count_5s": failed_login_count_5s,
                "same_username_count": same_username_count,
                "unique_password_count": unique_password_count,
                "avg_time_between_attempts": avg_time_between_attempts,
                "login_attempt_rate": login_attempt_rate,
                "destination_port": destination_port
            }])

            prediction = model.predict(X)[0]

            print("\n========== RANDOM FOREST LOGIN DETECTION ==========")
            print("IP:", ip)
            print("request_count_5s:", request_count_5s)
            print("failed_login_count_5s:", failed_login_count_5s)
            print("same_username_count:", same_username_count)
            print("unique_password_count:", unique_password_count)
            print("avg_time_between_attempts:", avg_time_between_attempts)
            print("login_attempt_rate:", login_attempt_rate)
            print("Prediction:", prediction)
            print("===================================================\n")


            if prediction == 0:
                print(f"[NORMAL] Normal login activity from {ip}")

            elif prediction == 1:
                last_alert_time = alert_cooldown.get(ip, 0)

                if time.time() - last_alert_time < ALERT_COOLDOWN_SECONDS:
                    continue

                alert_cooldown[ip] = time.time()

                print(f"[ALERT] Brute Force Attack detected from {ip}")

                alert_data = {
                    "src_ip": ip,
                    "dst_ip": "Flask Login Server",
                    "port": 5000,
                    "attack": "HTTP Brute Force",
                    "severity": "HIGH",
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "BLOCKED" if ip in blocked_ips else "DETECTED",
                    "prediction": int(prediction),
                    "request_count": request_count_5s,
                    "failed_login_count": failed_login_count_5s,
                    "unique_password_count": unique_password_count,
                    "login_attempt_rate": login_attempt_rate
                }

                log_alert(alert_data)
                send_alert(ip, "HTTP Brute Force Attack", "HIGH")

                if ip not in blocked_ips:
                    blocked_ips.add(ip)
                    #block_ip(ip)
                    #auto_unblock(ip, 60)

        time.sleep(1)


if __name__ == "__main__":
    print("[INFO] Starting Brute-NetDefense Real Time Monitoring...")
    monitor_login_attempts()