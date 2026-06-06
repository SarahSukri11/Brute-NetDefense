import requests
import time
from datetime import datetime
import random

BASE_URL = "https://brute.sneakyturtle.my"

normal_ips = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12"
]

attack_ips = [
    "192.168.1.50",
    "192.168.1.60"
]


def send_normal_traffic():
    data = {
        "time": str(datetime.now()),
        "src_ip": random.choice(normal_ips),
        "dst_ip": "192.168.1.1",
        "dst_port": random.choice([80, 443, 53]),
        "protocol": "TCP",
        "failed_attempt": 0,
        "status": "Normal"
    }

    response = requests.post(f"{BASE_URL}/save_traffic", json=data)
    print("[NORMAL]", data["src_ip"], response.status_code, response.text[:100])


def send_brute_force_traffic():
    attacker_ip = random.choice(attack_ips)

    traffic_data = {
        "time": str(datetime.now()),
        "src_ip": attacker_ip,
        "dst_ip": "192.168.1.1",
        "dst_port": 22,
        "protocol": "TCP",
        "failed_attempt": random.randint(5, 15),
        "status": "Brute Force Attack"
    }

    alert_data = {
        "time": str(datetime.now()),
        "src_ip": attacker_ip,
        "attack": "Brute Force Attack",
        "severity": "HIGH",
        "status": "Detected"
    }

    traffic_response = requests.post(f"{BASE_URL}/save_traffic", json=traffic_data)
    alert_response = requests.post(f"{BASE_URL}/alert", json=alert_data)

    print(
        "[BRUTE FORCE]",
        attacker_ip,
        traffic_response.status_code,
        alert_response.status_code
    )


print("Starting Brute-NetDefense traffic simulation...")
print("Press CTRL + C to stop.")

while True:
    send_normal_traffic()

    # Every few rounds, send brute force attack
    if random.randint(1, 3) == 1:
        send_brute_force_traffic()

    time.sleep(2)
