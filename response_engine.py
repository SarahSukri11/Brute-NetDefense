import os
import platform
import threading
import time

# Prevent blocking yourself
WHITELIST = {"127.0.0.1", "192.168.1.1"}

def block_ip(ip):
    if ip in WHITELIST:
        print(f"[SAFE] Skipping trusted IP: {ip}")
        return

    print(f"[ACTION] Blocking IP: {ip}")

    system = platform.system()

    try:
        if system == "Linux":
            os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

        elif system == "Windows":
            os.system(
                f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
            )

        else:
            print("[WARNING] Unsupported OS")

    except Exception as e:
        print("Blocking error:", e)


def unblock_ip(ip):
    print(f"[ACTION] Unblocking IP: {ip}")

    system = platform.system()

    try:
        if system == "Linux":
            os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")

        elif system == "Windows":
            os.system(
                f'netsh advfirewall firewall delete rule name="Block {ip}"'
            )

    except Exception as e:
        print("Unblock error:", e)


def auto_unblock(ip, delay=60):
    def task():
        time.sleep(delay)
        unblock_ip(ip)
        print(f"[INFO] IP {ip} automatically unblocked")

    threading.Thread(target=task, daemon=True).start()