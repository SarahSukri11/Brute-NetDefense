import requests
import time

print("[INFO] Starting traffic generator...")

for i in range(50):
    try:
        requests.get("http://example.com")
        print(f"Request {i+1} sent")
    except Exception as e:
        print("Error:", e)

    time.sleep(0.2)