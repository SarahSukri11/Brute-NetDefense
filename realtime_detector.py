X_CACHE = None
import pandas as pd
import time
import os

from model.load_model import load_rf_model


# ==============================
# STEP 1: Load trained RF model
# ==============================
rf_model = None

def get_model():
    global rf_model
    if rf_model is None:
        rf_model = load_rf_model()
        print("[INFO] RF model loaded (lazy)")
    return rf_model

# ==============================
# STEP 2: Define features (MUST MATCH TRAINING)
# ==============================
FEATURES = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Packets/s',
    'Flow Bytes/s'
]


# ==============================
# STEP 3: Dataset path
# ==============================
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

LIVE_DATA_PATH = os.path.join(
    BASE_DIR,
    "dataset",
    "Tuesday-WorkingHours.pcap_ISCX.csv"
)


# ==============================
# STEP 4: Load + preprocess data (ON DEMAND)
# ==============================
def load_and_preprocess_data():
    global X_CACHE

    if X_CACHE is not None:
        return X_CACHE

    print("[INFO] Loading live traffic dataset...")

    df = pd.read_csv(LIVE_DATA_PATH)
    df.columns = df.columns.str.strip()

    X = df[FEATURES]
    X = X.replace([float('inf'), -float('inf')], 0)
    X = X.fillna(0)

    print("[INFO] Total flows loaded:", len(X))

    X_CACHE = X
    return X

# ==============================
# STEP 5: Simulated real-time detection
# ==============================
def run_live_detection(max_flows=500, delay=0.05):
    """
    Simulate real-time brute-force detection
    """
    X_live = load_and_preprocess_data()

    print("\n[INFO] Starting live brute-force detection...\n")

    for index, row in X_live.head(max_flows).iterrows():
        sample = row.values.reshape(1, -1)

        model = get_model()
        prediction = model.predict(sample)[0]


        if prediction == 1:
            print(f"[ALERT] Brute Force Attack Detected at flow index {index}")
        else:
            print(f"[OK] Normal traffic at flow index {index}")

        time.sleep(delay)


# ==============================
# STEP 6: Entry point
# ==============================
if __name__ == "__main__":
    run_live_detection()

def get_live_detection_data(max_flows=100):
    X_live = load_and_preprocess_data()
    results = []

    for index, row in X_live.head(max_flows).iterrows():
        sample = row.values.reshape(1, -1)
        model = get_model()
        prediction = model.predict(sample)[0]


        if prediction == 1:
            status = "Brute Force"
        else:
            status = "Normal"

        results.append({
            "index": index,
            "status": status
        })

    return results
