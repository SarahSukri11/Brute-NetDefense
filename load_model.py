import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Model Loading (Load only when needed)
def load_rf_model():
    model_path = os.path.join(BASE_DIR, "rf_bruteforce_model.pkl")
    return joblib.load(model_path)
