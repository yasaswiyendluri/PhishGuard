# backend/app/ml/predictor.py
# Loads the ML model package and runs predictions
# The model package contains: model, scaler, feature_extractor_class

import joblib
import numpy as np
import os
from urllib.parse import urlparse, parse_qs
import re
from app.ml.feature_extractor import URLFeatureExtractor

import __main__
__main__.URLFeatureExtractor = URLFeatureExtractor
# ── Load model package once at startup ───────────────────
# joblib.load reads the .pkl file your teammate exported
MODEL_PATH = os.path.join(os.path.dirname(
    __file__), "phishing_detector_enhanced.pkl")

try:
    package = joblib.load(MODEL_PATH)
    model = package["model"]
    scaler = package["scaler"]
    feature_names = package["feature_names"]
    # The URLFeatureExtractor class is saved inside the pkl
    # URLFeatureExtractor = package["feature_extractor_class"]
    extractor = URLFeatureExtractor()
    ML_READY = True
    print(
        f"✅ ML Model loaded: {package['model_name']} | Accuracy: {package['accuracy']:.4f}")
except Exception as e:
    ML_READY = False
    print(f"⚠️  ML Model not loaded: {e}")


def predict(url: str) -> dict:
    """
    Takes a raw URL string.
    Returns prediction dict with score and label.

    Returns:
    {
        "ml_score": 0.87,        # probability of being phishing (0.0 to 1.0)
        "ml_prediction": "phishing",  # or "safe"
        "ml_confidence": 87,     # percentage 0-100
        "ml_ready": True         # False if model failed to load
    }
    """
    if not ML_READY:
        return {
            "ml_score": 0.0,
            "ml_prediction": "unknown",
            "ml_confidence": 0,
            "ml_ready": False
        }

    try:
        # Step 1 — extract 48 features from the URL
        # This uses yasaswi's URLFeatureExtractor class
        features = extractor.extract_features(url)

        # Step 2 — convert to numpy array in correct feature order
        # feature_names ensures we pass features in the exact order model was trained on
        feature_array = np.array([[features.get(f, 0) for f in feature_names]])

        # Step 3 — scale features (MUST do this — model was trained on scaled data)
        feature_scaled = scaler.transform(feature_array)

        # Step 4 — get probability score (not just 0/1 label)
        # predict_proba returns [[prob_legitimate, prob_phishing]]
        proba = model.predict_proba(feature_scaled)[0]
        phishing_probability = float(proba[1])  # probability of being phishing

        # Step 5 — build result
        prediction = "phishing" if phishing_probability >= 0.5 else "safe"
        confidence = int(phishing_probability * 100)

        return {
            "ml_score": phishing_probability,
            "ml_prediction": prediction,
            "ml_confidence": confidence,
            "ml_ready": True
        }

    except Exception as e:
        print(f"ML prediction error: {e}")
        return {
            "ml_score": 0.0,
            "ml_prediction": "unknown",
            "ml_confidence": 0,
            "ml_ready": False,
            "error": str(e)
        }
