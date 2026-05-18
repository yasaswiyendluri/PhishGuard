"""Normalize ML predictor output to JSON-safe Python types."""
from typing import Any


def normalize_ml_result(raw: dict | None) -> dict:
    """Always return the same keys the dashboard expects."""
    if not raw:
        return {
            "ml_score": 0.0,
            "ml_confidence": 0,
            "ml_prediction": "unknown",
            "ml_ready": False,
        }

    def _float(v, default=0.0):
        if v is None:
            return default
        try:
            return float(v)
        except (TypeError, ValueError):
            return default

    def _int(v, default=0):
        if v is None:
            return default
        try:
            return int(round(float(v)))
        except (TypeError, ValueError):
            return default

    ready = bool(raw.get("ml_ready", False))
    score = _float(raw.get("ml_score"), 0.0)
    conf = _int(raw.get("ml_confidence"), 0)
    if ready and conf == 0 and score > 0:
        conf = int(round(score * 100))

    pred = raw.get("ml_prediction") or "unknown"
    if pred not in ("phishing", "safe", "unknown"):
        pred = str(pred)

    return {
        "ml_score": score,
        "ml_confidence": conf,
        "ml_prediction": pred,
        "ml_ready": ready,
    }
