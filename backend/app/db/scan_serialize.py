"""Ensure scan documents always expose ML fields for the dashboard."""
from app.ml.ml_utils import normalize_ml_result


def enrich_scan_ml_fields(doc: dict) -> dict:
    """
    Fill top-level ml_* from threat_intel.ml or nested structures.
    Never leave ml_confidence missing when any ML data exists.
    """
    if doc.get("ml_confidence") is not None and doc.get("ml_confidence") != "":
        try:
            doc["ml_confidence"] = int(round(float(doc["ml_confidence"])))
            return doc
        except (TypeError, ValueError):
            pass

    # Top-level probability only
    top_score = doc.get("ml_score")
    if top_score is not None:
        try:
            s = float(top_score)
            if 0 <= s <= 1:
                doc["ml_confidence"] = int(round(s * 100))
                doc["ml_score"] = s
                if doc.get("ml_ready") is None:
                    doc["ml_ready"] = True
                return doc
        except (TypeError, ValueError):
            pass

    intel = doc.get("threat_intel") or {}
    ml_raw = intel.get("ml") if isinstance(intel, dict) else None
    if not isinstance(ml_raw, dict):
        ml_raw = doc.get("ml") if isinstance(doc.get("ml"), dict) else None

    if isinstance(ml_raw, dict):
        ml = normalize_ml_result(ml_raw)
        doc["ml_score"] = ml["ml_score"]
        doc["ml_confidence"] = ml["ml_confidence"]
        doc["ml_prediction"] = ml["ml_prediction"]
        doc["ml_ready"] = ml["ml_ready"]
        if isinstance(intel, dict):
            intel["ml"] = ml
            doc["threat_intel"] = intel

    return doc
