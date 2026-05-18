# app/models/schemas.py
# Defines what data looks like going IN and coming OUT of your API
# Similar to defining req.body shape in Express with TypeScript

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Any
from datetime import datetime

# ── Auth ─────────────────────────────────────────────────────


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    user_id: str
    username: str
    email: str
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ── What the user sends TO your API ──────────────────────────


class ScanRequest(BaseModel):
    url: str  # the URL to scan, e.g. "http://suspicious-site.com"

# ── What your API sends BACK ─────────────────────────────────


class ScanResponse(BaseModel):
    scan_id: str
    user_id: Optional[str] = None
    url: str
    risk_score: int                 # 0-100, your weighted engine output
    risk_level: str                 # "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
    prediction: str                 # "safe" or "phishing"
    explanation: str                # human-readable reason e.g. "Domain is 2 days old..."
    features: Dict[str, Any]        # all extracted features (domain age, etc.)
    threat_intel: Dict[str, Any]    # VirusTotal + URLHaus results
    timestamp: datetime             # when was this scanned

# ── Shape of a record stored in MongoDB ──────────────────────


class ScanRecord(BaseModel):
    scan_id: str
    url: str
    risk_score: int
    risk_level: str
    prediction: str
    timestamp: datetime
