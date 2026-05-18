# app/main.py
# Entry point of the FastAPI application
# Same role as index.js/app.js in Express

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.routers import scan, history, report, auth

# Rate limiter setup — prevents abuse (10 scans/minute per IP)
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="PhishGuard API",
    description="ML-powered phishing URL detection with Cyber Threat Intelligence",
    version="1.0.0"
)

# Attach rate limiter to app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — allows your React dashboard and Chrome extension to call this API
# Like cors() middleware in Express
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers — like app.use('/scan', scanRouter) in Express
app.include_router(auth.router, prefix="/api", tags=["Auth"])
app.include_router(scan.router, prefix="/api", tags=["Scan"])
app.include_router(history.router, prefix="/api", tags=["History"])
app.include_router(report.router, prefix="/api", tags=["Report"])


@app.get("/")
def root():
    return {"message": "PhishGuard API is running", "docs": "/docs"}
