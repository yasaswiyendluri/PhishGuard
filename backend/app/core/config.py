# app/core/config.py
# Loads environment variables from .env file
# Think of this like dotenv in Node.js

from dotenv import load_dotenv
import os

load_dotenv()  # reads your .env file into memory

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")

# MongoDB
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "phishguard")

# App settings
APP_ENV = os.getenv("APP_ENV", "development")
