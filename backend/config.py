import os
from dotenv import load_dotenv

# Load .env if present
load_dotenv()


class Config:
    PORT = int(os.getenv("PORT", "5000"))
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "verifyfix-insecure-dev-secret-key-change-in-production")

    # Google Gemini (Primary & Only LLM Provider)
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

    # GitHub
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

    # CORS
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,*").split(",")

    # MongoDB
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "verifyfix")


config = Config()
