import os

# Hardcoded credentials — CWE-798
DATABASE_URL = "postgresql://admin:SuperSecret123@db.internal:5432/production"
SECRET_KEY = "hardcoded-flask-secret-key-do-not-use"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae5b31"

# Debug mode left on in production — CWE-11
DEBUG = True
TESTING = True

# Weak JWT secret
JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"

# Disable SSL verification
VERIFY_SSL = False
SSL_CERT_REQUIRED = False

# Redis without auth
REDIS_URL = "redis://localhost:6379/0"

# MongoDB without auth
MONGO_URI = "mongodb://localhost:27017/appdb"

# Insecure CORS
CORS_ORIGINS = ["*"]

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "fallback-insecure-secret"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = False       # should be True in prod
    SESSION_COOKIE_HTTPONLY = False     # should be True
    SESSION_COOKIE_SAMESITE = None      # should be "Lax" or "Strict"
    PERMANENT_SESSION_LIFETIME = 99999  # extremely long session
