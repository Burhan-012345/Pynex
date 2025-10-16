import os
from datetime import timedelta

class Config:
    # Basic Flask Config
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'pynex-dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///pynex.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

        # Session Configuration - ADD THESE
    SESSION_TYPE = 'filesystem'  # or 'redis' in production
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_USE_SIGNER = True
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Google OAuth Config
    GOOGLE_CLIENT_ID = '979261059125-b2pj6hpp0la0j1jivbttk4qcp0ofp45l.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
    
    # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'contact.menscraft@gmail.com'
    MAIL_PASSWORD = 'aelg eiuo jtlj inle'
    MAIL_DEFAULT_SENDER = 'contact.menscraft@gmail.com'
    MAIL_DEBUG = True
    
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # OTP Configuration
    OTP_EXPIRY_MINUTES = 10
    OTP_LENGTH = 6
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'static/uploads/avatars'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    
    # Application Config
    APP_NAME = 'Pynex Expense Tracker'
    VERSION = '1.0.0'
    
    # Admin Configuration
    ADMIN_EMAILS = ['admin@pynex.com']

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    # Use environment variables in production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}