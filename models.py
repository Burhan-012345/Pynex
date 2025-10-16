from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200))
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    avatar = db.Column(db.String(255), default='default_avatar.png')
    is_verified = db.Column(db.Boolean, default=False)
    google_id = db.Column(db.String(100), unique=True)
    role = db.Column(db.String(20), default='user')  # 'user', 'admin'
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    language = db.Column(db.String(10), default='en')  # 'en', 'hi'
    theme = db.Column(db.String(10), default='light')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    two_fa_secret = db.Column(db.String(32))  # Store the TOTP secret
    backup_codes = db.Column(db.Text)
    avatar = db.Column(db.String(255), default='default_avatar.png')
    notification_email = db.Column(db.Boolean, default=True)
    notification_sms = db.Column(db.Boolean, default=False)
    notification_push = db.Column(db.Boolean, default=True)
    theme = db.Column(db.String(10), default='auto') 
    
    expenses = db.relationship('Expense', backref='user', lazy=True, cascade='all, delete-orphan')
    login_history = db.relationship('LoginHistory', backref='user', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'phone': self.phone,
            'avatar': self.avatar,
            'is_verified': self.is_verified,
            'role': self.role,
            'is_2fa_enabled': self.is_2fa_enabled,
            'language': self.language,
            'theme': self.theme,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'avatar': self.avatar,
            'notification_email': self.notification_email,
            'notification_sms': self.notification_sms,
            'notification_push': self.notification_push,
            'theme': self.theme,
        }
    def is_admin(self):
        return self.role == 'admin'

class Expense(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'amount': self.amount,
            'category': self.category,
            'description': self.description,
            'date': self.date.strftime('%Y-%m-%d'),
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M')
        }

class OTP(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), nullable=False, index=True)
    otp_code = db.Column(db.String(6), nullable=False)
    purpose = db.Column(db.String(20), nullable=False)  # 'register', 'reset', '2fa'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

    def is_valid(self):
        return not self.is_used and datetime.utcnow() < self.expires_at

    @classmethod
    def cleanup_expired(cls):
        expired_time = datetime.utcnow() - timedelta(hours=1)
        cls.query.filter(cls.created_at < expired_time).delete()

class LoginHistory(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    login_at = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'login_at': self.login_at.strftime('%Y-%m-%d %H:%M:%S'),
            'success': self.success
        }