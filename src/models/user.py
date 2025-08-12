from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import hashlib
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Profile Information
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    company = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    timezone = db.Column(db.String(50), default='UTC')
    
    # Account Status
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='user')  # user, admin, manager, viewer
    
    # Subscription & Limits
    subscription_type = db.Column(db.String(20), default='free')  # free, pro, enterprise
    monthly_email_limit = db.Column(db.Integer, default=1000)
    monthly_emails_sent = db.Column(db.Integer, default=0)
    api_rate_limit = db.Column(db.Integer, default=100)  # requests per hour
    
    # Security
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(45))
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Two-Factor Authentication
    totp_secret = db.Column(db.String(32))
    backup_codes = db.Column(db.Text)  # JSON array of backup codes
    two_factor_enabled = db.Column(db.Boolean, default=False)
    
    # Email Verification & Password Reset
    email_verification_token = db.Column(db.String(100))
    email_verification_sent_at = db.Column(db.DateTime)
    password_reset_token = db.Column(db.String(100))
    password_reset_sent_at = db.Column(db.DateTime)
    
    # API Access
    api_key = db.Column(db.String(64), unique=True)
    api_key_created_at = db.Column(db.DateTime)
    api_last_used = db.Column(db.DateTime)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    campaigns = db.relationship('Campaign', backref='owner', lazy=True, cascade='all, delete-orphan')
    login_sessions = db.relationship('LoginSession', backref='user', lazy=True, cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True, cascade='all, delete-orphan')

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.api_key:
            self.generate_api_key()

    def set_password(self, password):
        """Set password with advanced hashing"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256:100000')
        self.password_changed_at = datetime.utcnow()

    def check_password(self, password):
        """Check password with timing attack protection"""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def is_account_locked(self):
        """Check if account is locked due to failed login attempts"""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def lock_account(self, duration_minutes=30):
        """Lock account for specified duration"""
        self.locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.failed_login_attempts += 1

    def unlock_account(self):
        """Unlock account and reset failed attempts"""
        self.locked_until = None
        self.failed_login_attempts = 0

    def record_login(self, ip_address):
        """Record successful login"""
        self.last_login = datetime.utcnow()
        self.last_login_ip = ip_address
        self.failed_login_attempts = 0
        self.locked_until = None

    def generate_api_key(self):
        """Generate secure API key"""
        self.api_key = secrets.token_urlsafe(48)
        self.api_key_created_at = datetime.utcnow()

    def regenerate_api_key(self):
        """Regenerate API key"""
        self.generate_api_key()

    def generate_email_verification_token(self):
        """Generate email verification token"""
        self.email_verification_token = secrets.token_urlsafe(32)
        self.email_verification_sent_at = datetime.utcnow()
        return self.email_verification_token

    def verify_email_token(self, token):
        """Verify email verification token"""
        if not self.email_verification_token or not self.email_verification_sent_at:
            return False
        
        # Token expires after 24 hours
        if datetime.utcnow() - self.email_verification_sent_at > timedelta(hours=24):
            return False
            
        if secrets.compare_digest(self.email_verification_token, token):
            self.is_verified = True
            self.email_verification_token = None
            self.email_verification_sent_at = None
            return True
        return False

    def generate_password_reset_token(self):
        """Generate password reset token"""
        self.password_reset_token = secrets.token_urlsafe(32)
        self.password_reset_sent_at = datetime.utcnow()
        return self.password_reset_token

    def verify_password_reset_token(self, token):
        """Verify password reset token"""
        if not self.password_reset_token or not self.password_reset_sent_at:
            return False
        
        # Token expires after 1 hour
        if datetime.utcnow() - self.password_reset_sent_at > timedelta(hours=1):
            return False
            
        return secrets.compare_digest(self.password_reset_token, token)

    def reset_password_with_token(self, token, new_password):
        """Reset password using token"""
        if self.verify_password_reset_token(token):
            self.set_password(new_password)
            self.password_reset_token = None
            self.password_reset_sent_at = None
            return True
        return False

    def setup_two_factor(self):
        """Setup two-factor authentication"""
        self.totp_secret = secrets.token_urlsafe(24)
        # Generate backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        self.backup_codes = json.dumps(backup_codes)
        return self.totp_secret, backup_codes

    def verify_totp(self, token):
        """Verify TOTP token"""
        if not self.totp_secret:
            return False
        
        import pyotp
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)

    def use_backup_code(self, code):
        """Use backup code for 2FA"""
        if not self.backup_codes:
            return False
        
        codes = json.loads(self.backup_codes)
        if code.upper() in codes:
            codes.remove(code.upper())
            self.backup_codes = json.dumps(codes)
            return True
        return False

    def can_send_emails(self, count=1):
        """Check if user can send emails within limits"""
        if self.subscription_type == 'enterprise':
            return True
        return self.monthly_emails_sent + count <= self.monthly_email_limit

    def increment_email_count(self, count=1):
        """Increment monthly email count"""
        self.monthly_emails_sent += count

    def reset_monthly_counts(self):
        """Reset monthly counters (called by cron job)"""
        self.monthly_emails_sent = 0

    def get_permissions(self):
        """Get user permissions based on role"""
        permissions = {
            'user': ['view_own_campaigns', 'create_campaigns', 'edit_own_campaigns'],
            'manager': ['view_own_campaigns', 'create_campaigns', 'edit_own_campaigns', 'view_team_campaigns'],
            'admin': ['view_all_campaigns', 'create_campaigns', 'edit_all_campaigns', 'manage_users', 'view_analytics'],
            'viewer': ['view_own_campaigns']
        }
        return permissions.get(self.role, permissions['user'])

    def has_permission(self, permission):
        """Check if user has specific permission"""
        return permission in self.get_permissions()

    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'company': self.company,
            'phone': self.phone,
            'timezone': self.timezone,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'is_admin': self.is_admin,
            'role': self.role,
            'subscription_type': self.subscription_type,
            'monthly_email_limit': self.monthly_email_limit,
            'monthly_emails_sent': self.monthly_emails_sent,
            'two_factor_enabled': self.two_factor_enabled,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
        
        if include_sensitive:
            data.update({
                'api_key': self.api_key,
                'failed_login_attempts': self.failed_login_attempts,
                'locked_until': self.locked_until.isoformat() if self.locked_until else None,
                'last_login_ip': self.last_login_ip
            })
        
        return data

    def __repr__(self):
        return f'<User {self.username}>'


class LoginSession(db.Model):
    __tablename__ = 'login_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(100), unique=True, nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    location = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

    def __init__(self, user_id, ip_address=None, user_agent=None, duration_days=30):
        self.user_id = user_id
        self.session_token = secrets.token_urlsafe(32)
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.expires_at = datetime.utcnow() + timedelta(days=duration_days)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def extend_session(self, days=30):
        self.expires_at = datetime.utcnow() + timedelta(days=days)
        self.last_activity = datetime.utcnow()


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.String(50))
    details = db.Column(db.Text)  # JSON string
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, action, user_id=None, resource_type=None, resource_id=None, 
                 details=None, ip_address=None, user_agent=None):
        self.action = action
        self.user_id = user_id
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.details = json.dumps(details) if details else None
        self.ip_address = ip_address
        self.user_agent = user_agent

    def get_details(self):
        return json.loads(self.details) if self.details else {}


class Campaign(db.Model):
    __tablename__ = 'campaigns'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='active')  # active, paused, completed, archived
    
    # Campaign Settings
    auto_grab_emails = db.Column(db.Boolean, default=True)
    track_opens = db.Column(db.Boolean, default=True)
    track_clicks = db.Column(db.Boolean, default=True)
    track_location = db.Column(db.Boolean, default=True)
    
    # Security Settings
    enable_captcha = db.Column(db.Boolean, default=False)
    block_bots = db.Column(db.Boolean, default=True)
    block_vpn = db.Column(db.Boolean, default=False)
    allowed_domains = db.Column(db.Text)  # JSON array
    blocked_domains = db.Column(db.Text)  # JSON array
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    tracking_links = db.relationship('TrackingLink', backref='campaign', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'status': self.status,
            'auto_grab_emails': self.auto_grab_emails,
            'track_opens': self.track_opens,
            'track_clicks': self.track_clicks,
            'track_location': self.track_location,
            'enable_captcha': self.enable_captcha,
            'block_bots': self.block_bots,
            'block_vpn': self.block_vpn,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class TrackingLink(db.Model):
    __tablename__ = 'tracking_links'
    
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=False)
    original_url = db.Column(db.Text, nullable=False)
    tracking_token = db.Column(db.String(100), unique=True, nullable=False)
    recipient_email = db.Column(db.String(120))
    recipient_name = db.Column(db.String(100))
    
    # Auto-grabbed emails
    auto_grabbed_emails = db.Column(db.Text)  # JSON array of emails
    
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, **kwargs):
        super(TrackingLink, self).__init__(**kwargs)
        if not self.tracking_token:
            self.tracking_token = secrets.token_urlsafe(16)

    def add_auto_grabbed_email(self, email):
        """Add auto-grabbed email to the list"""
        emails = json.loads(self.auto_grabbed_emails) if self.auto_grabbed_emails else []
        if email not in emails:
            emails.append(email)
            self.auto_grabbed_emails = json.dumps(emails)

    def get_auto_grabbed_emails(self):
        """Get list of auto-grabbed emails"""
        return json.loads(self.auto_grabbed_emails) if self.auto_grabbed_emails else []

