from flask import Blueprint, request, jsonify, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from models.user import User, LoginSession, AuditLog, db
from datetime import datetime, timedelta
import secrets
import re
import json
import pyotp
import qrcode
import io
import base64
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import smtplib

auth_bp = Blueprint('auth', __name__)

def get_client_ip():
    """Get client IP address"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    return request.environ.get('REMOTE_ADDR', 'unknown')

def get_user_agent():
    """Get user agent"""
    return request.headers.get('User-Agent', 'unknown')

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password_strength(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

def log_audit_event(action, user_id=None, resource_type=None, resource_id=None, details=None):
    """Log audit event"""
    try:
        audit_log = AuditLog(
            action=action,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=get_client_ip(),
            user_agent=get_user_agent()
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log audit event: {e}")

def send_email(to_email, subject, body, is_html=False):
    """Send email (placeholder - implement with your email service)"""
    # This is a placeholder. In production, use services like:
    # - SendGrid, Mailgun, AWS SES, etc.
    print(f"EMAIL TO: {to_email}")
    print(f"SUBJECT: {subject}")
    print(f"BODY: {body}")
    return True

@auth_bp.route('/register', methods=['POST'])
def register():
    """Advanced user registration with validation"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        username = data['username'].strip().lower()
        email = data['email'].strip().lower()
        password = data['password']
        
        # Validate email format
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password strength
        is_strong, message = validate_password_strength(password)
        if not is_strong:
            return jsonify({'error': message}), 400
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create new user
        user = User(
            username=username,
            email=email,
            first_name=data.get('first_name', '').strip(),
            last_name=data.get('last_name', '').strip(),
            company=data.get('company', '').strip(),
            phone=data.get('phone', '').strip(),
            timezone=data.get('timezone', 'UTC')
        )
        user.set_password(password)
        
        # Generate email verification token
        verification_token = user.generate_email_verification_token()
        
        db.session.add(user)
        db.session.commit()
        
        # Send verification email
        verification_link = f"{request.host_url}auth/verify-email?token={verification_token}"
        email_body = f"""
        Welcome to 7th Brain Link Tracker!
        
        Please verify your email address by clicking the link below:
        {verification_link}
        
        This link will expire in 24 hours.
        
        If you didn't create this account, please ignore this email.
        """
        
        send_email(email, "Verify your 7th Brain account", email_body)
        
        # Log registration
        log_audit_event('user_registered', user.id, 'user', str(user.id), {
            'username': username,
            'email': email
        })
        
        return jsonify({
            'message': 'Registration successful. Please check your email to verify your account.',
            'user_id': user.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """Advanced login with security features"""
    try:
        data = request.get_json()
        
        if not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password are required'}), 400
        
        username = data['username'].strip().lower()
        password = data['password']
        
        # Find user by username or email
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user:
            log_audit_event('login_failed', None, 'auth', None, {
                'username': username,
                'reason': 'user_not_found'
            })
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if account is locked
        if user.is_account_locked():
            log_audit_event('login_blocked', user.id, 'auth', None, {
                'reason': 'account_locked'
            })
            return jsonify({'error': 'Account is temporarily locked due to multiple failed login attempts'}), 423
        
        # Check if account is active
        if not user.is_active:
            log_audit_event('login_blocked', user.id, 'auth', None, {
                'reason': 'account_inactive'
            })
            return jsonify({'error': 'Account is deactivated'}), 403
        
        # Verify password
        if not user.check_password(password):
            user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.lock_account(30)  # Lock for 30 minutes
                db.session.commit()
                
                log_audit_event('account_locked', user.id, 'auth', None, {
                    'reason': 'too_many_failed_attempts'
                })
                return jsonify({'error': 'Account locked due to too many failed login attempts'}), 423
            
            db.session.commit()
            log_audit_event('login_failed', user.id, 'auth', None, {
                'reason': 'invalid_password',
                'failed_attempts': user.failed_login_attempts
            })
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check if 2FA is enabled
        if user.two_factor_enabled:
            totp_token = data.get('totp_token')
            backup_code = data.get('backup_code')
            
            if not totp_token and not backup_code:
                return jsonify({
                    'requires_2fa': True,
                    'message': 'Two-factor authentication required'
                }), 200
            
            # Verify 2FA
            if totp_token and not user.verify_totp(totp_token):
                log_audit_event('2fa_failed', user.id, 'auth', None, {
                    'method': 'totp'
                })
                return jsonify({'error': 'Invalid 2FA code'}), 401
            
            if backup_code and not user.use_backup_code(backup_code):
                log_audit_event('2fa_failed', user.id, 'auth', None, {
                    'method': 'backup_code'
                })
                return jsonify({'error': 'Invalid backup code'}), 401
        
        # Successful login
        ip_address = get_client_ip()
        user.record_login(ip_address)
        
        # Create login session
        login_session = LoginSession(
            user_id=user.id,
            ip_address=ip_address,
            user_agent=get_user_agent()
        )
        
        db.session.add(login_session)
        db.session.commit()
        
        # Flask-Login
        login_user(user, remember=data.get('remember_me', False))
        
        # Store session token
        session['session_token'] = login_session.session_token
        
        log_audit_event('login_successful', user.id, 'auth', None, {
            'ip_address': ip_address,
            'session_id': login_session.id
        })
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'session_token': login_session.session_token
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout and invalidate session"""
    try:
        session_token = session.get('session_token')
        
        if session_token:
            login_session = LoginSession.query.filter_by(
                session_token=session_token,
                user_id=current_user.id
            ).first()
            
            if login_session:
                login_session.is_active = False
                db.session.commit()
        
        log_audit_event('logout', current_user.id, 'auth', None)
        
        logout_user()
        session.clear()
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    """Verify email address"""
    try:
        token = request.args.get('token') or request.json.get('token')
        
        if not token:
            return jsonify({'error': 'Verification token is required'}), 400
        
        user = User.query.filter_by(email_verification_token=token).first()
        
        if not user:
            return jsonify({'error': 'Invalid or expired verification token'}), 400
        
        if user.verify_email_token(token):
            db.session.commit()
            
            log_audit_event('email_verified', user.id, 'user', str(user.id))
            
            return jsonify({'message': 'Email verified successfully'}), 200
        else:
            return jsonify({'error': 'Invalid or expired verification token'}), 400
            
    except Exception as e:
        return jsonify({'error': 'Email verification failed'}), 500

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            reset_token = user.generate_password_reset_token()
            db.session.commit()
            
            # Send reset email
            reset_link = f"{request.host_url}auth/reset-password?token={reset_token}"
            email_body = f"""
            Password Reset Request
            
            Click the link below to reset your password:
            {reset_link}
            
            This link will expire in 1 hour.
            
            If you didn't request this reset, please ignore this email.
            """
            
            send_email(email, "Password Reset - 7th Brain", email_body)
            
            log_audit_event('password_reset_requested', user.id, 'auth', None)
        
        # Always return success to prevent email enumeration
        return jsonify({'message': 'If the email exists, a reset link has been sent'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Password reset request failed'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token"""
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('password')
        
        if not token or not new_password:
            return jsonify({'error': 'Token and new password are required'}), 400
        
        # Validate password strength
        is_strong, message = validate_password_strength(new_password)
        if not is_strong:
            return jsonify({'error': message}), 400
        
        user = User.query.filter_by(password_reset_token=token).first()
        
        if not user:
            return jsonify({'error': 'Invalid or expired reset token'}), 400
        
        if user.reset_password_with_token(token, new_password):
            db.session.commit()
            
            log_audit_event('password_reset_completed', user.id, 'auth', None)
            
            # Send confirmation email
            send_email(user.email, "Password Changed - 7th Brain", 
                      "Your password has been successfully changed.")
            
            return jsonify({'message': 'Password reset successful'}), 200
        else:
            return jsonify({'error': 'Invalid or expired reset token'}), 400
            
    except Exception as e:
        return jsonify({'error': 'Password reset failed'}), 500

@auth_bp.route('/setup-2fa', methods=['POST'])
@login_required
def setup_2fa():
    """Setup two-factor authentication"""
    try:
        if current_user.two_factor_enabled:
            return jsonify({'error': '2FA is already enabled'}), 400
        
        secret, backup_codes = current_user.setup_two_factor()
        
        # Generate QR code
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=current_user.email,
            issuer_name="7th Brain Link Tracker"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        
        db.session.commit()
        
        log_audit_event('2fa_setup_initiated', current_user.id, 'auth', None)
        
        return jsonify({
            'secret': secret,
            'qr_code': f"data:image/png;base64,{qr_code_data}",
            'backup_codes': backup_codes
        }), 200
        
    except Exception as e:
        return jsonify({'error': '2FA setup failed'}), 500

@auth_bp.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    """Enable 2FA after verification"""
    try:
        data = request.get_json()
        totp_token = data.get('totp_token')
        
        if not totp_token:
            return jsonify({'error': 'TOTP token is required'}), 400
        
        if not current_user.totp_secret:
            return jsonify({'error': '2FA setup not initiated'}), 400
        
        if current_user.verify_totp(totp_token):
            current_user.two_factor_enabled = True
            db.session.commit()
            
            log_audit_event('2fa_enabled', current_user.id, 'auth', None)
            
            return jsonify({'message': '2FA enabled successfully'}), 200
        else:
            return jsonify({'error': 'Invalid TOTP token'}), 400
            
    except Exception as e:
        return jsonify({'error': '2FA enable failed'}), 500

@auth_bp.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable two-factor authentication"""
    try:
        data = request.get_json()
        password = data.get('password')
        totp_token = data.get('totp_token')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        if not current_user.check_password(password):
            return jsonify({'error': 'Invalid password'}), 401
        
        if current_user.two_factor_enabled and not current_user.verify_totp(totp_token):
            return jsonify({'error': 'Invalid 2FA token'}), 401
        
        current_user.two_factor_enabled = False
        current_user.totp_secret = None
        current_user.backup_codes = None
        
        db.session.commit()
        
        log_audit_event('2fa_disabled', current_user.id, 'auth', None)
        
        return jsonify({'message': '2FA disabled successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': '2FA disable failed'}), 500

@auth_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """Get user profile"""
    return jsonify(current_user.to_dict()), 200

@auth_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update user profile"""
    try:
        data = request.get_json()
        
        # Update allowed fields
        allowed_fields = ['first_name', 'last_name', 'company', 'phone', 'timezone']
        for field in allowed_fields:
            if field in data:
                setattr(current_user, field, data[field])
        
        db.session.commit()
        
        log_audit_event('profile_updated', current_user.id, 'user', str(current_user.id))
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': current_user.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Profile update failed'}), 500

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Current and new passwords are required'}), 400
        
        if not current_user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password strength
        is_strong, message = validate_password_strength(new_password)
        if not is_strong:
            return jsonify({'error': message}), 400
        
        current_user.set_password(new_password)
        db.session.commit()
        
        log_audit_event('password_changed', current_user.id, 'auth', None)
        
        # Send confirmation email
        send_email(current_user.email, "Password Changed - 7th Brain", 
                  "Your password has been successfully changed.")
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Password change failed'}), 500

@auth_bp.route('/sessions', methods=['GET'])
@login_required
def get_sessions():
    """Get active login sessions"""
    sessions = LoginSession.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).filter(
        LoginSession.expires_at > datetime.utcnow()
    ).order_by(LoginSession.last_activity.desc()).all()
    
    session_data = []
    for s in sessions:
        session_data.append({
            'id': s.id,
            'ip_address': s.ip_address,
            'location': s.location,
            'user_agent': s.user_agent,
            'created_at': s.created_at.isoformat(),
            'last_activity': s.last_activity.isoformat(),
            'is_current': s.session_token == session.get('session_token')
        })
    
    return jsonify({'sessions': session_data}), 200

@auth_bp.route('/sessions/<int:session_id>', methods=['DELETE'])
@login_required
def revoke_session(session_id):
    """Revoke a login session"""
    try:
        login_session = LoginSession.query.filter_by(
            id=session_id,
            user_id=current_user.id
        ).first()
        
        if not login_session:
            return jsonify({'error': 'Session not found'}), 404
        
        login_session.is_active = False
        db.session.commit()
        
        log_audit_event('session_revoked', current_user.id, 'auth', str(session_id))
        
        return jsonify({'message': 'Session revoked successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': 'Session revocation failed'}), 500

@auth_bp.route('/check', methods=['GET'])
def check_auth():
    """Check authentication status"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user': current_user.to_dict()
        }), 200
    else:
        return jsonify({'authenticated': False}), 200

