from flask import Flask, request, jsonify, send_file, redirect, render_template_string, send_from_directory
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import time
import requests
import json
from datetime import datetime, timedelta
import os
import uuid
from PIL import Image
import io
import base64
from urllib.parse import urlparse
import socket
import dns.resolver
import geoip2.database
import geoip2.errors
from user_agents import parse
import os
import bcrypt
from functools import wraps

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
# Configuration
SECRET_KEY = "7th-brain-advanced-link-tracker-secret-2024"
DATABASE_PATH = "app.db"

# Initialize database
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create users table for authentication and hierarchy
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member',
            status TEXT NOT NULL DEFAULT 'pending',
            parent_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            subscription_status TEXT DEFAULT 'inactive',
            subscription_expires TIMESTAMP,
            FOREIGN KEY (parent_id) REFERENCES users (id)
        )
    ''')
    
    # Create user_permissions table for granular permissions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            permission TEXT NOT NULL,
            granted_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (granted_by) REFERENCES users (id)
        )
    ''')
    
    # Create user_sessions table for session management
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Update tracking_links table to include user ownership
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tracking_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER,
            user_id INTEGER NOT NULL,
            original_url TEXT NOT NULL,
            tracking_token TEXT UNIQUE NOT NULL,
            recipient_email TEXT,
            status TEXT DEFAULT 'active',
            link_status TEXT DEFAULT 'created',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tracking_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracking_token TEXT NOT NULL,
            event_type TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            country_code TEXT,
            city TEXT,
            device_type TEXT,
            browser TEXT,
            is_bot BOOLEAN DEFAULT 0,
            bot_confidence REAL DEFAULT 0.0,
            blocked BOOLEAN DEFAULT 0,
            block_reason TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'ok',
            redirect_success BOOLEAN DEFAULT 1,
            email_opened BOOLEAN DEFAULT 0,
            link_clicked BOOLEAN DEFAULT 0,
            campaign_id INTEGER,
            user_id INTEGER,
            FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_reputation (
            ip_address TEXT PRIMARY KEY,
            reputation_score REAL DEFAULT 0.5,
            country_code TEXT,
            is_vpn BOOLEAN DEFAULT 0,
            is_proxy BOOLEAN DEFAULT 0,
            threat_types TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create default admin user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    admin_count = cursor.fetchone()[0]
    
    if admin_count == 0:
        import bcrypt
        password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role, status, subscription_status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@brainlinktracker.com', password_hash, 'admin', 'active', 'lifetime'))
    
    # Insert sample data with user ownership
    cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    admin_user = cursor.fetchone()
    if admin_user:
        admin_id = admin_user[0]
        cursor.execute("INSERT OR IGNORE INTO campaigns (id, name, description, user_id) VALUES (1, 'Test Campaign', 'Sample campaign for testing', ?)", (admin_id,))
        cursor.execute("INSERT OR IGNORE INTO tracking_links (campaign_id, user_id, original_url, tracking_token, recipient_email) VALUES (1, ?, 'https://example.com', 'test123token456', 'test@example.com')", (admin_id,))
    
    conn.commit()
    conn.close()

# Security Services
class SecurityService:
    BLOCKED_REFERRERS = [
        'facebook.com', 'twitter.com', 'linkedin.com', 'slack.com',
        'virustotal.com', 'urlvoid.com', 'hybrid-analysis.com'
    ]
    
    BOT_PATTERNS = [
        'curl', 'wget', 'python-requests', 'axios', 'postman',
        'bot', 'crawler', 'spider', 'scanner'
    ]
    
    @staticmethod
    def is_blocked_referrer(referrer):
        if not referrer:
            return False
        return any(blocked in referrer.lower() for blocked in SecurityService.BLOCKED_REFERRERS)
    
    @staticmethod
    def detect_bot(user_agent, headers):
        if not user_agent:
            return True, 0.9, "Missing user agent"
        
        ua_lower = user_agent.lower()
        confidence = 0.0
        reasons = []
        
        # Check bot patterns
        for pattern in SecurityService.BOT_PATTERNS:
            if pattern in ua_lower:
                confidence += 0.4
                reasons.append(f"Bot pattern: {pattern}")
        
        # Check missing headers
        if not headers.get('Accept'):
            confidence += 0.2
            reasons.append("Missing Accept header")
        
        if not headers.get('Accept-Language'):
            confidence += 0.1
            reasons.append("Missing Accept-Language")
        
        # Very short user agent
        if len(user_agent) < 20:
            confidence += 0.2
            reasons.append("Suspicious user agent length")
        
        is_bot = confidence > 0.6
        return is_bot, min(confidence, 1.0), "; ".join(reasons)
    
    @staticmethod
    def update_link_status(tracking_token, new_status, event_type='status_update'):
        """Update the status of a tracking link and log the event"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # Update the tracking link status
            cursor.execute('''
                UPDATE tracking_links 
                SET link_status = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE tracking_token = ?
            ''', (new_status, tracking_token))
            
            # Get link details for event logging
            cursor.execute('''
                SELECT campaign_id, user_id FROM tracking_links 
                WHERE tracking_token = ?
            ''', (tracking_token,))
            link_data = cursor.fetchone()
            
            if link_data:
                campaign_id, user_id = link_data
                
                # Log the status change event
                cursor.execute('''
                    INSERT INTO tracking_events 
                    (tracking_token, event_type, status, campaign_id, user_id, timestamp)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (tracking_token, event_type, new_status, campaign_id, user_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error updating link status: {e}")
            return False
    
    @staticmethod
    def get_link_status_history(tracking_token):
        """Get the status history for a tracking link"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT event_type, status, timestamp, ip_address, user_agent
                FROM tracking_events 
                WHERE tracking_token = ? 
                ORDER BY timestamp DESC
            ''', (tracking_token,))
            
            events = cursor.fetchall()
            conn.close()
            
            return [{
                'event_type': event[0],
                'status': event[1],
                'timestamp': event[2],
                'ip_address': event[3],
                'user_agent': event[4]
            } for event in events]
        except Exception as e:
            print(f"Error getting status history: {e}")
            return []
    
    @staticmethod
    def get_geolocation(ip_address):
        # Simple geolocation using ipapi.co
        try:
            if ip_address in ['127.0.0.1', '::1', 'localhost']:
                return {'country_code': 'US', 'city': 'Local', 'is_vpn': False}
            
            response = requests.get(f'http://ipapi.co/{ip_address}/json/', timeout=2)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country_code': data.get('country_code', 'XX'),
                    'city': data.get('city', 'Unknown'),
                    'is_vpn': data.get('threat', {}).get('is_anonymous', False)
                }
        except:
            pass
        
        return {'country_code': 'XX', 'city': 'Unknown', 'is_vpn': False}

# Authentication and Authorization Services
class AuthService:
    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    @staticmethod
    def verify_password(password, password_hash):
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    @staticmethod
    def generate_session_token():
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def create_session(user_id):
        token = AuthService.generate_session_token()
        expires_at = datetime.now() + timedelta(days=7)  # 7 days session
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_sessions (user_id, session_token, expires_at)
            VALUES (?, ?, ?)
        ''', (user_id, token, expires_at))
        conn.commit()
        conn.close()
        
        return token
    
    @staticmethod
    def validate_session(token):
        if not token:
            return None
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.role, u.status, u.parent_id
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND s.expires_at > datetime('now') AND u.status = 'active'
        ''', (token,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3],
                'status': result[4],
                'parent_id': result[5]
            }
        return None
    
    @staticmethod
    def get_user_hierarchy(user_id):
        """Get all users under this user's hierarchy"""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get direct children
        cursor.execute('SELECT id FROM users WHERE parent_id = ?', (user_id,))
        children = [row[0] for row in cursor.fetchall()]
        
        # Recursively get all descendants
        all_descendants = children.copy()
        for child_id in children:
            all_descendants.extend(AuthService.get_user_hierarchy(child_id))
        
        conn.close()
        return all_descendants
    
    @staticmethod
    def has_permission(user, permission):
        """Check if user has specific permission"""
        role_permissions = {
            'admin': ['*'],  # Admin has all permissions
            'admin2': [
                'view_users', 'manage_members', 'manage_workers', 'view_analytics',
                'create_campaigns', 'manage_campaigns', 'view_tracking_links'
            ],
            'member': [
                'create_campaigns', 'manage_own_campaigns', 'view_own_analytics',
                'create_tracking_links', 'view_own_tracking_links'
            ],
            'business': [
                'view_users', 'manage_members', 'manage_workers', 'view_analytics',
                'create_campaigns', 'manage_campaigns', 'view_tracking_links',
                'view_tracking_events', 'create_tracking_links'
            ],
            'worker': [
                'view_assigned_campaigns', 'view_assigned_tracking_links', 'view_tracking_events',
                'create_campaigns', 'create_tracking_links', 'manage_own_campaigns'
            ],
            'individual': [
                'create_campaigns', 'manage_own_campaigns', 'view_own_analytics',
                'create_tracking_links', 'view_own_tracking_links', 'view_tracking_events'
            ]
        }
        
        user_permissions = role_permissions.get(user['role'], [])
        return '*' in user_permissions or permission in user_permissions

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token and token.startswith('Bearer '):
            token = token[7:]  # Remove 'Bearer ' prefix
        
        user = AuthService.validate_session(token)
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            if not AuthService.has_permission(request.current_user, permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Generate tracking pixel (1x1 transparent PNG)
def generate_pixel():
    # 1x1 transparent PNG in base64
    pixel_data = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')
    return pixel_data

# Authentication Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'member')
        
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        # Check if user already exists
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'User already exists'}), 400
        
        # Hash password
        password_hash = AuthService.hash_password(password)
        
        # Create user with pending status (admin approval required)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, password_hash, role, 'pending'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Registration successful. Awaiting admin approval.'}), 201
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, username, email, password_hash, role, status
            FROM users WHERE username = ? OR email = ?
        ''', (username, username))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not AuthService.verify_password(password, user[3]):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if user[5] != 'active':
            return jsonify({'error': 'Account not activated. Please contact admin.'}), 403
        
        # Create session
        token = AuthService.create_session(user[0])
        
        # Update last login
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET last_login = datetime("now") WHERE id = ?', (user[0],))
        conn.commit()
        conn.close()
        
        return jsonify({
            'token': token,
            'user': {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[4],
                'status': user[5]
            }
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    try:
        token = request.headers.get('Authorization')
        if token and token.startswith('Bearer '):
            token = token[7:]
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM user_sessions WHERE session_token = ?', (token,))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'Logged out successfully'}), 200
        
    except Exception as e:
        print(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def get_current_user():
    return jsonify({'user': request.current_user}), 200

# User Management Routes (Admin only)
@app.route("/api/admin/users", methods=["GET"])
@require_auth
@require_permission("view_users")
def get_users():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Admin can see all users, Admin2/Business can see their hierarchy
        if request.current_user['role'] == 'admin':
            cursor.execute('''
                SELECT id, username, email, role, status, parent_id, created_at, last_login,
                       subscription_status, subscription_expires
                FROM users ORDER BY created_at DESC
            ''')
        else:
            # Admin2/Business can only see users in their hierarchy
            hierarchy = AuthService.get_user_hierarchy(request.current_user['id'])
            hierarchy.append(request.current_user['id'])  # Include self
            placeholders = ','.join('?' * len(hierarchy))
            cursor.execute(f'''
                SELECT id, username, email, role, status, parent_id, created_at, last_login,
                       subscription_status, subscription_expires
                FROM users WHERE id IN ({placeholders}) ORDER BY created_at DESC
            ''', hierarchy)
        
        users = cursor.fetchall()
        conn.close()
        
        users_list = []
        for user in users:
            users_list.append({
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[3],
                'status': user[4],
                'parent_id': user[5],
                'created_at': user[6],
                'last_login': user[7],
                'subscription_status': user[8],
                'subscription_expires': user[9]
            })
        
        return jsonify({'users': users_list}), 200
        
    except Exception as e:
        print(f"Get users error: {e}")
        return jsonify({'error': 'Failed to get users'}), 500

@app.route('/api/admin/users/<int:user_id>/approve', methods=['POST'])
@require_auth
@require_permission('manage_members')
def approve_user(user_id):
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET status = ? WHERE id = ?', ('active', user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'User approved successfully'}), 200
        
    except Exception as e:
        print(f"Approve user error: {e}")
        return jsonify({'error': 'Failed to approve user'}), 500

@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@require_auth
@require_permission('manage_members')
def update_user_role(user_id):
    try:
        data = request.get_json()
        new_role = data.get('role')
        parent_id = data.get('parent_id')
        
        if new_role not in ['admin2', 'member', 'worker', 'business', 'individual']:
            return jsonify({'error': 'Invalid role'}), 400
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Set parent_id based on role and current user
        if new_role == 'admin2' and request.current_user['role'] == 'admin':
            parent_id = request.current_user['id']
        elif new_role in ['member', 'worker', 'business', 'individual'] and request.current_user['role'] in ['admin', 'admin2', 'business']:
            parent_id = request.current_user['id']
        
        cursor.execute('UPDATE users SET role = ?, parent_id = ? WHERE id = ?', (new_role, parent_id, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({'message': 'User role updated successfully'}), 200
        
    except Exception as e:
        print(f"Update user role error: {e}")
        return jsonify({'error': 'Failed to update user role'}), 500

# Routes
@app.route('/track/pixel/<token>')
def track_pixel(token):
    try:
        # Update link status to 'opened' (email opened)
        SecurityService.update_link_status(token, 'opened', 'email_open')
        
        # Get request info
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')
        
        # Security checks
        if SecurityService.is_blocked_referrer(referrer):
            SecurityService.update_link_status(token, 'blocked', 'security_block')
            record_event(token, 'pixel_blocked', ip_address, user_agent, block_reason='Social referrer blocked')
        else:
            # Bot detection
            is_bot, confidence, reason = SecurityService.detect_bot(user_agent, dict(request.headers))
            
            if is_bot:
                SecurityService.update_link_status(token, 'blocked', 'bot_detected')
                record_event(token, 'pixel_blocked', ip_address, user_agent, 
                           is_bot=True, bot_confidence=confidence, block_reason=f'Bot detected: {reason}')
            else:
                # Get geolocation
                geo = SecurityService.get_geolocation(ip_address)
                
                # Record successful pixel view and update opens count
                record_event(token, 'pixel_view', ip_address, user_agent,
                           country_code=geo['country_code'], city=geo['city'])
                
                # Update opens count in tracking_links
                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute('UPDATE tracking_links SET opens = COALESCE(opens, 0) + 1 WHERE tracking_token = ?', (token,))
                conn.commit()
                conn.close()
        
        # Always return pixel
        pixel_data = generate_pixel()
        response = app.response_class(
            pixel_data,
            mimetype='image/png',
            headers={
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        )
        return response
        
    except Exception as e:
        print(f"Error in pixel tracking: {e}")
        SecurityService.update_link_status(token, 'error', 'system_error')
        return send_file(io.BytesIO(generate_pixel()), mimetype='image/png')

@app.route('/track/click/<token>')
def track_click(token):
    try:
        # Update link status to 'clicked'
        SecurityService.update_link_status(token, 'clicked', 'click')
        
        # Get request info
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')
        
        # Security checks
        if SecurityService.is_blocked_referrer(referrer):
            SecurityService.update_link_status(token, 'blocked', 'security_block')
            record_event(token, 'click_blocked', ip_address, user_agent, block_reason='Social referrer blocked')
            return "Access Denied", 403
        
        # Bot detection
        is_bot, confidence, reason = SecurityService.detect_bot(user_agent, dict(request.headers))
        
        if is_bot:
            SecurityService.update_link_status(token, 'blocked', 'bot_detected')
            record_event(token, 'click_blocked', ip_address, user_agent,
                       is_bot=True, bot_confidence=confidence, block_reason=f'Bot detected: {reason}')
            return "Access Denied", 403
        
        # Get original URL
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT original_url FROM tracking_links WHERE tracking_token = ? AND is_active = 1", (token,))
        result = cursor.fetchone()
        
        if not result:
            SecurityService.update_link_status(token, 'not_found', 'error')
            conn.close()
            return "Link not found", 404
        
        original_url = result[0]
        
        # Update click count
        cursor.execute('UPDATE tracking_links SET clicks = COALESCE(clicks, 0) + 1 WHERE tracking_token = ?', (token,))
        conn.commit()
        conn.close()
        
        # Get geolocation
        geo = SecurityService.get_geolocation(ip_address)
        
        # Record successful click
        record_event(token, 'click', ip_address, user_agent,
                   country_code=geo['country_code'], city=geo['city'])
        
        # Update status to 'redirected' before redirect
        SecurityService.update_link_status(token, 'redirected', 'redirect')
        
        # Redirect to original URL
        response = redirect(original_url, code=302)
        
        # Update final status to 'ok' after successful redirect setup
        SecurityService.update_link_status(token, 'ok', 'redirect_success')
        
        return response
        
    except Exception as e:
        print(f"Error in click tracking: {e}")
        SecurityService.update_link_status(token, 'error', 'system_error')
        return "Internal Server Error", 500

def record_event(token, event_type, ip_address, user_agent, country_code='XX', city='Unknown',
                is_bot=False, bot_confidence=0.0, blocked=False, block_reason=None):
    try:
        # Parse user agent
        device_type = 'Unknown'
        browser = 'Unknown'
        
        if user_agent:
            ua = parse(user_agent)
            device_type = 'Mobile' if ua.is_mobile else 'Tablet' if ua.is_tablet else 'Desktop'
            browser = f"{ua.browser.family} {ua.browser.version_string}" if ua.browser.family else 'Unknown'
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get campaign_id and user_id from tracking_links
        cursor.execute('SELECT campaign_id, user_id FROM tracking_links WHERE tracking_token = ?', (token,))
        link_data = cursor.fetchone()
        campaign_id = link_data[0] if link_data else None
        user_id = link_data[1] if link_data else None
        
        # Set event-specific flags
        email_opened = event_type == 'pixel_view'
        link_clicked = event_type == 'click'
        redirect_success = event_type == 'click' and not blocked
        
        cursor.execute('''
            INSERT INTO tracking_events 
            (tracking_token, event_type, ip_address, user_agent, country_code, city, 
             device_type, browser, is_bot, bot_confidence, blocked, block_reason,
             email_opened, link_clicked, redirect_success, campaign_id, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (token, event_type, ip_address, user_agent, country_code, city,
              device_type, browser, is_bot, bot_confidence, blocked, block_reason,
              email_opened, link_clicked, redirect_success, campaign_id, user_id))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error recording event: {e}")

# Analytics API
@app.route('/api/analytics')
def get_analytics():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get overview stats
        cursor.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type = 'click' AND blocked = 0")
        total_clicks = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type = 'pixel_view' AND blocked = 0")
        total_opens = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT ip_address) FROM tracking_events WHERE blocked = 0")
        unique_visitors = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM tracking_events WHERE blocked = 1")
        blocked_requests = cursor.fetchone()[0]
        
        # Get hourly activity (last 24 hours)
        cursor.execute('''
            SELECT 
                strftime('%H:00', timestamp) as hour,
                COUNT(CASE WHEN event_type = 'click' AND blocked = 0 THEN 1 END) as clicks,
                COUNT(CASE WHEN event_type = 'pixel_view' AND blocked = 0 THEN 1 END) as opens,
                COUNT(CASE WHEN blocked = 1 THEN 1 END) as blocked
            FROM tracking_events 
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY strftime('%H', timestamp)
            ORDER BY hour
        ''')
        hourly_data = cursor.fetchall()
        
        # Get top countries
        cursor.execute('''
            SELECT 
                country_code,
                COUNT(CASE WHEN event_type = 'click' AND blocked = 0 THEN 1 END) as clicks,
                COUNT(CASE WHEN event_type = 'pixel_view' AND blocked = 0 THEN 1 END) as opens
            FROM tracking_events 
            WHERE blocked = 0 AND country_code != 'XX'
            GROUP BY country_code
            ORDER BY (clicks + opens) DESC
            LIMIT 10
        ''')
        country_data = cursor.fetchall()
        
        # Get device types
        cursor.execute('''
            SELECT 
                device_type,
                COUNT(*) as count
            FROM tracking_events 
            WHERE blocked = 0 AND device_type != 'Unknown'
            GROUP BY device_type
        ''')
        device_data = cursor.fetchall()
        
        # Get security events
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN is_bot = 1 THEN 'Bot Detected'
                    WHEN block_reason LIKE '%referrer%' THEN 'Social Referrer'
                    WHEN block_reason LIKE '%rate%' THEN 'Rate Limited'
                    ELSE 'Other'
                END as event_type,
                COUNT(*) as count
            FROM tracking_events 
            WHERE blocked = 1
            GROUP BY event_type
        ''')
        security_data = cursor.fetchall()
        
        # Get recent activity
        cursor.execute('''
            SELECT 
                event_type,
                country_code,
                city,
                device_type,
                browser,
                blocked,
                timestamp
            FROM tracking_events 
            ORDER BY timestamp DESC
            LIMIT 20
        ''')
        recent_activity = cursor.fetchall()
        
        conn.close()
        
        # Format response
        analytics = {
            'overview': {
                'totalClicks': total_clicks,
                'totalOpens': total_opens,
                'uniqueVisitors': unique_visitors,
                'conversionRate': round((total_clicks / max(total_opens, 1)) * 100, 1),
                'blockedRequests': blocked_requests,
                'riskScore': min(blocked_requests / max(total_clicks + total_opens, 1), 1.0)
            },
            'hourlyActivity': [
                {'hour': row[0], 'clicks': row[1], 'opens': row[2], 'blocked': row[3]}
                for row in hourly_data
            ],
            'topCountries': [
                {
                    'country': get_country_name(row[0]),
                    'code': row[0],
                    'clicks': row[1],
                    'opens': row[2],
                    'percentage': round(((row[1] + row[2]) / max(total_clicks + total_opens, 1)) * 100, 1)
                }
                for row in country_data
            ],
            'deviceTypes': [
                {
                    'name': row[0],
                    'count': row[1],
                    'value': round((row[1] / max(sum(d[1] for d in device_data), 1)) * 100, 1)
                }
                for row in device_data
            ],
            'securityEvents': [
                {'type': row[0], 'count': row[1], 'severity': 'high' if 'Bot' in row[0] else 'medium'}
                for row in security_data
            ],
            'recentActivity': [
                {
                    'time': get_time_ago(row[6]),
                    'event': format_event_name(row[0]),
                    'location': f"{row[2]}, {row[1]}" if row[2] != 'Unknown' else row[1],
                    'device': row[4] if row[4] != 'Unknown' else row[3],
                    'status': 'blocked' if row[5] else 'success'
                }
                for row in recent_activity
            ]
        }
        
        return jsonify(analytics)
        
    except Exception as e:
        print(f"Error getting analytics: {e}")
        return jsonify({'error': 'Failed to get analytics'}), 500

def get_country_name(code):
    country_names = {
        'US': 'United States', 'GB': 'United Kingdom', 'CA': 'Canada',
        'AU': 'Australia', 'DE': 'Germany', 'FR': 'France', 'JP': 'Japan',
        'CN': 'China', 'IN': 'India', 'BR': 'Brazil'
    }
    return country_names.get(code, code)

def get_time_ago(timestamp):
    try:
        event_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        now = datetime.now()
        diff = now - event_time
        
        if diff.seconds < 60:
            return f"{diff.seconds} sec ago"
        elif diff.seconds < 3600:
            return f"{diff.seconds // 60} min ago"
        elif diff.days == 0:
            return f"{diff.seconds // 3600} hr ago"
        else:
            return f"{diff.days} day ago"
    except:
        return "Unknown"

def format_event_name(event_type):
    names = {
        'pixel_view': 'Email opened',
        'click': 'Link clicked',
        'pixel_blocked': 'Email blocked',
        'click_blocked': 'Click blocked'
    }
    return names.get(event_type, event_type)

# Health check
@app.route('/health')
def health():
    return jsonify({'status': 'OK', 'timestamp': datetime.now().isoformat()})

# Serve frontend


# API endpoint to get link status history
@app.route('/api/tracking-links/<tracking_token>/status-history')
@require_auth
def get_link_status_history(tracking_token):
    try:
        history = SecurityService.get_link_status_history(tracking_token)
        return jsonify({'history': history})
    except Exception as e:
        print(f"Get status history error: {e}")
        return jsonify({'error': 'Failed to get status history'}), 500

# API endpoint to manually update link status (admin only)
@app.route('/api/tracking-links/<tracking_token>/status', methods=['PUT'])
@require_auth
def update_link_status_api(tracking_token):
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if not new_status:
            return jsonify({'error': 'Status is required'}), 400
        
        # Check if user has permission (admin or link owner)
        user = get_current_user()
        if user['role'] not in ['admin', 'admin2']:
            # Check if user owns this link
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT user_id FROM tracking_links WHERE tracking_token = ?', (tracking_token,))
            result = cursor.fetchone()
            conn.close()
            
            if not result or result[0] != user['id']:
                return jsonify({'error': 'Permission denied'}), 403
        
        success = SecurityService.update_link_status(tracking_token, new_status, 'manual_update')
        
        if success:
            return jsonify({'message': 'Status updated successfully'})
        else:
            return jsonify({'error': 'Failed to update status'}), 500
            
    except Exception as e:
        print(f"Update status error: {e}")
        return jsonify({'error': 'Failed to update status'}), 500

# Role-based analytics endpoints
@app.route('/api/analytics/hierarchy')
@require_auth
def get_hierarchy_analytics():
    try:
        user = get_current_user()
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        if user['role'] == 'admin':
            # Admin sees everything
            cursor.execute('''
                SELECT 
                    u.role,
                    COUNT(DISTINCT u.id) as user_count,
                    COUNT(DISTINCT c.id) as campaign_count,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM users u
                LEFT JOIN campaigns c ON u.id = c.user_id
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                GROUP BY u.role
            ''')
            
        elif user['role'] == 'admin2':
            # Admin2 sees their team only
            cursor.execute('''
                SELECT 
                    u.role,
                    COUNT(DISTINCT u.id) as user_count,
                    COUNT(DISTINCT c.id) as campaign_count,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM users u
                LEFT JOIN campaigns c ON u.id = c.user_id
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                WHERE u.created_by = ? OR u.id = ?
                GROUP BY u.role
            ''', (user['id'], user['id']))
            
        else:
            # Members and Workers see only their own data
            cursor.execute('''
                SELECT 
                    ? as role,
                    1 as user_count,
                    COUNT(DISTINCT c.id) as campaign_count,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM campaigns c
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                WHERE c.user_id = ?
            ''', (user['role'], user['id']))
        
        results = cursor.fetchall()
        conn.close()
        
        hierarchy_data = []
        for row in results:
            hierarchy_data.append({
                'role': row[0],
                'user_count': row[1],
                'campaign_count': row[2],
                'link_count': row[3],
                'total_clicks': row[4],
                'total_opens': row[5],
                'conversion_rate': (row[4] / row[5] * 100) if row[5] > 0 else 0
            })
        
        return jsonify({'hierarchy_analytics': hierarchy_data})
        
    except Exception as e:
        print(f"Hierarchy analytics error: {e}")
        return jsonify({'error': 'Failed to fetch hierarchy analytics'}), 500

@app.route('/api/analytics/campaigns')
@require_auth
def get_campaign_analytics():
    try:
        user = get_current_user()
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        if user['role'] == 'admin':
            # Admin sees all campaigns
            cursor.execute('''
                SELECT 
                    c.id, c.name, c.status, c.created_at,
                    u.username as owner,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM campaigns c
                JOIN users u ON c.user_id = u.id
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                GROUP BY c.id, c.name, c.status, c.created_at, u.username
                ORDER BY c.created_at DESC
            ''')
            
        elif user['role'] == 'admin2':
            # Admin2 sees campaigns from their team
            cursor.execute('''
                SELECT 
                    c.id, c.name, c.status, c.created_at,
                    u.username as owner,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM campaigns c
                JOIN users u ON c.user_id = u.id
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                WHERE u.created_by = ? OR u.id = ?
                GROUP BY c.id, c.name, c.status, c.created_at, u.username
                ORDER BY c.created_at DESC
            ''', (user['id'], user['id']))
            
        else:
            # Members and Workers see only their own campaigns
            cursor.execute('''
                SELECT 
                    c.id, c.name, c.status, c.created_at,
                    ? as owner,
                    COUNT(DISTINCT tl.id) as link_count,
                    COALESCE(SUM(tl.clicks), 0) as total_clicks,
                    COALESCE(SUM(tl.opens), 0) as total_opens
                FROM campaigns c
                LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
                WHERE c.user_id = ?
                GROUP BY c.id, c.name, c.status, c.created_at
                ORDER BY c.created_at DESC
            ''', (user['username'], user['id']))
        
        results = cursor.fetchall()
        conn.close()
        
        campaigns_data = []
        for row in results:
            campaigns_data.append({
                'id': row[0],
                'name': row[1],
                'status': row[2],
                'created_at': row[3],
                'owner': row[4],
                'link_count': row[5],
                'total_clicks': row[6],
                'total_opens': row[7],
                'conversion_rate': (row[6] / row[7] * 100) if row[7] > 0 else 0
            })
        
        return jsonify({'campaigns': campaigns_data})
        
    except Exception as e:
        print(f"Campaign analytics error: {e}")
        return jsonify({'error': 'Failed to fetch campaign analytics'}), 500

@app.route('/')
def serve_frontend():
    return send_file('static/index.html')

@app.route('/<path:path>')
def serve_static(path):
    # Don't serve static files for API routes
    if path.startswith('api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    return send_file(f'static/{path}')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)


# New API endpoints for tracking links management

@app.route('/api/tracking-links', methods=['GET'])
@require_auth
def get_tracking_links():
    """Get all tracking links with their details"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                tl.id,
                tl.tracking_token,
                tl.original_url,
                tl.recipient_email,
                tl.created_at,
                tl.is_active,
                c.name as campaign_name,
                COUNT(te.id) as total_events,
                COUNT(CASE WHEN te.event_type = 'click' AND te.blocked = 0 THEN 1 END) as clicks,
                COUNT(CASE WHEN te.event_type = 'pixel_view' AND te.blocked = 0 THEN 1 END) as opens
            FROM tracking_links tl
            LEFT JOIN campaigns c ON tl.campaign_id = c.id
            LEFT JOIN tracking_events te ON tl.tracking_token = te.tracking_token
            GROUP BY tl.id, tl.tracking_token, tl.original_url, tl.recipient_email, tl.created_at, tl.is_active, c.name
            ORDER BY tl.created_at DESC
        ''')
        
        links = cursor.fetchall()
        conn.close()
        
        tracking_links = []
        for link in links:
            tracking_links.append({
                'id': link[0],
                'tracking_token': link[1],
                'original_url': link[2],
                'recipient_email': link[3] or 'N/A',
                'created_at': link[4],
                'is_active': bool(link[5]),
                'campaign_name': link[6] or 'Default Campaign',
                'total_events': link[7],
                'clicks': link[8],
                'opens': link[9],
                'tracking_url': f"{request.host_url}track/click/{link[1]}",
                'pixel_url': f"{request.host_url}track/pixel/{link[1]}"
            })
        
        return jsonify({
            'success': True,
            'tracking_links': tracking_links,
            'total_count': len(tracking_links)
        })
        
    except Exception as e:
        print(f"Error getting tracking links: {e}")
        return jsonify({'success': False, 'error': 'Failed to get tracking links'}), 500

@app.route('/api/tracking-links', methods=['POST'])
@require_auth
def create_tracking_link():
    """Create a new tracking link"""
    try:
        data = request.get_json()
        original_url = data.get('original_url')
        recipient_email = data.get('recipient_email', '')
        campaign_name = data.get('campaign_name', 'Default Campaign')
        
        if not original_url:
            return jsonify({'success': False, 'error': 'Original URL is required'}), 400
        
        # Validate URL format
        if not original_url.startswith(('http://', 'https://')):
            original_url = 'https://' + original_url
        
        # Generate unique tracking token
        import uuid
        tracking_token = str(uuid.uuid4()).replace('-', '')[:16]
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get or create campaign
        cursor.execute("SELECT id FROM campaigns WHERE name = ?", (campaign_name,))
        campaign = cursor.fetchone()
        
        if not campaign:
            cursor.execute("INSERT INTO campaigns (name, description, user_id) VALUES (?, ?, ?)", 
                         (campaign_name, f"Campaign for {original_url}", request.current_user['id']))
            campaign_id = cursor.lastrowid
        else:
            campaign_id = campaign[0]
        
        # Create tracking link
        cursor.execute('''
            INSERT INTO tracking_links (campaign_id, user_id, original_url, tracking_token, recipient_email)
            VALUES (?, ?, ?, ?, ?)
        ''', (campaign_id, request.current_user['id'], original_url, tracking_token, recipient_email))
        
        link_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        tracking_url = f"{request.host_url}track/click/{tracking_token}"
        pixel_url = f"{request.host_url}track/pixel/{tracking_token}"
        
        return jsonify({
            'success': True,
            'tracking_link': {
                'id': link_id,
                'tracking_token': tracking_token,
                'original_url': original_url,
                'recipient_email': recipient_email,
                'campaign_name': campaign_name,
                'tracking_url': tracking_url,
                'pixel_url': pixel_url,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        })
        
    except Exception as e:
        print(f"Error creating tracking link: {e}")
        return jsonify({'success': False, 'error': 'Failed to create tracking link'}), 500

@app.route('/api/tracking-events/<token>', methods=['GET'])
def get_tracking_events(token):
    """Get all events for a specific tracking token"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                id,
                event_type,
                ip_address,
                user_agent,
                country_code,
                city,
                device_type,
                browser,
                is_bot,
                blocked,
                block_reason,
                timestamp
            FROM tracking_events 
            WHERE tracking_token = ?
            ORDER BY timestamp DESC
        ''', (token,))
        
        events = cursor.fetchall()
        conn.close()
        
        tracking_events = []
        for event in events:
            tracking_events.append({
                'id': event[0],
                'event_type': event[1],
                'ip_address': event[2],
                'user_agent': event[3],
                'country_code': event[4],
                'city': event[5],
                'device_type': event[6],
                'browser': event[7],
                'is_bot': bool(event[8]),
                'blocked': bool(event[9]),
                'block_reason': event[10],
                'timestamp': event[11]
            })
        
        return jsonify({
            'success': True,
            'events': tracking_events,
            'total_count': len(tracking_events)
        })
        
    except Exception as e:
        print(f"Error getting tracking events: {e}")
        return jsonify({'success': False, 'error': 'Failed to get tracking events'}), 500



@app.route('/')
def serve_frontend():
    return send_file('static/index.html')

@app.route('/<path:path>')
def serve_static(path):
    # Don't serve static files for API routes
    if path.startswith('api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    return send_file(f'static/{path}')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)


# Business User Management Routes
@app.route('/api/business/create-worker', methods=['POST'])
@require_auth
@require_permission('manage_workers')
def create_worker():
    """Allow business users to create worker accounts"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password', 'worker123')  # Default password
        
        if not username or not email:
            return jsonify({'error': 'Username and email are required'}), 400
        
        # Check if user already exists
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'User already exists'}), 400
        
        # Create worker account under current business user
        password_hash = AuthService.hash_password(password)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role, status, parent_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, email, password_hash, 'worker', 'active', request.current_user['id']))
        
        worker_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'Worker account created successfully',
            'worker_id': worker_id,
            'username': username,
            'email': email,
            'default_password': password
        }), 201
        
    except Exception as e:
        print(f"Create worker error: {e}")
        return jsonify({'error': 'Failed to create worker account'}), 500

@app.route('/api/business/workers', methods=['GET'])
@require_auth
@require_permission('manage_workers')
def get_business_workers():
    """Get all workers under current business user"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, email, role, status, created_at, last_login
            FROM users 
            WHERE parent_id = ? AND role = 'worker'
            ORDER BY created_at DESC
        ''', (request.current_user['id'],))
        
        workers = cursor.fetchall()
        conn.close()
        
        workers_list = []
        for worker in workers:
            workers_list.append({
                'id': worker[0],
                'username': worker[1],
                'email': worker[2],
                'role': worker[3],
                'status': worker[4],
                'created_at': worker[5],
                'last_login': worker[6]
            })
        
        return jsonify({'workers': workers_list}), 200
        
    except Exception as e:
        print(f"Get business workers error: {e}")
        return jsonify({'error': 'Failed to get workers'}), 500

@app.route('/api/business/campaigns', methods=['GET'])
@require_auth
@require_permission('manage_campaigns')
def get_business_campaigns():
    """Get all campaigns for business user and their workers"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get campaigns for business user and their workers
        hierarchy = AuthService.get_user_hierarchy(request.current_user['id'])
        hierarchy.append(request.current_user['id'])  # Include self
        placeholders = ','.join('?' * len(hierarchy))
        
        cursor.execute(f'''
            SELECT c.id, c.name, c.description, c.status, c.created_at, u.username as creator
            FROM campaigns c
            JOIN users u ON c.user_id = u.id
            WHERE c.user_id IN ({placeholders})
            ORDER BY c.created_at DESC
        ''', hierarchy)
        
        campaigns = cursor.fetchall()
        conn.close()
        
        campaigns_list = []
        for campaign in campaigns:
            campaigns_list.append({
                'id': campaign[0],
                'name': campaign[1],
                'description': campaign[2],
                'status': campaign[3],
                'created_at': campaign[4],
                'creator': campaign[5]
            })
        
        return jsonify({'campaigns': campaigns_list}), 200
        
    except Exception as e:
        print(f"Get business campaigns error: {e}")
        return jsonify({'error': 'Failed to get campaigns'}), 500

@app.route('/api/business/analytics', methods=['GET'])
@require_auth
@require_permission('view_analytics')
def get_business_analytics():
    """Get analytics for business user and their workers"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get hierarchy of users under this business
        hierarchy = AuthService.get_user_hierarchy(request.current_user['id'])
        hierarchy.append(request.current_user['id'])  # Include self
        placeholders = ','.join('?' * len(hierarchy))
        
        # Get total campaigns
        cursor.execute(f'SELECT COUNT(*) FROM campaigns WHERE user_id IN ({placeholders})', hierarchy)
        total_campaigns = cursor.fetchone()[0]
        
        # Get total tracking links
        cursor.execute(f'SELECT COUNT(*) FROM tracking_links WHERE user_id IN ({placeholders})', hierarchy)
        total_links = cursor.fetchone()[0]
        
        # Get total clicks
        cursor.execute(f'SELECT COUNT(*) FROM tracking_events WHERE user_id IN ({placeholders}) AND event_type = "click"', hierarchy)
        total_clicks = cursor.fetchone()[0]
        
        # Get total email opens
        cursor.execute(f'SELECT COUNT(*) FROM tracking_events WHERE user_id IN ({placeholders}) AND event_type = "email_open"', hierarchy)
        total_opens = cursor.fetchone()[0]
        
        # Get workers count
        cursor.execute('SELECT COUNT(*) FROM users WHERE parent_id = ? AND role = "worker"', (request.current_user['id'],))
        workers_count = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_campaigns': total_campaigns,
            'total_links': total_links,
            'total_clicks': total_clicks,
            'total_opens': total_opens,
            'workers_count': workers_count,
            'conversion_rate': round((total_clicks / max(total_opens, 1)) * 100, 2)
        }), 200
        
    except Exception as e:
        print(f"Get business analytics error: {e}")
        return jsonify({'error': 'Failed to get analytics'}), 500


# Worker/Individual Tracking Data Routes
@app.route('/api/tracking/detailed-events/<tracking_token>', methods=['GET'])
@require_auth
@require_permission('view_tracking_events')
def get_detailed_tracking_events(tracking_token):
    """Get detailed tracking events for a specific tracking link"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Check if user has access to this tracking link
        cursor.execute('''
            SELECT tl.user_id, tl.original_url, tl.recipient_email, c.name as campaign_name
            FROM tracking_links tl
            LEFT JOIN campaigns c ON tl.campaign_id = c.id
            WHERE tl.tracking_token = ?
        ''', (tracking_token,))
        
        link_info = cursor.fetchone()
        if not link_info:
            conn.close()
            return jsonify({'error': 'Tracking link not found'}), 404
        
        link_owner_id = link_info[0]
        
        # Check access permissions
        if request.current_user['role'] not in ['admin', 'admin2']:
            # For business users, check if link belongs to them or their workers
            if request.current_user['role'] == 'business':
                hierarchy = AuthService.get_user_hierarchy(request.current_user['id'])
                hierarchy.append(request.current_user['id'])
                if link_owner_id not in hierarchy:
                    conn.close()
                    return jsonify({'error': 'Access denied'}), 403
            # For worker/individual, only their own links
            elif link_owner_id != request.current_user['id']:
                conn.close()
                return jsonify({'error': 'Access denied'}), 403
        
        # Get detailed tracking events
        cursor.execute('''
            SELECT event_type, ip_address, user_agent, country_code, city, device_type, 
                   browser, is_bot, bot_confidence, blocked, block_reason, timestamp,
                   status, redirect_success, email_opened, link_clicked
            FROM tracking_events 
            WHERE tracking_token = ?
            ORDER BY timestamp DESC
        ''', (tracking_token,))
        
        events = cursor.fetchall()
        
        # Get IP reputation data
        cursor.execute('''
            SELECT DISTINCT te.ip_address, ir.reputation_score, ir.is_vpn, ir.is_proxy, ir.threat_types
            FROM tracking_events te
            LEFT JOIN ip_reputation ir ON te.ip_address = ir.ip_address
            WHERE te.tracking_token = ?
        ''', (tracking_token,))
        
        ip_data = cursor.fetchall()
        conn.close()
        
        events_list = []
        for event in events:
            events_list.append({
                'event_type': event[0],
                'ip_address': event[1],
                'user_agent': event[2],
                'country_code': event[3],
                'city': event[4],
                'device_type': event[5],
                'browser': event[6],
                'is_bot': bool(event[7]),
                'bot_confidence': event[8],
                'blocked': bool(event[9]),
                'block_reason': event[10],
                'timestamp': event[11],
                'status': event[12],
                'redirect_success': bool(event[13]),
                'email_opened': bool(event[14]),
                'link_clicked': bool(event[15])
            })
        
        ip_reputation = {}
        for ip_info in ip_data:
            ip_reputation[ip_info[0]] = {
                'reputation_score': ip_info[1],
                'is_vpn': bool(ip_info[2]),
                'is_proxy': bool(ip_info[3]),
                'threat_types': ip_info[4]
            }
        
        return jsonify({
            'link_info': {
                'original_url': link_info[1],
                'recipient_email': link_info[2],
                'campaign_name': link_info[3]
            },
            'events': events_list,
            'ip_reputation': ip_reputation,
            'total_events': len(events_list)
        }), 200
        
    except Exception as e:
        print(f"Get detailed tracking events error: {e}")
        return jsonify({'error': 'Failed to get tracking events'}), 500

@app.route('/api/tracking/user-links', methods=['GET'])
@require_auth
def get_user_tracking_links():
    """Get all tracking links for current user with detailed stats"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Determine which links to show based on user role
        if request.current_user['role'] == 'admin':
            # Admin sees all links
            cursor.execute('''
                SELECT tl.id, tl.tracking_token, tl.original_url, tl.recipient_email, 
                       tl.created_at, tl.status, c.name as campaign_name, u.username as creator
                FROM tracking_links tl
                LEFT JOIN campaigns c ON tl.campaign_id = c.id
                LEFT JOIN users u ON tl.user_id = u.id
                ORDER BY tl.created_at DESC
            ''')
        elif request.current_user['role'] in ['admin2', 'business']:
            # Admin2/Business sees their hierarchy's links
            hierarchy = AuthService.get_user_hierarchy(request.current_user['id'])
            hierarchy.append(request.current_user['id'])
            placeholders = ','.join('?' * len(hierarchy))
            cursor.execute(f'''
                SELECT tl.id, tl.tracking_token, tl.original_url, tl.recipient_email, 
                       tl.created_at, tl.status, c.name as campaign_name, u.username as creator
                FROM tracking_links tl
                LEFT JOIN campaigns c ON tl.campaign_id = c.id
                LEFT JOIN users u ON tl.user_id = u.id
                WHERE tl.user_id IN ({placeholders})
                ORDER BY tl.created_at DESC
            ''', hierarchy)
        else:
            # Worker/Individual sees only their own links
            cursor.execute('''
                SELECT tl.id, tl.tracking_token, tl.original_url, tl.recipient_email, 
                       tl.created_at, tl.status, c.name as campaign_name, u.username as creator
                FROM tracking_links tl
                LEFT JOIN campaigns c ON tl.campaign_id = c.id
                LEFT JOIN users u ON tl.user_id = u.id
                WHERE tl.user_id = ?
                ORDER BY tl.created_at DESC
            ''', (request.current_user['id'],))
        
        links = cursor.fetchall()
        
        # Get stats for each link
        links_with_stats = []
        for link in links:
            tracking_token = link[1]
            
            # Get click count
            cursor.execute('SELECT COUNT(*) FROM tracking_events WHERE tracking_token = ? AND event_type = "click"', (tracking_token,))
            clicks = cursor.fetchone()[0]
            
            # Get email open count
            cursor.execute('SELECT COUNT(*) FROM tracking_events WHERE tracking_token = ? AND event_type = "email_open"', (tracking_token,))
            opens = cursor.fetchone()[0]
            
            # Get unique visitors
            cursor.execute('SELECT COUNT(DISTINCT ip_address) FROM tracking_events WHERE tracking_token = ?', (tracking_token,))
            unique_visitors = cursor.fetchone()[0]
            
            # Get geographic data
            cursor.execute('''
                SELECT country_code, COUNT(*) as count
                FROM tracking_events 
                WHERE tracking_token = ? AND country_code IS NOT NULL
                GROUP BY country_code
                ORDER BY count DESC
                LIMIT 5
            ''', (tracking_token,))
            geo_data = cursor.fetchall()
            
            links_with_stats.append({
                'id': link[0],
                'tracking_token': link[1],
                'original_url': link[2],
                'recipient_email': link[3],
                'created_at': link[4],
                'status': link[5],
                'campaign_name': link[6],
                'creator': link[7],
                'stats': {
                    'clicks': clicks,
                    'opens': opens,
                    'unique_visitors': unique_visitors,
                    'conversion_rate': round((clicks / max(opens, 1)) * 100, 2),
                    'top_countries': [{'country': geo[0], 'count': geo[1]} for geo in geo_data]
                }
            })
        
        conn.close()
        
        return jsonify({
            'links': links_with_stats,
            'total_links': len(links_with_stats)
        }), 200
        
    except Exception as e:
        print(f"Get user tracking links error: {e}")
        return jsonify({'error': 'Failed to get tracking links'}), 500

@app.route('/api/tracking/user-analytics', methods=['GET'])
@require_auth
def get_user_analytics():
    """Get analytics for current user based on their role"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Determine scope based on user role
        if request.current_user['role'] == 'admin':
            # Admin sees all data
            user_filter = ''
            params = []
        elif request.current_user['role'] in ['admin2', 'business']:
            # Admin2/Business sees their hierarchy's data
            hierarchy = AuthService.get_user_hierarchy(request.current_user['id'])
            hierarchy.append(request.current_user['id'])
            placeholders = ','.join('?' * len(hierarchy))
            user_filter = f'WHERE user_id IN ({placeholders})'
            params = hierarchy
        else:
            # Worker/Individual sees only their own data
            user_filter = 'WHERE user_id = ?'
            params = [request.current_user['id']]
        
        # Get campaign stats
        cursor.execute(f'SELECT COUNT(*) FROM campaigns {user_filter}', params)
        total_campaigns = cursor.fetchone()[0]
        
        # Get tracking link stats
        cursor.execute(f'SELECT COUNT(*) FROM tracking_links {user_filter}', params)
        total_links = cursor.fetchone()[0]
        
        # Get event stats
        cursor.execute(f'SELECT COUNT(*) FROM tracking_events {user_filter} AND event_type = "click"', params)
        total_clicks = cursor.fetchone()[0]
        
        cursor.execute(f'SELECT COUNT(*) FROM tracking_events {user_filter} AND event_type = "email_open"', params)
        total_opens = cursor.fetchone()[0]
        
        # Get unique visitors
        cursor.execute(f'SELECT COUNT(DISTINCT ip_address) FROM tracking_events {user_filter}', params)
        unique_visitors = cursor.fetchone()[0]
        
        # Get geographic distribution
        cursor.execute(f'''
            SELECT country_code, city, COUNT(*) as count
            FROM tracking_events 
            {user_filter} AND country_code IS NOT NULL
            GROUP BY country_code, city
            ORDER BY count DESC
            LIMIT 10
        ''', params)
        geo_distribution = cursor.fetchall()
        
        # Get device/browser stats
        cursor.execute(f'''
            SELECT device_type, COUNT(*) as count
            FROM tracking_events 
            {user_filter} AND device_type IS NOT NULL
            GROUP BY device_type
            ORDER BY count DESC
        ''', params)
        device_stats = cursor.fetchall()
        
        cursor.execute(f'''
            SELECT browser, COUNT(*) as count
            FROM tracking_events 
            {user_filter} AND browser IS NOT NULL
            GROUP BY browser
            ORDER BY count DESC
            LIMIT 5
        ''', params)
        browser_stats = cursor.fetchall()
        
        # Get recent activity (last 7 days)
        cursor.execute(f'''
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM tracking_events 
            {user_filter} AND timestamp >= datetime('now', '-7 days')
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        ''', params)
        recent_activity = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'summary': {
                'total_campaigns': total_campaigns,
                'total_links': total_links,
                'total_clicks': total_clicks,
                'total_opens': total_opens,
                'unique_visitors': unique_visitors,
                'conversion_rate': round((total_clicks / max(total_opens, 1)) * 100, 2)
            },
            'geographic_distribution': [
                {'country': geo[0], 'city': geo[1], 'count': geo[2]} 
                for geo in geo_distribution
            ],
            'device_stats': [
                {'device': device[0], 'count': device[1]} 
                for device in device_stats
            ],
            'browser_stats': [
                {'browser': browser[0], 'count': browser[1]} 
                for browser in browser_stats
            ],
            'recent_activity': [
                {'date': activity[0], 'count': activity[1]} 
                for activity in recent_activity
            ]
        }), 200
        
    except Exception as e:
        print(f"Get user analytics error: {e}")
        return jsonify({'error': 'Failed to get analytics'}), 500



# Worker Campaign Management Endpoints
@app.route('/api/campaigns', methods=['GET'])
@require_auth
def get_campaigns():
    """Get campaigns based on user role"""
    try:
        user = request.current_user
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        if user['role'] in ['admin', 'admin2']:
            # Admin sees all campaigns
            cursor.execute('''
                SELECT c.id, c.name, c.description, c.status, c.created_at, u.username as creator
                FROM campaigns c
                JOIN users u ON c.user_id = u.id
                ORDER BY c.created_at DESC
            ''')
        elif user['role'] == 'business':
            # Business sees their campaigns and their workers' campaigns
            hierarchy = AuthService.get_user_hierarchy(user['id'])
            hierarchy.append(user['id'])  # Include self
            placeholders = ','.join('?' * len(hierarchy))
            
            cursor.execute(f'''
                SELECT c.id, c.name, c.description, c.status, c.created_at, u.username as creator
                FROM campaigns c
                JOIN users u ON c.user_id = u.id
                WHERE c.user_id IN ({placeholders})
                ORDER BY c.created_at DESC
            ''', hierarchy)
        else:
            # Worker, Individual, Member see only their own campaigns
            cursor.execute('''
                SELECT c.id, c.name, c.description, c.status, c.created_at, u.username as creator
                FROM campaigns c
                JOIN users u ON c.user_id = u.id
                WHERE c.user_id = ?
                ORDER BY c.created_at DESC
            ''', (user['id'],))
        
        campaigns = cursor.fetchall()
        conn.close()
        
        campaigns_list = []
        for campaign in campaigns:
            campaigns_list.append({
                'id': campaign[0],
                'name': campaign[1],
                'description': campaign[2],
                'status': campaign[3],
                'created_at': campaign[4],
                'creator': campaign[5]
            })
        
        return jsonify({'campaigns': campaigns_list}), 200
        
    except Exception as e:
        print(f"Get campaigns error: {e}")
        return jsonify({'error': 'Failed to get campaigns'}), 500

@app.route('/api/campaigns', methods=['POST'])
@require_auth
@require_permission('create_campaigns')
def create_campaign():
    """Create a new campaign"""
    try:
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        status = data.get('status', 'active')
        
        if not name:
            return jsonify({'error': 'Campaign name is required'}), 400
        
        user = request.current_user
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO campaigns (name, description, user_id, status)
            VALUES (?, ?, ?, ?)
        ''', (name, description, user['id'], status))
        
        campaign_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'campaign_id': campaign_id,
            'message': 'Campaign created successfully'
        }), 201
        
    except Exception as e:
        print(f"Create campaign error: {e}")
        return jsonify({'error': 'Failed to create campaign'}), 500

@app.route('/api/campaigns/<int:campaign_id>', methods=['PUT'])
@require_auth
def update_campaign(campaign_id):
    """Update a campaign"""
    try:
        data = request.get_json()
        user = request.current_user
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Check if user owns the campaign or has permission
        if user['role'] in ['admin', 'admin2']:
            # Admin can update any campaign
            pass
        elif user['role'] == 'business':
            # Business can update campaigns in their hierarchy
            hierarchy = AuthService.get_user_hierarchy(user['id'])
            hierarchy.append(user['id'])
            placeholders = ','.join('?' * len(hierarchy))
            
            cursor.execute(f'''
                SELECT id FROM campaigns WHERE id = ? AND user_id IN ({placeholders})
            ''', [campaign_id] + hierarchy)
            
            if not cursor.fetchone():
                return jsonify({'error': 'Campaign not found or access denied'}), 404
        else:
            # Worker, Individual, Member can only update their own campaigns
            cursor.execute('SELECT id FROM campaigns WHERE id = ? AND user_id = ?', (campaign_id, user['id']))
            if not cursor.fetchone():
                return jsonify({'error': 'Campaign not found or access denied'}), 404
        
        # Update campaign
        update_fields = []
        update_values = []
        
        if 'name' in data:
            update_fields.append('name = ?')
            update_values.append(data['name'])
        
        if 'description' in data:
            update_fields.append('description = ?')
            update_values.append(data['description'])
        
        if 'status' in data:
            update_fields.append('status = ?')
            update_values.append(data['status'])
        
        if not update_fields:
            return jsonify({'error': 'No fields to update'}), 400
        
        update_values.append(campaign_id)
        cursor.execute(f'''
            UPDATE campaigns SET {', '.join(update_fields)}
            WHERE id = ?
        ''', update_values)
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Campaign updated successfully'}), 200
        
    except Exception as e:
        print(f"Update campaign error: {e}")
        return jsonify({'error': 'Failed to update campaign'}), 500

@app.route('/api/campaigns/<int:campaign_id>', methods=['DELETE'])
@require_auth
def delete_campaign(campaign_id):
    """Delete a campaign"""
    try:
        user = request.current_user
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Check if user owns the campaign or has permission
        if user['role'] in ['admin', 'admin2']:
            # Admin can delete any campaign
            pass
        elif user['role'] == 'business':
            # Business can delete campaigns in their hierarchy
            hierarchy = AuthService.get_user_hierarchy(user['id'])
            hierarchy.append(user['id'])
            placeholders = ','.join('?' * len(hierarchy))
            
            cursor.execute(f'''
                SELECT id FROM campaigns WHERE id = ? AND user_id IN ({placeholders})
            ''', [campaign_id] + hierarchy)
            
            if not cursor.fetchone():
                return jsonify({'error': 'Campaign not found or access denied'}), 404
        else:
            # Worker, Individual, Member can only delete their own campaigns
            cursor.execute('SELECT id FROM campaigns WHERE id = ? AND user_id = ?', (campaign_id, user['id']))
            if not cursor.fetchone():
                return jsonify({'error': 'Campaign not found or access denied'}), 404
        
        # Delete campaign and related data
        cursor.execute('DELETE FROM tracking_events WHERE campaign_id = ?', (campaign_id,))
        cursor.execute('DELETE FROM tracking_links WHERE campaign_id = ?', (campaign_id,))
        cursor.execute('DELETE FROM campaigns WHERE id = ?', (campaign_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Campaign deleted successfully'}), 200
        
    except Exception as e:
        print(f"Delete campaign error: {e}")
        return jsonify({'error': 'Failed to delete campaign'}), 500



# Enhanced Business Analytics and Campaign Overview
@app.route('/api/business/comprehensive-analytics', methods=['GET'])
@require_auth
@require_permission('view_analytics')
def get_comprehensive_business_analytics():
    """Get comprehensive analytics for business including all workers and campaigns"""
    try:
        user = request.current_user
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get hierarchy of users under this business
        hierarchy = AuthService.get_user_hierarchy(user['id'])
        hierarchy.append(user['id'])  # Include self
        placeholders = ','.join('?' * len(hierarchy))
        
        # Get campaign analytics with detailed breakdown
        cursor.execute(f'''
            SELECT 
                c.id, c.name, c.status, c.created_at, u.username as creator,
                COUNT(DISTINCT tl.id) as link_count,
                COUNT(DISTINCT CASE WHEN te.event_type = 'click' AND te.blocked = 0 THEN te.id END) as clicks,
                COUNT(DISTINCT CASE WHEN te.event_type = 'email_open' AND te.blocked = 0 THEN te.id END) as opens,
                COUNT(DISTINCT te.ip_address) as unique_visitors
            FROM campaigns c
            JOIN users u ON c.user_id = u.id
            LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
            LEFT JOIN tracking_events te ON tl.tracking_token = te.tracking_token
            WHERE c.user_id IN ({placeholders})
            GROUP BY c.id, c.name, c.status, c.created_at, u.username
            ORDER BY c.created_at DESC
        ''', hierarchy)
        
        campaigns_data = []
        for row in cursor.fetchall():
            campaigns_data.append({
                'id': row[0],
                'name': row[1],
                'status': row[2],
                'created_at': row[3],
                'creator': row[4],
                'link_count': row[5],
                'clicks': row[6],
                'opens': row[7],
                'unique_visitors': row[8],
                'conversion_rate': round((row[6] / max(row[7], 1)) * 100, 2)
            })
        
        # Get worker performance data
        cursor.execute(f'''
            SELECT 
                u.id, u.username, u.email, u.created_at,
                COUNT(DISTINCT c.id) as campaigns_created,
                COUNT(DISTINCT tl.id) as links_created,
                COUNT(DISTINCT CASE WHEN te.event_type = 'click' AND te.blocked = 0 THEN te.id END) as total_clicks,
                COUNT(DISTINCT CASE WHEN te.event_type = 'email_open' AND te.blocked = 0 THEN te.id END) as total_opens
            FROM users u
            LEFT JOIN campaigns c ON u.id = c.user_id
            LEFT JOIN tracking_links tl ON u.id = tl.user_id
            LEFT JOIN tracking_events te ON tl.tracking_token = te.tracking_token
            WHERE u.id IN ({placeholders}) AND u.id != ?
            GROUP BY u.id, u.username, u.email, u.created_at
            ORDER BY total_clicks DESC
        ''', hierarchy + [user['id']])
        
        workers_data = []
        for row in cursor.fetchall():
            workers_data.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'created_at': row[3],
                'campaigns_created': row[4],
                'links_created': row[5],
                'total_clicks': row[6],
                'total_opens': row[7],
                'performance_score': row[6] + (row[7] * 0.5)  # Simple performance metric
            })
        
        # Get geographic distribution
        cursor.execute(f'''
            SELECT country_code, city, COUNT(*) as visit_count
            FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id IN ({placeholders}) AND te.blocked = 0
            GROUP BY country_code, city
            ORDER BY visit_count DESC
            LIMIT 10
        ''', hierarchy)
        
        geographic_data = []
        for row in cursor.fetchall():
            geographic_data.append({
                'country_code': row[0],
                'city': row[1],
                'visit_count': row[2]
            })
        
        # Get device and browser statistics
        cursor.execute(f'''
            SELECT device_type, browser, COUNT(*) as usage_count
            FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id IN ({placeholders}) AND te.blocked = 0
            GROUP BY device_type, browser
            ORDER BY usage_count DESC
            LIMIT 10
        ''', hierarchy)
        
        device_data = []
        for row in cursor.fetchall():
            device_data.append({
                'device_type': row[0],
                'browser': row[1],
                'usage_count': row[2]
            })
        
        # Get summary statistics
        cursor.execute(f'''
            SELECT 
                COUNT(DISTINCT c.id) as total_campaigns,
                COUNT(DISTINCT tl.id) as total_links,
                COUNT(DISTINCT CASE WHEN te.event_type = 'click' AND te.blocked = 0 THEN te.id END) as total_clicks,
                COUNT(DISTINCT CASE WHEN te.event_type = 'email_open' AND te.blocked = 0 THEN te.id END) as total_opens,
                COUNT(DISTINCT te.ip_address) as unique_visitors,
                COUNT(DISTINCT u.id) - 1 as workers_count
            FROM users u
            LEFT JOIN campaigns c ON u.id = c.user_id
            LEFT JOIN tracking_links tl ON u.id = tl.user_id
            LEFT JOIN tracking_events te ON tl.tracking_token = te.tracking_token
            WHERE u.id IN ({placeholders})
        ''', hierarchy)
        
        summary = cursor.fetchone()
        summary_data = {
            'total_campaigns': summary[0] or 0,
            'total_links': summary[1] or 0,
            'total_clicks': summary[2] or 0,
            'total_opens': summary[3] or 0,
            'unique_visitors': summary[4] or 0,
            'workers_count': summary[5] or 0,
            'conversion_rate': round((summary[2] / max(summary[3], 1)) * 100, 2)
        }
        
        conn.close()
        
        return jsonify({
            'summary': summary_data,
            'campaigns': campaigns_data,
            'workers': workers_data,
            'geographic_distribution': geographic_data,
            'device_stats': device_data
        }), 200
        
    except Exception as e:
        print(f"Comprehensive business analytics error: {e}")
        return jsonify({'error': 'Failed to fetch comprehensive analytics'}), 500

@app.route('/api/business/campaign-overview', methods=['GET'])
@require_auth
@require_permission('manage_campaigns')
def get_business_campaign_overview():
    """Get detailed campaign overview for business including worker campaigns"""
    try:
        user = request.current_user
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get hierarchy of users under this business
        hierarchy = AuthService.get_user_hierarchy(user['id'])
        hierarchy.append(user['id'])  # Include self
        placeholders = ','.join('?' * len(hierarchy))
        
        # Get detailed campaign information
        cursor.execute(f'''
            SELECT 
                c.id, c.name, c.description, c.status, c.created_at,
                u.username as creator, u.role as creator_role,
                COUNT(DISTINCT tl.id) as total_links,
                COUNT(DISTINCT CASE WHEN te.event_type = 'click' AND te.blocked = 0 THEN te.id END) as total_clicks,
                COUNT(DISTINCT CASE WHEN te.event_type = 'email_open' AND te.blocked = 0 THEN te.id END) as total_opens,
                COUNT(DISTINCT te.ip_address) as unique_visitors,
                COUNT(DISTINCT CASE WHEN te.blocked = 1 THEN te.id END) as blocked_attempts,
                MAX(te.timestamp) as last_activity
            FROM campaigns c
            JOIN users u ON c.user_id = u.id
            LEFT JOIN tracking_links tl ON c.id = tl.campaign_id
            LEFT JOIN tracking_events te ON tl.tracking_token = te.tracking_token
            WHERE c.user_id IN ({placeholders})
            GROUP BY c.id, c.name, c.description, c.status, c.created_at, u.username, u.role
            ORDER BY c.created_at DESC
        ''', hierarchy)
        
        campaigns_overview = []
        for row in cursor.fetchall():
            campaign_data = {
                'id': row[0],
                'name': row[1],
                'description': row[2],
                'status': row[3],
                'created_at': row[4],
                'creator': row[5],
                'creator_role': row[6],
                'total_links': row[7],
                'total_clicks': row[8],
                'total_opens': row[9],
                'unique_visitors': row[10],
                'blocked_attempts': row[11],
                'last_activity': row[12],
                'conversion_rate': round((row[8] / max(row[9], 1)) * 100, 2),
                'security_score': max(0, 100 - (row[11] * 10))  # Simple security score
            }
            
            # Get top performing links for this campaign
            cursor.execute('''
                SELECT 
                    tl.tracking_token, tl.original_url, tl.recipient_email,
                    COUNT(DISTINCT CASE WHEN te.event_type = 'click' AND te.blocked = 0 THEN te.id END) as clicks,
                    COUNT(DISTINCT CASE WHEN te.event_type = 'email_open' AND te.blocked = 0 THEN te.id END) as opens
                FROM tracking_links tl
                LEFT JOIN tracking_events te ON tl.tracking_token = te.tracking_token
                WHERE tl.campaign_id = ?
                GROUP BY tl.tracking_token, tl.original_url, tl.recipient_email
                ORDER BY clicks DESC
                LIMIT 5
            ''', (row[0],))
            
            top_links = []
            for link_row in cursor.fetchall():
                top_links.append({
                    'tracking_token': link_row[0],
                    'original_url': link_row[1],
                    'recipient_email': link_row[2],
                    'clicks': link_row[3],
                    'opens': link_row[4]
                })
            
            campaign_data['top_links'] = top_links
            campaigns_overview.append(campaign_data)
        
        # Get campaign status distribution
        cursor.execute(f'''
            SELECT status, COUNT(*) as count
            FROM campaigns
            WHERE user_id IN ({placeholders})
            GROUP BY status
        ''', hierarchy)
        
        status_distribution = {}
        for row in cursor.fetchall():
            status_distribution[row[0]] = row[1]
        
        # Get monthly campaign creation trend
        cursor.execute(f'''
            SELECT 
                strftime('%Y-%m', created_at) as month,
                COUNT(*) as campaigns_created
            FROM campaigns
            WHERE user_id IN ({placeholders})
            GROUP BY strftime('%Y-%m', created_at)
            ORDER BY month DESC
            LIMIT 12
        ''', hierarchy)
        
        monthly_trend = []
        for row in cursor.fetchall():
            monthly_trend.append({
                'month': row[0],
                'campaigns_created': row[1]
            })
        
        conn.close()
        
        return jsonify({
            'campaigns': campaigns_overview,
            'status_distribution': status_distribution,
            'monthly_trend': monthly_trend,
            'total_campaigns': len(campaigns_overview)
        }), 200
        
    except Exception as e:
        print(f"Business campaign overview error: {e}")
        return jsonify({'error': 'Failed to fetch campaign overview'}), 500



@app.route('/api/admin/users', methods=['OPTIONS'])
@require_auth
@require_permission('view_users')
def get_users_options():
    return jsonify({'status': 'ok'}), 200



# Live Activity API Endpoints
@app.route('/api/live-activity', methods=['GET'])
@require_auth
def get_live_activity():
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 30))
        search_tracking_id = request.args.get('search', '')
        
        # Calculate offset
        offset = (page - 1) * per_page
        
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Base query with joins to get additional information
        base_query = '''
            SELECT 
                te.id,
                te.tracking_token,
                te.event_type,
                te.ip_address,
                te.user_agent,
                te.country_code,
                te.city,
                te.timestamp,
                te.status,
                te.is_bot,
                te.blocked,
                te.block_reason,
                te.redirect_success,
                te.email_opened,
                te.link_clicked,
                tl.recipient_email,
                tl.original_url,
                ir.is_vpn,
                ir.is_proxy
            FROM tracking_events te
            LEFT JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            LEFT JOIN ip_reputation ir ON te.ip_address = ir.ip_address
        '''
        
        # Add search filter if provided
        where_clause = ''
        params = []
        if search_tracking_id:
            where_clause = ' WHERE te.tracking_token LIKE ?'
            params.append(f'%{search_tracking_id}%')
        
        # Get total count for pagination
        count_query = f'''
            SELECT COUNT(*) 
            FROM tracking_events te
            LEFT JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            {where_clause}
        '''
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]
        
        # Get paginated results
        query = f'{base_query}{where_clause} ORDER BY te.timestamp DESC LIMIT ? OFFSET ?'
        cursor.execute(query, params + [per_page, offset])
        events = cursor.fetchall()
        
        # Format results
        events_list = []
        for event in events:
            # Extract ISP information from user agent or use a placeholder
            isp = extract_isp_from_user_agent(event[4]) if event[4] else 'Unknown'
            
            # Determine status based on event data
            status = determine_event_status(event)
            
            events_list.append({
                'id': event[0],
                'tracking_id': event[1],
                'event_type': event[2],
                'ip_address': event[3],
                'user_agent': event[4],
                'country': event[5] or 'Unknown',
                'city': event[6] or 'Unknown',
                'timestamp': event[7],
                'status': status,
                'is_bot': event[9],
                'blocked': event[10],
                'block_reason': event[11],
                'redirect_success': event[12],
                'email_opened': event[13],
                'link_clicked': event[14],
                'auto_grabbed_email': event[15] or 'N/A',
                'original_url': event[16],
                'isp': isp,
                'is_vpn': event[17] or False,
                'is_proxy': event[18] or False
            })
        
        # Calculate pagination info
        total_pages = (total_count + per_page - 1) // per_page
        has_next = page < total_pages
        has_prev = page > 1
        
        conn.close()
        
        return jsonify({
            'events': events_list,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'total_pages': total_pages,
                'has_next': has_next,
                'has_prev': has_prev
            }
        }), 200
        
    except Exception as e:
        print(f"Get live activity error: {e}")
        return jsonify({'error': 'Failed to get live activity data'}), 500

@app.route('/api/live-activity/analytics', methods=['GET'])
@require_auth
def get_live_activity_analytics():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get analytics data
        cursor.execute('''
            SELECT 
                COUNT(*) as total_events,
                COUNT(CASE WHEN event_type = 'click' THEN 1 END) as total_clicks,
                COUNT(CASE WHEN redirect_success = 1 THEN 1 END) as total_redirects,
                COUNT(CASE WHEN is_bot = 1 OR blocked = 1 THEN 1 END) as bot_blocks,
                COUNT(CASE WHEN is_bot = 0 AND blocked = 0 THEN 1 END) as real_visitors,
                COUNT(CASE WHEN event_type = 'pixel_view' THEN 1 END) as email_opens
            FROM tracking_events
        ''')
        
        analytics = cursor.fetchone()
        
        # Get recent activity (last 24 hours)
        cursor.execute('''
            SELECT COUNT(*) 
            FROM tracking_events 
            WHERE timestamp >= datetime('now', '-24 hours')
        ''')
        recent_activity = cursor.fetchone()[0]
        
        # Get top countries
        cursor.execute('''
            SELECT country_code, COUNT(*) as count
            FROM tracking_events 
            WHERE country_code IS NOT NULL AND country_code != ''
            GROUP BY country_code 
            ORDER BY count DESC 
            LIMIT 5
        ''')
        top_countries = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'total_events': analytics[0],
            'total_clicks': analytics[1],
            'total_redirects': analytics[2],
            'bot_blocks': analytics[3],
            'real_visitors': analytics[4],
            'email_opens': analytics[5],
            'recent_activity_24h': recent_activity,
            'top_countries': [{'country': country[0], 'count': country[1]} for country in top_countries]
        }), 200
        
    except Exception as e:
        print(f"Get live activity analytics error: {e}")
        return jsonify({'error': 'Failed to get analytics data'}), 500

def extract_isp_from_user_agent(user_agent):
    """Extract ISP information from user agent or return a placeholder"""
    # This is a simplified ISP extraction - in production, you'd use a proper ISP database
    if not user_agent:
        return 'Unknown'
    
    # Common ISP indicators in user agents
    isp_indicators = {
        'comcast': 'Comcast',
        'verizon': 'Verizon',
        'att': 'AT&T',
        'tmobile': 'T-Mobile',
        'sprint': 'Sprint',
        'charter': 'Charter Communications',
        'cox': 'Cox Communications'
    }
    
    user_agent_lower = user_agent.lower()
    for indicator, isp_name in isp_indicators.items():
        if indicator in user_agent_lower:
            return isp_name
    
    # Default ISP based on common patterns
    if 'mobile' in user_agent_lower:
        return 'Mobile Network'
    elif 'wifi' in user_agent_lower:
        return 'WiFi Network'
    else:
        return 'Internet Service Provider'

def determine_event_status(event_data):
    """Determine the status based on event data"""
    event_type = event_data[2]
    is_bot = event_data[9]
    blocked = event_data[10]
    redirect_success = event_data[12]
    email_opened = event_data[13]
    link_clicked = event_data[14]
    
    if blocked or is_bot:
        return 'blocked'
    elif event_type == 'pixel_view' and email_opened:
        return 'opened'
    elif event_type == 'click' and link_clicked:
        if redirect_success:
            return 'redirected'
        else:
            return 'clicked'
    elif event_type == 'email_sent':
        return 'sent'
    else:
        return 'ok'


# Enhanced Geography API Endpoints
@app.route('/api/geography/overview', methods=['GET'])
@require_auth
def get_geography_overview():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get click density by country for heatmap
        cursor.execute('''
            SELECT 
                country_code,
                COUNT(*) as click_count,
                COUNT(DISTINCT ip_address) as unique_visitors,
                AVG(CASE WHEN redirect_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate
            FROM tracking_events 
            WHERE event_type = 'click' AND blocked = 0 AND country_code != 'XX'
            GROUP BY country_code
            ORDER BY click_count DESC
        ''')
        
        country_data = cursor.fetchall()
        total_clicks = sum(row[1] for row in country_data)
        
        # Format for heatmap
        heatmap_data = []
        for row in country_data:
            country_code = row[0]
            click_count = row[1]
            unique_visitors = row[2]
            success_rate = row[3]
            percentage = (click_count / total_clicks * 100) if total_clicks > 0 else 0
            
            # Get top 3 links for this country
            cursor.execute('''
                SELECT tl.original_url, COUNT(*) as clicks
                FROM tracking_events te
                JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
                WHERE te.country_code = ? AND te.event_type = 'click' AND te.blocked = 0
                GROUP BY tl.original_url
                ORDER BY clicks DESC
                LIMIT 3
            ''', (country_code,))
            
            top_links = cursor.fetchall()
            
            heatmap_data.append({
                'country_code': country_code,
                'country_name': get_country_name(country_code),
                'click_count': click_count,
                'unique_visitors': unique_visitors,
                'percentage': round(percentage, 2),
                'success_rate': round(success_rate * 100, 1),
                'top_links': [{'url': link[0], 'clicks': link[1]} for link in top_links]
            })
        
        conn.close()
        
        return jsonify({
            'heatmap_data': heatmap_data,
            'total_clicks': total_clicks,
            'total_countries': len(country_data)
        }), 200
        
    except Exception as e:
        print(f"Geography overview error: {e}")
        return jsonify({'error': 'Failed to get geography overview'}), 500

@app.route('/api/geography/ranking', methods=['GET'])
@require_auth
def get_geography_ranking():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get detailed country ranking data
        cursor.execute('''
            SELECT 
                te.country_code,
                COUNT(CASE WHEN te.event_type = 'click' THEN 1 END) as clicks,
                COUNT(CASE WHEN te.event_type = 'pixel_view' THEN 1 END) as opens,
                COUNT(DISTINCT te.ip_address) as unique_visitors,
                AVG(CASE WHEN te.redirect_success = 1 THEN 1.0 ELSE 0.0 END) as ctr,
                COUNT(CASE WHEN te.blocked = 1 OR te.is_bot = 1 THEN 1 END) as blocked_attempts,
                AVG(julianday(te.timestamp) - julianday(te.timestamp)) as avg_session_duration
            FROM tracking_events te
            WHERE te.country_code != 'XX' AND te.country_code IS NOT NULL
            GROUP BY te.country_code
            HAVING clicks > 0
            ORDER BY clicks DESC
        ''')
        
        ranking_data = cursor.fetchall()
        total_clicks = sum(row[1] for row in ranking_data)
        
        # Format ranking data
        countries = []
        for i, row in enumerate(ranking_data):
            country_code = row[0]
            clicks = row[1]
            opens = row[2]
            unique_visitors = row[3]
            ctr = row[4]
            blocked_attempts = row[5]
            
            # Calculate engagement score
            engagement_score = calculate_engagement_score(clicks, opens, unique_visitors, blocked_attempts)
            
            countries.append({
                'rank': i + 1,
                'country_code': country_code,
                'country_name': get_country_name(country_code),
                'flag': f"https://flagcdn.com/24x18/{country_code.lower()}.png",
                'clicks': clicks,
                'opens': opens,
                'unique_visitors': unique_visitors,
                'percentage': round((clicks / total_clicks * 100), 2) if total_clicks > 0 else 0,
                'ctr': round(ctr * 100, 1) if ctr else 0,
                'engagement_score': engagement_score,
                'blocked_attempts': blocked_attempts
            })
        
        conn.close()
        
        return jsonify({
            'countries': countries,
            'total_clicks': total_clicks
        }), 200
        
    except Exception as e:
        print(f"Geography ranking error: {e}")
        return jsonify({'error': 'Failed to get geography ranking'}), 500

@app.route('/api/geography/engagement', methods=['GET'])
@require_auth
def get_geography_engagement():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get engagement quality by location
        cursor.execute('''
            SELECT 
                te.country_code,
                te.city,
                COUNT(CASE WHEN te.event_type = 'click' THEN 1 END) as clicks,
                COUNT(CASE WHEN te.event_type = 'pixel_view' THEN 1 END) as opens,
                COUNT(DISTINCT te.tracking_token) as unique_links_clicked,
                COUNT(DISTINCT te.ip_address) as unique_visitors,
                AVG(CASE WHEN te.redirect_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
                COUNT(CASE WHEN te.blocked = 1 OR te.is_bot = 1 THEN 1 END) as bounce_count
            FROM tracking_events te
            WHERE te.country_code != 'XX' AND te.country_code IS NOT NULL
            GROUP BY te.country_code, te.city
            HAVING clicks > 0
            ORDER BY te.country_code, clicks DESC
        ''')
        
        engagement_data = cursor.fetchall()
        
        # Process engagement data
        engagement_by_location = {}
        for row in engagement_data:
            country_code = row[0]
            city = row[1] or 'Unknown'
            clicks = row[2]
            opens = row[3]
            unique_links = row[4]
            unique_visitors = row[5]
            success_rate = row[6]
            bounce_count = row[7]
            
            # Calculate engagement metrics
            bounce_rate = (bounce_count / (clicks + opens)) * 100 if (clicks + opens) > 0 else 0
            engagement_score = calculate_engagement_score(clicks, opens, unique_visitors, bounce_count)
            
            # Determine if visitor is "engaged" (clicked >= 2 links or high success rate)
            is_engaged = unique_links >= 2 or success_rate >= 0.8
            
            if country_code not in engagement_by_location:
                engagement_by_location[country_code] = {
                    'country_name': get_country_name(country_code),
                    'total_clicks': 0,
                    'total_opens': 0,
                    'total_bounce_rate': 0,
                    'total_engagement_score': 0,
                    'cities': []
                }
            
            engagement_by_location[country_code]['total_clicks'] += clicks
            engagement_by_location[country_code]['total_opens'] += opens
            engagement_by_location[country_code]['cities'].append({
                'city': city,
                'clicks': clicks,
                'opens': opens,
                'unique_visitors': unique_visitors,
                'bounce_rate': round(bounce_rate, 1),
                'engagement_score': engagement_score,
                'is_engaged': is_engaged,
                'success_rate': round(success_rate * 100, 1)
            })
        
        # Calculate country-level averages
        for country_data in engagement_by_location.values():
            cities = country_data['cities']
            if cities:
                country_data['avg_bounce_rate'] = round(sum(city['bounce_rate'] for city in cities) / len(cities), 1)
                country_data['avg_engagement_score'] = round(sum(city['engagement_score'] for city in cities) / len(cities), 1)
                country_data['engaged_cities_count'] = sum(1 for city in cities if city['is_engaged'])
        
        conn.close()
        
        return jsonify({
            'engagement_by_location': engagement_by_location
        }), 200
        
    except Exception as e:
        print(f"Geography engagement error: {e}")
        return jsonify({'error': 'Failed to get geography engagement data'}), 500

@app.route('/api/geography/link-performance', methods=['GET'])
@require_auth
def get_geography_link_performance():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get link performance by region
        cursor.execute('''
            SELECT 
                tl.tracking_token,
                tl.original_url,
                te.country_code,
                COUNT(CASE WHEN te.event_type = 'click' THEN 1 END) as clicks,
                COUNT(CASE WHEN te.event_type = 'pixel_view' THEN 1 END) as opens,
                AVG(CASE WHEN te.redirect_success = 1 THEN 1.0 ELSE 0.0 END) as success_rate,
                COUNT(DISTINCT te.ip_address) as unique_visitors
            FROM tracking_links tl
            LEFT JOIN tracking_events te ON tl.tracking_token = te.tracking_token
            WHERE te.country_code != 'XX' AND te.country_code IS NOT NULL
            GROUP BY tl.tracking_token, tl.original_url, te.country_code
            HAVING clicks > 0
            ORDER BY tl.original_url, clicks DESC
        ''')
        
        performance_data = cursor.fetchall()
        
        # Process link performance data
        link_performance = {}
        for row in performance_data:
            tracking_token = row[0]
            original_url = row[1]
            country_code = row[2]
            clicks = row[3]
            opens = row[4]
            success_rate = row[5]
            unique_visitors = row[6]
            
            if original_url not in link_performance:
                link_performance[original_url] = {
                    'tracking_token': tracking_token,
                    'total_clicks': 0,
                    'total_opens': 0,
                    'regions': [],
                    'best_performing_region': None,
                    'worst_performing_region': None
                }
            
            link_performance[original_url]['total_clicks'] += clicks
            link_performance[original_url]['total_opens'] += opens
            link_performance[original_url]['regions'].append({
                'country_code': country_code,
                'country_name': get_country_name(country_code),
                'clicks': clicks,
                'opens': opens,
                'success_rate': round(success_rate * 100, 1),
                'unique_visitors': unique_visitors,
                'performance_score': calculate_performance_score(clicks, opens, success_rate, unique_visitors)
            })
        
        # Determine best and worst performing regions for each link
        for url, data in link_performance.items():
            if data['regions']:
                sorted_regions = sorted(data['regions'], key=lambda x: x['performance_score'], reverse=True)
                data['best_performing_region'] = sorted_regions[0]
                data['worst_performing_region'] = sorted_regions[-1] if len(sorted_regions) > 1 else None
                
                # Identify underperforming regions (below average)
                avg_score = sum(r['performance_score'] for r in data['regions']) / len(data['regions'])
                data['underperforming_regions'] = [r for r in data['regions'] if r['performance_score'] < avg_score]
        
        conn.close()
        
        return jsonify({
            'link_performance': link_performance
        }), 200
        
    except Exception as e:
        print(f"Geography link performance error: {e}")
        return jsonify({'error': 'Failed to get link performance data'}), 500

def get_country_name(country_code):
    """Convert country code to country name"""
    country_names = {
        'US': 'United States', 'GB': 'United Kingdom', 'CA': 'Canada', 'AU': 'Australia',
        'DE': 'Germany', 'FR': 'France', 'IT': 'Italy', 'ES': 'Spain', 'NL': 'Netherlands',
        'BE': 'Belgium', 'CH': 'Switzerland', 'AT': 'Austria', 'SE': 'Sweden', 'NO': 'Norway',
        'DK': 'Denmark', 'FI': 'Finland', 'IE': 'Ireland', 'PT': 'Portugal', 'GR': 'Greece',
        'PL': 'Poland', 'CZ': 'Czech Republic', 'HU': 'Hungary', 'RO': 'Romania', 'BG': 'Bulgaria',
        'HR': 'Croatia', 'SI': 'Slovenia', 'SK': 'Slovakia', 'LT': 'Lithuania', 'LV': 'Latvia',
        'EE': 'Estonia', 'RU': 'Russia', 'UA': 'Ukraine', 'BY': 'Belarus', 'MD': 'Moldova',
        'JP': 'Japan', 'KR': 'South Korea', 'CN': 'China', 'IN': 'India', 'TH': 'Thailand',
        'VN': 'Vietnam', 'PH': 'Philippines', 'ID': 'Indonesia', 'MY': 'Malaysia', 'SG': 'Singapore',
        'BR': 'Brazil', 'AR': 'Argentina', 'MX': 'Mexico', 'CL': 'Chile', 'CO': 'Colombia',
        'PE': 'Peru', 'VE': 'Venezuela', 'UY': 'Uruguay', 'PY': 'Paraguay', 'BO': 'Bolivia',
        'ZA': 'South Africa', 'EG': 'Egypt', 'MA': 'Morocco', 'NG': 'Nigeria', 'KE': 'Kenya',
        'GH': 'Ghana', 'TZ': 'Tanzania', 'UG': 'Uganda', 'ZW': 'Zimbabwe', 'ZM': 'Zambia'
    }
    return country_names.get(country_code, country_code)

def calculate_engagement_score(clicks, opens, unique_visitors, blocked_attempts):
    """Calculate engagement score based on various metrics"""
    if clicks == 0 and opens == 0:
        return 0
    
    # Base score from clicks and opens
    base_score = (clicks * 2 + opens) / max(unique_visitors, 1)
    
    # Penalty for blocked attempts
    penalty = min(blocked_attempts * 0.1, 0.5)
    
    # Normalize to 0-100 scale
    score = max(0, min(100, (base_score - penalty) * 20))
    
    return round(score, 1)

def calculate_performance_score(clicks, opens, success_rate, unique_visitors):
    """Calculate performance score for link performance analysis"""
    if clicks == 0 and opens == 0:
        return 0
    
    # Weight different factors
    click_weight = 0.4
    open_weight = 0.2
    success_weight = 0.3
    visitor_weight = 0.1
    
    # Normalize values
    normalized_clicks = min(clicks / 10, 10)  # Cap at 10 for normalization
    normalized_opens = min(opens / 20, 10)   # Cap at 10 for normalization
    normalized_success = success_rate * 10    # Already 0-1, scale to 0-10
    normalized_visitors = min(unique_visitors / 5, 10)  # Cap at 10 for normalization
    
    score = (normalized_clicks * click_weight + 
             normalized_opens * open_weight + 
             normalized_success * success_weight + 
             normalized_visitors * visitor_weight) * 10
    
    return round(score, 1)

