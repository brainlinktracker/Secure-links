from flask import Flask, request, jsonify, send_file, redirect, render_template_string, send_from_directory
from flask_cors import CORS
import os
import hashlib
import secrets
import time
import requests
import json
from datetime import datetime, timedelta
import uuid
# from PIL import Image  # Commented out for Vercel compatibility
import io
import base64
from urllib.parse import urlparse
import socket
import dns.resolver
import geoip2.database
import geoip2.errors
from user_agents import parse
import bcrypt
from functools import wraps

# Database imports - using PostgreSQL for Vercel
try:
    import psycopg2
    from psycopg2 import Error, sql
    DATABASE_TYPE = "postgresql"
except ImportError:
    # Fallback to SQLite for local development
    import sqlite3
    DATABASE_TYPE = "sqlite"

app = Flask(__name__, static_folder='static')
CORS(app, origins="*")

# Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "sB7u2!fX9#Lp4qZwRvT8&NzM6@eKyC1")
app.config['SECRET_KEY'] = SECRET_KEY

# Database configuration
if DATABASE_TYPE == "postgresql":
    DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://neondb_owner:npg_0y9XMKzHCBsN@ep-blue-resonance-add39g5q-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require")
else:
    DATABASE_PATH = os.path.join(os.path.dirname(__file__), "database", "app.db")

def get_db_connection():
    """Get a database connection"""
    if DATABASE_TYPE == "postgresql":
        return psycopg2.connect(DATABASE_URL)
    else:
        return sqlite3.connect(DATABASE_PATH)

# Initialize database
def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            # PostgreSQL table creation
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL DEFAULT 'member',
                    status VARCHAR(50) NOT NULL DEFAULT 'pending',
                    parent_id INTEGER,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP WITH TIME ZONE,
                    subscription_status VARCHAR(50) DEFAULT 'inactive',
                    subscription_expires TIMESTAMP WITH TIME ZONE,
                    FOREIGN KEY (parent_id) REFERENCES users (id)
                );
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_permissions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    permission VARCHAR(255) NOT NULL,
                    granted_by INTEGER,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (granted_by) REFERENCES users (id)
                );
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    session_token VARCHAR(255) UNIQUE NOT NULL,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    description TEXT,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'active',
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tracking_links (
                    id SERIAL PRIMARY KEY,
                    campaign_id INTEGER,
                    user_id INTEGER NOT NULL,
                    original_url TEXT NOT NULL,
                    tracking_token VARCHAR(255) UNIQUE NOT NULL,
                    recipient_email VARCHAR(255),
                    recipient_name VARCHAR(255),
                    link_status VARCHAR(50) DEFAULT 'active',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP WITH TIME ZONE,
                    click_limit INTEGER DEFAULT 0,
                    click_count INTEGER DEFAULT 0,
                    last_clicked TIMESTAMP WITH TIME ZONE,
                    custom_message TEXT,
                    redirect_delay INTEGER DEFAULT 0,
                    password_protected BOOLEAN DEFAULT FALSE,
                    access_password VARCHAR(255),
                    geo_restrictions TEXT,
                    device_restrictions TEXT,
                    time_restrictions TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tracking_events (
                    id SERIAL PRIMARY KEY,
                    tracking_token TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    referrer TEXT,
                    country TEXT,
                    city TEXT,
                    device_type TEXT,
                    browser TEXT,
                    os TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    additional_data TEXT,
                    campaign_id INTEGER,
                    user_id INTEGER,
                    is_bot INTEGER DEFAULT 0,
                    bot_confidence REAL,
                    bot_reason TEXT,
                    status TEXT DEFAULT 'processed',
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS visitor_stats (
                    id SERIAL PRIMARY KEY,
                    date TEXT UNIQUE NOT NULL,
                    total_clicks INTEGER DEFAULT 0,
                    unique_visitors INTEGER DEFAULT 0,
                    bot_clicks INTEGER DEFAULT 0,
                    mobile_clicks INTEGER DEFAULT 0,
                    desktop_clicks INTEGER DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS visitor_stats (
                    id SERIAL PRIMARY KEY,
                    date DATE UNIQUE NOT NULL,
                    total_clicks INTEGER DEFAULT 0,
                    unique_visitors INTEGER DEFAULT 0,
                    bot_clicks INTEGER DEFAULT 0,
                    mobile_clicks INTEGER DEFAULT 0,
                    desktop_clicks INTEGER DEFAULT 0,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            
        else:
            # SQLite table creation (for local development)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
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
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_permissions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    permission TEXT NOT NULL,
                    granted_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (granted_by) REFERENCES users (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS campaigns (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracking_links (
                    id SERIAL PRIMARY KEY,
                    campaign_id INTEGER,
                    user_id INTEGER NOT NULL,
                    original_url TEXT NOT NULL,
                    tracking_token TEXT UNIQUE NOT NULL,
                    recipient_email TEXT,
                    recipient_name TEXT,
                    link_status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    click_limit INTEGER DEFAULT 0,
                    click_count INTEGER DEFAULT 0,
                    last_clicked TIMESTAMP,
                    custom_message TEXT,
                    redirect_delay INTEGER DEFAULT 0,
                    password_protected INTEGER DEFAULT 0,
                    access_password TEXT,
                    geo_restrictions TEXT,
                    device_restrictions TEXT,
                    time_restrictions TEXT,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracking_events (
                    id SERIAL PRIMARY KEY,
                    tracking_token TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    referrer TEXT,
                    country TEXT,
                    city TEXT,
                    device_type TEXT,
                    browser TEXT,
                    os TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    additional_data TEXT,
                    campaign_id INTEGER,
                    user_id INTEGER,
                    is_bot INTEGER DEFAULT 0,
                    bot_confidence REAL,
                    bot_reason TEXT,
                    status TEXT DEFAULT 'processed',
                    FOREIGN KEY (campaign_id) REFERENCES campaigns (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
        
        # Check if admin user exists
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        else:
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        
        admin_count = cursor.fetchone()[0]
        
        if admin_count == 0:
            # Create default admin user
            admin_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (%s, %s, %s, %s, %s)
                """, ("admin", "admin@brainlinktracker.com", admin_password, "admin", "active"))
            else:
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (?, ?, ?, ?, ?)
                """, ("admin", "admin@brainlinktracker.com", admin_password, "admin", "active"))
            
            print("✅ Default admin user created: admin / admin123")
        
        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Database initialized successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        return False

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.headers.get('Authorization')
        if not session_token:
            return jsonify({'error': 'No authorization token provided'}), 401
        
        if session_token.startswith('Bearer '):
            session_token = session_token[7:]
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    SELECT u.id, u.username, u.role, u.status 
                    FROM users u 
                    JOIN user_sessions s ON u.id = s.user_id 
                    WHERE s.session_token = %s AND s.expires_at > CURRENT_TIMESTAMP
                """, (session_token,))
            else:
                cursor.execute("""
                    SELECT u.id, u.username, u.role, u.status 
                    FROM users u 
                    JOIN user_sessions s ON u.id = s.user_id 
                    WHERE s.session_token = ? AND s.expires_at > datetime('now')
                """, (session_token,))
            
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not user:
                return jsonify({'error': 'Invalid or expired session'}), 401
            
            if user[3] != 'active':  # status
                return jsonify({'error': 'Account not active'}), 401
            
            # Add user info to request context
            request.current_user = {
                'id': user[0],
                'username': user[1],
                'role': user[2],
                'status': user[3]
            }
            
            return f(*args, **kwargs)
            
        except Exception as e:
            print(f"Auth error: {e}")
            return jsonify({'error': 'Authentication failed'}), 401
    
    return decorated_function

# Frontend serving routes
@app.route('/')
def serve_frontend():
    """Serve the main frontend page"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static_files(path):
    """Serve static files"""
    try:
        return send_from_directory(app.static_folder, path)
    except:
        # If file not found, serve index.html for SPA routing
        return send_from_directory(app.static_folder, 'index.html')

# Health check endpoint
@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'Brain Link Tracker API is running',
        'version': '1.0.0',
        'database': DATABASE_TYPE
    })

# Authentication endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT id, username, password_hash, role, status FROM users WHERE username = %s", (username,))
        else:
            cursor.execute("SELECT id, username, password_hash, role, status FROM users WHERE username = ?", (username,))
        
        user = cursor.fetchone()
        
        if not user:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user_id, username, password_hash, role, status = user
        
        if status != 'active':
            cursor.close()
            conn.close()
            return jsonify({'error': 'Account not active'}), 401
        
        if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(days=7)
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (%s, %s, %s)
            """, (user_id, session_token, expires_at))
            
            cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s", (user_id,))
        else:
            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, expires_at)
                VALUES (?, ?, ?)
            """, (user_id, session_token, expires_at))
            
            cursor.execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (user_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Login successful',
            'token': session_token,
            'user': {
                'id': user_id,
                'username': username,
                'role': role
            }
        })
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """User logout endpoint"""
    try:
        session_token = request.headers.get('Authorization')
        if session_token.startswith('Bearer '):
            session_token = session_token[7:]
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("DELETE FROM user_sessions WHERE session_token = %s", (session_token,))
        else:
            cursor.execute("DELETE FROM user_sessions WHERE session_token = ?", (session_token,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Logout successful'})
        
    except Exception as e:
        print(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

# User management endpoints
@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not username or not email or not password:
            return jsonify({'error': 'Username, email, and password required'}), 400
        
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            if DATABASE_TYPE == "postgresql":
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (%s, %s, %s, %s, %s)
                """, (username, email, password_hash, "member", "pending"))
            else:
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role, status)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, email, password_hash, "member", "pending"))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({'message': 'Registration successful'})
            
        except Exception as e:
            cursor.close()
            conn.close()
            if 'UNIQUE constraint failed' in str(e) or 'duplicate key' in str(e):
                return jsonify({'error': 'Username or email already exists'}), 400
            raise e
            
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return send_from_directory(app.static_folder, 'index.html')

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    print(f"✅ Brain Link Tracker starting with {DATABASE_TYPE} database...")
    app.run(host='0.0.0.0', port=5000, debug=True)


# User management endpoints
@app.route('/api/users', methods=['GET'])
@require_auth
def get_users():
    """Get all users (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("""
                SELECT id, username, email, role, status, created_at, last_login
                FROM users ORDER BY created_at DESC
            """)
        else:
            cursor.execute("""
                SELECT id, username, email, role, status, created_at, last_login
                FROM users ORDER BY created_at DESC
            """)
        
        users = cursor.fetchall()
        cursor.close()
        conn.close()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'role': user[3],
                'status': user[4],
                'created_at': user[5],
                'last_login': user[6]
            })
        
        return jsonify(user_list)
        
    except Exception as e:
        print(f"Get users error: {e}")
        return jsonify({'error': 'Failed to fetch users'}), 500

@app.route('/api/users/<int:user_id>/approve', methods=['POST'])
@require_auth
def approve_user(user_id):
    """Approve a pending user (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("UPDATE users SET status = 'active' WHERE id = %s", (user_id,))
        else:
            cursor.execute("UPDATE users SET status = 'active' WHERE id = ?", (user_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'User approved successfully'})
        
    except Exception as e:
        print(f"Approve user error: {e}")
        return jsonify({'error': 'Failed to approve user'}), 500

@app.route('/api/users/<int:user_id>/reject', methods=['POST'])
@require_auth
def reject_user(user_id):
    """Reject a pending user (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("UPDATE users SET status = 'rejected' WHERE id = %s", (user_id,))
        else:
            cursor.execute("UPDATE users SET status = 'rejected' WHERE id = ?", (user_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'User rejected successfully'})
        
    except Exception as e:
        print(f"Reject user error: {e}")
        return jsonify({'error': 'Failed to reject user'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    """Delete a user (admin only)"""
    try:
        if request.current_user['role'] != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if DATABASE_TYPE == "postgresql":
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        else:
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'User deleted successfully'})
        
    except Exception as e:
        print(f"Delete user error: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500

@app.route('/api/analytics', methods=['GET'])
@require_auth
def get_analytics():
    """Get analytics data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user counts
        if DATABASE_TYPE == "postgresql":
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active'")
            active_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending'")
            pending_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            admin_users = cursor.fetchone()[0]
        else:
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'active'")
            active_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE status = 'pending'")
            pending_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            admin_users = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'pending_users': pending_users,
            'admin_users': admin_users,
            'last_updated': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Analytics error: {e}")
        return jsonify({'error': 'Failed to fetch analytics'}), 500




# Tracking Helper Functions (from enhanced_main.py)
def get_geolocation(ip_address):
    """Get geolocation data for IP address"""
    try:
        response = requests.get(f'http://ipapi.co/{ip_address}/json/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country_name', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'isp': data.get('org', 'Unknown')
            }
    except Exception as e:
        print(f"Geolocation error: {e}")
    
    return {
        'country': 'Unknown',
        'city': 'Unknown', 
        'region': 'Unknown',
        'isp': 'Unknown'
    }

def detect_bot(user_agent, ip_address):
    """Detect if the request is from a bot"""
    if not user_agent:
        return True
    
    user_agent_lower = user_agent.lower()
    
    bot_indicators = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python',
        'requests', 'urllib', 'http', 'api', 'monitor', 'check', 'test',
        'scan', 'probe', 'fetch', 'download', 'automation', 'headless'
    ]
    
    for indicator in bot_indicators:
        if indicator in user_agent_lower:
            return True
    
    if len(user_agent) < 20 or len(user_agent) > 500:
        return True
    
    if not any(browser in user_agent_lower for browser in ['mozilla', 'webkit', 'chrome', 'firefox', 'safari', 'edge']):
        return True
    
    return False

def analyze_user_agent(user_agent):
    """Analyze user agent for device and browser info"""
    try:
        parsed = parse(user_agent)
        return {
            'browser': f"{parsed.browser.family} {parsed.browser.version_string}",
            'os': f"{parsed.os.family} {parsed.os.version_string}",
            'device_type': 'Mobile' if parsed.is_mobile else ('Tablet' if parsed.is_tablet else 'Desktop'),
            'is_mobile': parsed.is_mobile
        }
    except:
        return {
            'browser': 'Unknown',
            'os': 'Unknown',
            'device_type': 'Unknown',
            'is_mobile': False
        }

def create_fingerprint(ip_address, user_agent):
    """Create a unique fingerprint for visitor identification"""
    fingerprint_data = f"{ip_address}:{user_agent}"
    return hashlib.md5(fingerprint_data.encode()).hexdigest()[:16]






# Log click function (adapted for PostgreSQL)
def log_click(tracking_token, email=None, campaign_id=None, user_id=None):
    """Log a click event with enhanced analytics"""
    start_time = datetime.now()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    ip_address = request.environ.get("HTTP_X_FORWARDED_FOR", request.environ.get("REMOTE_ADDR"))
    user_agent = request.headers.get("User-Agent", "")
    referrer = request.headers.get("Referer", "")
    
    geo_data = get_geolocation(ip_address)
    is_bot = detect_bot(user_agent, ip_address)
    ua_data = analyze_user_agent(user_agent)
    
    # Calculate response time (simple placeholder, actual response time would be measured differently)
    response_time = int((datetime.now() - start_time).total_seconds() * 1000)
    
    try:
        cursor.execute("""
            INSERT INTO tracking_events 
            (tracking_token, event_type, ip_address, user_agent, referrer, 
             country, city, device_type, browser, os, additional_data, 
             campaign_id, user_id, is_bot, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (tracking_token, "click", ip_address, user_agent, referrer,
              geo_data["country"], geo_data["city"], ua_data["device_type"], 
              ua_data["browser"], ua_data["os"], json.dumps({"response_time_ms": response_time}),
              campaign_id, user_id, is_bot, "processed"))
        conn.commit()
    except Exception as e:
        print(f"Error logging click: {e}")
    finally:
        cursor.close()
        conn.close()


# New API Endpoints for Tracking Links and Analytics
@app.route("/api/tracking-links", methods=["POST"])
@require_auth
def create_tracking_link_hyphen():
    """Create a new tracking link (hyphenated endpoint for frontend compatibility)"""
    return create_tracking_link()

@app.route("/api/tracking-links", methods=["GET"])
@require_auth
def get_tracking_links_hyphen():
    """Get all tracking links for the current user (hyphenated endpoint for frontend compatibility)"""
    return get_tracking_links()

@app.route("/api/tracking-events", methods=["GET"])
@require_auth
def get_tracking_events_hyphen():
    """Get all tracking events for the current user's links (hyphenated endpoint for frontend compatibility)"""
    return get_tracking_events()

@app.route("/api/tracking_links", methods=["POST"])
@require_auth
def create_tracking_link():
    """Create a new tracking link"""
    try:
        data = request.get_json()
        original_url = data.get("original_url")
        campaign_id = data.get("campaign_id")
        recipient_email = data.get("recipient_email")
        recipient_name = data.get("recipient_name")
        
        if not original_url:
            return jsonify({"error": "Original URL is required"}), 400
        
        user_id = request.current_user["id"]
        tracking_token = secrets.token_urlsafe(16)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO tracking_links 
            (user_id, original_url, tracking_token, campaign_id, recipient_email, recipient_name)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user_id, original_url, tracking_token, campaign_id, recipient_email, recipient_name))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({"message": "Tracking link created successfully", "tracking_token": tracking_token}), 201
        
    except Exception as e:
        print(f"Error creating tracking link: {e}")
        return jsonify({"error": "Failed to create tracking link"}), 500

@app.route("/api/tracking_links", methods=["GET"])
@require_auth
def get_tracking_links():
    """Get all tracking links for the current user"""
    try:
        user_id = request.current_user["id"]
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM tracking_links WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
        links = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        link_list = []
        for link in links:
            link_list.append({
                "id": link[0],
                "campaign_id": link[1],
                "user_id": link[2],
                "original_url": link[3],
                "tracking_token": link[4],
                "recipient_email": link[5],
                "recipient_name": link[6],
                "link_status": link[7],
                "created_at": link[8].isoformat() if link[8] else None,
                "expires_at": link[9].isoformat() if link[9] else None,
                "click_limit": link[10],
                "click_count": link[11],
                "last_clicked": link[12].isoformat() if link[12] else None,
                "custom_message": link[13],
                "redirect_delay": link[14],
                "password_protected": link[15],
                "access_password": link[16],
                "geo_restrictions": link[17],
                "device_restrictions": link[18],
                "time_restrictions": link[19]
            })
        
        return jsonify(link_list)
        
    except Exception as e:
        print(f"Error fetching tracking links: {e}")
        return jsonify({"error": "Failed to fetch tracking links"}), 500

@app.route("/track/<tracking_token>")
def track_link(tracking_token):
    """Redirects to the original URL after logging the click"""
    conn = get_db_connection()
    cursor = conn.cursor()
    original_url = "/"
    campaign_id = None
    user_id = None
    
    try:
        cursor.execute("SELECT original_url, campaign_id, user_id FROM tracking_links WHERE tracking_token = %s", (tracking_token,))
        link_data = cursor.fetchone()
        
        if link_data:
            original_url = link_data[0]
            campaign_id = link_data[1]
            user_id = link_data[2]
            log_click(tracking_token, campaign_id=campaign_id, user_id=user_id)
        else:
            print(f"Tracking token {tracking_token} not found.")
            return "Link not found", 404
            
    except Exception as e:
        print(f"Error in track_link: {e}")
    finally:
        cursor.close()
        conn.close()
        
    return redirect(original_url)

@app.route("/api/tracking_events", methods=["GET"])
@require_auth
def get_tracking_events():
    """Get all tracking events for the current user's links"""
    try:
        user_id = request.current_user["id"]
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT te.* FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = %s ORDER BY te.timestamp DESC
        """, (user_id,))
        events = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        event_list = []
        for event in events:
            event_list.append({
                "id": event[0],
                "tracking_token": event[1],
                "event_type": event[2],
                "ip_address": str(event[3]),
                "user_agent": event[4],
                "referrer": event[5],
                "country": event[6],
                "city": event[7],
                "device_type": event[8],
                "browser": event[9],
                "os": event[10],
                "timestamp": event[11].isoformat() if event[11] else None,
                "additional_data": event[12],
                "campaign_id": event[13],
                "user_id": event[14],
                "is_bot": event[15],
                "bot_confidence": event[16],
                "bot_reason": event[17],
                "status": event[18]
            })
        
        return jsonify(event_list)
        
    except Exception as e:
        print(f"Error fetching tracking events: {e}")
        return jsonify({"error": "Failed to fetch tracking events"}), 500

@app.route("/api/analytics/summary", methods=["GET"])
@require_auth
def get_analytics_summary():
    """Get summary analytics data for the current user"""
    try:
        user_id = request.current_user["id"]
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total links
        cursor.execute("SELECT COUNT(*) FROM tracking_links WHERE user_id = %s", (user_id,))
        total_links = cursor.fetchone()[0]
        
        # Total clicks
        cursor.execute("""
            SELECT COUNT(*) FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = %s
        """, (user_id,))
        total_clicks = cursor.fetchone()[0]
        
        # Unique visitors (based on IP and user agent, simplified for now)
        cursor.execute("""
            SELECT COUNT(DISTINCT ip_address, user_agent) FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = %s
        """, (user_id,))
        unique_visitors = cursor.fetchone()[0]
        
        # Bot clicks
        cursor.execute("""
            SELECT COUNT(*) FROM tracking_events te
            JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
            WHERE tl.user_id = %s AND te.is_bot = TRUE
        """, (user_id,))
        bot_clicks = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "total_links": total_links,
            "total_clicks": total_clicks,
            "unique_visitors": unique_visitors,
            "bot_clicks": bot_clicks
        })
        
    except Exception as e:
        print(f"Error fetching analytics summary: {e}")
        return jsonify({"error": "Failed to fetch analytics summary"}), 500



