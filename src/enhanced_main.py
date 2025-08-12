#!/usr/bin/env python3
"""
Enhanced link tracking service with advanced analytics
"""

from flask import Flask, request, redirect, jsonify, render_template_string
from flask_cors import CORS
import sqlite3
import datetime
import os
import hashlib
import requests
import json
import re
from user_agents import parse

app = Flask(__name__)
CORS(app)

# Database setup
DB_PATH = '/home/ubuntu/enhanced_tracker.db'

def init_db():
    """Initialize the database with enhanced schema"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create enhanced tracking table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tracking_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracking_id TEXT NOT NULL,
            email TEXT,
            ip_address TEXT,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            referer TEXT,
            campaign_id TEXT,
            country TEXT,
            city TEXT,
            region TEXT,
            isp TEXT,
            is_bot BOOLEAN DEFAULT 0,
            is_mobile BOOLEAN DEFAULT 0,
            browser TEXT,
            os TEXT,
            device_type TEXT,
            redirect_status TEXT DEFAULT 'success',
            redirect_url TEXT,
            response_time_ms INTEGER,
            fingerprint TEXT
        )
    ''')
    
    # Create visitor classification table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS visitor_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            total_clicks INTEGER DEFAULT 0,
            unique_visitors INTEGER DEFAULT 0,
            bot_clicks INTEGER DEFAULT 0,
            mobile_clicks INTEGER DEFAULT 0,
            desktop_clicks INTEGER DEFAULT 0,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_geolocation(ip_address):
    """Get geolocation data for IP address"""
    try:
        # Using ipapi.co for geolocation (free tier)
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
    
    # Common bot indicators
    bot_indicators = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python',
        'requests', 'urllib', 'http', 'api', 'monitor', 'check', 'test',
        'scan', 'probe', 'fetch', 'download', 'automation', 'headless'
    ]
    
    for indicator in bot_indicators:
        if indicator in user_agent_lower:
            return True
    
    # Check for suspicious patterns
    if len(user_agent) < 20 or len(user_agent) > 500:
        return True
    
    # Check for missing common browser components
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

def log_click(tracking_id, email=None, campaign_id=None):
    """Log a click event with enhanced analytics"""
    start_time = datetime.datetime.now()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
    user_agent = request.headers.get('User-Agent', '')
    referer = request.headers.get('Referer', '')
    
    # Get geolocation data
    geo_data = get_geolocation(ip_address)
    
    # Detect bot
    is_bot = detect_bot(user_agent, ip_address)
    
    # Analyze user agent
    ua_data = analyze_user_agent(user_agent)
    
    # Create fingerprint
    fingerprint = create_fingerprint(ip_address, user_agent)
    
    # Calculate response time
    response_time = int((datetime.datetime.now() - start_time).total_seconds() * 1000)
    
    # Default redirect URL (can be customized per campaign)
    redirect_url = "https://www.google.com"
    redirect_status = "success"
    
    cursor.execute('''
        INSERT INTO tracking_events 
        (tracking_id, email, ip_address, user_agent, referer, campaign_id,
         country, city, region, isp, is_bot, is_mobile, browser, os, 
         device_type, redirect_status, redirect_url, response_time_ms, fingerprint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (tracking_id, email, ip_address, user_agent, referer, campaign_id,
          geo_data['country'], geo_data['city'], geo_data['region'], geo_data['isp'],
          is_bot, ua_data['is_mobile'], ua_data['browser'], ua_data['os'],
          ua_data['device_type'], redirect_status, redirect_url, response_time, fingerprint))
    
    # Update daily stats
    today = datetime.date.today().isoformat()
    cursor.execute('''
        INSERT OR IGNORE INTO visitor_stats (date, total_clicks, unique_visitors, bot_clicks, mobile_clicks, desktop_clicks)
        VALUES (?, 0, 0, 0, 0, 0)
    ''', (today,))
    
    cursor.execute('''
        UPDATE visitor_stats SET 
            total_clicks = total_clicks + 1,
            bot_clicks = bot_clicks + ?,
            mobile_clicks = mobile_clicks + ?,
            desktop_clicks = desktop_clicks + ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE date = ?
    ''', (1 if is_bot else 0, 1 if ua_data['is_mobile'] else 0, 1 if not ua_data['is_mobile'] else 0, today))
    
    # Update unique visitors (based on fingerprint)
    cursor.execute('''
        SELECT COUNT(*) FROM tracking_events 
        WHERE fingerprint = ? AND date(timestamp) = ?
    ''', (fingerprint, today))
    
    if cursor.fetchone()[0] == 1:  # First visit today
        cursor.execute('''
            UPDATE visitor_stats SET 
                unique_visitors = unique_visitors + 1
            WHERE date = ?
        ''', (today,))
    
    conn.commit()
    conn.close()
    
    return redirect_url

@app.route('/')
def dashboard():
    """Enhanced dashboard with advanced analytics"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get overall stats
    cursor.execute('SELECT COUNT(*) FROM tracking_events')
    total_clicks = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(DISTINCT fingerprint) FROM tracking_events')
    unique_visitors = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM tracking_events WHERE is_bot = 1')
    bot_clicks = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM tracking_events WHERE is_bot = 0')
    human_clicks = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM tracking_events WHERE is_mobile = 1')
    mobile_clicks = cursor.fetchone()[0]
    
    # Get top countries
    cursor.execute('''
        SELECT country, COUNT(*) as clicks 
        FROM tracking_events 
        WHERE country != 'Unknown'
        GROUP BY country 
        ORDER BY clicks DESC 
        LIMIT 5
    ''')
    top_countries = cursor.fetchall()
    
    # Get top ISPs
    cursor.execute('''
        SELECT isp, COUNT(*) as clicks 
        FROM tracking_events 
        WHERE isp != 'Unknown'
        GROUP BY isp 
        ORDER BY clicks DESC 
        LIMIT 5
    ''')
    top_isps = cursor.fetchall()
    
    # Get recent clicks with enhanced data
    cursor.execute('''
        SELECT tracking_id, email, ip_address, country, city, region, isp, 
               is_bot, device_type, browser, os, redirect_status, response_time_ms, 
               timestamp, user_agent
        FROM tracking_events 
        ORDER BY timestamp DESC 
        LIMIT 15
    ''')
    recent_clicks = cursor.fetchall()
    
    # Get hourly activity for last 24 hours
    cursor.execute('''
        SELECT strftime('%H', timestamp) as hour, 
               COUNT(*) as total,
               SUM(CASE WHEN is_bot = 0 THEN 1 ELSE 0 END) as human,
               SUM(CASE WHEN is_bot = 1 THEN 1 ELSE 0 END) as bot
        FROM tracking_events 
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    ''')
    hourly_stats = cursor.fetchall()
    
    conn.close()
    
    dashboard_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Enhanced Link Tracker Dashboard</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f7fa; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; }
            .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .stat-card { 
                background: white; 
                padding: 25px; 
                border-radius: 10px; 
                text-align: center;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                border-left: 4px solid #667eea;
            }
            .stat-number { font-size: 2.5em; font-weight: bold; color: #333; margin-bottom: 5px; }
            .stat-label { color: #666; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }
            .content-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px; }
            .panel { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .panel h3 { margin-top: 0; color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
            th { background-color: #f8f9fa; font-weight: 600; color: #555; }
            .timestamp { font-size: 0.85em; color: #666; }
            .tracking-id { font-family: monospace; background: #f0f0f0; padding: 3px 6px; border-radius: 3px; font-size: 0.85em; }
            .status-success { color: #28a745; font-weight: bold; }
            .status-bot { color: #dc3545; font-weight: bold; }
            .status-human { color: #28a745; font-weight: bold; }
            .country-flag { margin-right: 8px; }
            .device-icon { margin-right: 5px; }
            .full-width { grid-column: 1 / -1; }
            .metric-positive { color: #28a745; }
            .metric-warning { color: #ffc107; }
            .metric-danger { color: #dc3545; }
            .hourly-chart { display: flex; align-items: end; height: 100px; gap: 2px; margin: 20px 0; }
            .hour-bar { background: #667eea; min-height: 2px; flex: 1; border-radius: 2px 2px 0 0; position: relative; }
            .hour-bar:hover::after { 
                content: attr(data-tooltip); 
                position: absolute; 
                bottom: 100%; 
                left: 50%; 
                transform: translateX(-50%);
                background: #333; 
                color: white; 
                padding: 5px 8px; 
                border-radius: 4px; 
                font-size: 12px;
                white-space: nowrap;
            }
            code { 
                background: #f8f9fa; 
                padding: 2px 6px; 
                border-radius: 3px; 
                font-family: 'Courier New', monospace; 
                font-size: 0.85em;
                color: #e83e8c;
            }
            .table-container { 
                overflow-x: auto; 
                margin: 15px 0;
                border: 1px solid #dee2e6;
                border-radius: 8px;
            }
            .enhanced-table { 
                min-width: 1400px; 
                margin: 0;
                border-collapse: separate;
                border-spacing: 0;
            }
            .enhanced-table th {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                font-weight: 600;
                padding: 12px 8px;
                text-align: center;
                border: none;
                position: sticky;
                top: 0;
                z-index: 10;
            }
            .enhanced-table td {
                padding: 10px 8px;
                border-bottom: 1px solid #eee;
                border-right: 1px solid #f0f0f0;
                vertical-align: middle;
                font-size: 0.85em;
            }
            .enhanced-table tr:hover {
                background-color: #f8f9fa;
            }
            .enhanced-table th:first-child,
            .enhanced-table td:first-child {
                border-left: none;
            }
            .enhanced-table th:last-child,
            .enhanced-table td:last-child {
                border-right: none;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔗 Enhanced Link Tracker Dashboard</h1>
            <p>Advanced Analytics & Bot Detection System</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{{ total_clicks }}</div>
                <div class="stat-label">Total Clicks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ unique_visitors }}</div>
                <div class="stat-label">Unique Visitors</div>
            </div>
            <div class="stat-card">
                <div class="stat-number metric-positive">{{ human_clicks }}</div>
                <div class="stat-label">Human Clicks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number metric-danger">{{ bot_clicks }}</div>
                <div class="stat-label">Bot Clicks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ mobile_clicks }}</div>
                <div class="stat-label">Mobile Clicks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ (human_clicks / total_clicks * 100) | round(1) if total_clicks > 0 else 0 }}%</div>
                <div class="stat-label">Human Rate</div>
            </div>
        </div>
        
        <div class="content-grid">
            <div class="panel">
                <h3>🌍 Top Countries</h3>
                <table>
                    <thead>
                        <tr><th>Country</th><th>Clicks</th><th>%</th></tr>
                    </thead>
                    <tbody>
                        {% for country, clicks in top_countries %}
                        <tr>
                            <td>🌍 {{ country }}</td>
                            <td>{{ clicks }}</td>
                            <td>{{ (clicks / total_clicks * 100) | round(1) if total_clicks > 0 else 0 }}%</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <div class="panel">
                <h3>🏢 Top ISPs</h3>
                <table>
                    <thead>
                        <tr><th>ISP</th><th>Clicks</th><th>%</th></tr>
                    </thead>
                    <tbody>
                        {% for isp, clicks in top_isps %}
                        <tr>
                            <td>{{ isp[:30] }}...</td>
                            <td>{{ clicks }}</td>
                            <td>{{ (clicks / total_clicks * 100) | round(1) if total_clicks > 0 else 0 }}%</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="panel full-width">
            <h3>📊 Hourly Activity (Last 24 Hours)</h3>
            <div class="hourly-chart">
                {% for hour, total, human, bot in hourly_stats %}
                <div class="hour-bar" 
                     style="height: {{ (total / 50 * 100) if total > 0 else 2 }}px"
                     data-tooltip="{{ hour }}:00 - Total: {{ total }}, Human: {{ human }}, Bot: {{ bot }}">
                </div>
                {% endfor %}
            </div>
        </div>
        
        <div class="panel full-width">
            <h3>🔍 Recent Activity</h3>
            <div class="table-container">
                <table class="enhanced-table">
                    <thead>
                        <tr>
                            <th>Tracking ID</th>
                            <th>Email</th>
                            <th>IP Address</th>
                            <th>Country</th>
                            <th>City</th>
                            <th>Region</th>
                            <th>ISP</th>
                            <th>Visitor Type</th>
                            <th>Device</th>
                            <th>Browser</th>
                            <th>OS</th>
                            <th>Status</th>
                            <th>Response Time</th>
                            <th>Timestamp</th>
                            <th>User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for click in recent_clicks %}
                        <tr>
                            <td><span class="tracking-id">{{ click[0] }}</span></td>
                            <td>{{ click[1] or 'N/A' }}</td>
                            <td><code>{{ click[2] }}</code></td>
                            <td>🌍 {{ click[3] }}</td>
                            <td>🏙️ {{ click[4] }}</td>
                            <td>📍 {{ click[5] }}</td>
                            <td title="{{ click[6] }}">{{ click[6][:25] }}{% if click[6]|length > 25 %}...{% endif %}</td>
                            <td>
                                {% if click[7] %}
                                    <span class="status-bot">🤖 Bot</span>
                                {% else %}
                                    <span class="status-human">👤 Human</span>
                                {% endif %}
                            </td>
                            <td>
                                {% if click[8] == 'Mobile' %}📱{% elif click[8] == 'Tablet' %}📱{% else %}💻{% endif %}
                                {{ click[8] }}
                            </td>
                            <td title="{{ click[9] }}">{{ click[9][:20] }}{% if click[9]|length > 20 %}...{% endif %}</td>
                            <td title="{{ click[10] }}">{{ click[10][:15] }}{% if click[10]|length > 15 %}...{% endif %}</td>
                            <td><span class="status-success">{{ click[11] }}</span></td>
                            <td>{{ click[12] }}ms</td>
                            <td class="timestamp">{{ click[13] }}</td>
                            <td title="{{ click[14] }}" style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                                {{ click[14][:30] }}{% if click[14]|length > 30 %}...{% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="panel full-width" style="margin-top: 30px; background: #e8f4fd;">
            <h3>📊 System Status</h3>
            <p><strong>Service Status:</strong> ✅ Active with Enhanced Analytics</p>
            <p><strong>Features:</strong> 🌍 Geolocation | 🤖 Bot Detection | 📱 Device Analysis | 🔍 ISP Tracking</p>
            <p><strong>Last Updated:</strong> {{ current_time }}</p>
            <p><strong>Database:</strong> {{ db_path }}</p>
            <div style="margin-top: 20px;">
                <a href="/api/stats" style="background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-right: 10px;">📈 API Stats</a>
                <a href="/api/export" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">📊 Export Data</a>
            </div>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(dashboard_html, 
                                total_clicks=total_clicks,
                                unique_visitors=unique_visitors,
                                bot_clicks=bot_clicks,
                                human_clicks=human_clicks,
                                mobile_clicks=mobile_clicks,
                                top_countries=top_countries,
                                top_isps=top_isps,
                                recent_clicks=recent_clicks,
                                hourly_stats=hourly_stats,
                                current_time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                db_path=DB_PATH)

@app.route('/track/<tracking_id>')
def track_click(tracking_id):
    """Track a click and redirect with enhanced analytics"""
    # Log the click with enhanced data
    redirect_url = log_click(tracking_id)
    
    # Create enhanced success page
    success_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Click Tracked Successfully</title>
        <style>
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                text-align: center; 
                padding: 50px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                margin: 0;
            }
            .container {
                background: rgba(255,255,255,0.1);
                padding: 40px;
                border-radius: 15px;
                backdrop-filter: blur(10px);
                max-width: 600px;
                margin: 0 auto;
            }
            .success-icon { font-size: 4em; margin-bottom: 20px; }
            h1 { margin-bottom: 20px; }
            .tracking-id { 
                font-family: monospace; 
                background: rgba(255,255,255,0.2); 
                padding: 10px; 
                border-radius: 5px; 
                margin: 20px 0;
                word-break: break-all;
            }
            .analytics-info {
                background: rgba(255,255,255,0.1);
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                text-align: left;
            }
            .btn {
                display: inline-block;
                padding: 12px 24px;
                background: rgba(255,255,255,0.2);
                color: white;
                text-decoration: none;
                border-radius: 25px;
                margin: 10px;
                transition: background 0.3s;
            }
            .btn:hover {
                background: rgba(255,255,255,0.3);
            }
            .redirect-info {
                background: rgba(40, 167, 69, 0.2);
                padding: 15px;
                border-radius: 8px;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="success-icon">✅</div>
            <h1>Click Tracked Successfully!</h1>
            <p>Your interaction has been recorded with advanced analytics.</p>
            
            <div class="tracking-id">Tracking ID: {{ tracking_id }}</div>
            
            <div class="analytics-info">
                <h3>📊 Analytics Captured:</h3>
                <ul>
                    <li>🌍 Geographic location (Country, City, Region)</li>
                    <li>🏢 Internet Service Provider (ISP)</li>
                    <li>🤖 Bot detection and classification</li>
                    <li>📱 Device type and browser analysis</li>
                    <li>⏱️ Response time and performance metrics</li>
                    <li>🔍 Unique visitor fingerprinting</li>
                </ul>
            </div>
            
            <div class="redirect-info">
                <strong>🔄 Redirect Status:</strong> Success<br>
                <strong>⏱️ Timestamp:</strong> {{ timestamp }}
            </div>
            
            <a href="/" class="btn">📊 View Dashboard</a>
            <a href="/api/stats" class="btn">📈 API Stats</a>
            <a href="{{ redirect_url }}" class="btn">🔗 Continue to Destination</a>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(success_html, 
                                tracking_id=tracking_id,
                                timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                redirect_url=redirect_url)

@app.route('/api/stats')
def api_stats():
    """Enhanced API endpoint for statistics"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Get comprehensive stats
    cursor.execute('SELECT COUNT(*) FROM tracking_events')
    total_clicks = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(DISTINCT fingerprint) FROM tracking_events')
    unique_visitors = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM tracking_events WHERE is_bot = 1')
    bot_clicks = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM tracking_events WHERE is_bot = 0')
    human_clicks = cursor.fetchone()[0]
    
    # Get geographic distribution
    cursor.execute('''
        SELECT country, COUNT(*) as clicks 
        FROM tracking_events 
        GROUP BY country 
        ORDER BY clicks DESC
    ''')
    countries = dict(cursor.fetchall())
    
    # Get device distribution
    cursor.execute('''
        SELECT device_type, COUNT(*) as clicks 
        FROM tracking_events 
        GROUP BY device_type 
        ORDER BY clicks DESC
    ''')
    devices = dict(cursor.fetchall())
    
    # Get ISP distribution
    cursor.execute('''
        SELECT isp, COUNT(*) as clicks 
        FROM tracking_events 
        WHERE isp != 'Unknown'
        GROUP BY isp 
        ORDER BY clicks DESC
        LIMIT 10
    ''')
    isps = dict(cursor.fetchall())
    
    # Get all tracking events with enhanced data
    cursor.execute('''
        SELECT tracking_id, email, ip_address, country, city, region, isp,
               is_bot, is_mobile, browser, os, device_type, redirect_status,
               redirect_url, response_time_ms, fingerprint, timestamp
        FROM tracking_events 
        ORDER BY timestamp DESC
    ''')
    all_events = cursor.fetchall()
    
    conn.close()
    
    return jsonify({
        'summary': {
            'total_clicks': total_clicks,
            'unique_visitors': unique_visitors,
            'bot_clicks': bot_clicks,
            'human_clicks': human_clicks,
            'human_rate': round(human_clicks / total_clicks * 100, 2) if total_clicks > 0 else 0
        },
        'geographic_distribution': countries,
        'device_distribution': devices,
        'isp_distribution': isps,
        'events': [
            {
                'tracking_id': event[0],
                'email': event[1],
                'ip_address': event[2],
                'country': event[3],
                'city': event[4],
                'region': event[5],
                'isp': event[6],
                'is_bot': bool(event[7]),
                'is_mobile': bool(event[8]),
                'browser': event[9],
                'os': event[10],
                'device_type': event[11],
                'redirect_status': event[12],
                'redirect_url': event[13],
                'response_time_ms': event[14],
                'fingerprint': event[15],
                'timestamp': event[16]
            }
            for event in all_events
        ]
    })

@app.route('/api/export')
def export_data():
    """Export tracking data as CSV"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT tracking_id, email, ip_address, country, city, region, isp,
               CASE WHEN is_bot = 1 THEN 'Bot' ELSE 'Human' END as visitor_type,
               device_type, browser, os, redirect_status, timestamp
        FROM tracking_events 
        ORDER BY timestamp DESC
    ''')
    
    events = cursor.fetchall()
    conn.close()
    
    # Create CSV content
    csv_content = "Tracking ID,Email,IP Address,Country,City,Region,ISP,Visitor Type,Device,Browser,OS,Status,Timestamp\n"
    for event in events:
        csv_content += ",".join([str(field) for field in event]) + "\n"
    
    from flask import Response
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename=tracking_data_{datetime.date.today()}.csv"}
    )

if __name__ == '__main__':
    # Initialize database
    init_db()
    print("🚀 Starting Enhanced Link Tracker...")
    print("📊 Dashboard: http://0.0.0.0:5002")
    print("🔗 Track links: http://0.0.0.0:5002/track/{tracking_id}")
    print("📈 API Stats: http://0.0.0.0:5002/api/stats")
    print("📊 Export Data: http://0.0.0.0:5002/api/export")
    print("✨ Features: Geolocation, Bot Detection, Device Analysis, ISP Tracking")
    
    # Run the app
    app.run(host='0.0.0.0', port=5002, debug=True)

