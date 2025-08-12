from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from services.captcha_service import CaptchaService
from models.user import AuditLog, db
import json
from datetime import datetime
import hashlib

captcha_bp = Blueprint('captcha', __name__)

# Initialize CAPTCHA service
captcha_service = CaptchaService()

def get_client_ip():
    """Get client IP address"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    return request.environ.get('REMOTE_ADDR', 'unknown')

def log_captcha_event(action, challenge_id=None, success=None, details=None):
    """Log CAPTCHA-related events"""
    try:
        audit_log = AuditLog(
            action=action,
            user_id=current_user.id if current_user.is_authenticated else None,
            resource_type='captcha',
            resource_id=challenge_id,
            details={
                'success': success,
                'ip_address': get_client_ip(),
                'user_agent': request.headers.get('User-Agent', 'unknown'),
                **(details or {})
            }
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        print(f"Failed to log CAPTCHA event: {e}")

@captcha_bp.route('/api/captcha/generate', methods=['POST'])
def generate_captcha():
    """Generate a new CAPTCHA challenge"""
    try:
        data = request.get_json() or {}
        
        challenge_type = data.get('type')  # Optional: specific type
        difficulty = data.get('difficulty', 'medium')
        adaptive = data.get('adaptive', False)
        
        # Validate difficulty
        if difficulty not in ['easy', 'medium', 'hard']:
            difficulty = 'medium'
        
        # Generate challenge
        if adaptive and current_user.is_authenticated:
            # Get user's CAPTCHA history for adaptive challenge
            user_history = get_user_captcha_history(current_user.id)
            challenge = captcha_service.create_adaptive_challenge(user_history)
        else:
            challenge = captcha_service.generate_challenge(challenge_type, difficulty)
        
        # Log challenge generation
        log_captcha_event('captcha_generated', challenge['challenge_id'], None, {
            'type': challenge['type'],
            'difficulty': challenge['difficulty']
        })
        
        return jsonify({
            'success': True,
            'challenge': challenge
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Failed to generate CAPTCHA'
        }), 500

@captcha_bp.route('/api/captcha/verify', methods=['POST'])
def verify_captcha():
    """Verify CAPTCHA challenge answer"""
    try:
        data = request.get_json()
        
        if not data or 'challenge_id' not in data or 'answer' not in data:
            return jsonify({
                'success': False,
                'error': 'Challenge ID and answer are required'
            }), 400
        
        challenge_id = data['challenge_id']
        user_answer = data['answer']
        additional_data = data.get('additional_data', {})
        
        # Verify the challenge
        result = captcha_service.verify_challenge(challenge_id, user_answer, additional_data)
        
        # Log verification attempt
        log_captcha_event('captcha_verified', challenge_id, result['success'], {
            'error_code': result.get('error_code'),
            'remaining_attempts': result.get('remaining_attempts')
        })
        
        # Update user history if authenticated
        if current_user.is_authenticated:
            update_user_captcha_history(current_user.id, result['success'])
        
        return jsonify(result), 200 if result['success'] else 400
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Verification failed'
        }), 500

@captcha_bp.route('/api/captcha/validate-token', methods=['POST'])
def validate_token():
    """Validate CAPTCHA completion token"""
    try:
        data = request.get_json()
        
        if not data or 'token' not in data:
            return jsonify({
                'success': False,
                'error': 'Token is required'
            }), 400
        
        token = data['token']
        max_age = data.get('max_age', 3600)  # 1 hour default
        
        is_valid = captcha_service.verify_token(token, max_age)
        
        return jsonify({
            'success': True,
            'valid': is_valid
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Token validation failed'
        }), 500

@captcha_bp.route('/api/captcha/stats', methods=['GET'])
@login_required
def get_captcha_stats():
    """Get CAPTCHA service statistics (admin only)"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        stats = captcha_service.get_challenge_stats()
        
        # Get additional stats from database
        try:
            # Get recent CAPTCHA events
            recent_events = AuditLog.query.filter_by(
                resource_type='captcha'
            ).order_by(AuditLog.created_at.desc()).limit(100).all()
            
            success_count = 0
            failure_count = 0
            type_stats = {}
            
            for event in recent_events:
                if event.action == 'captcha_verified':
                    details = event.get_details()
                    if details.get('success'):
                        success_count += 1
                    else:
                        failure_count += 1
                elif event.action == 'captcha_generated':
                    details = event.get_details()
                    challenge_type = details.get('type', 'unknown')
                    type_stats[challenge_type] = type_stats.get(challenge_type, 0) + 1
            
            stats.update({
                'recent_success_count': success_count,
                'recent_failure_count': failure_count,
                'recent_success_rate': success_count / max(success_count + failure_count, 1),
                'type_usage_stats': type_stats
            })
            
        except Exception as e:
            print(f"Error getting additional stats: {e}")
        
        return jsonify({
            'success': True,
            'stats': stats
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Failed to get statistics'
        }), 500

@captcha_bp.route('/api/captcha/config', methods=['GET'])
@login_required
def get_captcha_config():
    """Get CAPTCHA configuration (admin only)"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        config = {
            'challenge_types': captcha_service.challenge_types,
            'difficulty_levels': list(captcha_service.difficulty_levels.keys()),
            'image_dimensions': {
                'width': captcha_service.image_width,
                'height': captcha_service.image_height
            },
            'settings': {
                'noise_level': captcha_service.noise_level,
                'distortion_level': captcha_service.distortion_level,
                'cleanup_interval': captcha_service.cleanup_interval
            }
        }
        
        return jsonify({
            'success': True,
            'config': config
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Failed to get configuration'
        }), 500

@captcha_bp.route('/api/captcha/config', methods=['PUT'])
@login_required
def update_captcha_config():
    """Update CAPTCHA configuration (admin only)"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        
        if 'noise_level' in data:
            captcha_service.noise_level = max(0.0, min(1.0, float(data['noise_level'])))
        
        if 'distortion_level' in data:
            captcha_service.distortion_level = max(0.0, min(1.0, float(data['distortion_level'])))
        
        if 'cleanup_interval' in data:
            captcha_service.cleanup_interval = max(300, int(data['cleanup_interval']))
        
        if 'image_width' in data:
            captcha_service.image_width = max(100, min(500, int(data['image_width'])))
        
        if 'image_height' in data:
            captcha_service.image_height = max(50, min(200, int(data['image_height'])))
        
        # Log configuration change
        log_captcha_event('captcha_config_updated', None, True, {
            'updated_fields': list(data.keys())
        })
        
        return jsonify({
            'success': True,
            'message': 'Configuration updated successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Failed to update configuration'
        }), 500

@captcha_bp.route('/api/captcha/test', methods=['POST'])
@login_required
def test_captcha():
    """Test CAPTCHA functionality"""
    try:
        data = request.get_json() or {}
        
        test_type = data.get('type', 'text_image')
        difficulty = data.get('difficulty', 'medium')
        
        # Generate test challenge
        challenge = captcha_service.generate_challenge(test_type, difficulty)
        
        # For testing, also return the correct answer (admin only)
        if current_user.is_admin:
            challenge_data = captcha_service.challenges.get(challenge['challenge_id'])
            if challenge_data:
                challenge['test_answer'] = challenge_data['answer']
        
        return jsonify({
            'success': True,
            'challenge': challenge
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Test failed'
        }), 500

def get_user_captcha_history(user_id: int) -> dict:
    """Get user's CAPTCHA history for adaptive challenges"""
    try:
        # Get recent CAPTCHA events for this user
        events = AuditLog.query.filter_by(
            user_id=user_id,
            resource_type='captcha',
            action='captcha_verified'
        ).order_by(AuditLog.created_at.desc()).limit(50).all()
        
        total_attempts = len(events)
        successful_attempts = sum(1 for event in events if event.get_details().get('success'))
        
        success_rate = successful_attempts / max(total_attempts, 1)
        failed_attempts = total_attempts - successful_attempts
        
        # Analyze preferred/problematic types
        type_performance = {}
        for event in events:
            details = event.get_details()
            challenge_type = details.get('type', 'unknown')
            success = details.get('success', False)
            
            if challenge_type not in type_performance:
                type_performance[challenge_type] = {'success': 0, 'total': 0}
            
            type_performance[challenge_type]['total'] += 1
            if success:
                type_performance[challenge_type]['success'] += 1
        
        # Find types with low success rate
        problematic_types = []
        for challenge_type, performance in type_performance.items():
            if performance['total'] >= 3:  # Minimum attempts to consider
                type_success_rate = performance['success'] / performance['total']
                if type_success_rate < 0.5:
                    problematic_types.append(challenge_type)
        
        return {
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'failed_attempts': failed_attempts,
            'success_rate': success_rate,
            'preferred_types': problematic_types,  # Types to avoid
            'type_performance': type_performance
        }
        
    except Exception as e:
        print(f"Error getting user CAPTCHA history: {e}")
        return {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'success_rate': 1.0,
            'preferred_types': [],
            'type_performance': {}
        }

def update_user_captcha_history(user_id: int, success: bool):
    """Update user's CAPTCHA performance history"""
    try:
        # This could be expanded to store more detailed history
        # For now, the audit log serves as the history
        pass
    except Exception as e:
        print(f"Error updating user CAPTCHA history: {e}")

# Middleware function to check CAPTCHA for suspicious activities
def require_captcha_verification(f):
    """Decorator to require CAPTCHA verification for suspicious activities"""
    def decorated_function(*args, **kwargs):
        # Check if CAPTCHA verification is required
        captcha_token = request.headers.get('X-Captcha-Token')
        
        if not captcha_token:
            return jsonify({
                'error': 'CAPTCHA verification required',
                'captcha_required': True
            }), 429
        
        # Verify CAPTCHA token
        if not captcha_service.verify_token(captcha_token):
            return jsonify({
                'error': 'Invalid or expired CAPTCHA token',
                'captcha_required': True
            }), 429
        
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

# Function to determine if CAPTCHA is required based on suspicious activity
def is_captcha_required(ip_address: str, user_agent: str, activity_type: str) -> bool:
    """Determine if CAPTCHA is required based on suspicious activity patterns"""
    try:
        # Check recent activity from this IP
        recent_events = AuditLog.query.filter(
            AuditLog.ip_address == ip_address,
            AuditLog.created_at >= datetime.utcnow() - timedelta(hours=1)
        ).count()
        
        # Thresholds for different activities
        thresholds = {
            'login_attempt': 3,
            'registration': 2,
            'password_reset': 2,
            'email_tracking': 10,
            'api_request': 20
        }
        
        threshold = thresholds.get(activity_type, 5)
        
        # Require CAPTCHA if threshold exceeded
        if recent_events >= threshold:
            return True
        
        # Check for bot-like user agents
        bot_indicators = ['curl', 'wget', 'python', 'bot', 'crawler', 'spider']
        if any(indicator in user_agent.lower() for indicator in bot_indicators):
            return True
        
        return False
        
    except Exception as e:
        print(f"Error checking CAPTCHA requirement: {e}")
        return False

