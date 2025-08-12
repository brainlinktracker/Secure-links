import random
import string
import hashlib
import hmac
import time
import json
import base64
import io
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import math
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import secrets

class CaptchaService:
    """Advanced CAPTCHA service with multiple challenge types"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.challenges = {}
        self.cleanup_interval = 3600  # 1 hour
        self.last_cleanup = time.time()
        
        # CAPTCHA settings
        self.image_width = 200
        self.image_height = 80
        self.font_size = 36
        self.noise_level = 0.3
        self.distortion_level = 0.2
        
        # Challenge types
        self.challenge_types = [
            'text_image',
            'math_problem',
            'pattern_recognition',
            'slider_puzzle',
            'audio_challenge'
        ]
        
        # Difficulty levels
        self.difficulty_levels = {
            'easy': {'length': 4, 'complexity': 1},
            'medium': {'length': 5, 'complexity': 2},
            'hard': {'length': 6, 'complexity': 3}
        }

    def generate_challenge_id(self) -> str:
        """Generate unique challenge ID"""
        return secrets.token_urlsafe(32)

    def create_text_captcha(self, difficulty: str = 'medium') -> Dict[str, any]:
        """Create text-based image CAPTCHA"""
        config = self.difficulty_levels[difficulty]
        
        # Generate random text
        if config['complexity'] == 1:
            # Easy: only uppercase letters
            chars = string.ascii_uppercase
        elif config['complexity'] == 2:
            # Medium: letters and numbers
            chars = string.ascii_uppercase + string.digits
        else:
            # Hard: mixed case, numbers, and some symbols
            chars = string.ascii_letters + string.digits
        
        text = ''.join(random.choices(chars, k=config['length']))
        
        # Create image
        image = Image.new('RGB', (self.image_width, self.image_height), 'white')
        draw = ImageDraw.Draw(image)
        
        # Add background noise
        self._add_noise(draw, config['complexity'])
        
        # Draw text with distortion
        self._draw_distorted_text(draw, text, config['complexity'])
        
        # Apply filters
        if config['complexity'] > 1:
            image = image.filter(ImageFilter.GaussianBlur(radius=0.5))
        
        # Convert to base64
        buffer = io.BytesIO()
        image.save(buffer, format='PNG')
        image_data = base64.b64encode(buffer.getvalue()).decode()
        
        challenge_id = self.generate_challenge_id()
        
        # Store challenge
        self.challenges[challenge_id] = {
            'type': 'text_image',
            'answer': text.lower(),
            'created_at': time.time(),
            'attempts': 0,
            'max_attempts': 3,
            'difficulty': difficulty
        }
        
        return {
            'challenge_id': challenge_id,
            'type': 'text_image',
            'image': f"data:image/png;base64,{image_data}",
            'instructions': 'Enter the text shown in the image',
            'difficulty': difficulty
        }

    def create_math_captcha(self, difficulty: str = 'medium') -> Dict[str, any]:
        """Create mathematical problem CAPTCHA"""
        config = self.difficulty_levels[difficulty]
        
        if config['complexity'] == 1:
            # Easy: simple addition
            a = random.randint(1, 10)
            b = random.randint(1, 10)
            question = f"{a} + {b}"
            answer = str(a + b)
        elif config['complexity'] == 2:
            # Medium: addition, subtraction, multiplication
            operations = ['+', '-', '*']
            op = random.choice(operations)
            
            if op == '+':
                a = random.randint(1, 20)
                b = random.randint(1, 20)
                answer = str(a + b)
            elif op == '-':
                a = random.randint(10, 30)
                b = random.randint(1, a)
                answer = str(a - b)
            else:  # multiplication
                a = random.randint(2, 9)
                b = random.randint(2, 9)
                answer = str(a * b)
            
            question = f"{a} {op} {b}"
        else:
            # Hard: complex operations
            operations = ['+', '-', '*', '/']
            op = random.choice(operations)
            
            if op == '/':
                # Ensure clean division
                b = random.randint(2, 9)
                answer_val = random.randint(2, 15)
                a = b * answer_val
                answer = str(answer_val)
                question = f"{a} {op} {b}"
            else:
                a = random.randint(5, 50)
                b = random.randint(5, 50)
                if op == '+':
                    answer = str(a + b)
                elif op == '-':
                    if a < b:
                        a, b = b, a
                    answer = str(a - b)
                else:  # multiplication
                    a = random.randint(2, 12)
                    b = random.randint(2, 12)
                    answer = str(a * b)
                question = f"{a} {op} {b}"
        
        challenge_id = self.generate_challenge_id()
        
        # Store challenge
        self.challenges[challenge_id] = {
            'type': 'math_problem',
            'answer': answer,
            'created_at': time.time(),
            'attempts': 0,
            'max_attempts': 3,
            'difficulty': difficulty
        }
        
        return {
            'challenge_id': challenge_id,
            'type': 'math_problem',
            'question': question,
            'instructions': 'Solve the mathematical problem',
            'difficulty': difficulty
        }

    def create_pattern_captcha(self, difficulty: str = 'medium') -> Dict[str, any]:
        """Create pattern recognition CAPTCHA"""
        config = self.difficulty_levels[difficulty]
        
        # Generate pattern sequence
        if config['complexity'] == 1:
            # Simple number sequence
            start = random.randint(1, 10)
            step = random.randint(1, 3)
            sequence = [start + i * step for i in range(4)]
            answer = str(start + 4 * step)
            question = f"What comes next? {', '.join(map(str, sequence))}, ?"
        elif config['complexity'] == 2:
            # Alternating pattern or geometric sequence
            if random.choice([True, False]):
                # Alternating pattern
                a, b = random.randint(1, 9), random.randint(1, 9)
                sequence = [a, b, a, b, a]
                answer = str(b)
                question = f"What comes next? {', '.join(map(str, sequence))}, ?"
            else:
                # Geometric sequence
                start = random.randint(2, 5)
                ratio = random.randint(2, 3)
                sequence = [start * (ratio ** i) for i in range(3)]
                answer = str(start * (ratio ** 3))
                question = f"What comes next? {', '.join(map(str, sequence))}, ?"
        else:
            # Complex patterns
            pattern_type = random.choice(['fibonacci', 'prime', 'square'])
            
            if pattern_type == 'fibonacci':
                sequence = [1, 1, 2, 3, 5]
                answer = "8"
                question = f"What comes next in the Fibonacci sequence? {', '.join(map(str, sequence))}, ?"
            elif pattern_type == 'prime':
                primes = [2, 3, 5, 7, 11]
                answer = "13"
                question = f"What comes next in the prime sequence? {', '.join(map(str, primes))}, ?"
            else:  # squares
                squares = [1, 4, 9, 16]
                answer = "25"
                question = f"What comes next? {', '.join(map(str, squares))}, ?"
        
        challenge_id = self.generate_challenge_id()
        
        # Store challenge
        self.challenges[challenge_id] = {
            'type': 'pattern_recognition',
            'answer': answer,
            'created_at': time.time(),
            'attempts': 0,
            'max_attempts': 3,
            'difficulty': difficulty
        }
        
        return {
            'challenge_id': challenge_id,
            'type': 'pattern_recognition',
            'question': question,
            'instructions': 'Complete the pattern',
            'difficulty': difficulty
        }

    def create_slider_captcha(self, difficulty: str = 'medium') -> Dict[str, any]:
        """Create slider puzzle CAPTCHA"""
        config = self.difficulty_levels[difficulty]
        
        # Create base image with puzzle piece
        image = Image.new('RGB', (300, 150), 'lightblue')
        draw = ImageDraw.Draw(image)
        
        # Draw background pattern
        for i in range(0, 300, 20):
            for j in range(0, 150, 20):
                color = (random.randint(200, 255), random.randint(200, 255), random.randint(200, 255))
                draw.rectangle([i, j, i+20, j+20], fill=color)
        
        # Create puzzle piece position
        piece_x = random.randint(50, 200)
        piece_y = random.randint(20, 100)
        piece_size = 30
        
        # Draw puzzle piece cutout
        draw.rectangle([piece_x, piece_y, piece_x + piece_size, piece_y + piece_size], 
                      fill='white', outline='black', width=2)
        
        # Create slider track
        track_y = 120
        draw.rectangle([20, track_y, 280, track_y + 20], fill='gray', outline='black')
        
        # Convert to base64
        buffer = io.BytesIO()
        image.save(buffer, format='PNG')
        image_data = base64.b64encode(buffer.getvalue()).decode()
        
        challenge_id = self.generate_challenge_id()
        
        # Store challenge (answer is the x-position of the puzzle piece)
        tolerance = 10 if config['complexity'] == 1 else 5
        self.challenges[challenge_id] = {
            'type': 'slider_puzzle',
            'answer': piece_x,
            'tolerance': tolerance,
            'created_at': time.time(),
            'attempts': 0,
            'max_attempts': 5,
            'difficulty': difficulty
        }
        
        return {
            'challenge_id': challenge_id,
            'type': 'slider_puzzle',
            'image': f"data:image/png;base64,{image_data}",
            'instructions': 'Drag the slider to align with the puzzle piece',
            'difficulty': difficulty
        }

    def create_audio_captcha(self, difficulty: str = 'medium') -> Dict[str, any]:
        """Create audio CAPTCHA (placeholder - would need audio generation)"""
        config = self.difficulty_levels[difficulty]
        
        # Generate sequence of numbers/letters
        if config['complexity'] == 1:
            chars = string.digits
        elif config['complexity'] == 2:
            chars = string.digits + 'ABCDEF'
        else:
            chars = string.digits + string.ascii_uppercase[:10]
        
        sequence = ''.join(random.choices(chars, k=config['length']))
        
        challenge_id = self.generate_challenge_id()
        
        # Store challenge
        self.challenges[challenge_id] = {
            'type': 'audio_challenge',
            'answer': sequence.lower(),
            'created_at': time.time(),
            'attempts': 0,
            'max_attempts': 3,
            'difficulty': difficulty
        }
        
        return {
            'challenge_id': challenge_id,
            'type': 'audio_challenge',
            'audio_url': f'/api/captcha/audio/{challenge_id}',  # Placeholder
            'instructions': 'Enter the sequence you hear',
            'difficulty': difficulty,
            'note': 'Audio CAPTCHA requires audio generation implementation'
        }

    def _add_noise(self, draw: ImageDraw.Draw, complexity: int):
        """Add noise to CAPTCHA image"""
        noise_points = int(self.image_width * self.image_height * self.noise_level * complexity)
        
        for _ in range(noise_points):
            x = random.randint(0, self.image_width - 1)
            y = random.randint(0, self.image_height - 1)
            color = (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
            draw.point((x, y), fill=color)
        
        # Add noise lines
        for _ in range(complexity * 2):
            x1, y1 = random.randint(0, self.image_width), random.randint(0, self.image_height)
            x2, y2 = random.randint(0, self.image_width), random.randint(0, self.image_height)
            color = (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))
            draw.line([(x1, y1), (x2, y2)], fill=color, width=1)

    def _draw_distorted_text(self, draw: ImageDraw.Draw, text: str, complexity: int):
        """Draw text with distortion effects"""
        try:
            # Try to use a system font, fallback to default
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", self.font_size)
        except:
            font = ImageFont.load_default()
        
        # Calculate text positioning
        char_width = self.image_width // len(text)
        
        for i, char in enumerate(text):
            # Random position variation
            x = i * char_width + random.randint(-5, 5)
            y = random.randint(10, 30)
            
            # Random rotation (for complexity > 1)
            if complexity > 1:
                # Create temporary image for rotation
                temp_img = Image.new('RGBA', (50, 50), (255, 255, 255, 0))
                temp_draw = ImageDraw.Draw(temp_img)
                temp_draw.text((10, 10), char, fill='black', font=font)
                
                # Rotate
                angle = random.randint(-30, 30)
                rotated = temp_img.rotate(angle, expand=True)
                
                # Paste back
                draw._image.paste(rotated, (x, y), rotated)
            else:
                # Simple text drawing
                color = (random.randint(0, 100), random.randint(0, 100), random.randint(0, 100))
                draw.text((x, y), char, fill=color, font=font)

    def generate_challenge(self, challenge_type: str = None, difficulty: str = 'medium') -> Dict[str, any]:
        """Generate a CAPTCHA challenge"""
        self._cleanup_expired_challenges()
        
        if not challenge_type:
            challenge_type = random.choice(self.challenge_types)
        
        if challenge_type == 'text_image':
            return self.create_text_captcha(difficulty)
        elif challenge_type == 'math_problem':
            return self.create_math_captcha(difficulty)
        elif challenge_type == 'pattern_recognition':
            return self.create_pattern_captcha(difficulty)
        elif challenge_type == 'slider_puzzle':
            return self.create_slider_captcha(difficulty)
        elif challenge_type == 'audio_challenge':
            return self.create_audio_captcha(difficulty)
        else:
            # Default to text image
            return self.create_text_captcha(difficulty)

    def verify_challenge(self, challenge_id: str, user_answer: str, 
                        additional_data: Dict[str, any] = None) -> Dict[str, any]:
        """Verify CAPTCHA challenge answer"""
        if challenge_id not in self.challenges:
            return {
                'success': False,
                'error': 'Invalid or expired challenge',
                'error_code': 'INVALID_CHALLENGE'
            }
        
        challenge = self.challenges[challenge_id]
        
        # Check if challenge is expired (5 minutes)
        if time.time() - challenge['created_at'] > 300:
            del self.challenges[challenge_id]
            return {
                'success': False,
                'error': 'Challenge expired',
                'error_code': 'EXPIRED_CHALLENGE'
            }
        
        # Check attempt limit
        challenge['attempts'] += 1
        if challenge['attempts'] > challenge['max_attempts']:
            del self.challenges[challenge_id]
            return {
                'success': False,
                'error': 'Too many attempts',
                'error_code': 'TOO_MANY_ATTEMPTS'
            }
        
        # Verify answer based on challenge type
        is_correct = False
        
        if challenge['type'] == 'slider_puzzle':
            # For slider puzzle, check if position is within tolerance
            try:
                user_position = int(user_answer)
                correct_position = challenge['answer']
                tolerance = challenge.get('tolerance', 5)
                is_correct = abs(user_position - correct_position) <= tolerance
            except ValueError:
                is_correct = False
        else:
            # For other types, exact match (case-insensitive)
            is_correct = user_answer.lower().strip() == challenge['answer'].lower().strip()
        
        if is_correct:
            # Generate verification token
            verification_token = self._generate_verification_token(challenge_id)
            del self.challenges[challenge_id]
            
            return {
                'success': True,
                'verification_token': verification_token,
                'message': 'Challenge completed successfully'
            }
        else:
            remaining_attempts = challenge['max_attempts'] - challenge['attempts']
            return {
                'success': False,
                'error': 'Incorrect answer',
                'error_code': 'INCORRECT_ANSWER',
                'remaining_attempts': remaining_attempts
            }

    def _generate_verification_token(self, challenge_id: str) -> str:
        """Generate verification token for successful CAPTCHA"""
        timestamp = str(int(time.time()))
        data = f"{challenge_id}:{timestamp}"
        signature = hmac.new(
            self.secret_key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        token_data = {
            'challenge_id': challenge_id,
            'timestamp': timestamp,
            'signature': signature
        }
        
        return base64.b64encode(json.dumps(token_data).encode()).decode()

    def verify_token(self, token: str, max_age: int = 3600) -> bool:
        """Verify CAPTCHA completion token"""
        try:
            token_data = json.loads(base64.b64decode(token).decode())
            challenge_id = token_data['challenge_id']
            timestamp = token_data['timestamp']
            signature = token_data['signature']
            
            # Check token age
            if int(time.time()) - int(timestamp) > max_age:
                return False
            
            # Verify signature
            data = f"{challenge_id}:{timestamp}"
            expected_signature = hmac.new(
                self.secret_key.encode(),
                data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception:
            return False

    def _cleanup_expired_challenges(self):
        """Clean up expired challenges"""
        current_time = time.time()
        
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        expired_challenges = [
            challenge_id for challenge_id, challenge in self.challenges.items()
            if current_time - challenge['created_at'] > 300  # 5 minutes
        ]
        
        for challenge_id in expired_challenges:
            del self.challenges[challenge_id]
        
        self.last_cleanup = current_time

    def get_challenge_stats(self) -> Dict[str, any]:
        """Get CAPTCHA service statistics"""
        active_challenges = len(self.challenges)
        
        type_counts = {}
        difficulty_counts = {}
        
        for challenge in self.challenges.values():
            challenge_type = challenge['type']
            difficulty = challenge['difficulty']
            
            type_counts[challenge_type] = type_counts.get(challenge_type, 0) + 1
            difficulty_counts[difficulty] = difficulty_counts.get(difficulty, 0) + 1
        
        return {
            'active_challenges': active_challenges,
            'type_distribution': type_counts,
            'difficulty_distribution': difficulty_counts,
            'last_cleanup': self.last_cleanup
        }

    def create_adaptive_challenge(self, user_history: Dict[str, any]) -> Dict[str, any]:
        """Create adaptive CAPTCHA based on user history"""
        # Analyze user's previous performance
        failed_attempts = user_history.get('failed_attempts', 0)
        success_rate = user_history.get('success_rate', 1.0)
        preferred_types = user_history.get('preferred_types', [])
        
        # Determine difficulty
        if failed_attempts > 3 or success_rate < 0.5:
            difficulty = 'easy'
        elif success_rate > 0.9 and failed_attempts == 0:
            difficulty = 'hard'
        else:
            difficulty = 'medium'
        
        # Choose challenge type
        if preferred_types:
            # Avoid types user struggles with
            available_types = [t for t in self.challenge_types if t not in preferred_types]
            challenge_type = random.choice(available_types) if available_types else random.choice(self.challenge_types)
        else:
            challenge_type = random.choice(self.challenge_types)
        
        return self.generate_challenge(challenge_type, difficulty)

