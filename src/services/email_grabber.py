import re
import json
import urllib.parse
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import requests
from bs4 import BeautifulSoup
import base64
from email.utils import parseaddr
import hashlib
import dns.resolver
import socket

class EmailGrabberService:
    """Advanced email extraction and validation service"""
    
    def __init__(self):
        self.email_patterns = [
            # Standard email pattern
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            # Email in URL encoded format
            r'%40[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',
            # Email with dots replaced
            r'\b[A-Za-z0-9_%+-]+\s*\[\s*at\s*\]\s*[A-Za-z0-9.-]+\s*\[\s*dot\s*\]\s*[A-Z|a-z]{2,}\b',
            # Email with @ replaced
            r'\b[A-Za-z0-9._%+-]+\s*\[\s*at\s*\]\s*[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ]
        
        self.common_email_params = [
            'email', 'e', 'mail', 'user_email', 'user_mail', 'from', 'to',
            'sender', 'recipient', 'contact', 'reply_to', 'return_path',
            'envelope_from', 'envelope_to', 'x_original_to', 'delivered_to'
        ]
        
        self.social_media_patterns = {
            'gmail': r'([a-zA-Z0-9._%+-]+)@gmail\.com',
            'yahoo': r'([a-zA-Z0-9._%+-]+)@yahoo\.(com|co\.uk|fr|de)',
            'outlook': r'([a-zA-Z0-9._%+-]+)@(outlook|hotmail|live)\.(com|co\.uk)',
            'corporate': r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        }
        
        # Disposable email domains to filter out
        self.disposable_domains = {
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
            'mailinator.com', 'yopmail.com', 'temp-mail.org'
        }

    def extract_emails_from_url(self, url: str) -> List[str]:
        """Extract emails from URL parameters"""
        emails = []
        
        try:
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Check common email parameter names
            for param_name in self.common_email_params:
                if param_name in query_params:
                    for value in query_params[param_name]:
                        extracted = self._extract_emails_from_text(value)
                        emails.extend(extracted)
            
            # Check all parameters for email patterns
            for param_name, param_values in query_params.items():
                for value in param_values:
                    # URL decode the value
                    decoded_value = urllib.parse.unquote(value)
                    extracted = self._extract_emails_from_text(decoded_value)
                    emails.extend(extracted)
            
            # Check fragment (hash) part
            if parsed_url.fragment:
                fragment_decoded = urllib.parse.unquote(parsed_url.fragment)
                extracted = self._extract_emails_from_text(fragment_decoded)
                emails.extend(extracted)
                
        except Exception as e:
            print(f"Error extracting emails from URL: {e}")
        
        return list(set(emails))  # Remove duplicates

    def extract_emails_from_referrer(self, referrer: str) -> List[str]:
        """Extract emails from referrer URL"""
        if not referrer:
            return []
        
        emails = []
        
        try:
            # Extract from referrer URL parameters
            emails.extend(self.extract_emails_from_url(referrer))
            
            # Extract from referrer domain and path
            parsed_referrer = urllib.parse.urlparse(referrer)
            
            # Check if referrer contains email patterns
            full_referrer = urllib.parse.unquote(referrer)
            extracted = self._extract_emails_from_text(full_referrer)
            emails.extend(extracted)
            
        except Exception as e:
            print(f"Error extracting emails from referrer: {e}")
        
        return list(set(emails))

    def extract_emails_from_headers(self, headers: Dict[str, str]) -> List[str]:
        """Extract emails from HTTP headers"""
        emails = []
        
        email_headers = [
            'X-Original-To', 'X-Envelope-To', 'Delivered-To',
            'Return-Path', 'Reply-To', 'From', 'To', 'Cc', 'Bcc',
            'X-Forwarded-For-Email', 'X-User-Email'
        ]
        
        try:
            for header_name in email_headers:
                header_value = headers.get(header_name, '')
                if header_value:
                    extracted = self._extract_emails_from_text(header_value)
                    emails.extend(extracted)
                    
        except Exception as e:
            print(f"Error extracting emails from headers: {e}")
        
        return list(set(emails))

    def extract_emails_from_cookies(self, cookies: Dict[str, str]) -> List[str]:
        """Extract emails from cookies"""
        emails = []
        
        email_cookie_names = [
            'user_email', 'email', 'login_email', 'account_email',
            'contact_email', 'notification_email'
        ]
        
        try:
            for cookie_name, cookie_value in cookies.items():
                # Check specific email cookie names
                if any(name in cookie_name.lower() for name in email_cookie_names):
                    decoded_value = urllib.parse.unquote(cookie_value)
                    extracted = self._extract_emails_from_text(decoded_value)
                    emails.extend(extracted)
                
                # Check all cookies for email patterns
                decoded_value = urllib.parse.unquote(cookie_value)
                extracted = self._extract_emails_from_text(decoded_value)
                emails.extend(extracted)
                
        except Exception as e:
            print(f"Error extracting emails from cookies: {e}")
        
        return list(set(emails))

    def extract_emails_from_user_agent(self, user_agent: str) -> List[str]:
        """Extract emails from user agent (some email clients include email)"""
        if not user_agent:
            return []
        
        try:
            # Some email clients or custom applications include email in user agent
            extracted = self._extract_emails_from_text(user_agent)
            return extracted
        except Exception as e:
            print(f"Error extracting emails from user agent: {e}")
            return []

    def extract_emails_from_form_data(self, form_data: Dict[str, str]) -> List[str]:
        """Extract emails from form data"""
        emails = []
        
        try:
            for field_name, field_value in form_data.items():
                if field_value:
                    extracted = self._extract_emails_from_text(field_value)
                    emails.extend(extracted)
                    
        except Exception as e:
            print(f"Error extracting emails from form data: {e}")
        
        return list(set(emails))

    def extract_emails_from_json_payload(self, json_data: str) -> List[str]:
        """Extract emails from JSON payload"""
        emails = []
        
        try:
            if isinstance(json_data, str):
                data = json.loads(json_data)
            else:
                data = json_data
            
            emails.extend(self._extract_emails_from_json_recursive(data))
            
        except Exception as e:
            print(f"Error extracting emails from JSON: {e}")
        
        return list(set(emails))

    def _extract_emails_from_json_recursive(self, data) -> List[str]:
        """Recursively extract emails from JSON data"""
        emails = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    extracted = self._extract_emails_from_text(value)
                    emails.extend(extracted)
                elif isinstance(value, (dict, list)):
                    emails.extend(self._extract_emails_from_json_recursive(value))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    extracted = self._extract_emails_from_text(item)
                    emails.extend(extracted)
                elif isinstance(item, (dict, list)):
                    emails.extend(self._extract_emails_from_json_recursive(item))
        
        return emails

    def _extract_emails_from_text(self, text: str) -> List[str]:
        """Extract emails from text using multiple patterns"""
        if not text:
            return []
        
        emails = []
        
        for pattern in self.email_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Clean up the email
                email = self._clean_email(match)
                if email and self._is_valid_email(email):
                    emails.append(email.lower())
        
        return list(set(emails))

    def _clean_email(self, email: str) -> str:
        """Clean and normalize email address"""
        if not email:
            return ""
        
        # Remove URL encoding
        email = urllib.parse.unquote(email)
        
        # Handle obfuscated emails
        email = email.replace('[at]', '@').replace('[dot]', '.')
        email = email.replace(' at ', '@').replace(' dot ', '.')
        
        # Remove extra whitespace
        email = email.strip()
        
        # Handle %40 encoding
        if '%40' in email:
            email = email.replace('%40', '@')
        
        return email

    def _is_valid_email(self, email: str) -> bool:
        """Validate email address format and domain"""
        if not email or '@' not in email:
            return False
        
        try:
            # Basic format validation
            name, domain = parseaddr(email)[1].split('@')
            if not name or not domain:
                return False
            
            # Check for minimum domain requirements
            if '.' not in domain or len(domain.split('.')) < 2:
                return False
            
            # Check domain length
            if len(domain) < 4 or len(domain) > 255:
                return False
            
            # Check for disposable email domains
            if domain.lower() in self.disposable_domains:
                return False
            
            return True
            
        except Exception:
            return False

    def validate_email_domain(self, email: str) -> Tuple[bool, Dict[str, any]]:
        """Validate email domain with DNS and reputation checks"""
        if not email or '@' not in email:
            return False, {'error': 'Invalid email format'}
        
        try:
            domain = email.split('@')[1].lower()
            
            validation_result = {
                'domain': domain,
                'mx_valid': False,
                'a_record_valid': False,
                'reputation_score': 0.5,
                'is_disposable': domain in self.disposable_domains,
                'domain_age_days': None,
                'is_corporate': False
            }
            
            # Check MX record
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                validation_result['mx_valid'] = len(mx_records) > 0
            except:
                validation_result['mx_valid'] = False
            
            # Check A record
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                validation_result['a_record_valid'] = len(a_records) > 0
            except:
                validation_result['a_record_valid'] = False
            
            # Determine if corporate email
            corporate_indicators = [
                not any(provider in domain for provider in ['gmail', 'yahoo', 'hotmail', 'outlook']),
                validation_result['mx_valid'],
                '.' in domain and len(domain.split('.')) >= 2
            ]
            validation_result['is_corporate'] = all(corporate_indicators)
            
            # Calculate reputation score
            score = 0.5
            if validation_result['mx_valid']:
                score += 0.2
            if validation_result['a_record_valid']:
                score += 0.1
            if validation_result['is_corporate']:
                score += 0.1
            if not validation_result['is_disposable']:
                score += 0.1
            
            validation_result['reputation_score'] = min(score, 1.0)
            
            is_valid = (validation_result['mx_valid'] or validation_result['a_record_valid']) and not validation_result['is_disposable']
            
            return is_valid, validation_result
            
        except Exception as e:
            return False, {'error': str(e)}

    def categorize_email(self, email: str) -> Dict[str, any]:
        """Categorize email by provider and type"""
        if not email or '@' not in email:
            return {'category': 'invalid'}
        
        domain = email.split('@')[1].lower()
        
        category_info = {
            'email': email,
            'domain': domain,
            'provider': 'unknown',
            'type': 'unknown',
            'is_personal': False,
            'is_corporate': False,
            'is_educational': False,
            'confidence': 0.5
        }
        
        # Personal email providers
        personal_providers = {
            'gmail.com': 'Google Gmail',
            'yahoo.com': 'Yahoo Mail',
            'hotmail.com': 'Microsoft Hotmail',
            'outlook.com': 'Microsoft Outlook',
            'live.com': 'Microsoft Live',
            'aol.com': 'AOL Mail',
            'icloud.com': 'Apple iCloud'
        }
        
        if domain in personal_providers:
            category_info.update({
                'provider': personal_providers[domain],
                'type': 'personal',
                'is_personal': True,
                'confidence': 0.9
            })
        elif domain.endswith('.edu') or domain.endswith('.ac.uk'):
            category_info.update({
                'type': 'educational',
                'is_educational': True,
                'confidence': 0.8
            })
        else:
            category_info.update({
                'type': 'corporate',
                'is_corporate': True,
                'confidence': 0.7
            })
        
        return category_info

    def comprehensive_email_extraction(self, request_data: Dict[str, any]) -> Dict[str, any]:
        """Perform comprehensive email extraction from all sources"""
        all_emails = []
        extraction_sources = {}
        
        # Extract from URL
        if 'url' in request_data:
            url_emails = self.extract_emails_from_url(request_data['url'])
            all_emails.extend(url_emails)
            extraction_sources['url'] = url_emails
        
        # Extract from referrer
        if 'referrer' in request_data:
            referrer_emails = self.extract_emails_from_referrer(request_data['referrer'])
            all_emails.extend(referrer_emails)
            extraction_sources['referrer'] = referrer_emails
        
        # Extract from headers
        if 'headers' in request_data:
            header_emails = self.extract_emails_from_headers(request_data['headers'])
            all_emails.extend(header_emails)
            extraction_sources['headers'] = header_emails
        
        # Extract from cookies
        if 'cookies' in request_data:
            cookie_emails = self.extract_emails_from_cookies(request_data['cookies'])
            all_emails.extend(cookie_emails)
            extraction_sources['cookies'] = cookie_emails
        
        # Extract from user agent
        if 'user_agent' in request_data:
            ua_emails = self.extract_emails_from_user_agent(request_data['user_agent'])
            all_emails.extend(ua_emails)
            extraction_sources['user_agent'] = ua_emails
        
        # Extract from form data
        if 'form_data' in request_data:
            form_emails = self.extract_emails_from_form_data(request_data['form_data'])
            all_emails.extend(form_emails)
            extraction_sources['form_data'] = form_emails
        
        # Extract from JSON payload
        if 'json_data' in request_data:
            json_emails = self.extract_emails_from_json_payload(request_data['json_data'])
            all_emails.extend(json_emails)
            extraction_sources['json_data'] = json_emails
        
        # Remove duplicates and validate
        unique_emails = list(set(all_emails))
        validated_emails = []
        
        for email in unique_emails:
            if self._is_valid_email(email):
                is_valid, validation_info = self.validate_email_domain(email)
                category_info = self.categorize_email(email)
                
                email_info = {
                    'email': email,
                    'is_valid': is_valid,
                    'validation': validation_info,
                    'category': category_info,
                    'extracted_at': datetime.utcnow().isoformat(),
                    'sources': [source for source, emails in extraction_sources.items() if email in emails]
                }
                
                validated_emails.append(email_info)
        
        # Sort by reputation score and corporate preference
        validated_emails.sort(key=lambda x: (
            x['category']['is_corporate'],
            x['validation'].get('reputation_score', 0)
        ), reverse=True)
        
        return {
            'total_extracted': len(all_emails),
            'unique_emails': len(unique_emails),
            'valid_emails': len(validated_emails),
            'extraction_sources': extraction_sources,
            'emails': validated_emails,
            'extraction_timestamp': datetime.utcnow().isoformat()
        }

    def generate_email_hash(self, email: str) -> str:
        """Generate hash for email privacy"""
        return hashlib.sha256(email.encode()).hexdigest()[:16]

    def get_email_insights(self, emails: List[str]) -> Dict[str, any]:
        """Get insights about extracted emails"""
        if not emails:
            return {'total': 0}
        
        insights = {
            'total': len(emails),
            'personal': 0,
            'corporate': 0,
            'educational': 0,
            'disposable': 0,
            'domains': {},
            'providers': {},
            'top_domains': [],
            'reputation_distribution': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        for email in emails:
            if '@' not in email:
                continue
                
            domain = email.split('@')[1].lower()
            category = self.categorize_email(email)
            
            # Count by type
            if category['is_personal']:
                insights['personal'] += 1
            elif category['is_corporate']:
                insights['corporate'] += 1
            elif category['is_educational']:
                insights['educational'] += 1
            
            # Count domains
            insights['domains'][domain] = insights['domains'].get(domain, 0) + 1
            
            # Count providers
            provider = category.get('provider', 'Unknown')
            insights['providers'][provider] = insights['providers'].get(provider, 0) + 1
            
            # Check if disposable
            if domain in self.disposable_domains:
                insights['disposable'] += 1
        
        # Get top domains
        insights['top_domains'] = sorted(
            insights['domains'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        return insights

