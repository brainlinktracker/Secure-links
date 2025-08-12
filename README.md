# 7th Brain Link Tracker - Advanced Analytics System

A comprehensive link tracking system with advanced cybersecurity features and real-time analytics dashboard.

## 🚀 Features

### Advanced Security Features
- **Social Referrer Firewall**: Blocks preview bots from Facebook, Twitter, LinkedIn, Slack, and security scanners
- **Advanced Bot Detection**: AI-like pattern recognition for detecting curl, axios, Python requests, and automated tools
- **IP Reputation System**: Comprehensive IP scoring with geolocation and threat detection
- **Rate-Limited IP Control**: Dynamic rate limiting based on IP reputation
- **MX-Verified Emails**: Email domain validation with MX record verification
- **Dynamic Signature Cloaking**: Rotating salts and hashed signatures for enhanced security
- **Geo-Aware Targeting**: Blocks high-risk countries and VPN/proxy services
- **Real-Time Tracking**: Live monitoring of email opens, clicks, and security events

### Analytics Dashboard
- **Real-Time Analytics**: Live activity feed with security incident monitoring
- **Geographic Distribution**: Country-wise traffic breakdown with visual progress bars
- **Device Analytics**: Device type breakdown with interactive charts
- **Hourly Activity**: 24-hour activity tracking with area charts
- **Security Events**: Comprehensive security monitoring and threat analysis
- **Conversion Tracking**: Email open rates and click-through analytics

## 🛠 Installation

### Prerequisites
- Python 3.8+
- Node.js 16+ (for development)

### Quick Start

1. **Clone and Setup**
   ```bash
   cd 7th Brain-link-tracker-backend
   source venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Run the Application**
   ```bash
   python src/main.py
   ```

3. **Access the Dashboard**
   - Open http://localhost:5000 in your browser
   - The analytics dashboard will load automatically

## 📊 Usage

### Creating Tracking Links

1. **Pixel Tracking (Email Opens)**
   ```html
   <img src="http://localhost:5000/track/pixel/YOUR_TOKEN" width="1" height="1" style="display:none;" />
   ```

2. **Click Tracking**
   ```html
   <a href="http://localhost:5000/track/click/YOUR_TOKEN">Your Link Text</a>
   ```

### API Endpoints

- `GET /track/pixel/<token>` - Email open tracking (returns 1x1 PNG)
- `GET /track/click/<token>` - Link click tracking (redirects to original URL)
- `GET /api/analytics` - Get comprehensive analytics data
- `GET /health` - Health check endpoint

### Sample Tracking Token
Use `test123token456` for testing (pre-configured in the database).

## 🔒 Security Features in Detail

### Social Referrer Firewall
Automatically blocks requests from:
- Facebook (facebookexternalhit, facebookcrawler)
- Twitter (twitterbot, twittercardgenerator) 
- LinkedIn (linkedinbot, linkedin-linkpreview)
- Slack (slackbot, slack-linkexpanding)
- Security scanners (VirusTotal, URLVoid, Hybrid Analysis)

### Advanced Bot Detection
Detects and blocks:
- Command-line tools (curl, wget, httpie)
- Programming libraries (python-requests, axios)
- Automated browsers (Selenium, PhantomJS)
- Security scanners and crawlers
- Missing or suspicious HTTP headers

### IP Reputation System
- Real-time geolocation lookup
- VPN/Proxy detection
- Country-based risk assessment
- Historical behavior tracking
- Automatic blacklisting of suspicious IPs

### Rate Limiting
- Per-IP rate limiting with configurable thresholds
- Dynamic limits based on IP reputation
- Automatic blocking of rapid-fire requests
- Whitelist support for trusted IPs

## 📈 Analytics Dashboard

The dashboard provides:

1. **Overview Cards**
   - Total clicks and email opens
   - Unique visitors and conversion rates
   - Blocked requests and risk scores

2. **Interactive Charts**
   - Hourly activity with stacked area charts
   - Geographic distribution with progress bars
   - Device type breakdown with pie charts

3. **Security Monitoring**
   - Real-time security event feed
   - Bot detection statistics
   - Blocked request analysis

4. **Live Activity Feed**
   - Real-time event streaming
   - Geographic and device information
   - Security incident alerts

## 🚀 Deployment

### Local Development
```bash
python src/main.py
```

### Production Deployment
1. Set environment variables for production database
2. Configure reverse proxy (nginx/Apache)
3. Use WSGI server (Gunicorn, uWSGI)
4. Enable HTTPS for secure tracking

### Environment Variables
- `DATABASE_URL`: Production database connection string
- `SECRET_KEY`: Application secret key
- `FLASK_ENV`: Set to 'production' for production deployment

## 🔧 Configuration

Edit `src/main.py` to customize:
- Security thresholds and rules
- Rate limiting parameters
- Blocked referrer lists
- Bot detection patterns
- Database configuration

## 📝 Database Schema

The system uses SQLite by default with these tables:
- `campaigns`: Campaign management
- `tracking_links`: Link and token storage
- `tracking_events`: All tracking events and analytics
- `ip_reputation`: IP reputation and security data

## 🛡 Security Best Practices

1. **Use HTTPS** in production for secure tracking
2. **Rotate tokens** regularly for enhanced security
3. **Monitor logs** for suspicious activity
4. **Configure firewalls** to block known bad actors
5. **Regular updates** to maintain security effectiveness

## 📞 Support

For technical support or feature requests, please refer to the documentation or contact the development team.

## 🔄 Version History

- **v1.0.0**: Initial release with full security and analytics features
- Advanced bot detection and social referrer firewall
- Real-time analytics dashboard with interactive charts
- Comprehensive IP reputation system
- Geographic and device tracking capabilities

---

**7th Brain Link Tracker** - Advanced email and link tracking with enterprise-grade security features.

