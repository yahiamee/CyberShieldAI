from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
import requests
import json
import os
import re
import logging
from urllib.parse import urlparse
from database import (init_db, add_scan_result, get_scan_results, create_user, 
                       get_user_by_username, get_user_by_id, verify_password, get_all_users,
                       get_setting, update_setting, get_all_settings)
from models.report_generator import generate_pdf_report
from zap_scanner import create_zap_scanner
from zap_manager import init_zap
from openai_analyzer import create_openai_analyzer
from translations import get_translation, get_current_language
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'cybershield-secret-key-change-in-production-please-use-env-variable')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Initialize the database
init_db()

# Initialize ZAP (start in background if enabled)
zap_manager = init_zap()

# Context processor to make language and translations available to all templates
@app.context_processor
def inject_language():
    lang = get_current_language()
    return dict(lang=lang, t=lambda k: get_translation(k, lang))

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, is_admin):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_id(int(user_id))
    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[4])
    return None

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need administrator privileges to access this page.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def clean_url(url):
    """Clean and validate URL input with security checks"""
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string")
    
    # Remove any trailing whitespace characters including tabs and newlines
    url = url.strip()
    
    # Remove any invisible unicode characters
    url = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff\u00a0\u0009\u000a\u000d]+', '', url)
    
    # Length check
    if len(url) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters)")
    
    # Ensure URL has proper protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Validate URL format
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        # Security: Block localhost and private IPs (optional - can be configured)
        blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        if parsed.hostname in blocked_hosts:
            raise ValueError("Scanning localhost is not allowed for security reasons")
        
        # Block file:// and other dangerous protocols
        if parsed.scheme not in ['http', 'https']:
            raise ValueError("Only HTTP and HTTPS protocols are allowed")
            
    except Exception as e:
        raise ValueError(f"Invalid URL format: {str(e)}")
    
    return url

def validate_input(text, max_length=500, field_name="Input"):
    """Validate and sanitize user input"""
    if not text or not isinstance(text, str):
        return None
    
    text = text.strip()
    
    if len(text) > max_length:
        raise ValueError(f"{field_name} is too long (maximum {max_length} characters)")
    
    # Remove potentially dangerous characters
    text = re.sub(r'[<>"\']', '', text)
    
    return text

@app.route('/set_language/<lang>')
def set_language(lang):
    """Set language preference"""
    if lang in ['en', 'ar']:
        session['language'] = lang
    return redirect(request.referrer or url_for('home'))

@app.route('/')
def home():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with enhanced validation"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            # Enhanced Validation
            if not username or not email or not password:
                flash('All fields are required.', 'danger')
                return render_template('register.html')
            
            # Validate username
            if len(username) < 3 or len(username) > 30:
                flash('Username must be between 3 and 30 characters.', 'danger')
                return render_template('register.html')
            
            if not re.match(r'^[a-zA-Z0-9_]+$', username):
                flash('Username can only contain letters, numbers, and underscores.', 'danger')
                return render_template('register.html')
            
            # Validate email
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                flash('Please enter a valid email address.', 'danger')
                return render_template('register.html')
            
            if len(email) > 100:
                flash('Email address is too long.', 'danger')
                return render_template('register.html')
            
            # Validate password
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('register.html')
            
            if len(password) < 6:
                flash('Password must be at least 6 characters long.', 'danger')
                return render_template('register.html')
            
            if len(password) > 128:
                flash('Password is too long (maximum 128 characters).', 'danger')
                return render_template('register.html')
            
            # Create user
            user_id = create_user(username, email, password)
            if user_id:
                flash('Registration successful! Please log in.', 'success')
                logger.info(f"New user registered: {username}")
                return redirect(url_for('login'))
            else:
                flash('Username or email already exists.', 'danger')
                return render_template('register.html')
                
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'danger')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with enhanced security"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            # Basic validation
            if not username or not password:
                flash('Please enter both username and password.', 'danger')
                return render_template('login.html')
            
            # Rate limiting check (simple implementation)
            if 'login_attempts' not in session:
                session['login_attempts'] = 0
                session['last_attempt'] = time.time()
            
            # Reset attempts after 5 minutes
            if time.time() - session.get('last_attempt', 0) > 300:
                session['login_attempts'] = 0
            
            # Check for too many attempts
            if session.get('login_attempts', 0) >= 5:
                flash('Too many login attempts. Please try again later.', 'danger')
                return render_template('login.html')
            
            user_data = verify_password(username, password)
            if user_data:
                user = User(user_data[0], user_data[1], user_data[2], user_data[4])
                login_user(user)
                session['login_attempts'] = 0
                flash(f'Welcome back, {user.username}!', 'success')
                logger.info(f"User logged in: {username}")
                
                # Redirect to admin dashboard if user is admin
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('dashboard'))
            else:
                session['login_attempts'] = session.get('login_attempts', 0) + 1
                session['last_attempt'] = time.time()
                flash('Invalid username or password.', 'danger')
                logger.warning(f"Failed login attempt for: {username}")
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login. Please try again.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    """Scan page for entering URL and performing scan with enhanced error handling"""
    if request.method == 'POST':
        try:
            url = request.form.get('url', '').strip()
            scan_type = request.form.get('scan_type', 'basic')  # 'basic' or 'advanced' (ZAP)
            
            # Validate scan_type
            if scan_type not in ['basic', 'advanced']:
                scan_type = 'basic'
            
            # Validate URL input
            if not url:
                return render_template('scan.html', error="Please enter a URL to scan.")
            
            # Clean and validate URL
            try:
                url = clean_url(url)
            except ValueError as e:
                return render_template('scan.html', error=f"Invalid URL: {str(e)}")
            except Exception as e:
                logger.error(f"URL validation error: {str(e)}")
                return render_template('scan.html', error="An error occurred while validating the URL.")
        
        except Exception as e:
            logger.error(f"Scan request error: {str(e)}")
            return render_template('scan.html', error="An error occurred. Please try again.")
        
        try:
            # Record start time for response time calculation
            start_time = time.time()
            
            # Perform basic HTTP scan with enhanced error handling
            try:
                response = requests.get(
                    url, 
                    timeout=15,  # Increased timeout
                    headers={
                        'User-Agent': 'CyberShield-Security-Scanner/1.0',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    },
                    allow_redirects=True,
                    verify=True  # SSL verification
                )
            except requests.exceptions.SSLError:
                # Try without SSL verification if SSL error occurs
                try:
                    response = requests.get(
                        url, 
                        timeout=15,
                        headers={
                            'User-Agent': 'CyberShield-Security-Scanner/1.0',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                        },
                        allow_redirects=True,
                        verify=False
                    )
                except Exception as e:
                    raise requests.exceptions.RequestException(f"SSL Error: {str(e)}")
            
            # Calculate response time
            response_time = time.time() - start_time
            
            # Count headers
            header_count = len(response.headers)
            
            # Check for security headers
            security_headers = [
                'content-security-policy',
                'x-frame-options',
                'x-content-type-options',
                'strict-transport-security',
                'x-xss-protection'
            ]
            
            has_security_headers = any(header.lower() in [h.lower() for h in response.headers.keys()] 
                                     for header in security_headers)
            
            # Initialize ZAP results
            zap_results = None
            zap_available = False
            
            # Perform advanced ZAP scan if requested
            if scan_type == 'advanced':
                try:
                    # Get ZAP configuration from database settings
                    zap_proxy_url = get_setting('zap_proxy_url', 'http://127.0.0.1:8080')
                    zap_api_key = get_setting('zap_api_key', None)
                    if zap_api_key == '':
                        zap_api_key = None
                    
                    zap_scanner = create_zap_scanner(zap_proxy_url, zap_api_key)
                    
                    if zap_scanner and zap_scanner.is_zap_running():
                        zap_available = True
                        flash('Starting advanced ZAP scan. This may take a few minutes...', 'info')
                        
                        # Perform passive scan (faster and less intrusive)
                        zap_results = zap_scanner.passive_scan_only(url)
                        
                        if 'error' in zap_results:
                            flash(f'ZAP scan warning: {zap_results["error"]}', 'warning')
                        else:
                            flash('ZAP scan completed successfully!', 'success')
                    else:
                        flash('ZAP is not available. Performing basic scan only. Please ensure ZAP proxy is running.', 'warning')
                except Exception as zap_error:
                    flash(f'ZAP scan error: {str(zap_error)}. Continuing with basic scan.', 'warning')
            
            # Save to database with user_id and ZAP results
            try:
                scan_id = add_scan_result(
                    url=url,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    user_id=current_user.id,
                    zap_results=zap_results
                )
                if not scan_id:
                    raise Exception("Failed to save scan result to database")
            except Exception as db_error:
                logger.error(f"Database error: {str(db_error)}")
                return render_template('scan.html', error="Failed to save scan results. Please try again.")
            
            # Real analysis data based on actual scan results
            analysis_data = {
                'response_time': round(response_time, 3),
                'header_count': header_count,
                'has_security_headers': has_security_headers,
                'scan_type': scan_type,
                'zap_available': zap_available
            }
            
            # Add ZAP summary to analysis if available
            if zap_results and 'summary' in zap_results:
                analysis_data['zap_summary'] = zap_results['summary']
                analysis_data['zap_alerts'] = zap_results.get('alerts', [])
            
            # AI Analysis using OpenAI (if enabled)
            ai_analysis_result = None
            openai_enabled = get_setting('openai_enabled', 'false') == 'true'
            if openai_enabled:
                try:
                    openai_api_key = get_setting('openai_api_key', '')
                    openai_model = get_setting('openai_model', 'gpt-4')
                    openai_temperature = float(get_setting('openai_temperature', '0.7'))
                    
                    if openai_api_key:
                        analyzer = create_openai_analyzer(
                            api_key=openai_api_key,
                            model=openai_model,
                            temperature=openai_temperature
                        )
                        
                        if analyzer and analyzer.is_available:
                            scan_data_dict = {
                                'url': url,
                                'status_code': response.status_code,
                                'scan_date': time.strftime('%Y-%m-%d %H:%M:%S')
                            }
                            ai_analysis_result = analyzer.analyze_scan_results(
                                scan_data=scan_data_dict,
                                headers=dict(response.headers),
                                zap_results=zap_results
                            )
                            if 'error' in ai_analysis_result:
                                logger.warning(f"OpenAI analysis error: {ai_analysis_result['error']}")
                                ai_analysis_result = None
                except Exception as ai_error:
                    logger.error(f"OpenAI analysis failed: {str(ai_error)}")
                    ai_analysis_result = None
            
            # Return results page with real analysis
            return render_template('results.html', 
                                url=url,
                                status_code=response.status_code,
                                headers=dict(response.headers),
                                scan_id=scan_id,
                                analysis=analysis_data,
                                zap_results=zap_results,
                                ai_analysis=ai_analysis_result)
                                
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            # Clean up error message for better user experience
            if "NameResolutionError" in error_msg:
                error_msg = "Could not resolve the domain name. Please check if the URL is correct and the website is accessible."
            elif "Max retries exceeded" in error_msg:
                error_msg = "Connection failed. The website might be down or blocking our requests."
            elif "timeout" in error_msg.lower():
                error_msg = "Request timed out. The website took too long to respond."
            else:
                error_msg = f"Error scanning website: {error_msg}"
                
            return render_template('scan.html', error=error_msg)
        except Exception as e:
            return render_template('scan.html', error=f"Unexpected error during scan: {str(e)}")
    
    return render_template('scan.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard to view scan results for current user"""
    try:
        results = get_scan_results(user_id=current_user.id)
        if results is None:
            results = []
        return render_template('dashboard.html', results=results)
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('An error occurred while loading your dashboard.', 'danger')
        return render_template('dashboard.html', results=[])

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard to view all users and scans"""
    try:
        all_users = get_all_users()
        if all_users is None:
            all_users = []
            
        all_scans = get_scan_results()  # Get all scans without user filter
        if all_scans is None:
            all_scans = []
        
        # Get ZAP status
        zap_status = False
        zap_settings = {}
        try:
            from zap_manager import zap_manager
            zap_url = get_setting('zap_proxy_url', 'http://127.0.0.1:8080')
            zap_status = zap_manager.check_zap_running(zap_url) if zap_manager else False
            zap_settings = get_all_settings()
        except Exception as e:
            logger.error(f"ZAP status check error: {str(e)}")
        
        return render_template('admin_dashboard.html', 
                             users=all_users, 
                             scans=all_scans,
                             zap_status=zap_status,
                             zap_settings=zap_settings)
    except Exception as e:
        logger.error(f"Admin dashboard error: {str(e)}")
        flash('An error occurred while loading the admin dashboard.', 'danger')
        return render_template('admin_dashboard.html', 
                             users=[], 
                             scans=[],
                             zap_status=False,
                             zap_settings={})

@app.route('/admin/zap-settings', methods=['GET', 'POST'])
@login_required
@admin_required
def zap_settings():
    """ZAP settings management page with validation"""
    if request.method == 'POST':
        try:
            # Get and validate settings
            zap_proxy_url = request.form.get('zap_proxy_url', 'http://127.0.0.1:8080').strip()
            zap_api_key = request.form.get('zap_api_key', '').strip()
            zap_enabled = 'true' if request.form.get('zap_enabled') == 'true' else 'false'
            zap_auto_start = 'true' if request.form.get('zap_auto_start') == 'true' else 'false'
            
            # Validate proxy URL
            if not zap_proxy_url.startswith(('http://', 'https://')):
                flash('Invalid proxy URL format. Must start with http:// or https://', 'danger')
                return redirect(url_for('zap_settings'))
            
            # Update settings
            try:
                update_setting('zap_proxy_url', zap_proxy_url)
                update_setting('zap_api_key', zap_api_key)
                update_setting('zap_enabled', zap_enabled)
                update_setting('zap_auto_start', zap_auto_start)
                
                flash('ZAP settings updated successfully!', 'success')
                
                # Restart ZAP if needed
                if zap_enabled == 'true' and zap_auto_start == 'true':
                    try:
                        from zap_manager import zap_manager
                        if not zap_manager.check_zap_running(zap_proxy_url):
                            zap_manager.start_in_background()
                            flash('ZAP is starting in the background...', 'info')
                    except Exception as zap_error:
                        logger.error(f"ZAP start error: {str(zap_error)}")
                        flash('ZAP could not be started automatically. Please start it manually.', 'warning')
                        
            except Exception as db_error:
                logger.error(f"Settings update error: {str(db_error)}")
                flash('Failed to update settings. Please try again.', 'danger')
            
        except Exception as e:
            logger.error(f"ZAP settings error: {str(e)}")
            flash('An error occurred while updating settings.', 'danger')
        
        return redirect(url_for('zap_settings'))
    
    # Get current settings
    try:
        settings = get_all_settings()
        if not settings:
            settings = {}
            
        zap_status = False
        try:
            from zap_manager import zap_manager
            zap_url = get_setting('zap_proxy_url', 'http://127.0.0.1:8080')
            zap_status = zap_manager.check_zap_running(zap_url) if zap_manager else False
        except Exception as e:
            logger.error(f"ZAP status check error: {str(e)}")
        
        return render_template('zap_settings.html', 
                             settings=settings,
                             zap_status=zap_status)
    except Exception as e:
        logger.error(f"ZAP settings page error: {str(e)}")
        flash('An error occurred while loading settings.', 'danger')
        return render_template('zap_settings.html', 
                             settings={},
                             zap_status=False)

@app.route('/admin/openai-settings', methods=['GET', 'POST'])
@login_required
@admin_required
def openai_settings():
    """OpenAI settings management page"""
    if request.method == 'POST':
        try:
            # Get and validate settings
            openai_api_key = request.form.get('openai_api_key', '').strip()
            openai_enabled = 'true' if request.form.get('openai_enabled') == 'true' else 'false'
            openai_model = request.form.get('openai_model', 'gpt-4').strip()
            openai_temperature = request.form.get('openai_temperature', '0.7').strip()
            
            # Validate model
            valid_models = ['gpt-4', 'gpt-4-turbo-preview', 'gpt-3.5-turbo', 'gpt-3.5-turbo-16k']
            if openai_model not in valid_models:
                openai_model = 'gpt-4'
            
            # Validate temperature
            try:
                temp_float = float(openai_temperature)
                if temp_float < 0 or temp_float > 2:
                    temp_float = 0.7
                openai_temperature = str(temp_float)
            except:
                openai_temperature = '0.7'
            
            # Update settings
            try:
                update_setting('openai_api_key', openai_api_key)
                update_setting('openai_enabled', openai_enabled)
                update_setting('openai_model', openai_model)
                update_setting('openai_temperature', openai_temperature)
                
                flash('OpenAI settings updated successfully!', 'success')
                
                # Test connection if API key is provided
                if openai_api_key and openai_enabled == 'true':
                    try:
                        analyzer = create_openai_analyzer(
                            api_key=openai_api_key,
                            model=openai_model,
                            temperature=float(openai_temperature)
                        )
                        if analyzer and analyzer.is_available:
                            flash('OpenAI connection test successful!', 'success')
                        else:
                            flash('OpenAI connection test failed. Please check your API key.', 'warning')
                    except Exception as test_error:
                        logger.error(f"OpenAI test error: {str(test_error)}")
                        flash('OpenAI connection test failed. Please verify your API key.', 'warning')
                        
            except Exception as db_error:
                logger.error(f"Settings update error: {str(db_error)}")
                flash('Failed to update settings. Please try again.', 'danger')
            
        except Exception as e:
            logger.error(f"OpenAI settings error: {str(e)}")
            flash('An error occurred while updating settings.', 'danger')
        
        return redirect(url_for('openai_settings'))
    
    # Get current settings
    try:
        settings = get_all_settings()
        if not settings:
            settings = {}
        
        # Check OpenAI status
        openai_status = False
        openai_api_key = settings.get('openai_api_key', '')
        if openai_api_key:
            try:
                analyzer = create_openai_analyzer(
                    api_key=openai_api_key,
                    model=settings.get('openai_model', 'gpt-4'),
                    temperature=float(settings.get('openai_temperature', '0.7'))
                )
                openai_status = analyzer.is_available if analyzer else False
            except:
                openai_status = False
        
        return render_template('openai_settings.html', 
                             settings=settings,
                             openai_status=openai_status)
    except Exception as e:
        logger.error(f"OpenAI settings page error: {str(e)}")
        flash('An error occurred while loading settings.', 'danger')
        return render_template('openai_settings.html', 
                             settings={},
                             openai_status=False)

@app.route('/api/scans')
@login_required
def api_scans():
    """API endpoint to get scan results as JSON"""
    try:
        # Only return scans for current user (unless admin)
        if current_user.is_admin:
            results = get_scan_results()
        else:
            results = get_scan_results(user_id=current_user.id)
        
        if results is None:
            results = []
        
        # Convert to JSON-serializable format
        scans = []
        for result in results:
            try:
                scans.append({
                    'id': result[0],
                    'url': result[1],
                    'status_code': result[2],
                    'scan_date': str(result[4]) if len(result) > 4 else None
                })
            except (IndexError, TypeError) as e:
                logger.error(f"Error processing scan result: {str(e)}")
                continue
        
        return jsonify(scans)
    except Exception as e:
        logger.error(f"API scans error: {str(e)}")
        return jsonify({'error': 'An error occurred while fetching scans'}), 500

@app.route('/report/<int:scan_id>')
@login_required
def download_report(scan_id):
    """Generate and download PDF report for a scan with security checks"""
    try:
        # Validate scan_id
        if not isinstance(scan_id, int) or scan_id <= 0:
            flash('Invalid scan ID.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check if user has access to this scan
        results = get_scan_results(user_id=current_user.id)
        scan_ids = [r[0] for r in results] if results else []
        
        # Admin can access all scans
        if not current_user.is_admin and scan_id not in scan_ids:
            flash('You do not have permission to access this report.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Generate report
        try:
            report_path = generate_pdf_report(scan_id)
            
            # Verify file exists
            if not os.path.exists(report_path):
                raise FileNotFoundError("Report file was not created")
            
            # Send file to user
            return send_file(report_path, as_attachment=True, download_name=f'scan_report_{scan_id}.pdf')
            
        except FileNotFoundError as e:
            logger.error(f"Report file not found: {str(e)}")
            flash('Report file not found. Please try scanning again.', 'danger')
            return redirect(url_for('dashboard'))
        except Exception as e:
            logger.error(f"Report generation error: {str(e)}")
            flash('An error occurred while generating the report. Please try again.', 'danger')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        logger.error(f"Download report error: {str(e)}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(error)}")
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 errors"""
    return render_template('error.html', error_code=403, error_message="Access forbidden"), 403

if __name__ == '__main__':
    # Ensure reports directory exists
    os.makedirs('reports', exist_ok=True)
    
    # Run app
    app.run(debug=True, host='0.0.0.0', port=5000)