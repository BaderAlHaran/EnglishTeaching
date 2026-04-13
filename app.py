from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify, send_file, send_from_directory, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import hashlib
import hmac
import bcrypt
import secrets
import os
import mimetypes
import uuid
import json
import io
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import re
import logging
import resend
import math
import importlib.resources as importlib_resources
from urllib.parse import urlparse
import threading
from markupsafe import escape, Markup

import time
from collections import deque

app = Flask(__name__)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.environ.get('RATE_LIMIT_STORAGE_URI', 'memory://')
)

# Production-ready configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['DEBUG'] = os.environ.get('FLASK_ENV') != 'production'
app.config['TESTING'] = False

# Configure logging for production
if not app.debug:
    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)

# CORS configuration for production
CORS(app, origins=[
    "https://*.onrender.com",
    "https://*.render.com", 
    "http://localhost:5000",
    "http://127.0.0.1:5000"
], supports_credentials=True)



# Add custom domain support
CUSTOM_DOMAIN = os.environ.get('CUSTOM_DOMAIN')
if CUSTOM_DOMAIN:
    # Add custom domain to CORS origins
    app.config['CORS_ORIGINS'] = [
        f"https://{CUSTOM_DOMAIN}",
        f"https://www.{CUSTOM_DOMAIN}",
        "https://*.onrender.com",
        "https://*.render.com", 
        "http://localhost:5000",
        "http://127.0.0.1:5000"
    ]
    # Reconfigure CORS with custom domain
    CORS(app, origins=app.config['CORS_ORIGINS'], supports_credentials=True)

# Force HTTPS in production
@app.before_request
def force_https():
    if not app.debug and request.headers.get('X-Forwarded-Proto') == 'http':
        return redirect(request.url.replace('http://', 'https://'), code=301)

@app.before_request
def daily_cleanup_guard():
    _ensure_daily_cleanup()


CSRF_EXEMPT_ENDPOINTS = {
    'track_visit',
    'admin_reset'
}


def _ensure_csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


def _get_request_csrf_token():
    header_token = request.headers.get('X-CSRF-Token', '').strip()
    if header_token:
        return header_token
    form_token = (request.form.get('csrf_token') or '').strip()
    if form_token:
        return form_token
    json_data = request.get_json(silent=True) or {}
    return (json_data.get('csrf_token') or '').strip()


def _csrf_error_response():
    message = 'Invalid or missing CSRF token. Refresh the page and try again.'
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': message}), 400
    flash(message, 'error')
    return redirect(request.url)


@app.before_request
def csrf_protect():
    _ensure_csrf_token()
    if request.method in {'GET', 'HEAD', 'OPTIONS', 'TRACE'}:
        return None
    if request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return None
    expected = session.get('_csrf_token', '')
    provided = _get_request_csrf_token()
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        return _csrf_error_response()
    return None


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': _ensure_csrf_token()}


# Set baseline security headers on all responses
@app.after_request
def set_security_headers(response):
    response.set_cookie(
        'csrf_token',
        _ensure_csrf_token(),
        max_age=86400,
        samesite='Lax',
        httponly=False,
        secure=not app.debug
    )
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-XSS-Protection', '1; mode=block')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    # Content Security Policy tuned for this app's static assets
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        # Allow Unsplash images used by the site
        "img-src 'self' data: https://images.unsplash.com https://*.unsplash.com; "
        # Allow Google Fonts CSS and Font Awesome CSS from cdnjs
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        # Allow font files from Google Fonts and cdnjs
        "font-src 'self' data: https://fonts.gstatic.com https://*.gstatic.com https://cdnjs.cloudflare.com; "
        # Scripts: allow local and inline scripts used in admin template
        "script-src 'self' 'unsafe-inline'; "
        # API calls and font loading connections
        "connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://*.gstatic.com https://cdnjs.cloudflare.com"
    )
    return response


@app.errorhandler(429)
def handle_rate_limit(exc):
    message = "Too many requests. Please wait a moment and try again."
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'error': message}), 429
    flash(message, 'error')
    return redirect(request.referrer or url_for('index'))

# File upload configuration
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'rtf', 'odt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE = os.environ.get('DATABASE_PATH', 'essay_service.db')
DATABASE_URL = os.environ.get('DATABASE_URL')  # e.g. postgres://user:pass@host/db

# Admin credentials (configure via environment variables)
# NOTE: Changing ADMIN_PASSWORD requires an app restart to take effect.
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'mikoandnenoarecool')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
if not ADMIN_PASSWORD:
    raise RuntimeError("ADMIN_PASSWORD is not set")
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@essaywriting.com')
ADMIN_RESET_TOKEN = os.environ.get('ADMIN_RESET_TOKEN')
FROM_EMAIL = os.environ.get('FROM_EMAIL', ADMIN_EMAIL)
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
CONTACT_RECIPIENT = os.environ.get('CONTACT_RECIPIENT', ADMIN_EMAIL)
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
GEOIP_ENABLED = os.environ.get('GEOIP_ENABLED', '').lower() in {'1', 'true', 'yes', 'on'}
GEOIP_DB_PATH = os.environ.get('GEOIP_DB_PATH', 'data/GeoLite2-Country.mmdb')

if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY

# Never log credentials

def _is_postgres() -> bool:
    return bool(DATABASE_URL)

def _get_connection():
    if _is_postgres():
        import psycopg
        conn = psycopg.connect(DATABASE_URL)
        conn.autocommit = True  # avoid aborted transaction states during schema setup
        return conn
    return sqlite3.connect(DATABASE)

class _CursorWrapper:
    def __init__(self, cursor, is_pg):
        self._cursor = cursor
        self._is_pg = is_pg

    def execute(self, query: str, params=None):
        # translate placeholders depending on backend
        if self._is_pg and '?' in query and '%s' not in query:
            query = query.replace('?', '%s')
        elif not self._is_pg and '%s' in query and '?' not in query:
            query = query.replace('%s', '?')
        if params is None:
            return self._cursor.execute(query)
        return self._cursor.execute(query, params)

    def __getattr__(self, name):
        return getattr(self._cursor, name)

def _get_cursor(conn):
    return _CursorWrapper(conn.cursor(), _is_postgres())

def _open_db():
    """Return a connection and wrapped cursor for the configured database."""
    conn = _get_connection()
    return conn, _get_cursor(conn)

def init_database():
    """Initialize database with tables"""
    conn = _get_connection()
    cursor = _get_cursor(conn)
    
    # Admin users table
    if _is_postgres():
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                email TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
    
    # Essay submissions table
    if _is_postgres():
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS essay_submissions (
                id SERIAL PRIMARY KEY,
                submission_id TEXT UNIQUE NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT,
                essay_type TEXT NOT NULL,
                academic_level TEXT NOT NULL,
                subject TEXT NOT NULL,
                pages TEXT NOT NULL,
                deadline TEXT NOT NULL,
                topic TEXT NOT NULL,
                instructions TEXT,
                citation_style TEXT,
                status TEXT DEFAULT 'pending',
                assigned_to TEXT,
                file_path TEXT,
                file_name TEXT,
                file_size INTEGER,
                admin_notes TEXT,
                priority TEXT DEFAULT 'normal',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS essay_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submission_id TEXT UNIQUE NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT,
                essay_type TEXT NOT NULL,
                academic_level TEXT NOT NULL,
                subject TEXT NOT NULL,
                pages TEXT NOT NULL,
                deadline TEXT NOT NULL,
                topic TEXT NOT NULL,
                instructions TEXT,
                citation_style TEXT,
                status TEXT DEFAULT 'pending',
                assigned_to TEXT,
                file_path TEXT,
                file_name TEXT,
                file_size INTEGER,
                admin_notes TEXT,
                priority TEXT DEFAULT 'normal',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    
    # Reviews table
    if _is_postgres():
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reviews (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                university TEXT NOT NULL,
                rating INTEGER NOT NULL,
                review_text TEXT NOT NULL,
                is_approved BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                university TEXT NOT NULL,
                rating INTEGER NOT NULL,
                review_text TEXT NOT NULL,
                is_approved BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

    # App metadata table for housekeeping (daily cleanup)
    if _is_postgres():
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS app_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS app_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')

    # Visits table for lightweight analytics
    if _is_postgres():
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS visits (
                id SERIAL PRIMARY KEY,
                visitor_id TEXT NOT NULL,
                visit_date DATE NOT NULL,
                first_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                referrer TEXT,
                user_agent TEXT,
                country_code TEXT,
                UNIQUE (visitor_id, visit_date)
            )
        ''')
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                visitor_id TEXT NOT NULL,
                visit_date DATE NOT NULL,
                first_path TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                referrer TEXT,
                user_agent TEXT,
                country_code TEXT,
                UNIQUE (visitor_id, visit_date)
            )
        ''')
    
    # Add new columns to existing table if they don't exist
    try:
        cursor.execute('ALTER TABLE essay_submissions ADD COLUMN file_path TEXT')
    except Exception:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE essay_submissions ADD COLUMN file_name TEXT')
    except Exception:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE essay_submissions ADD COLUMN file_size INTEGER')
    except Exception:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE essay_submissions ADD COLUMN admin_notes TEXT')
    except Exception:
        pass  # Column already exists
    
    try:
        cursor.execute("ALTER TABLE essay_submissions ADD COLUMN priority TEXT DEFAULT 'normal'")
    except Exception:
        pass  # Column already exists

    # Add country code column to visits if missing
    try:
        if _is_postgres():
            cursor.execute('ALTER TABLE visits ADD COLUMN IF NOT EXISTS country_code TEXT')
        else:
            cursor.execute('ALTER TABLE visits ADD COLUMN country_code TEXT')
    except Exception:
        pass  # Column already exists or visits table missing
    
    # Enforce single admin username
    cursor.execute('DELETE FROM admin_users WHERE username != ?', (ADMIN_USERNAME,))

    # Keep admin password in sync with ADMIN_PASSWORD env (restart required after changes).
    pw_hash = hash_password(ADMIN_PASSWORD)
    if _is_postgres():
        cursor.execute('''
            INSERT INTO admin_users (username, password_hash, email, is_active)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (username) DO UPDATE
            SET password_hash = EXCLUDED.password_hash,
                email = EXCLUDED.email,
                is_active = EXCLUDED.is_active
        ''', (ADMIN_USERNAME, pw_hash, ADMIN_EMAIL, True))
    else:
        cursor.execute('''
            INSERT OR IGNORE INTO admin_users (username, password_hash, email, is_active)
            VALUES (?, ?, ?, ?)
        ''', (ADMIN_USERNAME, pw_hash, ADMIN_EMAIL, 1))
        cursor.execute('''
            UPDATE admin_users
            SET password_hash = ?, email = ?, is_active = 1
            WHERE username = ?
        ''', (pw_hash, ADMIN_EMAIL, ADMIN_USERNAME))
    
    conn.commit()
    conn.close()
    print("Database initialized successfully")

def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        # fallback for legacy SHA-256 hashes: accept once, then upgrade on login
        try:
            legacy_ok = hashlib.sha256(password.encode()).hexdigest() == password_hash
            return legacy_ok
        except Exception:
            return False

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_logged_in():
    """Check if user is logged in"""
    return 'admin_logged_in' in session and session['admin_logged_in'] == True

def require_login(f):
    """Decorator to require login"""
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Initialize database
init_database()

_cleanup_lock = threading.Lock()
_last_cleanup_checked = None

def _run_cleanup_if_needed():
    if not _cleanup_lock.acquire(False):
        return
    conn = None
    try:
        today = datetime.now().date().isoformat()
        conn, cursor = _open_db()
        cursor.execute('SELECT value FROM app_meta WHERE key = ?', ('last_cleanup_date',))
        row = cursor.fetchone()
        last_cleanup = row[0] if row else None
        if last_cleanup == today:
            return

        cutoff_date = (datetime.now().date() - timedelta(days=180)).isoformat()
        cursor.execute('DELETE FROM visits WHERE visit_date < ?', (cutoff_date,))

        if _is_postgres():
            cursor.execute('''
                INSERT INTO app_meta (key, value)
                VALUES (?, ?)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            ''', ('last_cleanup_date', today))
        else:
            cursor.execute('''
                INSERT OR REPLACE INTO app_meta (key, value)
                VALUES (?, ?)
            ''', ('last_cleanup_date', today))
        conn.commit()
    except Exception:
        app.logger.exception("Daily analytics cleanup failed")
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        _cleanup_lock.release()

def _ensure_daily_cleanup():
    global _last_cleanup_checked
    today = datetime.now().date().isoformat()
    if _last_cleanup_checked == today:
        return
    _last_cleanup_checked = today
    threading.Thread(target=_run_cleanup_if_needed, daemon=True).start()

# Routes - Define specific routes BEFORE catch-all route
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/about')
def about():
    return send_from_directory('.', 'about.html')

@app.route('/free-essay-writing-help')
def free_essay_writing_help():
    return send_from_directory('.', 'free-essay-writing-help.html')

@app.route('/essay-form')
def essay_form():
    return send_from_directory('.', 'essay-form.html')

@app.route('/terms')
def terms():
    return send_from_directory('.', 'terms.html')

@app.route('/privacy')
def privacy():
    return send_from_directory('.', 'privacy.html')

@app.route('/contact')
def contact():
    return send_from_directory('.', 'contact.html')

@app.route('/faq')
def faq():
    return send_from_directory('.', 'faq.html')

@app.route('/robots.txt')
def robots_txt():
    """Robots file allowing crawl and pointing to sitemap"""
    base = request.url_root.rstrip('/')
    content = f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n"
    return (content, 200, {'Content-Type': 'text/plain; charset=utf-8'})

@app.route('/sitemap.xml')
def sitemap_xml():
    """Simple dynamic sitemap covering key pages"""
    base = request.url_root.rstrip('/')
    urls = [
        "/", "/essay-form", "/about", "/contact", "/terms", "/privacy", "/faq"
    ]
    items = "\n".join(
        f"  <url>\n    <loc>{base}{path}</loc>\n  </url>" for path in urls
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{items}\n"
        "</urlset>\n"
    )
    return (xml, 200, {'Content-Type': 'application/xml; charset=utf-8'})

@app.route('/track', methods=['POST'])
def track_visit():
    data = request.get_json(silent=True) or request.form or {}
    visitor_id = request.cookies.get('visitor_id')
    new_visitor_id = None
    if not visitor_id:
        new_visitor_id = str(uuid.uuid4())
        visitor_id = new_visitor_id

    today = datetime.now().date().isoformat()
    path = (data.get('path') or '').strip()
    referrer = (request.referrer or '').strip()
    if not path and referrer:
        try:
            path = urlparse(referrer).path or referrer
        except Exception:
            path = referrer
    if not path:
        path = '/'

    if path.startswith('/admin'):
        resp = make_response('', 204)
        if new_visitor_id:
            resp.set_cookie('visitor_id', new_visitor_id, max_age=31536000, samesite='Lax', httponly=True, secure=not app.debug)
        return resp

    user_agent = (request.headers.get('User-Agent') or '')[:255]
    referrer_value = referrer[:512] if referrer else None
    path_value = path[:512]
    country_code = _get_country_code_from_request()

    conn, cursor = _open_db()
    if _is_postgres():
        cursor.execute('''
            INSERT INTO visits (visitor_id, visit_date, first_path, referrer, user_agent, country_code)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (visitor_id, visit_date) DO NOTHING
        ''', (visitor_id, today, path_value, referrer_value, user_agent or None, country_code))
    else:
        cursor.execute('''
            INSERT OR IGNORE INTO visits (visitor_id, visit_date, first_path, referrer, user_agent, country_code)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (visitor_id, today, path_value, referrer_value, user_agent or None, country_code))
    conn.commit()
    conn.close()

    resp = make_response('', 204)
    if new_visitor_id:
        resp.set_cookie('visitor_id', new_visitor_id, max_age=31536000, samesite='Lax', httponly=True, secure=not app.debug)
    return resp

# Static file routes - Must be AFTER specific routes
@app.route('/<path:filename>')
def static_files(filename):
    """Serve static files (CSS, JS, images, etc.)"""
    if not filename.startswith('api/') and not filename.startswith('templates/'):
        try:
            # Check if it's a static file
            if filename.endswith(('.html', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.woff', '.woff2', '.ttf', '.xml', '.txt', '.json')):
                return send_from_directory('.', filename)
            else:
                return jsonify({'error': 'Not found'}), 404
        except FileNotFoundError:
            return jsonify({'error': 'File not found'}), 404
    else:
        return jsonify({'error': 'Not found'}), 404

def _send_contact_email(sender_email: str, message_text: str):
    admin_recipient = ADMIN_EMAIL or CONTACT_RECIPIENT
    if not admin_recipient:
        return False, 'Email not configured on server'

    subject = 'New contact form message'
    body = (
        f"You received a new contact form submission.\n\n"
        f"From: {sender_email}\n"
        f"Time: {datetime.utcnow().isoformat()} UTC\n\n"
        f"Message:\n{message_text}\n"
    )

    return _send_email(to_email=admin_recipient, subject=subject, body=body, reply_to=sender_email)

def _send_email(to_email: str, subject: str, body: str, reply_to: str = None):
    """Generic email sender using Resend"""
    if not RESEND_API_KEY or not FROM_EMAIL or not to_email:
        return False, 'Email not configured or recipient missing'

    recipients = [to_email] if isinstance(to_email, str) else [addr for addr in to_email if addr]
    if not recipients:
        return False, 'Email recipient missing'

    payload = {
        "from": FROM_EMAIL,
        "to": recipients,
        "subject": subject,
        "text": body
    }
    if reply_to:
        payload["reply_to"] = [reply_to]

    try:
        resend.Emails.send(payload)
        return True, ''
    except Exception as e:
        app.logger.error("Resend email failed: %s", e)
        return False, 'Unable to send email right now. Please try again later.'

def _get_country_code_from_request():
    if not GEOIP_ENABLED:
        return None
    if not GEOIP_DB_PATH or not os.path.exists(GEOIP_DB_PATH):
        return None
    try:
        from geoip2.database import Reader
    except Exception:
        return None

    ip = None
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        ip = xff.split(',')[0].strip()
    if not ip:
        ip = request.remote_addr
    if not ip:
        return None

    try:
        with Reader(GEOIP_DB_PATH) as reader:
            response = reader.country(ip)
            code = (response.country.iso_code or '').strip().upper()
            return code or None
    except Exception:
        return None

@app.route('/contact/send', methods=['POST'])
@limiter.limit("10 per hour")
def send_contact():
    data = request.get_json(silent=True) or request.form
    sender_email = (data.get('email') or '').strip()
    message_text = (data.get('message') or '').strip()

    if not sender_email or not message_text:
        return jsonify({'success': False, 'error': 'email and message are required'}), 400

    if not EMAIL_REGEX.match(sender_email):
        return jsonify({'success': False, 'error': 'invalid email'}), 400

    ok, err = _send_contact_email(sender_email, message_text)
    if not ok:
        return jsonify({'success': False, 'error': err}), 500

    return jsonify({'success': True})

@app.route('/index.html')
def index_html():
    """Serve home page for direct /index.html requests"""
    return send_from_directory('.', 'index.html')

@app.route('/favicon.ico')
def favicon():
    """Handle favicon requests; serve if present, else no content"""
    favicon_path = os.path.join('.', 'favicon.ico')
    if os.path.exists(favicon_path):
        return send_from_directory('.', 'favicon.ico')
    return ('', 204)

@app.route('/google23ea826885685fa0.html')
def google_site_verification():
    """Serve Google Search Console verification file"""
    return (
        'google-site-verification: google23ea826885685fa0.html',
        200,
        {'Content-Type': 'text/html; charset=utf-8'}
    )

@app.route('/google308cceed71efd1b6.html')
def google_site_verification_new():
    """Serve Google Search Console verification file (current token)"""
    return (
        'google-site-verification: google308cceed71efd1b6.html',
        200,
        {'Content-Type': 'text/html; charset=utf-8'}
    )

# 404 honeypot handler


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    return admin_routes.login()

@app.route('/logout')
def logout():
    return admin_routes.logout()

@app.route('/admin')
def admin():
    return admin_routes.admin()

@app.route('/admin/analytics')
def admin_analytics():
    return admin_routes.admin_analytics()

@app.route('/admin-setup')
def admin_setup():
    return admin_routes.admin_setup()

@app.route('/admin-setup', methods=['POST'])
@limiter.limit("5 per hour")
def admin_setup_post():
    return admin_routes.admin_setup_post()

@app.route('/admin-reset', methods=['POST'])
def admin_reset():
    return admin_routes.admin_reset()

@app.route('/submit', methods=['POST'])
@app.route('/submit-essay', methods=['POST'])
@limiter.limit("5 per hour")
def submit_essay():
    return submission_routes.submit_essay()

@app.route('/submit-review', methods=['POST'])
@limiter.limit("5 per hour")
def submit_review():
    return submission_routes.submit_review()

@app.route('/get-reviews')
def get_reviews():
    return submission_routes.get_reviews()

@app.route('/admin/edit-submission/<int:submission_id>', methods=['GET', 'POST'])
@require_login
def edit_submission(submission_id):
    return admin_routes.edit_submission(submission_id)

@app.route('/admin/download-file/<int:submission_id>')
@require_login
def download_file(submission_id):
    return admin_routes.download_file(submission_id)

@app.route('/admin/update-status', methods=['POST'])
@require_login
@limiter.limit("20 per minute")
def update_status():
    return admin_routes.update_status()

@app.route('/admin/delete-submission', methods=['POST'])
@require_login
@limiter.limit("10 per minute")
def delete_submission():
    return admin_routes.delete_submission()

@app.route('/admin/bulk-update-status', methods=['POST'])
@require_login
@limiter.limit("5 per minute")
def bulk_update_status():
    return admin_routes.bulk_update_status()

@app.route('/admin/delete-review', methods=['POST'])
@require_login
@limiter.limit("10 per minute")
def delete_review():
    return admin_routes.delete_review()

@app.route('/admin/approve-review', methods=['POST'])
@require_login
@limiter.limit("10 per minute")
def approve_review():
    return admin_routes.approve_review()
@app.route('/admin/set-password', methods=['POST'])
@require_login
@limiter.limit("5 per hour")
def admin_set_password():
    return admin_routes.admin_set_password()

import admin_routes
import app_services
import improve_routes
import submission_routes

app_services.configure(
    open_db=_open_db,
    is_postgres=_is_postgres,
    send_email=_send_email,
    allowed_file=allowed_file,
    hash_password=hash_password,
    verify_password=verify_password,
    email_regex=EMAIL_REGEX,
    admin_username=ADMIN_USERNAME,
    admin_password=ADMIN_PASSWORD,
    admin_email=ADMIN_EMAIL,
    admin_reset_token=ADMIN_RESET_TOKEN,
    from_email=FROM_EMAIL,
    contact_recipient=CONTACT_RECIPIENT,
    upload_folder=app.config['UPLOAD_FOLDER'],
    logger=app.logger
)

admin_routes.configure(
    ensure_submissions_table=lambda: improve_routes._ensure_submissions_table()
)

IMPROVE_ALLOWED_EXTENSIONS = improve_routes.IMPROVE_ALLOWED_EXTENSIONS
IMPROVE_MAX_BYTES = improve_routes.IMPROVE_MAX_BYTES
IMPROVE_MAX_CHARS = improve_routes.IMPROVE_MAX_CHARS
IMPROVE_MAX_PAGES = improve_routes.IMPROVE_MAX_PAGES
IMPROVE_JOB_TIMEOUT_SECONDS = improve_routes.IMPROVE_JOB_TIMEOUT_SECONDS


def _improve_context():
    return improve_routes._improve_context()


def _ensure_submissions_table():
    return improve_routes._ensure_submissions_table()


def _read_upload_bytes(file_storage):
    return improve_routes._read_upload_bytes(file_storage)


def _extract_text_from_upload(file_storage):
    return improve_routes._extract_text_from_upload(file_storage)


def _ensure_improve_jobs_table():
    return improve_routes._ensure_improve_jobs_table()


def _create_improve_job(extracted_text, warning):
    return improve_routes._create_improve_job(extracted_text, warning)


def _update_improve_job(job_id, status=None, progress=None, message=None, result_html=None, result_json=None, error=None, warning=None):
    return improve_routes._update_improve_job(
        job_id,
        status=status,
        progress=progress,
        message=message,
        result_html=result_html,
        result_json=result_json,
        error=error,
        warning=warning
    )


def _build_result_html(ai_result, highlighted_text):
    return improve_routes._build_result_html(ai_result, highlighted_text)


def _serialize_improve_json(ai_result):
    return improve_routes._serialize_improve_json(ai_result)


def _process_improve_job(job_id, extracted_text, warning):
    return improve_routes._process_improve_job(job_id, extracted_text, warning)


def _run_local_analysis(text, progress_cb=None, timeout_seconds=20, start_time=None):
    return improve_routes._run_local_analysis(
        text,
        progress_cb=progress_cb,
        timeout_seconds=timeout_seconds,
        start_time=start_time
    )


def _build_highlighted_html(text, issues):
    return improve_routes._build_highlighted_html(text, issues)


@app.route('/improve', methods=['GET'])
def improve():
    return improve_routes.improve()


@app.route('/improve/ai', methods=['POST'])
@limiter.limit("10 per hour")
def improve_ai():
    return improve_routes.improve_ai()


@app.route('/improve/human/form', methods=['POST'])
@limiter.limit("10 per hour")
def improve_human_form():
    return improve_routes.improve_human_form()


@app.route('/improve/human', methods=['POST'])
@limiter.limit("10 per hour")
def improve_human():
    return improve_routes.improve_human()


@app.route('/improve/human/submit', methods=['POST'])
@limiter.limit("5 per hour")
def improve_human_submit():
    return improve_routes.improve_human_submit()


@app.route('/admin/submissions', methods=['GET'])
@require_login
def admin_submissions():
    return improve_routes.admin_submissions()


@app.route('/improve/progress/<job_id>', methods=['GET'])
def improve_progress(job_id):
    return improve_routes.improve_progress(job_id)


@app.route('/improve/status/<job_id>', methods=['GET'])
def improve_status(job_id):
    return improve_routes.improve_status(job_id)


@app.route('/improve/result/<job_id>', methods=['GET'])
def improve_result(job_id):
    return improve_routes.improve_result(job_id)


if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Development server (not used in production)
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(debug=debug, host='0.0.0.0', port=port)
