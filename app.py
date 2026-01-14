from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify, send_file, send_from_directory, make_response
from flask_cors import CORS
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
from urllib.parse import urlparse
import threading
from markupsafe import escape, Markup

import time
from collections import deque

app = Flask(__name__)

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


# Set baseline security headers on all responses
@app.after_request
def set_security_headers(response):
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
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password required', 'error')
            return render_template('login.html')
        
        conn, cursor = _open_db()
        
        cursor.execute('SELECT * FROM admin_users WHERE username = ? AND is_active = ?', (username, True))
        user = cursor.fetchone()
        env_match = hmac.compare_digest(password, ADMIN_PASSWORD)

        if not user:
            conn.close()
            flash('Invalid credentials', 'error')
            return render_template('login.html')

        # First-time setup: require ADMIN_PASSWORD and set it now
        if not user[2] or user[2] == '':
            if not env_match:
                conn.close()
                flash('Invalid credentials', 'error')
                return render_template('login.html')
            new_hash = hash_password(ADMIN_PASSWORD)
            cursor.execute('UPDATE admin_users SET password_hash = ? WHERE id = ?', (new_hash, user[0]))
        else:
            password_ok = verify_password(password, user[2])
            if not password_ok and not env_match:
                conn.close()
                flash('Invalid credentials', 'error')
                return render_template('login.html')
            if env_match and not password_ok:
                new_hash = hash_password(ADMIN_PASSWORD)
                cursor.execute('UPDATE admin_users SET password_hash = ? WHERE id = ?', (new_hash, user[0]))
        
        # Update last login
        # If a legacy SHA-256 hash matched, upgrade to bcrypt (only if hash exists)
        if user[2] and not user[2].startswith('$2b$') and not user[2].startswith('$2a$'):
            upgraded = hash_password(password)
            cursor.execute('UPDATE admin_users SET password_hash = ? WHERE id = ?', (upgraded, user[0],))
        cursor.execute('UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
        conn.commit()
        conn.close()
        
        # Set session
        session['admin_logged_in'] = True
        session['admin_username'] = user[1]
        session['admin_id'] = user[0]
        
        flash('Login successful!', 'success')
        return redirect(url_for('admin'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/admin')
def admin():
    # Check if password is set first
    conn, cursor = _open_db()
    cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (ADMIN_USERNAME,))
    pw_row = cursor.fetchone()
    password_set = bool(pw_row and pw_row[0])
    conn.close()
    
    # If password not set, redirect to setup
    if not password_set:
        return redirect(url_for('admin_setup'))
    
    # Check if user is logged in
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    # Get statistics
    conn, cursor = _open_db()
    
    # Get submission stats
    cursor.execute('SELECT COUNT(*) FROM essay_submissions')
    total_submissions = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM essay_submissions WHERE status = 'pending'")
    pending_submissions = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM essay_submissions WHERE status = 'completed'")
    completed_submissions = cursor.fetchone()[0]
    
    # Get all submissions
    cursor.execute('''
        SELECT * FROM essay_submissions 
        ORDER BY created_at DESC
    ''')
    all_submissions = cursor.fetchall()

    # Load reviews for admin dashboard
    cursor.execute('''
        SELECT id, name, university, rating, review_text, created_at, is_approved
        FROM reviews
        ORDER BY created_at DESC
    ''')
    all_reviews = cursor.fetchall()
    
    # Check if admin password is set
    cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (ADMIN_USERNAME,))
    pw_row = cursor.fetchone()
    password_set = bool(pw_row and pw_row[0])

    conn.close()
    
    stats = {
        'total_submissions': total_submissions,
        'pending_submissions': pending_submissions,
        'completed_submissions': completed_submissions
    }
    
    return render_template('admin.html', stats=stats, submissions=all_submissions, password_set=password_set, reviews=all_reviews)

@app.route('/admin/analytics')
def admin_analytics():
    conn, cursor = _open_db()
    cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (ADMIN_USERNAME,))
    pw_row = cursor.fetchone()
    password_set = bool(pw_row and pw_row[0])
    conn.close()

    if not password_set:
        return redirect(url_for('admin_setup'))
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))

    today = datetime.now().date()
    yesterday = today - timedelta(days=1)
    start_date = today - timedelta(days=6)

    conn, cursor = _open_db()
    cursor.execute('''
        SELECT visit_date, COUNT(*)
        FROM visits
        WHERE visit_date >= ?
        GROUP BY visit_date
    ''', (start_date.isoformat(),))
    rows = cursor.fetchall()
    counts_by_date = {}
    for row in rows:
        date_value = row[0]
        date_key = date_value.isoformat() if hasattr(date_value, 'isoformat') else str(date_value)
        counts_by_date[date_key] = row[1]

    cursor.execute('''
        SELECT first_path, COUNT(*)
        FROM visits
        WHERE visit_date = ? AND first_path IS NOT NULL AND first_path != ''
        GROUP BY first_path
        ORDER BY COUNT(*) DESC
        LIMIT 10
    ''', (today.isoformat(),))
    top_rows = cursor.fetchall()

    cursor.execute('''
        SELECT country_code, COUNT(*)
        FROM visits
        WHERE visit_date = ? AND country_code IS NOT NULL AND country_code != ''
        GROUP BY country_code
        ORDER BY COUNT(*) DESC
        LIMIT 10
    ''', (today.isoformat(),))
    country_rows = cursor.fetchall()
    conn.close()

    last_7_days = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_key = day.isoformat()
        last_7_days.append({'date': day_key, 'count': counts_by_date.get(day_key, 0)})

    top_pages = [{'path': row[0], 'count': row[1]} for row in top_rows]
    top_countries = [{'country': row[0], 'count': row[1]} for row in country_rows]

    return render_template(
        'admin_analytics.html',
        today_count=counts_by_date.get(today.isoformat(), 0),
        yesterday_count=counts_by_date.get(yesterday.isoformat(), 0),
        last_7_days=last_7_days,
        top_pages=top_pages,
        top_countries=top_countries
    )

@app.route('/admin-setup')
def admin_setup():
    """Admin password setup page"""
    # Check if password is already set
    conn, cursor = _open_db()
    cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (ADMIN_USERNAME,))
    pw_row = cursor.fetchone()
    password_set = bool(pw_row and pw_row[0])
    conn.close()
    
    if password_set:
        return redirect(url_for('login'))
    
    return render_template('admin_setup.html', username=ADMIN_USERNAME)

@app.route('/admin-setup', methods=['POST'])
def admin_setup_post():
    """Handle admin password setup"""
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    if not password or not confirm_password:
        flash('Please fill in all fields', 'error')
        return redirect(url_for('admin_setup'))
    
    if password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('admin_setup'))

    if password != ADMIN_PASSWORD:
        flash('Password must match ADMIN_PASSWORD. Update env vars and restart the app.', 'error')
        return redirect(url_for('admin_setup'))

    if len(password) < 8:
        flash('Password must be at least 8 characters long', 'error')
        return redirect(url_for('admin_setup'))
    
    # Hash and save password
    password_hash = hash_password(password)
    
    conn, cursor = _open_db()
    cursor.execute('''
        UPDATE admin_users 
        SET password_hash = ? 
        WHERE username = ?
    ''', (password_hash, ADMIN_USERNAME))
    conn.commit()
    conn.close()
    
    flash('Password set successfully! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/admin-reset', methods=['POST'])
def admin_reset():
    """Reset admin password using a one-time token (only if ADMIN_RESET_TOKEN is set)."""
    if not ADMIN_RESET_TOKEN:
        return jsonify({'error': 'Not found'}), 404

    payload = request.get_json(silent=True) or {}
    token = (
        request.headers.get('X-Admin-Reset-Token')
        or payload.get('token')
        or request.form.get('token')
    )
    if not token or token != ADMIN_RESET_TOKEN:
        return jsonify({'error': 'Invalid token'}), 403

    password_hash = hash_password(ADMIN_PASSWORD)
    conn, cursor = _open_db()
    cursor.execute('UPDATE admin_users SET password_hash = ? WHERE username = ?', (password_hash, ADMIN_USERNAME))
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'message': 'DB synced to ADMIN_PASSWORD; restart required only if ADMIN_PASSWORD changed.'
    })

@app.route('/submit', methods=['POST'])
@app.route('/submit-essay', methods=['POST'])
def submit_essay():
    """Handle essay form submission with file upload"""
    try:
        # Honeypot to deter bots
        if request.form.get('website'):
            app.logger.info("Honeypot field triggered; ignoring submission.")
            return jsonify({'success': True}), 200

        # Get form data
        data = {
            'submission_id': secrets.token_hex(8),
            'first_name': (request.form.get('firstName') or '').strip(),
            'last_name': (request.form.get('lastName') or '').strip(),
            'email': (request.form.get('email') or '').strip(),
            'phone': (request.form.get('phone') or '').strip(),
            'essay_type': (request.form.get('essayType') or '').strip(),
            'academic_level': (request.form.get('academicLevel') or '').strip(),
            'subject': (request.form.get('subject') or '').strip(),
            'pages': (request.form.get('pages') or '').strip(),
            'deadline': (request.form.get('deadline') or '').strip(),
            'topic': (request.form.get('topic') or '').strip(),
            'instructions': (request.form.get('instructions') or '').strip(),
            'citation_style': (request.form.get('citationStyle') or '').strip(),
            'writer_preference': (request.form.get('writerPreference') or '').strip(),
            'sources': (request.form.get('sources') or '').strip(),
            'newsletter': request.form.get('newsletter', ''),
            'terms': request.form.get('terms')
        }
        
        # Validate required fields
        required_fields = ['first_name', 'last_name', 'email', 'essay_type', 'academic_level', 'subject', 'pages', 'deadline', 'topic']
        for field in required_fields:
            if not data[field]:
                return jsonify({'error': f'{field} is required'}), 400

        if not EMAIL_REGEX.match(data['email']):
            return jsonify({'error': 'invalid email'}), 400

        if not data['terms']:
            return jsonify({'error': 'Please accept the terms and conditions'}), 400
        
        # Handle file upload
        file_path = None
        file_name = None
        file_size = None
        
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename and allowed_file(file.filename):
                # Generate unique filename
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                file_name = filename
                file_size = os.path.getsize(file_path)
        
        # Save to database
        conn, cursor = _open_db()
        
        cursor.execute('''
            INSERT INTO essay_submissions 
            (submission_id, first_name, last_name, email, phone, essay_type, academic_level, 
             subject, pages, deadline, topic, instructions, citation_style, file_path, file_name, file_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (data['submission_id'], data['first_name'], data['last_name'], data['email'], 
              data['phone'], data['essay_type'], data['academic_level'], data['subject'], 
              data['pages'], data['deadline'], data['topic'], data['instructions'], data['citation_style'],
              file_path, file_name, file_size))
        
        conn.commit()
        conn.close()

        # Send email notifications
        student_email = data['email']
        student_name = f"{data.get('first_name','').strip()} {data.get('last_name','').strip()}".strip()
        submission_id = data['submission_id']

        admin_body_lines = [
            "New essay submission received.",
            f"Submission ID: {submission_id}",
            f"Name: {student_name or 'N/A'}",
            f"Email: {student_email}",
            f"Phone: {data.get('phone') or 'N/A'}",
            f"Essay Type: {data.get('essay_type')}",
            f"Academic Level: {data.get('academic_level')}",
            f"Subject: {data.get('subject')}",
            f"Pages: {data.get('pages')}",
            f"Deadline: {data.get('deadline')}",
            f"Topic: {data.get('topic')}",
            f"Citation Style: {data.get('citation_style') or 'N/A'}",
            f"Writer Preference: {data.get('writer_preference') or 'N/A'}",
            f"Required Sources: {data.get('sources') or 'N/A'}",
            f"Newsletter Opt-in: {'Yes' if data.get('newsletter') else 'No'}",
            f"File Uploaded: {file_name or 'No file'}" + (f" ({file_size} bytes)" if file_size else ''),
            "",
            "Instructions:",
            data.get('instructions') or 'None provided'
        ]

        admin_ok, admin_err = _send_email(
            to_email=ADMIN_EMAIL or CONTACT_RECIPIENT,
            subject="New submission received",
            body="\n".join(admin_body_lines),
            reply_to=student_email
        )

        if not admin_ok:
            app.logger.error("Admin notification email failed: %s", admin_err)
            return jsonify({'error': 'Unable to send confirmation emails right now. Please try again shortly.'}), 500

        student_ok, student_err = _send_email(
            to_email=student_email,
            subject=f"Submission received: {submission_id}",
            body=(
                f"Hello {student_name or 'there'},\n\n"
                f"We've received your essay request (ID: {submission_id}).\n"
                f"Current status: pending. We'll email you when the status changes.\n\n"
                f"Summary:\n"
                f"- Type: {data.get('essay_type','')}\n"
                f"- Subject: {data.get('subject','')}\n"
                f"- Pages: {data.get('pages','')}\n"
                f"- Deadline: {data.get('deadline','')}\n\n"
                f"Thank you,\nEnglish Essay Writing Team"
            ),
            reply_to=ADMIN_EMAIL or FROM_EMAIL
        )

        if not student_ok:
            app.logger.warning("Student confirmation email failed for %s: %s", student_email, student_err)
        
        return jsonify({'success': True, 'submission_id': submission_id})
        
    except Exception:
        app.logger.exception("Error handling submission")
        return jsonify({'error': 'Something went wrong. Please try again later.'}), 500

@app.route('/submit-review', methods=['POST'])
def submit_review():
    """Handle review submission"""
    conn = None
    try:
        data = request.get_json(silent=True) or request.form or {}
        
        # Validate required fields
        required_fields = ['name', 'university', 'rating', 'review_text']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Save to database
        conn, cursor = _open_db()
        
        cursor.execute('''
            INSERT INTO reviews (name, university, rating, review_text, is_approved)
            VALUES (%s, %s, %s, %s, %s)
        ''', (data['name'], data['university'], data['rating'], data['review_text'], False))
        
        conn.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        app.logger.exception("submit-review failed")
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

@app.route('/get-reviews')
def get_reviews():
    """Get approved reviews"""
    conn, cursor = _open_db()
    
    cursor.execute('''
        SELECT name, university, rating, review_text, created_at 
        FROM reviews 
        WHERE is_approved = %s 
        ORDER BY created_at DESC
    ''', (True,))
    
    reviews = []
    for row in cursor.fetchall():
        reviews.append({
            'name': row[0],
            'university': row[1],
            'rating': row[2],
            'review_text': row[3],
            'created_at': row[4]
        })
    
    conn.close()
    resp = jsonify(reviews)
    resp.headers['Cache-Control'] = 'no-store, max-age=0'
    return resp

@app.route('/admin/edit-submission/<int:submission_id>', methods=['GET', 'POST'])
@require_login
def edit_submission(submission_id):
    """Edit submission details"""
    conn, cursor = _open_db()
    
    if request.method == 'POST':
        # Update submission
        status = request.form.get('status')
        assigned_to = request.form.get('assigned_to')
        admin_notes = request.form.get('admin_notes')
        priority = request.form.get('priority')
        
        cursor.execute('''
            UPDATE essay_submissions 
            SET status = ?, assigned_to = ?, admin_notes = ?, priority = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (status, assigned_to, admin_notes, priority, submission_id))
        
        conn.commit()

        # Email the student about the status update (also when updated from the edit page)
        try:
            cursor.execute('SELECT first_name, last_name, email, submission_id FROM essay_submissions WHERE id = ?', (submission_id,))
            row = cursor.fetchone()
            if row:
                first_name, last_name, email, sub_id = row
                if email:
                    full_name = f"{first_name} {last_name}".strip()
                    _send_email(
                        to_email=email,
                        subject=f"Your submission status updated to {status}",
                        body=(
                            f"Hello {full_name or 'there'},\n\n"
                            f"Your essay submission (ID: {sub_id}) status is now: {status}.\n\n"
                            f"Thank you,\nEnglish Essay Writing Team"
                        ),
                        reply_to=CONTACT_RECIPIENT or None
                    )
        except Exception:
            pass

        conn.close()
        
        flash('Submission updated successfully!', 'success')
        return redirect(url_for('admin'))
    
    # Get submission details
    cursor.execute('SELECT * FROM essay_submissions WHERE id = ?', (submission_id,))
    submission = cursor.fetchone()
    conn.close()
    
    if not submission:
        flash('Submission not found!', 'error')
        return redirect(url_for('admin'))
    
    return render_template('edit_submission.html', submission=submission)

@app.route('/admin/download-file/<int:submission_id>')
@require_login
def download_file(submission_id):
    """Download uploaded file"""
    conn, cursor = _open_db()
    
    cursor.execute('SELECT file_path, file_name FROM essay_submissions WHERE id = ?', (submission_id,))
    result = cursor.fetchone()
    conn.close()
    
    if not result or not result[0]:
        flash('File not found!', 'error')
        return redirect(url_for('admin'))
    
    file_path, file_name = result
    # Normalize path separators for cross-platform compatibility
    file_path = file_path.replace('\\', '/')
    
    # Check if file exists
    if not os.path.exists(file_path):
        flash('File not found on disk!', 'error')
        return redirect(url_for('admin'))
    
    return send_file(file_path, as_attachment=True, download_name=file_name)

@app.route('/admin/update-status', methods=['POST'])
@require_login
def update_status():
    """Update submission status via AJAX"""
    try:
        data = request.get_json()
        submission_id = data.get('submission_id')
        status = data.get('status')
        assigned_to = data.get('assigned_to', '')
        admin_notes = data.get('admin_notes', '')
        
        conn, cursor = _open_db()
        
        cursor.execute('''
            UPDATE essay_submissions 
            SET status = ?, assigned_to = ?, admin_notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (status, assigned_to, admin_notes, submission_id))
        
        conn.commit()

        # Notify student about status update (best-effort)
        try:
            cursor.execute('SELECT first_name, last_name, email FROM essay_submissions WHERE id = ?', (submission_id,))
            row = cursor.fetchone()
            if row:
                first_name, last_name, email = row
                if email:
                    full_name = f"{first_name} {last_name}".strip()
                    _send_email(
                        to_email=email,
                        subject=f"Your submission status updated to {status}",
                        body=(
                            f"Hello {full_name or 'there'},\n\n"
                            f"Your essay submission (ID: {submission_id}) status is now: {status}.\n\n"
                            f"Thank you,\nEnglish Essay Writing Team"
                        ),
                        reply_to=CONTACT_RECIPIENT or None
                    )
        except Exception:
            pass

        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete-submission', methods=['POST'])
@require_login
def delete_submission():
    """Delete a submission only if its status is 'completed'. Removes file as well."""
    try:
        data = request.get_json()
        submission_id = data.get('submission_id')
        if not submission_id:
            return jsonify({'error': 'submission_id is required'}), 400

        conn, cursor = _open_db()

        # Fetch status and file path
        cursor.execute('SELECT status, file_path FROM essay_submissions WHERE id = ?', (submission_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Submission not found'}), 404

        status, file_path = row
        if status != 'completed':
            conn.close()
            return jsonify({'error': 'Only completed submissions can be deleted'}), 400

        # Delete record
        cursor.execute('DELETE FROM essay_submissions WHERE id = ?', (submission_id,))
        conn.commit()
        conn.close()

        # Remove file from disk if present
        try:
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/bulk-update-status', methods=['POST'])
@require_login
def bulk_update_status():
    """Bulk update submission statuses"""
    try:
        data = request.get_json()
        from_status = data.get('from_status')
        to_status = data.get('to_status')
        
        conn, cursor = _open_db()
        
        # Update all submissions with the specified status
        cursor.execute('''
            UPDATE essay_submissions 
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE status = ?
        ''', (to_status, from_status))
        
        count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'count': count})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete-review', methods=['POST'])
@require_login
def delete_review():
    """Delete a review by id"""
    try:
        data = request.get_json()
        review_id = data.get('review_id')
        if not review_id:
            return jsonify({'error': 'review_id is required'}), 400

        conn, cursor = _open_db()
        cursor.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        if deleted == 0:
            return jsonify({'error': 'Review not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/approve-review', methods=['POST'])
@require_login
def approve_review():
    """Approve a review by id (makes it visible publicly)."""
    conn = None
    try:
        data = request.get_json()
        review_id = data.get('review_id')
        if not review_id:
            return jsonify({'error': 'review_id is required'}), 400

        conn, cursor = _open_db()
        cursor.execute('UPDATE reviews SET is_approved = %s WHERE id = %s', (True, review_id))
        updated = cursor.rowcount
        conn.commit()

        if updated == 0:
            return jsonify({'error': 'Review not found'}), 404
        return jsonify({'success': True})
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
@app.route('/admin/set-password', methods=['POST'])
@require_login
def admin_set_password():
    try:
        data = request.get_json()
        new_password = (data.get('password') or '').strip()
        if new_password != ADMIN_PASSWORD:
            return jsonify({'error': 'Password must match ADMIN_PASSWORD. Update env vars and restart the app.'}), 400
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400

        hpw = hash_password(new_password)
        conn, cursor = _open_db()
        cursor.execute('UPDATE admin_users SET password_hash = ? WHERE username = ?', (hpw, ADMIN_USERNAME))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

IMPROVE_ALLOWED_EXTENSIONS = {'pdf', 'docx'}
IMPROVE_MAX_BYTES = 10 * 1024 * 1024
IMPROVE_MAX_CHARS = int(os.environ.get('IMPROVE_MAX_CHARS', '10000'))
IMPROVE_MAX_PAGES = int(os.environ.get('IMPROVE_MAX_PAGES', '10'))
IMPROVE_JOB_TIMEOUT_SECONDS = 20
AI_CHECKER_ENABLED = os.environ.get('AI_CHECKER_ENABLED', 'true').lower() in {'1', 'true', 'yes', 'on'}
SPELLING_ALLOWLIST = {
    'Bader', 'Kuwait', 'GCC', 'MENA', 'SaaS', 'STEM', 'API', 'APIs', 'COVID', 'COVID-19',
    'Python', 'Flask', 'Postgres', 'PostgreSQL', 'SQL', 'NoSQL', 'GitHub', 'Render',
    'IELTS', 'TOEFL', 'SAT', 'GRE', 'GPA', 'UK', 'USA', 'UAE', 'EU', 'UN', 'UNESCO',
    'Arabic', 'Islam', 'Qatar', 'Oman', 'Bahrain', 'Riyadh', 'Jeddah', 'Dammam'
}
_IMPROVE_NLP = None
_IMPROVE_ALLOWLIST_CACHE = None

def _ensure_submissions_table():
    conn, cursor = _open_db()
    try:
        if _is_postgres():
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS submissions (
                    id SERIAL PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    mode TEXT NOT NULL,
                    extracted_text TEXT NOT NULL,
                    ai_results_json TEXT,
                    status TEXT DEFAULT 'new'
                )
            ''')
        else:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    mode TEXT NOT NULL,
                    extracted_text TEXT NOT NULL,
                    ai_results_json TEXT,
                    status TEXT DEFAULT 'new'
                )
            ''')
        conn.commit()
    finally:
        conn.close()

def _read_upload_bytes(file_storage):
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size > IMPROVE_MAX_BYTES:
        return None, "File too large. Max size is 10MB."
    data = file_storage.stream.read()
    file_storage.stream.seek(0)
    return data, None

def _extract_text_from_upload(file_storage):
    filename = (file_storage.filename or '').strip()
    if '.' not in filename:
        return None, "File must have a .pdf or .docx extension.", None
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in IMPROVE_ALLOWED_EXTENSIONS:
        return None, "Unsupported file type. Only PDF and DOCX are allowed.", None

    data, err = _read_upload_bytes(file_storage)
    if err:
        return None, err, None

    warning = None

    if ext == 'pdf':
        try:
            import pypdf
        except Exception:
            return None, "PDF support is unavailable. Please install pypdf.", None
        reader = pypdf.PdfReader(io.BytesIO(data))
        pages = reader.pages or []
        if len(pages) > IMPROVE_MAX_PAGES:
            warning = f"This document is long; we analyzed the first {IMPROVE_MAX_PAGES} pages. You may upload a shorter section."
            pages = pages[:IMPROVE_MAX_PAGES]
        parts = []
        for page in pages:
            try:
                parts.append(page.extract_text() or '')
            except Exception:
                parts.append('')
        text = "\n".join(parts).strip()
        if not text:
            return None, "No text could be extracted from the PDF.", None
        return text, None, warning

    try:
        import docx
    except Exception:
        return None, "DOCX support is unavailable. Please install python-docx.", None
    document = docx.Document(io.BytesIO(data))
    text = "\n".join(p.text for p in document.paragraphs).strip()
    if not text:
        return None, "No text could be extracted from the DOCX.", None
    return text, None, warning

def _ensure_improve_jobs_table():
    conn, cursor = _open_db()
    try:
        if _is_postgres():
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS improve_jobs (
                    job_id TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT NOT NULL,
                    progress INTEGER DEFAULT 0,
                    message TEXT,
                    result_html TEXT,
                    error TEXT,
                    extracted_text TEXT,
                    warning TEXT
                )
            ''')
            cursor.execute('''
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = ?
            ''', ('improve_jobs',))
            cols = {row[0] for row in cursor.fetchall()}
            if 'job_id' not in cols and 'id' in cols:
                try:
                    cursor.execute('ALTER TABLE improve_jobs RENAME COLUMN id TO job_id')
                    cols.remove('id')
                    cols.add('job_id')
                except Exception:
                    pass
            if 'job_id' not in cols:
                try:
                    cursor.execute('ALTER TABLE improve_jobs ADD COLUMN job_id TEXT')
                except Exception:
                    pass
            for col, col_type in (
                ('updated_at', 'TIMESTAMP'),
                ('status', 'TEXT'),
                ('progress', 'INTEGER'),
                ('message', 'TEXT'),
                ('result_html', 'TEXT'),
                ('error', 'TEXT'),
                ('extracted_text', 'TEXT'),
                ('warning', 'TEXT')
            ):
                if col not in cols:
                    try:
                        cursor.execute(f'ALTER TABLE improve_jobs ADD COLUMN {col} {col_type}')
                    except Exception:
                        pass
        else:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS improve_jobs (
                    job_id TEXT PRIMARY KEY,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT NOT NULL,
                    progress INTEGER DEFAULT 0,
                    message TEXT,
                    result_html TEXT,
                    error TEXT,
                    extracted_text TEXT,
                    warning TEXT
                )
            ''')
            cursor.execute('PRAGMA table_info(improve_jobs)')
            cols = {row[1] for row in cursor.fetchall()}
            if 'job_id' not in cols and 'id' in cols:
                try:
                    cursor.execute('ALTER TABLE improve_jobs RENAME COLUMN id TO job_id')
                except Exception:
                    pass
                cursor.execute('PRAGMA table_info(improve_jobs)')
                cols = {row[1] for row in cursor.fetchall()}
            if 'job_id' not in cols:
                try:
                    cursor.execute('ALTER TABLE improve_jobs ADD COLUMN job_id TEXT')
                except Exception:
                    pass
            for col, col_type in (
                ('updated_at', 'DATETIME'),
                ('status', 'TEXT'),
                ('progress', 'INTEGER'),
                ('message', 'TEXT'),
                ('result_html', 'TEXT'),
                ('error', 'TEXT'),
                ('extracted_text', 'TEXT'),
                ('warning', 'TEXT')
            ):
                if col not in cols:
                    try:
                        cursor.execute(f'ALTER TABLE improve_jobs ADD COLUMN {col} {col_type}')
                    except Exception:
                        pass
        conn.commit()
    finally:
        conn.close()

def _create_improve_job(extracted_text, warning):
    _ensure_improve_jobs_table()
    job_id = uuid.uuid4().hex
    conn, cursor = _open_db()
    try:
        cursor.execute('''
            INSERT INTO improve_jobs (job_id, status, progress, message, extracted_text, warning, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (job_id, 'queued', 0, 'Queued', extracted_text, warning))
        conn.commit()
    finally:
        conn.close()
    return job_id

def _update_improve_job(job_id, status=None, progress=None, message=None, result_html=None, error=None, warning=None):
    fields = []
    values = []
    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if progress is not None:
        fields.append("progress = ?")
        values.append(progress)
    if message is not None:
        fields.append("message = ?")
        values.append(message)
    if result_html is not None:
        fields.append("result_html = ?")
        values.append(result_html)
    if error is not None:
        fields.append("error = ?")
        values.append(error)
    if warning is not None:
        fields.append("warning = ?")
        values.append(warning)
    if not fields:
        return
    fields.append("updated_at = CURRENT_TIMESTAMP")
    values.append(job_id)
    conn, cursor = _open_db()
    try:
        cursor.execute(f"UPDATE improve_jobs SET {', '.join(fields)} WHERE job_id = ?", values)
        conn.commit()
    finally:
        conn.close()

def _build_result_html(ai_result, highlighted_text):
    if not ai_result:
        return '<p class="form__help">No issues detected.</p>'
    summary = ai_result.get('summary') or {}
    issues = ai_result.get('issues') or []
    sentences = ai_result.get('sentences') or []
    parts = []
    parts.append('<div class="improve-legend">')
    parts.append(
        f'<span><span class="improve-legend-swatch" style="background:#dc2626"></span> Spelling ({summary.get("spelling", 0)})</span>'
    )
    parts.append(
        f'<span><span class="improve-legend-swatch" style="background:#f59e0b"></span> Grammar ({summary.get("grammar", 0)})</span>'
    )
    parts.append(
        f'<span><span class="improve-legend-swatch" style="background:#2563eb"></span> Style ({summary.get("style", 0)})</span>'
    )
    parts.append('</div>')
    parts.append('<h4 class="section__title" style="font-size: var(--fs-2xl); margin-bottom: var(--space-4);">Highlighted Text</h4>')
    parts.append(f'<div class="improve-highlight">{highlighted_text}</div>')
    parts.append('<h4 class="section__title" style="font-size: var(--fs-2xl); margin: var(--space-6) 0 var(--space-3);">Issues</h4>')
    if not issues:
        parts.append('<p class="form__help">No issues detected.</p>')
        return ''.join(parts)

    issues_by_sentence = {}
    general_issues = []
    for issue in issues:
        sid = issue.get('sentence_id')
        if sid is None:
            general_issues.append(issue)
        else:
            issues_by_sentence.setdefault(sid, []).append(issue)

    if sentences:
        display_idx = 0
        for sentence in sentences:
            sentence_issues = issues_by_sentence.get(sentence.get('id'), [])
            if not sentence_issues:
                continue
            display_idx += 1
            sentence_text = escape(sentence.get('text') or '')
            parts.append('<div style="margin-top: var(--space-6);">')
            parts.append(f'<p class="form__help"><strong>Sentence {display_idx}:</strong> {sentence_text}</p>')
            rewrite_issues = [i for i in sentence_issues if i.get('is_rewrite')]
            regular_issues = [i for i in sentence_issues if not i.get('is_rewrite')]
            kind_priority = {'grammar': 0, 'spelling': 1, 'style': 2}
            regular_issues.sort(key=lambda item: (kind_priority.get(item.get('kind'), 3), item.get('start', 0)))
            if rewrite_issues:
                for issue in rewrite_issues:
                    message = escape(issue.get('message') or '')
                    if message:
                        parts.append(f'<div class="improve-rewrite"><strong>Suggested rewrite:</strong> {message}</div>')
            if regular_issues:
                parts.append('<ul class="improve-issues">')
            for issue in regular_issues:
                kind = escape(issue.get('kind') or 'grammar')
                message = escape(issue.get('message') or 'Issue detected.')
                parts.append(f'<li><span class="improve-issues__kind improve-issues__kind-{kind}">{kind.replace("_", " ").title()}</span>')
                parts.append(f'<span class="improve-issues__message">{message}</span>')
                suggestions = issue.get('suggestions') or []
                if suggestions:
                    safe_suggestions = ", ".join(escape(s) for s in suggestions if s)
                    if safe_suggestions:
                        parts.append(f'<span class="improve-issues__suggestions">Suggestions: {safe_suggestions}</span>')
                parts.append('</li>')
            if regular_issues:
                parts.append('</ul>')
            parts.append('</div>')

    if general_issues:
        parts.append('<div style="margin-top: var(--space-6);">')
        parts.append('<p class="form__help"><strong>Other notes:</strong></p>')
        parts.append('<ul class="improve-issues">')
        for issue in general_issues:
            kind = escape(issue.get('kind') or 'grammar')
            message = escape(issue.get('message') or 'Issue detected.')
            parts.append(f'<li><span class="improve-issues__kind improve-issues__kind-{kind}">{kind.replace("_", " ").title()}</span>')
            parts.append(f'<span class="improve-issues__message">{message}</span>')
            suggestions = issue.get('suggestions') or []
            if suggestions:
                safe_suggestions = ", ".join(escape(s) for s in suggestions if s)
                if safe_suggestions:
                    parts.append(f'<span class="improve-issues__suggestions">Suggestions: {safe_suggestions}</span>')
            parts.append('</li>')
        parts.append('</ul>')
        parts.append('</div>')
    return ''.join(parts)

def _process_improve_job(job_id, extracted_text, warning):
    start_time = time.time()
    last_progress = -1

    def _progress_cb(value, message=None):
        nonlocal last_progress
        value = max(0, min(100, int(value)))
        if value == last_progress and not message:
            return
        last_progress = value
        _update_improve_job(job_id, progress=value, message=message)

    try:
        if len(extracted_text or '') > IMPROVE_MAX_CHARS:
            message = "This document is too long for online analysis. Please upload a shorter section or use Human Review."
            app.logger.info("Improve job %s rejected len=%s reason=too_long", job_id, len(extracted_text))
            _update_improve_job(job_id, status='error', progress=100, error=message, message=message)
            return
        _update_improve_job(job_id, status='running', progress=5, message='Preparing analysis...', warning=warning)
        ai_result, analysis_error, analysis_warning = _run_local_analysis(
            extracted_text,
            progress_cb=_progress_cb,
            timeout_seconds=IMPROVE_JOB_TIMEOUT_SECONDS,
            start_time=start_time
        )
        if analysis_error:
            _update_improve_job(job_id, status='error', progress=100, error=analysis_error, message=analysis_error)
            return
        combined_warning = warning
        if analysis_warning:
            if combined_warning:
                combined_warning = f"{combined_warning} {analysis_warning}"
            else:
                combined_warning = analysis_warning
        highlighted = _build_highlighted_html(extracted_text, ai_result.get('issues', []))
        result_html = _build_result_html(ai_result, highlighted)
        final_message = combined_warning if combined_warning else 'Complete'
        _update_improve_job(job_id, status='done', progress=100, result_html=result_html, message=final_message, warning=combined_warning)
    except Exception as exc:
        app.logger.exception("Improve AI background job failed")
        err_msg = str(exc).strip() or "Writing checker failed unexpectedly. Please try again or use Human Review."
        _update_improve_job(job_id, status='error', progress=100, error=err_msg, message=err_msg)

def _run_local_analysis(text, progress_cb=None, timeout_seconds=20, start_time=None):
    if not AI_CHECKER_ENABLED:
        return None, "Writing checker unavailable. Please use Human Review.", None

    text = text or ''

    global _IMPROVE_NLP
    global _IMPROVE_ALLOWLIST_CACHE

    warnings = []

    if start_time is None:
        start_time = time.time()

    def _timed_out():
        return (time.time() - start_time) > timeout_seconds

    def _time_guard():
        if _timed_out():
            if not warnings or 'partial' not in warnings[-1].lower():
                warnings.append('Returned partial results due to time limits.')
            return True
        return False

    if _IMPROVE_ALLOWLIST_CACHE is None:
        allowlist = set(SPELLING_ALLOWLIST)
        allowlist_path = os.path.join(os.path.dirname(__file__), 'data', 'allowlist.txt')
        try:
            with open(allowlist_path, 'r', encoding='utf-8') as handle:
                for line in handle:
                    word = line.strip()
                    if word:
                        allowlist.add(word)
        except Exception:
            pass
        _IMPROVE_ALLOWLIST_CACHE = {w.lower() for w in allowlist}

    allowlist_lower = _IMPROVE_ALLOWLIST_CACHE

    try:
        from spellchecker import SpellChecker
    except Exception as exc:
        SpellChecker = None
        warnings.append(f"Spelling checker unavailable: {exc}")

    try:
        from proselint.tools import lint as proselint_lint
    except Exception as exc:
        proselint_lint = None
        warnings.append(f"Style checker unavailable: {exc}")

    try:
        from wordfreq import zipf_frequency
    except Exception:
        zipf_frequency = None

    nlp = None
    try:
        import spacy
        if _IMPROVE_NLP is None:
            _IMPROVE_NLP = spacy.load('en_core_web_sm', disable=['ner'])
        nlp = _IMPROVE_NLP
    except Exception as exc:
        warnings.append(f"NLP engine unavailable: {exc}")
        nlp = None

    issues = []

    if progress_cb:
        progress_cb(8, "Preparing checks...")

    email_pattern = re.compile(r'\b[\w\.-]+@[\w\.-]+\.\w+\b')
    url_pattern = re.compile(r'\b(?:https?://|www\.)\S+\b')
    ignored_spans = [(m.start(), m.end()) for m in email_pattern.finditer(text)]
    ignored_spans += [(m.start(), m.end()) for m in url_pattern.finditer(text)]

    def _overlaps_ignored(start, end):
        for s, e in ignored_spans:
            if start < e and end > s:
                return True
        return False

    def _sentence_id_for_span(start, end, sentences):
        for s in sentences:
            if start >= s['start'] and end <= s['end']:
                return s['id']
        return None

    def _add_issue(start, end, kind, message, suggestions=None, no_highlight=False, sentence_id=None, is_rewrite=False):
        if start is None or end is None:
            return
        if start < 0 or end <= start or start > len(text):
            return
        issues.append({
            'start': start,
            'end': end,
            'kind': kind,
            'message': message,
            'suggestions': suggestions or [],
            'sentence_id': sentence_id,
            'no_highlight': no_highlight,
            'is_rewrite': is_rewrite
        })

    def _is_code_like(word):
        return any(sym in word for sym in ('_', '/', '\\', '::', '->', '=>', '()')) or (word[:1].islower() and any(ch.isupper() for ch in word[1:]))

    def _preprocess_sentences(source_text):
        if not source_text.strip():
            return []
        end_punct_count = len(re.findall(r'[.!?]', source_text))
        words = re.findall(r"[^\W\d_]+(?:'[^\W\d_]+)?", source_text)
        if end_punct_count >= 2 or len(words) <= 12:
            return []
        patterns = [
            r"\bhi\b",
            r"\bhello\b",
            r"\bhey\b",
            r"\bthis is\b",
            r"\bmy name is\b",
            r"\bhow are\b",
            r"\bhow is\b",
            r"\bi am\b",
            r"\bi'm\b"
        ]
        points = []
        for pattern in patterns:
            for match in re.finditer(pattern, source_text, flags=re.IGNORECASE):
                idx = match.start()
                if idx != 0:
                    points.append(idx)
        if not points:
            return []
        points = sorted(set(points))
        segments = []
        last = 0
        for idx in points:
            segment = source_text[last:idx].strip()
            if segment:
                segments.append(segment)
            last = idx
        tail = source_text[last:].strip()
        if tail:
            segments.append(tail)
        refined = []
        for segment in segments:
            seg_words = re.findall(r"[^\W\d_]+(?:'[^\W\d_]+)?", segment)
            if len(seg_words) <= 15:
                refined.append(segment)
                continue
            split_match = re.search(r"\b(and|but|because|so)\b", segment, flags=re.IGNORECASE)
            if split_match:
                idx = split_match.start()
                left = segment[:idx].strip()
                right = segment[idx:].strip()
                if left:
                    refined.append(left)
                if right:
                    refined.append(right)
            else:
                refined.append(segment)
        return refined

    def _rewrite_templates(sentence_text):
        base = sentence_text.strip()
        if not base:
            return []
        lowered = base.lower()
        name_match = re.search(r'\bthis is\s+([A-Za-z][\w-]*)', base, flags=re.IGNORECASE)
        name = name_match.group(1) if name_match else None
        if name:
            name = name.capitalize()
        casual = None
        formal = None
        if 'how are you' in lowered and 'this is' in lowered:
            casual = f"Hi, this is {name or 'your name'}. How are you doing today?"
            formal = f"Hello, this is {name or 'your name'}. How are you doing today?"
        return [s for s in (casual, formal) if s]

    def _apply_rewrite_rules(sentence_text):
        updated = sentence_text
        updated = re.sub(r"\b(i)(?=\b)", 'I', updated)
        updated = re.sub(r"\biI\b", 'I', updated)
        updated = re.sub(r"\bthis is\s+([A-Za-z][\w-]*)", lambda m: f"this is {m.group(1).capitalize()}", updated, flags=re.IGNORECASE)
        updated = re.sub(r"\bmy name is\s+([A-Za-z][\w-]*)", lambda m: f"my name is {m.group(1).capitalize()}", updated, flags=re.IGNORECASE)
        updated = updated.strip()
        if updated and updated[0].islower():
            updated = updated[0].upper() + updated[1:]
        return updated

    def _split_on_conjunction(sentence_text):
        match = re.search(r"\b(and|but|because|so)\b", sentence_text, flags=re.IGNORECASE)
        if not match:
            return None
        idx = match.start()
        left = sentence_text[:idx].strip()
        right = sentence_text[idx:].strip()
        if left and right:
            return f"{left}. {right[0].upper() + right[1:] if right else right}"
        return None

    def _with_end_punct(sentence_text):
        stripped = sentence_text.rstrip()
        if not stripped:
            return sentence_text
        if stripped[-1] in '.!?':
            return stripped
        return stripped + '.'

    doc = None
    if nlp is not None:
        try:
            doc = nlp(text)
        except Exception as exc:
            doc = None
            warnings.append(f"NLP processing failed: {exc}")

    sentences = []
    sentence_flags = {}

    if doc is not None:
        for sent in doc.sents:
            segment = sent.text
            if segment.strip():
                sentences.append({
                    'id': len(sentences) + 1,
                    'start': sent.start_char,
                    'end': sent.end_char,
                    'text': segment.strip()
                })
        sentence_flags = {s['id']: set() for s in sentences}
    else:
        s_start = 0
        for match in re.finditer(r'[.!?]+', text):
            s_end = match.end()
            segment = text[s_start:s_end]
            if segment.strip():
                sentences.append({
                    'id': len(sentences) + 1,
                    'start': s_start,
                    'end': s_end,
                    'text': segment.strip()
                })
            s_start = s_end
        if s_start < len(text):
            segment = text[s_start:]
            if segment.strip():
                sentences.append({
                    'id': len(sentences) + 1,
                    'start': s_start,
                    'end': len(text),
                    'text': segment.strip()
                })
        sentence_flags = {s['id']: set() for s in sentences}

    if not sentences:
        pseudo = _preprocess_sentences(text)
        offset = 0
        sentences = []
        for segment in pseudo:
            start = text.find(segment, offset)
            if start == -1:
                start = offset
            end = start + len(segment)
            sentences.append({
                'id': len(sentences) + 1,
                'start': start,
                'end': end,
                'text': segment.strip()
            })
            offset = end
        sentence_flags = {s['id']: set() for s in sentences}

    if progress_cb:
        progress_cb(18, "Checking grammar...")

    comparatives = {'more', 'less', 'rather', 'better', 'worse', 'higher', 'lower', 'greater', 'fewer'}
    greetings = {'hi', 'hello', 'dear'}
    obj_pronouns = {'me', 'him', 'her', 'us', 'them'}
    subj_pronouns = {'i', 'he', 'she', 'we', 'they'}
    determiners = {'a', 'an', 'the', 'this', 'that', 'these', 'those', 'my', 'your', 'his', 'her', 'our', 'their', 'its'}
    count_nouns = {
        'idea', 'problem', 'issue', 'result', 'study', 'case', 'factor', 'reason', 'example',
        'argument', 'method', 'solution', 'benefit', 'risk', 'model', 'approach', 'paper', 'essay',
        'work', 'research', 'analysis', 'assignment', 'project', 'thesis', 'conclusion', 'summary'
    }

    def _token_number(token):
        numbers = token.morph.get('Number')
        if numbers:
            return numbers[0]
        if token.lower_ in {'he', 'she', 'it', 'this', 'that', 'someone', 'everybody'}:
            return 'Sing'
        if token.lower_ in {'they', 'we', 'you'}:
            return 'Plur'
        return None

    def _verb_number(token):
        numbers = token.morph.get('Number')
        if numbers:
            return numbers[0]
        if token.tag_ == 'VBZ':
            return 'Sing'
        if token.tag_ == 'VBP':
            return 'Plur'
        return None

    if doc is not None:
        for token in doc:
            if _time_guard():
                break
            if token.is_space or token.is_punct:
                continue
            if _overlaps_ignored(token.idx, token.idx + len(token.text)):
                continue

            if token.pos_ == 'PROPN' and token.text and token.text[0].islower() and not token.text.isupper():
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Proper noun should be capitalized.', [token.text.capitalize()], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))
                sentence_flags.get(_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences), set()).add('proper_noun')

            if token.lower_ in allowlist_lower and token.text and token.text[0].islower() and not token.text.isupper():
                proper = token.text.capitalize()
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Proper noun should be capitalized.', [proper], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))
                sentence_flags.get(_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences), set()).add('proper_noun')

            if token.dep_ in {'nsubj', 'nsubjpass'} and token.head.pos_ in {'VERB', 'AUX'}:
                subj_num = _token_number(token)
                verb_num = _verb_number(token.head)
                if subj_num and verb_num and subj_num != verb_num:
                    _add_issue(token.head.idx, token.head.idx + len(token.head.text), 'grammar', 'Subject and verb may not agree.', [], sentence_id=_sentence_id_for_span(token.head.idx, token.head.idx + len(token.head.text), sentences))

            if token.pos_ == 'NOUN' and token.tag_ == 'NN' and token.lemma_.lower() in count_nouns:
                has_det = any(child.dep_ in {'det', 'poss'} for child in token.children)
                prev_token = token.nbor(-1) if token.i > 0 else None
                prev_det = prev_token is not None and prev_token.lower_ in determiners
                if not has_det and not prev_det:
                    suggestion = 'a'
                    if token.text and token.text[0].lower() in 'aeiou':
                        suggestion = 'an'
                    _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Missing article before singular noun.', [suggestion, 'the'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ in obj_pronouns and token.dep_ in {'nsubj', 'nsubjpass'}:
                subj_map = {'me': 'I', 'him': 'he', 'her': 'she', 'us': 'we', 'them': 'they'}
                suggestion = subj_map.get(token.lower_, '')
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Use subject pronoun in this position.', [suggestion] if suggestion else [], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ in subj_pronouns and token.dep_ in {'dobj', 'pobj', 'obj', 'iobj'}:
                obj_map = {'i': 'me', 'he': 'him', 'she': 'her', 'we': 'us', 'they': 'them'}
                suggestion = obj_map.get(token.lower_, '')
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Use object pronoun in this position.', [suggestion] if suggestion else [], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            next_token = token.nbor(1) if token.i + 1 < len(doc) else None
            prev_token = token.nbor(-1) if token.i > 0 else None

            if token.lower_ == 'your' and next_token and next_token.lower_ in {'are', 'were'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', "Did you mean \"you're\"?", ["you're"], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == "you're" and next_token and next_token.pos_ in {'NOUN', 'PROPN', 'ADJ'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Did you mean "your"?', ['your'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == 'their' and next_token and next_token.lower_ in {'is', 'are', 'was', 'were'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Did you mean "there"?', ['there'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == 'there' and next_token and next_token.pos_ in {'NOUN', 'PROPN'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Did you mean "their"?', ['their'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == "they're" and next_token and next_token.pos_ in {'NOUN', 'PROPN'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Did you mean "their"?', ['their'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == 'its' and next_token and next_token.lower_ in {'is', 'was', 'has'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', "Did you mean \"it's\"?", ["it's"], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == "it's" and next_token and next_token.pos_ in {'NOUN', 'PROPN'}:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Did you mean "its"?', ['its'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

            if token.lower_ == 'then' and prev_token and prev_token.lower_ in comparatives:
                _add_issue(token.idx, token.idx + len(token.text), 'grammar', 'Use "than" for comparisons.', ['than'], sentence_id=_sentence_id_for_span(token.idx, token.idx + len(token.text), sentences))

    if progress_cb:
        progress_cb(32, "Checking sentence rules...")

    for sentence in sentences:
        if _time_guard():
            break
        sent_text = text[sentence['start']:sentence['end']]
        sent_id = sentence['id']
        words = list(re.finditer(r"[^\W\d_]+(?:'[^\W\d_]+)?", sent_text))
        if len(words) < 2:
            continue

        first_alpha = re.search(r'[A-Za-z]', sent_text)
        if first_alpha:
            pos = sentence['start'] + first_alpha.start()
            if text[pos:pos + 1].islower():
                sentence_flags.setdefault(sent_id, set()).add('capitalization')
                _add_issue(pos, pos + 1, 'grammar', 'Capitalize the start of the sentence.', [], sentence_id=sent_id)

        stripped = sent_text.rstrip()
        if stripped and stripped[-1] not in '.!?':
            end_pos = sentence['start'] + len(stripped)
            if end_pos > sentence['start']:
                sentence_flags.setdefault(sent_id, set()).add('end_punctuation')
                _add_issue(end_pos - 1, end_pos, 'grammar', 'Add ending punctuation.', ['.'], sentence_id=sent_id)

        if re.search(r"\bi\b", sent_text):
            for match in re.finditer(r"\bi\b", sent_text):
                _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Capitalize "I" when used as a pronoun.', ['I'], sentence_id=sent_id)

        for match in re.finditer(r"\b(youre|dont|cant|isnt|im|ive|ill|weve|theyre)\b", sent_text, flags=re.IGNORECASE):
            missing = match.group(1).lower()
            mapping = {
                'youre': "you're",
                'dont': "don't",
                'cant': "can't",
                'isnt': "isn't",
                'im': "I'm",
                'ive': "I've",
                'ill': "I'll",
                'weve': "we've",
                'theyre': "they're"
            }
            suggestion = mapping.get(missing, "")
            _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Missing apostrophe in contraction.', [suggestion] if suggestion else [], sentence_id=sent_id)

        for match in re.finditer(r"\b([A-Za-z]+)\s+\1\b", sent_text, flags=re.IGNORECASE):
            _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'style', 'Repeated word.', [], sentence_id=sent_id)

        first_word = words[0].group(0).lower()
        if first_word in greetings and len(words) >= 2:
            name_token = words[1]
            after_name_index = sentence['start'] + name_token.end()
            if after_name_index < len(text) and text[after_name_index] != ',':
                _add_issue(sentence['start'] + name_token.start(), sentence['start'] + name_token.end(), 'grammar', 'Add a comma after the greeting name.', [','], sentence_id=sent_id)

        if len(words) > 12 and ',' not in sent_text:
            if re.search(r"\b(and|but|because|so)\b", sent_text, flags=re.IGNORECASE):
                sentence_flags.setdefault(sent_id, set()).add('run_on')
                conj_match = re.search(r"\b(and|but|because|so)\b", sent_text, flags=re.IGNORECASE)
                if conj_match:
                    _add_issue(sentence['start'] + conj_match.start(), sentence['start'] + conj_match.end(), 'grammar', 'Possible run-on sentence; consider a comma or split it.', [], sentence_id=sent_id)

        if re.search(r"\b(a|an)\s+[A-Za-z]", sent_text, flags=re.IGNORECASE):
            for match in re.finditer(r"\b(a|an)\s+([A-Za-z][\w-]*)", sent_text, flags=re.IGNORECASE):
                article = match.group(1).lower()
                word = match.group(2)
                lower = word.lower()
                vowel = lower[0] in 'aeiou'
                special_an = lower.startswith(('honest', 'hour', 'heir'))
                special_a = lower.startswith(('university', 'unicorn', 'user'))
                if article == 'a' and (vowel or special_an):
                    _add_issue(sentence['start'] + match.start(1), sentence['start'] + match.start(1) + 1, 'grammar', 'Use "an" before vowel sounds.', ['an'], sentence_id=sent_id)
                if article == 'an' and (special_a or (not vowel and not special_an)):
                    _add_issue(sentence['start'] + match.start(1), sentence['start'] + match.start(1) + 2, 'grammar', 'Use "a" before consonant sounds.', ['a'], sentence_id=sent_id)

        if re.search(r"\bpeople\s+is\b", sent_text, flags=re.IGNORECASE):
            match = re.search(r"\bpeople\s+is\b", sent_text, flags=re.IGNORECASE)
            _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Use "people are" for plural subject.', ['people are'], sentence_id=sent_id)

        if re.search(r"\bresults\s+shows\b", sent_text, flags=re.IGNORECASE):
            match = re.search(r"\bresults\s+shows\b", sent_text, flags=re.IGNORECASE)
            _add_issue(sentence['start'] + match.start(), sentence['start'] + match.end(), 'grammar', 'Use "results show" for plural subject.', ['results show'], sentence_id=sent_id)

        if re.search(r"\b(he|she|it)\s+([a-z]+)\b", sent_text, flags=re.IGNORECASE):
            for match in re.finditer(r"\b(he|she|it)\s+([a-z]+)\b", sent_text, flags=re.IGNORECASE):
                verb = match.group(2)
                if not verb.endswith('s') and verb not in {'is', 'was', 'has', 'does'}:
                    _add_issue(sentence['start'] + match.start(2), sentence['start'] + match.end(2), 'grammar', 'Add -s for third-person singular.', [], sentence_id=sent_id)

    if progress_cb:
        progress_cb(48, "Checking mechanics...")

    for match in re.finditer(r' {2,}', text):
        if _time_guard():
            break
        _add_issue(match.start(), match.end(), 'grammar', 'Extra spaces.', ['Use a single space.'])

    for match in re.finditer(r'\s+([,.;:!?])', text):
        if _time_guard():
            break
        _add_issue(match.start(), match.end(), 'grammar', 'Remove space before punctuation.', [])

    for match in re.finditer(r'([,.;:!?])([A-Za-z])', text):
        if _time_guard():
            break
        _add_issue(match.start(1), match.start(2) + 1, 'grammar', 'Add a space after punctuation.', [])

    if progress_cb:
        progress_cb(60, "Checking spelling...")

    if SpellChecker:
        spell = SpellChecker()
        spell.word_frequency.load_words(list(allowlist_lower))
        tokens_for_spell = []
        if doc is not None:
            tokens_for_spell = list(doc)
        else:
            for match in re.finditer(r"[^\W\d_]+(?:'[^\W\d_]+)?", text):
                tokens_for_spell.append(match)
        total_tokens = max(1, len(tokens_for_spell))
        for idx, token in enumerate(tokens_for_spell):
            if _time_guard():
                break
            if doc is not None:
                word = token.text
                start = token.idx
                end = token.idx + len(token.text)
                if token.is_space or token.is_punct:
                    continue
                if token.like_url or token.like_email:
                    continue
                if token.pos_ == 'PROPN':
                    continue
            else:
                word = token.group(0)
                start = token.start()
                end = token.end()
                if _overlaps_ignored(start, end):
                    continue
            if not word:
                continue
            if word.isupper() and len(word) > 1:
                continue
            if any(ch.isdigit() for ch in word):
                continue
            if _is_code_like(word):
                continue
            if '-' in word:
                continue
            if word[0].isupper():
                continue
            lower = word.lower()
            if lower in allowlist_lower:
                continue
            if zipf_frequency and zipf_frequency(lower, 'en') >= 4.5:
                continue
            try:
                unknown = lower in spell.unknown([lower])
            except Exception:
                app.logger.info("Spellcheck skip len=%s reason=candidates_error", len(lower))
                continue
            if not unknown:
                continue
            try:
                cand = spell.candidates(lower) or []
                candidates = list(cand)
            except Exception:
                app.logger.info("Spellcheck skip len=%s reason=candidates_error", len(lower))
                continue
            suggestions = [c for c in candidates if c != lower][:3]
            _add_issue(start, end, 'spelling', 'Possible spelling mistake.', suggestions, sentence_id=_sentence_id_for_span(start, end, sentences))
            if progress_cb and idx % 80 == 0:
                progress_cb(60 + int(15 * idx / total_tokens), "Checking spelling...")

    if progress_cb:
        progress_cb(78, "Checking style...")

    if proselint_lint:
        try:
            style_hits = proselint_lint(text) or []
        except Exception:
            style_hits = []
        for hit in style_hits:
            if _time_guard():
                break
            if not isinstance(hit, dict):
                continue
            start = hit.get('start')
            end = hit.get('end')
            message = (hit.get('message') or '').strip()
            if start is None or end is None or not message:
                continue
            msg_lower = message.lower()
            if not any(key in msg_lower for key in ('capitalize', 'punctuation', 'comma', 'period', 'a/an', 'article', 'agreement', 'subject')):
                continue
            _add_issue(start, end, 'style', message, [], sentence_id=_sentence_id_for_span(start, end, sentences))

    for sentence in sentences:
        sid = sentence.get('id')
        flags = sentence_flags.get(sid, set())
        key_flags = {'capitalization', 'end_punctuation', 'proper_noun', 'run_on'}
        if len(flags.intersection(key_flags)) >= 2:
            original = sentence.get('text') or ''
            suggestion = _apply_rewrite_rules(original)
            split_suggestion = _split_on_conjunction(suggestion)
            if split_suggestion:
                suggestion = split_suggestion
            suggestion = _with_end_punct(suggestion)
            templates = _rewrite_templates(original)
            if templates:
                for template in templates:
                    _add_issue(sentence['start'], sentence['end'], 'style', template, [], no_highlight=True, sentence_id=sid, is_rewrite=True)
            if suggestion and suggestion.strip() and suggestion.strip() != original.strip():
                _add_issue(sentence['start'], sentence['end'], 'style', suggestion, [], no_highlight=True, sentence_id=sid, is_rewrite=True)

    def _dedupe_issues(items):
        seen = set()
        result = []
        last_end = -1
        for item in sorted(items, key=lambda i: (i['start'], -(i['end'] - i['start']))):
            key = (item['start'], item['end'], item['kind'], item['message'])
            if key in seen:
                continue
            if item.get('no_highlight'):
                seen.add(key)
                result.append(item)
                continue
            if item['start'] < last_end:
                continue
            seen.add(key)
            result.append(item)
            last_end = item['end']
        return result

    issues = _dedupe_issues(issues)

    if progress_cb:
        progress_cb(95, "Finalizing...")

    summary = {
        'spelling': sum(1 for i in issues if i['kind'] == 'spelling' and not i.get('no_highlight')),
        'grammar': sum(1 for i in issues if i['kind'] == 'grammar' and not i.get('no_highlight')),
        'style': sum(1 for i in issues if i['kind'] == 'style' and not i.get('no_highlight') and not i.get('is_rewrite'))
    }

    warning = '; '.join(warnings) if warnings else None
    return {'issues': issues, 'summary': summary, 'sentences': sentences}, None, warning
def _build_highlighted_html(text, issues):
    if not issues:
        return Markup(escape(text))
    pieces = []
    last_index = 0
    def _issue_length(issue):
        return (issue.get('end', 0) or 0) - (issue.get('start', 0) or 0)

    sorted_issues = sorted(issues, key=lambda i: (i.get('start', 0), -_issue_length(i)))
    for issue in sorted_issues:
        if issue.get('no_highlight'):
            continue
        start = issue.get('start', 0) or 0
        end = issue.get('end', 0) or 0
        if start < last_index or end <= start or start > len(text):
            continue
        pieces.append(escape(text[last_index:start]))
        segment = escape(text[start:end])
        issue_kind = issue.get('kind') or issue.get('type') or 'style'
        pieces.append(f'<span class="improve-issue-{issue_kind}">{segment}</span>')
        last_index = end
    pieces.append(escape(text[last_index:]))
    return Markup(''.join(pieces))

@app.route('/improve', methods=['GET'])
def improve():
    return render_template(
        'improve.html',
        ai_result=None,
        highlighted_text=None,
        extracted_text=None,
        error=None,
        ai_results_json=None,
        human_notice=None,
        prefill_text=''
    )

@app.route('/improve/ai', methods=['POST'])
def improve_ai():
    extracted_text = ''
    try:
        text_input = (request.form.get('text') or '').strip()
        file = request.files.get('file')
        warning = None

        if file and file.filename:
            extracted_text, err, warning = _extract_text_from_upload(file)
            if err:
                return render_template(
                    'improve.html',
                    ai_result=None,
                    highlighted_text=None,
                    extracted_text=None,
                    error=err,
                    ai_results_json=None,
                    human_notice=None,
                    prefill_text=text_input
                )
            if warning:
                app.logger.info("Improve AI truncated PDF to %s pages", IMPROVE_MAX_PAGES)
        else:
            extracted_text = text_input

        if not extracted_text:
            return render_template(
                'improve.html',
                ai_result=None,
                highlighted_text=None,
                extracted_text=None,
                error="Please paste text or upload a file.",
                ai_results_json=None,
                human_notice=None,
                prefill_text=''
            )

        if len(extracted_text) > IMPROVE_MAX_CHARS:
            message = "This document is too long for online analysis. Please upload a shorter section or use Human Review."
            app.logger.info("Improve AI rejected len=%s reason=too_long", len(extracted_text))
            job_id = _create_improve_job('', warning)
            _update_improve_job(job_id, status='error', progress=100, error=message, message=message)
            return redirect(url_for('improve_progress', job_id=job_id))

        job_id = _create_improve_job(extracted_text, warning)
        threading.Thread(
            target=_process_improve_job,
            args=(job_id, extracted_text, warning),
            daemon=True
        ).start()
        return redirect(url_for('improve_progress', job_id=job_id))
    except Exception:
        app.logger.exception("Improve AI failed")
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error="Writing checker failed. Please use Human Review.",
            ai_results_json=None,
            human_notice=None,
            prefill_text=extracted_text
        )

@app.route('/improve/human', methods=['POST'])
def improve_human():
    text_input = (request.form.get('text') or '').strip()
    file = request.files.get('file')
    provided_text = (request.form.get('extracted_text') or '').strip()
    ai_results_json = (request.form.get('ai_results_json') or '').strip()

    extracted_text = ''
    warning = None
    if provided_text:
        extracted_text = provided_text
    elif file and file.filename:
        extracted_text, err, warning = _extract_text_from_upload(file)
        if err:
            return render_template(
                'improve.html',
                ai_result=None,
                highlighted_text=None,
                extracted_text=None,
                error=err,
                ai_results_json=None,
                human_notice=None
            )
    else:
        extracted_text = text_input

    if not extracted_text:
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error="Please paste text or upload a file.",
            ai_results_json=None,
            human_notice=None
        )

    if len(extracted_text) > IMPROVE_MAX_CHARS:
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error="Text is too long. Please submit 10,000 characters or fewer.",
            ai_results_json=None,
            human_notice=None
        )

    mode = 'after_ai' if ai_results_json else 'human_only'
    _ensure_submissions_table()
    conn, cursor = _open_db()
    try:
        cursor.execute('''
            INSERT INTO submissions (mode, extracted_text, ai_results_json, status)
            VALUES (?, ?, ?, ?)
        ''', (mode, extracted_text, ai_results_json or None, 'new'))
        conn.commit()
    finally:
        conn.close()

    notice = "Submitted for human review."
    if warning:
        notice = f"{notice} {warning}"
    return render_template(
        'improve.html',
        ai_result=None,
        highlighted_text=None,
        extracted_text=None,
        error=None,
        ai_results_json=None,
        human_notice=notice,
        prefill_text=''
    )

@app.route('/admin/submissions', methods=['GET'])
@require_login
def admin_submissions():
    _ensure_submissions_table()
    conn, cursor = _open_db()
    cursor.execute('''
        SELECT id, created_at, mode, extracted_text, ai_results_json, status
        FROM submissions
        ORDER BY created_at DESC
    ''')
    rows = cursor.fetchall()
    conn.close()

    submissions = []
    for row in rows:
        submissions.append({
            'id': row[0],
            'created_at': row[1],
            'mode': row[2],
            'extracted_text': row[3],
            'ai_results_json': row[4],
            'status': row[5]
        })
    return render_template('admin_submissions.html', submissions=submissions)

@app.route('/improve/progress/<job_id>', methods=['GET'])
def improve_progress(job_id):
    _ensure_improve_jobs_table()
    return render_template('improve_progress.html', job_id=job_id)

@app.route('/improve/status/<job_id>', methods=['GET'])
def improve_status(job_id):
    _ensure_improve_jobs_table()
    conn, cursor = _open_db()
    cursor.execute('''
        SELECT status, progress, message, updated_at, error
        FROM improve_jobs
        WHERE job_id = ?
    ''', (job_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return jsonify({'status': 'error', 'progress': 100, 'message': 'Job not found.'}), 404
    status, progress, message, updated_at, error = row
    if status == 'running' and updated_at:
        last_update = updated_at
        if isinstance(last_update, str):
            try:
                last_update = datetime.fromisoformat(last_update)
            except Exception:
                last_update = None
        if isinstance(last_update, datetime):
            age = (datetime.utcnow() - last_update).total_seconds()
            if age > 120:
                stale_message = "The server restarted while processing. Please try again or use Human Review."
                app.logger.info("Improve job %s marked stale after %ss", job_id, int(age))
                _update_improve_job(job_id, status='error', progress=100, error=stale_message, message=stale_message)
                status = 'error'
                progress = 100
                message = stale_message
    payload = {
        'status': status,
        'progress': progress or 0,
        'message': message or error or ''
    }
    if status == 'done':
        payload['result_url'] = url_for('improve_result', job_id=job_id)
    return jsonify(payload)

@app.route('/improve/result/<job_id>', methods=['GET'])
def improve_result(job_id):
    _ensure_improve_jobs_table()
    conn, cursor = _open_db()
    cursor.execute('''
        SELECT status, message, extracted_text, result_html, error, warning
        FROM improve_jobs
        WHERE job_id = ?
    ''', (job_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return render_template('improve.html', ai_result=None, highlighted_text=None, extracted_text=None, error="Result not found.", ai_results_json=None, human_notice=None, prefill_text='')
    status, message, extracted_text, result_html, error, warning = row
    if status != 'done' or not result_html:
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error=error or message or "Writing checker failed. Please try again or use Human Review.",
            ai_results_json=None,
            human_notice=None,
            prefill_text=extracted_text or ''
        )
    return render_template(
        'improve_results.html',
        result_html=result_html,
        ai_results_json=result_html,
        extracted_text=extracted_text or '',
        warning=warning
    )

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Development server (not used in production)
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(debug=debug, host='0.0.0.0', port=port)
