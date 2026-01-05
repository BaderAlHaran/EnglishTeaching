from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify, send_file, send_from_directory
from flask_cors import CORS
import sqlite3
import hashlib
import bcrypt
import secrets
import os
import mimetypes
import uuid
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import re
import logging
import resend

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
# Defaults are safe/non-verbose and do not log to console
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'mikoandnenoarecool')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', secrets.token_urlsafe(32))
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@essaywriting.com')
FROM_EMAIL = os.environ.get('FROM_EMAIL', ADMIN_EMAIL)
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
CONTACT_RECIPIENT = os.environ.get('CONTACT_RECIPIENT', ADMIN_EMAIL)
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

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
    
    # Enforce single admin username
    cursor.execute('DELETE FROM admin_users WHERE username != ?', (ADMIN_USERNAME,))

    # Create default admin user if missing; if ADMIN_PASSWORD not provided, leave hash NULL and require setup
    admin_pw = os.environ.get('ADMIN_PASSWORD')
    pw_hash = hash_password(admin_pw) if admin_pw else None
    if _is_postgres():
        cursor.execute('''
            INSERT INTO admin_users (username, password_hash, email)
            VALUES (?, ?, ?)
            ON CONFLICT (username) DO NOTHING
        ''', (ADMIN_USERNAME, pw_hash, ADMIN_EMAIL))
    else:
        cursor.execute('''
            INSERT OR IGNORE INTO admin_users (username, password_hash, email)
            VALUES (?, ?, ?)
        ''', (ADMIN_USERNAME, pw_hash, ADMIN_EMAIL))
    
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
        
        cursor.execute('SELECT * FROM admin_users WHERE username = %s AND is_active = %s', (username, True))
        user = cursor.fetchone()
        
        # First-time setup: if user exists with no password yet, set it now
        if user and (not user[2] or user[2] == ''):
            new_hash = hash_password(password)
            cursor.execute('UPDATE admin_users SET password_hash = ? WHERE id = ?', (new_hash, user[0]))
            conn.commit()
        elif not user or not verify_password(password, user[2]):
            conn.close()
            flash('Invalid credentials', 'error')
            return render_template('login.html')
        
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
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400

        hpw = hash_password(new_password)
        conn, cursor = _open_db()
        cursor.execute('UPDATE admin_users SET password_hash = ? WHERE username = ?', (hpw, 'mikoandnenoarecool'))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Development server (not used in production)
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(debug=debug, host='0.0.0.0', port=port)
