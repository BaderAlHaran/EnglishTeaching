from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app)

DATABASE = 'essay_service.db'

# Admin credentials (in production, use environment variables)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'EssayAdmin2024!')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@essaywriting.com')

def init_database():
    """Initialize database with tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Admin users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Essay submissions table
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
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Reviews table
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
    
    # Create default admin user
    password_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
    cursor.execute('''
        INSERT OR IGNORE INTO admin_users (username, password_hash, email)
        VALUES (?, ?, ?)
    ''', (ADMIN_USERNAME, password_hash, ADMIN_EMAIL))
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    """Verify password against hash"""
    return hash_password(password) == password_hash

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

# Static file routes
@app.route('/<path:filename>')
def static_files(filename):
    """Serve static files (CSS, JS, images, etc.)"""
    if not filename.startswith('api/') and not filename.startswith('templates/'):
        try:
            mimetype = mimetypes.guess_type(filename)[0] or 'text/plain'
            return send_file(filename, mimetype=mimetype)
        except FileNotFoundError:
            return jsonify({'error': 'File not found'}), 404
    else:
        return jsonify({'error': 'Not found'}), 404

# Routes
@app.route('/')
def index():
    return send_file('index.html')

@app.route('/about')
def about():
    return send_file('about.html')

@app.route('/essay-form')
def essay_form():
    return send_file('essay-form.html')

@app.route('/terms')
def terms():
    return send_file('terms.html')

@app.route('/privacy')
def privacy():
    return send_file('privacy.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password required', 'error')
            return render_template('login.html')
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM admin_users WHERE username = ? AND is_active = ?', (username, True))
        user = cursor.fetchone()
        
        if not user or not verify_password(password, user[2]):
            conn.close()
            flash('Invalid credentials', 'error')
            return render_template('login.html')
        
        # Update last login
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
@require_login
def admin():
    # Get statistics
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Get submission stats
    cursor.execute('SELECT COUNT(*) FROM essay_submissions')
    total_submissions = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM essay_submissions WHERE status = "pending"')
    pending_submissions = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM essay_submissions WHERE status = "completed"')
    completed_submissions = cursor.fetchone()[0]
    
    # Get recent submissions
    cursor.execute('''
        SELECT * FROM essay_submissions 
        ORDER BY created_at DESC 
        LIMIT 10
    ''')
    recent_submissions = cursor.fetchall()
    
    conn.close()
    
    stats = {
        'total_submissions': total_submissions,
        'pending_submissions': pending_submissions,
        'completed_submissions': completed_submissions
    }
    
    return render_template('admin.html', stats=stats, submissions=recent_submissions)

@app.route('/submit-essay', methods=['POST'])
def submit_essay():
    """Handle essay form submission"""
    try:
        # Get form data
        data = {
            'submission_id': secrets.token_hex(8),
            'first_name': request.form.get('firstName'),
            'last_name': request.form.get('lastName'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'essay_type': request.form.get('essayType'),
            'academic_level': request.form.get('academicLevel'),
            'subject': request.form.get('subject'),
            'pages': request.form.get('pages'),
            'deadline': request.form.get('deadline'),
            'topic': request.form.get('topic'),
            'instructions': request.form.get('instructions'),
            'citation_style': request.form.get('citationStyle')
        }
        
        # Validate required fields
        required_fields = ['first_name', 'last_name', 'email', 'essay_type', 'academic_level', 'subject', 'pages', 'deadline', 'topic']
        for field in required_fields:
            if not data[field]:
                return jsonify({'error': f'{field} is required'}), 400
        
        # Save to database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO essay_submissions 
            (submission_id, first_name, last_name, email, phone, essay_type, academic_level, 
             subject, pages, deadline, topic, instructions, citation_style)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (data['submission_id'], data['first_name'], data['last_name'], data['email'], 
              data['phone'], data['essay_type'], data['academic_level'], data['subject'], 
              data['pages'], data['deadline'], data['topic'], data['instructions'], data['citation_style']))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'submission_id': data['submission_id']})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/submit-review', methods=['POST'])
def submit_review():
    """Handle review submission"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'university', 'rating', 'review_text']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Save to database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO reviews (name, university, rating, review_text)
            VALUES (?, ?, ?, ?)
        ''', (data['name'], data['university'], data['rating'], data['review_text']))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get-reviews')
def get_reviews():
    """Get approved reviews"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT name, university, rating, review_text, created_at 
        FROM reviews 
        WHERE is_approved = ? 
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
    return jsonify(reviews)

if __name__ == '__main__':
    print("🚀 Starting Simple Essay Writing Service...")
    print("📊 Backend: Python Flask (Simplified)")
    print("🗄️  Database: SQLite")
    print("🌐 URL: http://localhost:5000")
    print("==================================================")
    print(f"🔐 Admin Username: {ADMIN_USERNAME}")
    print(f"🔐 Admin Email: {ADMIN_EMAIL}")
    print("✅ Database initialized successfully")
    app.run(debug=True, host='0.0.0.0', port=5000)
