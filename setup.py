#!/usr/bin/env python3
"""
Setup script for Essay Writing Service
"""
import os
import sys
import subprocess
import sqlite3
import hashlib
import secrets

def install_requirements():
    """Install Python requirements"""
    print("📦 Installing Python requirements...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        return False

def setup_admin_user():
    """Set up admin user with custom credentials"""
    # Non-interactive secure defaults
    username = os.environ.get('ADMIN_USERNAME', 'mekoandnenoarecool')
    password = os.environ.get('ADMIN_PASSWORD', secrets.token_urlsafe(32))
    email = os.environ.get('ADMIN_EMAIL', 'admin@essaywriting.com')
    
    # Hash password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Update database
    try:
        conn = sqlite3.connect('database.sqlite')
        cursor = conn.cursor()
        
        # Update or insert admin user
        cursor.execute('''
            INSERT OR REPLACE INTO admin_users (id, username, password_hash, email, created_at, is_active)
            VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP, ?)
        ''', (username, password_hash, email, True))
        
        conn.commit()
        conn.close()
        
        print("✅ Admin user created successfully!")
        
    except Exception as e:
        print(f"❌ Failed to create admin user: {e}")
        return False
    
    return True

def create_env_file():
    """Create .env file with secure credentials"""
    print("\n🔧 Creating environment configuration...")
    
    env_content = f"""# Essay Writing Service Environment Configuration
SECRET_KEY={secrets.token_hex(32)}
JWT_SECRET={secrets.token_hex(32)}
ADMIN_USERNAME=admin
ADMIN_PASSWORD=EssayAdmin2024!
ADMIN_EMAIL=admin@essaywriting.com
FLASK_ENV=development
FLASK_DEBUG=True
"""
    
    try:
        with open('.env', 'w') as f:
            f.write(env_content)
        print("✅ Environment file created (.env)")
        print("⚠️  Remember to change the admin credentials in .env for production!")
    except Exception as e:
        print(f"❌ Failed to create .env file: {e}")
        return False
    
    return True

def main():
    """Main setup function"""
    print("🚀 Essay Writing Service Setup")
    print("=============================")
    
    # Install requirements
    if not install_requirements():
        sys.exit(1)
    
    # Create environment file
    if not create_env_file():
        sys.exit(1)
    
    # Run the app to initialize database
    print("\n🗄️  Initializing database...")
    try:
        from app import init_database
        init_database()
        print("✅ Database initialized")
    except Exception as e:
        print(f"❌ Failed to initialize database: {e}")
        sys.exit(1)
    
    # Setup admin user
    if not setup_admin_user():
        sys.exit(1)
    
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Run: python app.py")
    print("2. Open: http://localhost:5000")
    print("3. Login with your admin credentials")
    print("\n🔐 Default credentials:")
    print("   Username: admin")
    print("   Password: EssayAdmin2024!")

if __name__ == "__main__":
    main()
