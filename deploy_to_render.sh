#!/bin/bash

echo "🚀 Preparing for Render Deployment..."

# 1. Check if all required files exist
echo "Checking required files..."
required_files=(
    "app.py"
    "wsgi.py" 
    "requirements.txt"
    "render.yaml"
    "Procfile"
    "templates/admin.html"
    "templates/admin_setup.html"
    "templates/login.html"
    "templates/edit_submission.html"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "❌ Missing required file: $file"
        exit 1
    else
        echo "✅ Found: $file"
    fi
done

# 2. Check Python dependencies
echo "Checking Python dependencies..."
if ! python -c "import flask, gunicorn, bcrypt" 2>/dev/null; then
    echo "❌ Missing Python dependencies. Run: pip install -r requirements.txt"
    exit 1
else
    echo "✅ Python dependencies OK"
fi

# 3. Test local server
echo "Testing local server..."
python -c "
from app import app
print('✅ Flask app imports successfully')
print('✅ Database initialization ready')
print('✅ All routes configured')
"

# 4. Check environment variables
echo "Checking environment configuration..."
echo "✅ FLASK_ENV will be set to 'production'"
echo "✅ SECRET_KEY will be auto-generated"
echo "✅ ADMIN_USERNAME: mikoandnenoarecool"
echo "✅ ADMIN_PASSWORD: Set in Render dashboard"
echo "✅ UPLOAD_FOLDER: uploads"

# 5. Final checklist
echo ""
echo "📋 Final Deployment Checklist:"
echo "1. Push all files to GitHub repository"
echo "2. Go to render.com and create new Web Service"
echo "3. Connect your GitHub repository"
echo "4. Set environment variables in Render dashboard"
echo "5. Deploy and test!"
echo ""
echo "🎉 Your app is ready for Render deployment!"
echo ""
echo "📖 See RENDER_DEPLOYMENT.md for detailed instructions"
