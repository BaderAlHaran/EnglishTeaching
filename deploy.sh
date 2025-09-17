#!/bin/bash
# Quick deployment script for Render

echo "🚀 Preparing Essay Writing Service for Render deployment..."

# Check if git is available
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi

# Check if all required files exist
echo "📁 Checking required files..."

required_files=(
    "requirements.txt"
    "wsgi.py"
    "Procfile"
    "render.yaml"
    "app.py"
    "templates/admin.html"
    "templates/login.html"
)

for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "❌ Missing required file: $file"
        exit 1
    else
        echo "✅ Found: $file"
    fi
done

# Check git status
echo "📊 Checking git status..."
if [ -n "$(git status --porcelain)" ]; then
    echo "⚠️  You have uncommitted changes. Committing them now..."
    git add .
    git commit -m "Prepare for Render deployment - $(date)"
fi

# Push to GitHub
echo "📤 Pushing to GitHub..."
git push origin main

echo ""
echo "✅ Deployment preparation complete!"
echo ""
echo "🚀 Next steps:"
echo "1. Go to https://render.com"
echo "2. Create a new Web Service"
echo "3. Connect your GitHub repository"
echo "4. Use these settings:"
echo "   - Build Command: pip install -r requirements.txt"
echo "   - Start Command: gunicorn wsgi:app"
echo "   - Plan: Free"
echo ""
echo "🔐 Don't forget to set environment variables:"
echo "   - FLASK_ENV=production"
echo "   - ADMIN_USERNAME=admin"
echo "   - ADMIN_PASSWORD=(your secure password)"
echo "   - ADMIN_EMAIL=admin@yourdomain.com"
echo ""
echo "📚 See DEPLOYMENT.md for detailed instructions."
