# English Essay Writing Service

A professional essay writing service with a secure admin dashboard, built with Python Flask, SQLite, and modern web technologies.

## Features

### 🎯 **Core Features**
- **Professional Website** - Modern, responsive design
- **Essay Submission Form** - Complete requirements collection
- **Admin Dashboard** - Secure management interface
- **Review System** - Customer feedback collection
- **Export Functionality** - CSV and Word document export

### 🔐 **Security Features**
- **JWT Authentication** - Secure token-based auth
- **Password Hashing** - bcrypt encryption
- **Data Encryption** - AES-256-CBC for sensitive data
- **Rate Limiting** - Protection against abuse
- **Input Validation** - Comprehensive data validation
- **SQL Injection Protection** - Parameterized queries

### 🗄️ **Database Features**
- **SQLite Database** - Lightweight, file-based storage
- **Encrypted Storage** - Sensitive data encryption
- **Automatic Schema** - Database initialization
- **Data Integrity** - Foreign key constraints

## Technology Stack

### **Backend**
- **Python** - Runtime environment
- **Flask** - Web framework
- **SQLite3** - Database
- **hashlib** - Password hashing
- **PyJWT** - JWT authentication
- **python-docx** - Word document generation

### **Frontend**
- **HTML5** - Semantic markup
- **CSS3** - Modern styling with custom properties
- **Vanilla JavaScript** - No framework dependencies
- **Font Awesome** - Icons
- **Google Fonts** - Typography

### **Security**
- **Helmet.js** - Security headers
- **CORS** - Cross-origin resource sharing
- **Rate Limiting** - Request throttling
- **Input Validation** - Data sanitization

## Installation

### **Local Development**

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd essay-writing-service
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python run.py
   ```

4. **Access the application**
   - Website: `http://localhost:5000`
   - Admin Login: `http://localhost:5000/login`
   - Admin Dashboard: `http://localhost:5000/admin`

### **Default Admin Credentials**
- **Username:** `admin`
- **Password:** `EssayAdmin2024!`

## Deployment

### **Render Deployment**

1. **Connect to Render**
   - Push code to GitHub
   - Connect repository to Render
   - Render will automatically detect the `package.json`

2. **Environment Variables**
   - `NODE_ENV=production`
   - `PORT=3000`
   - `ENCRYPTION_KEY` (auto-generated)
   - `JWT_SECRET` (auto-generated)

3. **Deploy**
   - Render will automatically build and deploy
   - Database will be created on first run
   - Admin user will be created automatically

### **Manual Deployment**

1. **Prepare server**
   ```bash
   # Install Node.js 18+
   # Install dependencies
   npm install --production
   ```

2. **Set environment variables**
   ```bash
   export NODE_ENV=production
   export PORT=3000
   export ENCRYPTION_KEY=your-32-character-key
   export JWT_SECRET=your-64-character-secret
   ```

3. **Start the application**
   ```bash
   npm start
   ```

## API Endpoints

### **Authentication**
- `POST /api/auth/login` - Admin login

### **Submissions**
- `GET /api/submissions` - Get all submissions (admin only)
- `POST /api/submissions` - Create new submission
- `PUT /api/submissions/:id/status` - Update submission status (admin only)

### **Reviews**
- `GET /api/reviews` - Get all approved reviews
- `POST /api/reviews` - Create new review

### **Statistics**
- `GET /api/stats` - Get submission statistics (admin only)

### **Export**
- `GET /api/export/csv` - Export submissions as CSV (admin only)

## Database Schema

### **admin_users**
- `id` - Primary key
- `username` - Unique username
- `password_hash` - Hashed password
- `email` - Admin email
- `created_at` - Creation timestamp
- `last_login` - Last login timestamp
- `is_active` - Account status

### **essay_submissions**
- `id` - Primary key
- `submission_id` - Unique submission identifier
- `first_name` - Student first name
- `last_name` - Student last name
- `email` - Student email
- `phone` - Student phone
- `essay_type` - Type of essay
- `academic_level` - Academic level
- `subject` - Subject area
- `pages` - Number of pages
- `deadline` - Submission deadline
- `topic` - Essay topic
- `instructions` - Additional instructions
- `citation_style` - Citation format
- `status` - Submission status
- `assigned_to` - Assigned writer
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp
- `encrypted_data` - Encrypted sensitive data

### **reviews**
- `id` - Primary key
- `name` - Reviewer name
- `university` - University name
- `rating` - Star rating (1-5)
- `review_text` - Review content
- `is_approved` - Approval status
- `created_at` - Creation timestamp

## Security Considerations

### **Data Protection**
- All sensitive data is encrypted using AES-256-CBC
- Passwords are hashed with bcrypt (12 rounds)
- JWT tokens expire after 30 minutes
- Rate limiting prevents brute force attacks

### **Input Validation**
- All inputs are validated and sanitized
- SQL injection protection via parameterized queries
- XSS protection through proper escaping
- File upload restrictions

### **Authentication**
- JWT-based authentication
- Token refresh mechanism
- Session timeout handling
- Secure password requirements

## File Structure

```
essay-writing-service/
├── app.py                 # Main Flask application
├── run.py                 # Simple run script
├── requirements.txt       # Python dependencies
├── setup.py               # Setup script for admin credentials
├── database.sqlite        # SQLite database (created on first run)
├── templates/             # Flask templates
│   ├── login.html         # Admin login page
│   └── admin.html         # Admin dashboard
├── index.html             # Home page
├── essay-form.html        # Essay submission form
├── about.html             # About page
├── terms.html             # Terms and conditions
├── privacy.html           # Privacy policy
├── styles.css             # Main stylesheet
├── script.js              # Frontend JavaScript
└── README.md              # This file
```

## Development

### **Adding New Features**
1. Update the database schema in `app.py`
2. Add routes for new functionality
3. Update the frontend forms to work with the simplified backend
4. Modify the frontend pages as needed

### **Database Migrations**
- The database schema is automatically created on first run
- For production, consider using a proper migration system
- Backup the database regularly

### **Testing**
- Test all API endpoints
- Verify authentication flows
- Check data encryption/decryption
- Test export functionality

## Troubleshooting

### **Common Issues**

1. **Database not created**
   - Check file permissions
   - Ensure SQLite3 is installed
   - Check console for errors

2. **Authentication not working**
   - Verify JWT secret is set
   - Check token expiration
   - Clear browser storage

3. **Export not working**
   - Check file permissions
   - Verify docx.js is loaded
   - Check browser console for errors

### **Logs**
- Check server console for errors
- Monitor database queries
- Check browser console for frontend errors

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review the console logs
3. Check the database integrity
4. Verify all dependencies are installed

## License

MIT License - see LICENSE file for details.
