#!/usr/bin/env python3
"""
Essay Writing Service Runner
"""

import os

if __name__ == '__main__':
    from app import app
    
    # Get port from environment variable (for Render)
    port = int(os.environ.get('PORT', 5000))
    
    # Debug mode only in development
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    app.run(debug=debug, host='0.0.0.0', port=port)
