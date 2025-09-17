#!/usr/bin/env python3
"""
Simple Essay Writing Service Runner
"""

if __name__ == '__main__':
    from simple_app import app
    app.run(debug=True, host='0.0.0.0', port=5000)
