# English Teaching Website

Flask application for essay submissions, writing improvement, contact handling, reviews, and an admin dashboard.

## Stack

- Python 3.11
- Flask
- SQLite locally, Postgres-compatible via `DATABASE_URL`
- Gunicorn on Render
- Vanilla HTML/CSS/JavaScript

## Main features

- Public marketing pages
- Essay submission workflow
- Contact form handling
- Improve Your Writing checker with PDF/DOCX text extraction
- Admin dashboard and analytics
- Email sending through Resend

## Local development

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set required environment variables:

```bash
set ADMIN_PASSWORD=your-password
set SECRET_KEY=your-secret
```

Optional variables:

- `DATABASE_PATH`
- `DATABASE_URL`
- `UPLOAD_FOLDER`
- `CUSTOM_DOMAIN`
- `RESEND_API_KEY`
- `ADMIN_EMAIL`
- `CONTACT_RECIPIENT`

4. Run the app:

```bash
python run.py
```

Or:

```bash
gunicorn wsgi:app
```

## Tests

Run:

```bash
pytest
```

Current tests cover:

- admin login redirect flow
- Improve page load
- Improve validation for empty input
- Improve long-text rejection
- Improve job creation for valid text

## Render deployment

Render reads `render.yaml` and runs:

```bash
pip install -r requirements.txt
gunicorn wsgi:app --bind 0.0.0.0:$PORT
```

Required Render environment variables:

- `ADMIN_PASSWORD`
- `SECRET_KEY`

Recommended:

- `DATABASE_URL` for production database
- `RESEND_API_KEY`
- `ADMIN_EMAIL`
- `CONTACT_RECIPIENT`
- `CUSTOM_DOMAIN`

## Project structure

- `app.py` - main Flask app
- `templates/` - Jinja templates
- `script.js` - frontend behavior
- `styles.css` - site styling
- `data/` - local allowlists and support files
- `tests/` - pytest suite
- `render.yaml` - Render service definition

## Notes

- The Improve UI should stay stable while backend logic evolves.
- Uploaded files and database files are runtime data and should not be treated as source assets.
- `app.py` is currently large and is a good candidate for modularization in the next phase.
