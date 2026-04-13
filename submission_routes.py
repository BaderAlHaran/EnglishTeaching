import os
import uuid

from flask import jsonify, request
from werkzeug.utils import secure_filename

import app_services


def submit_essay():
    try:
        if request.form.get('website'):
            app_services.logger().info("Honeypot field triggered; ignoring submission.")
            return jsonify({'success': True}), 200

        data = {
            'submission_id': secrets_token(),
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
            'terms': request.form.get('terms'),
        }

        required_fields = ['first_name', 'last_name', 'email', 'essay_type', 'academic_level', 'subject', 'pages', 'deadline', 'topic']
        for field in required_fields:
            if not data[field]:
                return jsonify({'error': f'{field} is required'}), 400

        if not app_services.email_regex().match(data['email']):
            return jsonify({'error': 'invalid email'}), 400
        if not data['terms']:
            return jsonify({'error': 'Please accept the terms and conditions'}), 400

        file_path = None
        file_name = None
        file_size = None

        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename and app_services.allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file_path = os.path.join(app_services.upload_folder(), unique_filename)
                file.save(file_path)
                file_name = filename
                file_size = os.path.getsize(file_path)

        conn, cursor = app_services.open_db()
        cursor.execute('''
            INSERT INTO essay_submissions
            (submission_id, first_name, last_name, email, phone, essay_type, academic_level,
             subject, pages, deadline, topic, instructions, citation_style, file_path, file_name, file_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['submission_id'], data['first_name'], data['last_name'], data['email'],
            data['phone'], data['essay_type'], data['academic_level'], data['subject'],
            data['pages'], data['deadline'], data['topic'], data['instructions'], data['citation_style'],
            file_path, file_name, file_size
        ))
        conn.commit()
        conn.close()

        student_email = data['email']
        student_name = f"{data.get('first_name', '').strip()} {data.get('last_name', '').strip()}".strip()
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
            data.get('instructions') or 'None provided',
        ]

        admin_ok, admin_err = app_services.send_email(
            to_email=app_services.admin_email() or app_services.contact_recipient(),
            subject="New submission received",
            body="\n".join(admin_body_lines),
            reply_to=student_email,
        )
        if not admin_ok:
            app_services.logger().error("Admin notification email failed: %s", admin_err)
            return jsonify({'error': 'Unable to send confirmation emails right now. Please try again shortly.'}), 500

        student_ok, student_err = app_services.send_email(
            to_email=student_email,
            subject=f"Submission received: {submission_id}",
            body=(
                f"Hello {student_name or 'there'},\n\n"
                f"We've received your essay request (ID: {submission_id}).\n"
                f"Current status: pending. We'll email you when the status changes.\n\n"
                f"Summary:\n"
                f"- Type: {data.get('essay_type', '')}\n"
                f"- Subject: {data.get('subject', '')}\n"
                f"- Pages: {data.get('pages', '')}\n"
                f"- Deadline: {data.get('deadline', '')}\n\n"
                f"Thank you,\nEnglish Essay Writing Team"
            ),
            reply_to=app_services.admin_email() or app_services.from_email(),
        )
        if not student_ok:
            app_services.logger().warning("Student confirmation email failed for %s: %s", student_email, student_err)

        return jsonify({'success': True, 'submission_id': submission_id})
    except Exception:
        app_services.logger().exception("Error handling submission")
        return jsonify({'error': 'Something went wrong. Please try again later.'}), 500


def submit_review():
    conn = None
    try:
        data = request.get_json(silent=True) or request.form or {}
        required_fields = ['name', 'university', 'rating', 'review_text']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400

        conn, cursor = app_services.open_db()
        cursor.execute('''
            INSERT INTO reviews (name, university, rating, review_text, is_approved)
            VALUES (%s, %s, %s, %s, %s)
        ''', (data['name'], data['university'], data['rating'], data['review_text'], False))
        conn.commit()
        return jsonify({'success': True})
    except Exception as exc:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        app_services.logger().exception("submit-review failed")
        return jsonify({'error': str(exc)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def get_reviews():
    conn, cursor = app_services.open_db()
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
            'created_at': row[4],
        })

    conn.close()
    resp = jsonify(reviews)
    resp.headers['Cache-Control'] = 'no-store, max-age=0'
    return resp


def secrets_token():
    import secrets

    return secrets.token_hex(8)
