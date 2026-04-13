import hmac
import os
from datetime import datetime, timedelta

from flask import flash, jsonify, redirect, render_template, request, session, send_file, url_for

import app_services

_ensure_submissions_table = None


def configure(*, ensure_submissions_table):
    global _ensure_submissions_table
    _ensure_submissions_table = ensure_submissions_table


def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password required', 'error')
            return render_template('login.html')

        conn, cursor = app_services.open_db()
        cursor.execute('SELECT * FROM admin_users WHERE username = ? AND is_active = ?', (username, True))
        user = cursor.fetchone()
        env_match = hmac.compare_digest(password, app_services.admin_password())

        if not user:
            conn.close()
            flash('Invalid credentials', 'error')
            return render_template('login.html')

        if not user[2] or user[2] == '':
            if not env_match:
                conn.close()
                flash('Invalid credentials', 'error')
                return render_template('login.html')
            new_hash = app_services.hash_password(app_services.admin_password())
            cursor.execute('UPDATE admin_users SET password_hash = ? WHERE id = ?', (new_hash, user[0]))
        else:
            password_ok = app_services.verify_password(password, user[2])
            if not password_ok and not env_match:
                conn.close()
                flash('Invalid credentials', 'error')
                return render_template('login.html')
            if env_match and not password_ok:
                new_hash = app_services.hash_password(app_services.admin_password())
                cursor.execute('UPDATE admin_users SET password_hash = ? WHERE id = ?', (new_hash, user[0]))

        if user[2] and not user[2].startswith('$2b$') and not user[2].startswith('$2a$'):
            upgraded = app_services.hash_password(password)
            cursor.execute('UPDATE admin_users SET password_hash = ? WHERE id = ?', (upgraded, user[0]))
        cursor.execute('UPDATE admin_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
        conn.commit()
        conn.close()

        session['admin_logged_in'] = True
        session['admin_username'] = user[1]
        session['admin_id'] = user[0]

        flash('Login successful!', 'success')
        return redirect(url_for('admin'))

    return render_template('login.html')


def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))


def admin():
    conn, cursor = app_services.open_db()
    cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (app_services.admin_username(),))
    pw_row = cursor.fetchone()
    password_set = bool(pw_row and pw_row[0])
    conn.close()

    if not password_set:
        return redirect(url_for('admin_setup'))
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))

    _ensure_submissions_table()
    conn, cursor = app_services.open_db()

    cursor.execute('SELECT COUNT(*) FROM essay_submissions')
    total_submissions = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM essay_submissions WHERE status = 'pending'")
    pending_submissions = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM essay_submissions WHERE status = 'completed'")
    completed_submissions = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM submissions')
    improve_total = cursor.fetchone()[0]

    cursor.execute('SELECT * FROM essay_submissions ORDER BY created_at DESC')
    all_submissions = cursor.fetchall()

    cursor.execute('''
        SELECT id, submission_id, created_at, mode, extracted_text, status,
               requester_name, requester_email, requester_phone
        FROM submissions
        ORDER BY created_at DESC
        LIMIT 25
    ''')
    improve_rows = cursor.fetchall()
    improve_submissions = []
    for row in improve_rows:
        text_preview = row[4] or ''
        if len(text_preview) > 160:
            text_preview = text_preview[:160].rstrip() + "..."
        improve_submissions.append({
            'id': row[0],
            'submission_id': row[1],
            'created_at': row[2],
            'mode': row[3],
            'preview': text_preview,
            'status': row[5],
            'requester_name': row[6],
            'requester_email': row[7],
            'requester_phone': row[8],
        })

    cursor.execute('''
        SELECT id, name, university, rating, review_text, created_at, is_approved
        FROM reviews
        ORDER BY created_at DESC
    ''')
    all_reviews = cursor.fetchall()

    cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (app_services.admin_username(),))
    pw_row = cursor.fetchone()
    password_set = bool(pw_row and pw_row[0])
    conn.close()

    stats = {
        'total_submissions': total_submissions,
        'pending_submissions': pending_submissions,
        'completed_submissions': completed_submissions,
        'improve_submissions': improve_total,
    }

    return render_template(
        'admin.html',
        stats=stats,
        submissions=all_submissions,
        improve_submissions=improve_submissions,
        password_set=password_set,
        reviews=all_reviews,
    )


def admin_analytics():
    conn, cursor = app_services.open_db()
    cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (app_services.admin_username(),))
    pw_row = cursor.fetchone()
    password_set = bool(pw_row and pw_row[0])
    conn.close()

    if not password_set:
        return redirect(url_for('admin_setup'))
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))

    today = datetime.now().date()
    yesterday = today - timedelta(days=1)
    start_date = today - timedelta(days=6)

    conn, cursor = app_services.open_db()
    cursor.execute('''
        SELECT visit_date, COUNT(*)
        FROM visits
        WHERE visit_date >= ?
        GROUP BY visit_date
    ''', (start_date.isoformat(),))
    rows = cursor.fetchall()
    counts_by_date = {}
    for row in rows:
        date_value = row[0]
        date_key = date_value.isoformat() if hasattr(date_value, 'isoformat') else str(date_value)
        counts_by_date[date_key] = row[1]

    cursor.execute('''
        SELECT first_path, COUNT(*)
        FROM visits
        WHERE visit_date = ? AND first_path IS NOT NULL AND first_path != ''
        GROUP BY first_path
        ORDER BY COUNT(*) DESC
        LIMIT 10
    ''', (today.isoformat(),))
    top_rows = cursor.fetchall()

    cursor.execute('''
        SELECT country_code, COUNT(*)
        FROM visits
        WHERE visit_date = ? AND country_code IS NOT NULL AND country_code != ''
        GROUP BY country_code
        ORDER BY COUNT(*) DESC
        LIMIT 10
    ''', (today.isoformat(),))
    country_rows = cursor.fetchall()
    conn.close()

    last_7_days = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_key = day.isoformat()
        last_7_days.append({'date': day_key, 'count': counts_by_date.get(day_key, 0)})

    top_pages = [{'path': row[0], 'count': row[1]} for row in top_rows]
    top_countries = [{'country': row[0], 'count': row[1]} for row in country_rows]

    return render_template(
        'admin_analytics.html',
        today_count=counts_by_date.get(today.isoformat(), 0),
        yesterday_count=counts_by_date.get(yesterday.isoformat(), 0),
        last_7_days=last_7_days,
        top_pages=top_pages,
        top_countries=top_countries,
    )


def admin_setup():
    conn, cursor = app_services.open_db()
    cursor.execute('SELECT password_hash FROM admin_users WHERE username = ?', (app_services.admin_username(),))
    pw_row = cursor.fetchone()
    password_set = bool(pw_row and pw_row[0])
    conn.close()

    if password_set:
        return redirect(url_for('login'))

    return render_template('admin_setup.html', username=app_services.admin_username())


def admin_setup_post():
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if not password or not confirm_password:
        flash('Please fill in all fields', 'error')
        return redirect(url_for('admin_setup'))
    if password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('admin_setup'))
    if password != app_services.admin_password():
        flash('Password must match ADMIN_PASSWORD. Update env vars and restart the app.', 'error')
        return redirect(url_for('admin_setup'))
    if len(password) < 8:
        flash('Password must be at least 8 characters long', 'error')
        return redirect(url_for('admin_setup'))

    conn, cursor = app_services.open_db()
    cursor.execute('''
        UPDATE admin_users
        SET password_hash = ?
        WHERE username = ?
    ''', (app_services.hash_password(password), app_services.admin_username()))
    conn.commit()
    conn.close()

    flash('Password set successfully! You can now log in.', 'success')
    return redirect(url_for('login'))


def admin_reset():
    if not app_services.admin_reset_token():
        return jsonify({'error': 'Not found'}), 404

    payload = request.get_json(silent=True) or {}
    token = request.headers.get('X-Admin-Reset-Token') or payload.get('token') or request.form.get('token')
    if not token or token != app_services.admin_reset_token():
        return jsonify({'error': 'Invalid token'}), 403

    conn, cursor = app_services.open_db()
    cursor.execute(
        'UPDATE admin_users SET password_hash = ? WHERE username = ?',
        (app_services.hash_password(app_services.admin_password()), app_services.admin_username()),
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'message': 'DB synced to ADMIN_PASSWORD; restart required only if ADMIN_PASSWORD changed.',
    })


def edit_submission(submission_id):
    conn, cursor = app_services.open_db()

    if request.method == 'POST':
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

        try:
            cursor.execute('SELECT first_name, last_name, email, submission_id FROM essay_submissions WHERE id = ?', (submission_id,))
            row = cursor.fetchone()
            if row:
                first_name, last_name, email, sub_id = row
                if email:
                    full_name = f"{first_name} {last_name}".strip()
                    app_services.send_email(
                        to_email=email,
                        subject=f"Your submission status updated to {status}",
                        body=(
                            f"Hello {full_name or 'there'},\n\n"
                            f"Your essay submission (ID: {sub_id}) status is now: {status}.\n\n"
                            f"Thank you,\nEnglish Essay Writing Team"
                        ),
                        reply_to=app_services.contact_recipient() or None,
                    )
        except Exception:
            pass

        conn.close()
        flash('Submission updated successfully!', 'success')
        return redirect(url_for('admin'))

    cursor.execute('SELECT * FROM essay_submissions WHERE id = ?', (submission_id,))
    submission = cursor.fetchone()
    conn.close()

    if not submission:
        flash('Submission not found!', 'error')
        return redirect(url_for('admin'))

    return render_template('edit_submission.html', submission=submission)


def download_file(submission_id):
    conn, cursor = app_services.open_db()
    cursor.execute('SELECT file_path, file_name FROM essay_submissions WHERE id = ?', (submission_id,))
    result = cursor.fetchone()
    conn.close()

    if not result or not result[0]:
        flash('File not found!', 'error')
        return redirect(url_for('admin'))

    file_path, file_name = result
    file_path = file_path.replace('\\', '/')
    if not os.path.exists(file_path):
        flash('File not found on disk!', 'error')
        return redirect(url_for('admin'))

    return send_file(file_path, as_attachment=True, download_name=file_name)


def update_status():
    try:
        data = request.get_json()
        submission_id = data.get('submission_id')
        status = data.get('status')
        assigned_to = data.get('assigned_to', '')
        admin_notes = data.get('admin_notes', '')

        conn, cursor = app_services.open_db()
        cursor.execute('''
            UPDATE essay_submissions
            SET status = ?, assigned_to = ?, admin_notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (status, assigned_to, admin_notes, submission_id))
        conn.commit()

        try:
            cursor.execute('SELECT first_name, last_name, email FROM essay_submissions WHERE id = ?', (submission_id,))
            row = cursor.fetchone()
            if row:
                first_name, last_name, email = row
                if email:
                    full_name = f"{first_name} {last_name}".strip()
                    app_services.send_email(
                        to_email=email,
                        subject=f"Your submission status updated to {status}",
                        body=(
                            f"Hello {full_name or 'there'},\n\n"
                            f"Your essay submission (ID: {submission_id}) status is now: {status}.\n\n"
                            f"Thank you,\nEnglish Essay Writing Team"
                        ),
                        reply_to=app_services.contact_recipient() or None,
                    )
        except Exception:
            pass

        conn.close()
        return jsonify({'success': True})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


def delete_submission():
    try:
        data = request.get_json()
        submission_id = data.get('submission_id')
        if not submission_id:
            return jsonify({'error': 'submission_id is required'}), 400

        conn, cursor = app_services.open_db()
        cursor.execute('SELECT status, file_path FROM essay_submissions WHERE id = ?', (submission_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Submission not found'}), 404

        status, file_path = row
        if status != 'completed':
            conn.close()
            return jsonify({'error': 'Only completed submissions can be deleted'}), 400

        cursor.execute('DELETE FROM essay_submissions WHERE id = ?', (submission_id,))
        conn.commit()
        conn.close()

        try:
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass
        return jsonify({'success': True})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


def bulk_update_status():
    try:
        data = request.get_json()
        from_status = data.get('from_status')
        to_status = data.get('to_status')

        conn, cursor = app_services.open_db()
        cursor.execute('''
            UPDATE essay_submissions
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE status = ?
        ''', (to_status, from_status))
        count = cursor.rowcount
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'count': count})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


def delete_review():
    try:
        data = request.get_json()
        review_id = data.get('review_id')
        if not review_id:
            return jsonify({'error': 'review_id is required'}), 400

        conn, cursor = app_services.open_db()
        cursor.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        if deleted == 0:
            return jsonify({'error': 'Review not found'}), 404
        return jsonify({'success': True})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


def approve_review():
    conn = None
    try:
        data = request.get_json()
        review_id = data.get('review_id')
        if not review_id:
            return jsonify({'error': 'review_id is required'}), 400

        conn, cursor = app_services.open_db()
        cursor.execute('UPDATE reviews SET is_approved = %s WHERE id = %s', (True, review_id))
        updated = cursor.rowcount
        conn.commit()

        if updated == 0:
            return jsonify({'error': 'Review not found'}), 404
        return jsonify({'success': True})
    except Exception as exc:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        return jsonify({'error': str(exc)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def admin_set_password():
    try:
        data = request.get_json()
        new_password = (data.get('password') or '').strip()
        if new_password != app_services.admin_password():
            return jsonify({'error': 'Password must match ADMIN_PASSWORD. Update env vars and restart the app.'}), 400
        if len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400

        conn, cursor = app_services.open_db()
        cursor.execute(
            'UPDATE admin_users SET password_hash = ? WHERE username = ?',
            (app_services.hash_password(new_password), app_services.admin_username()),
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
