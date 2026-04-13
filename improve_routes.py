import io
import json
import math
import os
import re
import secrets
import threading
import time
import uuid
from datetime import datetime

from flask import jsonify, redirect, render_template, request, url_for
from markupsafe import Markup, escape

import app_services
import improve_analysis

IMPROVE_ALLOWED_EXTENSIONS = {'pdf', 'docx'}
IMPROVE_MAX_BYTES = 10 * 1024 * 1024
IMPROVE_MAX_CHARS = int(os.environ.get('IMPROVE_MAX_CHARS', '40000'))
IMPROVE_MAX_PAGES = int(os.environ.get('IMPROVE_MAX_PAGES', '10'))
IMPROVE_JOB_TIMEOUT_SECONDS = 20


def _improve_context():
    return {
        'max_chars': IMPROVE_MAX_CHARS
    }

def _ensure_submissions_table():
    conn, cursor = app_services.open_db()
    try:
        if app_services.is_postgres():
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS submissions (
                    id SERIAL PRIMARY KEY,
                    submission_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    mode TEXT NOT NULL,
                    extracted_text TEXT NOT NULL,
                    ai_results_json TEXT,
                    status TEXT DEFAULT 'new'
                )
            ''')
        else:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    submission_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    mode TEXT NOT NULL,
                    extracted_text TEXT NOT NULL,
                    ai_results_json TEXT,
                    status TEXT DEFAULT 'new'
                )
            ''')
        if app_services.is_postgres():
            cursor.execute('''
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'submissions'
            ''')
            columns = {row[0] for row in cursor.fetchall()}
        else:
            cursor.execute('PRAGMA table_info(submissions)')
            columns = {row[1] for row in cursor.fetchall()}
        if 'requester_name' not in columns:
            cursor.execute('ALTER TABLE submissions ADD COLUMN requester_name TEXT')
        if 'requester_email' not in columns:
            cursor.execute('ALTER TABLE submissions ADD COLUMN requester_email TEXT')
        if 'requester_phone' not in columns:
            cursor.execute('ALTER TABLE submissions ADD COLUMN requester_phone TEXT')
        if 'submission_id' not in columns:
            cursor.execute('ALTER TABLE submissions ADD COLUMN submission_id TEXT')
        conn.commit()
    finally:
        conn.close()

def _read_upload_bytes(file_storage):
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size > IMPROVE_MAX_BYTES:
        return None, "File too large. Max size is 10MB."
    data = file_storage.stream.read()
    file_storage.stream.seek(0)
    return data, None

def _extract_text_from_upload(file_storage):
    filename = (file_storage.filename or '').strip()
    if '.' not in filename:
        return None, "File must have a .pdf or .docx extension.", None
    ext = filename.rsplit('.', 1)[1].lower()
    if ext not in IMPROVE_ALLOWED_EXTENSIONS:
        return None, "Unsupported file type. Only PDF and DOCX are allowed.", None

    data, err = _read_upload_bytes(file_storage)
    if err:
        return None, err, None

    warning = None

    if ext == 'pdf':
        try:
            import pypdf
        except Exception:
            return None, "PDF support is unavailable. Please install pypdf.", None
        reader = pypdf.PdfReader(io.BytesIO(data))
        pages = reader.pages or []
        if len(pages) > IMPROVE_MAX_PAGES:
            warning = f"This document is long; we analyzed the first {IMPROVE_MAX_PAGES} pages. You may upload a shorter section."
            pages = pages[:IMPROVE_MAX_PAGES]
        parts = []
        for page in pages:
            try:
                parts.append(page.extract_text() or '')
            except Exception:
                parts.append('')
        text = "\n".join(parts).strip()
        if not text:
            return None, "No text could be extracted from the PDF.", None
        return text, None, warning

    try:
        import docx
    except Exception:
        return None, "DOCX support is unavailable. Please install python-docx.", None
    document = docx.Document(io.BytesIO(data))
    text = "\n".join(p.text for p in document.paragraphs).strip()
    if not text:
        return None, "No text could be extracted from the DOCX.", None
    return text, None, warning

def _ensure_improve_jobs_table():
    conn, cursor = app_services.open_db()
    try:
        if app_services.is_postgres():
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS improve_jobs (
                    job_id TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT NOT NULL,
                    progress INTEGER DEFAULT 0,
                    message TEXT,
                    result_html TEXT,
                    result_json TEXT,
                    error TEXT,
                    extracted_text TEXT,
                    warning TEXT
                )
            ''')
            cursor.execute('''
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = ?
            ''', ('improve_jobs',))
            cols = {row[0] for row in cursor.fetchall()}
            if 'job_id' not in cols and 'id' in cols:
                try:
                    cursor.execute('ALTER TABLE improve_jobs RENAME COLUMN id TO job_id')
                    cols.remove('id')
                    cols.add('job_id')
                except Exception:
                    pass
            if 'job_id' not in cols:
                try:
                    cursor.execute('ALTER TABLE improve_jobs ADD COLUMN job_id TEXT')
                except Exception:
                    pass
            for col, col_type in (
                ('updated_at', 'TIMESTAMP'),
                ('status', 'TEXT'),
                ('progress', 'INTEGER'),
                ('message', 'TEXT'),
                ('result_html', 'TEXT'),
                ('result_json', 'TEXT'),
                ('error', 'TEXT'),
                ('extracted_text', 'TEXT'),
                ('warning', 'TEXT')
            ):
                if col not in cols:
                    try:
                        cursor.execute(f'ALTER TABLE improve_jobs ADD COLUMN {col} {col_type}')
                    except Exception:
                        pass
        else:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS improve_jobs (
                    job_id TEXT PRIMARY KEY,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT NOT NULL,
                    progress INTEGER DEFAULT 0,
                    message TEXT,
                    result_html TEXT,
                    result_json TEXT,
                    error TEXT,
                    extracted_text TEXT,
                    warning TEXT
                )
            ''')
            cursor.execute('PRAGMA table_info(improve_jobs)')
            cols = {row[1] for row in cursor.fetchall()}
            if 'job_id' not in cols and 'id' in cols:
                try:
                    cursor.execute('ALTER TABLE improve_jobs RENAME COLUMN id TO job_id')
                except Exception:
                    pass
                cursor.execute('PRAGMA table_info(improve_jobs)')
                cols = {row[1] for row in cursor.fetchall()}
            if 'job_id' not in cols:
                try:
                    cursor.execute('ALTER TABLE improve_jobs ADD COLUMN job_id TEXT')
                except Exception:
                    pass
            for col, col_type in (
                ('updated_at', 'DATETIME'),
                ('status', 'TEXT'),
                ('progress', 'INTEGER'),
                ('message', 'TEXT'),
                ('result_html', 'TEXT'),
                ('result_json', 'TEXT'),
                ('error', 'TEXT'),
                ('extracted_text', 'TEXT'),
                ('warning', 'TEXT')
            ):
                if col not in cols:
                    try:
                        cursor.execute(f'ALTER TABLE improve_jobs ADD COLUMN {col} {col_type}')
                    except Exception:
                        pass
        conn.commit()
    finally:
        conn.close()

def _create_improve_job(extracted_text, warning):
    _ensure_improve_jobs_table()
    job_id = uuid.uuid4().hex
    conn, cursor = app_services.open_db()
    try:
        cursor.execute('''
            INSERT INTO improve_jobs (job_id, status, progress, message, extracted_text, warning, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (job_id, 'queued', 0, 'Queued', extracted_text, warning))
        conn.commit()
    finally:
        conn.close()
    return job_id

def _update_improve_job(job_id, status=None, progress=None, message=None, result_html=None, result_json=None, error=None, warning=None):
    fields = []
    values = []
    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if progress is not None:
        fields.append("progress = ?")
        values.append(progress)
    if message is not None:
        fields.append("message = ?")
        values.append(message)
    if result_html is not None:
        fields.append("result_html = ?")
        values.append(result_html)
    if result_json is not None:
        fields.append("result_json = ?")
        values.append(result_json)
    if error is not None:
        fields.append("error = ?")
        values.append(error)
    if warning is not None:
        fields.append("warning = ?")
        values.append(warning)
    if not fields:
        return
    fields.append("updated_at = CURRENT_TIMESTAMP")
    values.append(job_id)
    conn, cursor = app_services.open_db()
    try:
        cursor.execute(f"UPDATE improve_jobs SET {', '.join(fields)} WHERE job_id = ?", values)
        conn.commit()
    finally:
        conn.close()

def _build_result_html(ai_result, highlighted_text):
    if not ai_result:
        return '<p class="form__help">No issues detected.</p>'
    summary = ai_result.get('summary') or {}
    stats = ai_result.get('stats') or {}
    issues = ai_result.get('issues') or []
    score = ai_result.get('score')
    issue_total = ai_result.get('issue_total')
    rewrite_count = ai_result.get('rewrite_count')

    if rewrite_count is None:
        rewrite_count = sum(1 for i in issues if i.get('is_rewrite'))
    if issue_total is None:
        issue_total = summary.get('spelling', 0) + summary.get('grammar', 0) + summary.get('style', 0) + rewrite_count
    if score is None:
        score = max(35, min(100, 100 - (issue_total * 2)))

    word_count = stats.get('word_count') or 0
    sentence_count = stats.get('sentence_count') or 0
    read_time = stats.get('read_time_minutes') or 0

    def _fmt(value):
        try:
            return f"{int(value):,}"
        except (TypeError, ValueError):
            return "0"

    parts = []
    parts.append('<div class="improve-workspace" data-improve-workspace>')
    parts.append('<div class="improve-overview">')
    parts.append('<div class="improve-score-card">')
    parts.append(f'<div class="improve-score">{escape(str(score))}</div>')
    parts.append('<div class="improve-score-label">Writing score</div>')
    parts.append(f'<div class="improve-score-meta">{escape(str(issue_total))} suggestions</div>')
    parts.append('</div>')
    parts.append('<div class="improve-stat-grid">')
    parts.append(f'<div class="improve-stat"><div class="improve-stat__value">{_fmt(word_count)}</div><div class="improve-stat__label">Words</div></div>')
    parts.append(f'<div class="improve-stat"><div class="improve-stat__value">{_fmt(sentence_count)}</div><div class="improve-stat__label">Sentences</div></div>')
    parts.append(f'<div class="improve-stat"><div class="improve-stat__value">{_fmt(read_time)}</div><div class="improve-stat__label">Read time (min)</div></div>')
    parts.append('</div>')
    parts.append('</div>')

    parts.append('<div class="improve-legend">')
    parts.append(
        f'<span><span class="improve-legend-swatch" style="background:#dc2626"></span> Spelling ({summary.get("spelling", 0)})</span>'
    )
    parts.append(
        f'<span><span class="improve-legend-swatch" style="background:#f59e0b"></span> Grammar ({summary.get("grammar", 0)})</span>'
    )
    parts.append(
        f'<span><span class="improve-legend-swatch" style="background:#2563eb"></span> Style ({summary.get("style", 0)})</span>'
    )
    parts.append(
        f'<span><span class="improve-legend-swatch" style="background:#0ea5e9"></span> Rewrites ({rewrite_count})</span>'
    )
    parts.append('</div>')

    parts.append('<div class="improve-layout">')
    parts.append('<div class="improve-document-card">')
    parts.append('<div class="improve-document__header">')
    parts.append('<div>')
    parts.append('<h4 class="improve-document__title">Document</h4>')
    parts.append('<p class="improve-document__meta">Click a highlight to review and apply suggestions.</p>')
    parts.append('</div>')
    parts.append('<button class="improve-copy" type="button" data-improve-copy>Copy revised text</button>')
    parts.append('</div>')
    parts.append(f'<div class="improve-highlight" data-improve-document>{highlighted_text}</div>')
    parts.append('</div>')

    parts.append('<aside class="improve-sidebar">')
    parts.append('<div class="improve-sidebar__section">')
    parts.append('<div class="improve-filter">')
    parts.append(
        f'<button class="improve-filter__btn is-active" type="button" data-improve-filter="all">All <span data-improve-count="all">{issue_total}</span></button>'
    )
    parts.append(
        f'<button class="improve-filter__btn" type="button" data-improve-filter="grammar">Grammar <span data-improve-count="grammar">{summary.get("grammar", 0)}</span></button>'
    )
    parts.append(
        f'<button class="improve-filter__btn" type="button" data-improve-filter="spelling">Spelling <span data-improve-count="spelling">{summary.get("spelling", 0)}</span></button>'
    )
    parts.append(
        f'<button class="improve-filter__btn" type="button" data-improve-filter="style">Style <span data-improve-count="style">{summary.get("style", 0)}</span></button>'
    )
    parts.append(
        f'<button class="improve-filter__btn" type="button" data-improve-filter="rewrite">Rewrite <span data-improve-count="rewrite">{rewrite_count}</span></button>'
    )
    parts.append('</div>')
    parts.append('<div class="improve-issues-list" data-improve-issue-list>')

    if not issues:
        parts.append('<p class="form__help">No issues detected.</p>')
    else:
        sorted_issues = sorted(issues, key=lambda item: (item.get('start', 0), item.get('end', 0)))
        for issue in sorted_issues:
            issue_id = escape(str(issue.get('issue_id') or ''))
            kind = issue.get('kind') or 'grammar'
            is_rewrite = bool(issue.get('is_rewrite'))
            kind_key = 'rewrite' if is_rewrite else kind
            kind_label = 'Rewrite' if is_rewrite else kind.replace('_', ' ').title()
            raw_message = issue.get('message') or ''
            message = escape(raw_message or 'Issue detected.')
            suggestions = issue.get('suggestions') or []
            suggestion_payload = [s for s in suggestions if s]
            if is_rewrite and raw_message:
                suggestion_payload = [raw_message]
            safe_suggestions = escape(json.dumps(suggestion_payload))
            suggestion_text = ", ".join(escape(s) for s in suggestion_payload if s)
            start = issue.get('start', '')
            end = issue.get('end', '')
            parts.append(
                f'<button class="improve-issue-card improve-issue-card--{kind_key}" type="button" '
                f'data-issue-id="{issue_id}" data-kind="{escape(kind_key)}" data-message="{message}" '
                f'data-start="{start}" data-end="{end}" data-suggestions="{safe_suggestions}" '
                f'data-is-rewrite="{str(is_rewrite).lower()}">'
            )
            parts.append(f'<div class="improve-issue-card__kind">{escape(kind_label)}</div>')
            if is_rewrite:
                parts.append(f'<div class="improve-issue-card__message">Suggested rewrite: {message}</div>')
            else:
                parts.append(f'<div class="improve-issue-card__message">{message}</div>')
            if suggestion_text:
                parts.append(f'<div class="improve-issue-card__suggestion">Suggestions: {suggestion_text}</div>')
            parts.append('</button>')

    parts.append('</div>')
    parts.append('</div>')

    parts.append('<div class="improve-detail" data-improve-detail>')
    parts.append('<div class="improve-detail__empty" data-improve-detail-empty>Select an issue to see details and apply a fix.</div>')
    parts.append('<div class="improve-detail__content" data-improve-detail-content hidden></div>')
    parts.append('</div>')
    parts.append('</aside>')
    parts.append('</div>')
    parts.append('</div>')
    return ''.join(parts)

def _serialize_improve_json(ai_result):
    if not ai_result:
        return None
    try:
        payload = json.dumps(ai_result, ensure_ascii=True)
    except Exception:
        return None
    return payload.replace('<', '\\u003c')

def _process_improve_job(job_id, extracted_text, warning):
    start_time = time.time()
    last_progress = -1

    def _progress_cb(value, message=None):
        nonlocal last_progress
        value = max(0, min(100, int(value)))
        if value == last_progress and not message:
            return
        last_progress = value
        _update_improve_job(job_id, progress=value, message=message)

    try:
        if len(extracted_text or '') > IMPROVE_MAX_CHARS:
            message = "This document is too long for online analysis. Please upload a shorter section or use Human Review."
            app_services.logger().info("Improve job %s rejected len=%s reason=too_long", job_id, len(extracted_text))
            _update_improve_job(job_id, status='error', progress=100, error=message, message=message)
            return
        _update_improve_job(job_id, status='running', progress=5, message='Preparing analysis...', warning=warning)
        ai_result, analysis_error, analysis_warning = _run_local_analysis(
            extracted_text,
            progress_cb=_progress_cb,
            timeout_seconds=IMPROVE_JOB_TIMEOUT_SECONDS,
            start_time=start_time
        )
        if analysis_error:
            _update_improve_job(job_id, status='error', progress=100, error=analysis_error, message=analysis_error)
            return
        combined_warning = warning
        if analysis_warning:
            if combined_warning:
                combined_warning = f"{combined_warning} {analysis_warning}"
            else:
                combined_warning = analysis_warning
        highlighted = _build_highlighted_html(extracted_text, ai_result.get('issues', []))
        result_html = _build_result_html(ai_result, highlighted)
        result_json = _serialize_improve_json(ai_result)
        final_message = combined_warning if combined_warning else 'Complete'
        _update_improve_job(
            job_id,
            status='done',
            progress=100,
            result_html=result_html,
            result_json=result_json,
            message=final_message,
            warning=combined_warning
        )
    except Exception as exc:
        app_services.logger().exception("Improve AI background job failed")
        err_msg = str(exc).strip() or "Writing checker failed unexpectedly. Please try again or use Human Review."
        _update_improve_job(job_id, status='error', progress=100, error=err_msg, message=err_msg)

import improve_analysis


def _run_local_analysis(text, progress_cb=None, timeout_seconds=20, start_time=None):
    return improve_analysis.run_local_analysis(
        text,
        progress_cb=progress_cb,
        timeout_seconds=timeout_seconds,
        start_time=start_time,
        logger=app_services.logger()
    )


def _build_highlighted_html(text, issues):
    return improve_analysis.build_highlighted_html(text, issues)


def improve():
    return render_template(
        'improve.html',
        ai_result=None,
        highlighted_text=None,
        extracted_text=None,
        error=None,
        ai_results_json=None,
        human_notice=None,
        prefill_text='',
        **_improve_context()
    )

def improve_ai():
    extracted_text = ''
    try:
        text_input = (request.form.get('text') or '').strip()
        file = request.files.get('file')
        warning = None

        if file and file.filename:
            extracted_text, err, warning = _extract_text_from_upload(file)
            if err:
                return render_template(
                    'improve.html',
                    ai_result=None,
                    highlighted_text=None,
                    extracted_text=None,
                    error=err,
                    ai_results_json=None,
                    human_notice=None,
                    prefill_text=text_input,
                    **_improve_context()
                )
            if warning:
                app_services.logger().info("Improve AI truncated PDF to %s pages", IMPROVE_MAX_PAGES)
        else:
            extracted_text = text_input

        if not extracted_text:
            return render_template(
                'improve.html',
                ai_result=None,
                highlighted_text=None,
                extracted_text=None,
                error="Please paste text or upload a file.",
                ai_results_json=None,
                human_notice=None,
                prefill_text='',
                **_improve_context()
            )

        if len(extracted_text) > IMPROVE_MAX_CHARS:
            message = "This document is too long for online analysis. Please upload a shorter section or use Human Review."
            app_services.logger().info("Improve AI rejected len=%s reason=too_long", len(extracted_text))
            job_id = _create_improve_job('', warning)
            _update_improve_job(job_id, status='error', progress=100, error=message, message=message)
            return redirect(url_for('improve_progress', job_id=job_id))

        job_id = _create_improve_job(extracted_text, warning)
        threading.Thread(
            target=_process_improve_job,
            args=(job_id, extracted_text, warning),
            daemon=True
        ).start()
        return redirect(url_for('improve_progress', job_id=job_id))
    except Exception:
        app_services.logger().exception("Improve AI failed")
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error="Writing checker failed. Please use Human Review.",
            ai_results_json=None,
            human_notice=None,
            prefill_text=extracted_text,
            **_improve_context()
        )

def improve_human_form():
    extracted_text = (request.form.get('extracted_text') or '').strip()
    ai_results_json = (request.form.get('ai_results_json') or '').strip()

    if not extracted_text:
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error="Please run a check before requesting human review.",
            ai_results_json=None,
            human_notice=None,
            **_improve_context()
        )

    if len(extracted_text) > IMPROVE_MAX_CHARS:
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error=f"Text is too long. Please submit {IMPROVE_MAX_CHARS:,} characters or fewer.",
            ai_results_json=None,
            human_notice=None,
            **_improve_context()
        )

    return render_template(
        'improve_human_form.html',
        extracted_text=extracted_text,
        ai_results_json=ai_results_json,
        requester_name='',
        requester_email='',
        requester_phone='',
        error=None
    )

def improve_human():
    text_input = (request.form.get('text') or '').strip()
    file = request.files.get('file')
    provided_text = (request.form.get('extracted_text') or '').strip()
    ai_results_json = (request.form.get('ai_results_json') or '').strip()
    requester_name = (request.form.get('requester_name') or '').strip()
    requester_email = (request.form.get('requester_email') or '').strip()
    requester_phone = (request.form.get('requester_phone') or '').strip()
    has_contact = bool(requester_name or requester_email or requester_phone or (request.form.get('require_contact') or '').strip())

    extracted_text = ''
    warning = None
    if provided_text:
        extracted_text = provided_text
    elif file and file.filename:
        extracted_text, err, warning = _extract_text_from_upload(file)
        if err:
            return render_template(
                'improve.html',
                ai_result=None,
                highlighted_text=None,
                extracted_text=None,
                error=err,
                ai_results_json=None,
                human_notice=None,
                **_improve_context()
            )
    else:
        extracted_text = text_input

    if not extracted_text:
        if has_contact:
            return render_template(
                'improve_human_form.html',
                extracted_text='',
                ai_results_json=ai_results_json,
                requester_name=requester_name,
                requester_email=requester_email,
                requester_phone=requester_phone,
                error="Please provide the text you want corrected."
            )
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error="Please paste text or upload a file.",
            ai_results_json=None,
            human_notice=None,
            **_improve_context()
        )

    if len(extracted_text) > IMPROVE_MAX_CHARS:
        error_message = f"Text is too long. Please submit {IMPROVE_MAX_CHARS:,} characters or fewer."
        if has_contact:
            return render_template(
                'improve_human_form.html',
                extracted_text=extracted_text,
                ai_results_json=ai_results_json,
                requester_name=requester_name,
                requester_email=requester_email,
                requester_phone=requester_phone,
                error=error_message
            )
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error=error_message,
            ai_results_json=None,
            human_notice=None,
            **_improve_context()
        )

    if not requester_name or not requester_email:
        return render_template(
            'improve_human_form.html',
            extracted_text=extracted_text,
            ai_results_json=ai_results_json,
            requester_name=requester_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            error="Please enter your name and email address."
        )
    if not app_services.email_regex().match(requester_email):
        return render_template(
            'improve_human_form.html',
            extracted_text=extracted_text,
            ai_results_json=ai_results_json,
            requester_name=requester_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            error="Please enter a valid email address."
        )

    mode = 'after_ai' if ai_results_json else 'human_only'
    submission_id = secrets.token_hex(8)
    _ensure_submissions_table()
    conn, cursor = app_services.open_db()
    try:
        cursor.execute('''
            INSERT INTO submissions (
                submission_id,
                mode,
                extracted_text,
                ai_results_json,
                status,
                requester_name,
                requester_email,
                requester_phone
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            submission_id,
            mode,
            extracted_text,
            ai_results_json or None,
            'new',
            requester_name or None,
            requester_email or None,
            requester_phone or None
        ))
        conn.commit()
    finally:
        conn.close()

    name_parts = requester_name.split()
    first_name = name_parts[0] if name_parts else "Improve"
    last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "Request"
    word_count = len(re.findall(r"[A-Za-z0-9]+(?:'[A-Za-z0-9]+)?", extracted_text))
    pages = max(1, int(math.ceil(word_count / 250))) if word_count else 1
    deadline = datetime.utcnow().isoformat(timespec='minutes')
    essay_data = {
        'submission_id': submission_id,
        'first_name': first_name,
        'last_name': last_name,
        'email': requester_email,
        'phone': requester_phone,
        'essay_type': 'Editing',
        'academic_level': 'Other',
        'subject': 'Writing correction',
        'pages': str(pages),
        'deadline': deadline,
        'topic': 'Human correction request',
        'instructions': extracted_text,
        'citation_style': 'N/A',
        'writer_preference': 'N/A',
        'sources': 'N/A',
        'newsletter': ''
    }

    conn, cursor = app_services.open_db()
    try:
        cursor.execute('''
            INSERT INTO essay_submissions 
            (submission_id, first_name, last_name, email, phone, essay_type, academic_level, 
             subject, pages, deadline, topic, instructions, citation_style, file_path, file_name, file_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            essay_data['submission_id'],
            essay_data['first_name'],
            essay_data['last_name'],
            essay_data['email'],
            essay_data['phone'],
            essay_data['essay_type'],
            essay_data['academic_level'],
            essay_data['subject'],
            essay_data['pages'],
            essay_data['deadline'],
            essay_data['topic'],
            essay_data['instructions'],
            essay_data['citation_style'],
            None,
            None,
            None
        ))
        conn.commit()
    finally:
        conn.close()

    admin_recipient = app_services.admin_email() or app_services.contact_recipient()
    admin_body_lines = [
        "New essay submission received.",
        f"Submission ID: {essay_data['submission_id']}",
        f"Name: {requester_name or 'N/A'}",
        f"Email: {requester_email}",
        f"Phone: {requester_phone or 'N/A'}",
        f"Essay Type: {essay_data['essay_type']}",
        f"Academic Level: {essay_data['academic_level']}",
        f"Subject: {essay_data['subject']}",
        f"Pages: {essay_data['pages']}",
        f"Deadline: {essay_data['deadline']}",
        f"Topic: {essay_data['topic']}",
        f"Citation Style: {essay_data['citation_style']}",
        f"Writer Preference: {essay_data['writer_preference']}",
        f"Required Sources: {essay_data['sources']}",
        f"Newsletter Opt-in: {'Yes' if essay_data.get('newsletter') else 'No'}",
        "File Uploaded: No file",
        "",
        "Instructions:",
        essay_data['instructions'] or 'None provided'
    ]
    admin_ok, admin_err = app_services.send_email(
        to_email=admin_recipient,
        subject="New submission received",
        body="\n".join(admin_body_lines),
        reply_to=requester_email or None
    )
    if not admin_ok:
        app_services.logger().error("Admin notification email failed for improve submission: %s", admin_err)
        return render_template(
            'improve_human_form.html',
            extracted_text=extracted_text,
            ai_results_json=ai_results_json,
            requester_name=requester_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            error=admin_err or "Unable to send confirmation emails right now. Please try again shortly."
        )

    student_name = requester_name or "there"
    student_ok, student_err = app_services.send_email(
        to_email=requester_email,
        subject=f"Submission received: {essay_data['submission_id']}",
        body=(
            f"Hello {student_name},\n\n"
            f"We've received your request (ID: {essay_data['submission_id']}).\n"
            f"Current status: pending. We'll email you when the status changes.\n\n"
            f"Summary:\n"
            f"- Type: {essay_data['essay_type']}\n"
            f"- Subject: {essay_data['subject']}\n"
            f"- Pages: {essay_data['pages']}\n"
            f"- Deadline: {essay_data['deadline']}\n\n"
            f"Thank you,\nEnglish Essay Writing Team"
        ),
        reply_to=app_services.admin_email() or app_services.from_email()
    )
    if not student_ok:
        app_services.logger().warning("User confirmation email failed for improve submission: %s", student_err)

    notice = f"Submitted for human review. Your request ID is {submission_id}."
    if warning:
        notice = f"{notice} {warning}"
    return render_template(
        'improve.html',
        ai_result=None,
        highlighted_text=None,
        extracted_text=None,
        error=None,
        ai_results_json=None,
        human_notice=notice,
        prefill_text='',
        **_improve_context()
    )

def improve_human_submit():
    if request.form.get('website'):
        app_services.logger().info("Honeypot field triggered; ignoring improve submission.")
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error=None,
            ai_results_json=None,
            human_notice="Submitted for human review.",
            prefill_text='',
            **_improve_context()
        )

    full_name = (request.form.get('fullName') or '').strip()
    requester_email = (request.form.get('email') or '').strip()
    requester_phone = (request.form.get('phone') or '').strip()
    instructions = (request.form.get('instructions') or '').strip()
    terms = request.form.get('terms')

    if not full_name or not requester_email or not instructions:
        return render_template(
            'improve_human_form.html',
            extracted_text=instructions,
            requester_name=full_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            error="Please fill in all required fields."
        )

    if not app_services.email_regex().match(requester_email):
        return render_template(
            'improve_human_form.html',
            extracted_text=instructions,
            requester_name=full_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            error="Please enter a valid email address."
        )

    if not terms:
        return render_template(
            'improve_human_form.html',
            extracted_text=instructions,
            requester_name=full_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            error="Please accept the terms and conditions."
        )

    if len(instructions) > IMPROVE_MAX_CHARS:
        return render_template(
            'improve_human_form.html',
            extracted_text=instructions,
            requester_name=full_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            error=f"Text is too long. Please submit {IMPROVE_MAX_CHARS:,} characters or fewer."
        )

    name_parts = full_name.split()
    first_name = name_parts[0] if name_parts else "Improve"
    last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "Request"
    word_count = len(re.findall(r"[A-Za-z0-9]+(?:'[A-Za-z0-9]+)?", instructions))
    pages = max(1, int(math.ceil(word_count / 250))) if word_count else 1
    deadline = datetime.utcnow().isoformat(timespec='minutes')
    submission_id = secrets.token_hex(8)

    _ensure_submissions_table()
    conn, cursor = app_services.open_db()
    try:
        cursor.execute('''
            INSERT INTO submissions (
                submission_id,
                mode,
                extracted_text,
                ai_results_json,
                status,
                requester_name,
                requester_email,
                requester_phone
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            submission_id,
            'human_only',
            instructions,
            None,
            'new',
            full_name,
            requester_email,
            requester_phone or None
        ))
        conn.commit()
    finally:
        conn.close()

    conn, cursor = app_services.open_db()
    try:
        cursor.execute('''
            INSERT INTO essay_submissions 
            (submission_id, first_name, last_name, email, phone, essay_type, academic_level, 
             subject, pages, deadline, topic, instructions, citation_style, file_path, file_name, file_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            submission_id,
            first_name,
            last_name,
            requester_email,
            requester_phone or None,
            'Editing',
            'Other',
            'Writing correction',
            str(pages),
            deadline,
            'Human correction request',
            instructions,
            'N/A',
            None,
            None,
            None
        ))
        conn.commit()
    finally:
        conn.close()

    admin_recipient = app_services.admin_email() or app_services.contact_recipient()
    admin_body_lines = [
        "New essay submission received.",
        f"Submission ID: {submission_id}",
        f"Name: {full_name}",
        f"Email: {requester_email}",
        f"Phone: {requester_phone or 'N/A'}",
        "Essay Type: Editing",
        "Academic Level: Other",
        "Subject: Writing correction",
        f"Pages: {pages}",
        f"Deadline: {deadline}",
        "Topic: Human correction request",
        "Citation Style: N/A",
        "Writer Preference: N/A",
        "Required Sources: N/A",
        "Newsletter Opt-in: No",
        "File Uploaded: No file",
        "",
        "Instructions:",
        instructions or 'None provided'
    ]
    admin_ok, admin_err = app_services.send_email(
        to_email=admin_recipient,
        subject="New submission received",
        body="\n".join(admin_body_lines),
        reply_to=requester_email
    )
    if not admin_ok:
        app_services.logger().error("Admin notification email failed for improve submission: %s", admin_err)
        return render_template(
            'improve_human_form.html',
            extracted_text=instructions,
            requester_name=full_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            error=admin_err or "Unable to send confirmation emails right now. Please try again shortly."
        )

    student_ok, student_err = app_services.send_email(
        to_email=requester_email,
        subject=f"Submission received: {submission_id}",
        body=(
            f"Hello {full_name},\n\n"
            f"We've received your request (ID: {submission_id}).\n"
            "Current status: pending. We'll email you when the status changes.\n\n"
            "Summary:\n"
            "- Type: Editing\n"
            "- Subject: Writing correction\n"
            f"- Pages: {pages}\n"
            f"- Deadline: {deadline}\n\n"
            "Thank you,\nEnglish Essay Writing Team"
        ),
        reply_to=app_services.admin_email() or app_services.from_email()
    )
    if not student_ok:
        app_services.logger().warning("User confirmation email failed for improve submission: %s", student_err)

    notice = f"Submitted for human review. Your request ID is {submission_id}."
    return render_template(
        'improve.html',
        ai_result=None,
        highlighted_text=None,
        extracted_text=None,
        error=None,
        ai_results_json=None,
        human_notice=notice,
        prefill_text='',
        **_improve_context()
    )

def admin_submissions():
    _ensure_submissions_table()
    conn, cursor = app_services.open_db()
    cursor.execute('''
        SELECT id, submission_id, created_at, mode, extracted_text, ai_results_json, status,
               requester_name, requester_email, requester_phone
        FROM submissions
        ORDER BY created_at DESC
    ''')
    rows = cursor.fetchall()
    conn.close()

    submissions = []
    for row in rows:
        submissions.append({
            'id': row[0],
            'submission_id': row[1],
            'created_at': row[2],
            'mode': row[3],
            'extracted_text': row[4],
            'ai_results_json': row[5],
            'status': row[6],
            'requester_name': row[7],
            'requester_email': row[8],
            'requester_phone': row[9]
        })
    return render_template('admin_submissions.html', submissions=submissions)

def improve_progress(job_id):
    _ensure_improve_jobs_table()
    return render_template('improve_progress.html', job_id=job_id)

def improve_status(job_id):
    _ensure_improve_jobs_table()
    conn, cursor = app_services.open_db()
    cursor.execute('''
        SELECT status, progress, message, updated_at, error
        FROM improve_jobs
        WHERE job_id = ?
    ''', (job_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return jsonify({'status': 'error', 'progress': 100, 'message': 'Job not found.'}), 404
    status, progress, message, updated_at, error = row
    if status == 'running' and updated_at:
        last_update = updated_at
        if isinstance(last_update, str):
            try:
                last_update = datetime.fromisoformat(last_update)
            except Exception:
                last_update = None
        if isinstance(last_update, datetime):
            age = (datetime.utcnow() - last_update).total_seconds()
            if age > 120:
                stale_message = "The server restarted while processing. Please try again or use Human Review."
                app_services.logger().info("Improve job %s marked stale after %ss", job_id, int(age))
                _update_improve_job(job_id, status='error', progress=100, error=stale_message, message=stale_message)
                status = 'error'
                progress = 100
                message = stale_message
    payload = {
        'status': status,
        'progress': progress or 0,
        'message': message or error or ''
    }
    if status == 'done':
        payload['result_url'] = url_for('improve_result', job_id=job_id)
    return jsonify(payload)

def improve_result(job_id):
    _ensure_improve_jobs_table()
    conn, cursor = app_services.open_db()
    cursor.execute('''
        SELECT status, message, extracted_text, result_html, result_json, error, warning
        FROM improve_jobs
        WHERE job_id = ?
    ''', (job_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error="Result not found.",
            ai_results_json=None,
            human_notice=None,
            prefill_text='',
            **_improve_context()
        )
    status, message, extracted_text, result_html, result_json, error, warning = row
    if status != 'done' or not result_html:
        return render_template(
            'improve.html',
            ai_result=None,
            highlighted_text=None,
            extracted_text=None,
            error=error or message or "Writing checker failed. Please try again or use Human Review.",
            ai_results_json=None,
            human_notice=None,
            prefill_text=extracted_text or '',
            **_improve_context()
        )
    return render_template(
        'improve_results.html',
        result_html=result_html,
        ai_results_json=result_json or '',
        extracted_text=extracted_text or '',
        warning=warning
    )

