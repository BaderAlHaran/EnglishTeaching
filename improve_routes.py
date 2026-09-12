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
import ielts_report
import mechanics_report

IMPROVE_ALLOWED_EXTENSIONS = {'pdf', 'docx'}
IMPROVE_MAX_BYTES = 10 * 1024 * 1024
IMPROVE_MAX_CHARS = int(os.environ.get('IMPROVE_MAX_CHARS', '40000'))
IMPROVE_MAX_PAGES = int(os.environ.get('IMPROVE_MAX_PAGES', '10'))
IMPROVE_JOB_TIMEOUT_SECONDS = int(os.environ.get('IMPROVE_JOB_TIMEOUT_SECONDS', '45'))
IELTS_MAX_QUESTION_CHARS = 2000
REVIEWER_NOTE_MAX_CHARS = 1000
# The browser posts the checker's result JSON back with a review request;
# anything larger than this is not a genuine result, so it is ignored.
CHECKER_JSON_MAX_CHARS = 2_000_000


def _improve_context():
    return {
        'max_chars': IMPROVE_MAX_CHARS
    }


def _filter_non_prose(text):
    """Drop lines from extracted PDF text that are not prose: figure/table
    captions, table rows (number/symbol heavy), page numbers, and stray
    fragments. Keeps the essay content for analysis."""
    if not text:
        return text
    kept = []
    for line in text.replace('\r\n', '\n').split('\n'):
        stripped = line.strip()
        if not stripped:
            kept.append('')
            continue
        # Figure/table/chart captions, e.g. "Figure 3: results", "Table 2."
        if re.match(r'^(figure|fig\.?|table|chart|diagram|exhibit|appendix)\s*\d', stripped, flags=re.IGNORECASE):
            continue
        # Bare page numbers / numeric rows
        if re.fullmatch(r'[\d\s.,%$()\-–—/:+*=|]+', stripped):
            continue
        # Delimited table rows ("Hours | Grade | Count", tab-separated cells)
        if stripped.count('|') >= 2 or '\t' in stripped:
            continue
        # Table rows and equations: mostly digits/symbols rather than letters
        non_space = re.sub(r'\s', '', stripped)
        alpha = sum(1 for ch in non_space if ch.isalpha())
        if non_space and alpha / len(non_space) < 0.5:
            continue
        # Stray one/two-word fragments without sentence punctuation
        # (running headers, axis labels, column headings)
        words = re.findall(r"[A-Za-z]+(?:'[A-Za-z]+)?", stripped)
        if len(words) <= 2 and not stripped.endswith(('.', '!', '?', ',', ';', ':')) and not stripped.endswith('-'):
            continue
        kept.append(line)
    filtered = '\n'.join(kept)
    filtered = re.sub(r'\n{3,}', '\n\n', filtered)
    return filtered.strip()


def _normalize_text(text):
    """Clean up PDF-style hard wrapping so analysis sees real sentences:
    rejoin hyphenated line-wraps (con-\\ntrolled -> controlled) and merge
    line breaks that fall mid-sentence. Blank-line paragraph breaks and
    breaks after sentence-ending punctuation are preserved."""
    if not text:
        return text
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    text = re.sub(r'(\w)-\n(?=\w)', r'\1', text)
    text = re.sub(r'(?<![.!?])\n(?!\n)', ' ', text)
    text = re.sub(r'[ \t]{2,}', ' ', text)
    return text.strip()

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
        if 'reviewer_note' not in columns:
            cursor.execute('ALTER TABLE submissions ADD COLUMN reviewer_note TEXT')
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
        filtered = _filter_non_prose(text)
        # If filtering removed everything (e.g. a table-only document),
        # fall back to the raw extraction rather than returning nothing.
        if filtered:
            text = filtered
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

def _build_mechanics_html(mechanics):
    if not mechanics:
        return ''

    def _badge(value):
        return f'<span style="display:inline-block;min-width:2em;text-align:center;padding:2px 10px;border-radius:999px;background:#eef2ff;color:#3730a3;font-weight:600;font-size:13px;">{escape(str(value))}</span>'

    def _card(title, badge_value, summary, detail_items):
        items_html = ''
        if detail_items:
            items = ''.join(f'<li style="margin:4px 0;">{escape(item)}</li>' for item in detail_items)
            items_html = f'<ul style="margin:10px 0 0;padding-left:20px;color:#475569;font-size:14px;">{items}</ul>'
        return (
            '<details class="improve-card" style="margin-bottom:12px;padding:14px 18px;">'
            f'<summary style="cursor:pointer;display:flex;align-items:center;gap:10px;font-weight:600;">'
            f'{_badge(badge_value)} {escape(title)}</summary>'
            f'<p style="margin:10px 0 0;color:#334155;font-size:14px;">{escape(summary)}</p>'
            f'{items_html}'
            '</details>'
        )

    clarity = mechanics.get('sentenceClarity') or {}
    variety = mechanics.get('repetitionVariety') or {}
    style = mechanics.get('academicStyle') or {}
    structure = mechanics.get('structuralSignals') or {}
    readability = mechanics.get('readability') or {}

    parts = ['<div class="improve-mechanics" style="margin-top:24px;">']
    parts.append('<h4 class="improve-document__title" style="margin-bottom:12px;">Writing Mechanics Report</h4>')

    parts.append(_card(
        'Sentence Clarity',
        clarity.get('longSentenceCount', 0),
        clarity.get('summary', ''),
        [f'Example: {e}' for e in (clarity.get('examples') or [])]
    ))

    variety_details = [f"\"{item['word']}\" used {item['count']} times" for item in (variety.get('repeatedWords') or [])]
    variety_details += [f"Filler \"{item['phrase']}\" used {item['count']} times" for item in (variety.get('overusedFillers') or [])]
    parts.append(_card(
        'Repetition & Word Variety',
        len(variety.get('repeatedWords') or []) + len(variety.get('overusedFillers') or []),
        variety.get('summary', ''),
        variety_details
    ))

    style_details = [
        'Replace "the %s of" with "%s" (%dx)' % (item['noun'], item['verb'], item['count'])
        for item in (style.get('nominalisations') or [])
    ]
    if style.get('expletiveOpeners'):
        style_details.append(
            '%d sentence(s) start with "there is" or "it is" - rewrite to lead with the subject'
            % style['expletiveOpeners'])
    if style.get('toBePercent'):
        style_details.append('Forms of "to be": %d%% of words' % style['toBePercent'])
    parts.append(_card(
        'Academic Style',
        len(style.get('nominalisations') or []) + (style.get('expletiveOpeners') or 0),
        style.get('summary', ''),
        style_details
    ))

    transition = structure.get('transitionOpenerPercent')
    parts.append(_card(
        'Structural Signals',
        f"{transition}%" if transition is not None else '—',
        structure.get('summary', ''),
        structure.get('repetitiveStarters') or []
    ))

    parts.append(_card(
        'Readability',
        readability.get('gradeLevel', '—'),
        readability.get('label', ''),
        []
    ))

    parts.append(
        '<p class="form__help" style="margin-top:10px;">'
        'This report uses rule-based writing analysis (no AI-generated content or feedback). '
        'It checks mechanics like sentence length, repetition, and structure — not argument quality or content accuracy.'
        '</p>'
    )
    parts.append('</div>')
    return ''.join(parts)


# Pill label, text colour and background for each checklist status.
IELTS_STATUS_STYLES = {
    'pass': ('Good', '#027a48', '#ecfdf3'),
    'warn': ('Check', '#b45309', '#fff7ed'),
    'fail': ('Fix', '#b42318', '#fdecea'),
    'info': ('Note', '#1d4ed8', '#eff6ff'),
}


def _build_ielts_html(report):
    if not report:
        return ""
    rows = []
    for check in report.get('checks') or []:
        label, colour, background = IELTS_STATUS_STYLES.get(check.get('status'), IELTS_STATUS_STYLES['info'])
        rows.append(
            '<li style="display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-top:1px solid #e5e7eb;">'
            f'<span style="flex:none;min-width:54px;text-align:center;padding:2px 8px;border-radius:999px;'
            f'background:{background};color:{colour};font-weight:600;font-size:12px;">{label}</span>'
            f'<span><strong>{escape(check.get("title", ""))}</strong>'
            f'<span style="display:block;color:#475569;font-size:14px;">{escape(check.get("detail", ""))}</span></span>'
            '</li>'
        )
    return (
        '<div class="improve-card" style="margin-bottom:20px;padding:18px 22px;">'
        f'<h4 class="improve-document__title" style="margin-bottom:4px;">IELTS {escape(report.get("taskLabel", ""))} checklist</h4>'
        f'<p class="improve-document__meta" style="margin:0 0 8px;">Minimum {escape(str(report.get("minimumWords", "")))} words, '
        f'about {escape(str(report.get("minutes", "")))} minutes in the exam</p>'
        f'<ul style="list-style:none;margin:0;padding:0;">{"".join(rows)}</ul>'
        '<p class="form__help" style="margin-top:10px;">These checks cover length, structure and formal language. '
        'They do not predict a band score or judge how well you answered the question.</p>'
        '</div>'
    )


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
    parts.append(_build_ielts_html(ai_result.get('ielts')))
    parts.append('<div class="improve-overview">')
    parts.append('<div class="improve-score-card">')
    parts.append(f'<div class="improve-score">{escape(str(score))}</div>')
    parts.append('<div class="improve-score-label">Writing score</div>')
    parts.append(f'<div class="improve-score-meta">{escape(str(issue_total))} suggestions</div>')
    style_penalty = ai_result.get('style_penalty')
    if style_penalty:
        reasons = ', '.join(item['reason'] for item in (ai_result.get('style_penalty_breakdown') or []))
        parts.append(
            f'<div class="improve-score-meta">-{escape(str(style_penalty))} for style: {escape(reasons)}</div>')
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
    recheck_url = '/improve'
    if ai_result.get('ielts'):
        recheck_url = '/ielts-writing-checker?task=' + (ai_result['ielts'].get('task') or ielts_report.DEFAULT_TASK)
    parts.append(
        f'<button class="improve-copy" type="button" data-improve-recheck data-recheck-url="{escape(recheck_url)}">'
        'Edit &amp; re-check</button>')
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
    parts.append(_build_mechanics_html(ai_result.get('mechanics')))
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

def _merge_ielts_highlights(ai_result):
    """Add the IELTS findings (contractions, informal words, copied wording)
    to the highlighted document, skipping any span another check already
    marked so highlights never overlap."""
    report = ai_result.get('ielts') or {}
    issues = list(ai_result.get('issues') or [])
    taken = [(i['start'], i['end']) for i in issues if not i.get('no_highlight')]
    added = 0
    for item in report.get('highlights') or []:
        start, end = item['start'], item['end']
        if any(start < taken_end and taken_start < end for taken_start, taken_end in taken):
            continue
        added += 1
        issues.append({
            'start': start,
            'end': end,
            'kind': 'style',
            'message': item['message'],
            'suggestions': item.get('suggestions') or [],
            'sentence_id': None,
            'no_highlight': False,
            'is_rewrite': False,
            'issue_id': f'ielts-{added}',
        })
        taken.append((start, end))
    if not added:
        return
    issues.sort(key=lambda issue: (issue.get('start', 0), issue.get('end', 0)))
    summary = improve_analysis._build_summary(issues)
    ai_result['issues'] = issues
    ai_result['summary'] = summary
    ai_result['issue_total'] = (summary['spelling'] + summary['grammar'] + summary['style']
                                + (ai_result.get('rewrite_count') or 0))


def _process_improve_job(job_id, extracted_text, warning, language='en-GB', ielts=None):
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
            start_time=start_time,
            language=language
        )
        if analysis_error:
            _update_improve_job(job_id, status='error', progress=100, error=analysis_error, message=analysis_error)
            return
        if mechanics_report.MECHANICS_REPORT_ENABLED and ai_result:
            try:
                ai_result['mechanics'] = mechanics_report.build_report(
                    extracted_text,
                    sentences=ai_result.get('sentences'),
                    passive_sentence_ids=ai_result.get('passive_sentence_ids'),
                    issues=ai_result.get('issues')
                )
                # Grammar alone can rate turgid prose highly, so deduct for the
                # style weaknesses the mechanics report surfaces.
                penalty, breakdown = mechanics_report.style_penalty(
                    ai_result['mechanics'], (ai_result.get('stats') or {}).get('word_count'))
                if penalty:
                    ai_result['style_penalty'] = penalty
                    ai_result['style_penalty_breakdown'] = [
                        {'reason': reason, 'points': pts} for reason, pts in breakdown]
                    ai_result['score_before_style'] = ai_result.get('score')
                    ai_result['score'] = max(35, (ai_result.get('score') or 100) - penalty)
            except Exception:
                app_services.logger().exception("Mechanics report failed; continuing without it")
        if ielts and ai_result:
            try:
                report = ielts_report.build_report(
                    extracted_text, task=ielts.get('task'), question=ielts.get('question'))
                if report:
                    ai_result['ielts'] = report
                    # Show the same count the IELTS check uses (numbers included)
                    # so the Words card and the checklist agree.
                    stats = ai_result.get('stats') or {}
                    stats['word_count'] = report['wordCount']
                    ai_result['stats'] = stats
                    _merge_ielts_highlights(ai_result)
            except Exception:
                app_services.logger().exception("IELTS report failed; continuing without it")
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


IMPROVE_LANGUAGES = {'en-US', 'en-GB'}


def _run_local_analysis(text, progress_cb=None, timeout_seconds=20, start_time=None, language='en-GB'):
    return improve_analysis.run_local_analysis(
        text,
        progress_cb=progress_cb,
        timeout_seconds=timeout_seconds,
        start_time=start_time,
        logger=app_services.logger(),
        language=language
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

def _ensure_checker_runs_table():
    """One row per check: when it ran and which checker it was, with no essay
    text. Kept permanently, so the counts survive the 30-day deletion of the
    checks in improve_jobs."""
    conn, cursor = app_services.open_db()
    try:
        if app_services.is_postgres():
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS checker_runs (
                    id SERIAL PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    exam TEXT NOT NULL,
                    task TEXT
                )
            """)
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS checker_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    exam TEXT NOT NULL,
                    task TEXT
                )
            """)
        conn.commit()
        cursor.execute('SELECT COUNT(*) FROM checker_runs')
        if cursor.fetchone()[0] == 0:
            # First time: carry over the history still sitting in improve_jobs
            # before old checks start being deleted.
            try:
                cursor.execute("""
                    INSERT INTO checker_runs (created_at, exam)
                    SELECT created_at,
                           CASE WHEN result_json LIKE '%"ielts"%' THEN 'ielts' ELSE 'essay' END
                    FROM improve_jobs
                """)
                conn.commit()
            except Exception:
                conn.rollback()
    finally:
        conn.close()


def _record_checker_run(ielts=None):
    """Count one check for the admin analytics. Never blocks the student."""
    try:
        _ensure_checker_runs_table()
        conn, cursor = app_services.open_db()
        try:
            cursor.execute('INSERT INTO checker_runs (exam, task) VALUES (?, ?)',
                           ('ielts' if ielts else 'essay', (ielts or {}).get('task')))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        app_services.logger().exception("Could not record checker run")


def _render_input_page(error=None, prefill_text='', ielts=None):
    """Re-show whichever form the student came from, keeping their text."""
    if ielts is not None:
        return render_template(
            'ielts.html',
            error=error,
            prefill_text=prefill_text,
            task=ielts.get('task'),
            question=ielts.get('question') or '',
            **_improve_context()
        )
    return render_template(
        'improve.html',
        ai_result=None,
        highlighted_text=None,
        extracted_text=None,
        error=error,
        ai_results_json=None,
        human_notice=None,
        prefill_text=prefill_text,
        **_improve_context()
    )


def _ielts_options_from_form():
    """The IELTS page posts exam=ielts with the task and the optional
    question; the general checker sends neither."""
    if (request.form.get('exam') or '').strip() != 'ielts':
        return None
    task = (request.form.get('task') or '').strip()
    if task not in ielts_report.TASKS:
        task = ielts_report.DEFAULT_TASK
    question = (request.form.get('question') or '')[:IELTS_MAX_QUESTION_CHARS].strip()
    return {'task': task, 'question': question}


def ielts_page():
    task = (request.args.get('task') or '').strip()
    if task not in ielts_report.TASKS:
        task = ielts_report.DEFAULT_TASK
    return render_template(
        'ielts.html',
        error=None,
        prefill_text='',
        task=task,
        question='',
        **_improve_context()
    )


def improve_ai():
    extracted_text = ''
    ielts = None
    try:
        ielts = _ielts_options_from_form()
        text_input = (request.form.get('text') or '').strip()
        file = request.files.get('file')
        warning = None

        if file and file.filename:
            extracted_text, err, warning = _extract_text_from_upload(file)
            if err:
                return _render_input_page(error=err, prefill_text=text_input, ielts=ielts)
            if warning:
                app_services.logger().info("Improve AI truncated PDF to %s pages", IMPROVE_MAX_PAGES)
        else:
            extracted_text = text_input

        extracted_text = _normalize_text(extracted_text)

        if not extracted_text:
            message = "Please paste your answer." if ielts else "Please paste text or upload a file."
            return _render_input_page(error=message, ielts=ielts)

        if len(extracted_text) > IMPROVE_MAX_CHARS:
            message = "This document is too long for online analysis. Please upload a shorter section or use Human Review."
            app_services.logger().info("Improve AI rejected len=%s reason=too_long", len(extracted_text))
            job_id = _create_improve_job('', warning)
            _update_improve_job(job_id, status='error', progress=100, error=message, message=message)
            return redirect(url_for('improve_progress', job_id=job_id))

        language = (request.form.get('language') or 'en-GB').strip()
        if language not in IMPROVE_LANGUAGES:
            language = 'en-US'

        # Counted before the job row exists, so the one-time backfill in
        # _ensure_checker_runs_table cannot count this check twice.
        _record_checker_run(ielts)
        job_id = _create_improve_job(extracted_text, warning)
        threading.Thread(
            target=_process_improve_job,
            args=(job_id, extracted_text, warning, language, ielts),
            daemon=True
        ).start()
        return redirect(url_for('improve_progress', job_id=job_id))
    except Exception:
        app_services.logger().exception("Improve AI failed")
        return _render_input_page(
            error="Writing checker failed. Please use Human Review.",
            prefill_text=extracted_text,
            ielts=ielts
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

def _clean_line(value, limit):
    """One line of plain text: collapsing whitespace stops a tampered value
    from adding lines to the reviewer's email, and the length is capped."""
    return ' '.join(str(value or '').split())[:limit]


def _checker_summary_from_json(ai_results_json):
    """The few facts a reviewer needs from the checker's results.

    The browser posts the full result JSON back with a review request, so it
    is untrusted: anything missing, malformed or oversized gives None. It also
    accepts the stored summary it returns, so the admin page can reuse it."""
    if not ai_results_json or len(ai_results_json) > CHECKER_JSON_MAX_CHARS:
        return None
    try:
        data = json.loads(ai_results_json)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None

    def _number(value):
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return None

    score = _number(data.get('score'))
    if score is None:
        return None
    counts = data['summary'] if isinstance(data.get('summary'), dict) else data
    stats = data['stats'] if isinstance(data.get('stats'), dict) else {}
    summary = {
        'score': score,
        'words': _number(stats.get('word_count', data.get('words'))),
        'spelling': _number(counts.get('spelling')) or 0,
        'grammar': _number(counts.get('grammar')) or 0,
        'style': _number(counts.get('style')) or 0,
    }
    ielts = data.get('ielts')
    if isinstance(ielts, dict) and ielts.get('task') in ielts_report.TASKS:
        raw_checks = ielts.get('checks') if isinstance(ielts.get('checks'), list) else []
        summary['ielts'] = {
            'task': ielts['task'],
            'question': _clean_line(ielts.get('question'), IELTS_MAX_QUESTION_CHARS),
            'checks': [
                {'status': check['status'],
                 'title': _clean_line(check.get('title'), 60),
                 'detail': _clean_line(check.get('detail'), 300)}
                for check in raw_checks[:12]
                if isinstance(check, dict) and check.get('status') in IELTS_STATUS_STYLES
            ],
        }
    return summary


def _format_checker_summary(checker):
    """Plain-text lines telling the reviewer where the text came from and
    what the automatic checks found."""
    if not checker:
        return ["Came from: review form, no checker results attached"]
    lines = []
    ielts = checker.get('ielts')
    if ielts:
        lines.append("Came from: IELTS writing checker, %s" % ielts_report.TASKS[ielts['task']]['label'])
        lines.append("Question: %s" % (ielts.get('question') or 'not given'))
    else:
        lines.append("Came from: essay checker")
    lines += ["", "Checker results (score %d):" % checker['score']]
    passed = []
    for check in (ielts or {}).get('checks') or []:
        if check['status'] == 'pass':
            passed.append(check['title'])
        else:
            label = IELTS_STATUS_STYLES[check['status']][0].upper()
            lines.append("  %-6s %s: %s" % (label, check['title'], check['detail']))
    if passed:
        lines.append("  %-6s %s" % ('GOOD', ', '.join(passed)))
    lines.append("  Spelling %d, grammar %d, style %d"
                 % (checker['spelling'], checker['grammar'], checker['style']))
    return lines


def request_source(ai_results_json):
    """Where a review request came from, for the admin lists: 'IELTS checker',
    'Essay checker', or None when no checker results were attached."""
    checker = _checker_summary_from_json(ai_results_json)
    if not checker:
        return None
    return 'IELTS checker' if checker.get('ielts') else 'Essay checker'


def _checker_text_for_admin(ai_results_json):
    checker = _checker_summary_from_json(ai_results_json)
    return '\n'.join(_format_checker_summary(checker)) if checker else ''


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
    ai_results_json = (request.form.get('ai_results_json') or '').strip()
    reviewer_note = (request.form.get('reviewer_note') or '').strip()[:REVIEWER_NOTE_MAX_CHARS]

    if not full_name or not requester_email or not instructions:
        return render_template(
            'improve_human_form.html',
            extracted_text=instructions,
            requester_name=full_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            ai_results_json=ai_results_json,
            reviewer_note=reviewer_note,
            error="Please fill in all required fields."
        )

    if not app_services.email_regex().match(requester_email):
        return render_template(
            'improve_human_form.html',
            extracted_text=instructions,
            requester_name=full_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            ai_results_json=ai_results_json,
            reviewer_note=reviewer_note,
            error="Please enter a valid email address."
        )

    if not terms:
        return render_template(
            'improve_human_form.html',
            extracted_text=instructions,
            requester_name=full_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            ai_results_json=ai_results_json,
            reviewer_note=reviewer_note,
            error="Please accept the terms and conditions."
        )

    if len(instructions) > IMPROVE_MAX_CHARS:
        return render_template(
            'improve_human_form.html',
            extracted_text=instructions,
            requester_name=full_name,
            requester_email=requester_email,
            requester_phone=requester_phone,
            ai_results_json=ai_results_json,
            reviewer_note=reviewer_note,
            error=f"Text is too long. Please submit {IMPROVE_MAX_CHARS:,} characters or fewer."
        )

    name_parts = full_name.split()
    first_name = name_parts[0] if name_parts else "Improve"
    last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "Request"
    word_count = ielts_report.count_words(instructions)
    pages = max(1, int(math.ceil(word_count / 250))) if word_count else 1
    submission_id = secrets.token_hex(8)

    checker = _checker_summary_from_json(ai_results_json)
    ielts = (checker or {}).get('ielts')
    if ielts:
        task_label = ielts_report.TASKS[ielts['task']]['label']
        text_kind = 'IELTS ' + task_label
        checked_with = 'IELTS writing checker (%s)' % task_label
    else:
        text_kind = 'essay'
        checked_with = 'essay checker' if checker else 'not checked'

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
                requester_phone,
                reviewer_note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            submission_id,
            'after_ai' if checker else 'human_only',
            instructions,
            json.dumps(checker, indent=2) if checker else None,
            'new',
            full_name,
            requester_email,
            requester_phone or None,
            reviewer_note or None
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
            'IELTS Writing' if ielts else 'Writing correction',
            str(pages),
            # This form does not ask for a deadline; students can give one in
            # their note. Storing the submission time here made every request
            # look due immediately.
            'Not specified',
            'Human review request: ' + text_kind,
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
    phone_text = ('phone ' + requester_phone) if requester_phone else 'phone not given'
    admin_body_lines = [
        f"Submission ID: {submission_id}",
        f"From: {full_name} <{requester_email}>, {phone_text}",
    ] + _format_checker_summary(checker)
    if reviewer_note:
        admin_body_lines += ["", "Note from the student:", reviewer_note]
    admin_body_lines += ["", f"Student's text ({word_count} words):", instructions]
    admin_ok, admin_err = app_services.send_email(
        to_email=admin_recipient,
        subject=f"Human review request: {text_kind} ({word_count} words)",
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
            ai_results_json=ai_results_json,
            reviewer_note=reviewer_note,
            error=admin_err or "Unable to send confirmation emails right now. Please try again shortly."
        )

    student_ok, student_err = app_services.send_email(
        to_email=requester_email,
        subject=f"Review request received: {submission_id}",
        body=(
            f"Hello {full_name},\n\n"
            f"We've received your review request (ID: {submission_id}).\n\n"
            "What happens next: we'll read it and email you to confirm we can take it. "
            "Nothing is charged before then, and you only pay after you have seen a "
            "summary of the finished review.\n\n"
            "Summary:\n"
            f"- Text: {word_count} words\n"
            f"- Checked with: {checked_with}\n\n"
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
               requester_name, requester_email, requester_phone, reviewer_note
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
            'requester_phone': row[9],
            'reviewer_note': row[10],
            'checker_text': _checker_text_for_admin(row[5]),
            'source': request_source(row[5])
        })
    return render_template('admin_submissions.html', submissions=submissions)

def improve_progress(job_id):
    _ensure_improve_jobs_table()
    return render_template('improve_progress.html', job_id=job_id)

def improve_status(job_id):
    _ensure_improve_jobs_table()
    conn, cursor = app_services.open_db()
    try:
        cursor.execute('''
            SELECT status, progress, message, updated_at, error
            FROM improve_jobs
            WHERE job_id = ?
        ''', (job_id,))
        row = cursor.fetchone()
    finally:
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

def _start_over_url(result_json):
    """IELTS students go back to the IELTS page, everyone else to /improve."""
    try:
        report = (json.loads(result_json or '{}') or {}).get('ielts')
    except (TypeError, ValueError, AttributeError):
        report = None
    if report:
        return '/ielts-writing-checker?task=' + (report.get('task') or ielts_report.DEFAULT_TASK)
    return '/improve'


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
        warning=warning,
        start_over_url=_start_over_url(result_json)
    )

