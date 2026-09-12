import json
import re


def _structured_data(body):
    return [json.loads(block) for block in
            re.findall(r'<script type="application/ld\+json">(.*?)</script>', body, re.S)]


def test_ielts_page_leads_on_privacy(client):
    body = client.get("/ielts-writing-checker").data.decode("utf-8")
    assert "Your answer is never published" in body
    assert "no public library of essays" in body
    assert "deleted automatically after 30 days" in body
    # The LanguageTool disclosure stays, because the text really is sent there.
    assert "LanguageTool" in body
    assert 'href="/privacy"' in body


def test_ielts_page_explains_the_band_score_question(client):
    body = client.get("/ielts-writing-checker").data.decode("utf-8")
    assert "Why there is no band score" in body
    for criterion in ("Task Response", "Coherence and Cohesion",
                      "Lexical Resource", "Grammatical Range and Accuracy"):
        assert criterion in body


def test_ielts_faq_answers_whether_answers_are_published(client):
    body = client.get("/ielts-writing-checker").data.decode("utf-8")
    questions = [q["name"] for data in _structured_data(body) for q in data.get("mainEntity", [])]
    assert "Will my answer be published?" in questions


def test_privacy_policy_mentions_the_30_day_deletion(client):
    body = client.get("/privacy").data.decode("utf-8")
    assert "30 days" in body


def test_old_checks_are_deleted_but_review_requests_are_kept(app_module):
    routes = app_module.improve_routes
    old_job = routes._create_improve_job("an old draft", None)
    fresh_job = routes._create_improve_job("a draft from today", None)
    routes._ensure_submissions_table()

    conn, cursor = routes.app_services.open_db()
    try:
        cursor.execute("UPDATE improve_jobs SET created_at = ? WHERE job_id = ?",
                       ("2020-01-01 00:00:00", old_job))
        cursor.execute(
            "INSERT INTO submissions (submission_id, mode, extracted_text, status) VALUES (?, ?, ?, ?)",
            ("sub-old", "human_only", "a paying customer's draft", "new"))
        # Let the once-a-day cleanup run now.
        cursor.execute("DELETE FROM app_meta WHERE key = ?", ("last_cleanup_date",))
        conn.commit()
    finally:
        conn.close()

    app_module._run_cleanup_if_needed()

    conn, cursor = routes.app_services.open_db()
    try:
        cursor.execute("SELECT COUNT(*) FROM improve_jobs WHERE job_id = ?", (old_job,))
        old_kept = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM improve_jobs WHERE job_id = ?", (fresh_job,))
        fresh_kept = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM submissions")
        submissions = cursor.fetchone()[0]
    finally:
        conn.close()

    assert old_kept == 0, "checks older than 30 days should be deleted"
    assert fresh_kept == 1, "today's check should survive"
    assert submissions == 1, "review requests are customer records and must be kept"
