import json
import re

import ielts_report


QUESTION = (
    "Some people think children should start school at a very early age, while others believe "
    "they should not begin until they are older. Discuss both views and give your own opinion."
)
ANSWER = (
    "In this day and age, some people think children should start school at a very early age. "
    "Others believe it's better to wait.\n\n"
    "Starting early helps children learn to share and follow rules.\n\n"
    "To sum up, I think children should start formal lessons at around six."
)
NOTE = "I keep getting 6.0 for Coherence and Cohesion. My deadline is Friday."


def extract_csrf_token(response):
    body = response.data.decode("utf-8")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', body)
    assert match, "csrf token field not found"
    return match.group(1)


def login_admin(client):
    token = extract_csrf_token(client.get("/login"))
    return client.post("/login", data={
        "username": "mikoandnenoarecool",
        "password": "test-admin-password",
        "csrf_token": token,
    })


def checker_json(ielts=True):
    """What the results page posts back: the checker's full result JSON."""
    data = {
        "score": 78,
        "summary": {"spelling": 1, "grammar": 2, "style": 3},
        "stats": {"word_count": ielts_report.count_words(ANSWER)},
        "issues": [],
    }
    if ielts:
        data["ielts"] = ielts_report.build_report(ANSWER, task="task2", question=QUESTION)
    return json.dumps(data)


def submit(client, app_module, monkeypatch, **overrides):
    sent = []

    def fake_send_email(**kwargs):
        sent.append(kwargs)
        return True, None

    monkeypatch.setattr(app_module.improve_routes.app_services, "send_email", fake_send_email)
    token = extract_csrf_token(client.get("/improve"))
    data = {
        "fullName": "Sara Ahmed",
        "email": "sara@example.com",
        "phone": "",
        "instructions": ANSWER,
        "terms": "on",
        "csrf_token": token,
    }
    data.update(overrides)
    return client.post("/improve/human/submit", data=data), sent


def saved_rows(app_module):
    conn, cursor = app_module.improve_routes.app_services.open_db()
    try:
        cursor.execute("SELECT mode, ai_results_json, reviewer_note, submission_id FROM submissions")
        submission = cursor.fetchone()
        cursor.execute("SELECT deadline, subject FROM essay_submissions WHERE submission_id = ?",
                       (submission[3],))
        essay = cursor.fetchone()
    finally:
        conn.close()
    return submission, essay


def test_request_form_carries_checker_results_and_has_a_note_box(client):
    token = extract_csrf_token(client.get("/improve"))
    body = client.post("/improve/human/form", data={
        "extracted_text": ANSWER, "ai_results_json": checker_json(), "csrf_token": token,
    }).data.decode("utf-8")
    assert 'name="ai_results_json"' in body
    assert "&#34;score&#34;: 78" in body
    assert 'name="reviewer_note"' in body


def test_ielts_request_email_shows_task_question_checks_and_note(client, app_module, monkeypatch):
    response, sent = submit(client, app_module, monkeypatch,
                            ai_results_json=checker_json(), reviewer_note=NOTE)
    assert b"Submitted for human review" in response.data

    admin = sent[0]
    words = ielts_report.count_words(ANSWER)
    assert admin["subject"] == f"Human review request: IELTS Task 2 essay ({words} words)"
    assert admin["reply_to"] == "sara@example.com"
    body = admin["body"]
    assert "Came from: IELTS writing checker, Task 2 essay" in body
    assert "Question: " + QUESTION in body
    assert "Checker results (score 78):" in body
    assert re.search(r"^  FIX\s+Word count: ", body, re.M)
    assert "Spelling 1, grammar 2, style 3" in body
    assert "Note from the student:\n" + NOTE in body
    assert f"Student's text ({words} words):\n" + ANSWER in body
    for stale in ("Deadline:", "Citation Style", "Writer Preference", "Newsletter"):
        assert stale not in body


def test_student_confirmation_has_no_fake_deadline(client, app_module, monkeypatch):
    _, sent = submit(client, app_module, monkeypatch, ai_results_json=checker_json())
    student = sent[1]
    assert student["to_email"] == "sara@example.com"
    assert "Deadline" not in student["body"]
    assert "Checked with: IELTS writing checker (Task 2 essay)" in student["body"]


def test_submission_saved_with_checker_summary_and_note(client, app_module, monkeypatch):
    submit(client, app_module, monkeypatch, ai_results_json=checker_json(), reviewer_note=NOTE)
    (mode, stored_json, note, _), (deadline, subject) = saved_rows(app_module)
    assert mode == "after_ai"
    assert json.loads(stored_json)["ielts"]["question"] == QUESTION
    assert note == NOTE
    assert deadline == "Not specified"
    assert subject == "IELTS Writing"


def test_general_checker_request_is_labelled_as_essay_checker(client, app_module, monkeypatch):
    _, sent = submit(client, app_module, monkeypatch, ai_results_json=checker_json(ielts=False))
    words = ielts_report.count_words(ANSWER)
    assert sent[0]["subject"] == f"Human review request: essay ({words} words)"
    assert "Came from: essay checker" in sent[0]["body"]
    assert "Checker results (score 78):" in sent[0]["body"]


def test_tampered_checker_results_are_ignored(client, app_module, monkeypatch):
    response, sent = submit(client, app_module, monkeypatch, ai_results_json='{"score": "x", broken')
    assert b"Submitted for human review" in response.data
    assert "no checker results attached" in sent[0]["body"]
    (mode, stored_json, _, _), _ = saved_rows(app_module)
    assert mode == "human_only"
    assert stored_json is None


def test_injected_newlines_cannot_add_lines_to_the_email(client, app_module, monkeypatch):
    data = json.loads(checker_json())
    data["ielts"]["question"] = "Real question\nFrom: attacker@example.com"
    _, sent = submit(client, app_module, monkeypatch, ai_results_json=json.dumps(data))
    body = sent[0]["body"]
    assert "\nFrom: attacker@example.com" not in body
    assert "Question: Real question From: attacker@example.com" in body


def test_validation_error_keeps_results_and_note(client, app_module, monkeypatch):
    response, sent = submit(client, app_module, monkeypatch,
                            ai_results_json=checker_json(), reviewer_note=NOTE, terms="")
    body = response.data.decode("utf-8")
    assert "Please accept the terms and conditions." in body
    assert NOTE in body
    assert "&#34;score&#34;: 78" in body
    assert sent == []


def test_admin_page_shows_readable_results_and_note(client, app_module, monkeypatch):
    submit(client, app_module, monkeypatch, ai_results_json=checker_json(), reviewer_note=NOTE)
    login_admin(client)
    body = client.get("/admin/submissions").data.decode("utf-8")
    assert "From checker" in body
    assert "Checker results" in body
    assert "Came from: IELTS writing checker, Task 2 essay" in body
    assert "Note from the student" in body
    assert NOTE in body
