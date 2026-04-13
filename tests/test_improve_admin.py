import re

import improve_analysis


def extract_csrf_token(response):
    body = response.data.decode("utf-8")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', body)
    assert match, "csrf token field not found"
    return match.group(1)


def login_admin(client):
    page = client.get("/login")
    token = extract_csrf_token(page)
    return client.post(
        "/login",
        data={
            "username": "mikoandnenoarecool",
            "password": "test-admin-password",
            "csrf_token": token,
        },
        follow_redirects=False,
    )


def test_login_with_env_password_redirects_to_admin(client):
    response = login_admin(client)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin")


def test_admin_dashboard_loads_after_login(client):
    login_response = login_admin(client)
    assert login_response.status_code == 302

    response = client.get("/admin")

    assert response.status_code == 200
    assert b"Admin" in response.data or b"Submission" in response.data


def test_improve_page_loads(client):
    response = client.get("/improve")

    assert response.status_code == 200
    assert b"Improve" in response.data or b"Writing" in response.data


def test_submit_essay_rejects_missing_required_field(client):
    page = client.get("/login")
    token = extract_csrf_token(page)
    response = client.post(
        "/submit",
        data={
            "firstName": "",
            "lastName": "User",
            "email": "user@example.com",
            "essayType": "Essay",
            "academicLevel": "College",
            "subject": "English",
            "pages": "2",
            "deadline": "Tomorrow",
            "topic": "Test",
            "terms": "on",
            "csrf_token": token,
        },
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert b"first_name is required" in response.data


def test_submit_review_rejects_missing_required_field(client):
    page = client.get("/login")
    csrf = extract_csrf_token(page)
    response = client.post(
        "/submit-review",
        json={"name": "Test", "csrf_token": csrf},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert b"university is required" in response.data


def test_checker_dedupe_prefers_tighter_grammar_issue():
    issues = [
        {
            "start": 0,
            "end": 28,
            "kind": "style",
            "message": "Long sentence; consider splitting it.",
            "suggestions": [],
        },
        {
            "start": 10,
            "end": 15,
            "kind": "grammar",
            "message": "Use the correct verb form.",
            "suggestions": ["is"],
        },
    ]

    deduped = improve_analysis._dedupe_issues(issues)

    assert len(deduped) == 1
    assert deduped[0]["kind"] == "grammar"
    assert deduped[0]["start"] == 10
    assert deduped[0]["end"] == 15


def test_checker_dedupe_keeps_non_highlight_rewrite():
    issues = [
        {
            "start": 0,
            "end": 12,
            "kind": "style",
            "message": "Rewrite suggestion",
            "suggestions": [],
            "no_highlight": True,
            "is_rewrite": True,
        },
        {
            "start": 0,
            "end": 4,
            "kind": "grammar",
            "message": "Capitalize this word.",
            "suggestions": ["This"],
        },
    ]

    deduped = improve_analysis._dedupe_issues(issues)

    assert len(deduped) == 2
    assert any(issue.get("no_highlight") for issue in deduped)
    assert any(issue["kind"] == "grammar" for issue in deduped)


def test_checker_flags_subject_verb_agreement_issue():
    result, error, warning = improve_analysis.run_local_analysis("He go to school every day.")

    assert error is None
    assert result is not None
    assert any(
        issue["kind"] == "grammar" and "third-person singular" in issue["message"].lower()
        for issue in result["issues"]
    )


def test_checker_flags_repeated_word_issue():
    result, error, warning = improve_analysis.run_local_analysis("This is is a simple sentence.")

    assert error is None
    assert result is not None
    assert any(
        issue["kind"] == "style" and "repeated word" in issue["message"].lower()
        for issue in result["issues"]
    )


def test_checker_handles_clean_sentence_without_crashing():
    result, error, warning = improve_analysis.run_local_analysis("This is a clear sentence with proper punctuation.")

    assert error is None
    assert result is not None
    assert isinstance(result["issues"], list)
    assert "summary" in result


def test_improve_requires_text_or_file(client):
    page = client.get("/improve")
    token = extract_csrf_token(page)

    response = client.post("/improve/ai", data={"csrf_token": token}, follow_redirects=True)

    assert response.status_code == 200
    assert b"Please paste text or upload a file." in response.data


def test_improve_rejects_missing_csrf(client):
    response = client.post("/improve/ai", data={"text": "Test"}, follow_redirects=False)

    assert response.status_code == 302


def test_improve_rejects_text_over_limit(client, app_module):
    long_text = "a" * (app_module.IMPROVE_MAX_CHARS + 1)
    page = client.get("/improve")
    token = extract_csrf_token(page)

    response = client.post("/improve/ai", data={"text": long_text, "csrf_token": token}, follow_redirects=False)

    assert response.status_code == 302
    assert "/improve/progress/" in response.headers["Location"]

    progress_response = client.get(response.headers["Location"], follow_redirects=True)
    assert progress_response.status_code == 200


def test_improve_creates_job_for_valid_text(client, app_module, monkeypatch):
    created = {}
    page = client.get("/improve")
    token = extract_csrf_token(page)

    def fake_create_job(extracted_text, warning):
        created["text"] = extracted_text
        created["warning"] = warning
        return "job-123"

    def fake_process_job(*args, **kwargs):
        created["process_args"] = args

    monkeypatch.setattr(app_module.improve_routes, "_create_improve_job", fake_create_job)
    monkeypatch.setattr(app_module.improve_routes, "_process_improve_job", fake_process_job)

    response = client.post(
        "/improve/ai",
        data={"text": "This are a test sentence.", "csrf_token": token},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/improve/progress/job-123")
    assert created["text"] == "This are a test sentence."
