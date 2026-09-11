import re
import types


def extract_csrf_token(response):
    body = response.data.decode("utf-8")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', body)
    assert match, "csrf token field not found"
    return match.group(1)


class ImmediateThread:
    """Runs the checker job inline so a test can see what it was given."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self.target = target
        self.args = args
        self.kwargs = kwargs or {}

    def start(self):
        self.target(*self.args, **self.kwargs)


def _checked_task(body):
    match = re.search(r'value="(task[12])"[^>]*\bchecked\b', body)
    return match.group(1) if match else None


def _post_to_checker(client, app_module, monkeypatch, data):
    captured = {}
    token = extract_csrf_token(client.get("/ielts-writing-checker"))
    monkeypatch.setattr(app_module.improve_routes, "_create_improve_job", lambda text, warning: "job-ielts")
    monkeypatch.setattr(app_module.improve_routes, "_process_improve_job",
                        lambda *args, **kwargs: captured.setdefault("args", args))
    # Patch only the threading reference inside improve_routes; replacing
    # threading.Thread itself also breaks the Timer thread Flask-Limiter uses.
    monkeypatch.setattr(app_module.improve_routes, "threading", types.SimpleNamespace(Thread=ImmediateThread))
    response = client.post("/improve/ai", data=dict(data, csrf_token=token), follow_redirects=False)
    return response, captured


def test_ielts_page_loads_with_one_h1_and_canonical(client):
    response = client.get("/ielts-writing-checker")
    assert response.status_code == 200
    body = response.data.decode("utf-8")
    assert body.count("<h1") == 1
    assert "IELTS Writing Checker" in body
    assert '<link rel="canonical" href="https://englishessaywriting.net/ielts-writing-checker">' in body
    assert 'name="exam" value="ielts"' in body


def test_ielts_page_defaults_to_task2(client):
    body = client.get("/ielts-writing-checker").data.decode("utf-8")
    assert _checked_task(body) == "task2"


def test_ielts_page_preselects_task_from_query(client):
    body = client.get("/ielts-writing-checker?task=task1").data.decode("utf-8")
    assert _checked_task(body) == "task1"


def test_ielts_page_ignores_unknown_task(client):
    body = client.get("/ielts-writing-checker?task=bogus").data.decode("utf-8")
    assert _checked_task(body) == "task2"


def test_sitemap_lists_ielts_page(client):
    assert b"/ielts-writing-checker" in client.get("/sitemap.xml").data


def test_ielts_submission_passes_task_and_question_to_job(client, app_module, monkeypatch):
    response, captured = _post_to_checker(client, app_module, monkeypatch, {
        "text": "The chart shows sales in three shops.",
        "exam": "ielts",
        "task": "task1",
        "question": "  The chart below shows sales.  ",
    })
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/improve/progress/job-ielts")
    assert captured["args"][4] == {"task": "task1", "question": "The chart below shows sales."}


def test_ielts_submission_with_unknown_task_uses_task2(client, app_module, monkeypatch):
    _, captured = _post_to_checker(client, app_module, monkeypatch, {
        "text": "Some answer text.", "exam": "ielts", "task": "task7",
    })
    assert captured["args"][4]["task"] == "task2"


def test_general_checker_submission_has_no_ielts_options(client, app_module, monkeypatch):
    _, captured = _post_to_checker(client, app_module, monkeypatch, {"text": "This are a test sentence."})
    assert captured["args"][4] is None


def test_empty_ielts_answer_returns_to_the_ielts_page(client):
    token = extract_csrf_token(client.get("/ielts-writing-checker"))
    response = client.post("/improve/ai", data={
        "text": "", "exam": "ielts", "task": "task1", "question": "Q", "csrf_token": token,
    })
    body = response.data.decode("utf-8")
    assert response.status_code == 200
    assert "Please paste your answer." in body
    assert "IELTS Writing Checker" in body
    assert _checked_task(body) == "task1"


ANSWER = (
    "The graph shows sales in three shops between 2010 and 2020.\n\n"
    "Overall, sales rose in every shop. It's clear the largest shop grew fastest.\n\n"
    "In 2010 the largest shop sold 40 units, and by 2020 it sold 95."
)


def test_ielts_result_shows_checklist_and_links_back(client, app_module):
    routes = app_module.improve_routes
    job_id = routes._create_improve_job(ANSWER, None)
    routes._process_improve_job(job_id, ANSWER, None, "en-GB", {"task": "task1", "question": ""})

    body = client.get(f"/improve/result/{job_id}").data.decode("utf-8")
    assert "IELTS Academic Task 1 report checklist" in body
    assert 'data-recheck-url="/ielts-writing-checker?task=task1"' in body
    assert 'href="/ielts-writing-checker?task=task1"' in body
    assert "Contraction. Use the full form in IELTS Writing." in body


def test_general_result_still_links_to_the_essay_checker(client, app_module):
    routes = app_module.improve_routes
    job_id = routes._create_improve_job(ANSWER, None)
    routes._process_improve_job(job_id, ANSWER, None)

    body = client.get(f"/improve/result/{job_id}").data.decode("utf-8")
    assert "checklist</h4>" not in body
    assert 'data-recheck-url="/improve"' in body
    assert 'href="/improve" class="btn btn--secondary">Start Over' in body
