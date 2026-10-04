import re
import types


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


class ImmediateThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self.target = target
        self.args = args
        self.kwargs = kwargs or {}

    def start(self):
        pass  # the analysis itself is irrelevant to counting runs


def run_check(client, app_module, monkeypatch, data):
    monkeypatch.setattr(app_module.improve_routes, "threading",
                        types.SimpleNamespace(Thread=ImmediateThread))
    token = extract_csrf_token(client.get("/improve"))
    return client.post("/improve/ai", data=dict(data, csrf_token=token), follow_redirects=False)


def counts(app_module):
    conn, cursor = app_module.improve_routes.app_services.open_db()
    try:
        cursor.execute("SELECT exam, task FROM checker_runs ORDER BY id")
        return cursor.fetchall()
    finally:
        conn.close()


def test_ielts_and_essay_runs_are_counted_separately(client, app_module, monkeypatch):
    run_check(client, app_module, monkeypatch,
              {"text": "The chart shows sales.", "exam": "ielts", "task": "task1"})
    run_check(client, app_module, monkeypatch, {"text": "A plain essay draft."})

    assert counts(app_module) == [("ielts", "task1"), ("essay", None)]


def test_counts_survive_the_30_day_cleanup(client, app_module, monkeypatch):
    # Mark the once-a-day cleanup as already done, so it does not also run in a
    # background thread and race this test's own call for the sqlite file.
    monkeypatch.setattr(app_module, "_last_cleanup_checked",
                        app_module.datetime.now().date().isoformat())
    run_check(client, app_module, monkeypatch,
              {"text": "The chart shows sales.", "exam": "ielts", "task": "task2"})
    routes = app_module.improve_routes

    conn, cursor = routes.app_services.open_db()
    try:
        cursor.execute("UPDATE improve_jobs SET created_at = ?", ("2020-01-01 00:00:00",))
        cursor.execute("UPDATE checker_runs SET created_at = ?", ("2020-01-01 00:00:00",))
        cursor.execute("DELETE FROM app_meta WHERE key = ?", ("last_cleanup_date",))
        conn.commit()
    finally:
        conn.close()

    app_module._run_cleanup_if_needed()

    conn, cursor = routes.app_services.open_db()
    try:
        cursor.execute("SELECT COUNT(*) FROM improve_jobs")
        jobs_left = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM checker_runs")
        runs_left = cursor.fetchone()[0]
    finally:
        conn.close()

    assert jobs_left == 0, "the essay text should be deleted"
    assert runs_left == 1, "the count of runs must be kept"


def test_existing_jobs_are_backfilled_once(client, app_module):
    routes = app_module.improve_routes
    ielts_job = routes._create_improve_job("an IELTS answer", None)
    essay_job = routes._create_improve_job("an essay", None)
    conn, cursor = routes.app_services.open_db()
    try:
        cursor.execute("UPDATE improve_jobs SET result_json = ? WHERE job_id = ?",
                       ('{"score": 70, "ielts": {"task": "task2"}}', ielts_job))
        cursor.execute("UPDATE improve_jobs SET result_json = ? WHERE job_id = ?",
                       ('{"score": 70}', essay_job))
        conn.commit()
    finally:
        conn.close()

    routes._ensure_checker_runs_table()
    first = counts(app_module)
    assert sorted(exam for exam, _ in first) == ["essay", "ielts"]

    routes._ensure_checker_runs_table()
    assert counts(app_module) == first, "the backfill must not run twice"


def test_analytics_page_shows_ielts_counts(client, app_module, monkeypatch):
    run_check(client, app_module, monkeypatch,
              {"text": "The chart shows sales.", "exam": "ielts", "task": "task2"})
    run_check(client, app_module, monkeypatch, {"text": "A plain essay draft."})
    login_admin(client)

    body = client.get("/admin/analytics").data.decode("utf-8")
    assert "IELTS Checker Runs Today" in body
    assert "IELTS Checker Runs (All Time)" in body
    assert "<th>IELTS Runs</th>" in body
    cards = dict(re.findall(r'stat-label">([^<]+)</div>\s*<div class="stat-value">(\d+)</div>', body))
    assert cards["Checker Runs Today"] == "2"
    assert cards["IELTS Checker Runs Today"] == "1"
    assert cards["IELTS Checker Runs (All Time)"] == "1"
