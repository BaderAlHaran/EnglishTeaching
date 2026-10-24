"""Guards for the audit fixes: connection handling, HSTS, and the title and
description lengths Google will actually display."""
import glob
import os
import re


def test_hsts_header_is_sent(client):
    response = client.get("/")
    assert "max-age=" in response.headers.get("Strict-Transport-Security", "")


def test_a_handler_that_forgets_to_close_still_releases_its_connection(app_module):
    """The teardown is the safety net for the 20-odd handlers that close by
    hand on every branch."""
    closed = []

    class FakeConnection:
        def close(self):
            closed.append(True)

    with app_module.app.test_request_context("/"):
        app_module._track_connection(FakeConnection())
    assert closed, "the connection was never closed"


def test_tracking_outside_a_request_does_not_raise(app_module):
    class FakeConnection:
        def close(self):
            pass

    # Background jobs open connections with no request in flight.
    app_module._track_connection(FakeConnection())


def test_results_page_closes_its_connection_on_failure(app_module, monkeypatch):
    """improve_result runs on every finished check, so its connection must be
    returned even when the query raises."""
    routes = app_module.improve_routes
    closed = []
    real_open = routes.app_services.open_db

    class ClosingSpy:
        """sqlite3 connections do not allow attribute assignment, so wrap."""

        def __init__(self, conn):
            self._conn = conn

        def close(self):
            closed.append(True)
            self._conn.close()

        def __getattr__(self, name):
            return getattr(self._conn, name)

    class BoomCursor:
        def execute(self, *args, **kwargs):
            raise RuntimeError("database went away")

    def tracking_open():
        conn, _ = real_open()
        return ClosingSpy(conn), BoomCursor()

    monkeypatch.setattr(routes.app_services, "open_db", tracking_open)
    with app_module.app.test_request_context("/improve/result/abc"):
        try:
            routes.improve_result("abc")
        except RuntimeError:
            pass
    assert closed, "connection leaked when the query failed"


PAGES = glob.glob("*.html") + glob.glob(os.path.join("templates", "*.html"))


def test_titles_and_descriptions_fit_in_search_results():
    too_long = []
    for path in PAGES:
        html = open(path, encoding="utf-8").read()
        if 'name="robots" content="noindex' in html:
            continue
        title = re.search(r"<title>(.*?)</title>", html, re.S)
        desc = re.search(r'<meta name="description" content="(.*?)"', html, re.S)
        if title and len(title.group(1)) > 60:
            too_long.append("%s title %d chars" % (path, len(title.group(1))))
        if desc and len(desc.group(1)) > 160:
            too_long.append("%s description %d chars" % (path, len(desc.group(1))))
    assert not too_long, too_long


def test_dependencies_are_all_pinned():
    unpinned = [line.strip() for line in open("requirements.txt", encoding="utf-8")
                if line.strip() and not line.startswith("#")
                and "==" not in line and "@" not in line]
    assert unpinned == [], unpinned


def test_dead_entry_points_are_gone():
    for name in ("simple_app.py", "run_simple.py", "deploy.sh", "deploy_to_render.sh",
                 "start.sh", "Dockerfile"):
        assert not os.path.exists(name), name
