import ast
import glob
from datetime import datetime, timezone


def test_trailing_slash_redirects_to_the_real_page(client):
    response = client.get("/improve/", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["Location"].endswith("/improve")


def test_trailing_slash_keeps_the_query_string(client):
    response = client.get("/ielts-writing-checker/?task=task1", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["Location"].endswith("/ielts-writing-checker?task=task1")


def test_the_homepage_slash_is_left_alone(client):
    assert client.get("/").status_code == 200


def test_normal_urls_are_not_redirected(client):
    for path in ("/improve", "/ielts-writing-checker", "/faq"):
        assert client.get(path, follow_redirects=False).status_code == 200, path


def test_posts_are_never_turned_into_redirects(client):
    """A 301 on a POST would drop the form data, so only GET and HEAD move."""
    response = client.post("/track/", json={"path": "/"}, follow_redirects=False)
    assert response.status_code != 301


def test_no_deprecated_utcnow_left_in_the_source():
    """Parsed rather than grepped, so the docstrings that mention the
    deprecation are not mistaken for calls."""
    offenders = []
    for path in glob.glob("*.py"):
        tree = ast.parse(open(path, encoding="utf-8").read(), path)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "utcnow"):
                offenders.append("%s:%d" % (path, node.lineno))
    assert offenders == [], offenders


def test_utcnow_helper_matches_the_shape_the_database_stores(app_module):
    stamp = app_module._utcnow()
    # Naive, so it can still be compared with timestamps read back from the DB.
    assert stamp.tzinfo is None
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    assert abs((stamp - now).total_seconds()) < 5
