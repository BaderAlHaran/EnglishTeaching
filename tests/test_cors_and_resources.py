import importlib
import sys
import types
import warnings

import pytest


@pytest.fixture()
def production_app(tmp_path, monkeypatch):
    """The app as Render runs it: production mode, real domain set."""
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("CUSTOM_DOMAIN", "englishessaywriting.net")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.sqlite"))
    monkeypatch.setenv("UPLOAD_FOLDER", str(tmp_path / "uploads"))
    monkeypatch.setenv("RESEND_API_KEY", "")
    monkeypatch.setitem(sys.modules, "resend", types.SimpleNamespace(api_key=""))
    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    module.app.config.update(TESTING=True)
    yield module
    sys.modules.pop("app", None)


def _allow_origin(client, origin):
    headers = {"Origin": origin} if origin else {}
    return client.get("/faq", headers=headers).headers.get("Access-Control-Allow-Origin")


def test_production_allows_only_the_real_domain(production_app):
    client = production_app.app.test_client()
    assert _allow_origin(client, "https://englishessaywriting.net") == "https://englishessaywriting.net"
    assert _allow_origin(client, "https://www.englishessaywriting.net") == "https://www.englishessaywriting.net"


def test_production_rejects_dev_servers_and_other_render_apps(production_app):
    client = production_app.app.test_client()
    for origin in ("http://127.0.0.1:5000", "http://localhost:5000",
                   "https://someone-else.onrender.com", "https://evil.example"):
        assert _allow_origin(client, origin) is None, origin


def test_production_sends_no_cors_header_without_an_origin(production_app):
    """The live site used to answer plain requests with the dev address."""
    assert _allow_origin(production_app.app.test_client(), None) is None


def test_development_still_allows_local_dev_servers(client):
    assert _allow_origin(client, "http://127.0.0.1:5000") == "http://127.0.0.1:5000"


def test_spelling_dictionary_loads_without_deprecation_warnings(monkeypatch):
    pytest.importorskip("symspellpy")
    import improve_analysis

    # Force a fresh load rather than reusing one cached by an earlier test.
    monkeypatch.setattr(improve_analysis, "_IMPROVE_SYMSPELL", None)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        improve_analysis.run_local_analysis("Thsi sentense has two typos in it.")

    ours = [w for w in caught
            if issubclass(w.category, DeprecationWarning) and w.filename.endswith("improve_analysis.py")]
    assert ours == [], [str(w.message) for w in ours]
    assert improve_analysis._IMPROVE_SYMSPELL is not None, "the dictionary did not load"
