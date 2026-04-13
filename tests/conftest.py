import importlib
import os
import sys
import types

import pytest


@pytest.fixture()
def app_module(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.sqlite"))
    monkeypatch.setenv("UPLOAD_FOLDER", str(tmp_path / "uploads"))
    monkeypatch.setenv("RESEND_API_KEY", "")
    monkeypatch.setenv("FLASK_ENV", "development")
    sys.modules["resend"] = types.SimpleNamespace(api_key="")

    if "app" in sys.modules:
        del sys.modules["app"]

    module = importlib.import_module("app")
    module.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )
    return module


@pytest.fixture()
def client(app_module):
    return app_module.app.test_client()
