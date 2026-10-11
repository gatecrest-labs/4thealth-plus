import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def _isolate_tsuite_revocation_env(monkeypatch):
    """app/config.py runs load_dotenv() at import, so a developer's real .env
    (which may set the 4tSuite revocation variables) would otherwise leak into
    every test and silently turn the revocation checker on."""
    for name in (
        "TSUITE_REVOCATIONS_URL",
        "TSUITE_REVOCATIONS_TOKEN",
        "TSUITE_REVOCATIONS_VERIFY_TLS",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def app_ctx():
    from app import create_app

    app = create_app(test_config={"TESTING": True})
    with app.app_context():
        yield app
