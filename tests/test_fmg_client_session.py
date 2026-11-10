import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from unittest.mock import MagicMock


def test_fmg_client_uses_requests_session():
    """FMGClient._post must use self._http (a requests.Session), not module-level requests.post."""
    from app.fmg_client import FMGClient
    client = FMGClient(host="fmg.example.com", token="tok")
    assert hasattr(client, "_http"), "FMGClient must have a _http attribute"
    import requests as req_mod
    assert isinstance(client._http, req_mod.Session)


def test_fmg_client_http_session_not_closed_on_exit():
    """The session is the process-wide pool (app.fmg_access); other threads still use it."""
    from app.fmg_client import FMGClient
    client = FMGClient(host="fmg.example.com", token="tok")
    mock_session = MagicMock()
    client._http = mock_session
    client.__exit__(None, None, None)
    mock_session.close.assert_not_called()
