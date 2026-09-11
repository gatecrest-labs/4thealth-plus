from unittest.mock import patch, MagicMock


def test_bulk_device_review_adom_aggregates(app_ctx):
    """bulk_device_review_adom returns one entry per device with rows and no error."""
    from app.routes.audit_review_routes import bulk_device_review_adom

    mock_client = MagicMock()
    mock_client.__enter__ = lambda s: s
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.get_devices.return_value = [
        {"name": "fw-01", "ip": "10.0.0.1", "conn_status": "up"},
        {"name": "fw-02", "ip": "10.0.0.2", "conn_status": "up"},
    ]
    mock_client.get_device_ntp.return_value = {}

    fake_row = {
        "device": "fw-01", "check": "NTP Configuration (CIS)", "result": "CONFIG_MISSING",
        "interface": "system", "vdom": "root", "ip": "", "detail": "no param",
        "protocols": [], "has_insecure": False, "has_secure": False,
    }

    with patch("app.routes.audit_review_routes.make_client", return_value=mock_client):
        with patch("app.routes.audit_review_routes.run_checks", return_value=[fake_row]):
            results = bulk_device_review_adom(
                "TEST", ["ntp_config"], {}, max_workers=2
            )

    assert len(results) == 2
    assert all("device" in r for r in results)
    assert all("rows" in r for r in results)
    assert all(r["error"] is None for r in results)
