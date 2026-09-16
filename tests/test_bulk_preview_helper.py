import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("FMG_PRIMARY_HOST", "127.0.0.1")



def test_bulk_preview_adom_importable():
    from app.routes.pending_changes_routes import bulk_preview_adom
    assert callable(bulk_preview_adom)
