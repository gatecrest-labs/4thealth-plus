import inspect
import json
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")


def test_save_db_is_atomic(tmp_path, monkeypatch):
    """save_db should write to a temp file and rename, not write in-place."""
    import app.zone_db as zdb
    monkeypatch.setattr(zdb, "DB_PATH", tmp_path / "policy_db.json")

    db = {"zones": {}, "policies": []}
    zdb.save_db(db)

    assert (tmp_path / "policy_db.json").exists()
    with open(tmp_path / "policy_db.json") as f:
        result = json.load(f)
    assert result == db


def test_save_db_uses_replace(tmp_path, monkeypatch):
    """Verify os.replace is used (not a plain open write) by inspecting source."""
    import app.zone_db as zdb
    src = inspect.getsource(zdb.save_db)
    assert "os.replace" in src or "replace(" in src or "atomic_write_json(" in src, \
        "save_db must use os.replace or atomic_write_json for atomic writes"
