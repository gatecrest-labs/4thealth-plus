import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

import app.zone_db as zdb


def _zone(name, trust_level=None):
    return {
        "domain": "Default",
        "is_shared": False,
        "description": "",
        "subnets": [],
        "children": [],
        "parents": [],
        **({"trust_level": trust_level} if trust_level is not None else {}),
    }


def _policy(from_zone, to_zone, access_type="allow all"):
    return {
        "policy_set": "Corp",
        "from_zone": from_zone,
        "to_zone": to_zone,
        "access_type": access_type,
        "severity": "high",
        "services": [],
        "description": "",
    }


def test_score_fully_open():
    """All zone pairs have allow-all — score should be 0%."""
    db = {
        "zones": {"A": _zone("A"), "B": _zone("B")},
        "policies": [_policy("A", "B"), _policy("B", "A")],
    }
    report = zdb.compute_segmentation_report(db)
    # 2 zones → 2 ordered pairs; both open → score = 0
    assert report["score"] == 0.0
    assert report["total_pairs"] == 2
    assert report["open_pair_count"] == 2


def test_score_fully_closed():
    """No allow-all policies — score should be 100%."""
    db = {
        "zones": {"A": _zone("A"), "B": _zone("B")},
        "policies": [_policy("A", "B", "block all")],
    }
    report = zdb.compute_segmentation_report(db)
    assert report["score"] == 100.0
    assert report["open_pair_count"] == 0


def test_score_partial():
    """Three zones, one allow-all out of 6 possible pairs — score = 5/6 ≈ 83.3%."""
    db = {
        "zones": {"A": _zone("A"), "B": _zone("B"), "C": _zone("C")},
        "policies": [_policy("A", "B")],  # only A→B is open
    }
    report = zdb.compute_segmentation_report(db)
    assert report["total_pairs"] == 6
    assert report["open_pair_count"] == 1
    assert abs(report["score"] - 83.3) < 0.1


def test_open_pairs_list():
    """open_pairs contains the correct zone pair."""
    db = {
        "zones": {"A": _zone("A"), "B": _zone("B")},
        "policies": [_policy("A", "B")],
    }
    report = zdb.compute_segmentation_report(db)
    assert len(report["open_pairs"]) == 1
    assert report["open_pairs"][0]["from_zone"] == "A"
    assert report["open_pairs"][0]["to_zone"] == "B"


def test_no_trust_levels_no_mismatches():
    """Zones without trust_level produce no trust_mismatches."""
    db = {
        "zones": {"A": _zone("A"), "B": _zone("B")},
        "policies": [_policy("A", "B")],
    }
    report = zdb.compute_segmentation_report(db)
    assert report["trust_mismatches"] == []
    assert report["has_trust_levels"] is False


def test_trust_mismatch_flagged():
    """Allow-all from low-trust (10) to high-trust (90) zone is flagged."""
    db = {
        "zones": {
            "Guest": _zone("Guest", trust_level=10),
            "Server": _zone("Server", trust_level=90),
        },
        "policies": [_policy("Guest", "Server", "allow all")],
    }
    report = zdb.compute_segmentation_report(db)
    assert report["has_trust_levels"] is True
    assert len(report["trust_mismatches"]) == 1
    m = report["trust_mismatches"][0]
    assert m["from_zone"] == "Guest"
    assert m["to_zone"] == "Server"
    assert m["delta"] == 80


def test_trust_mismatch_below_threshold_not_flagged():
    """Delta < 40 is not flagged."""
    db = {
        "zones": {"A": _zone("A", trust_level=50), "B": _zone("B", trust_level=80)},
        "policies": [_policy("A", "B", "allow all")],
    }
    report = zdb.compute_segmentation_report(db)
    assert report["trust_mismatches"] == []


def test_trust_mismatch_block_policy_not_flagged():
    """block-all policy between mismatched trust zones is not a mismatch."""
    db = {
        "zones": {
            "Guest": _zone("Guest", trust_level=10),
            "Server": _zone("Server", trust_level=90),
        },
        "policies": [_policy("Guest", "Server", "block all")],
    }
    report = zdb.compute_segmentation_report(db)
    assert report["trust_mismatches"] == []


def test_empty_db_returns_zero_score():
    """Empty zone DB returns score=100 and empty lists."""
    db = {"zones": {}, "policies": []}
    report = zdb.compute_segmentation_report(db)
    assert report["score"] == 100.0
    assert report["total_zones"] == 0
    assert report["open_pairs"] == []
