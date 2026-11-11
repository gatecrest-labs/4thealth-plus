"""Unit tests for app.zone_ai payload building."""
import json
from unittest.mock import patch

from app import zone_ai


def _capture():
    calls = []

    def fake(system_prompt, payload, *, feature, user=None):
        calls.append({"system": system_prompt, "payload": payload, "feature": feature})
        return "ok", None

    return calls, fake


def _result(i):
    return {"src": f"10.0.0.{i}", "dst": "10.1.0.1", "service": "ssh", "verdict": "BLOCKED",
            "src_zones": ["A"], "dst_zones": ["B"],
            "governing": [{"access_type": "block all", "from_zone": "A", "to_zone": "B"}],
            "all_policies": [{"access_type": "block all"}] * 40}


def test_explain_caps_results_at_20():
    calls, fake = _capture()
    with patch("app.zone_ai.safe_narrate", fake):
        zone_ai.explain_query([_result(i) for i in range(30)])
    p = calls[0]["payload"]
    assert len(p["results"]) == 20 and p["results_not_shown"] == 10
    assert calls[0]["feature"] == "zone_query_explain"
    assert "block all > block only > allow only > allow all" in calls[0]["system"]
    assert "data" in calls[0]["system"].lower()


def test_explain_tolerates_malformed_results():
    calls, fake = _capture()
    with patch("app.zone_ai.safe_narrate", fake):
        zone_ai.explain_query([1, None, {"governing": "x", "src_zones": 5, "all_policies": 3}])
    assert len(calls[0]["payload"]["results"]) == 1


def test_segmentation_payload_orders_mismatches_first_and_caps_pairs():
    calls, fake = _capture()
    report = {
        "score": 40.0, "total_zones": 10, "total_pairs": 90, "open_pair_count": 30,
        "has_trust_levels": True,
        "open_pairs": [{"from_zone": f"a{i}", "to_zone": f"b{i}", "policy_count": 1} for i in range(30)],
        "trust_mismatches": [{"from_zone": f"m{i}", "to_zone": "x", "from_trust": 10,
                              "to_trust": 90, "delta": 80, "policy_count": 1} for i in range(18)],
    }
    with patch("app.zone_ai.safe_narrate", fake):
        zone_ai.summarize_segmentation(report)
    p = calls[0]["payload"]
    keys = list(p)
    assert keys.index("trust_mismatches") < keys.index("open_pairs")
    assert len(p["trust_mismatches"]) == 18
    assert len(p["open_pairs"]) == 15 and p["open_pairs_not_shown"] == 15
    assert calls[0]["feature"] == "zone_segmentation_summary"
    assert "three" in calls[0]["system"].lower()


def test_segmentation_tolerates_malformed_report():
    calls, fake = _capture()
    with patch("app.zone_ai.safe_narrate", fake):
        zone_ai.summarize_segmentation({"open_pairs": "x", "trust_mismatches": [1, {"from_zone": "a"}]})
    json.dumps(calls[0]["payload"])


def test_segmentation_open_pairs_sorted_by_policy_count_before_cap():
    pairs = [{"from_zone": f"a{i}", "to_zone": f"b{i}", "policy_count": 1} for i in range(20)]
    pairs.append({"from_zone": "big", "to_zone": "x", "policy_count": 9})
    cap = {}
    with patch("app.zone_ai.safe_narrate", side_effect=lambda p, payload, **k: cap.update(payload=payload)):
        zone_ai.summarize_segmentation({"open_pairs": pairs})
    shown = cap["payload"]["open_pairs"]
    assert shown[0]["from_zone"] == "big" and len(shown) == 15
