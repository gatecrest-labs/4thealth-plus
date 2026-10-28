from app.fmg_helpers import expand_ha_members


def _expand(d, conn=1):
    return list(expand_ha_members(d, "v7.4.1", "ADOM1", conn))


def test_standalone_yields_single_unit():
    out = _expand(
        {"name": "fw1", "ip": "10.0.0.1", "sn": "S1", "platform_str": "FG-201G"}
    )
    assert len(out) == 1
    assert out[0]["ha_role"] == ""
    assert out[0]["serial"] == "S1"
    assert out[0]["status"] == "green"


def test_cluster_yields_only_members_with_roles_by_priority():
    d = {
        "name": "cluster",
        "ip": "10.0.0.2",
        "ha_mode": 2,
        "platform_str": "FG-201G",
        "ha_slave": [
            {"name": "b", "sn": "SB", "prio": 100},
            {"name": "a", "sn": "SA", "prio": 200},
        ],
    }
    out = _expand(d)
    assert [u["name"] for u in out] == ["a", "b"]
    assert [u["ha_role"] for u in out] == ["Primary", "Secondary"]
    assert all(u["ip"] == "10.0.0.2" for u in out)  # inherits cluster IP


def test_member_conn_status_overrides_cluster():
    d = {
        "name": "c",
        "ha_mode": 1,
        "ha_slave": [{"name": "a", "prio": 1, "conn_status": 0}],
    }
    assert _expand(d, conn=1)[0]["status"] == "offline"


def test_ha_mode_without_slaves_is_standalone():
    out = _expand({"name": "c", "ha_mode": 2})
    assert len(out) == 1 and out[0]["ha_role"] == ""
