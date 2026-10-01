def test_add_group_member_adds_a_new_member(tmp_path, monkeypatch):
    import app.groups as groups_mod

    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    groups_mod.create_group("operators", members=[], allowed_tabs=["dashboard"])

    groups_mod.add_group_member("operators", "dave")

    assert groups_mod.get_group("operators")["members"] == ["dave"]


def test_add_group_member_is_idempotent(tmp_path, monkeypatch):
    import app.groups as groups_mod

    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    groups_mod.create_group("operators", members=["dave"], allowed_tabs=["dashboard"])

    groups_mod.add_group_member("operators", "dave")

    assert groups_mod.get_group("operators")["members"] == ["dave"]


def test_add_group_member_does_nothing_for_unknown_group(tmp_path, monkeypatch):
    import app.groups as groups_mod

    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")

    groups_mod.add_group_member("nonexistent", "dave")  # must not raise

    assert groups_mod.get_group("nonexistent") is None


def test_remove_group_member_removes_an_existing_member(tmp_path, monkeypatch):
    import app.groups as groups_mod

    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    groups_mod.create_group("operators", members=["dave"], allowed_tabs=["dashboard"])

    groups_mod.remove_group_member("operators", "dave")

    assert groups_mod.get_group("operators")["members"] == []


def test_remove_group_member_is_idempotent(tmp_path, monkeypatch):
    import app.groups as groups_mod

    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    groups_mod.create_group("operators", members=[], allowed_tabs=["dashboard"])

    groups_mod.remove_group_member("operators", "dave")  # must not raise

    assert groups_mod.get_group("operators")["members"] == []


def test_add_group_member_preserves_other_fields(tmp_path, monkeypatch):
    import app.groups as groups_mod

    monkeypatch.setattr(groups_mod, "GROUPS_FILE", tmp_path / "groups.json")
    groups_mod.create_group(
        "operators",
        members=[],
        allowed_tabs=["dashboard"],
        adom_restrict=True,
        allowed_adoms=["root"],
    )

    groups_mod.add_group_member("operators", "dave")

    group = groups_mod.get_group("operators")
    assert group["allowed_tabs"] == ["dashboard"]
    assert group["adom_restrict"] is True
    assert group["allowed_adoms"] == ["root"]
