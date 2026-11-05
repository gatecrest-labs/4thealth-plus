import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

import pytest

from app.fmg_helpers import format_fortios_version


def _legacy_inline(d: dict) -> str:
    """The logic that was copy-pasted into versions_cache, map_cache,
    license_status_cache, executive_summary_cache and audit_review_routes."""
    os_ver = d.get("os_ver", 0)
    mr = d.get("mr")
    patch = d.get("patch")
    major = (
        int(os_ver) // 100 if str(os_ver).isdigit() and int(os_ver) >= 100 else os_ver
    )
    if mr is not None and patch is not None and int(patch) >= 0:
        return f"v{major}.{mr}.{patch}"
    if mr is not None:
        return f"v{major}.{mr}"
    return "n/a"


@pytest.mark.parametrize(
    "d, expected",
    [
        ({"os_ver": 7, "mr": 6, "patch": 8}, "v7.6.8"),
        ({"os_ver": 8, "mr": 0, "patch": 2}, "v8.0.2"),  # FortiOS 8.0 on FMG 8.0.2
        ({"os_ver": 7, "mr": 4, "patch": 0}, "v7.4.0"),  # patch 0 is a real patch
        ({"os_ver": 700, "mr": 4, "patch": 5}, "v7.4.5"),  # legacy FMG encoding
        ({"os_ver": 6, "mr": 4, "patch": 15}, "v6.4.15"),
    ],
)
def test_normal_records_match_the_old_inline_logic(d, expected):
    assert format_fortios_version(d) == expected
    assert format_fortios_version(d) == _legacy_inline(d)


@pytest.mark.parametrize(
    "d, expected",
    [
        ({"os_ver": 7, "mr": 6, "patch": -1}, "v7.6"),  # -1 = patch unknown
        ({"os_ver": 7, "mr": 6, "patch": None}, "v7.6"),
        ({"os_ver": 7, "mr": 6}, "v7.6"),
        ({"os_ver": 7, "mr": 6, "patch": "x"}, "v7.6"),  # garbage must not raise
    ],
)
def test_unknown_patch_is_dropped_not_rendered(d, expected):
    assert format_fortios_version(d) == expected


def test_patch_minus_one_never_renders_as_a_version_component():
    # pending_status_cache used to show "v7.6.-1" for these.
    assert "-1" not in format_fortios_version({"os_ver": 7, "mr": 6, "patch": -1})


@pytest.mark.parametrize("os_ver", ["7", "7.0", " 8 "])
def test_string_os_ver_uses_its_leading_integer(os_ver):
    # FMG sometimes sends "7.0" where ".0" is a legacy suffix, not the minor release.
    major = os_ver.strip().split(".")[0]
    assert (
        format_fortios_version({"os_ver": os_ver, "mr": 6, "patch": 8})
        == f"v{major}.6.8"
    )


def test_numeric_strings_for_mr_and_patch_work():
    assert format_fortios_version({"os_ver": 7, "mr": "6", "patch": "8"}) == "v7.6.8"


@pytest.mark.parametrize(
    "d",
    [
        {},
        {"os_ver": 0},
        {"os_ver": 7},
        {"os_ver": None, "mr": None},
        {"os_ver": "", "mr": 3},
    ],
)
def test_unusable_records_return_the_unknown_marker(d):
    assert format_fortios_version(d) == "n/a"
    assert format_fortios_version(d, unknown="") == ""


def test_prefix_is_configurable_for_comparison_strings():
    assert (
        format_fortios_version({"os_ver": 7, "mr": 6, "patch": 8}, prefix="") == "7.6.8"
    )
    assert format_fortios_version({"os_ver": 8, "mr": 0}, prefix="") == "8.0"


def test_non_dict_input_is_unknown_not_a_crash():
    assert format_fortios_version(None) == "n/a"
    assert format_fortios_version("v7.6.8") == "n/a"
