import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from unittest.mock import MagicMock

import pytest


@pytest.mark.parametrize(
    "raw, expected",
    [
        # Real strings: 8.0.2 captured from a lab FMG-VM64-KVM, 7.4 per psirt/engine docs.
        ("v8.0.2-build0198 261006 (GA.F)", (8, 0, 2, 198)),
        ("v7.4.5,build2360,240702 (GA)", (7, 4, 5, 2360)),
        ("v7.6.7-build3737 260101 (GA)", (7, 6, 7, 3737)),
        ("v7.6.7", (7, 6, 7, None)),
        ("7.4.10", (7, 4, 10, None)),
    ],
)
def test_parse_fmg_version(raw, expected):
    from app.fmg_client import parse_fmg_version

    v = parse_fmg_version(raw)
    assert (v.major, v.minor, v.patch, v.build) == expected


@pytest.mark.parametrize("raw", ["", None, "garbage", "v8", 42])
def test_parse_fmg_version_unparseable_returns_none(raw):
    from app.fmg_client import parse_fmg_version

    assert parse_fmg_version(raw) is None


def test_fmg_version_train_and_ordering():
    from app.fmg_client import parse_fmg_version

    v = parse_fmg_version("v8.0.2-build0198 261006 (GA.F)")
    assert v.train == "8.0"
    assert v >= (7, 6)
    assert not (v < (8, 0, 2))
    assert parse_fmg_version("v7.4.5,build2360") < parse_fmg_version("v7.6.0")


def test_client_version_is_fetched_once_and_cached():
    from app.fmg_client import FMGClient

    c = FMGClient(host="fmg.example.com", token="tok")
    c.get_system_status = MagicMock(
        return_value={"Version": "v8.0.2-build0198 261006 (GA.F)"}
    )
    assert c.version.train == "8.0"
    assert c.version.patch == 2
    c.get_system_status.assert_called_once()


def test_client_version_unknown_when_status_unavailable():
    from app.fmg_client import FMGClient, FMGError

    c = FMGClient(host="fmg.example.com", token="tok")
    c.get_system_status = MagicMock(side_effect=FMGError("boom"))
    assert c.version is None
    # A failed lookup is not cached forever as success, but must not raise.
    assert c.version is None
