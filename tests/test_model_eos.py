"""Tests for app.model_eos — hardware EOS lookups and month-window math."""
import datetime
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")

from app.model_eos import _add_months, hw_eos_within, is_hw_eos


# ── is_hw_eos ────────────────────────────────────────────────────────────────


def test_is_hw_eos_true_when_past_eos_date():
    assert is_hw_eos("FortiGate-60C", as_of=datetime.date(2026, 9, 10)) is True


def test_is_hw_eos_false_when_not_yet_eos():
    assert is_hw_eos("FortiGate-100F", as_of=datetime.date(2026, 9, 10)) is False


def test_is_hw_eos_true_on_exact_eos_date():
    assert is_hw_eos("FortiGate-60E", as_of=datetime.date(2026, 12, 29)) is True


def test_is_hw_eos_none_for_unknown_model():
    assert is_hw_eos("FortiGate-9999Z", as_of=datetime.date(2026, 9, 10)) is None


def test_is_hw_eos_none_never_false_for_unknown_model():
    # Regression guard: absence of data must never silently read as "safe".
    result = is_hw_eos("SomeUnknownDevice", as_of=datetime.date(2026, 9, 10))
    assert result is not False
    assert result is None


def test_is_hw_eos_defaults_as_of_to_today():
    # Doesn't crash and returns a real value for a long-past EOS model.
    assert is_hw_eos("FortiGate-60C") is True


def test_is_hw_eos_strips_whitespace():
    assert is_hw_eos(" FortiGate-60C ", as_of=datetime.date(2026, 9, 10)) is True


# ── hw_eos_within ────────────────────────────────────────────────────────────


def test_hw_eos_within_true_when_eos_within_window():
    # FortiGate-60E EOS is 2026-12-29; from 2026-9-10, that's within 12 months.
    assert hw_eos_within("FortiGate-60E", 12, as_of=datetime.date(2026, 9, 10)) is True


def test_hw_eos_within_false_when_eos_beyond_window():
    # FortiGate-100F EOS is 2031-04-16 — far beyond a 12-month window from now.
    assert hw_eos_within("FortiGate-100F", 12, as_of=datetime.date(2026, 9, 10)) is False


def test_hw_eos_within_true_when_already_past_eos():
    # Already-EOS models are trivially "within" any forward window.
    assert hw_eos_within("FortiGate-60C", 12, as_of=datetime.date(2026, 9, 10)) is True


def test_hw_eos_within_none_for_unknown_model():
    assert hw_eos_within("Unknown-Model", 12, as_of=datetime.date(2026, 9, 10)) is None


def test_hw_eos_within_boundary_at_exactly_the_cutoff():
    # FortiGate-30E EOS 2026-7-15; 3 months from 2026-4-15 lands exactly on it.
    assert hw_eos_within("FortiGate-30E", 3, as_of=datetime.date(2026, 4, 15)) is True


def test_hw_eos_within_one_day_short_of_the_cutoff_is_false():
    # 3 months from 2026-4-14 lands one day before the 2026-7-15 EOS date.
    assert hw_eos_within("FortiGate-30E", 3, as_of=datetime.date(2026, 4, 14)) is False


# ── _add_months ──────────────────────────────────────────────────────────────


def test_add_months_simple():
    assert _add_months(datetime.date(2026, 9, 10), 3) == datetime.date(2026, 12, 10)


def test_add_months_rolls_over_year():
    assert _add_months(datetime.date(2026, 11, 1), 3) == datetime.date(2027, 2, 1)


def test_add_months_clamps_day_for_shorter_month():
    # Jan 31 + 1 month -> Feb has no 31st.
    assert _add_months(datetime.date(2026, 1, 31), 1) == datetime.date(2026, 2, 28)


def test_add_months_handles_leap_year_february():
    assert _add_months(datetime.date(2027, 12, 31), 2) == datetime.date(2028, 2, 29)
