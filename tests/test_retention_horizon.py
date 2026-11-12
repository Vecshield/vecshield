"""Retention horizon: how old the data is, and when that is unknowable.

The failure this guards against is a confidently wrong answer. A date of
birth is timestamp-shaped, and reading one as an ingestion time would report a
clinical corpus as fifty years old — which looks like a finding, reads like a
retention breach, and is nonsense.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from vecshield_platform.scan.retention import (
    RetentionObservation,
    is_subject_date,
    observe_retention,
    parse_timestamp,
)

NOW = datetime(2026, 9, 25, tzinfo=timezone.utc)


# ------------------------------------------------------------------ parsing
@pytest.mark.parametrize("value,expected_year", [
    ("2024-01-15T10:00:00Z", 2024),
    ("2024-01-15T10:00:00+00:00", 2024),
    ("2024-01-15 10:00:00", 2024),
    ("2024-01-15", 2024),
    (1719792000, 2024),            # epoch seconds
    (1719792000000, 2024),         # epoch milliseconds
    (datetime(2024, 1, 15), 2024),  # naive datetime, read as UTC
    (date(2024, 1, 15), 2024),      # a Postgres date column, via psycopg
])
def test_parse_timestamp_accepts_the_shapes_stores_actually_use(value, expected_year):
    parsed = parse_timestamp(value)
    assert parsed is not None and parsed.year == expected_year
    assert parsed.tzinfo is not None, "a naive result would break age arithmetic"


@pytest.mark.parametrize("value", [
    None, "", "not a date", "v2.1.0", 42, 0, -1, True, False, [], {},
    "15/01/2024",   # ambiguous day/month order: refused rather than guessed
])
def test_parse_timestamp_refuses_everything_else(value):
    assert parse_timestamp(value) is None


def test_booleans_are_never_timestamps():
    """bool is a subclass of int; True must not become 1970."""
    assert parse_timestamp(True) is None


# --------------------------------------------------------- field selection
@pytest.mark.parametrize("name", [
    "date_of_birth", "dob", "birth_date", "expiry_date", "expires_at",
    "valid_until", "admission_date", "discharge_date", "appointment_time",
])
def test_subject_dates_are_never_read_as_record_age(name):
    assert is_subject_date(name)


def test_a_date_of_birth_does_not_become_the_retention_horizon():
    """The whole point. A 1968 birth date must not read as a 58-year-old record."""
    observation = observe_retention(
        [{"date_of_birth": "1968-03-11", "text": "clinic letter"}] * 5, now=NOW)
    assert not observation.observable
    assert observation.status == "no_record_timestamp"
    assert "date_of_birth" in observation.excluded
    assert "describe the subject" in observation.summary()


def test_date_values_are_a_record_time_and_a_birth_date_still_is_not():
    """A Postgres ``date`` column arrives as a date object, not a string."""
    records = [{"ingested_on": date(2026, 9, day), "date_of_birth": date(1968, 3, 11)}
               for day in range(1, 6)]
    observation = observe_retention(records, now=NOW)
    assert observation.status == "observed"
    assert "date_of_birth" in observation.excluded
    assert "ingested_on" in observation.summary()

def test_the_field_the_most_records_carry_wins():
    records = [{"created_at": "2024-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}]
    records += [{"updated_at": "2026-02-01T00:00:00Z"}] * 4
    observation = observe_retention(records, now=NOW)
    assert observation.timestamp_field == "updated_at"


def test_ties_break_alphabetically_so_two_runs_agree():
    records = [{"created_at": "2024-01-01T00:00:00Z",
                "indexed_at": "2024-01-01T00:00:00Z"}]
    assert observe_retention(records, now=NOW).timestamp_field == "created_at"


# ------------------------------------------------------------- the horizon
def test_oldest_and_newest_are_reported_with_an_age():
    observation = observe_retention([
        {"ingested_at": "2024-01-15T10:00:00Z"},
        {"ingested_at": "2026-09-01T10:00:00Z"},
    ], now=NOW)
    assert observation.status == "observed"
    assert observation.oldest.startswith("2024-01-15")
    assert observation.newest.startswith("2026-09-01")
    assert observation.oldest_age_days == 983
    assert observation.newest_age_days == 23  # 23d14h from 2026-09-01T10:00; .days truncates


def test_a_partly_dated_collection_says_the_horizon_may_be_older():
    records = [{"created_at": "2025-01-01T00:00:00Z"}] * 3 + [{"text": "no date"}] * 7
    observation = observe_retention(records, now=NOW)
    assert observation.status == "partly_dated"
    assert observation.records_dated == 3 and observation.records_scanned == 10
    assert "may be older" in observation.summary()


def test_an_empty_collection_reports_nothing_scanned_not_a_clean_pass():
    observation = observe_retention([], now=NOW)
    assert observation.status == "nothing_scanned"
    assert not observation.observable


def test_future_timestamps_do_not_produce_negative_ages():
    observation = observe_retention([{"created_at": "2030-01-01T00:00:00Z"}], now=NOW)
    assert observation.oldest_age_days == 0


# -------------------------------------------------------------- reporting
def test_the_result_never_claims_the_age_is_permitted():
    """VecShield does not hold the retention schedule and must not imply it."""
    payload = observe_retention([{"created_at": "2019-01-01T00:00:00Z"}],
                                now=NOW).to_dict()
    assert "not a judgement" in payload["note"]
    for banned in ("violation", "breach", "non-compliant", "overdue"):
        assert banned not in str(payload).lower()


def test_to_dict_is_json_safe_and_carries_the_summary():
    import json

    payload = observe_retention([{"created_at": "2025-01-01T00:00:00Z"}],
                                now=NOW).to_dict()
    json.dumps(payload)
    assert payload["summary"] and payload["field"] == "created_at"


def test_an_unparseable_value_in_a_time_shaped_field_is_not_counted():
    observation = observe_retention([{"created_at": "not a date"}] * 3, now=NOW)
    assert observation.status == "no_record_timestamp"
    assert RetentionObservation().coverage == 0.0
