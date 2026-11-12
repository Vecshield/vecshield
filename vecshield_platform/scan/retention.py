"""How old the data is — and whether that is knowable at all.

Nothing else in the product looks at a timestamp. The scan engine reads chunk
metadata to classify it and discards the temporal part, so a reviewer asked
"how long have you held this?" has nothing to answer with.

This module observes the answer where the records carry one, and says so
plainly where they do not. The second case is the common one and is the more
useful finding: a collection with no temporal signal cannot have a retention
policy applied to it by anyone, which is a different and more actionable
statement than "retention looks fine".

**It does not evaluate whether an age is permitted.** VecShield does not know
the retention schedule, the lawful basis, or whether a record is under legal
hold. It reports the horizon; a person decides whether it is too long. For
that reason this check never emits ``failed`` — an old record is not a
violation, it is a fact a reviewer needs.

Pure: no I/O, no connector, no clock except the one passed in.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Optional

#: Field names that plausibly record when *this record* arrived.
_TIME_HINTS = (
    "created", "created_at", "ingested", "ingested_at", "indexed", "indexed_at",
    "inserted", "inserted_at", "imported", "imported_at", "updated",
    "updated_at", "modified", "last_modified", "timestamp", "ts", "date",
    "datetime", "loaded_at", "synced_at", "crawled_at", "published_at",
)

#: Field names that are timestamp-shaped but describe the *subject*, not the
#: record. Treating a date of birth as an ingestion time would report a corpus
#: as decades old and is exactly the kind of confident wrong answer this
#: product exists not to give.
_SUBJECT_TIME_FIELDS = (
    "birth", "dob", "born", "death", "died", "expiry", "expires", "expiration",
    "valid_until", "valid_from", "due", "appointment", "admission",
    "discharge", "onset", "effective", "renewal", "anniversary",
)

#: Epoch seconds below this are almost certainly not a timestamp (1973-03-03),
#: and above the millisecond threshold the value is milliseconds instead.
_MIN_EPOCH_SECONDS = 100_000_000
_MS_THRESHOLD = 100_000_000_000

_ISO_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?")


@dataclass(frozen=True)
class RetentionObservation:
    """What the records say about their own age."""

    #: The field the horizon was read from, or None when there was none.
    #: Deliberately not called `field`: that name shadows `dataclasses.field`
    #: inside the class body and every later default blows up at import.
    timestamp_field: Optional[str] = None
    #: Every timestamp-shaped field seen, with how many records carried it.
    candidates: dict[str, int] = field(default_factory=dict)
    #: Subject-date fields that were found and deliberately not used.
    excluded: dict[str, int] = field(default_factory=dict)
    records_scanned: int = 0
    records_dated: int = 0
    oldest: Optional[str] = None
    newest: Optional[str] = None
    oldest_age_days: Optional[int] = None
    newest_age_days: Optional[int] = None

    @property
    def observable(self) -> bool:
        return self.timestamp_field is not None and self.records_dated > 0

    @property
    def coverage(self) -> float:
        """Share of scanned records that carried the chosen field."""
        return (self.records_dated / self.records_scanned) if self.records_scanned else 0.0

    @property
    def status(self) -> str:
        if not self.records_scanned:
            return "nothing_scanned"
        if not self.observable:
            return "no_record_timestamp"
        return "observed" if self.coverage >= 0.99 else "partly_dated"

    def summary(self) -> str:
        """One sentence a reviewer can act on."""
        if self.status == "nothing_scanned":
            return "No records were read, so no retention horizon was observed."
        if self.status == "no_record_timestamp":
            extra = ""
            if self.excluded:
                extra = (" Date fields are present but describe the subject "
                         f"({', '.join(sorted(self.excluded))}), not when the "
                         "record arrived.")
            return ("No field records when these entries were created or "
                    "ingested, so their age cannot be established from the "
                    "store." + extra)
        span = f"{self.oldest} to {self.newest}"
        age = (f"the oldest is {self.oldest_age_days} days old"
               if self.oldest_age_days is not None else "age unknown")
        if self.status == "partly_dated":
            return (f"{self.records_dated} of {self.records_scanned} records "
                    f"carry '{self.timestamp_field}' ({span}); {age}. The rest have no "
                    "date, so the true horizon may be older.")
        return f"Records span {span} from '{self.timestamp_field}'; {age}."

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status, "field": self.timestamp_field,
            "candidates": dict(self.candidates), "excluded": dict(self.excluded),
            "records_scanned": self.records_scanned,
            "records_dated": self.records_dated,
            "coverage": round(self.coverage, 3),
            "oldest": self.oldest, "newest": self.newest,
            "oldest_age_days": self.oldest_age_days,
            "newest_age_days": self.newest_age_days,
            "summary": self.summary(),
            "note": ("This is the observed age of records, not a judgement "
                     "about whether that age is permitted. VecShield does not "
                     "hold the retention schedule."),
        }


def is_subject_date(name: str) -> bool:
    """True for a date about the person rather than about the record."""
    lowered = name.lower()
    return any(hint in lowered for hint in _SUBJECT_TIME_FIELDS)


def looks_like_record_time(name: str) -> bool:
    """True for a field name that plausibly records arrival time."""
    if is_subject_date(name):
        return False
    lowered = name.lower()
    return (any(hint == lowered or lowered.endswith("_" + hint) or hint in lowered
                for hint in _TIME_HINTS))


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse ISO-8601 or epoch seconds/milliseconds. None when it is neither.

    Naive datetimes are read as UTC rather than rejected: a store that records
    local time without an offset is common, and refusing to read it would lose
    the horizon entirely over a few hours of imprecision. A bare date (what
    psycopg returns for a Postgres ``date`` column) is read as midnight UTC.
    """
    if isinstance(value, bool):  # bool is an int; it is never a timestamp
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):  # after datetime, which is a date subclass
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds >= _MS_THRESHOLD:
            seconds /= 1000.0
        if seconds < _MIN_EPOCH_SECONDS:
            return None
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not _ISO_LIKE.match(text):
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def observe_retention(records: Iterable[Mapping[str, Any]], *,
                      now: Optional[datetime] = None) -> RetentionObservation:
    """Read the retention horizon from a collection's record metadata.

    The chosen field is the timestamp-shaped field that the most records
    actually carry a *parseable* value for, ties broken alphabetically so two
    runs over the same data agree.
    """
    now = now or datetime.now(timezone.utc)
    scanned = 0
    excluded: dict[str, int] = {}
    parsed_by_field: dict[str, list[datetime]] = {}

    for record in records:
        scanned += 1
        for key, value in (record or {}).items():
            if is_subject_date(str(key)):
                if parse_timestamp(value) is not None:
                    excluded[str(key)] = excluded.get(str(key), 0) + 1
                continue
            if not looks_like_record_time(str(key)):
                continue
            when = parse_timestamp(value)
            if when is not None:
                parsed_by_field.setdefault(str(key), []).append(when)

    candidates = {name: len(values) for name, values in parsed_by_field.items()}
    if not candidates:
        return RetentionObservation(records_scanned=scanned, excluded=excluded)

    chosen = min(candidates, key=lambda name: (-candidates[name], name))
    stamps = sorted(parsed_by_field[chosen])
    oldest, newest = stamps[0], stamps[-1]
    return RetentionObservation(
        timestamp_field=chosen, candidates=candidates, excluded=excluded,
        records_scanned=scanned, records_dated=len(stamps),
        oldest=oldest.isoformat(), newest=newest.isoformat(),
        oldest_age_days=max(0, (now - oldest).days),
        newest_age_days=max(0, (now - newest).days),
    )
