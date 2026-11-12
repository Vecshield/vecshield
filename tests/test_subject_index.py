"""The subject index: what it records, what it refuses to record, and its limits.

Most of these assert an absence. An index of where every data subject appears
is itself personal data, so the interesting properties are that identifiers
never reach storage, that a lookup cannot be read as proving absence, and that
erasing a subject erases their rows too.
"""

from __future__ import annotations

import os
import stat

import pytest

from vecshield.classify.regex_classifier import RegexClassifier
from vecshield.classify.surfaces import classify_chunk
from vecshield.models import Chunk
from vecshield_platform.history import ScanHistory
from vecshield_platform.scan.engine import scan_store
from vecshield_platform.subject_index import (
    IDENTIFIER_DETECTORS,
    candidate_keys,
    load_or_create_salt,
    locations_from_chunk,
    lookup_limits,
    make_sink,
    normalize_identifier,
    salt_path_for,
    subject_key,
)

SALT = b"x" * 32
SUBJECT = "Maya.Brooks@Example.test"


def classified(text, metadata=None):
    chunk = Chunk(id="c1", collection="tickets", text=text, metadata=metadata or {})
    return chunk, classify_chunk(RegexClassifier(), chunk)


# --- normalization: the only reason a lookup ever matches --------------------

@pytest.mark.parametrize("raw,detector,expected", [
    ("Maya.Brooks@Example.test ", "email", "maya.brooks@example.test"),
    ("  MAYA@x.test", "email", "maya@x.test"),
    ("(555) 867-5309", "us_phone", "5558675309"),
    ("555-867-5309", "us_phone", "5558675309"),
    ("123-45-6789", "us_ssn", "123456789"),
])
def test_identifiers_fold_to_one_form(raw, detector, expected):
    assert normalize_identifier(raw, detector) == expected


def test_the_same_person_written_differently_gets_one_key():
    assert (subject_key("Maya.Brooks@Example.test ", SALT, detector="email")
            == subject_key("maya.brooks@example.test", SALT, detector="email"))
    assert (subject_key("(555) 867-5309", SALT, detector="us_phone")
            == subject_key("555-867-5309", SALT, detector="us_phone"))


def test_a_different_key_gives_a_different_hash():
    assert subject_key(SUBJECT, SALT) != subject_key(SUBJECT, b"y" * 32)


def test_an_empty_identifier_has_no_key():
    assert subject_key("   ", SALT) == ""


# --- extraction ---------------------------------------------------------------

def test_a_subject_is_located_without_its_identifier_being_returned():
    chunk, result = classified(f"Ticket from {SUBJECT} about billing")
    locations = locations_from_chunk(chunk, result, store_id="s1", salt=SALT)

    assert len(locations) == 1
    loc = locations[0]
    assert loc.detector == "email"
    assert loc.chunk_id == "c1" and loc.collection == "tickets"
    # Nothing in the record resembles the identifier it was built from.
    blob = repr(loc.to_dict()).lower()
    assert "maya" not in blob and "example.test" not in blob


def test_the_key_matches_what_a_later_request_would_look_up():
    chunk, result = classified(f"Ticket from {SUBJECT} about billing")
    loc = locations_from_chunk(chunk, result, store_id="s1", salt=SALT)[0]
    assert loc.subject_key in candidate_keys("maya.brooks@example.test", SALT)


def test_metadata_surfaces_are_indexed_too():
    chunk, result = classified("Nothing identifying in the body.",
                               {"reporter": "j.okafor@example.test"})
    locations = locations_from_chunk(chunk, result, store_id="s1", salt=SALT)
    assert [loc.surface for loc in locations] == ["metadata.reporter"]


def test_only_identifiers_a_rights_request_would_name_are_indexed():
    """A card number is personal data; it is not what someone writes on a DSAR."""
    chunk, result = classified("Card 4111 1111 1111 1111 and key AKIAIOSFODNN7EXAMPLE")
    assert locations_from_chunk(chunk, result, store_id="s1", salt=SALT) == []
    assert "credit_card" not in IDENTIFIER_DETECTORS
    assert "aws_access_key" not in IDENTIFIER_DETECTORS


def test_a_chunk_with_no_spans_yields_nothing():
    chunk, result = classified("An entirely unremarkable runbook paragraph.")
    assert locations_from_chunk(chunk, result, store_id="s1", salt=SALT) == []


def test_the_same_subject_twice_in_one_chunk_is_one_location():
    chunk, result = classified(f"{SUBJECT} wrote in; reply to {SUBJECT.lower()}")
    locations = locations_from_chunk(chunk, result, store_id="s1", salt=SALT)
    assert len(locations) == 1


# --- the key file --------------------------------------------------------------

def test_the_key_is_created_once_and_kept_private(tmp_path):
    path = salt_path_for(tmp_path / "history.db")
    first = load_or_create_salt(path)

    assert len(first) == 32
    assert load_or_create_salt(path) == first, "the key must be stable"
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"key is mode {oct(mode)}"


def test_a_truncated_key_is_refused_rather_than_replaced(tmp_path):
    """Silently regenerating it would orphan every row already indexed."""
    path = tmp_path / "short.key"
    path.write_bytes(b"tooshort")
    with pytest.raises(ValueError, match="orphan"):
        load_or_create_salt(path)


@pytest.mark.parametrize("key", [
    b"\n" + bytes(range(65, 96)),           # leading whitespace byte
    bytes(range(65, 96)) + b" ",            # trailing whitespace byte
    b"\t" + bytes(range(65, 95)) + b"\r",   # both ends
    b"\n" * 8 + b"\r\n" * 4 + bytes(range(65, 81)),  # embedded newlines
], ids=["leading", "trailing", "both-ends", "embedded-newlines"])
def test_a_key_with_whitespace_bytes_reads_back_exactly(tmp_path, key):
    """The key is random bytes; any of them can be whitespace."""
    assert len(key) == 32
    path = tmp_path / "ws.key"
    path.write_bytes(key)
    assert load_or_create_salt(path) == key


def test_every_created_key_reads_back_unchanged(tmp_path):
    """Before the fix, ~5% of keys (more on Windows) failed this on restart."""
    for i in range(400):
        path = tmp_path / f"k{i}.key"
        created = load_or_create_salt(path)
        assert load_or_create_salt(path) == created
        assert path.read_bytes() == created


def test_a_key_written_in_windows_text_mode_reads_back_as_written(tmp_path):
    """Earlier releases wrote each 0x0A byte as 0x0D 0x0A on Windows."""
    key = b"\n" + bytes(range(65, 95)) + b"\n"
    path = tmp_path / "legacy.key"
    path.write_bytes(key.replace(b"\n", b"\r\n"))
    assert load_or_create_salt(path) == key


def test_a_provisioned_key_with_a_trailing_newline_is_still_accepted(tmp_path):
    key = bytes(range(65, 105))
    path = tmp_path / "provisioned.key"
    path.write_bytes(key + b"\n")
    assert load_or_create_salt(path) == key


def test_the_key_does_not_live_in_the_database(tmp_path):
    assert salt_path_for(tmp_path / "history.db").parent == tmp_path
    assert salt_path_for(tmp_path / "history.db").name != "history.db"


# --- storage --------------------------------------------------------------------

@pytest.fixture
def indexed():
    history = ScanHistory()
    chunk, result = classified(f"Ticket from {SUBJECT}")
    locations = locations_from_chunk(chunk, result, store_id="s1", salt=SALT)
    history.record_subject_locations(locations, scan_id="scan-1", coverage_complete=True)
    return history, locations


def test_a_lookup_finds_the_subject(indexed):
    history, _ = indexed
    rows = history.lookup_subject(candidate_keys(SUBJECT, SALT))
    assert [(r["store_id"], r["chunk_id"]) for r in rows] == [("s1", "c1")]


def test_rescanning_does_not_duplicate_rows(indexed):
    history, locations = indexed
    history.record_subject_locations(locations, scan_id="scan-2", coverage_complete=True)
    assert history.subject_index_stats()["locations"] == 1


def test_stats_carry_no_subject_detail(indexed):
    history, _ = indexed
    stats = history.subject_index_stats()
    assert stats == {"locations": 1, "subjects": 1,
                     "stores": [{"store_id": "s1", "locations": 1,
                                 "all_complete": True,
                                 "last_indexed": stats["stores"][0]["last_indexed"]}]}
    assert "subject_key" not in repr(stats)


def test_forgetting_a_subject_removes_their_rows(indexed):
    history, _ = indexed
    assert history.forget_subject(candidate_keys(SUBJECT, SALT)) == 1
    assert history.lookup_subject(candidate_keys(SUBJECT, SALT)) == []


def test_deregistering_a_store_drops_its_rows(indexed):
    history, _ = indexed
    assert history.forget_store_subjects("s1") == 1
    assert history.subject_index_stats()["locations"] == 0


# --- the limits a caller must carry ---------------------------------------------

def test_a_lookup_never_claims_to_prove_absence():
    limits = lookup_limits([])
    assert any("does not record where they are absent" in x for x in limits)


def test_rows_from_a_capped_scan_say_so():
    limits = lookup_limits([{"coverage_complete": False}])
    assert any("did not inspect its whole scope" in x for x in limits)


def test_an_empty_index_says_nothing_has_been_indexed():
    assert any("No store in this deployment has been indexed" in x
               for x in lookup_limits([], stores_scanned=0))


# --- the scan hook ----------------------------------------------------------------

class _Store:
    kind = "memory"
    content_enumerable = True

    def __init__(self):
        self.chunks = [
            Chunk(id="a", collection="tickets", text=f"From {SUBJECT}"),
            Chunk(id="b", collection="tickets", text="Nothing identifying here."),
        ]

    def capabilities(self):
        return set()

    def describe(self):
        from vecshield.models import VectorStore
        return VectorStore(kind=self.kind, name="s1", endpoint="memory://",
                           collections=self.list_collections())

    def list_collections(self):
        from vecshield.models import Collection
        return [Collection(name="tickets", count=len(self.chunks))]

    def iter_chunks(self, collection, batch_size=256):
        yield from self.chunks


def test_the_index_is_built_during_the_scan_that_already_reads_every_chunk():
    history = ScanHistory()
    store = _Store()
    sink = make_sink("s1", SALT,
                     lambda locs: history.record_subject_locations(
                         locs, scan_id="scan-x", coverage_complete=True))

    job = scan_store(store, classifier=RegexClassifier(), observer=sink)

    assert job.stats["chunks_scanned"] == 2
    rows = history.lookup_subject(candidate_keys(SUBJECT, SALT))
    assert [r["chunk_id"] for r in rows] == ["a"]


def test_a_failing_observer_is_recorded_and_does_not_fail_the_assessment():
    def explode(chunk, result):
        raise RuntimeError("index unavailable")

    job = scan_store(_Store(), classifier=RegexClassifier(), observer=explode)

    assert job.stats["chunks_scanned"] == 2          # the scan still completed
    assert job.stats["observer_errors"]
    assert "RuntimeError" in job.stats["observer_errors"][0]
