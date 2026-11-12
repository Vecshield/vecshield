"""Unit tests for the ASQ-PHI adapter's normalization logic.

These exercise the pure parsing / value-resolution functions on inline text, so
they run with no network and no dataset file present.
"""

from __future__ import annotations

from benchmarks.asq_phi.normalize import asq_phi as A

_SAMPLE = """\
===QUERY===
Treatment for Anna S., seen at Methodist Hospital on April 12, 2023?
===PHI_TAGS===
{"identifier_type": "NAME", "value": "Anna S."}
{"identifier_type": "GEOGRAPHIC_LOCATION", "value": "Methodist Hospital"}
{"identifier_type": "DATE", "value": "April 12, 2023"}

===QUERY===
Guidelines for ACE inhibitors in a 55-year-old male with CKD?
===PHI_TAGS===

===QUERY===
Contact Dr. Lee at lee@clinic.org or Dr. Lee's office (MRN 445).
===PHI_TAGS===
{"identifier_type": "NAME", "value": "Lee"}
{"identifier_type": "NAME", "value": "Lee"}
{"identifier_type": "EMAIL_ADDRESS", "value": "lee@clinic.org"}
{"identifier_type": "MEDICAL_RECORD_NUMBER", "value": "445"}
"""


def test_parse_records_counts():
    records = A._parse_records(_SAMPLE)
    assert len(records) == 3
    # Second record is a hard negative (no PHI tags).
    assert records[1][1] == []


def test_hard_negative_has_no_gold():
    records = A._parse_records(_SAMPLE)
    query, tags = records[1]
    assert A._annotations_from_tags(query, tags) == []


def test_all_types_map_to_phi():
    text, tags = A._parse_records(_SAMPLE)[0]
    anns = A._annotations_from_tags(text, tags)
    assert {a.entity_type for a in anns} == {"PHI"}
    assert {a.subtype for a in anns} == {"NAME", "GEOGRAPHIC_LOCATION", "DATE"}


def test_spans_resolve_to_correct_offsets():
    text, tags = A._parse_records(_SAMPLE)[0]
    anns = A._annotations_from_tags(text, tags)
    for a in anns:
        assert text[a.start:a.end] == a.text
    name = next(a for a in anns if a.subtype == "NAME")
    assert text[name.start:name.end] == "Anna S."


def test_duplicate_values_get_distinct_spans():
    # "Lee" appears three times; two NAME tags must map to the first two, not
    # collapse onto the same span.
    A._UNRESOLVED.clear()
    text, tags = A._parse_records(_SAMPLE)[2]
    anns = A._annotations_from_tags(text, tags)
    name_spans = sorted((a.start, a.end) for a in anns if a.subtype == "NAME")
    assert len(name_spans) == 2
    assert name_spans[0] != name_spans[1]
    assert A.unresolved_values() == {}


def test_email_and_mrn_resolved():
    text, tags = A._parse_records(_SAMPLE)[2]
    anns = A._annotations_from_tags(text, tags)
    by_sub = {a.subtype: text[a.start:a.end] for a in anns}
    assert by_sub["EMAIL_ADDRESS"] == "lee@clinic.org"
    assert by_sub["MEDICAL_RECORD_NUMBER"] == "445"


def test_case_insensitive_fallback():
    A._UNRESOLVED.clear()
    text = "Referred to st. vincent's hospital yesterday."
    tags = [{"identifier_type": "GEOGRAPHIC_LOCATION", "value": "St. Vincent's"}]
    anns = A._annotations_from_tags(text, tags)
    assert len(anns) == 1
    assert text[anns[0].start:anns[0].end].lower() == "st. vincent's"
    assert A.unresolved_values() == {}


def test_curly_apostrophe_resolves():
    # Tag uses ASCII "'", query uses typographic "’" (U+2019).
    A._UNRESOLVED.clear()
    text = "Treated at Children’s Clinic on March 20th, 2023."
    tags = [{"identifier_type": "GEOGRAPHIC_LOCATION", "value": "Children's Clinic"}]
    anns = A._annotations_from_tags(text, tags)
    assert len(anns) == 1
    assert text[anns[0].start:anns[0].end] == "Children’s Clinic"
    assert A.unresolved_values() == {}


def test_unresolvable_value_recorded():
    A._UNRESOLVED.clear()
    text = "No identifiers here."
    tags = [{"identifier_type": "NAME", "value": "Ghost McMissing"}]
    assert A._annotations_from_tags(text, tags) == []
    assert A.unresolved_values().get("NAME") == 1


def test_unknown_identifier_type_recorded_as_unmapped():
    A._UNMAPPED.clear()
    text = "value here"
    tags = [{"identifier_type": "TOTALLYNEW", "value": "value"}]
    assert A._annotations_from_tags(text, tags) == []
    assert A.unmapped_labels().get("TOTALLYNEW") == 1


def test_malformed_json_tag_lines_skipped():
    block = (
        "===QUERY===\nHello world\n===PHI_TAGS===\n"
        "not json\n{\"identifier_type\": \"NAME\", \"value\": \"world\"}\n"
    )
    records = A._parse_records(block)
    assert len(records) == 1
    _, tags = records[0]
    assert tags == [{"identifier_type": "NAME", "value": "world"}]
