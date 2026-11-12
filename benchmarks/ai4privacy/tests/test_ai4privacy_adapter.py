"""Unit tests for the ai4privacy adapter's normalization logic.

These exercise the pure transformation functions (label mapping, span coercion)
without touching the network, so they run in any environment.
"""

from __future__ import annotations

from benchmarks.ai4privacy.normalize import ai4privacy as A


def test_base_label_strips_separated_index_suffix():
    assert A._base_label("FIRSTNAME_1") == "FIRSTNAME"
    assert A._base_label("lastname-2") == "LASTNAME"
    assert A._base_label("EMAIL") == "EMAIL"
    assert A._base_label("CREDITCARDNUMBER_3") == "CREDITCARDNUMBER"


def test_base_label_keeps_bare_trailing_digits():
    # Bare trailing digits are meaningful — must NOT be stripped.
    assert A._base_label("IPV4") == "IPV4"
    assert A._base_label("IPV6") == "IPV6"


def test_coerce_mask_from_json_string():
    raw = '[{"label": "EMAIL_1", "start": 0, "end": 5, "value": "a@b.c"}]'
    mask = A._coerce_mask(raw)
    assert mask == [{"label": "EMAIL_1", "start": 0, "end": 5, "value": "a@b.c"}]


def test_coerce_mask_from_python_repr_string():
    raw = "[{'label': 'SSN_1', 'start': 2, 'end': 5, 'value': '123'}]"
    mask = A._coerce_mask(raw)
    assert mask[0]["label"] == "SSN_1"


def test_coerce_mask_passthrough_list():
    data = [{"label": "EMAIL", "start": 0, "end": 3}]
    assert A._coerce_mask(data) == data


def test_coerce_mask_handles_none_and_garbage():
    assert A._coerce_mask(None) == []
    assert A._coerce_mask("not json") == []
    assert A._coerce_mask(123) == []


def test_annotations_map_categories():
    text = "John lives at 1.2.3.4 with card 4111111111111111 pw hunter2"
    mask = [
        {"label": "FIRSTNAME_1", "start": 0, "end": 4, "value": "John"},
        {"label": "IPV4_1", "start": 14, "end": 21, "value": "1.2.3.4"},
        {
            "label": "CREDITCARDNUMBER_1",
            "start": 32,
            "end": 48,
            "value": "4111111111111111",
        },
        {"label": "PASSWORD_1", "start": 52, "end": 59, "value": "hunter2"},
    ]
    anns = A._annotations_from_mask(mask, text)
    by_type = {a.subtype: a.entity_type for a in anns}
    assert by_type["FIRSTNAME"] == "PII"
    assert by_type["IPV4"] == "PII"
    assert by_type["CREDITCARDNUMBER"] == "PCI"
    assert by_type["PASSWORD"] == "SECRET"


def test_ignored_labels_are_dropped():
    A._UNMAPPED.clear()
    text = "Acme Corp pays in USD"
    mask = [
        {"label": "COMPANYNAME_1", "start": 0, "end": 9, "value": "Acme Corp"},
        {"label": "CURRENCYCODE_1", "start": 18, "end": 21, "value": "USD"},
    ]
    anns = A._annotations_from_mask(mask, text)
    assert anns == []
    assert A.unmapped_labels() == {}  # ignored, not unmapped


def test_unknown_labels_recorded_as_unmapped():
    A._UNMAPPED.clear()
    text = "hello world"
    mask = [{"label": "TOTALLYNEWLABEL_1", "start": 0, "end": 5, "value": "hello"}]
    anns = A._annotations_from_mask(mask, text)
    assert anns == []
    assert A.unmapped_labels().get("TOTALLYNEWLABEL") == 1


def test_out_of_bounds_spans_skipped():
    text = "short"
    mask = [{"label": "EMAIL_1", "start": 0, "end": 999, "value": "x"}]
    assert A._annotations_from_mask(mask, text) == []


def test_is_english_filter():
    assert A._is_english({"language": "English"}) is True
    assert A._is_english({"language": "en"}) is True
    assert A._is_english({"language": "French"}) is False
    assert A._is_english({}) is True  # no language column -> keep
