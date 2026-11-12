"""Unit tests for the regex classifier."""

from __future__ import annotations

from vecshield.classify import classify_text
from vecshield.models import SensitivityLabel


def test_email_detected():
    r = classify_text("ping me at alice@corp.io")
    assert r.label == SensitivityLabel.PII
    assert "email" in r.detectors


def test_ssn_detected():
    r = classify_text("SSN 123-45-6789")
    assert r.label == SensitivityLabel.PII
    assert "us_ssn" in r.detectors


def test_additional_pii_identifiers_detected():
    cases = {
        "date_of_birth": "DOB: 1980-01-02",
        "us_street_address": "Ship to 123 Main Street Apt 4B tomorrow.",
        "us_driver_license_context": "driver license: D1234567",
        "passport_context": "passport number X12345678",
        "tax_id_context": "EIN: 12-3456789",
        "bank_routing": "routing number 011000015",
        "bank_account_context": "bank account: 123456789012",
        "ipv4_address": "last login from 203.0.113.42",
        "metadata_identifier": "customer_id: cus_12345",
    }
    for detector, text in cases.items():
        r = classify_text(text)
        assert r.label == SensitivityLabel.PII
        assert detector in r.detectors


def test_phi_and_iban_identifiers_detected():
    mrn = classify_text("MRN: A1234567")
    assert mrn.label == SensitivityLabel.PHI
    assert "medical_record_context" in mrn.detectors

    iban = classify_text("IBAN GB82 WEST 1234 5698 7654 32")
    assert iban.label == SensitivityLabel.PCI
    assert "iban" in iban.detectors


def test_credit_card_luhn_valid():
    r = classify_text("card 4111 1111 1111 1111")
    assert r.label == SensitivityLabel.PCI


def test_credit_card_luhn_invalid_rejected():
    # 16 digits but fails Luhn -> should not be flagged as PCI
    # (4111...1111 is the canonical valid test card; +1 on the last digit breaks it)
    r = classify_text("order number 4111 1111 1111 1112 confirmed")
    assert "credit_card" not in r.detectors


def test_invalid_financial_checks_rejected():
    assert "bank_routing" not in classify_text("routing number 123456789").detectors
    assert "iban" not in classify_text("IBAN GB82 TEST 1234 5678 0000 00").detectors


def test_secret_outranks_pii():
    r = classify_text("email bob@x.io key AKIAIOSFODNN7EXAMPLE")
    assert r.label == SensitivityLabel.SECRET  # higher priority label wins


def test_clean_text():
    r = classify_text("the otter swam happily in the river")
    assert r.label == SensitivityLabel.NONE
    assert not r.is_sensitive


def test_spans_are_redacted():
    r = classify_text("key AKIAIOSFODNN7EXAMPLE")
    assert r.spans
    assert "AKIAIOSFODNN7EXAMPLE" not in r.spans[0]["preview"]


def test_presidio_runtime_failure_degrades_to_none():
    from vecshield.classify.presidio_classifier import PresidioClassifier

    clf = PresidioClassifier.__new__(PresidioClassifier)

    class BrokenAnalyzer:
        def analyze(self, **_kwargs):
            raise PermissionError("cache unavailable")

    clf._analyzer = BrokenAnalyzer()
    clf.score_floor = 0.5
    result = clf.classify("jane@example.com")
    assert result.label == SensitivityLabel.NONE
