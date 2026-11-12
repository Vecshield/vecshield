"""Ingest redaction and DPIA generation."""

from __future__ import annotations

from vecshield.classify import RegexClassifier
from vecshield_platform.compliance import build_pia_html, generate_pia
from vecshield.ingest import IngestGate
from vecshield.models import (
    Finding,
    Severity,
)


# ---------------- redaction ----------------

def test_redact_masks_text_span():
    gate = IngestGate(classifier=RegexClassifier())
    chunks = [type("C", (), {"id": "1", "collection": "kb",
                             "text": "my ssn is 123-45-6789 thanks",
                             "metadata": {}, "embedding": None,
                             "classification": None})()]
    # use a real Chunk
    from vecshield.models import Chunk
    chunks = [Chunk(id="1", collection="kb", text="my ssn is 123-45-6789 thanks")]
    clean, n = gate.redact(chunks)
    assert n == 1
    assert "123-45-6789" not in clean[0].text
    assert "[REDACTED:PII]" in clean[0].text
    # original untouched
    assert chunks[0].text == "my ssn is 123-45-6789 thanks"


def test_redact_masks_metadata_value():
    from vecshield.models import Chunk
    gate = IngestGate(classifier=RegexClassifier())
    chunks = [Chunk(id="1", collection="kb", text="clean",
                    metadata={"contact": "reach me at bob@acme.com"})]
    clean, n = gate.redact(chunks)
    assert n == 1
    assert "bob@acme.com" not in clean[0].metadata["contact"]


def test_redact_clean_chunk_untouched():
    from vecshield.models import Chunk
    gate = IngestGate(classifier=RegexClassifier())
    chunks = [Chunk(id="1", collection="kb", text="totally benign content")]
    clean, n = gate.redact(chunks)
    assert n == 0
    assert clean[0].text == "totally benign content"


def test_redact_multiple_spans_offsets_stay_valid():
    from vecshield.models import Chunk
    gate = IngestGate(classifier=RegexClassifier())
    text = "ssn 123-45-6789 and email a@b.com end"
    clean, n = gate.redact([Chunk(id="1", collection="kb", text=text)])
    assert n == 2
    assert "123-45-6789" not in clean[0].text
    assert "a@b.com" not in clean[0].text
    assert clean[0].text.endswith("end")


def test_redact_overlapping_spans_leave_nothing_behind():
    # Two detectors covering the same value used to be spliced one after the
    # other, cutting into the first token and leaving most of the secret.
    from vecshield.models import Chunk
    gate = IngestGate(classifier=RegexClassifier())
    secret = "rs1234-AbCdEfGhIjKlMnOpQrStUv"
    for text, gone in ((f"secret: {secret}", "AbCdEfGhIjKlMnOpQrStUv"),
                       ("Card 4111 1111 1111 1111 exp 12/27", "1111")):
        [clean], n = gate.redact([Chunk(id="1", collection="kb", text=text)])
        assert gone not in clean.text, clean.text
        assert "CTED:" not in clean.text.replace("[REDACTED:", ""), clean.text
        assert n >= 1


def test_redact_nested_metadata():
    from vecshield.models import Chunk
    gate = IngestGate(classifier=RegexClassifier())
    chunk = Chunk(id="1", collection="kb", text="clean",
                  metadata={"author": {"email": "bob@acme.com"},
                            "cc": ["ok", "carol@acme.com"], "pages": 3})
    [clean], n = gate.redact([chunk])
    assert n == 2
    assert "bob@acme.com" not in clean.metadata["author"]["email"]
    assert "carol@acme.com" not in clean.metadata["cc"][1]
    assert clean.metadata["pages"] == 3
    assert chunk.metadata["author"]["email"] == "bob@acme.com"  # input untouched


# ---------------- DPIA ----------------

class _FakeAudit:
    """Minimal duck-typed AuditResult for PIA generation."""

    def __init__(self, findings, violations=None, store="store"):
        self._f = findings
        self.violations = violations or []
        self.store = store

    def all_findings(self):
        return self._f


def _pii_finding(severity=Severity.HIGH, label="pii", category="data_classification"):
    return Finding(
        id="f1", title="PII detected", severity=severity, category=category,
        store="store", collection="docs",
        evidence={"label_counts": {label: 5}},
        remediation="Tag and restrict.",
    )


def test_pia_high_risk_on_phi():
    audit = _FakeAudit([_pii_finding(label="phi", severity=Severity.HIGH)])
    pia = generate_pia(audit)
    assert pia.high_risk is True
    assert any("health" in c.lower() for c in pia.data_categories)
    assert pia.dpo_action_required is True


def test_pia_no_pii_not_high_risk():
    network = Finding(id="n", title="ok", severity=Severity.LOW,
                      category="network_exposure", store="store")
    pia = generate_pia(_FakeAudit([network]))
    assert pia.high_risk is False
    assert pia.data_categories == []


def test_pia_safeguard_gap_from_plaintext():
    tls = Finding(id="t", title="not TLS", severity=Severity.HIGH,
                  category="transport_encryption", store="store",
                  remediation="Enable TLS.")
    pia = generate_pia(_FakeAudit([_pii_finding(), tls]))
    tls_safeguard = next(s for s in pia.safeguards
                         if s["control"] == "Encryption in transit (TLS)")
    assert tls_safeguard["status"] == "GAP"
    assert tls_safeguard["open_findings"] == 1


def test_pia_residual_high_on_critical():
    crit = _pii_finding(severity=Severity.CRITICAL, label="secret")
    pia = generate_pia(_FakeAudit([crit]))
    assert pia.residual_risk == "high"


def test_pia_html_renders():
    pia = generate_pia(_FakeAudit([_pii_finding()]))
    html = build_pia_html(pia, generated_at="2026-06-30")
    assert "Data Protection Impact Assessment" in html
    assert "Article 35" in html
    assert "(a) Description of processing" in html
