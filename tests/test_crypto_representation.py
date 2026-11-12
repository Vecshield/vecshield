"""Data representation (VCR-03 to VCR-09): classes, PAN forms, drift, evidence hygiene."""

from __future__ import annotations

import json

import pytest

from vecshield.classify import RegexClassifier
from vecshield.classify.surfaces import classify_chunk
from vecshield.models import Chunk, Collection, VectorStore
from vecshield_platform.compliance.criteria import evaluate_pack
from vecshield_platform.compliance.packs import criteria_for
from vecshield_platform.compliance.policy import evaluate_policies
from vecshield_platform.connectors.base import Connector
from vecshield_platform.crypto import representation
from vecshield_platform.crypto.representation import (
    STATEMENT,
    RepresentationObserver,
    classify_representation,
    find_pan_representations,
    pan_representation,
    representation_policies,
)
from vecshield_platform.scan import scan_store

CLASSIFIER = RegexClassifier()
RAW_PAN = "4539578890123489"
RAW_EMAIL = "maria.gonzalez@example.com"


class MemoryConnector(Connector):
    kind = "memory"

    def __init__(self, data, *, models=None):
        self.data = data
        self.models = models or {}

    def describe(self):
        return VectorStore(kind=self.kind, name="memory", endpoint="memory://",
                           collections=self.list_collections())

    def list_collections(self):
        return [Collection(name=name, count=len(chunks), **self.models.get(name, {}))
                for name, chunks in self.data.items()]

    def capabilities(self):
        return set()

    def iter_chunks(self, collection, batch_size=256):
        yield from self.data[collection]


def chunk(i, collection="docs", text=None, metadata=None, embedding=True):
    return Chunk(id=str(i), collection=collection, text=text, metadata=metadata or {},
                 embedding=[0.1] * 8 if embedding else None)


def observe(chunks, **kwargs):
    obs = RepresentationObserver(**kwargs)
    for c in chunks:
        obs(c, classify_chunk(CLASSIFIER, c))
    return obs


def outcomes(job, collection="docs"):
    return {o["check"]: o for o in job.stats["check_outcomes"]
            if o["collection"] == collection}


# ---------------------------------------------------------------- classes
@pytest.mark.parametrize("value,key,expected", [
    ("jane.doe@example.com", None, "plaintext"),
    ("123-45-6789", "ssn", "plaintext"),
    ("Maria Gonzalez", "patient_name", "plaintext"),
    ("j***@e***.com", "email", "masked"),
    ("****1234", None, "masked"),
    ("***-**-6789", "ssn", "masked"),
    ("[REDACTED]", "email", "masked"),
    ("411111******1111", None, "truncated"),
    ("4111 11** **** 1111", None, "truncated"),
    ("******1111", None, "truncated"),
    ("tok_9f8a7b6c5d4e3f21", "patient_id", "tokenized"),
    ("vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zo", "ssn", "tokenized"),
    ("4111111111111112", "card_number", "tokenized"),
    ("123e4567-e89b-12d3-a456-426614174000", "customer_id", "pseudonymous"),
    ("cus_N8fY2kL0pQ7rT3", "customer_id", "pseudonymous"),
    ("5f4dcc3b5aa765d61d8327deb882cf99", "ssn", "hash_candidate"),
    ("$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234", None, "hash_candidate"),
    ("dGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIDEyMw==", "email", "opaque"),
    # Hard negatives: nothing to say about their representation.
    ("123e4567-e89b-12d3-a456-426614174000", None, "unknown"),
    ("a1b2c3d4e5f60718", None, "unknown"),
    ("meeting at noon", "meeting_notes", "unknown"),
    ("", "email", "unknown"),
])
def test_representation_classes(value, key, expected):
    assert classify_representation(value, key=key) == expected


def test_a_detected_secret_is_plaintext_not_opaque():
    """High entropy never turns a value a detector recognised into protection."""
    key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert classify_representation(key) == "opaque"
    assert classify_representation(key, detected=True) == "plaintext"
    # Explicit markers survive detection: a masked PAN is still truncated.
    assert classify_representation("411111******1111", detected=True) == "truncated"


def test_key_context_makes_a_readable_identifier_plaintext():
    assert classify_representation("4481726", key="patient_id") == "unknown"
    assert classify_representation("4481726", key="patient_id", key_context=True) == "plaintext"


@pytest.mark.parametrize("value,key,expected", [
    (RAW_PAN, None, "full"),
    ("4539 5788 9012 3489", "notes", "full"),
    ("411111******1111", None, "truncated"),
    ("****1111", "card_last4", "truncated"),
    ("4111111111111112", "card_number", "tokenized"),
    ("tok_9f8a7b6c5d4e3f21", "card_token", "tokenized"),
    ("5f4dcc3b5aa765d61d8327deb882cf99", "pan_hash", "hash_candidate"),
    # Hard negatives: not PAN in any form.
    ("a1b2c3d4e5f60718", "build", None),
    ("123e4567-e89b-12d3-a456-426614174000", "request_id", None),
    ("4111111111111112", "order_number", None),
    ("tok_9f8a7b6c5d4e3f21", "cardinality", None),
    ("****1111", None, None),
])
def test_pan_forms(value, key, expected):
    assert pan_representation(value, key=key) == expected


def test_pan_forms_in_free_text():
    text = ("Card ending ****1111 declined; later 4539 5788 9012 3489 was read out. "
            "Receipt shows 411111******1111. Build a1b2c3d4e5f60718, request "
            "123e4567-e89b-12d3-a456-426614174000, order 4111111111111112.")
    assert [c for c, _, _ in find_pan_representations(text)] == [
        "truncated", "full", "truncated"]


# ---------------------------------------------------------------- PAN counts
def test_pan_counts_on_a_mixed_collection_and_the_finding():
    obs = observe([
        chunk(1, text=f"Customer read out {RAW_PAN} over the phone."),
        chunk(2, text="Receipt: 411111******1111, approved."),
        chunk(3, metadata={"card_number": "4111111111111112", "card_last4": "****1111"}),
        chunk(4, metadata={"card_hash": "5f4dcc3b5aa765d61d8327deb882cf99"}),
        chunk(5, text="Deploy build a1b2c3d4e5f60718 for request "
                      "123e4567-e89b-12d3-a456-426614174000."),
    ])
    job = obs.job("memory")
    pan = outcomes(job)["pan_representation"]
    assert pan["coverage"]["counts"] == {"full": 1, "truncated": 2, "tokenized": 1,
                                         "hash_candidate": 1, "opaque": 0}
    assert pan["coverage"]["records_with_pan"] == 1
    assert pan["outcome"] == "failed"
    assert pan["coverage"]["crypto_state"] == "observed_exposure"
    assert pan["coverage"]["control"] == "VCR-06"
    assert 1 <= len(pan["coverage"]["examples"]) <= 5
    [finding] = [f for f in job.findings if f.category == "pan_representation"]
    assert finding.severity.value == "high"  # free text only
    assert "3.5.1" in finding.remediation
    assert finding.evidence["fingerprint"].startswith("fp-")


def test_full_pan_in_a_metadata_field_is_critical():
    job = observe([chunk(1, metadata={"card_number": RAW_PAN})]).job("memory")
    [finding] = [f for f in job.findings if f.category == "pan_representation"]
    assert finding.severity.value == "critical"


def test_only_truncated_pan_is_protected_representation():
    job = observe([chunk(1, text="Receipt: 411111******1111."),
                   chunk(2, metadata={"card_last4": "****4242"})]).job("memory")
    pan = outcomes(job)["pan_representation"]
    assert (pan["outcome"], pan["coverage"]["crypto_state"]) == (
        "passed", "protected_representation")
    assert not [f for f in job.findings if f.category == "pan_representation"]


# ---------------------------------------------------------------- data representation
def test_drift_99_tokenized_and_one_plaintext_patient_id_fails():
    chunks = [chunk(i, metadata={"patient_id": f"tok_{i:04d}a8f3c9e2b7d1"})
              for i in range(99)]
    chunks.append(chunk(99, metadata={"patient_id": "4481726"}))
    job = observe(chunks).job("memory")
    data = outcomes(job)["data_representation"]
    assert data["outcome"] == "failed"
    assert data["coverage"]["crypto_state"] == "observed_exposure"
    assert data["coverage"]["drift_fields"] == ["patient_id"]
    [field] = data["coverage"]["fields"]
    assert field["classes"] == {"plaintext": 1, "tokenized": 99}
    assert field["protected_fraction"] == 0.99
    assert field["drift"] is True
    [finding] = [f for f in job.findings if f.category == "data_representation"]
    assert finding.severity.value == "medium"
    violations = evaluate_policies(representation_policies(), job.findings)
    assert {v.policy_id for v in violations} == {"protection-applied-consistently"}


def test_opaque_values_beside_plaintext_are_not_drift():
    """Entropy is not evidence of a mechanism, so it cannot establish drift."""
    job = observe([
        chunk(1, metadata={"email": "dGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIDEyMw=="}),
        chunk(2, metadata={"email": RAW_EMAIL}),
    ]).job("memory")
    data = outcomes(job)["data_representation"]
    assert data["coverage"]["drift_fields"] == []
    assert data["outcome"] == "inconclusive"


def test_consistently_plaintext_is_inconclusive_not_failed():
    job = observe([chunk(i, metadata={"email": f"user{i}@example.com"})
                   for i in range(5)]).job("memory")
    data = outcomes(job)["data_representation"]
    assert (data["outcome"], data["coverage"]["crypto_state"]) == (
        "inconclusive", "observed_exposure")
    assert data["coverage"]["plaintext_values"] == 5
    assert not job.findings  # data_classification already reports plaintext PII


def test_no_sensitive_values_is_not_applicable_and_passed():
    job = observe([chunk(1, text="Ordinary documentation.",
                         metadata={"source": "manual", "sha": "a1b2c3d4e5f60718"})]
                  ).job("memory")
    for check in ("data_representation", "pan_representation",
                  "direct_identifier_exposure"):
        o = outcomes(job)[check]
        assert (o["outcome"], o["coverage"]["crypto_state"]) == ("passed", "not_applicable")
        assert o["coverage"]["complete"] is True
    assert outcomes(job)["data_representation"]["coverage"]["statement"] == STATEMENT


def test_consistently_protected_is_protected_representation():
    job = observe([chunk(i, text=f"Contact j***@e***.com about case {i}.",
                         metadata={"customer_id": "123e4567-e89b-12d3-a456-426614174000"})
                   for i in range(3)]).job("memory")
    data = outcomes(job)["data_representation"]
    assert (data["outcome"], data["coverage"]["crypto_state"]) == (
        "passed", "protected_representation")
    assert data["coverage"]["surfaces"]["text"]["masked"] == 3
    assert data["coverage"]["surfaces"]["metadata"]["pseudonymous"] == 3


def test_metadata_only_phi_without_text():
    """The plan's example: vectors plus identifying metadata, no stored chunk text."""
    obs = observe([chunk(i, metadata={"patient_id": "MRN-0045812",
                                      "patient_name": "Maria Gonzalez"})
                   for i in range(2)],
                  collections=[Collection(name="docs", count=2, dimension=1536,
                                          embedding_model="text-embedding-3-small")])
    data = outcomes(obs.job("memory"))["data_representation"]["coverage"]
    assert data["record_structure"] == {"embedding": "present", "text": "absent",
                                        "metadata": "present"}
    assert sum(data["surfaces"]["text"].values()) == 0
    assert data["surfaces"]["metadata"]["plaintext"] == 4
    fields = {f["path"]: f for f in data["fields"]}
    assert "phi" in fields["patient_id"]["labels"]
    assert data["inversion_risk"] == 0.8


def test_direct_identifiers_with_a_pseudonymous_alternative():
    job = observe([chunk(i, metadata={"email": f"user{i}@example.com",
                                      "phone": "+1 415 555 0132",
                                      "user_id": "123e4567-e89b-12d3-a456-426614174000"})
                   for i in range(3)]).job("memory")
    direct = outcomes(job)["direct_identifier_exposure"]
    assert (direct["outcome"], direct["coverage"]["crypto_state"]) == (
        "inconclusive", "observed_exposure")
    assert direct["coverage"]["fields"] == [
        {"path": "email", "kind": "email", "count": 3, "pseudonymous_alternative": "user_id"},
        {"path": "phone", "kind": "phone", "count": 3, "pseudonymous_alternative": "user_id"},
    ]


def test_capped_or_unread_collections_are_not_verified():
    obs = observe([chunk(1, text="Ordinary documentation.")])
    obs.mark_capped("docs")
    o = outcomes(obs.job("memory"))["pan_representation"]
    assert (o["outcome"], o["coverage"]["crypto_state"]) == ("inconclusive", "not_verified")
    assert o["coverage"]["complete"] is False


def test_an_observer_never_raises():
    obs = RepresentationObserver()
    obs(chunk(1, text="x"), None)  # no classification
    obs(object(), None)  # not a chunk at all
    job = obs.job("memory")
    assert job.stats["check_outcomes"]


def test_no_raw_values_anywhere_in_the_job():
    job = observe([
        chunk(1, text=f"Card {RAW_PAN} and mail {RAW_EMAIL}.",
              metadata={"card_number": RAW_PAN, "email": RAW_EMAIL,
                        "patient_id": "4481726"}),
        chunk(2, metadata={"patient_id": "tok_0001a8f3c9e2b7d1"}),
    ]).job("memory")
    blob = json.dumps(job.to_dict(), default=str)
    for raw in (RAW_PAN, "4539 5788 9012 3489", RAW_EMAIL, "4481726",
                "tok_0001a8f3c9e2b7d1"):
        assert raw not in blob


# ---------------------------------------------------------------- end to end
def _by_id(assessments):
    return {a.criterion_id: a for a in assessments}


def test_end_to_end_scan_to_criteria():
    conn = MemoryConnector({
        "payments": [chunk(1, "payments", text=f"Customer card {RAW_PAN} on file."),
                     chunk(2, "payments", metadata={"card_last4": "****1111"})],
        "receipts": [chunk(3, "receipts", text="Receipt: 411111******1111, approved.")],
        "patients": [chunk(i, "patients", metadata={"patient_id": f"tok_{i:04d}a8f3c9e2b7d1"})
                     for i in range(9)]
                    + [chunk(9, "patients", metadata={"patient_id": "4481726"})],
    })
    obs = RepresentationObserver(collections=conn.list_collections())
    scan = scan_store(conn, classifier=CLASSIFIER, observer=obs)
    assert "observer_errors" not in scan.stats
    job = obs.job("memory", classification=scan)

    checks = {(o["check"], o["collection"]): o for o in job.stats["check_outcomes"]}
    assert checks[("pan_representation", "payments")]["outcome"] == "failed"
    assert checks[("pan_representation", "receipts")]["coverage"]["crypto_state"] == (
        "protected_representation")
    assert checks[("data_representation", "patients")]["outcome"] == "failed"
    assert all(o["coverage"]["complete"] for o in job.stats["check_outcomes"])

    pci = criteria_for("PCI-DSS")
    gdpr = criteria_for("GDPR")
    pci_id, gdpr_id = "PCI-DSS-3-STORAGE-01", "GDPR-32-1A-ENCRYPTION-01"

    def evaluate(criteria, collection):
        relevant = [o for o in scan.stats["check_outcomes"] + job.stats["check_outcomes"]
                    if o["collection"] == collection]
        return _by_id(evaluate_pack(criteria, check_outcomes=relevant))

    # Full PAN readable: PCI 3 storage fails.
    assert evaluate(pci, "payments")[pci_id].technical_result == "failed"
    # Truncated only, and no other sensitive data: nothing fails (defect 3 fixed).
    assert evaluate(pci, "receipts")[pci_id].technical_result == "passed"
    # Drift fails the GDPR 32(1)(a) data-representation check; transport and
    # at-rest checks did not run here, so only this one is reduced.
    assert evaluate(gdpr, "patients")[gdpr_id].technical_result == "failed"
    # Consistently protected: data representation passes, the rest is partial.
    assert evaluate(gdpr, "receipts")[gdpr_id].technical_result == "passed"

    violations = evaluate_policies(representation_policies(), job.findings)
    assert {v.policy_id for v in violations} == {"pan-rendered-unreadable",
                                                 "protection-applied-consistently"}


def test_end_to_end_capped_scan_reads_coverage_from_the_classification_job():
    conn = MemoryConnector({"docs": [chunk(i, text="Ordinary documentation.")
                                     for i in range(3)]})
    obs = RepresentationObserver()
    scan = scan_store(conn, classifier=CLASSIFIER, observer=obs, max_chunks_per_collection=1)
    job = obs.job("memory", classification=scan)
    for o in job.stats["check_outcomes"]:
        assert o["coverage"]["complete"] is False
        assert o["outcome"] == "inconclusive"
        assert "limit" in o["coverage"]["note"]


def test_unreadable_collections_are_not_observable():
    class Inventory(MemoryConnector):
        content_enumerable = False

    conn = Inventory({"kb": []})
    obs = RepresentationObserver()
    job = obs.job("memory", classification=scan_store(conn, classifier=CLASSIFIER,
                                                      observer=obs))
    for o in job.stats["check_outcomes"]:
        assert (o["outcome"], o["coverage"]["crypto_state"]) == ("unsupported",
                                                                 "not_observable")


def test_x_runs_inside_words_are_not_masks():
    from vecshield_platform.crypto.representation import classify_representation

    assert classify_representation("maxxxwell@example.com", detected=True) == "plaintext"
    assert classify_representation("Foxxx Street 12", key="address") == "plaintext"
    assert classify_representation("xxx-xx-6789", detected=True) == "masked"


# ---------------------------------------------------------------- reasons
_SCENARIOS = {
    "full_pan_one": [chunk(1, text=f"Customer card {RAW_PAN} on file.")],
    "full_pan_many": [chunk(1, text=f"Cards {RAW_PAN} and 4111 1111 1111 1111."),
                      chunk(2, metadata={"card_number": RAW_PAN}),
                      chunk(3, metadata={"card_number": "378282246310005"})],
    "truncated_one": [chunk(1, text="Receipt: 411111******1111.")],
    "truncated_many": [chunk(1, text="Receipt: 411111******1111."),
                       chunk(2, metadata={"card_last4": "****4242"})],
    "drift_one": [chunk(i, metadata={"patient_id": f"tok_{i:04d}a8f3c9e2b7d1"})
                  for i in range(3)] + [chunk(3, metadata={"patient_id": "4481726"})],
    "drift_many": [chunk(1, metadata={"patient_id": "tok_0001a8f3c9e2b7d1",
                                      "email": "j***@e***.com"}),
                   chunk(2, metadata={"patient_id": "4481726", "email": RAW_EMAIL})],
    "plaintext_one": [chunk(1, metadata={"email": RAW_EMAIL})],
    "plaintext_many": [chunk(i, metadata={"email": f"user{i}@example.com",
                                          "phone": "+1 415 555 0132"}) for i in range(3)],
    "protected_one": [chunk(1, metadata={"customer_id": "123e4567-e89b-12d3-a456-426614174000"})],
    "protected_many": [chunk(i, text="Contact j***@e***.com.") for i in range(3)],
    "clean": [chunk(1, text="Ordinary documentation.")],
}


def _reasons(job):
    return {o["check"]: o["reason"] for o in job.stats["check_outcomes"]}


@pytest.mark.parametrize("scenario", sorted(_SCENARIOS))
def test_reasons_are_one_short_sentence(scenario):
    obs = observe(_SCENARIOS[scenario])
    if scenario == "clean":
        obs.mark_capped("docs")
    for outcome in obs.job("memory").stats["check_outcomes"]:
        reason = outcome["reason"]
        assert len(reason) <= 120, reason
        assert "(s)" not in reason
        assert not reason[0].islower() and reason.endswith(".")
        assert reason.count(". ") == 0, f"more than one sentence: {reason}"
        assert isinstance(outcome["coverage"]["note"], str)


@pytest.mark.parametrize("scenario,check,expected", [
    ("full_pan_one", "pan_representation", "1 full PAN is stored readable in 1 record."),
    ("full_pan_many", "pan_representation", "4 full PANs are stored readable in 3 records."),
    ("truncated_one", "pan_representation",
     "No full PAN; the one PAN value found is in a protected form."),
    ("truncated_many", "pan_representation",
     "No full PAN; all 2 PAN values found are in a protected form."),
    ("drift_one", "data_representation",
     "Field patient_id mixes protected and plaintext values."),
    ("drift_many", "data_representation",
     "2 metadata fields mix protected and plaintext values."),
    ("plaintext_one", "data_representation",
     "1 sensitive value is stored as plaintext with no protection observed."),
    ("plaintext_one", "direct_identifier_exposure",
     "1 metadata field holds direct identifiers in plaintext."),
    ("plaintext_many", "direct_identifier_exposure",
     "2 metadata fields hold direct identifiers in plaintext."),
    ("protected_one", "data_representation",
     "The one sensitive value examined is in a protected form."),
    ("protected_many", "data_representation",
     "All 3 sensitive values examined are in a protected form."),
])
def test_reasons_agree_in_number(scenario, check, expected):
    assert _reasons(observe(_SCENARIOS[scenario]).job("memory"))[check] == expected


def test_caveats_move_to_the_note():
    job = observe(_SCENARIOS["plaintext_many"]).job("memory")
    data = outcomes(job)["data_representation"]["coverage"]
    assert "depends on risk" in data["note"]
    assert "disk encryption" in data["note"]
    assert "depends on risk" not in outcomes(job)["data_representation"]["reason"]
    direct = outcomes(job)["direct_identifier_exposure"]["coverage"]["note"]
    assert "pseudonymous identifier" in direct and "passive" in direct
    protected = outcomes(observe(_SCENARIOS["protected_many"]).job("memory"))
    assert "not an algorithm" in protected["data_representation"]["coverage"]["note"]


def test_sampling_caveats_move_to_the_note():
    obs = observe(_SCENARIOS["clean"])
    obs.mark_capped("docs")
    for o in obs.job("memory").stats["check_outcomes"]:
        assert "not every record was read" in o["reason"]
        assert "chunk limit" in o["coverage"]["note"]
        assert "limit" not in o["reason"]


@pytest.mark.parametrize("path, sensitive, card, subject, kind", [
    ("customer_id", True, False, True, None),
    ("meta.userEmail", True, False, False, "email"),
    ("payment.cardNumber", True, True, False, None),
    ("meeting_notes", False, False, False, None),
    ("cardinality", False, False, False, None),
    (None, False, False, False, None),
    ("", False, False, False, None),
    (0, False, False, False, None),
])
def test_key_helpers_answer_the_same_on_repeat_calls(path, sensitive, card, subject, kind):
    # The helpers remember answers per key path; a repeat must agree with the
    # first answer, and detectors still decide for keys that name nothing.
    for _ in range(2):
        assert representation.sensitive_key(path) is sensitive
        assert representation.card_key(path) is card
        assert representation.subject_id_key(path) is subject
        assert representation.direct_identifier_kind(path) == kind
    assert representation.direct_identifier_kind("meeting_notes", ["regex:email"]) == "email"
    assert representation.direct_identifier_kind("meeting_notes") is None
