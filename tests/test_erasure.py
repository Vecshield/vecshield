"""GDPR erasure impact tests against a seeded Chroma store."""

from __future__ import annotations

import pytest

from vecshield_platform.compliance import erasure_impact, verify_erasure
from vecshield_platform.connectors.chroma import ChromaConnector


@pytest.fixture
def subject_chroma(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("support-tickets")
    docs = [
        "Ticket from john.doe@example.com about a refund.",   # text match
        "Follow-up call with the customer went well.",
        "Escalation note: see prior thread.",
    ]
    col.add(
        ids=["t1", "t2", "t3"],
        documents=docs,
        embeddings=[[0.1, 0.2]] * 3,
        metadatas=[{"reporter": "john.doe@example.com"},   # metadata match (t1 too)
                   {"reporter": "jane@example.com"},
                   {"reporter": "john.doe@example.com"}],  # metadata-only match (t3)
    )
    client.create_collection("unrelated").add(
        ids=["u1"], documents=["nothing to see"], embeddings=[[0.1, 0.2]])
    return str(tmp_path / "chroma")


def test_finds_subject_in_text_and_metadata(subject_chroma):
    with ChromaConnector(path=subject_chroma) as conn:
        report = erasure_impact(conn, "john.doe@example.com")

    # t1 (text), t3 (metadata) match; t2 and unrelated do not.
    assert report.chunks_to_delete == 2
    assert report.collections_affected == {"support-tickets": 2}
    assert "support-tickets" in report.collections_to_reindex
    assert report.reindex_chunk_cost == 3  # whole affected collection reindexed
    # subject value is masked in previews
    assert all("john.doe@example.com" not in m.preview for m in report.matches)


def test_subject_not_present_yields_empty(subject_chroma):
    with ChromaConnector(path=subject_chroma) as conn:
        report = erasure_impact(conn, "nobody@nowhere.test")
    assert report.chunks_to_delete == 0
    assert report.collections_affected == {}


def test_empty_subject_rejected(subject_chroma):
    with ChromaConnector(path=subject_chroma) as conn:
        with pytest.raises(ValueError):
            erasure_impact(conn, "   ")


def test_verify_erasure_reports_remaining_matches(subject_chroma):
    with ChromaConnector(path=subject_chroma) as conn:
        verification = verify_erasure(conn, "john.doe@example.com", expected_deleted=2)
    assert not verification.ok
    assert verification.expected_deleted == 2
    assert verification.remaining.chunks_to_delete == 2


def test_verify_erasure_ok_when_subject_absent(subject_chroma):
    with ChromaConnector(path=subject_chroma) as conn:
        verification = verify_erasure(conn, "nobody@nowhere.test")
    assert verification.ok
    assert verification.to_dict()["remaining_matches"] == 0


@pytest.fixture
def name_chroma(tmp_path):
    import chromadb

    client = chromadb.PersistentClient(path=str(tmp_path / "chroma"))
    col = client.create_collection("people")
    col.add(
        ids=["p1", "p2", "p3"],
        documents=[
            "Jones filed the report yesterday.",       # substring of 'Jon' -> must NOT match
            "Message from Jon about the meeting.",     # standalone token -> matches
            "Contact jonathan@example.com for info.",  # substring of 'Jon' -> must NOT match
        ],
        embeddings=[[0.1, 0.2]] * 3,
    )
    return str(tmp_path / "chroma")


def test_word_boundary_avoids_false_positives(name_chroma):
    """Subject 'Jon' must not over-match 'Jones'/'jonathan' (over-deletion risk)."""
    with ChromaConnector(path=name_chroma) as conn:
        report = erasure_impact(conn, "Jon")
    assert {m.chunk_id for m in report.matches} == {"p2"}


def test_email_subject_with_punctuation_still_matches(name_chroma):
    with ChromaConnector(path=name_chroma) as conn:
        report = erasure_impact(conn, "jonathan@example.com")
    assert {m.chunk_id for m in report.matches} == {"p3"}


def test_erasure_report_from_dict_round_trip(subject_chroma):
    """ErasureReport.from_dict rebuilds matches and derived aggregates
    (improvement plan 1.7). collection_sizes is preserved when present."""
    from vecshield_platform.compliance.erasure import ErasureReport

    with ChromaConnector(path=subject_chroma) as conn:
        report = erasure_impact(conn, "john.doe@example.com")

    d = report.to_dict()
    # to_dict() intentionally omits collection_sizes; inject it so we can prove
    # from_dict honors it when a caller preserves it.
    d["collection_sizes"] = dict(report.collection_sizes)

    restored = ErasureReport.from_dict(d)
    assert restored.subject == report.subject
    assert restored.generated_at == report.generated_at
    assert restored.chunks_to_delete == report.chunks_to_delete
    assert restored.collections_affected == report.collections_affected
    assert restored.collection_sizes == report.collection_sizes
    assert restored.reindex_chunk_cost == report.reindex_chunk_cost
    assert restored.content_enumerable == report.content_enumerable
    assert [m.to_dict() for m in restored.matches] == \
        [m.to_dict() for m in report.matches]


def test_erasure_verification_from_dict_round_trip(subject_chroma):
    from vecshield_platform.compliance.erasure import ErasureVerification

    with ChromaConnector(path=subject_chroma) as conn:
        verification = verify_erasure(conn, "john.doe@example.com",
                                      expected_deleted=2)

    restored = ErasureVerification.from_dict(verification.to_dict())
    assert restored.ok == verification.ok
    assert restored.expected_deleted == verification.expected_deleted
    assert restored.remaining.chunks_to_delete == \
        verification.remaining.chunks_to_delete

