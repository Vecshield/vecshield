"""Collections whose vectors are face or voice templates.

A false "this is a biometric database" is expensive, so most tests here are
about what must NOT flag: a 512-wide text collection, a travel corpus with a
"landmark" field, a diarised meeting transcript with speaker ids.
"""

from __future__ import annotations

import json

import pytest

from vecshield.models import Collection, Severity
from vecshield_platform.compliance.data import load_references
from vecshield_platform.scan.biometric import (
    BIOMETRIC_MODELS,
    biometric_findings,
    biometric_templates_outcome,
    detect_biometric_collection,
    match_biometric_model,
)


def col(name="vectors", *, dimension=None, model=None, metadata=None):
    return Collection(name=name, count=100, dimension=dimension,
                      embedding_model=model, metadata=metadata or {})


# --------------------------------------------------------------- (a) model
@pytest.mark.parametrize("name,modality,model_id", [
    ("insightface/buffalo_l", "face", "insightface_buffalo_l"),
    ("antelopev2", "face", "insightface_antelopev2"),
    ("ArcFace", "face", "arcface"),
    ("arcface_r100", "face", "arcface"),
    ("Facenet512", "face", "deepface_facenet512"),
    ("facenet-pytorch", "face", "facenet"),
    ("VGG-Face", "face", "deepface_vgg_face"),
    ("dlib_face_recognition_resnet_model_v1", "face", "dlib_face_recognition"),
    ("SFace", "face", "deepface_sface"),
    ("GhostFaceNet", "face", "deepface_ghostfacenet"),
    ("adaface_ir101_webface12m", "face", "adaface"),
    ("MagFace", "face", "magface"),
    ("speechbrain/spkrec-ecapa-voxceleb", "voice", "speechbrain_ecapa_voxceleb"),
    ("speechbrain/spkrec-xvect-voxceleb", "voice", "speechbrain_xvect_voxceleb"),
    ("microsoft/wavlm-base-plus-sv", "voice", "wavlm_base_plus_sv"),
    ("pyannote/embedding", "voice", "pyannote_embedding"),
    ("pyannote/wespeaker-voxceleb-resnet34-LM", "voice", "wespeaker_resnet34"),
    ("nvidia/speakerverification_en_titanet_large", "voice", "nvidia_titanet_large"),
    ("resemblyzer", "voice", "resemblyzer"),
])
def test_curated_models_are_recognised(name, modality, model_id):
    model = match_biometric_model(name)
    assert model is not None and model.id == model_id and model.modality == modality


@pytest.mark.parametrize("name", [
    "text-embedding-3-small", "all-MiniLM-L6-v2", "facebook/contriever",
    "BAAI/bge-base-en-v1.5", "openai/clip-vit-base-patch32",
    "speechbrain/lang-id-voxlingua107-ecapa", "surface-embed-v1", None, "",
])
def test_other_models_are_not(name):
    assert match_biometric_model(name) is None


def test_every_curated_model_cites_a_source():
    for model in BIOMETRIC_MODELS:
        assert model.source_url.startswith(("https://", "http://")), model.id


def test_declared_face_model_with_matching_width_is_high_confidence():
    result = detect_biometric_collection(
        col("faces", dimension=512, model="insightface/buffalo_l"), [])
    assert result.status == "biometric_templates"
    assert result.modality == "face"
    assert result.dimension_consistent is True
    assert result.confidence == "high"
    assert result.model_source


def test_declared_voice_model_in_record_metadata_counts():
    samples = [{"model": "speechbrain/spkrec-ecapa-voxceleb", "speaker_id": f"s{i % 3}"}
               for i in range(10)]
    result = detect_biometric_collection(col("enrol", dimension=192), samples)
    assert (result.status, result.modality) == ("biometric_templates", "voice")
    assert result.estimated_distinct_identities == 3
    assert result.identity_key == "speaker_id"


def test_declared_model_that_contradicts_the_width_is_only_possible():
    result = detect_biometric_collection(col(dimension=1536, model="arcface"), [])
    assert result.status == "possible"
    assert result.dimension_consistent is False
    assert any("declaration may be wrong" in note for note in result.notes)


# ------------------------------------------------------------ (b) metadata
def test_two_independent_signals_with_one_face_specific_flag_the_collection():
    samples = [{"face_id": f"f{i}", "image_path": f"/cam/{i}.jpg", "person_id": f"p{i % 4}"}
               for i in range(20)]
    result = detect_biometric_collection(col("people", dimension=512), samples)
    assert result.status == "biometric_templates" and result.modality == "face"
    assert result.estimated_distinct_identities == 4
    assert result.identity_key == "person_id"
    signals = {e["signal"] for e in result.evidence}
    assert {"face_id", "image_source", "person_id", "dimension"} <= signals


def test_speaker_id_plus_segment_times_flag_voice():
    samples = [{"speaker_id": f"spk{i % 2}", "segment_start": 1.0, "segment_end": 3.5}
               for i in range(8)]
    result = detect_biometric_collection(col("enrollments", dimension=256), samples)
    assert (result.status, result.modality) == ("biometric_templates", "voice")


def test_one_strong_signal_alone_is_only_possible():
    result = detect_biometric_collection(col(), [{"face_id": "f1"}] * 5)
    assert result.status == "possible" and result.confidence == "low"


def test_dimension_alone_never_flags():
    for width in (128, 192, 256, 512, 4096):
        result = detect_biometric_collection(col("vectors", dimension=width),
                                             [{"doc_id": "d1", "page": 3}] * 5)
        assert result.status == "none", width


def test_supporting_signals_without_a_modality_specific_one_do_not_flag():
    samples = [{"image_path": "a.jpg", "person_id": "p1", "bbox": [1, 2, 3, 4]}] * 5
    assert detect_biometric_collection(col("catalog", dimension=512), samples).status == "none"


def test_a_place_called_landmark_is_not_facial_landmarks():
    samples = [{"landmark": "Eiffel Tower", "image_path": "paris.jpg"}] * 5
    assert detect_biometric_collection(col("travel"), samples).status == "none"


def test_real_landmark_points_are_face_specific():
    points = [[10.0, 20.0], [30.0, 20.0], [20.0, 30.0], [12.0, 40.0], [28.0, 40.0]]
    samples = [{"kps": points, "bbox": [0, 0, 50, 50]}] * 5
    result = detect_biometric_collection(col(dimension=512), samples)
    assert result.status == "biometric_templates" and result.modality == "face"


def test_a_diarised_transcript_with_a_text_model_is_only_possible():
    samples = [{"speaker_id": "S1", "start": 1.0, "end": 2.0}] * 10
    result = detect_biometric_collection(
        col("meetings", dimension=1536, model="text-embedding-3-small"), samples)
    assert result.status == "possible"
    assert any("text embedding model" in note for note in result.notes)


def test_a_text_bearing_corpus_is_only_possible():
    samples = [{"speaker_id": "S1", "start": 1.0, "end": 2.0}] * 10
    result = detect_biometric_collection(col("calls"), samples, text_share=0.9)
    assert result.status == "possible"


def test_one_stray_record_does_not_flag_a_large_sample():
    samples = [{"doc": i} for i in range(99)] + [{"face_id": "x", "image_path": "a.jpg"}]
    assert detect_biometric_collection(col(), samples).status == "none"


def test_identity_values_are_counted_not_kept():
    samples = [{"face_id": f"f{i}", "person_id": f"alice{i}@example.com",
                "image_path": "x.jpg"} for i in range(5)]
    result = detect_biometric_collection(col(), samples)
    assert result.estimated_distinct_identities == 5
    assert "alice" not in json.dumps(result.to_dict())


# --------------------------------------------------------------- outcomes
def test_templates_are_a_passed_classification_with_a_high_finding():
    result = detect_biometric_collection(col("faces", dimension=512, model="arcface"), [])
    outcome = biometric_templates_outcome("store", "faces", result)
    assert outcome["check"] == "biometric_templates"
    assert outcome["outcome"] == "passed"
    assert outcome["coverage"]["biometric_status"] == "biometric_templates"
    assert outcome["coverage"]["status"] == "complete"
    [finding] = biometric_findings("store", "faces", result)
    assert finding.category == "biometric_templates"
    assert finding.severity == Severity.HIGH
    for phrase in ("consent", "retention schedule", "DPIA", "Provenance",
                   "3 years", "Art. 5(1)(e)"):
        assert phrase in finding.remediation, phrase
    ids = {ref["id"] for ref in finding.evidence["references"]}
    assert {"bipa_740_ilcs_14_15", "gdpr_art_9_1", "eu_ai_act_art_5_1_e"} <= ids


def test_voice_findings_do_not_cite_the_face_scraping_prohibition():
    result = detect_biometric_collection(col(model="resemblyzer", dimension=256), [])
    [finding] = biometric_findings("s", "voices", result)
    ids = {ref["id"] for ref in finding.evidence["references"]}
    assert "eu_ai_act_art_5_1_e" not in ids
    assert "Provenance" not in finding.remediation


def test_possible_templates_are_medium():
    result = detect_biometric_collection(col(), [{"voiceprint": "v"}] * 3)
    [finding] = biometric_findings("s", "c", result)
    assert finding.severity == Severity.MEDIUM


def test_nothing_to_judge_from_is_inconclusive():
    result = detect_biometric_collection(col(), [])
    assert not result.assessed
    outcome = biometric_templates_outcome("s", "c", result)
    assert outcome["outcome"] == "inconclusive"
    assert outcome["coverage"]["complete"] is False
    assert biometric_findings("s", "c", result) == []


def test_no_evidence_is_passed_with_no_finding():
    result = detect_biometric_collection(col(), [{"title": "doc"}] * 3)
    assert biometric_templates_outcome("s", "c", result)["outcome"] == "passed"
    assert biometric_findings("s", "c", result) == []


def test_biometric_references_are_sourced():
    data = load_references("biometric")
    ids = {ref["id"] for ref in data["references"]}
    assert {"eu_ai_act_art_5_1_e", "gdpr_art_9_1", "bipa_740_ilcs_14_15",
            "texas_cubi_bus_com_503_001", "washington_rcw_19_375_020",
            "ccpa_1798_140_ae_2_a", "ccpa_regs_7150_b_6", "colorado_crs_6_1_1314"} == ids
    for ref in data["references"]:
        assert ref["source_url"].startswith("https://")
        assert set(ref["modalities"]) <= {"face", "voice"}
    ai_act = next(r for r in data["references"] if r["id"] == "eu_ai_act_art_5_1_e")
    assert ai_act["applies_from"] == "2025-02-02"
