"""Collections whose vectors are face or voice templates.

A face-recognition or speaker-verification embedding is not "an embedding of
some personal data". It *is* the biometric identifier: the vector that
identifies the person, compared by nearest-neighbour search. A collection of
them is a biometric database, and the regimes that attach to one (GDPR Art. 9,
BIPA, Texas CUBI, Washington RCW 19.375, CCPA sensitive personal information,
Colorado's biometric amendment, and, for face databases built by untargeted
scraping, EU AI Act Art. 5(1)(e)) are different from anything the text
classifier can report.

This module says which collections hold such templates. It is **not** an
inversion test and never reads or reconstructs a face or a voice.

**Evidence rules.** A wrong "this is a biometric database" is expensive, so a
collection is flagged only on strong evidence:

(a) its declared embedding model is on a curated list of face-recognition or
    speaker-verification models (``BIOMETRIC_MODELS``, each with its source); or
(b) at least two independent metadata signals, at least one of them specific
    to the modality (a face id, face box, facial landmarks, speaker id,
    voiceprint...), e.g. ``face_id`` plus an image path, or ``speaker_id``
    plus audio segment times.

Vector width alone **never** flags a collection: 512 is also the width of
many text and image models. It only raises confidence once (a) or (b) holds.
Two things lower a (b) verdict to ``possible``: a declared *text* embedding
model (the vectors are text embeddings of metadata about faces, not templates)
and chunks that mostly carry text (a diarised transcript has speaker ids and
segment times too).

**Outcome semantics.** ``biometric_templates`` is a classification, not a
control test: "this collection is a biometric database" is a fact about the
data, not a failure of anything. The check outcome is therefore ``passed``
(the question was answered) with the verdict in its details, and the risk is
carried by a separate, high-visibility finding (category
``biometric_templates``; HIGH when templates are confirmed, MEDIUM when
possible) whose remediation lists the obligations to evidence. Criteria that
care (BIPA, GDPR Art. 9) must read the finding or ``details.biometric_status``,
never the bare ``passed``. With nothing to judge from (no declared model and
no metadata sampled), the outcome is ``inconclusive``.

Pure: no I/O, no connector.
"""

from __future__ import annotations

import math
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Optional

from vecshield.models import Collection, Finding, Severity
from vecshield_platform.coverage import check_outcome
from vecshield_platform.scan.embedding_consistency import KNOWN_DIMENSIONS

CHECK = "biometric_templates"
CATEGORY = "biometric_templates"

FACE = "face"
VOICE = "voice"


# ------------------------------------------------------------ curated models
@dataclass(frozen=True)
class BiometricModel:
    id: str
    modality: str
    pattern: str
    #: Output widths documented for this model; empty when not verified.
    dimensions: tuple[int, ...]
    source_url: str

    def matches(self, name: str) -> bool:
        return re.search(r"(?<![a-z0-9])(?:" + self.pattern + r")(?![a-z0-9])",
                         name) is not None


#: Face-recognition and speaker-verification models, most specific first.
#: Widths were read from each model's card, config or source (see source_url).
BIOMETRIC_MODELS: tuple[BiometricModel, ...] = (
    # --- face
    BiometricModel("insightface_buffalo_l", FACE, r"buffalo_[lm]", (512,),
                   "https://github.com/deepinsight/insightface/tree/master/model_zoo"),
    BiometricModel("insightface_buffalo_s", FACE, r"buffalo_sc?", (),
                   "https://github.com/deepinsight/insightface/tree/master/model_zoo"),
    BiometricModel("insightface_antelopev2", FACE, r"antelopev2|glintr100", (512,),
                   "https://github.com/deepinsight/insightface/tree/master/model_zoo"),
    BiometricModel("insightface_w600k", FACE, r"w600k_r50|w600k_mbf", (512,),
                   "https://github.com/deepinsight/insightface/tree/master/model_zoo"),
    BiometricModel("arcface", FACE, r"arcface(?:[_-]?r?\d+)?", (512,),
                   "https://github.com/deepinsight/insightface/blob/master/recognition/arcface_torch/configs/base.py"),
    BiometricModel("insightface", FACE, r"insightface", (512,),
                   "https://github.com/deepinsight/insightface/tree/master/model_zoo"),
    BiometricModel("deepface_facenet512", FACE, r"facenet512", (512,),
                   "https://github.com/serengil/deepface/blob/master/deepface/models/facial_recognition/Facenet.py"),
    BiometricModel("facenet", FACE, r"facenet(?:[_-]pytorch)?", (128, 512),
                   "https://github.com/timesler/facenet-pytorch"),
    BiometricModel("facenet_vggface2", FACE, r"vggface2", (512,),
                   "https://github.com/timesler/facenet-pytorch"),
    BiometricModel("deepface_vgg_face", FACE, r"vgg[_-]?face", (4096,),
                   "https://github.com/serengil/deepface/blob/master/deepface/models/facial_recognition/VGGFace.py"),
    BiometricModel("dlib_face_recognition", FACE,
                   r"dlib_face_recognition_resnet_model_v1|dlib", (128,),
                   "http://dlib.net/python/index.html"),
    BiometricModel("deepface_sface", FACE, r"sface", (128,),
                   "https://github.com/serengil/deepface/blob/master/deepface/models/facial_recognition/SFace.py"),
    BiometricModel("deepface_ghostfacenet", FACE, r"ghostfacenets?", (512,),
                   "https://github.com/serengil/deepface/blob/master/deepface/models/facial_recognition/GhostFaceNet.py"),
    BiometricModel("deepface_openface", FACE, r"openface", (128,),
                   "https://github.com/serengil/deepface/blob/master/deepface/models/facial_recognition/OpenFace.py"),
    BiometricModel("deepface_deepid", FACE, r"deepid", (160,),
                   "https://github.com/serengil/deepface/blob/master/deepface/models/facial_recognition/DeepID.py"),
    BiometricModel("deepface_fb_deepface", FACE, r"deepface", (4096,),
                   "https://github.com/serengil/deepface/blob/master/deepface/models/facial_recognition/FbDeepFace.py"),
    BiometricModel("adaface", FACE, r"adaface", (512,),
                   "https://github.com/mk-minchul/AdaFace"),
    BiometricModel("magface", FACE, r"magface", (512,),
                   "https://github.com/IrvingMeng/MagFace"),
    # --- voice
    BiometricModel("speechbrain_ecapa_voxceleb", VOICE,
                   r"spkrec-ecapa-voxceleb|ecapa[_-]?tdnn", (192,),
                   "https://huggingface.co/speechbrain/spkrec-ecapa-voxceleb/blob/main/hyperparams.yaml"),
    BiometricModel("speechbrain_xvect_voxceleb", VOICE, r"spkrec-xvect-voxceleb", (512,),
                   "https://huggingface.co/speechbrain/spkrec-xvect-voxceleb/blob/main/hyperparams.yaml"),
    BiometricModel("wavlm_base_plus_sv", VOICE, r"wavlm-base-plus-sv", (512,),
                   "https://huggingface.co/microsoft/wavlm-base-plus-sv/blob/main/config.json"),
    BiometricModel("pyannote_embedding", VOICE, r"pyannote/embedding", (512,),
                   "https://github.com/pyannote/pyannote-audio/blob/develop/src/pyannote/audio/models/embedding/xvector.py"),
    BiometricModel("wespeaker_resnet34", VOICE,
                   r"wespeaker-voxceleb-resnet34(?:-lm)?", (256,),
                   "https://github.com/pyannote/pyannote-audio/blob/develop/src/pyannote/audio/models/embedding/wespeaker/__init__.py"),
    BiometricModel("wespeaker", VOICE, r"wespeaker", (),
                   "https://huggingface.co/pyannote/wespeaker-voxceleb-resnet34-LM"),
    BiometricModel("nvidia_titanet_large", VOICE,
                   r"speakerverification_en_titanet_large|titanet[_-]?l(?:arge)?", (192,),
                   "https://github.com/NVIDIA/NeMo/blob/main/examples/speaker_tasks/recognition/conf/titanet-large.yaml"),
    BiometricModel("nvidia_titanet", VOICE, r"titanet", (),
                   "https://huggingface.co/nvidia/speakerverification_en_titanet_large"),
    BiometricModel("resemblyzer", VOICE, r"resemblyzer", (256,),
                   "https://github.com/resemble-ai/Resemblyzer"),
    BiometricModel("x_vector", VOICE, r"x-?vectors?", (),
                   "https://huggingface.co/speechbrain/spkrec-xvect-voxceleb"),
)

#: Keys whose value names the model that produced the vectors.
_MODEL_KEYS = frozenset({"model", "model_name", "embedding_model", "embedder",
                         "encoder", "embedding_model_name", "recognition_model"})


def match_biometric_model(name: Optional[str]) -> Optional[BiometricModel]:
    """The curated model a declared name refers to, or None."""
    if not name:
        return None
    lowered = str(name).strip().lower()
    for model in BIOMETRIC_MODELS:
        if model.matches(lowered):
            return model
    return None


def _is_text_model(name: Optional[str]) -> bool:
    if not name:
        return False
    return str(name).strip().lower().rsplit("/", 1)[-1] in KNOWN_DIMENSIONS


# ------------------------------------------------------------ metadata signals
#: (kind, modality or None for either, strength)
_STRONG, _SUPPORTING = "strong", "supporting"

_KEY_SIGNALS: dict[str, tuple[str, Optional[str], str]] = {}


def _keys(kind: str, modality: Optional[str], strength: str, *names: str) -> None:
    for name in names:
        _KEY_SIGNALS[name] = (kind, modality, strength)


_keys("face_id", FACE, _STRONG, "face_id", "faceid", "face_uuid", "face_index",
      "face_token")
_keys("face_box", FACE, _STRONG, "face_box", "face_bbox", "facial_area",
      "face_rect", "face_location", "face_region")
_keys("face_score", FACE, _STRONG, "face_confidence", "face_score",
      "face_det_score", "face_detection_score", "det_score")
_keys("face_landmarks", FACE, _STRONG, "face_landmarks", "facial_landmarks",
      "landmark_2d_106", "landmark_3d_68")
_keys("image_source", FACE, _SUPPORTING, "image_path", "img_path", "image_url",
      "image_uri", "photo", "photo_url", "photo_path", "frame_path",
      "source_image", "snapshot")
_keys("camera", FACE, _SUPPORTING, "camera_id", "cctv", "cctv_id", "frame_id",
      "frame_number")
_keys("detection_score", FACE, _SUPPORTING, "detection_score",
      "detection_confidence")
_keys("speaker_id", VOICE, _STRONG, "speaker_id", "spk_id", "speaker",
      "speaker_label")
_keys("voiceprint", VOICE, _STRONG, "voiceprint", "voice_print", "voice_id",
      "voice_template", "voice_embedding", "speaker_embedding")
_keys("audio_source", VOICE, _SUPPORTING, "audio_path", "audio_file",
      "audio_url", "wav_path", "recording_id", "utterance_id")
_keys("sample_rate", VOICE, _SUPPORTING, "sample_rate", "sampling_rate")
_keys("enrollment", None, _STRONG, "enrollment_id", "enrolment_id",
      "enrolled_at", "enrollment_date", "template_id", "biometric_id",
      "biometric_template")
_keys("person_id", None, _SUPPORTING, "person_id", "identity", "identity_id",
      "subject_id", "individual_id")

#: Keys that need a value of the right shape before they count: "landmark"
#: is also a tourist attraction and "bbox" any detected object.
_LANDMARK_KEYS = frozenset({"landmarks", "landmark", "kps", "keypoints"})
_BBOX_KEYS = frozenset({"bbox", "bounding_box", "box"})
_MODALITY_KEYS = frozenset({"modality", "embedding_type", "template_type",
                            "biometric_type", "type", "kind"})
_MODALITY_VALUES = {"face": FACE, "facial": FACE, "face_embedding": FACE,
                    "face_template": FACE, "voice": VOICE, "speaker": VOICE,
                    "voiceprint": VOICE, "speaker_embedding": VOICE,
                    "voice_template": VOICE}
_SEGMENT_START = frozenset({"segment_start", "start_time", "start", "start_sec",
                            "offset"})
_SEGMENT_END = frozenset({"segment_end", "end_time", "end", "end_sec", "duration"})
_IMAGE_EXT = re.compile(r"\.(?:jpe?g|png|bmp|webp|tiff?|heic)$", re.I)
_AUDIO_EXT = re.compile(r"\.(?:wav|flac|mp3|m4a|ogg|opus|aac)$", re.I)
_NAME_HINTS = {
    FACE: re.compile(r"(?<![a-z])(?:faces?|facial|face_?(?:embeddings?|templates?|"
                     r"ids?|db|gallery|index|vectors?))(?![a-z])"),
    VOICE: re.compile(r"(?<![a-z])(?:voices?|voiceprints?|speakers?|"
                      r"speaker_?(?:embeddings?|ids?|enrollments?|vectors?))(?![a-z])"),
}

#: Keys whose distinct values estimate how many people the collection holds,
#: most person-like first. A face id usually names a detection, not a person,
#: so it is the last resort.
_IDENTITY_KEYS = ("person_id", "identity", "identity_id", "subject_id",
                  "individual_id", "speaker_id", "spk_id", "speaker",
                  "enrollment_id", "enrolment_id", "face_id")

#: Widths that face and speaker templates commonly have. Used only to raise
#: confidence in a verdict already reached on other evidence.
_TEMPLATE_WIDTHS = frozenset({128, 160, 192, 256, 512, 4096})

#: A metadata signal counts when at least this share of samples carries it
#: (and at least one does), so one stray record cannot flag a collection.
MIN_SIGNAL_SHARE = 0.1


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_points(value: Any) -> bool:
    """Five or more 2-D/3-D points: face landmarks, not a place name."""
    if isinstance(value, Mapping):
        keys = {str(k).lower() for k in value}
        return len(keys & {"left_eye", "right_eye", "nose", "mouth_left",
                           "mouth_right"}) >= 2
    if not isinstance(value, (list, tuple)) or len(value) < 5:
        return False
    return all(isinstance(p, (list, tuple)) and 2 <= len(p) <= 3
               and all(_number(c) for c in p) for p in value)


def _is_box(value: Any) -> bool:
    if isinstance(value, Mapping):
        keys = {str(k).lower() for k in value}
        return {"x", "y"} <= keys and bool(keys & {"w", "h", "width", "height"})
    return (isinstance(value, (list, tuple)) and len(value) == 4
            and all(_number(c) for c in value))


def _flatten(record: Mapping[str, Any], depth: int = 2) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in record.items():
        name = str(key).strip().lower()
        out.setdefault(name, value)
        if depth > 1 and isinstance(value, Mapping):
            for inner, inner_value in _flatten(value, depth - 1).items():
                out.setdefault(inner, inner_value)
    return out


def _record_signals(record: Mapping[str, Any]) -> tuple[set[tuple[str, Optional[str], str]],
                                                        list[str]]:
    """Signals one record carries, and any model names it declares."""
    signals: set[tuple[str, Optional[str], str]] = set()
    models: list[str] = []
    flat = _flatten(record)
    for key, value in flat.items():
        if key in _KEY_SIGNALS and value not in (None, "", [], {}):
            signals.add(_KEY_SIGNALS[key])
        if key in _LANDMARK_KEYS and _is_points(value):
            signals.add(("face_landmarks", FACE, _STRONG))
        if key in _BBOX_KEYS and _is_box(value):
            signals.add(("bounding_box", FACE, _SUPPORTING))
        if key in _MODALITY_KEYS and isinstance(value, str):
            modality = _MODALITY_VALUES.get(value.strip().lower())
            if modality:
                signals.add((f"declared_{modality}_modality", modality, _STRONG))
        if key in _MODEL_KEYS and isinstance(value, str):
            models.append(value)
        if isinstance(value, str):
            text = value.strip()
            if _IMAGE_EXT.search(text):
                signals.add(("image_source", FACE, _SUPPORTING))
            elif _AUDIO_EXT.search(text):
                signals.add(("audio_source", VOICE, _SUPPORTING))
    if (any(k in flat and _number(flat[k]) for k in _SEGMENT_START)
            and any(k in flat and _number(flat[k]) for k in _SEGMENT_END)):
        signals.add(("segment_times", VOICE, _SUPPORTING))
    return signals, models


# ------------------------------------------------------------------- verdict
@dataclass(frozen=True)
class BiometricAssessment:
    collection: str
    #: "biometric_templates" | "possible" | "none"
    status: str = "none"
    modality: Optional[str] = None
    evidence: tuple[dict[str, Any], ...] = ()
    estimated_distinct_identities: Optional[int] = None
    identity_key: Optional[str] = None
    model: Optional[str] = None
    model_source: Optional[str] = None
    dimension: Optional[int] = None
    dimension_consistent: Optional[bool] = None
    confidence: str = "none"
    samples: int = 0
    notes: tuple[str, ...] = ()
    #: False when there was nothing to judge from: no declared model, no
    #: collection metadata and no sampled records.
    assessed: bool = True

    @property
    def flagged(self) -> bool:
        return self.status in ("biometric_templates", "possible")

    def summary(self) -> str:
        if not self.assessed:
            return ("No declared model and no metadata were available, so "
                    "whether this collection holds biometric templates is unknown.")
        kind = {"face": "face-recognition", "voice": "speaker-verification"}.get(
            self.modality or "", "biometric")
        if self.status == "biometric_templates":
            return (f"The vectors in '{self.collection}' appear to be {kind} "
                    f"templates ({self._because()}).")
        if self.status == "possible":
            return (f"'{self.collection}' may hold {kind} templates "
                    f"({self._because()}); the evidence is not conclusive.")
        return f"No evidence that '{self.collection}' holds face or voice templates."

    def _because(self) -> str:
        return ", ".join(item["detail"] for item in self.evidence[:3]) or "no detail"

    def to_dict(self) -> dict[str, Any]:
        return {"collection": self.collection, "status": self.status,
                "modality": self.modality, "evidence": [dict(e) for e in self.evidence],
                "estimated_distinct_identities": self.estimated_distinct_identities,
                "identity_key": self.identity_key, "model": self.model,
                "model_source": self.model_source, "dimension": self.dimension,
                "dimension_consistent": self.dimension_consistent,
                "confidence": self.confidence, "samples": self.samples,
                "notes": list(self.notes), "assessed": self.assessed,
                "summary": self.summary()}


_RANK = {"none": 0, "possible": 1, "biometric_templates": 2}


def detect_biometric_collection(collection: Collection,
                                metadata_samples: Iterable[Mapping[str, Any]], *,
                                text_share: Optional[float] = None) -> BiometricAssessment:
    """Decide whether ``collection`` holds face or voice templates.

    ``metadata_samples`` are chunk metadata dicts from the scan (any number;
    more is better). ``text_share`` is the share of sampled chunks with a
    classifiable text surface, when the caller knows it.
    """
    samples = [dict(s or {}) for s in metadata_samples]
    n = len(samples)
    threshold = max(1, math.ceil(MIN_SIGNAL_SHARE * n)) if n else 1

    # --- (a) declared model: on the collection, or on the records themselves
    declared = collection.embedding_model
    model_hit = match_biometric_model(declared)
    model_origin = "collection" if model_hit else None
    col_meta_signals, col_meta_models = _record_signals(collection.metadata or {})
    for name in col_meta_models:
        if model_hit is None and (hit := match_biometric_model(name)):
            model_hit, declared, model_origin = hit, name, "collection metadata"

    counts: dict[tuple[str, Optional[str], str], int] = {}
    record_models: dict[str, int] = {}
    for sample in samples:
        signals, models = _record_signals(sample)
        for sig in signals:
            counts[sig] = counts.get(sig, 0) + 1
        for name in set(models):
            record_models[name] = record_models.get(name, 0) + 1
    if model_hit is None:
        for name, seen in sorted(record_models.items(), key=lambda kv: (-kv[1], kv[0])):
            if seen >= threshold and (hit := match_biometric_model(name)):
                model_hit, declared, model_origin = hit, name, "record metadata"
                break

    present: dict[tuple[str, Optional[str], str], dict[str, Any]] = {}
    for sig in col_meta_signals:
        present[sig] = {"signal": sig[0], "strength": sig[2], "modality": sig[1],
                        "source": "collection metadata",
                        "detail": f"collection metadata carries {sig[0].replace('_', ' ')}"}
    for sig, seen in counts.items():
        if seen >= threshold and sig not in present:
            present[sig] = {"signal": sig[0], "strength": sig[2], "modality": sig[1],
                            "source": "record metadata", "records": seen,
                            "share": round(seen / n, 3),
                            "detail": f"{sig[0].replace('_', ' ')} in {seen}/{n} records"}
    name = collection.name.lower()
    for hint_modality, pattern in _NAME_HINTS.items():
        if pattern.search(name):
            sig = (f"{hint_modality}_collection_name", hint_modality, _SUPPORTING)
            present[sig] = {"signal": sig[0], "strength": _SUPPORTING,
                            "modality": hint_modality, "source": "collection name",
                            "detail": f"collection name suggests {hint_modality} data"}

    assessed = bool(n or collection.embedding_model or collection.metadata or model_hit)
    dimension = collection.dimension if isinstance(collection.dimension, int) and \
        collection.dimension > 0 else None
    notes: list[str] = []

    # --- per-modality verdicts
    best: tuple[int, int, str, str, list[dict[str, Any]]] = (0, 0, "", "none", [])
    for candidate in (FACE, VOICE):
        relevant = [ev for sig, ev in present.items() if sig[1] in (candidate, None)]
        specific = [ev for ev in relevant if ev["modality"] == candidate]
        strong = [ev for ev in relevant if ev["strength"] == _STRONG]
        specific_strong = [ev for ev in specific if ev["strength"] == _STRONG]
        status = "none"
        evidence = list(relevant)
        if model_hit is not None and model_hit.modality == candidate:
            status = "biometric_templates"
            evidence.insert(0, {"signal": "declared_model", "strength": _STRONG,
                                "modality": candidate, "source": model_origin,
                                "model": model_hit.id,
                                "detail": f"declared model '{declared}' is a "
                                          f"{'face-recognition' if candidate == FACE else 'speaker-verification'} model"})
        elif specific_strong and len(relevant) >= 2:
            status = "biometric_templates"
        elif strong:
            status = "possible"
        key = (_RANK[status], len(evidence), candidate == FACE)
        if key > (best[0], best[1], best[2] == FACE):
            best = (_RANK[status], len(evidence), candidate, status, evidence)

    _, _, best_modality, status, evidence = best
    modality: Optional[str] = best_modality or None
    if status == "none":
        modality, evidence = None, []

    # --- counter-evidence for a metadata-only verdict
    model_consistent: Optional[bool] = None
    if status != "none" and model_hit is None:
        if _is_text_model(collection.embedding_model):
            notes.append(f"The declared model '{collection.embedding_model}' is a "
                         "text embedding model, so the vectors are likely text "
                         "embeddings of metadata about people, not templates.")
            status = "possible" if status == "biometric_templates" else status
        elif text_share is not None and text_share >= 0.5:
            notes.append(f"{round(text_share * 100)}% of sampled chunks carry text; "
                         "this may be a transcript or caption corpus with speaker "
                         "or face metadata rather than a template store.")
            status = "possible" if status == "biometric_templates" else status

    # --- width: confirms or questions, never decides
    if model_hit is not None and status == "biometric_templates":
        if dimension is not None and model_hit.dimensions:
            model_consistent = dimension in model_hit.dimensions
            if not model_consistent:
                notes.append(f"'{declared}' produces {model_hit.dimensions} dimension "
                             f"vectors but this collection's are {dimension}; the "
                             "declaration may be wrong.")
                status = "possible"
    if status == "none":
        confidence = "none"
    elif status == "possible":
        confidence = "low"
    elif model_consistent or (model_hit is None and dimension in _TEMPLATE_WIDTHS
                              and len(evidence) >= 3):
        confidence = "high"
    else:
        confidence = "medium"
    if status != "none" and model_hit is None and dimension in _TEMPLATE_WIDTHS:
        evidence.append({"signal": "dimension", "strength": _SUPPORTING,
                         "modality": modality, "source": "inventory",
                         "detail": f"{dimension}-dimension vectors are typical of "
                                   "face and speaker templates"})

    identities, identity_key = _distinct_identities(samples)
    if status == "none":
        identities, identity_key = None, None
    return BiometricAssessment(
        collection=collection.name, status=status, modality=modality,
        evidence=tuple(evidence), estimated_distinct_identities=identities,
        identity_key=identity_key,
        model=declared if model_hit is not None else None,
        model_source=model_hit.source_url if model_hit is not None else None,
        dimension=dimension, dimension_consistent=model_consistent,
        confidence=confidence, samples=n, notes=tuple(notes), assessed=assessed)


def _distinct_identities(samples: list[dict[str, Any]]) -> tuple[Optional[int], Optional[str]]:
    """Distinct identity values among the samples. Values are never kept."""
    flats = [_flatten(s) for s in samples]
    for key in _IDENTITY_KEYS:
        values = {repr(f[key]) for f in flats
                  if f.get(key) not in (None, "", [], {}) and not isinstance(f.get(key), Mapping)}
        if values:
            return len(values), key
    return None, None


# ------------------------------------------------------------------ outputs
def biometric_templates_outcome(store: str, collection: Optional[str],
                                assessment: BiometricAssessment, *,
                                complete: bool = True, **coverage: Any) -> dict:
    """The ``biometric_templates`` check outcome (see the module docstring)."""
    details = assessment.to_dict()
    details.pop("summary", None)
    details.pop("collection", None)
    details["biometric_status"] = details.pop("status")
    if not assessment.assessed:
        return check_outcome(CHECK, store, collection, outcome="inconclusive",
                             reason=assessment.summary(), complete=False,
                             **{**details, **coverage})
    return check_outcome(CHECK, store, collection, outcome="passed",
                         reason=assessment.summary(), complete=bool(complete),
                         **{**details, **coverage})


def _obligations(modality: Optional[str]) -> tuple[list[str], list[dict[str, str]]]:
    from vecshield_platform.compliance.data import load_references

    refs = [ref for ref in load_references("biometric")["references"]
            if modality is None or modality in ref.get("modalities", ())]
    steps = [
        "Consent: hold a record of notice and written consent for every enrolled "
        "person (BIPA 740 ILCS 14/15(b); Texas Bus. & Com. Code 503.001; "
        "RCW 19.375.020; the GDPR Art. 9(2) condition relied on).",
        "Retention: publish a written retention schedule and destroy templates when "
        "the purpose is met and no later than 3 years after last interaction "
        "(BIPA 15(a)); 24 months under Colorado C.R.S. 6-1-1314; within a year of "
        "the purpose expiring under Texas CUBI. Declare it as a retention rule so "
        "the scan can evaluate it.",
        "Impact assessment: a DPIA (GDPR Art. 35) and a CCPA risk assessment "
        "(11 CCR 7150(b)(2) and (b)(6)).",
    ]
    if modality in (FACE, None):
        steps.append(
            "Provenance: confirm how the face images were obtained. If the "
            "collection was built or expanded by untargeted scraping of facial "
            "images from the internet or CCTV footage, that is prohibited under "
            "EU AI Act Art. 5(1)(e) (applies from 2 February 2025).")
    steps.append("Access: restrict query access to the matching service; a "
                 "template store answers 'who is this?' for anyone who can query it.")
    cited = [{"id": ref["id"], "citation": ref["citation"],
              "source_url": ref["source_url"]} for ref in refs]
    return steps, cited


def biometric_findings(store: str, collection: Optional[str],
                       assessment: BiometricAssessment) -> list[Finding]:
    """A high-visibility finding for a template (or possible template) store."""
    if not assessment.flagged:
        return []
    severity = Severity.HIGH if assessment.status == "biometric_templates" else Severity.MEDIUM
    steps, cited = _obligations(assessment.modality)
    kind = {"face": "Face", "voice": "Voice"}.get(assessment.modality or "", "Biometric")
    verdict = ("holds" if assessment.status == "biometric_templates" else "may hold")
    where = f"'{collection}'" if collection else "this store"
    people = (f" About {assessment.estimated_distinct_identities} distinct "
              f"identities appear in the sampled records."
              if assessment.estimated_distinct_identities else "")
    return [Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"{kind} templates: {where} {verdict} biometric identifiers",
        severity=severity,
        category=CATEGORY,
        store=store,
        collection=collection,
        description=(assessment.summary() + people + " Vectors like these identify "
                     "the person directly; biometric regimes attach to the "
                     "collection itself, whatever else it contains."),
        evidence={**assessment.to_dict(), "references": cited},
        remediation=" ".join(f"({i}) {step}" for i, step in enumerate(steps, 1)),
    )]
