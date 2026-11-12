"""Platform-side configuration for the installed detection engines.

Detection rules, entity mapping and scoring stay in the `vecshield` library.
This module selects the local NLP model, exposes provenance and makes unavailable
or failed NLP visible instead of treating a model failure as clean content.
Models are installed at build time or with ``vecshield-platform nlp install``
(see ``vecshield_platform.nlp_models`` and docs/nlp_models.md); classification
never downloads weights.
"""

from __future__ import annotations

from copy import deepcopy
from importlib import metadata
import json
import logging
import os
from pathlib import Path
import threading

from vecshield.classify import Classifier, RegexClassifier
from vecshield.classify.base import apply_phi_context, merge
from vecshield.models import Classification, SensitivityLabel
from vecshield_platform.nlp_models import DEFAULT_MODEL as _catalog_default
from vecshield_platform.nlp_models import install_hint

#: The default model (decision D-N1): the curated-transformers RoBERTa
#: pipeline. It loads with released packages, has MIT weights and gave the best
#: measured precision. ``en_core_web_hftrf`` stays in the catalog but needs a
#: spacy-transformers release that can read its safetensors weights.
DEFAULT_NLP_MODEL = _catalog_default
DEFAULT_MODEL_VERSION = "3.8.0"
logger = logging.getLogger(__name__)
#: Guards the bookkeeping below. Held only for dictionary updates, never for a
#: model load, so status reads stay instant while a model loads.
_state_lock = threading.RLock()
_loaded: dict[tuple[str, str], "EnterpriseClassifier"] = {}
#: Keys whose model is being loaded right now, or whose warm-up has been
#: scheduled and not yet finished.
_loading: set[tuple[str, str]] = set()
_warmups: set[tuple[str, str]] = set()
#: The last load failure per key, for a mode (``required``) that raises
#: rather than degrading, so status can say why instead of "unverified".
_failed: dict[tuple[str, str], str] = {}
_key_locks: dict[tuple[str, str], threading.Lock] = {}


class DetectionConfigurationError(ValueError):
    pass


class DetectionUnavailableError(RuntimeError):
    pass


class DetectionRuntimeError(RuntimeError):
    pass


#: Detection states in which the NER layer did not run over the content.
NLP_NOT_READY = ("degraded", "disabled", "unavailable")


def nlp_coverage_gap(classifier) -> tuple[str | None, str | None]:
    """(status, reason) when the classifier's NLP layer did not run, else (None, None).

    Degraded (model missing or failed to load) and disabled (turned off by
    configuration) are the same fact for coverage: names, locations and
    organisations were not examined, so a run cannot be complete. A
    classifier that reports no detection metadata makes no claim either way.
    """
    meta_fn = getattr(classifier, "detection_metadata", None)
    if meta_fn is None:
        return None, None
    status = (meta_fn() or {}).get("status")
    if status not in NLP_NOT_READY:
        return None, None
    why = ("NLP detection is turned off" if status == "disabled"
           else "NLP detection is not available" if status == "unavailable"
           else "The NLP model is not loaded")
    return status, (f"{why} (detection status: {status}), so names, locations and "
                    "organisations were not examined; only pattern detectors ran.")


def _version(package: str) -> str | None:
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def _detection_version() -> str:
    """`vecshield` ships in the same distribution as this package, so its
    version is the module's, not a separately installed distribution's."""
    from vecshield import __version__
    return __version__


def _configuration(use_nlp: bool | None, model: str | None) -> tuple[str, str]:
    mode = os.environ.get("VECSHIELD_NLP_MODE", "auto").strip().lower()
    if use_nlp is False:
        mode = "disabled"
    elif use_nlp is True or model is not None:
        mode = "required"
    if mode not in {"auto", "required", "disabled"}:
        raise DetectionConfigurationError("VECSHIELD_NLP_MODE must be auto, required, or disabled")
    selected = model if model is not None else os.environ.get("VECSHIELD_NLP_MODEL", DEFAULT_NLP_MODEL)
    if not selected.strip():
        raise DetectionConfigurationError("NLP model must be a package name or local model directory")
    if use_nlp is False and model is not None:
        raise DetectionConfigurationError("Cannot select an NLP model with NLP disabled")
    return mode, selected.strip()


def _model_installed(model: str) -> bool:
    return _version(model) is not None or (Path(model).is_dir() and (Path(model) / "meta.json").is_file())


def _model_version(model: str) -> str | None:
    installed = _version(model)
    if installed:
        return installed
    try:
        return json.loads((Path(model) / "meta.json").read_text()).get("version")
    except (OSError, ValueError):
        return None


def _requirement_name(requirement: str) -> str:
    try:
        from packaging.requirements import Requirement

        return Requirement(requirement).name
    except Exception:  # noqa: BLE001 - fall back to the leading name
        import re

        return re.split(r"[<>=!~;\[\s]", requirement.strip(), maxsplit=1)[0]


def _missing_requirements(model: str) -> list[str]:
    """Runtime packages the model's catalog entry declares that are absent.

    A transformer pipeline (``en_core_web_trf``) installs as a package but
    cannot load without ``spacy-curated-transformers`` and torch; being installed is not being
    loadable. Presence only: a version outside the declared range is left to
    the load itself, which is the real test.
    """
    from vecshield_platform.nlp_models import CATALOG, RUNTIME_REQUIREMENTS

    spec = CATALOG.get(model)
    declared = tuple(spec.requires if spec else ()) + RUNTIME_REQUIREMENTS
    return [req for req in dict.fromkeys(declared)
            if _version(_requirement_name(req)) is None]


def _missing_requirements_message(model: str, missing: list[str]) -> str:
    names = ", ".join(_requirement_name(req) for req in missing)
    hint = install_hint(model)
    return (f"NLP model {model!r} needs {names}, which "
            f"{'is' if len(missing) == 1 else 'are'} not installed; "
            + (f"install it with `{hint}`" if hint else "see docs/nlp_models.md"))


def _not_installed_message(model: str) -> str:
    hint = install_hint(model)
    return (f"NLP model {model!r} is not installed; "
            + (f"install it with `{hint}`" if hint else "see docs/nlp_models.md"))


def nlp_settings() -> tuple[list[str], frozenset[str]]:
    """The requested entity types and allow-list, from the environment.

    ``VECSHIELD_NLP_ENTITIES`` narrows the entity types (decision D-N3 keeps
    ORGANIZATION in the default and leaves dropping it to the deployment);
    ``VECSHIELD_NLP_ALLOW_LIST`` / ``VECSHIELD_NLP_ALLOW_LIST_FILE`` name
    product and brand terms the NER layer must not report. A bad value is a
    configuration error, raised rather than ignored.
    """
    from vecshield.classify.presidio_classifier import (
        resolve_allow_list,
        resolve_requested_entities,
    )

    try:
        return resolve_requested_entities(), resolve_allow_list()
    except ValueError as exc:
        raise DetectionConfigurationError(str(exc)) from exc
    except OSError as exc:
        raise DetectionConfigurationError(
            f"VECSHIELD_NLP_ALLOW_LIST_FILE could not be read ({type(exc).__name__}: "
            f"{exc.strerror or exc})") from exc


def _build_nlp(model: str):
    if not _model_installed(model):
        raise DetectionUnavailableError(_not_installed_message(model))
    if missing := _missing_requirements(model):
        raise DetectionUnavailableError(_missing_requirements_message(model, missing))
    entities, allow_list = nlp_settings()
    try:
        from vecshield.classify.presidio_classifier import (
            PresidioClassifier,
            pin_offline_runtime,
        )

        # Weights are never downloaded at scan time, and classification never
        # fetches reference data (the Public Suffix List) either.
        pin_offline_runtime()

        class CheckedPresidio(PresidioClassifier):
            # The library's optional adapter converts analyzer failures to
            # NONE. The platform needs those failures to reach its
            # coverage/error path. Entity selection and result conversion are
            # reused from the library unchanged.
            # Each text goes to the model for its detected language when one
            # is loaded (see ``language_for``), so the languages detection
            # status reports are the languages actually analysed.
            def classify(self, text):
                if not text:
                    return Classification(SensitivityLabel.NONE, 0.0)
                results = self._analyzer.analyze(
                    text=text, language=self.language_for(text),
                    entities=self.requested_entities)
                return self._results_to_classification(text, results)

            def classify_batch(self, texts, spacy_batch_size=64):
                items = list(texts)
                indexed = [(i, text) for i, text in enumerate(items) if text]
                out = [Classification(SensitivityLabel.NONE, 0.0) for _ in items]
                if indexed:
                    # Metadata values (a source file, a tenant, a language)
                    # repeat across a batch's chunks; the model reads each
                    # distinct text once. Every position still gets its own
                    # Classification, since callers mutate span dicts.
                    unique = list(dict.fromkeys(text for _, text in indexed))
                    analysed = dict(zip(unique, self._analyze_batch(unique, spacy_batch_size),
                                        strict=True))
                    for index, text in indexed:
                        out[index] = self._results_to_classification(text, analysed[text])
                return out

        return CheckedPresidio(model=model, entities=entities, allow_list=allow_list)
    except DetectionUnavailableError:
        raise
    except Exception as exc:
        raise DetectionUnavailableError(
            f"NLP model {model!r} could not load ({type(exc).__name__}); "
            "install the NLP extra and the model before scanning") from exc


class EnterpriseClassifier(Classifier):
    """Cached, thread-safe `vecshield` ensemble with batch and status metadata."""

    def __init__(self, *, mode: str, model: str, nlp=None, reason: str = ""):
        self.regex = RegexClassifier()
        self.nlp = nlp
        self.mode = mode
        self.model = model
        self.reason = reason
        self.name = "ensemble" if nlp is not None else "regex"
        self.classifiers = [self.regex] + ([nlp] if nlp is not None else [])
        self._lock = threading.RLock()

    @property
    def members(self) -> list[str]:
        return [classifier.name for classifier in self.classifiers]

    def classify(self, text: str | None) -> Classification:
        with self._lock:
            try:
                results = [classifier.classify(text) for classifier in self.classifiers]
                return deepcopy(apply_phi_context(merge(results), text))
            except Exception as exc:
                raise DetectionRuntimeError(
                    f"Classification failed ({type(exc).__name__}); content was not fully assessed"
                ) from exc

    def classify_batch(self, texts, batch_size: int = 64, *, use_nlp: bool = True,
                       timings: dict | None = None) -> list[Classification]:
        """Classify ``texts`` in order, the NLP leg through ``nlp.pipe``.

        ``use_nlp=False`` runs the pattern detectors only; the scan uses it once
        its NLP time budget is spent, and records those chunks as partially
        covered. ``timings``, when given, accumulates ``nlp_seconds``: the time
        spent in the model, measured inside the lock so waiting for another
        scan's batch is not charged to this one.
        """
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        # Bound the NLP working set while preserving input order and empty text.
        from itertools import islice
        import time

        iterator = iter(texts)
        output = []
        nlp = self.nlp if use_nlp else None
        with self._lock:
            try:
                while items := list(islice(iterator, batch_size)):
                    regex_results = [self.regex.classify(text) for text in items]
                    started = time.perf_counter()
                    if nlp is None:
                        nlp_results = [Classification(SensitivityLabel.NONE, 0.0) for _ in items]
                    elif hasattr(nlp, "classify_batch"):
                        nlp_results = nlp.classify_batch(items, spacy_batch_size=batch_size)
                    else:
                        nlp_results = [nlp.classify(text) for text in items]
                    if timings is not None and nlp is not None:
                        timings["nlp_seconds"] = (timings.get("nlp_seconds", 0.0)
                                                  + time.perf_counter() - started)
                    for text, regex, nlp_result in zip(items, regex_results, nlp_results,
                                                       strict=True):
                        output.append(deepcopy(apply_phi_context(merge([regex, nlp_result]),
                                                                 text)))
            except Exception as exc:
                raise DetectionRuntimeError(
                    f"Batch classification failed ({type(exc).__name__}); content was not fully assessed"
                ) from exc
        return output

    def detection_metadata(self) -> dict:
        metadata_ = self._metadata()
        # Degraded because the model is absent: say how to fix it. Never for
        # other load failures, where reinstalling would not be the remedy.
        if (self.nlp is None and self.mode != "disabled"
                and not _model_installed(self.model)
                and (hint := install_hint(self.model))):
            metadata_["install_command"] = hint
        return metadata_

    def _metadata(self) -> dict:
        return {"classifier": self.name, "mode": self.mode,
                "requested_model": self.model,
                "active_model": self.model if self.nlp is not None else None,
                "model_version": _model_version(self.model) if self.nlp is not None else None,
                "nlp_loaded": self.nlp is not None,
                # The languages this classifier's NER actually analyses in:
                # what loaded, not what is installed.
                "ner_languages": (sorted(getattr(self.nlp, "languages", None) or ("en",))
                                  if self.nlp is not None else []),
                "status": "disabled" if self.mode == "disabled" else
                          "ready" if self.nlp is not None else "degraded",
                "reason": self.reason, "detection_version": _detection_version(),
                "requested_entities": (list(getattr(self.nlp, "requested_entities", []) or [])
                                       if self.nlp is not None else []),
                "allow_list_terms": (len(getattr(self.nlp, "allow_list", None) or ())
                                     if self.nlp is not None else 0),
                "regex_detector_count": len(self.regex.detectors),
                "presidio_version": _version("presidio-analyzer"),
                "spacy_version": _version("spacy")}


def _load_classifier(mode: str, model: str) -> EnterpriseClassifier:
    nlp = None
    reason = ""
    if mode != "disabled":
        try:
            nlp = _build_nlp(model)
        except DetectionUnavailableError as exc:
            if mode == "required":
                raise
            reason = str(exc)
            logger.warning("NLP detection unavailable; using regex detectors only: %s", reason)
    return EnterpriseClassifier(mode=mode, model=model, nlp=nlp, reason=reason)


def _cached_classifier(mode: str, model: str) -> EnterpriseClassifier:
    """Build once per (mode, model), even under simultaneous first use.

    A per-key lock serialises the load itself, so two scans never build a
    heavy model twice, while the shared state lock is held only to read and
    update the bookkeeping -- a status request during a 40-second load
    answers ``loading`` at once instead of waiting for it.
    """
    key = (mode, model)
    with _state_lock:
        if (cached := _loaded.get(key)) is not None:
            return cached
        key_lock = _key_locks.setdefault(key, threading.Lock())
    with key_lock:
        with _state_lock:
            if (cached := _loaded.get(key)) is not None:
                return cached
            _loading.add(key)
        try:
            classifier = _load_classifier(mode, model)
        except Exception as exc:
            with _state_lock:
                _failed[key] = str(exc) or type(exc).__name__
                _loading.discard(key)
            raise
        with _state_lock:
            _loaded[key] = classifier
            _failed.pop(key, None)
            _loading.discard(key)
        return classifier


def build_classifier(*, use_nlp: bool | None = None,
                     model: str | None = None) -> EnterpriseClassifier:
    mode, selected = _configuration(use_nlp, model)
    return _cached_classifier(mode, selected)


def reset_classifier_cache() -> None:
    with _state_lock:
        _loaded.clear()
        _loading.clear()
        _warmups.clear()
        _failed.clear()
        _key_locks.clear()


#: Status reason while the model loads in the background.
LOADING_REASON = ("The NLP model is loading in the background; detection reads ready "
                  "once the load succeeds. A scan started now waits for it.")


def start_warm_up() -> threading.Thread | None:
    """Load the configured classifier on a background thread.

    ``serve`` calls this at start so ``/admin/detection`` reads ``ready`` (or
    says why not) without a scan having run, and the first scan does not pay
    the 4-40 s model load. Status reads ``loading`` from the moment this
    returns until the load finishes. Returns ``None`` when NLP is disabled.
    A failure is logged and kept for status; it never raises here, because
    the caller has nothing better to do with it than status already does.
    """
    mode, model = _configuration(None, None)
    if mode == "disabled":
        return None
    key = (mode, model)
    with _state_lock:
        if key in _loaded:
            return None
        _warmups.add(key)

    def run() -> None:
        try:
            build_classifier()
        except Exception as exc:  # noqa: BLE001 - reported through status
            logger.error("NLP warm-up failed; detection status reports the reason: %s", exc)
        finally:
            with _state_lock:
                _warmups.discard(key)

    thread = threading.Thread(target=run, name="vecshield-nlp-warmup", daemon=True)
    thread.start()
    return thread


def startup_warning() -> str | None:
    """One line for ``serve`` and ``scan`` when NLP will not run in ``auto`` mode.

    pip installs cannot pull a model wheel in as a dependency, so a plain
    ``pip install`` starts regex-only; this is where the operator learns it,
    with the command that fixes it. ``None`` when NLP is available, disabled
    on purpose, or ``required`` (which fails loudly on its own).
    """
    try:
        status = detection_status()
    except ValueError:
        return None
    if status.get("mode") != "auto" or status.get("status") not in ("degraded", "unavailable"):
        return None
    command = status.get("install_command")
    reason = status.get("reason") or "the NLP model is not available"
    line = f"NLP detection unavailable, pattern detectors only: {reason}"
    if command and command not in line:
        line += f" (install: {command})"
    return line


def _unavailable_reason(model: str) -> str:
    missing = [name for name in ("spacy", "presidio-analyzer") if not _version(name)]
    if not _model_installed(model):
        return _not_installed_message(model) + (
            f" (also missing: {', '.join(missing)})" if missing else "")
    if requirements := _missing_requirements(model):
        return _missing_requirements_message(model, requirements)
    return f"NLP dependencies are not installed: {', '.join(missing)}"


#: Status before any classifier has loaded the model in this process.
UNVERIFIED_REASON = ("The model and its declared dependencies are installed, but it has "
                     "not been loaded in this process yet; it reads ready only after a "
                     "load succeeds.")


def detection_status() -> dict:
    """Inspect dependencies and last load result without loading/downloading NLP."""
    mode, model = _configuration(None, None)
    # Installed is not loadable: the catalog's declared runtime (for example
    # spacy-transformers for a transformer pipeline) must be present too, and
    # even then only a successful load makes the status ``ready``.
    available = bool(_version("spacy") and _version("presidio-analyzer")
                     and _model_installed(model) and not _missing_requirements(model))
    status: dict = {"mode": mode, "requested_model": model, "active_model": None,
              "model_version": _model_version(model), "nlp_available": available,
              "nlp_loaded": False, "detection_version": _detection_version(),
              "detection_revision": None, "regex_detector_count": len(RegexClassifier().detectors),
              "presidio_version": _version("presidio-analyzer"), "spacy_version": _version("spacy"),
              "status": "disabled" if mode == "disabled" else "unverified" if available else
                        "unavailable" if mode == "required" else "degraded",
              "reason": ("" if mode == "disabled" else UNVERIFIED_REASON if available
                         else _unavailable_reason(model)),
              "requested_entities": [], "allow_list_terms": 0,
              "features": ["community_regex", "checksummed_identifiers", "clinical_context",
                           "nested_metadata", "batch_classification", "local_ner"]}
    if mode != "disabled" and not _model_installed(model) and (hint := install_hint(model)):
        status["install_command"] = hint
    # Which languages the name detectors can actually reach. Reported whether
    # or not any extra model is installed, because "English only" is a coverage
    # fact a reader has to be able to see without inferring it from silence.
    from vecshield.classify.presidio_classifier import resolve_extra_models

    extra = {lang: name for lang, name in resolve_extra_models().items()
             if _model_installed(name)}
    status["ner_languages"] = ["en"] + sorted(extra)
    status["ner_languages_available"] = dict(sorted(extra.items()))
    missing_extra = {lang: name for lang, name in resolve_extra_models().items()
                     if lang not in extra}
    if missing_extra and mode != "disabled":
        status["ner_models_missing"] = dict(sorted(missing_extra.items()))
        status["extras_install_command"] = "vecshield-platform nlp install --extras"
    status["ner_language_note"] = (
        "Regex detectors are language-independent. Named entities -- people, "
        "locations, organisations -- are found only for the languages listed, "
        "and a collection largely written in another one reports reduced "
        "coverage rather than a clean pass.")
    # Both packages ship from one distribution, so the revision that matters is
    # the one this build was made from, when the install records it.
    try:
        dist = metadata.distribution("vecshield")
        origin = json.loads(dist.read_text("direct_url.json") or "{}")
        status["detection_revision"] = origin.get("vcs_info", {}).get("commit_id")
    except (metadata.PackageNotFoundError, ValueError):
        pass
    if mode != "disabled":
        try:
            entities, allow_list = nlp_settings()
            status["requested_entities"] = entities
            status["allow_list_terms"] = len(allow_list)
        except DetectionConfigurationError as exc:
            # A load would raise the same error; say so now.
            status.update(status="unavailable", nlp_available=False,
                          reason=f"NLP configuration is invalid: {exc}")
            return status
    key = (mode, model)
    with _state_lock:
        classifier = _loaded.get(key)
        loading = key in _loading or key in _warmups
        failure = _failed.get(key)
    if classifier is not None:
        status.update(classifier.detection_metadata())
    elif loading and available:
        status.update(status="loading", reason=LOADING_REASON)
    elif failure and available:
        # Installed, tried, and failed: "unverified" would invite a retry the
        # last attempt already answered.
        status.update(status="unavailable" if mode == "required" else "degraded",
                      reason=failure)
    return status
