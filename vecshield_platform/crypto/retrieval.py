"""Opt-in retrieval exposure probe.

At-rest and field encryption describe what an attacker with the disk or the
database files could read. A RAG deployment has a second, more ordinary reader:
any client holding a query credential. Whatever the store hands back from a
similarity search is what the application, and anyone who can impersonate it,
will see — regardless of how the pages are encrypted underneath.

This probe measures that path empirically, the way
:func:`vecshield_platform.access.isolation.probe_isolation` measures tenant
bleed. It needs no embedding model: it replays vectors already stored in the
collection through ``connector.query()`` and classifies what comes back.

  1. stream up to ``max_chunks`` chunks and classify each one;
  2. pick a deterministic sample — mostly chunks the classifier marks
     sensitive, a few that it does not — so reruns over an unchanged store
     replay the same probes and their results are comparable;
  3. replay each sample's stored vector and classify every returned hit's text
     and metadata surfaces;
  4. count the distinct returned chunks that carried a sensitive value, and
     whether each carried it in plaintext or in a protected representation
     (masked, truncated, pseudonymous, hash-shaped). Neighbouring probes often
     return the same chunk; counting it once keeps the numbers about the data,
     not about how the sample happened to overlap. ``hits`` keeps the raw
     occurrence total alongside.

The probe is read-only: it calls only ``iter_chunks`` and ``query``. Evidence
holds counts and masked previews, never raw values or hit ids (ids are
sometimes derived from document names or e-mail addresses).

A plaintext result is an exposure to an *authenticated retrieval client*. It is
not evidence that the data is unencrypted on disk, and the finding says so.
"""

from __future__ import annotations

import hashlib
import heapq
import uuid
from datetime import datetime, timezone
from typing import Optional

from vecshield.classify.base import Classifier
from vecshield.classify.surfaces import chunk_text_surfaces, classify_chunk
from vecshield.models import Chunk, Finding, QueryHit, ScanJob, Severity
from vecshield_platform.connectors.base import Connector, UnsupportedCapability
from vecshield_platform.coverage import set_job_coverage
from vecshield_platform.detection import nlp_coverage_gap
from vecshield_platform.crypto.representation import (
    PROTECTED_CLASSES as _REPRESENTATION_PROTECTED,
)
from vecshield_platform.crypto.representation import classify_representation
from vecshield_platform.crypto.states import (
    NOT_APPLICABLE,
    NOT_OBSERVABLE,
    NOT_VERIFIED,
    OBSERVED_EXPOSURE,
    PROTECTED_REPRESENTATION,
    RETRIEVAL_EXPOSURE,
    crypto_outcome,
)

#: Representation classes that keep the underlying value from being read back
#: in full. Shared with the data_representation check.
PROTECTED_CLASSES = _REPRESENTATION_PROTECTED

#: Share of the probe budget reserved for chunks the classifier does not flag.
#: Unflagged chunks can still sit near sensitive ones in embedding space, and
#: those neighbours are exactly what a retrieval client would receive.
_UNFLAGGED_SHARE = 4

_MAX_PREVIEWS = 5

#: Context that does not fit a one-sentence reason; it travels in ``note``.
_CAVEAT = ("Sampled probes are not proof of what retrieval can or cannot return. "
           "Plaintext here is readable by an authenticated retrieval client; it "
           "does not mean the data is unencrypted on disk.")


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")

# ---- Representation of a returned sensitive value ------------------------

def representation_class(value: str, *, key: Optional[str] = None,
                         key_context: bool = False) -> str:
    """Classify how a detected sensitive value is represented.

    Delegates to the data_representation classifier so a returned hit and a
    stored record are judged by the same rules. ``key_context`` marks a value
    that a detector recognised only on the ``key: value`` surface — the key
    made it sensitive, so the value's own shape decides its representation.
    """
    return classify_representation(value, key=key, detected=not key_context,
                                   key_context=key_context)


def _span_value(surface_name: str, surface_text: str, span: dict) -> str:
    """The detected value itself, stripped of a key-aware surface's key."""
    start, end = span.get("start"), span.get("end")
    if not isinstance(start, int) or not isinstance(end, int):
        return ""
    value = surface_text[start:end]
    if surface_name.startswith("metadata_key.") and ": " in value:
        # Key-aware surfaces read "customer_id: <value>"; the key is not data.
        value = value.split(": ", 1)[1]
    return value


def _classify_hit(classifier: Classifier, collection: str, hit: QueryHit) -> list[dict]:
    """Classified sensitive spans of one returned hit, with representation.

    Each surface is classified separately (as ``classify_chunk`` does) so the
    span offsets can be resolved against the surface they came from. Only
    masked previews leave this function.
    """
    chunk = Chunk(id=str(hit.id), collection=collection, text=hit.text,
                  metadata=dict(hit.metadata or {}))
    spans: list[dict] = []
    for surface in chunk_text_surfaces(chunk):
        result = classifier.classify(surface.text)
        if not result.is_sensitive:
            continue
        for span in result.spans:
            value = _span_value(surface.name, surface.text, span)
            spans.append({
                "surface": surface.name.split(".", 1)[0],
                "label": span.get("label") or result.label.value,
                "detector": span.get("detector", ""),
                "representation": (_hit_representation(surface.name, value)
                                   if value else "plaintext"),
                "preview": span.get("preview", ""),
            })
    return spans


def _hit_representation(surface_name: str, value: str) -> str:
    kind, _, path = surface_name.partition(".")
    return representation_class(value, key=path or None,
                                key_context=kind == "metadata_key")


# ---- Deterministic sampling ----------------------------------------------

def _sample_rank(chunk_id: str) -> int:
    """Order-independent rank so the same ids are chosen on every run."""
    return int(hashlib.sha256(chunk_id.encode("utf-8")).hexdigest()[:16], 16)


def _keep_lowest(heap: list, limit: int, chunk_id: str, vector: list[float]) -> None:
    """Keep the ``limit`` lowest-ranked chunks in a bounded heap.

    Streaming keeps memory proportional to the sample, not the collection.
    Entries are ``(-rank, id, vector)`` so the heap root is the worst kept one.
    """
    if limit <= 0:
        return
    entry = (-_sample_rank(chunk_id), chunk_id, vector)
    if len(heap) < limit:
        heapq.heappush(heap, entry)
    elif entry[:2] > heap[0][:2]:
        heapq.heapreplace(heap, entry)


def _ordered(heap: list) -> list[tuple[str, list[float]]]:
    return [(cid, vec) for _, cid, vec in sorted(heap, key=lambda e: (-e[0], e[1]))]


# ---- The probe ------------------------------------------------------------

def probe_retrieval_exposure(
    connector: Connector,
    collection: str,
    *,
    classifier: Classifier,
    samples: int = 20,
    top_k: int = 5,
    max_chunks: int = 5000,
) -> ScanJob:
    """Replay stored vectors and report what retrieval returns in readable form.

    Returns one ScanJob whose ``stats.check_outcomes`` holds a single
    ``retrieval_exposure`` outcome for ``collection``. A connector that cannot
    query or enumerate content yields ``not_observable`` — a coverage gap,
    never a failure.
    """
    store = connector.describe()
    job = ScanJob(id=f"rex-{uuid.uuid4().hex[:12]}", store=store.name)
    counts = {"probes": 0, "top_k": top_k, "hits": 0, "distinct_hits": 0,
              "returned_sensitive": 0, "returned_plaintext": 0,
              "returned_protected": 0}
    job.stats = {"check": RETRIEVAL_EXPOSURE, "collection": collection, **counts,
                 "chunks_examined": 0}

    # Returned hits are classified with the same classifier: without NLP,
    # names in what retrieval hands back are not examined either.
    nlp_status, nlp_gap = nlp_coverage_gap(classifier)

    def finish(state: str, reason: str, *, outcome: Optional[str] = None,
               **details) -> ScanJob:
        job.stats.update(details)
        if nlp_status:
            reason = f"{reason} {nlp_gap}"
            details = {**details, "nlp_status": nlp_status}
        set_job_coverage(job, [crypto_outcome(
            RETRIEVAL_EXPOSURE, store.name, collection, state=state, reason=reason,
            outcome=outcome, complete=False, sampled=True, limit=max_chunks,
            chunks_scanned=job.stats["chunks_examined"],
            **{key: job.stats[key] for key in counts}, **details)])
        job.finished_at = datetime.now(timezone.utc)
        return job

    if "query" not in connector.capabilities():
        job.stats["skipped"] = True
        return finish(NOT_OBSERVABLE, f"{connector.kind} does not support vector "
                      "query(), so retrieval cannot be observed.")
    if not getattr(connector, "content_enumerable", True):
        job.stats["skipped"] = True
        return finish(NOT_OBSERVABLE, "This store exposes inventory only, so no "
                      "stored vectors can be replayed.")

    # Pass 1: classify stored chunks and keep a deterministic sample of each kind.
    samples = max(samples, 0)
    flagged_budget = samples - samples // _UNFLAGGED_SHARE
    flagged: list = []
    unflagged: list = []
    scanned = without_vector = 0
    for chunk in connector.iter_chunks(collection):
        if scanned >= max_chunks:
            break
        scanned += 1
        if not chunk.embedding:
            without_vector += 1
            continue
        heap = flagged if classify_chunk(classifier, chunk).is_sensitive else unflagged
        _keep_lowest(heap, samples, str(chunk.id), list(chunk.embedding))
    job.stats["chunks_examined"] = scanned
    limit_reached = scanned >= max_chunks

    # Flagged chunks take their share first; either side backfills the other.
    flagged_ids = _ordered(flagged)
    unflagged_ids = _ordered(unflagged)
    sensitive_probes = min(len(flagged_ids),
                           max(flagged_budget, samples - len(unflagged_ids)))
    chosen = flagged_ids[:sensitive_probes] + unflagged_ids[:samples - sensitive_probes]

    if not chosen:
        if scanned and without_vector == scanned:
            return finish(NOT_OBSERVABLE, "The connector does not return stored "
                          "vectors, so no probe could be replayed.",
                          limit_reached=limit_reached)
        return finish(NOT_APPLICABLE, "The collection holds no stored vectors to "
                      "replay.", limit_reached=limit_reached)

    # Pass 2: replay each sample and classify what retrieval hands back.
    # Keyed by hit id: a chunk is plaintext if any occurrence carried plaintext.
    returned: dict[str, bool] = {}
    seen: set[str] = set()
    previews: list[dict] = []
    query_errors = 0
    for _, vector in chosen:
        try:
            hits = connector.query(collection, vector, top_k=top_k)
        except UnsupportedCapability:
            return finish(NOT_OBSERVABLE, f"{connector.kind} rejected vector "
                          "query(), so retrieval cannot be observed.",
                          limit_reached=limit_reached)
        except Exception:  # noqa: BLE001 — recorded as a count, never the message
            # Exception text can carry endpoints or payload fragments.
            query_errors += 1
            continue
        counts["probes"] += 1
        for rank, hit in enumerate(hits[:top_k], start=1):
            counts["hits"] += 1
            hit_id = str(hit.id)
            seen.add(hit_id)
            spans = _classify_hit(classifier, collection, hit)
            if not spans:
                continue
            plaintext = [s for s in spans if s["representation"] not in PROTECTED_CLASSES]
            returned[hit_id] = returned.get(hit_id, False) or bool(plaintext)
            for span in (plaintext or spans):
                if len(previews) < _MAX_PREVIEWS:
                    previews.append({**span, "rank": rank})
    counts["distinct_hits"] = len(seen)
    counts["returned_sensitive"] = len(returned)
    counts["returned_plaintext"] = sum(returned.values())
    counts["returned_protected"] = len(returned) - counts["returned_plaintext"]
    job.stats.update(counts)

    details = {"sensitive_probes": sensitive_probes, "query_errors": query_errors,
               "limit_reached": limit_reached}
    if not counts["probes"]:
        return finish(NOT_VERIFIED, "Every retrieval probe failed, so returned "
                      "content could not be observed.", outcome="error", **details)
    details["note"] = " ".join(filter(None, (
        f"Replayed {counts['probes']} of {_plural(len(chosen), 'sampled stored vector')} "
        f"({sensitive_probes} from chunks classified sensitive) at top_k={top_k}, "
        f"returning {_plural(counts['hits'], 'hit')} across "
        f"{_plural(counts['distinct_hits'], 'distinct chunk')}.",
        f"{query_errors} of {len(chosen)} probes failed." if query_errors else "",
        _CAVEAT)))

    plain, sensitive = counts["returned_plaintext"], counts["returned_sensitive"]
    distinct = counts["distinct_hits"]
    if plain:
        job.add(_exposure_finding(store.name, collection, counts, previews))
        return finish(OBSERVED_EXPOSURE,
                      f"{plain} of {_plural(distinct, 'returned chunk')} exposed "
                      "plaintext sensitive data to a retrieval client.",
                      outcome="inconclusive", examples=previews, **details)
    if sensitive:
        subject = ("The 1 sensitive returned chunk was" if sensitive == 1 else
                   f"All {sensitive} sensitive returned chunks were")
        return finish(PROTECTED_REPRESENTATION,
                      f"{subject} in a protected representation.",
                      examples=previews, **details)
    return finish(NOT_APPLICABLE, f"{_plural(counts['probes'], 'probe')} returned no "
                  "detected sensitive data.", **details)


def _exposure_finding(store: str, collection: str, counts: dict,
                      previews: list[dict]) -> Finding:
    return Finding(
        id=f"find-{uuid.uuid4().hex[:10]}",
        title=f"Sensitive plaintext returned by retrieval in '{collection}'",
        severity=Severity.MEDIUM,
        category=RETRIEVAL_EXPOSURE,
        store=store,
        collection=collection,
        description=(
            f"{counts['returned_plaintext']} of {counts['distinct_hits']} distinct "
            f"chunks returned by {counts['probes']} sampled similarity queries carried "
            "sensitive values in plaintext. They are readable by an authenticated retrieval client — "
            "the application and anyone holding its query credential. This says "
            "nothing about storage encryption: it does not mean the data is "
            "unencrypted on disk."
        ),
        evidence={"probes": counts["probes"], "top_k": counts["top_k"],
                  "hits": counts["hits"], "distinct_hits": counts["distinct_hits"],
                  "returned_sensitive": counts["returned_sensitive"],
                  "returned_plaintext": counts["returned_plaintext"],
                  "returned_protected": counts["returned_protected"],
                  "examples": previews},
        remediation=(
            "Mask, tokenize or pseudonymize sensitive values before ingestion, "
            "limit the payload fields returned by queries, or apply field-level "
            "encryption so retrieval clients receive only what they need."
        ),
    )
