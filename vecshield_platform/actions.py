"""Suggested and staged actions: proposing a change to a vector store.

This is the first part of the product that contemplates writing to customer
data on its own initiative. An erasure is a person discharging a rights request
they asked for; a remediation is the product acting on its own judgement, and a
wrong judgement destroys something that mattered. Every rule here exists
because of that difference.

**This module does not execute anything.** It suggests, it stages, and it
produces a diff to read. Execution arrives behind approval in a later phase,
and the absence of an execute path here is deliberate rather than unfinished.

Four things this module refuses to do quietly:

* **Suggest an irreversible action from an unmeasured detector.** A suggestion
  to delete data is a recommendation founded on a detector's judgement. Where
  the benchmark has not measured that detector, the suggestion is withheld and
  the reason is recorded. Reversible actions may rest on an unmeasured
  detector, and say so on their face.
* **Claim a plan covers a finding it only partly covers.** A classification
  finding counts every sensitive chunk it saw but retains only the first few
  chunk ids. A plan built from one therefore reaches a fraction of what the
  finding observed, and the plan states that fraction rather than implying it
  fixed the finding.
* **Stage against a store it has not looked at.** Staging resolves every target
  against the store as it is now. Ids that have gone are recorded as missing,
  not silently dropped, and the plan carries a fingerprint so a store that
  changes afterwards makes the plan stale rather than wrong.
* **Promise a capability a connector has not declared.** An action whose
  connector cannot perform it is blocked at staging, where a person is reading,
  rather than at execution, where one is not.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

from vecshield_platform.explain import CALIBRATED, CONFIDENCE_CLASSES

#: How much of a targeted chunk the diff shows. A reviewer has to see enough to
#: recognize what would be destroyed, and no more than that.
PREVIEW_CHARS = 160

#: Plans are frozen. A staged plan that has been through review is the thing
#: approved, so these are the only states it can hold in this phase.
PLAN_STATES = ("staged", "executing", "stale", "blocked", "withdrawn", "executed",
               "halted")


class ActionError(ValueError):
    """A suggestion or plan the module refuses to build, with the reason."""


@dataclass(frozen=True)
class ActionTemplate:
    """One kind of change that can be proposed against a store.

    ``reversible`` is a statement about the *store*, not about our intent. A
    connector that cannot restore what it removed makes the action
    irreversible however carefully it was approved.
    """

    kind: str
    title: str
    risk: str                       # low | medium | high
    reversible: bool
    capability: str                 # the connector capability it requires
    gate: str                       # what a person must do before it may run
    undo: str                       # how it is undone, or why it cannot be
    effect: str                     # what carrying it out actually changes
    #: The weakest confidence class a detector may hold and still motivate this
    #: action. "" means an unmeasured detector is acceptable. This is a per-action
    #: bar rather than a yes/no, because "the benchmark measured something" is a
    #: far weaker statement than "the benchmark measured it well enough to delete
    #: on": a detector at 'possible' has a precision floor of 0.50, which for an
    #: irreversible action means up to half the deletions could be wrong.
    requires_confidence: str = ""
    caveat: str = ""                # what it does *not* change, where that differs
    #: "chunks" needs resolved chunk targets to do anything; "collection" acts
    #: on the collection itself and has none by design. Without this, a
    #: collection-scoped operation looks like one whose targets all vanished.
    scope: str = "chunks"
    #: Capabilities needed beyond ``capability``. Moving a chunk to quarantine
    #: is a write *and* a delete; a connector that can do one and not the other
    #: would leave either a copy with no removal or a removal with no copy.
    also_requires: tuple[str, ...] = ()
    #: Values a person must supply at staging (a tenant to assign, say). They
    #: become part of the operation, so the approval covers the exact value.
    needs_params: tuple[str, ...] = ()
    #: How the result is checked after execution, in words a reviewer reads
    #: before approving. Every executable action has one.
    verification: str = ""


#: In ascending order of risk, which is also the order they are built in. The
#: reversible ones earn the trust the irreversible one needs.
ACTION_TEMPLATES: dict[str, ActionTemplate] = {
    # Writing the classification back onto the chunk is the only action here
    # that adds information rather than withdrawing content. It is what makes a
    # scan result outlive the scan: the customer's own retriever can filter on
    # it, a later DSAR can find it, and another tool can read it without asking
    # us. What it emphatically does not do is enforce anything — see caveat.
    "label_sensitivity": ActionTemplate(
        kind="label_sensitivity",
        title="Label chunks with what was found in them",
        risk="low",
        reversible=True,
        capability="metadata_write",
        gate="approval",
        undo="Remove the label fields. The chunk and its vector are untouched.",
        effect="Sets sensitivity, category, and provenance fields on each chunk's "
               "metadata, merged into whatever is already there.",
        caveat="A label does not restrict retrieval. Nothing filters on it unless "
               "the retrieving application chooses to, and this product does not "
               "control that application. It records what a scan observed; it "
               "does not act on it.",
        verification="Each chunk is read back and must carry the sensitivity label.",
    ),
    "tag_exclude": ActionTemplate(
        kind="tag_exclude",
        title="Tag chunks for exclusion from retrieval",
        risk="low",
        reversible=True,
        capability="metadata_write",
        gate="approval",
        undo="Remove the tag. The chunk and its vector are untouched.",
        effect="Sets a metadata field on each chunk.",
        caveat="The content and its vector stay in the store, and a retriever "
               "that does not filter on the field will keep returning them. "
               "This marks chunks for exclusion; it does not exclude them.",
        verification="Each chunk is read back and must carry the exclusion mark.",
    ),
    "quarantine_collection": ActionTemplate(
        kind="quarantine_collection",
        title="Quarantine a collection from retrieval",
        risk="medium",
        reversible=True,
        capability="collection_metadata_write",
        gate="approval",
        undo="Lift the quarantine. No content is altered.",
        scope="collection",
        effect="Sets a metadata field on the collection.",
        caveat="Nothing in the collection is altered or removed, and a retriever "
               "that does not check the field will keep querying it. This "
               "records a quarantine; it does not enforce one.",
        verification="The collection list is re-read and the collection must "
                     "report the quarantine mark.",
    ),
    # This was drafted as "re-embed after redaction". It is not that, and the
    # name was changed to say what it does. VecShield does not have the
    # customer's embedding model: asking the store to embed a replacement
    # would either fail on a locked-down deployment or, worse, succeed with the
    # store's default model and write a vector in a different space from every
    # neighbour it has. So this redacts the stored text, keeps the original,
    # and marks the chunk for the pipeline that owns the model. The vector is
    # untouched and still encodes what it encoded.
    "redact_text": ActionTemplate(
        kind="redact_text",
        title="Redact the matched spans in the stored text",
        risk="medium",
        reversible=True,
        capability="redact",
        # The original is copied aside with add_chunks() before its text is
        # replaced, so a store that can replace text but not add chunks (Qdrant)
        # would stage as supported and then halt at the copy.
        also_requires=("write",),
        gate="approval and a redaction preview",
        undo="Restore from the retained original, which is copied to a "
             "quarantine collection before the text is replaced and is never "
             "deleted by this action.",
        requires_confidence="possible",
        effect="Replaces the matched spans in the chunk's text with a redaction "
               "marker, copies the original to a quarantine collection, and marks "
               "the chunk as needing re-embedding.",
        caveat="The vector is not changed and still encodes the original text. "
               "Re-embedding needs the model the collection was built with, "
               "which this product does not have; the mark is for the pipeline "
               "that does. Metadata surfaces are not redacted. Anything already "
               "retrieved is not recalled.",
        verification="Each chunk is read back: it must hold the approved text and "
                     "the classifier must find nothing left in it.",
    ),
    "delete_chunks": ActionTemplate(
        kind="delete_chunks",
        title="Delete chunks",
        risk="high",
        reversible=False,
        capability="delete",
        gate="approval, and the store id typed by the approver",
        undo="It cannot be undone. The store offers no restore path through "
             "this connector.",
        requires_confidence="likely",
        effect="Removes the chunks and their vectors from the store.",
        caveat="Backups, replicas and downstream copies are outside this "
               "store and are not touched.",
        verification="The collection is read through and must no longer return "
                     "the chunks.",
    ),
    # ---- Remediations for findings that are not about classified content --- #
    # Each answers a specific finding kind (see remediation.py). They share the
    # same staging, approval, execution and verification path as the actions
    # above; nothing here is a side door.
    "tag_review": ActionTemplate(
        kind="tag_review",
        title="Flag chunks for human review",
        risk="low",
        reversible=True,
        capability="metadata_write",
        gate="approval",
        undo="Remove the review field. The chunk and its vector are untouched.",
        effect="Sets a vecshield_review field on each chunk naming why it was "
               "flagged, merged into its existing metadata.",
        caveat="A flag does not restrict retrieval. It records that a person "
               "should look; nothing filters on it unless the retrieving "
               "application does.",
        verification="Each chunk is read back and must carry the exact review value.",
    ),
    "tag_provenance": ActionTemplate(
        kind="tag_provenance",
        title="Tag chunks whose provenance is unverified",
        risk="low",
        reversible=True,
        capability="metadata_write",
        gate="approval",
        undo="Remove the provenance field. The chunk and its vector are untouched.",
        effect="Sets vecshield_provenance on each chunk the plan names, so the "
               "untraceable ones can be filtered, audited or re-ingested.",
        caveat="Tagging does not supply the missing source. It makes the gap "
               "visible where the data lives; recording a source at ingestion "
               "is what closes it.",
        verification="Each chunk is read back and must carry the provenance tag.",
    ),
    "assign_tenant": ActionTemplate(
        kind="assign_tenant",
        title="Assign a tenant to chunks that have none",
        risk="medium",
        reversible=True,
        capability="metadata_write",
        gate="approval; the tenant value is part of what is approved",
        needs_params=("tenant_value",),
        undo="Remove the tenant field from the chunks the plan names. They had "
             "none before, so removing it restores them exactly.",
        effect="Writes the tenant field, with the value the stager supplied, onto "
               "every chunk that carries no tenant value.",
        caveat="Every targeted chunk receives the same tenant. If they belong to "
               "different tenants, a wrong value exposes them to that tenant's "
               "filtered queries: stage one plan per owner over the chunk ids "
               "instead. Unfiltered queries still return them either way.",
        verification="Each chunk is read back and must carry the approved tenant "
                     "value; re-running the isolation check should then count "
                     "no untagged chunks.",
    ),
    "quarantine_chunks": ActionTemplate(
        kind="quarantine_chunks",
        title="Move chunks to a quarantine collection",
        risk="medium",
        reversible=True,
        capability="write",
        also_requires=("delete",),
        gate="approval",
        undo="Copy each chunk back from vecshield_quarantine, where it is kept "
             "with its text, vector and metadata unchanged under an id that names "
             "the plan.",
        effect="Copies each chunk, vector and metadata included, into the "
               "vecshield_quarantine collection, confirms the copy, and only then "
               "removes the chunk from its own collection.",
        caveat="The chunk is still in this store, in the quarantine collection: "
               "a retriever that queries every collection will still find it. "
               "Anything already retrieved is not recalled.",
        verification="The source collection is read back and must no longer "
                     "return the chunk, and the quarantine collection must hold "
                     "an identical copy.",
    ),
    "split_by_tenant": ActionTemplate(
        kind="split_by_tenant",
        title="Copy each tenant's chunks into a collection of its own",
        risk="medium",
        reversible=True,
        capability="write",
        also_requires=("collection_create",),
        gate="approval",
        undo="Delete the per-tenant collections the plan created. The shared "
             "collection is not modified, so nothing else needs restoring.",
        effect="Creates one collection per tenant with the shared collection's "
               "index settings, and copies each tenant's chunks, vectors and "
               "metadata into it.",
        caveat="The shared collection is left exactly as it is, and still mixes "
               "tenants until the application is pointed at the per-tenant "
               "collections and the shared one is retired. This makes another "
               "copy of the data in the same store. Chunks with no tenant value "
               "are not copied anywhere.",
        verification="Each per-tenant collection is read back: every planned "
                     "chunk must be present, and no chunk of another tenant may be.",
    ),
}

#: What a detected label suggests, most conservative first. A label that maps to
#: nothing is not an oversight to be filled in with a guess; it means nobody has
#: decided what the right response is, and the suggestion is withheld.
LABEL_ACTIONS: dict[str, tuple[str, ...]] = {
    "SECRET": ("label_sensitivity", "tag_exclude", "redact_text", "delete_chunks"),
    "PCI": ("label_sensitivity", "tag_exclude", "redact_text", "delete_chunks"),
    "PHI": ("label_sensitivity", "tag_exclude", "redact_text"),
    "PII": ("label_sensitivity", "tag_exclude", "redact_text"),
    "INJECTION": ("label_sensitivity", "tag_exclude", "delete_chunks"),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(payload: Any) -> str:
    """A stable hash over a structure, so two equal plans hash equally."""
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def content_hash(chunk: Any) -> str:
    """What a target's staleness is judged on: its text and metadata, hashed.

    One implementation, used when a plan is staged, when it is checked for
    staleness, and by execution immediately before it writes.
    """
    return _digest({"text": chunk.text, "metadata": chunk.metadata})


def hash_body(body: dict) -> str:
    """The plan hash, computed from a plan's serialized form.

    One implementation, used to stamp a plan and to check one read back. Two
    would eventually disagree, and the check would then pass on a plan that had
    been altered — which is the only thing this hash is for.

    Deliberately over the operations, the store and the fingerprint, and not
    over the id, the time, the note or the state: those may be annotated
    without changing what the plan would do.
    """
    return _digest({
        "store": body.get("store"),
        "fingerprint": body.get("store_fingerprint"),
        "operations": body.get("operations"),
    })


def verify_body(body: dict) -> bool:
    """Whether a plan still hashes to the value recorded on it."""
    return bool(body.get("plan_hash")) and hash_body(body) == body.get("plan_hash")


# --------------------------------------------------------------------------- #
# Suggest                                                                      #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Suggestion:
    """A proposal. It is not an action, and nothing about it is committed.

    ``rests_on`` names the detectors whose judgement this proposal depends on,
    and ``calibrated`` says whether the benchmark has measured them. A
    suggestion that rests on an unmeasured detector is still shown — withholding
    it entirely would hide a real observation — but it is never allowed to
    motivate something irreversible.
    """

    id: str
    action: str
    finding_id: str
    store: str
    collection: Optional[str]
    chunk_ids: tuple[str, ...]
    rests_on: tuple[str, ...]
    calibrated: bool
    rationale: str
    observed_chunks: int          # what the finding counted
    named_chunks: int             # how many ids it actually retained
    #: The classified labels this proposal answers, in the finding's own terms.
    #: Carried because label_sensitivity writes them back; every other action
    #: only reads them for its rationale.
    labels: tuple[str, ...] = ()
    #: Chunks the finding named that this action may *not* reach, with the
    #: detector and class that held each back. A gated action is gated per
    #: chunk: a chunk resting on a measured detector is not held back by its
    #: neighbour's unmeasured one, and a chunk that is held back is listed
    #: here rather than silently dropped from ``chunk_ids``.
    excluded: tuple[tuple[str, str], ...] = ()
    #: For findings that describe a condition rather than name chunks ("412
    #: chunks carry no tenant_id"), the condition itself. Staging resolves it
    #: against the store as it is then, and the plan records the ids it found,
    #: so what is approved is still a concrete list.
    selector: Optional[dict] = None
    #: Values the action needs beyond its targets: the review reason, the
    #: tenant to assign, the tenant field. Frozen into the operation and so
    #: covered by the plan hash.
    params: dict = field(default_factory=dict)
    #: The finding kind this proposal answers (see remediation.finding_kind).
    kind: str = ""
    #: What the proposal rests on when it is not a detector's judgement:
    #: "condition" (a metadata condition re-evaluated against the store at
    #: staging), "check" (a deterministic probe such as the isolation check),
    #: or "statistical" (an outlier score). Empty means detectors, as before.
    basis: str = ""

    @property
    def template(self) -> ActionTemplate:
        return ACTION_TEMPLATES[self.action]

    def to_dict(self) -> dict:
        template = self.template
        record = {
            "id": self.id,
            "action": self.action,
            "title": template.title,
            "risk": template.risk,
            "reversible": template.reversible,
            "undo": template.undo,
            "gate": template.gate,
            "effect": template.effect,
            "caveat": template.caveat,
            "finding_id": self.finding_id,
            "store": self.store,
            "collection": self.collection,
            "chunk_ids": list(self.chunk_ids),
            "rests_on": list(self.rests_on),
            "calibrated": self.calibrated,
            "rationale": self.rationale,
            "observed_chunks": self.observed_chunks,
            "named_chunks": self.named_chunks,
            # A selector reaches every chunk that meets its condition when the
            # plan is staged, which is what the finding counted; the staged
            # plan states the number it actually found, and a cap if it hit one.
            "reaches_all_observed": (True if self.selector else
                                     len(self.chunk_ids) >= self.observed_chunks
                                     and not self.excluded),
            "excluded": [{"chunk_id": cid, "reason": why} for cid, why in self.excluded],
            "labels": list(self.labels),
            "mode": "executable",
            "capability": template.capability,
            "also_requires": list(template.also_requires),
            "needs_params": list(template.needs_params),
            "verification": template.verification,
            "scope": template.scope,
        }
        if self.selector:
            record["selector"] = dict(self.selector)
            record["selector_text"] = describe_selector(self.selector)
        if self.params:
            record["params"] = dict(self.params)
        if self.kind:
            record["kind"] = self.kind
        if self.basis:
            record["basis"] = self.basis
        return record


@dataclass(frozen=True)
class Withheld:
    """A suggestion that was not made, and why it was not made.

    Returned alongside the suggestions rather than dropped. A reader who sees
    three proposals for a finding that could have had five is entitled to know
    what happened to the other two.
    """

    action: str
    finding_id: str
    reason: str

    def to_dict(self) -> dict:
        return {"action": self.action, "finding_id": self.finding_id,
                "reason": self.reason,
                "title": ACTION_TEMPLATES[self.action].title
                if self.action in ACTION_TEMPLATES else self.action}


def detectors_in(finding: dict) -> tuple[str, ...]:
    """Every detector named by a finding's explanations, deduplicated."""
    evidence = finding.get("evidence") or {}
    names: list[str] = []
    for explanation in evidence.get("explanations") or []:
        if isinstance(explanation, dict) and explanation.get("detector"):
            names.append(str(explanation["detector"]))
    for example in evidence.get("examples") or []:
        if isinstance(example, dict):
            names.extend(str(d) for d in example.get("detectors") or [])
            # Injection examples name the categories that matched, which are
            # the detector names the benchmark calibrates.
            names.extend(str(d) for d in example.get("categories") or [])
    return tuple(sorted(set(names)))


def _labels_in(finding: dict) -> tuple[str, ...]:
    """The classified labels a finding carries, as the scan engine writes them.

    Reads ``label_counts``, which is what the classification scan emits, as
    well as ``labels``. The first version read only ``labels`` — a key the
    engine never writes — and was rescued by the per-example ``label`` field
    by luck. An injection finding has no labels dict at all; it is recognised
    by its category and title, which is what ``INJECTION`` in the action map
    was always meant to be keyed on and was never wired to.
    """
    evidence = finding.get("evidence") or {}
    labels = [str(k).upper() for source in ("label_counts", "labels")
              for k in (evidence.get(source) or {})]
    for example in evidence.get("examples") or []:
        if isinstance(example, dict) and example.get("label"):
            labels.append(str(example["label"]).upper())
    if _is_injection(finding):
        labels.append("INJECTION")
    return tuple(sorted(set(labels)))


def _is_injection(finding: dict) -> bool:
    if str(finding.get("category") or "").lower() != "rag_integrity":
        return False
    title = str(finding.get("title") or "").lower()
    evidence = finding.get("evidence") or {}
    return "injection" in title or any(
        isinstance(e, dict) and e.get("categories") for e in evidence.get("examples") or [])


#: Counter-signals that say the *value* is not a live one — a key the vendor
#: prints in its documentation, a test-mode prefix, a placeholder, a domain
#: reserved for examples. These argue against acting at all. The other two
#: signals the explainer emits (`quoted_in_text`, `non_production_scope`) are
#: about context, are weaker, and are shown but do not hold a chunk back:
#: Terraform quotes every value, and "sandbox" in a collection name is a hint.
DISPUTING_SIGNALS = frozenset({"published_example", "vendor_test_prefix",
                               "placeholder_token", "reserved_domain"})


def disputes_by_chunk(finding: dict) -> dict[str, tuple[str, ...]]:
    """Chunks on which *every* match is disputed by a value-level signal.

    Maps chunk id to the signal codes. A chunk with one undisputed match is
    not here: something real is on it. A chunk with no explanations at all is
    not here either — absence of a dispute is not evidence the value is live,
    and the gate must not invent one.
    """
    evidence = finding.get("evidence") or {}
    out: dict[str, tuple[str, ...]] = {}
    for example in evidence.get("examples") or []:
        if not isinstance(example, dict) or not example.get("chunk_id"):
            continue
        explanations = [e for e in example.get("explanations") or [] if isinstance(e, dict)]
        if not explanations:
            continue
        codes: list[str] = []
        for explanation in explanations:
            signals = {str(c.get("code")) for c in explanation.get("counter_signals") or []
                       if isinstance(c, dict)} & DISPUTING_SIGNALS
            if not signals:
                break                      # an undisputed match: the chunk stands
            codes.extend(sorted(signals))
        else:
            out[str(example["chunk_id"])] = tuple(dict.fromkeys(codes))
    return out


def detectors_by_chunk(finding: dict) -> dict[str, tuple[str, ...]]:
    """The detectors that fired on each retained chunk, by chunk id.

    Read from the examples, which are per chunk, rather than from the
    finding's aggregate: the aggregate is what made a gate on one chunk depend
    on what fired in another.
    """
    evidence = finding.get("evidence") or {}
    out: dict[str, list[str]] = {}
    for example in evidence.get("examples") or []:
        if not isinstance(example, dict) or not example.get("chunk_id"):
            continue
        names = [str(d) for d in example.get("detectors") or []]
        names += [str(d) for d in example.get("categories") or []]
        names += [str(sp.get("detector")) for sp in example.get("spans") or []
                  if isinstance(sp, dict) and sp.get("detector")]
        out.setdefault(str(example["chunk_id"]), [])
        for name in names:
            if name not in out[str(example["chunk_id"])]:
                out[str(example["chunk_id"])].append(name)
    return {cid: tuple(names) for cid, names in out.items()}


def _chunk_ids_in(finding: dict) -> tuple[str, ...]:
    evidence = finding.get("evidence") or {}
    ids = [str(e["chunk_id"]) for e in evidence.get("examples") or []
           if isinstance(e, dict) and e.get("chunk_id")]
    return tuple(dict.fromkeys(ids))          # de-duplicate, keep scan order


def _observed_count(finding: dict, named: int) -> int:
    """How many chunks the finding says were sensitive.

    Falls back to the number of ids it retained. That is a floor, never an
    upper bound, and callers treat the difference as unknown rather than zero.
    """
    evidence = finding.get("evidence") or {}
    # ``sensitive`` is what the classification scan writes; ``count`` is what
    # the integrity scan writes for injections. The first version looked for
    # ``sensitive_chunks``, which nothing writes, so every real finding read
    # as fully covered and the "reaches N of M" warning never fired outside
    # the tests that had invented the key.
    for key in ("sensitive", "sensitive_chunks", "count", "matches", "affected_chunks"):
        value = evidence.get(key)
        if isinstance(value, int) and value >= 0:
            return max(value, named)
    return named


def suggest(finding: dict, *,
            include_disputed: bool = False) -> tuple[list[Suggestion], list[Withheld]]:
    """Propose actions for one finding, and record the ones refused.

    Returns ``(suggestions, withheld)``. Both matter: the second is how a
    reader learns that a delete was available in principle and refused on the
    evidence.

    A chunk on which every match is disputed — the value is a published
    example, a test-mode key, a placeholder, or on a reserved domain — is held
    back from chunk-scoped actions and listed with the signal, because acting
    on a documentation key is a wasted errand at best. ``include_disputed``
    is the reviewer's override, and is deliberately not the default.
    """
    finding_id = str(finding.get("id") or "")
    store = str(finding.get("store") or "")
    if not finding_id or not store:
        raise ActionError("a finding needs an id and a store before it can suggest anything")

    labels = _labels_in(finding)
    chunk_ids = _chunk_ids_in(finding)
    detectors = detectors_in(finding)
    per_chunk = detectors_by_chunk(finding)
    disputed = {} if include_disputed else disputes_by_chunk(finding)
    named = len(chunk_ids)
    observed = _observed_count(finding, named)

    kinds: list[str] = []
    for label in labels:
        for kind in LABEL_ACTIONS.get(label, ()):
            if kind not in kinds:
                kinds.append(kind)
    # Quarantine is the response to the gap, not to the label. Where a finding
    # saw more sensitive chunks than it retained ids for, no per-chunk action
    # can cover it, and the collection-level one is the only proposal that
    # honestly reaches what was observed.
    if finding.get("collection") and observed > named:
        kinds.append("quarantine_collection")

    suggestions: list[Suggestion] = []
    withheld: list[Withheld] = []

    if not labels:
        return [], [Withheld(action=kind, finding_id=finding_id,
                             reason="The finding names no classified label, so there "
                                    "is no established response to propose.")
                    for kind in ("tag_exclude",)]

    for kind in kinds:
        template = ACTION_TEMPLATES[kind]
        if template.kind == "quarantine_collection" and not finding.get("collection"):
            withheld.append(Withheld(kind, finding_id,
                                     "The finding is not scoped to a collection."))
            continue
        if template.kind != "quarantine_collection" and not chunk_ids:
            withheld.append(Withheld(
                kind, finding_id,
                "The finding retained no chunk ids, so there is nothing to target. "
                "Re-run the assessment with a higher example limit."))
            continue
        reach, excluded = gate_chunks(template, chunk_ids, per_chunk, detectors,
                                      disputed=disputed)
        if template.scope != "collection" and not reach:
            if not template.requires_confidence:
                withheld.append(Withheld(
                    kind, finding_id,
                    "Every match on every named chunk is disputed as not a live value "
                    f"({', '.join(sorted({c for cs in disputed.values() for c in cs}))}). "
                    "Nothing is proposed; a reviewer can include disputed chunks "
                    "explicitly."))
                continue
            withheld.append(Withheld(kind, finding_id,
                                     _confidence_reason(template, detectors,
                                                        _shortfall(excluded))))
            continue
        if template.scope == "collection":
            # A collection-level action has no per-chunk reach; it is gated on
            # the finding as a whole, as before.
            short = below_confidence(template, detectors)
            if short:
                withheld.append(Withheld(kind, finding_id,
                                         _confidence_reason(template, detectors, short)))
                continue
            reach, excluded = chunk_ids, ()
        rests_on = tuple(sorted({d for cid in reach for d in per_chunk.get(cid, ())}
                                or detectors))
        suggestions.append(Suggestion(
            id=f"sug-{uuid.uuid4().hex[:12]}",
            action=kind,
            finding_id=finding_id,
            store=store,
            collection=finding.get("collection"),
            chunk_ids=reach,
            rests_on=rests_on,
            calibrated=bool(rests_on) and all(d in CALIBRATED for d in rests_on),
            rationale=_rationale(template, labels, rests_on,
                                 bool(rests_on) and all(d in CALIBRATED for d in rests_on),
                                 observed=observed, named=named,
                                 excluded=len(excluded)),
            observed_chunks=observed,
            named_chunks=named,
            excluded=excluded,
            labels=tuple(sorted(labels)),
        ))
    return suggestions, withheld


def gate_chunks(template: ActionTemplate, chunk_ids: Iterable[str],
                per_chunk: dict[str, tuple[str, ...]], fallback: Iterable[str],
                *, disputed: Optional[dict[str, tuple[str, ...]]] = None
                ) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    """Which of a finding's chunks this action may reach, and which it may not.

    Two gates, applied per chunk. Confidence: judged on the detectors that
    fired on *this* chunk, falling back to the finding's aggregate for a chunk
    with no record, which is the conservative reading. Dispute: a chunk on
    which every match is disputed as not a live value is held back from any
    chunk-scoped action. Returns ``(reach, excluded)`` where each excluded
    entry carries the reason, so nothing is dropped without one.
    """
    disputed = disputed or {}
    reach: list[str] = []
    excluded: list[tuple[str, str]] = []
    for cid in chunk_ids:
        if cid in disputed:
            excluded.append((cid, "every match is disputed: " + ", ".join(disputed[cid])))
            continue
        if template.requires_confidence:
            own = per_chunk.get(cid) or tuple(fallback)
            short = below_confidence(template, own)
            if short:
                excluded.append((cid, "; ".join(f"{d} is '{held}'" for d, held in short)))
                continue
        reach.append(cid)
    return tuple(reach), tuple(excluded)


def _shortfall(excluded: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """Collapse per-chunk reasons back into (detector, class) pairs for a message."""
    seen: dict[str, str] = {}
    for _, reason in excluded:
        for part in reason.split("; "):
            if " is '" in part:
                detector, held = part.split(" is '", 1)
                seen.setdefault(detector.strip(), held.rstrip("'"))
    return list(seen.items())


def below_confidence(template: ActionTemplate,
                     detectors: Iterable[str]) -> list[tuple[str, str]]:
    """Detectors that do not meet this action's confidence bar, with what they hold.

    Returns ``[(detector, class)]``, empty when every detector clears the bar.
    A detector nobody has measured holds ``uncertain``, which clears nothing.
    """
    required = template.requires_confidence
    if not required:
        return []
    names = tuple(detectors)
    if not names:
        return [("(no detector named)", "uncertain")]
    short: list[tuple[str, str]] = []
    for detector in names:
        # CALIBRATED maps a detector to every class it may claim, so membership
        # of the required class is the whole test: a detector measured at
        # 'likely' may also claim 'possible', and one measured at 'possible'
        # may not claim 'likely'.
        permitted = CALIBRATED.get(detector, set())
        if required not in permitted:
            short.append((detector, held_class(detector)))
    return short


def held_class(detector: str) -> str:
    """The strongest class a detector has earned, or 'uncertain'."""
    permitted = CALIBRATED.get(detector, set())
    for candidate in CONFIDENCE_CLASSES:
        if candidate in permitted:
            return candidate
    return "uncertain"


def _confidence_reason(template: ActionTemplate, detectors: Iterable[str],
                       short: list[tuple[str, str]]) -> str:
    if not tuple(detectors):
        return (f"{template.title} needs a detector measured at "
                f"'{template.requires_confidence}', and this finding names none.")
    named = ", ".join(f"{d} is '{held}'" for d, held in short)
    severity = "irreversible" if not template.reversible else "high-impact"
    return (f"{template.title} is {severity} and needs every detector behind it "
            f"measured at '{template.requires_confidence}' or better. On the "
            f"benchmark, {named}. Growing the corpus is what changes this, not "
            "overriding it here.")


def _rationale(template: ActionTemplate, labels: Iterable[str],
               detectors: Iterable[str], calibrated: bool,
               observed: int = 0, named: int = 0, excluded: int = 0) -> str:
    what = "/".join(labels) or "sensitive content"
    who = ", ".join(detectors) or "an unnamed detector"
    held = (f" {excluded} of the {named} named chunk(s) are not reached by this "
            "action — held back by a confidence class it requires or because every "
            "match on them is disputed — and are listed on the proposal."
            if excluded else "")
    if template.kind == "quarantine_collection":
        return (f"The assessment saw {observed} chunk(s) of {what} here but retained "
                f"only {named} id(s), so no per-chunk action can cover this "
                "collection. Quarantining it is the only proposal that reaches "
                "what was observed.")
    basis = ("The detectors behind it have a measured precision."
             if calibrated else
             "The detectors behind it have no measured precision, so this rests on "
             "an unmeasured judgement and is limited to a reversible change.")
    return f"{what} was matched by {who}. {basis}{held}"


def suggest_all(findings: Iterable[dict], *,
                include_disputed: bool = False) -> tuple[list[Suggestion], list[Withheld]]:
    """Suggest across many findings, keeping every refusal."""
    suggestions: list[Suggestion] = []
    withheld: list[Withheld] = []
    for finding in findings:
        try:
            made, refused = suggest(finding, include_disputed=include_disputed)
        except ActionError as exc:
            withheld.append(Withheld("tag_exclude", str(finding.get("id") or "?"), str(exc)))
            continue
        suggestions.extend(made)
        withheld.extend(refused)
    return suggestions, withheld


# --------------------------------------------------------------------------- #
# Stage                                                                        #
# --------------------------------------------------------------------------- #

#: What a redacted span becomes. Short and unmistakable: a reader of the
#: redacted chunk should know something was removed, and what kind of thing.
REDACTION_MARK = "[REDACTED:{label}]"


def redact(text: str, spans: Iterable[dict]) -> tuple[str, list[dict]]:
    """Replace each span in ``text`` with a marker. Pure; never touches a store.

    Spans are ``{"start", "end", "label", "detector"}`` offsets into ``text``,
    as the classifier reports them. Overlapping spans are merged; an offset
    outside the text is dropped and reported rather than silently clipped, so
    a stale span cannot redact the wrong characters.
    """
    kept: list[tuple[int, int, str, str]] = []
    dropped: list[dict] = []
    for span in spans:
        start, end = span.get("start"), span.get("end")
        if (not isinstance(start, int) or not isinstance(end, int)
                or start < 0 or end > len(text) or end <= start):
            dropped.append({**span, "dropped": "offsets do not fit the current text"})
            continue
        kept.append((start, end, str(span.get("label") or "sensitive").lower(),
                     str(span.get("detector") or "")))
    kept.sort()
    merged: list[list] = []
    for start, end, label, detector in kept:
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
            if label not in merged[-1][2]:
                merged[-1][2] = f"{merged[-1][2]}+{label}"
            continue
        merged.append([start, end, label, detector])
    out: list[str] = []
    cursor = 0
    applied: list[dict] = []
    for start, end, label, detector in merged:
        out.append(text[cursor:start])
        out.append(REDACTION_MARK.format(label=label))
        applied.append({"start": start, "end": end, "label": label,
                        "detector": detector})
        cursor = end
    out.append(text[cursor:])
    return "".join(out), applied + dropped


@dataclass(frozen=True)
class TargetResolution:
    """What staging found when it went looking for one chunk.

    ``present`` has three values, and the third is the point. ``True`` and
    ``False`` are things we looked up; ``None`` means staging never checked,
    because the action was already blocked and reading the store for it would
    be pointless. Collapsing ``None`` into ``False`` would report a chunk as
    gone from the store on the strength of never having looked.
    """

    chunk_id: str
    collection: str
    present: Optional[bool]
    preview: str = ""
    content_hash: str = ""
    #: For a redaction: the text that would be written, computed against the
    #: chunk as it is now, and the spans that produce it. This is the
    #: "redaction preview" the action's gate names — a reviewer approves the
    #: exact replacement, not the idea of one.
    redacted_text: Optional[str] = None
    redaction_spans: tuple = ()
    #: The redacted text as a reviewer is shown it, masked like ``preview``.
    #: Computed once at resolution: masking classifies, and ``to_dict`` runs
    #: every time the plan is hashed.
    redacted_preview: str = ""

    @property
    def checked(self) -> bool:
        return self.present is not None

    def to_dict(self) -> dict:
        record = {"chunk_id": self.chunk_id, "collection": self.collection,
                  "present": self.present, "checked": self.checked,
                  "preview": self.preview, "content_hash": self.content_hash}
        if self.redacted_text is not None:
            record["redacted_preview"] = self.redacted_preview
            record["redacted_text"] = self.redacted_text
            record["redaction_spans"] = list(self.redaction_spans)
        return record


@dataclass(frozen=True)
class Operation:
    """One action against one collection, with its targets resolved."""

    action: str
    store: str
    collection: Optional[str]
    finding_id: str
    targets: tuple[TargetResolution, ...]
    supported: bool
    support_reason: str
    calibrated: bool
    observed_chunks: int
    named_chunks: int
    excluded: tuple[tuple[str, str], ...] = ()
    labels: tuple[str, ...] = ()
    #: The condition the targets were resolved from, when the finding named a
    #: condition rather than chunks, and what resolving it found.
    selector: Optional[dict] = None
    #: {"matched": n, "limit": n, "capped": bool} for a selector operation.
    selection: Optional[dict] = None
    params: dict = field(default_factory=dict)

    @property
    def template(self) -> ActionTemplate:
        return ACTION_TEMPLATES[self.action]

    @property
    def present(self) -> tuple[TargetResolution, ...]:
        return tuple(t for t in self.targets if t.present is True)

    @property
    def missing(self) -> tuple[TargetResolution, ...]:
        """Looked for and not found. Never includes the ones we did not check."""
        return tuple(t for t in self.targets if t.present is False)

    @property
    def unchecked(self) -> tuple[TargetResolution, ...]:
        return tuple(t for t in self.targets if t.present is None)

    @property
    def runnable(self) -> bool:
        """Supported, and with something left to act on.

        A collection-scoped operation has no chunk targets and is runnable on
        support alone; requiring targets of it would report it as blocked.
        """
        if not self.supported:
            return False
        return True if self.template.scope == "collection" else bool(self.present)

    def to_dict(self) -> dict:
        template = self.template
        return {
            "action": self.action,
            "title": template.title,
            "risk": template.risk,
            "reversible": template.reversible,
            "undo": template.undo,
            "gate": template.gate,
            "effect": template.effect,
            "caveat": template.caveat,
            "capability": template.capability,
            "store": self.store,
            "collection": self.collection,
            "finding_id": self.finding_id,
            "supported": self.supported,
            "support_reason": self.support_reason,
            "scope": template.scope,
            "runnable": self.runnable,
            "calibrated": self.calibrated,
            "targets": [t.to_dict() for t in self.targets],
            "resolved": len(self.present),
            "missing": len(self.missing),
            "unchecked": len(self.unchecked),
            "observed_chunks": self.observed_chunks,
            "named_chunks": self.named_chunks,
            "excluded": [{"chunk_id": cid, "reason": why} for cid, why in self.excluded],
            "labels": list(self.labels),
            "verification": template.verification,
            # Only when present: an operation that names its chunks directly
            # carries no empty selector or parameter placeholders.
            **({"selector": dict(self.selector),
                "selector_text": describe_selector(self.selector)} if self.selector else {}),
            **({"selection": dict(self.selection)} if self.selection else {}),
            **({"params": dict(self.params)} if self.params else {}),
        }


@dataclass(frozen=True)
class ActionPlan:
    """A frozen set of operations, hashed, with the world it was staged against.

    Immutable by construction: there is no method that changes an operation.
    Restaging produces a new plan with a new hash, which is what makes an
    approval scoped to a hash mean something.
    """

    id: str
    store: str
    staged_by: str
    staged_at: str
    operations: tuple[Operation, ...]
    store_fingerprint: str
    state: str = "staged"
    note: str = ""

    @property
    def plan_hash(self) -> str:
        return hash_body(self.to_dict())

    @property
    def executable(self) -> tuple[Operation, ...]:
        return tuple(op for op in self.operations if op.runnable)

    @property
    def irreversible(self) -> tuple[Operation, ...]:
        return tuple(op for op in self.executable if not op.template.reversible)

    def to_dict(self) -> dict:
        body = {
            "id": self.id,
            "store": self.store,
            "staged_by": self.staged_by,
            "staged_at": self.staged_at,
            "state": self.state,
            "note": self.note,
            "store_fingerprint": self.store_fingerprint,
            "operations": [op.to_dict() for op in self.operations],
            "blast_radius": blast_radius(self),
        }
        return {**body, "plan_hash": hash_body(body)}


def blast_radius(plan: ActionPlan) -> dict:
    """How far the plan reaches, and how far it does not.

    ``reaches_all_observed`` is the field that stops a plan reading as a fix.
    A finding that saw 300 sensitive chunks and retained 5 ids produces a plan
    over 5, and this says so.
    """
    collections = {op.collection for op in plan.executable if op.collection}
    resolved = sum(len(op.present) for op in plan.executable)
    # Counted once per finding, not once per operation. Two operations proposed
    # for the same finding are two ways of answering one observation, and adding
    # their counts would report twice as many sensitive chunks as were seen.
    #
    # Over every operation, not just the runnable ones: a blocked operation
    # reaches none of what its finding observed, and a plan where everything is
    # blocked must not report that it covers everything.
    per_finding: dict[str, int] = {}
    for op in plan.operations:
        key = op.finding_id or f"op:{id(op)}"
        per_finding[key] = max(per_finding.get(key, 0), op.observed_chunks)
    observed = sum(per_finding.values())
    return {
        "operations": len(plan.operations),
        "executable": len(plan.executable),
        "blocked": len(plan.operations) - len(plan.executable),
        "collections": sorted(collections),
        "chunks_targeted": resolved,
        "chunks_missing": sum(len(op.missing) for op in plan.operations),
        "chunks_unchecked": sum(len(op.unchecked) for op in plan.operations),
        "chunks_observed_by_findings": observed,
        "reaches_all_observed": observed <= resolved,
        "irreversible_operations": len(plan.irreversible),
        "irreversible_chunks": sum(len(op.present) for op in plan.irreversible),
    }


#: Shown in place of a preview when nothing could classify the text. A preview
#: that could not be masked is not shown at all.
PREVIEW_WITHHELD = "(preview withheld: the text could not be classified to mask it)"

#: How many of a selector's targets carry a preview. Masking classifies, a
#: selector may reach thousands of chunks, and the diff shows a sample of five.
MAX_PREVIEWED = 50


def _preview_classifier() -> Any:
    """The deployment's classifier for masking previews, or None if it cannot load."""
    try:
        from vecshield_platform.detection import build_classifier

        return build_classifier()
    except Exception:  # noqa: BLE001 — previews are then withheld, never raw
        return None


def _mask(text: Optional[str], classifier: Any = None) -> str:
    """A preview a reviewer can recognize without republishing the secret.

    Every value the classifier finds is masked over the whole text before the
    preview is cut, the way the chunk view masks it: a plan is stored whole and
    read by anyone who can read plans, and the reveal path is the only one
    that returns raw values. With no classifier the preview is withheld.
    """
    if not text:
        return ""
    if classifier is None:
        return PREVIEW_WITHHELD
    try:
        from vecshield_platform.reveal import mask_detected

        masked = mask_detected(text, classifier)
    except Exception:  # noqa: BLE001
        return PREVIEW_WITHHELD
    flat = " ".join(masked.split())
    return flat[:PREVIEW_CHARS] + ("…" if len(flat) > PREVIEW_CHARS else "")


def resolve_targets(connector: Any, collection: str, chunk_ids: Iterable[str],
                    *, with_redaction: bool = False,
                    classifier: Any = None,
                    previews: bool = True) -> tuple[TargetResolution, ...]:
    """Look up each chunk in the store as it is now.

    One pass over the collection rather than a lookup per id: connectors expose
    iteration, not random access, and a per-id scan would be quadratic.

    With ``with_redaction`` the classifier runs on each chunk's *current* text
    and the redaction is computed from those spans — not from the spans the
    finding recorded, which describe the chunk as it was when scanned.

    Previews are masked with the same classifier (see :func:`_mask`).
    ``previews=False`` skips them, for a caller that only compares hashes.

    On a store whose content cannot be enumerated (Bedrock KB, Vertex AI) the
    pass would yield nothing and every chunk would read as gone. Nothing was
    looked up there, so each target is returned unchecked (``present=None``).
    """
    wanted = list(dict.fromkeys(str(c) for c in chunk_ids))
    if not getattr(connector, "content_enumerable", True):
        return tuple(TargetResolution(cid, collection, present=None) for cid in wanted)
    found: dict[str, TargetResolution] = {}
    remaining = set(wanted)
    if remaining and with_redaction and classifier is None:
        from vecshield_platform.detection import build_classifier
        classifier = build_classifier()
    elif remaining and previews and classifier is None:
        classifier = _preview_classifier()
    if remaining:
        for chunk in connector.iter_chunks(collection):
            if chunk.id in remaining:
                redacted, spans = None, ()
                if with_redaction and chunk.text:
                    result = classifier.classify(chunk.text)
                    redacted, applied = redact(chunk.text, result.spans or [])
                    spans = tuple(applied)
                found[chunk.id] = TargetResolution(
                    chunk_id=chunk.id, collection=collection, present=True,
                    preview=_mask(chunk.text, classifier) if previews else "",
                    content_hash=content_hash(chunk),
                    redacted_text=redacted, redaction_spans=spans,
                    redacted_preview=(_mask(redacted, classifier)
                                      if redacted is not None else ""),
                )
                remaining.discard(chunk.id)
                if not remaining:
                    break
    return tuple(found.get(cid, TargetResolution(cid, collection, present=False))
                 for cid in wanted)


def store_fingerprint(connector: Any) -> str:
    """A cheap signature of the store's shape, for detecting drift.

    Collection names and counts only. It will not notice a chunk edited in
    place, which is why each target also carries its own content hash — the two
    together are what staleness is judged on.
    """
    try:
        shape = sorted((c.name, c.count) for c in connector.list_collections())
    except Exception as exc:                      # a store we cannot see is not a store we stage against
        raise ActionError(f"cannot fingerprint the store: {type(exc).__name__}: {exc}") from exc
    return _digest(shape)


#: The method each capability is a claim about. A capability set is a promise;
#: this is what checks the promise is backed by code, so a connector that
#: advertises something it has no method for is blocked at staging, where a
#: person is reading, rather than at execution, where one is not.
CAPABILITY_METHODS: dict[str, str] = {
    "delete": "delete_chunks",
    "write": "add_chunks",
    "redact": "replace_chunk_text",
    "metadata_write": "set_chunk_metadata",
    "collection_metadata_write": "set_collection_metadata",
    # Creating a collection with another's index settings (distance metric and
    # the rest), so a copy is searchable the way the original is.
    "collection_create": "create_collection_like",
    # Read-only crypto introspection. No action template needs these yet; they
    # are listed so a connector advertising one without implementing it fails
    # capability_verdict() like any other empty promise.
    "transport_introspection": "transport_session_info",
    "tls_enforcement_introspection": "tls_enforcement_info",
    "session_auth_introspection": "session_auth_info",
    "access_introspection": "access_model",
    "ann_iterative_scan": "query_iterative",
    "at_rest_introspection": "at_rest_encryption_state",
    "field_encryption_introspection": "field_encryption_config",
}


def capability_verdict(connector: Any, template: ActionTemplate) -> tuple[bool, str]:
    """Whether the connector has declared what this action needs *and can do it*.

    Checked at staging, where a person is reading the answer, rather than at
    execution, where the first sign of trouble would be a half-applied plan.
    Declaration alone is not enough: a connector advertising a capability it has
    no method for would stage as supported and fail on contact with the store.
    An action needing several capabilities needs every one of them.
    """
    try:
        declared = set(connector.capabilities())
    except Exception as exc:
        return False, f"The connector could not report its capabilities ({type(exc).__name__})."
    needed = (template.capability, *getattr(template, "also_requires", ()))
    for capability in needed:
        ok, reason = _one_capability(connector, declared, capability, template)
        if not ok:
            return False, reason
    names = "', '".join(needed)
    methods = ", ".join(f"{CAPABILITY_METHODS[c]}()" for c in needed)
    return True, f"The connector declares '{names}' and implements {methods}."


def unenumerable_reason(connector: Any, template: ActionTemplate) -> str:
    """Why a store whose content cannot be listed cannot take this action, or ''.

    Targets are looked up in the store, so an inventory-only store (Vertex,
    Bedrock) cannot take a chunk-level action even when it declares the
    capability. A whole-collection mark names no targets and is not affected.
    Shared by staging and the remediation view so the console does not offer as
    "VecShield does it" what staging will refuse.
    """
    if template.kind == "quarantine_collection" \
            or getattr(connector, "content_enumerable", True):
        return ""
    return ("Refused at staging: this store's content cannot be enumerated, so "
            "the targets cannot be looked up. Act on the backing store.")


def _one_capability(connector: Any, declared: set, capability: str,
                    template: ActionTemplate) -> tuple[bool, str]:
    if capability not in declared:
        return False, (f"The connector does not declare '{capability}', so it "
                       f"cannot be asked to {template.title.lower()}.")
    method_name = CAPABILITY_METHODS.get(capability)
    if method_name is None:
        return False, (f"'{capability}' has no method behind it in the connector "
                       "interface, so nothing could carry the action out.")
    method = getattr(connector, method_name, None)
    if not callable(method):
        return False, (f"The connector declares '{capability}' but has no "
                       f"{method_name}() to perform it. The declaration is not backed "
                       "by an implementation.")
    from vecshield_platform.connectors.base import Connector

    base = getattr(Connector, method_name, None)
    if base is not None and getattr(method, "__func__", method) is getattr(base, "__func__", base):
        return False, (f"The connector inherits the unimplemented {method_name}(), which "
                       "raises rather than acting. It cannot perform this.")
    return True, ""


# --------------------------------------------------------------------------- #
# Selectors: findings that name a condition rather than chunks                 #
# --------------------------------------------------------------------------- #

#: How many chunks one selector may resolve to. A plan is read by a person and
#: stored whole; past this the operation says it was capped rather than
#: silently reaching part of what the finding described.
MAX_SELECTED = 5000

#: The most per-tenant collections one split may create. Beyond this a split is
#: a migration, and belongs in the customer's own tooling.
MAX_SPLIT_TENANTS = 50

#: The reasons tag_review may write. A fixed vocabulary, because the value is
#: echoed back by the client at staging and must not become a way to write
#: arbitrary text into a customer's metadata.
REVIEW_REASONS = ("anomalous_embedding", "rare_source", "prompt_injection",
                  "protection_drift")
PROVENANCE_STATES = ("unverified", "unconfirmed_source")
REVIEW_KEY = "vecshield_review"
PROVENANCE_KEY = "vecshield_provenance"

_SELECTOR_MATCHES = ("missing_field", "has_field", "missing_all", "source_in")


def _blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def describe_selector(selector: dict) -> str:
    """The condition in words, for the proposal and the diff."""
    match = selector.get("match")
    if match == "missing_field":
        return f"every chunk with no '{selector.get('field')}' value"
    if match == "has_field":
        return f"every chunk that carries a '{selector.get('field')}' value"
    if match == "missing_all":
        return ("every chunk with none of "
                + ", ".join(f"'{f}'" for f in selector.get("fields") or []))
    if match == "source_in":
        values = [str(v) for v in selector.get("values") or []]
        shown = ", ".join(f"'{v}'" for v in values[:5])
        more = f" and {len(values) - 5} more" if len(values) > 5 else ""
        return f"every chunk whose source is {shown}{more}"
    return "an unrecognised condition"


def _source_value(metadata: dict, keys: Iterable[str]) -> Optional[str]:
    """The chunk's source as provenance analysis reads it: first key present."""
    for key in keys:
        value = metadata.get(key)
        if value:
            return str(value)
    return None


def _matches(selector: dict, metadata: dict) -> bool:
    match = selector.get("match")
    if match == "missing_field":
        return _blank(metadata.get(str(selector.get("field"))))
    if match == "has_field":
        return not _blank(metadata.get(str(selector.get("field"))))
    if match == "missing_all":
        return all(not metadata.get(str(f)) for f in selector.get("fields") or [])
    if match == "source_in":
        wanted = {str(v) for v in selector.get("values") or []}
        return _source_value(metadata, selector.get("keys") or ()) in wanted
    return False


def validate_selector(selector: Any) -> str:
    """Why a selector cannot be used, or "" when it can."""
    if not isinstance(selector, dict):
        return "the selector is not an object"
    match = selector.get("match")
    if match not in _SELECTOR_MATCHES:
        return f"unknown selector '{match}'"
    if match in ("missing_field", "has_field"):
        if not isinstance(selector.get("field"), str) or not selector["field"].strip():
            return "the selector names no field"
    if match == "missing_all":
        fields = selector.get("fields")
        if not fields or not all(isinstance(f, str) and f for f in fields):
            return "the selector names no fields"
    if match == "source_in":
        if not selector.get("values") or not selector.get("keys"):
            return "the selector names no sources"
    return ""


def resolve_selector(connector: Any, collection: str, selector: dict, *,
                     limit: int = MAX_SELECTED, value_field: Optional[str] = None,
                     classifier: Any = None
                     ) -> tuple[tuple[TargetResolution, ...], dict, dict[str, Any]]:
    """Every chunk in ``collection`` meeting ``selector``, as it is now.

    Returns ``(targets, selection, values)``. ``selection`` records how many
    matched and whether the limit stopped the pass; ``values`` maps each
    target to its ``value_field`` metadata value, for actions that route by it.
    One pass over the collection; the whole collection is read, because a
    condition cannot be answered for chunks nobody looked at.

    On a store whose content cannot be enumerated nothing is read, and
    ``selection["content_enumerable"]`` is False: zero matches there would
    mean "never looked", not "none meet the condition".
    """
    if not getattr(connector, "content_enumerable", True):
        return ((), {"matched": 0, "limit": limit, "capped": False, "reached": 0,
                     "content_enumerable": False}, {})
    targets: list[TargetResolution] = []
    values: dict[str, Any] = {}
    matched = 0
    capped = False
    loaded = classifier is not None
    for chunk in connector.iter_chunks(collection):
        metadata = chunk.metadata or {}
        if not _matches(selector, metadata):
            continue
        matched += 1
        if len(targets) >= limit:
            capped = True
            continue
        preview = ""
        if len(targets) < MAX_PREVIEWED:
            if not loaded:
                classifier, loaded = _preview_classifier(), True
            preview = _mask(chunk.text, classifier)
        targets.append(TargetResolution(
            chunk_id=chunk.id, collection=collection, present=True,
            preview=preview, content_hash=content_hash(chunk)))
        if value_field is not None:
            values[chunk.id] = metadata.get(value_field)
    return (tuple(targets),
            {"matched": matched, "limit": limit, "capped": capped,
             "reached": len(targets)},
            values)


_PARTITION_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_.")


def partition_name(collection: str, tenant: Any) -> str:
    """The per-tenant collection a split writes a tenant's chunks to."""
    slug = "".join(c if c in _PARTITION_CHARS else "-" for c in str(tenant).lower())
    slug = slug.strip("-_.")
    return f"{collection}__{slug}" if slug else ""


def _valid_collection_name(name: str) -> bool:
    """Conservative: what Chroma accepts, which most stores also accept."""
    return (3 <= len(name) <= 63 and name[0].isalnum() and name[-1].isalnum()
            and ".." not in name
            and all(c.isalnum() or c in "-_." for c in name))


def _stage_params(suggestion: Suggestion, *, tenant_field: Optional[str]
                  ) -> tuple[dict, str]:
    """Server-side parameters for an operation, and why they are refused if they are.

    The client echoes a suggestion back to be staged, so every value that ends
    up written to the store is recomputed or checked here rather than trusted:
    a review reason from a fixed vocabulary, a tenant field that must be the
    one this store is configured with, a tenant value of bounded shape.
    """
    kind = suggestion.action
    given = dict(suggestion.params or {})
    if kind == "tag_review":
        reason = given.get("reason")
        if reason not in REVIEW_REASONS:
            return {}, (f"a review flag needs a reason from {', '.join(REVIEW_REASONS)}; "
                        f"got {reason!r}")
        return {"reason": reason, "fields": {REVIEW_KEY: reason}}, ""
    if kind == "tag_provenance":
        status = given.get("status")
        if status not in PROVENANCE_STATES:
            return {}, (f"a provenance tag needs one of {', '.join(PROVENANCE_STATES)}; "
                        f"got {status!r}")
        return {"status": status, "fields": {PROVENANCE_KEY: status}}, ""
    if kind in ("assign_tenant", "split_by_tenant"):
        field_name = given.get("tenant_field")
        if not isinstance(field_name, str) or not field_name.strip():
            return {}, "the operation names no tenant field"
        if tenant_field and field_name != tenant_field:
            return {}, (f"the operation writes '{field_name}', but this store's tenant "
                        f"field is configured as '{tenant_field}'")
        if kind == "split_by_tenant":
            return {"tenant_field": field_name}, ""
        value = given.get("tenant_value")
        if not isinstance(value, str) or not value.strip():
            return {}, ("assigning a tenant needs the tenant value, supplied by the "
                        "person staging the plan")
        value = value.strip()
        if len(value) > 128 or any(ord(c) < 32 for c in value):
            return {}, "the tenant value must be printable and at most 128 characters"
        return {"tenant_field": field_name, "tenant_value": value,
                "fields": {field_name: value}}, ""
    # Every other action takes no parameters; whatever the client sent is not
    # carried into a plan where it could be mistaken for something approved.
    return {}, ""


def tenant_type(value: Any) -> str:
    """The type a tenant value is keyed on alongside its text: 'int' or 'str'.

    A store filters by value, and ``1`` and ``"1"`` are different values to it,
    so a split keys each partition on both the text and the type.
    """
    return "int" if isinstance(value, int) and not isinstance(value, bool) else "str"


def _plan_split(connector: Any, collection: str, params: dict,
                values: dict[str, Any]) -> tuple[dict, str]:
    """Which collection each tenant's chunks go to, or why they cannot."""
    tenants: dict[str, int] = {}
    types: dict[str, str] = {}
    for value in values.values():
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            return {}, "a tenant value is not a string or integer, so it cannot name a collection"
        key, kind = str(value), tenant_type(value)
        if types.setdefault(key, kind) != kind:
            return {}, (f"tenant values {value!r} and {key!r} differ only by type; the "
                        "store filters them as two tenants, and one collection name "
                        "cannot hold them apart. Make the tenant field one type first")
        tenants[key] = tenants.get(key, 0) + 1
    if len(tenants) < 2:
        return {}, "fewer than two tenants share this collection; there is nothing to split"
    if len(tenants) > MAX_SPLIT_TENANTS:
        return {}, (f"{len(tenants)} tenants share this collection; a split creates at "
                    f"most {MAX_SPLIT_TENANTS} collections from here")
    try:
        existing = {c.name: c for c in connector.list_collections()}
    except Exception as exc:
        return {}, f"the store's collections could not be listed ({type(exc).__name__})"
    partitions: dict[str, dict] = {}
    names: dict[str, str] = {}
    for tenant in sorted(tenants):
        name = partition_name(collection, tenant)
        if not name or not _valid_collection_name(name):
            return {}, f"tenant '{tenant}' does not make a valid collection name ({name!r})"
        if name in names:
            return {}, (f"tenants '{names[name]}' and '{tenant}' map to the same "
                        f"collection name {name!r}")
        names[name] = tenant
        prior = existing.get(name)
        if prior is not None:
            meta = getattr(prior, "metadata", None) or {}
            ours = (meta.get("vecshield_split_of") == collection
                    and str(meta.get("vecshield_tenant")) == tenant
                    and meta.get("vecshield_tenant_type", types[tenant]) == types[tenant])
            if not ours and (getattr(prior, "count", 0) or 0) > 0:
                return {}, (f"{name} already exists, holds data, and was not created by a "
                            "split of this collection; copying into it would mix data")
        partitions[tenant] = {"collection": name, "chunks": tenants[tenant],
                              "exists": prior is not None, "type": types[tenant]}
    return {**params, "partitions": partitions}, ""


def _same_selector(a: Optional[dict], b: Optional[dict]) -> bool:
    return _digest(dict(a) if a else None) == _digest(dict(b) if b else None)


def _as_proposed(suggestion: Suggestion, findings: Mapping[str, dict], *,
                 store: str, tenant_field: Optional[str],
                 cache: dict[str, tuple[list[Suggestion], list[Suggestion]]]) -> Suggestion:
    """The suggestion as the server itself would have proposed it, or a refusal.

    A client echoes suggestions back to be staged, so nothing it says about
    their reach or their evidence is taken on trust. The finding is re-read,
    the catalogue re-derived from it, and the suggestion must fit inside one
    of the server's own proposals for the same action: the same collection,
    the same selector, and chunk ids the server would reach, which is where
    each action's confidence bar is applied against this build's calibration.
    What the plan then records about the evidence (calibration, labels,
    counts, the detectors it rests on) is the server's, not the client's.
    """
    fid = suggestion.finding_id
    finding = findings.get(fid)
    if finding is None:
        raise ActionError(
            f"suggestion {suggestion.id} answers finding '{fid}', which is not a stored "
            "finding for this store. Only what the server proposes can be staged.")
    if fid not in cache:
        from vecshield_platform.remediation import catalogue

        record = {**finding, "store": store}
        # The reviewer may include disputed chunks (a stated override); the
        # confidence bar is never relaxed. So both catalogues bound the reach.
        cache[fid] = tuple(
            list(catalogue(record, store_id=store, tenant_field=tenant_field,
                           include_disputed=include).suggestions)
            for include in (False, True))
    strict, loose = ([p for p in group if p.action == suggestion.action]
                     for group in cache[fid])
    if not loose:
        raise ActionError(
            f"the server does not propose {suggestion.action} for finding '{fid}', so it "
            "cannot be staged from it. A withheld action stays withheld until the "
            "evidence behind it changes.")
    if suggestion.collection != loose[0].collection:
        raise ActionError(
            f"suggestion {suggestion.id} names collection '{suggestion.collection}', "
            f"but finding '{fid}' is about '{loose[0].collection}'.")
    reachable = {cid for p in loose for cid in p.chunk_ids}
    unknown = [cid for cid in suggestion.chunk_ids if cid not in reachable]
    if unknown:
        shown = ", ".join(unknown[:5]) + (f" and {len(unknown) - 5} more"
                                          if len(unknown) > 5 else "")
        raise ActionError(
            f"{suggestion.action} for finding '{fid}' does not reach chunk(s) {shown}: "
            "the finding did not name them, or the action's confidence bar holds "
            "them back.")
    wanted = set(suggestion.chunk_ids)

    def fits(p: Suggestion) -> bool:
        return (wanted <= set(p.chunk_ids)
                and (suggestion.selector is None
                     or _same_selector(suggestion.selector, p.selector)))

    base = next((p for p in strict if fits(p)), None) or next(
        (p for p in loose if fits(p)), None)
    if base is None:
        raise ActionError(
            f"suggestion {suggestion.id} does not match what the server proposes for "
            f"{suggestion.action} on finding '{fid}' (its selector or chunk set differs).")
    from dataclasses import replace

    return replace(
        suggestion, collection=base.collection, rests_on=base.rests_on,
        calibrated=base.calibrated, observed_chunks=base.observed_chunks,
        named_chunks=base.named_chunks, excluded=base.excluded, labels=base.labels,
        # The server's parameters win where it sets one (a review reason, a
        # tenant field); a value only the stager can supply, such as the
        # tenant to assign, is kept and validated by _stage_params.
        params={**dict(suggestion.params or {}), **dict(base.params or {})},
        kind=base.kind or suggestion.kind, basis=base.basis or suggestion.basis)


def _confidence_rechecked(suggestion: Suggestion) -> Suggestion:
    """Without stored findings: the bar is still this build's, not the client's flag."""
    template = suggestion.template
    if template.requires_confidence:
        short = below_confidence(template, suggestion.rests_on)
        if short:
            raise ActionError(
                f"{suggestion.action}: "
                + _confidence_reason(template, suggestion.rests_on, short))
    from dataclasses import replace

    rests_on = tuple(suggestion.rests_on)
    return replace(suggestion, calibrated=bool(rests_on)
                   and all(d in CALIBRATED for d in rests_on))


def stage(suggestions: Iterable[Suggestion], *, connector: Any, store: str,
          staged_by: str, note: str = "",
          tenant_field: Optional[str] = None,
          findings: Optional[Mapping[str, dict]] = None) -> ActionPlan:
    """Freeze suggestions into a plan resolved against the store as it is now.

    Raises rather than guessing when a suggestion names a different store: a
    plan reaches exactly one store, and that is what makes its fingerprint and
    its approval meaningful. ``tenant_field`` is the store's configured tenant
    field, which an operation writing tenant values must match.

    ``findings`` maps each finding id the suggestions answer to the stored
    finding, as the suggestion endpoint read it. With it, every suggestion is
    checked against what the server would propose for that finding (see
    :func:`_as_proposed`) and an unknown finding, collection or chunk is
    refused. A caller behind a trust boundary must pass it. Without it (a
    local operator staging their own suggestions file), the action's
    confidence bar is still checked against this build's calibration.
    """
    chosen = list(suggestions)
    if not chosen:
        raise ActionError("a plan needs at least one suggestion")
    if not staged_by:
        raise ActionError("a plan records who staged it")
    wrong = {s.store for s in chosen} - {store}
    if wrong:
        raise ActionError(f"suggestions target a different store: {', '.join(sorted(wrong))}")
    unknown = sorted({s.action for s in chosen} - set(ACTION_TEMPLATES))
    if unknown:
        raise ActionError(f"unknown action(s): {', '.join(unknown)}")
    if findings is not None:
        cache: dict[str, tuple[list[Suggestion], list[Suggestion]]] = {}
        chosen = [_as_proposed(s, findings, store=store, tenant_field=tenant_field,
                               cache=cache) for s in chosen]
    else:
        chosen = [_confidence_rechecked(s) for s in chosen]

    fingerprint = store_fingerprint(connector)
    operations: list[Operation] = []
    for suggestion in chosen:
        template = suggestion.template
        supported, reason = capability_verdict(connector, template)
        collection = suggestion.collection
        selector = dict(suggestion.selector) if suggestion.selector else None
        selection: Optional[dict] = None
        params, refused = _stage_params(suggestion, tenant_field=tenant_field)
        if supported and refused:
            supported, reason = False, f"Refused at staging: {refused}."
        if supported and selector and validate_selector(selector):
            supported, reason = False, f"Refused at staging: {validate_selector(selector)}."
        if template.kind == "split_by_tenant" and not selector:
            selector = {"match": "has_field", "field": params.get("tenant_field")}
        if template.kind == "quarantine_collection":
            targets: tuple[TargetResolution, ...] = ()
        elif not collection:
            supported, reason = False, "The suggestion names no collection to resolve against."
            targets = ()
        elif not supported:
            # Do not read the store for an action it cannot perform: the
            # capability answer is already final. That means these targets were
            # never looked up, which is recorded as unchecked rather than as
            # absent — we do not know whether they are still there. A selector
            # names no ids to record, so it records none.
            targets = tuple(TargetResolution(cid, collection, present=None)
                            for cid in suggestion.chunk_ids)
        elif unenumerable_reason(connector, template):
            # An inventory-only store cannot be searched for the chunks, so
            # they are recorded as unchecked and the action is refused rather
            # than staged against targets nobody could look up.
            supported, reason = False, unenumerable_reason(connector, template)
            targets = tuple(TargetResolution(cid, collection, present=None)
                            for cid in suggestion.chunk_ids)
        elif selector:
            value_field = (params.get("tenant_field")
                           if template.kind == "split_by_tenant" else None)
            targets, selection, values = resolve_selector(
                connector, collection, selector, value_field=value_field)
            if template.kind == "split_by_tenant" and targets:
                if selection.get("capped"):
                    supported, reason = False, (
                        f"Refused at staging: {selection['matched']} chunks carry a tenant "
                        f"value, more than the {MAX_SELECTED} one plan may copy.")
                else:
                    params, refused = _plan_split(connector, collection, params, values)
                    if refused:
                        supported, reason = False, f"Refused at staging: {refused}."
        else:
            targets = resolve_targets(connector, collection, suggestion.chunk_ids,
                                      with_redaction=template.kind == "redact_text")
        operations.append(Operation(
            action=suggestion.action, store=store, collection=collection,
            finding_id=suggestion.finding_id, targets=targets,
            supported=supported, support_reason=reason,
            calibrated=suggestion.calibrated,
            observed_chunks=suggestion.observed_chunks,
            named_chunks=suggestion.named_chunks,
            excluded=tuple(suggestion.excluded),
            labels=tuple(suggestion.labels),
            selector=selector, selection=selection,
            params=dict(params) if params else {},
        ))
    return ActionPlan(
        id=f"plan-{uuid.uuid4().hex[:12]}",
        store=store, staged_by=staged_by, staged_at=_now(),
        operations=tuple(operations), store_fingerprint=fingerprint, note=note,
    )


def plan_from_body(body: dict) -> ActionPlan:
    """Rebuild a plan from its stored form, so staleness can be re-checked.

    Refuses a body that does not hash to its recorded value: re-checking a plan
    against the store is only meaningful if the plan is the one that was staged.
    """
    if not verify_body(body):
        raise ActionError("this plan does not match its own hash")
    operations = []
    for op in body.get("operations") or []:
        if op.get("action") not in ACTION_TEMPLATES:
            raise ActionError(f"unknown action in stored plan: {op.get('action')}")
        operations.append(Operation(
            action=op["action"], store=str(body.get("store") or ""),
            collection=op.get("collection"), finding_id=op.get("finding_id", ""),
            targets=tuple(TargetResolution(
                chunk_id=t.get("chunk_id", ""), collection=t.get("collection", ""),
                present=t.get("present"), preview=t.get("preview", ""),
                content_hash=t.get("content_hash", ""))
                for t in op.get("targets") or ()),
            supported=bool(op.get("supported")),
            support_reason=op.get("support_reason", ""),
            calibrated=bool(op.get("calibrated")),
            observed_chunks=int(op.get("observed_chunks") or 0),
            named_chunks=int(op.get("named_chunks") or 0),
            excluded=tuple((str(e.get("chunk_id")), str(e.get("reason")))
                           for e in op.get("excluded") or () if isinstance(e, dict)),
            labels=tuple(str(x) for x in op.get("labels") or ()),
            selector=op.get("selector") or None,
            selection=op.get("selection") or None,
            params=dict(op.get("params") or {})))
    return ActionPlan(
        id=str(body.get("id") or ""), store=str(body.get("store") or ""),
        staged_by=str(body.get("staged_by") or ""),
        staged_at=str(body.get("staged_at") or ""), operations=tuple(operations),
        store_fingerprint=str(body.get("store_fingerprint") or ""),
        state=str(body.get("state") or "staged"), note=str(body.get("note") or ""))


def is_stale(plan: ActionPlan, connector: Any) -> tuple[bool, str]:
    """Has the world moved since this plan was staged?

    A plan staged against one store and executed against a different one is the
    failure mode this exists to catch, so the answer errs towards stale: a store
    we cannot re-read counts as changed.
    """
    try:
        current = store_fingerprint(connector)
    except ActionError as exc:
        return True, f"The store could not be re-read, so the plan cannot be trusted: {exc}"
    if current != plan.store_fingerprint:
        return True, ("The store's collections or counts have changed since staging. "
                      "Re-stage so the plan describes the store as it is now.")
    for op in plan.executable:
        if not op.collection:
            continue
        fresh = {t.chunk_id: t for t in resolve_targets(
            connector, op.collection, [t.chunk_id for t in op.present],
            previews=False)}
        for target in op.present:
            now = fresh.get(target.chunk_id)
            if now is None or not now.present:
                return True, (f"Chunk {target.chunk_id} in {op.collection} has gone "
                              "since staging.")
            if now.content_hash != target.content_hash:
                return True, (f"Chunk {target.chunk_id} in {op.collection} has changed "
                              "since staging, so the diff no longer describes it.")
    return False, "The store matches the plan as staged."


# --------------------------------------------------------------------------- #
# Dry-run diff                                                                 #
# --------------------------------------------------------------------------- #

#: Said in the same words wherever a plan is shown. Reading a diff changes
#: nothing; the one path that writes is executing an approved plan, and only a
#: deployment with safe mode off takes it. Written for both states, so it stays
#: true next to an Execute button and next to a disabled one.
EXECUTION_NOTE = ("Reviewing this diff writes nothing to the store. Only an approved "
                  "plan is executed, and only where safe mode is off; every change is "
                  "read back afterwards, and a re-scan decides whether the finding is gone.")


def warnings_for(body: dict) -> list[str]:
    """The things a reviewer would otherwise assume away.

    Takes a serialized plan rather than an ``ActionPlan`` so a plan read back
    from storage produces exactly the same warnings as one just staged. Two
    implementations would eventually disagree, and the stored one is the one a
    person approves.
    """
    radius = body.get("blast_radius") or {}
    operations = body.get("operations") or []
    executable = [op for op in operations if op.get("runnable")]
    warnings: list[str] = []
    if radius.get("irreversible_operations"):
        warnings.append(
            f"{radius.get('irreversible_chunks', 0)} chunk(s) would be permanently "
            "deleted. This cannot be undone: the connector offers no restore path.")
    for op in executable:
        warnings.extend(_operation_warnings(op))
    if not radius.get("reaches_all_observed", True):
        warnings.append(
            f"The findings observed {radius.get('chunks_observed_by_findings', 0)} "
            f"sensitive chunk(s); this plan reaches {radius.get('chunks_targeted', 0)}. "
            "Executing it does not resolve the findings, because assessments retain "
            "only a sample of chunk ids.")
    if radius.get("chunks_missing"):
        warnings.append(
            f"{radius['chunks_missing']} targeted chunk(s) were looked up and are no "
            "longer in the store. They would be skipped.")
    if radius.get("chunks_unchecked"):
        warnings.append(
            f"{radius['chunks_unchecked']} targeted chunk(s) were never looked up, "
            "because their operation is blocked. Whether they are still in the store "
            "is unknown.")
    if radius.get("blocked"):
        warnings.append(
            f"{radius['blocked']} operation(s) cannot run against this connector and "
            "are shown for completeness only.")
    held_back = sum(len(op.get("excluded") or []) for op in operations)
    if held_back:
        warnings.append(
            f"{held_back} named chunk(s) are not reached by a gated operation because "
            "the detectors that fired on them have not earned the confidence it "
            "requires. They are listed on the operation.")
    uncalibrated = [op for op in executable if not op.get("calibrated")]
    if uncalibrated:
        warnings.append(
            f"{len(uncalibrated)} operation(s) rest on detectors with no measured "
            "precision. They are reversible for that reason.")
    if not executable:
        warnings.append(
            "No operation in this plan can run against this store. It is a record of "
            "what was proposed, not something to approve.")
    return warnings


def _operation_warnings(op: dict) -> list[str]:
    """What a specific kind of operation changes that its title understates."""
    out: list[str] = []
    action = op.get("action")
    params = op.get("params") or {}
    count = int(op.get("resolved") or 0)
    where = op.get("collection") or "the store"
    if action == "quarantine_chunks":
        out.append(f"{count} chunk(s) would be moved out of {where} into "
                   "vecshield_quarantine. Retrieval over the source collection stops "
                   "returning them; the quarantine collection is in the same store.")
    elif action == "assign_tenant":
        out.append(f"{count} chunk(s) in {where} would be assigned to tenant "
                   f"'{params.get('tenant_value')}' on '{params.get('tenant_field')}'. "
                   "A query filtered to that tenant will then return them; check they "
                   "belong to it.")
    elif action == "split_by_tenant":
        parts = params.get("partitions") or {}
        out.append(f"{len(parts)} per-tenant collection(s) would be created or filled "
                   f"with copies of {count} chunk(s) from {where}. The shared "
                   "collection is not changed and still mixes tenants until the "
                   "application stops querying it.")
    selection = op.get("selection") or {}
    if selection.get("capped"):
        out.append(f"The condition behind an operation on {where} matched "
                   f"{selection.get('matched')} chunk(s); this plan reaches the first "
                   f"{selection.get('reached')}. Stage again after it runs for the rest.")
    return out


def diff(plan: ActionPlan) -> dict:
    """What the plan would do, what it cannot undo, and what it will not reach.

    Reviewing means reading this. It leads with the irreversible operations and
    with what the plan does *not* cover, because those are the two things a
    reviewer is most likely to assume away.
    """
    body = plan.to_dict()
    return {
        "plan_id": plan.id,
        "plan_hash": plan.plan_hash,
        "store": plan.store,
        "staged_by": plan.staged_by,
        "staged_at": plan.staged_at,
        "state": plan.state,
        "blast_radius": body["blast_radius"],
        "warnings": warnings_for(body),
        "executes": False,
        "execution_note": EXECUTION_NOTE,
        "operations": [
            {
                **op.to_dict(),
                "sample": [t.to_dict() for t in op.present[:5]],
            }
            for op in plan.operations
        ],
    }


def format_diff(report: dict) -> str:
    """The diff as text, warnings first."""
    lines = [f"Plan {report['plan_id']}  ({report['plan_hash'][:12]})",
             f"Store: {report['store']}  staged by {report['staged_by']} "
             f"at {report['staged_at']}", ""]
    if report["warnings"]:
        lines.append("Before you read the operations:")
        lines += [f"  ! {w}" for w in report["warnings"]]
        lines.append("")
    radius = report["blast_radius"]
    lines.append(f"{radius['executable']} of {radius['operations']} operation(s) can run, "
                 f"over {radius['chunks_targeted']} chunk(s) "
                 f"in {len(radius['collections'])} collection(s).")
    lines.append("")
    for op in report["operations"]:
        mark = "-" if op["supported"] else "x"
        lines.append(f" {mark} {op['title']}  [{op['risk']} risk, "
                     f"{'reversible' if op['reversible'] else 'IRREVERSIBLE'}]")
        lines.append(f"     collection: {op['collection'] or '(store scope)'}  "
                     f"from finding {op['finding_id']}")
        if not op["supported"]:
            lines.append(f"     blocked: {op['support_reason']}")
        else:
            lines.append(f"     targets: {op['resolved']} present, {op['missing']} missing"
                         + (f", {op['unchecked']} unchecked" if op.get("unchecked") else ""))
            for target in op["sample"]:
                lines.append(f"       {target['chunk_id']}: {target['preview'] or '(no text)'}")
                if target.get("redacted_preview") is not None:
                    lines.append(f"         -> {target['redacted_preview']}")
        lines.append(f"     undo: {op['undo']}")
        lines.append("")
    lines.append(report["execution_note"])
    return "\n".join(lines)
