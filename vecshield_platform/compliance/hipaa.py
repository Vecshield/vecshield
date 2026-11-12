"""HIPAA-specific reference data: the Safe Harbor identifier map and the
business-associate exposure a connector estate implies.

Two questions come up constantly in a HIPAA conversation about a retrieval
corpus, and both have concrete answers this product can partly supply:

1. *Is this content de-identified?* The Safe Harbor method at
   §164.514(b)(2)(i)(A)–(R) lists eighteen identifier categories that must be
   removed. VecShield's classifier detects some of them and cannot detect
   others at all. :func:`evaluate_safe_harbor` reports both, because a
   category the product cannot see produces no match whether or not the
   identifier is present — absence of a match there is not evidence of
   absence, and that has to be in the result, not in a comment.
2. *Who else holds this ePHI?* A connector kind says whether the store is a
   vendor-operated managed service. If it is, the vendor holds ePHI on the
   entity's behalf and §164.308(b)(1) requires a business associate contract
   before that happens. :func:`business_associate_exposure` names the vendors
   the registered estate implies, and says plainly where the connector kind
   does not establish an operator.

Everything here is pure: no I/O, no network, no classifier invocation. The
inputs are detector names and Presidio entity types as they already appear in
``data_classification`` finding evidence (``detector_counts``), and connector
kinds as they already appear on a registered store.

Nothing in this module concludes that content is de-identified, that Safe
Harbor is met, or that a contract exists. Those are determinations a person
makes; §164.514(b)(2)(ii) in particular turns on actual knowledge, which is
not a property of text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

#: The Safe Harbor identifier categories, by subparagraph letter.
SAFE_HARBOR_LETTERS = tuple("ABCDEFGHIJKLMNOPQR")

#: Locator for the identifier list itself.
SAFE_HARBOR_SECTION = "45 CFR 164.514(b)(2)(i)"

#: Why a null result is never a de-identification conclusion.
SAFE_HARBOR_CAVEAT = (
    "Safe Harbor also requires, under §164.514(b)(2)(ii), that the entity have "
    "no actual knowledge that the remaining information could identify an "
    "individual. Actual knowledge is not a property of text and is not "
    "observed here.")


@dataclass(frozen=True)
class SafeHarborIdentifier:
    """One of the eighteen categories, and what VecShield can see of it."""

    letter: str
    #: VecShield's own words for the category. Not the regulation's text.
    paraphrase: str
    #: Regex detector names from ``vecshield.classify.regex_classifier``.
    detectors: tuple[str, ...] = ()
    #: Presidio entity types from ``vecshield.classify.presidio_classifier``.
    entity_types: tuple[str, ...] = ()
    #: False when no check in this product can observe the category at all.
    detectable: bool = True
    #: Required when ``detectable`` is False: why the product cannot see it.
    undetectable_reason: str = ""
    #: What a match does and does not establish for this category.
    notes: str = ""
    #: True when the detectors listed cover only part of the category, so a
    #: null result is weaker than it looks even though something can fire.
    partial: bool = False

    def __post_init__(self) -> None:
        if self.letter not in SAFE_HARBOR_LETTERS:
            raise ValueError(f"not a Safe Harbor subparagraph: {self.letter}")
        if self.detectable and not (self.detectors or self.entity_types):
            raise ValueError(
                f"({self.letter}) claims to be detectable but names no detector")
        if not self.detectable and not self.undetectable_reason:
            raise ValueError(
                f"({self.letter}) is undetectable and must say why")

    @property
    def citation(self) -> str:
        return f"{SAFE_HARBOR_SECTION}({self.letter})"

    @property
    def signals(self) -> frozenset[str]:
        """Detector names and entity types that speak to this category."""
        return frozenset(self.detectors) | frozenset(self.entity_types)

    def to_dict(self) -> dict[str, Any]:
        return {
            "letter": self.letter, "citation": self.citation,
            "paraphrase": self.paraphrase, "detectors": list(self.detectors),
            "entity_types": list(self.entity_types),
            "detectable": self.detectable, "partial": self.partial,
            "undetectable_reason": self.undetectable_reason,
            "notes": self.notes,
        }


_NLP_ONLY = ("Detected only by the Presidio/spaCy classifier. A regex-only "
             "deployment does not detect this category at all.")

SAFE_HARBOR_IDENTIFIERS: tuple[SafeHarborIdentifier, ...] = (
    SafeHarborIdentifier(
        letter="A", paraphrase="Names.",
        entity_types=("PERSON",),
        notes="Named-entity recognition, not a roster lookup. It cannot tell a "
              "patient's name from a clinician's or an author's. " + _NLP_ONLY),
    SafeHarborIdentifier(
        letter="B",
        paraphrase="Geographic subdivisions smaller than a state — street "
                   "address, city, county, precinct, ZIP code and equivalent "
                   "geocodes — subject to the initial-three-digit ZIP rule.",
        detectors=("us_street_address", "street_name_context", "secondary_address",
                   "us_zip_context", "zip_plus4", "county_name", "gps_coordinate"),
        entity_types=("LOCATION",),
        partial=True,
        notes="The three-digit ZIP exception turns on Census population counts "
              "for the combined ZIP area. VecShield holds no population data "
              "and does not evaluate that exception, so it cannot say whether "
              "a truncated ZIP is permissible."),
    SafeHarborIdentifier(
        letter="C",
        paraphrase="All date elements except the year where the date relates "
                   "directly to an individual, and all ages over 89 together "
                   "with any date element indicating such an age.",
        detectors=("date_of_birth", "age_context"),
        entity_types=("DATE_TIME",),
        partial=True,
        notes="Whether a date relates directly to an individual is a judgement "
              "about context, not a pattern. DATE_TIME is only treated as "
              "health-related when other health context fires nearby, so "
              "isolated admission or discharge dates can pass unflagged. The "
              "age-over-89 aggregation rule is not evaluated."),
    SafeHarborIdentifier(
        letter="D", paraphrase="Telephone numbers.",
        detectors=("us_phone", "intl_phone"),
        entity_types=("PHONE_NUMBER",)),
    SafeHarborIdentifier(
        letter="E", paraphrase="Fax numbers.",
        detectors=("us_phone", "intl_phone"),
        entity_types=("PHONE_NUMBER",),
        partial=True,
        notes="No detector distinguishes a fax number from a telephone number. "
              "A fax number matches the phone detectors, so (D) and (E) are "
              "observed together and cannot be separated."),
    SafeHarborIdentifier(
        letter="F", paraphrase="Email addresses.",
        detectors=("email",), entity_types=("EMAIL_ADDRESS",)),
    SafeHarborIdentifier(
        letter="G", paraphrase="Social security numbers.",
        detectors=("us_ssn", "us_ssn_spaced", "us_ssn_context"),
        entity_types=("US_SSN",)),
    SafeHarborIdentifier(
        letter="H", paraphrase="Medical record numbers.",
        detectors=("medical_record_context",),
        notes="Context-gated: the detector needs a nearby record-number cue. A "
              "bare identifier in a metadata field without that cue is not "
              "matched by this detector."),
    SafeHarborIdentifier(
        letter="I", paraphrase="Health plan beneficiary numbers.",
        detectors=("us_medicare_mbi_context",),
        partial=True,
        notes="Medicare Beneficiary Identifiers are matched. Commercial plan "
              "member numbers have no standard format and are not matched "
              "except where they happen to fire a generic identifier detector."),
    SafeHarborIdentifier(
        letter="J", paraphrase="Account numbers.",
        detectors=("bank_account_context", "bank_routing", "iban", "credit_card",
                   "credit_card_issuer", "card_like_number"),
        entity_types=("US_BANK_NUMBER", "IBAN_CODE", "CREDIT_CARD"),
        partial=True,
        notes="Financial account formats are covered. An arbitrary internal "
              "account number is not, unless it fires a generic identifier "
              "detector; that residue belongs to category (R)."),
    SafeHarborIdentifier(
        letter="K", paraphrase="Certificate and license numbers.",
        detectors=("us_driver_license_context", "passport_context",
                   "us_dea_number_context", "npi_context"),
        entity_types=("US_DRIVER_LICENSE", "US_PASSPORT", "MEDICAL_LICENSE"),
        partial=True,
        notes="NPI and DEA numbers identify a provider, not the individual who "
              "is the subject of the record. They are Safe Harbor identifiers "
              "only where the provider is also the subject; otherwise a match "
              "here is a signal about the document, not about de-identification."),
    SafeHarborIdentifier(
        letter="L",
        paraphrase="Vehicle identifiers and serial numbers, including licence "
                   "plate numbers.",
        detectors=("vehicle_vin", "vehicle_vrm")),
    SafeHarborIdentifier(
        letter="M", paraphrase="Device identifiers and serial numbers.",
        detectors=("imei_number", "mac_address"),
        partial=True,
        notes="IMEI and MAC addresses are matched. Medical device serial "
              "numbers have no common format and are not matched."),
    SafeHarborIdentifier(
        letter="N", paraphrase="Web URLs.",
        entity_types=("URL",),
        notes=_NLP_ONLY),
    SafeHarborIdentifier(
        letter="O", paraphrase="IP addresses.",
        detectors=("ipv4_address", "ipv6_address"),
        entity_types=("IP_ADDRESS",)),
    SafeHarborIdentifier(
        letter="P",
        paraphrase="Biometric identifiers, including finger and voice prints.",
        detectors=("biometric_reference",),
        partial=True,
        notes=(
            "Reference-level only, and the distinction matters. VecShield "
            "classifies chunk text: it can see a note saying a voiceprint was "
            "enrolled, or a field named faceprint, and it reads that as "
            "biometric data being held. It cannot inspect a template, audio, "
            "or any binary payload, so a store whose biometric data is only "
            "ever binary produces no signal at all. Absence here is not "
            "evidence of absence."),),
    SafeHarborIdentifier(
        letter="Q",
        paraphrase="Full-face photographic images and comparable images.",
        detectable=False,
        undetectable_reason=(
            "No image is inspected. An image embedded in or referenced by a "
            "chunk is invisible to this product, and so is an image-bearing "
            "vector in a multimodal collection.")),
    SafeHarborIdentifier(
        letter="R",
        paraphrase="Any other unique identifying number, characteristic or code.",
        detectors=("metadata_identifier", "prefixed_id", "username_handle",
                   "us_itin", "tax_id_context", "user_agent_string"),
        detectable=False,
        undetectable_reason=(
            "The category is open-ended by design. The detectors listed surface "
            "some identifier-shaped values, but no detector set can establish "
            "that no other unique identifying number, characteristic or code "
            "remains. A rare diagnosis, an unusual occupation or a free-text "
            "narrative detail can identify a person and matches no pattern."),
        notes="Detectors are listed because a match here is informative. A "
              "null result is not."),
)

_BY_LETTER = {identifier.letter: identifier for identifier in SAFE_HARBOR_IDENTIFIERS}

#: Every detector name or entity type mapped to at least one category.
def _build_signal_index() -> dict[str, tuple[str, ...]]:
    index: dict[str, tuple[str, ...]] = {}
    for identifier in SAFE_HARBOR_IDENTIFIERS:
        for signal in identifier.signals:
            index[signal] = index.get(signal, ()) + (identifier.letter,)
    return index


_SIGNAL_INDEX: dict[str, tuple[str, ...]] = _build_signal_index()


def get_identifier(letter: str) -> Optional[SafeHarborIdentifier]:
    return _BY_LETTER.get(letter.upper())


def detectable_identifiers() -> tuple[SafeHarborIdentifier, ...]:
    return tuple(i for i in SAFE_HARBOR_IDENTIFIERS if i.detectable)


def undetectable_identifiers() -> tuple[SafeHarborIdentifier, ...]:
    """Categories where a null result carries no information at all."""
    return tuple(i for i in SAFE_HARBOR_IDENTIFIERS if not i.detectable)


@dataclass(frozen=True)
class SafeHarborObservation:
    """What a run's classification signals say about the eighteen categories.

    ``not_observed`` and ``undetectable`` are deliberately separate lists. A
    category in ``not_observed`` was looked for and not found within the
    inspected scope. A category in ``undetectable`` was never looked for,
    because nothing in this product can see it; its absence from ``observed``
    means nothing.
    """

    observed: tuple[str, ...]
    not_observed: tuple[str, ...]
    undetectable: tuple[str, ...]
    partial: tuple[str, ...]
    unmapped_signals: tuple[str, ...]
    signals_by_letter: dict[str, tuple[str, ...]]

    @property
    def conclusion(self) -> None:
        """There is none. De-identification is a determination, not a scan."""
        return None

    @property
    def absence_is_not_evidence(self) -> tuple[str, ...]:
        """Categories whose absence from ``observed`` proves nothing."""
        return tuple(sorted(set(self.undetectable) | set(self.partial)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": SAFE_HARBOR_SECTION,
            "categories": len(SAFE_HARBOR_IDENTIFIERS),
            "observed": [
                _BY_LETTER[letter].to_dict() | {
                    "matched_signals": list(self.signals_by_letter.get(letter, ()))}
                for letter in self.observed],
            "not_observed": [_BY_LETTER[letter].to_dict()
                             for letter in self.not_observed],
            "undetectable": [_BY_LETTER[letter].to_dict()
                             for letter in self.undetectable],
            "partial": list(self.partial),
            "absence_is_not_evidence": list(self.absence_is_not_evidence),
            "unmapped_signals": list(self.unmapped_signals),
            "conclusion": None,
            "note": (
                "Observed categories are Safe Harbor identifiers found in the "
                "inspected scope. Categories listed as undetectable are ones "
                "this product cannot see at all, so their absence from the "
                "observed list is not evidence that they are absent from the "
                "content. " + SAFE_HARBOR_CAVEAT),
        }


def evaluate_safe_harbor(signals: Iterable[str]) -> SafeHarborObservation:
    """Map observed detector names and entity types onto the eighteen categories.

    ``signals`` are detector names and Presidio entity types exactly as the
    classification scan emits them (the keys of ``detector_counts`` in a
    ``data_classification`` finding's evidence). Pure: nothing is fetched,
    nothing is classified here.
    """
    seen = {str(signal) for signal in signals}
    matched: dict[str, tuple[str, ...]] = {}
    unmapped: list[str] = []
    for signal in sorted(seen):
        letters = _SIGNAL_INDEX.get(signal)
        if not letters:
            unmapped.append(signal)
            continue
        for letter in letters:
            matched[letter] = matched.get(letter, ()) + (signal,)

    observed = tuple(l for l in SAFE_HARBOR_LETTERS if l in matched)
    undetectable = tuple(i.letter for i in undetectable_identifiers())
    not_observed = tuple(l for l in SAFE_HARBOR_LETTERS
                         if l not in matched and l not in undetectable)
    partial = tuple(i.letter for i in SAFE_HARBOR_IDENTIFIERS
                    if i.partial and i.detectable)
    return SafeHarborObservation(
        observed=observed, not_observed=not_observed, undetectable=undetectable,
        partial=partial, unmapped_signals=tuple(unmapped),
        signals_by_letter=matched)


def safe_harbor_manifest() -> dict[str, Any]:
    """Describe this map's coverage of the eighteen categories, and its limits.

    Mirrors :func:`vecshield_platform.compliance.packs.pack_manifest`: it
    reports what the content covers without implying the coverage is complete.
    """
    undetectable = undetectable_identifiers()
    partial = [i for i in SAFE_HARBOR_IDENTIFIERS if i.partial and i.detectable]
    return {
        "section": SAFE_HARBOR_SECTION,
        "categories": len(SAFE_HARBOR_IDENTIFIERS),
        "detectable": len(detectable_identifiers()),
        "undetectable": [
            {"letter": i.letter, "citation": i.citation,
             "paraphrase": i.paraphrase, "reason": i.undetectable_reason}
            for i in undetectable],
        "partially_detectable": [
            {"letter": i.letter, "citation": i.citation, "note": i.notes}
            for i in partial],
        "requires_nlp_classifier": sorted(
            i.letter for i in SAFE_HARBOR_IDENTIFIERS
            if i.detectable and i.entity_types and not i.detectors),
        "lifecycle": "draft",
        "regulatory_review": None,
        "note": (
            f"{len(undetectable)} of {len(SAFE_HARBOR_IDENTIFIERS)} categories "
            "cannot be observed by this product, and several more are only "
            "partly covered. This map supports a de-identification review; it "
            "does not perform one, and no combination of its outputs "
            "establishes that Safe Harbor is met. " + SAFE_HARBOR_CAVEAT),
    }


# --------------------------------------------------------------------------- #
# Business associate exposure implied by the connector estate                  #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VendorProfile:
    """What a connector kind says about who operates the store."""

    kind: str
    #: The organisation that operates the service, where the kind settles it.
    vendor: Optional[str]
    #: "vendor_managed" | "deployment_dependent"
    operator: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "vendor": self.vendor,
                "operator": self.operator, "note": self.note}


_DEPLOYMENT_DEPENDENT = (
    "The connector kind does not say who operates this deployment. It may be "
    "self-hosted inside the entity's own boundary, or run by a vendor as a "
    "managed service; only the operator of record settles that.")

VENDOR_PROFILES: tuple[VendorProfile, ...] = (
    VendorProfile("pinecone", "Pinecone", "vendor_managed"),
    VendorProfile("openai", "OpenAI", "vendor_managed",
                  note="OpenAI vector stores. The connector reaches a "
                       "vendor-operated service by construction."),
    VendorProfile("azure_search", "Microsoft (Azure AI Search)", "vendor_managed"),
    VendorProfile("bedrock_kb", "Amazon Web Services (Bedrock Knowledge Bases)",
                  "vendor_managed",
                  note="A Bedrock knowledge base is backed by another store "
                       "(for example OpenSearch or pgvector). That backing "
                       "store is a separate holder of the same content."),
    VendorProfile("vertex_ai", "Google Cloud (Vertex AI)", "vendor_managed"),
    VendorProfile("mongodb", None, "deployment_dependent",
                  note="MongoDB Atlas is vendor-operated; a self-managed "
                       "MongoDB deployment is not. The connector kind is the "
                       "same for both. " + _DEPLOYMENT_DEPENDENT),
    VendorProfile("chroma", None, "deployment_dependent", note=_DEPLOYMENT_DEPENDENT),
    VendorProfile("milvus", None, "deployment_dependent", note=_DEPLOYMENT_DEPENDENT),
    VendorProfile("opensearch", None, "deployment_dependent", note=_DEPLOYMENT_DEPENDENT),
    VendorProfile("pgvector", None, "deployment_dependent", note=_DEPLOYMENT_DEPENDENT),
    VendorProfile("qdrant", None, "deployment_dependent", note=_DEPLOYMENT_DEPENDENT),
    VendorProfile("redis", None, "deployment_dependent", note=_DEPLOYMENT_DEPENDENT),
    VendorProfile("weaviate", None, "deployment_dependent", note=_DEPLOYMENT_DEPENDENT),
)

_BY_KIND = {profile.kind: profile for profile in VENDOR_PROFILES}

#: Connector kinds whose operator is a named third party.
VENDOR_MANAGED_KINDS = frozenset(
    p.kind for p in VENDOR_PROFILES if p.operator == "vendor_managed")


def vendor_profile(kind: str) -> Optional[VendorProfile]:
    return _BY_KIND.get((kind or "").lower())


def business_associate_exposure(
        stores: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Name the vendors a registered estate implies a BAA is needed for.

    ``stores`` are mappings with at least ``kind``, optionally ``store_id``.
    Pure: it reads the connector kind already recorded for each store and does
    not open a connection.

    The result reports three groups, and the second two matter as much as the
    first: stores whose operator the connector kind settles, stores where it
    does not, and connector kinds this map does not know. Nothing here says a
    contract exists, that a vendor will sign one, or that ePHI is present —
    whether the store holds ePHI is an applicability question a person answers.
    """
    vendor_managed: list[dict[str, Any]] = []
    deployment_dependent: list[dict[str, Any]] = []
    unknown_kinds: list[dict[str, Any]] = []
    for store in stores:
        kind = str(store.get("kind") or "").lower()
        entry = {"store_id": store.get("store_id"), "kind": kind}
        profile = _BY_KIND.get(kind)
        if profile is None:
            unknown_kinds.append(entry)
        elif profile.operator == "vendor_managed":
            vendor_managed.append(entry | {"vendor": profile.vendor,
                                           "note": profile.note})
        else:
            deployment_dependent.append(entry | {"note": profile.note})

    vendors = sorted({e["vendor"] for e in vendor_managed if e["vendor"]})
    return {
        "vendors_requiring_a_baa": vendors,
        "vendor_managed_stores": vendor_managed,
        "operator_not_established": deployment_dependent,
        "unrecognised_kinds": unknown_kinds,
        "source_ids": ["hipaa-164-308-b-1", "hipaa-164-314-a", "hipaa-160-103"],
        "note": (
            "A vendor-operated store holds whatever is written to it, so if "
            "ePHI is present the vendor is a business associate and "
            "§164.308(b)(1) requires satisfactory assurances in a contract "
            "before that disclosure. This is an inference from the connector "
            "kind: it does not observe whether a contract exists, whether the "
            "vendor offers one, or whether the store holds ePHI at all. Where "
            "the operator is not established, the entity has to say who runs "
            "the deployment."),
    }
