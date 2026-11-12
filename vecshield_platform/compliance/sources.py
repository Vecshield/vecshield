"""Maintained regulatory source records for the policy template catalog.

A display label is not a citation. Template names carry human-readable hints
such as "(Art. 32)", but a name is edited for the UI and cannot be relied on to
say which provision a rule speaks to. This module holds the source records
themselves — issuer, title, section locator, URL, edition, dates, legal status,
provenance and lifecycle state — so attribution is maintained content rather
than parsed text.

Honesty rules this module enforces by construction:

* ``lifecycle`` reports where a record sits in the content lifecycle. The
  states from ``regulatory_reviewed`` onwards (:data:`REVIEW_GATED`) need a
  ``review_ref`` naming the content review that put them there, so a record
  cannot claim a review by editing one field. No record here carries one.
* ``retrieved_at`` and ``content_hash`` stay ``None`` until a build actually
  fetches the provision text (``fetch_method`` says how). An unfetched source
  never reports a verification it did not perform.
* ``citation_check`` is a separate, weaker fact: whether the *locator* was
  checked during research, and against what. It never sets ``verified``. A
  locator only confirmed from secondary sources, or assumed from
  documentation nobody re-read, says so (:data:`CITATION_CHECKS`).
* ``legal_status`` says whether a provision is in force, in force but not yet
  applicable, only proposed, vacated, superseded, or guidance. Text appearing
  in a consolidated code is not proof that it is enforceable.
* ``redistributable`` marks standards whose text is licensed (PCI DSS, the
  AICPA Trust Services Criteria). Their ``reproduction`` is ``link_only``:
  VecShield links to them and references the locator with a few words of its
  own; it does not reproduce their text or their headings. Public law is
  redistributable, but ``notes`` still paraphrases in VecShield's own words
  rather than quoting the provision.
* HIPAA records say in ``specification`` (and in ``notes``) whether a
  provision is a standard, a *required* implementation specification, an
  *addressable* one, a Privacy Rule implementation specification, or a
  definition, and cite 45 CFR 164.306(d) as the provision that draws the
  required/addressable line. Addressable does not mean optional.
* Where a locator could not be pinned down exactly, ``notes`` says so rather
  than the record inventing a subsection letter.

What a ``content_hash`` covers. It is the SHA-256 of the document a build
fetched on ``retrieved_at``, not of the provision alone, and it proves only
that the text was read; the paraphrase in ``notes`` is still VecShield's own.
The fetched documents are:

* GDPR and the EU AI Act: the English XHTML of the act as published, from the
  EU Publications Office (``publications.europa.eu/resource/celex/<CELEX>``,
  content-negotiated). The ``url`` stays the EUR-Lex ELI link a reader opens.
* HIPAA: the section's XML from the eCFR versioner API, as of the date named
  in ``_ECFR_AS_OF``. The ``url`` stays the human eCFR page for the section.
* CCPA/CPRA regulations and statute: the CPPA's own PDFs at the ``url``.

PCI DSS and the AICPA Trust Services Criteria are licence-gated. Their text
was not fetched, so their records stay unverified and their ``notes`` are
paraphrase from the locator, marked as such.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

#: Content lifecycle states from the content-governance model, least advanced
#: first. Content authored in this repository reaches the first two on its
#: own; the rest need a content review (see :data:`REVIEW_GATED`).
LIFECYCLE = ("draft", "technically_validated", "regulatory_reviewed",
             "pilot", "published", "superseded")

#: Lifecycle states that are reachable only through a recorded content review
#: by a qualified reviewer (see ``compliance.content_review``).
REVIEW_GATED = ("regulatory_reviewed", "pilot", "published")

#: How each lifecycle state reads on a screen. Neutral words; none of them is
#: a compliance claim, and "published" describes the mapping, not a store.
LIFECYCLE_LABELS = {
    "draft": "Draft mapping",
    "technically_validated": "Checked by engineers",
    "regulatory_reviewed": "Reviewed by a qualified reviewer",
    "pilot": "In pilot",
    "published": "Published mapping",
    "superseded": "Replaced by a newer mapping",
}

#: What kind of authority a source carries. These are not interchangeable.
SOURCE_KINDS = ("regulation", "statute", "rule", "contractual_standard",
                "guidance", "internal_policy")

#: Whether a provision binds anyone today.
LEGAL_STATUSES = ("in_force", "future_effective", "proposed",
                  "vacated_or_enjoined", "superseded", "guidance")

LEGAL_STATUS_LABELS = {
    "in_force": "In force",
    "future_effective": "In force; applies from a later date",
    "proposed": "Proposed; not in force",
    "vacated_or_enjoined": "Vacated or enjoined",
    "superseded": "Superseded",
    "guidance": "Guidance; not binding",
}

#: What VecShield may do with the source's text.
#:
#: ``link_only``
#:     Licensed text. Locator, link and a few words of VecShield's own only.
#: ``paraphrase``
#:     Redistributable, but VecShield describes it in its own words.
#: ``quote_permitted``
#:     Short quotation is permitted. Nothing in this catalog uses it today.
REPRODUCTION = ("link_only", "paraphrase", "quote_permitted")

#: How far a *locator* was checked during research. This is not ``verified``:
#: that needs the provision text fetched and hashed by a build.
CITATION_CHECKS = {
    "primary_source": (
        "Locator checked against the primary source during research. The "
        "provision text has not been fetched or hashed by a build."),
    "secondary_sources": (
        "Confirmed from secondary sources only. Re-check against the official "
        "text before relying on it."),
    "unverified": (
        "Taken from documentation that was not re-checked. It must be "
        "verified before it reaches a customer-facing document."),
    "not_recorded": "No research check is recorded for this locator.",
}

#: How a provision is written, where the framework draws the distinction.
#: ``required``/``addressable`` are Security Rule terms (45 CFR 164.306(d));
#: ``implementation_specification`` is a Privacy Rule implementation
#: specification, which carries no such label.
SOURCE_SPECIFICATIONS = ("standard", "required", "addressable",
                         "implementation_specification", "definition")

#: How a build obtained the provision text, when it did.
FETCH_METHODS = ("ecfr_api", "federal_register_api", "eur_lex_cellar",
                 "http_download", "manual")


@dataclass(frozen=True)
class ProvisionDate:
    """When a provision applies to one class of subject.

    One regulation can apply on different dates to different systems (the AI
    Act's high-risk rules apply on one date for Annex III systems and another
    for Annex I), so a single ``application_date`` on the record is not enough.
    """

    scope: str
    application_date: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"scope": self.scope, "application_date": self.application_date,
                "note": self.note}


@dataclass(frozen=True)
class RegulatorySource:
    """One citable provision, or one internal baseline."""

    id: str
    framework: str
    issuer: str
    title: str
    kind: str
    section: Optional[str] = None
    url: Optional[str] = None
    edition: Optional[str] = None
    #: When the provision took legal effect (entered into force).
    effective_date: Optional[str] = None
    #: When it began to apply, where the instrument separates the two (EU law).
    application_date: Optional[str] = None
    #: When regulated entities had to comply, where the instrument sets a
    #: compliance date distinct from the effective date (US rules).
    compliance_date: Optional[str] = None
    #: Per-scope application dates, where one date does not fit every subject.
    provision_dates: tuple[ProvisionDate, ...] = ()
    #: Kept for older consumers: ``in_force`` or ``internal``. ``legal_status``
    #: is the field that answers "does this bind anyone".
    status: str = "in_force"
    legal_status: str = "in_force"
    #: The consolidated text this record describes, "as amended through" this
    #: date, where the record is pinned to a dated version.
    consolidated_as_of: Optional[str] = None
    #: Ids of catalog records (or plain citations) that amended the provision.
    amended_by: tuple[str, ...] = ()
    lifecycle: str = "draft"
    #: Set only when a build fetched the provision text.
    retrieved_at: Optional[str] = None
    content_hash: Optional[str] = None
    fetch_method: Optional[str] = None
    #: False for licensed standards whose text may not be reproduced here.
    redistributable: bool = True
    licence: Optional[str] = None
    reproduction: str = "paraphrase"
    #: The content review that moved this record past technically_validated.
    review_ref: Optional[str] = None
    #: How the provision is written (see SOURCE_SPECIFICATIONS).
    specification: Optional[str] = None
    #: How far the locator was checked during research (see CITATION_CHECKS).
    citation_check: str = "not_recorded"
    citation_check_note: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if self.kind not in SOURCE_KINDS:
            raise ValueError(f"unknown source kind: {self.kind}")
        if self.lifecycle not in LIFECYCLE:
            raise ValueError(f"unknown lifecycle state: {self.lifecycle}")
        if self.lifecycle in REVIEW_GATED and not self.review_ref:
            raise ValueError(
                f"{self.id}: lifecycle '{self.lifecycle}' is reachable only "
                "through a recorded content review; set review_ref")
        if self.legal_status not in LEGAL_STATUSES:
            raise ValueError(f"unknown legal status: {self.legal_status}")
        if self.reproduction not in REPRODUCTION:
            raise ValueError(f"unknown reproduction policy: {self.reproduction}")
        if not self.redistributable and self.reproduction != "link_only":
            raise ValueError(
                f"{self.id}: a licensed source is linked, not reproduced; "
                "reproduction must be link_only")
        if self.citation_check not in CITATION_CHECKS:
            raise ValueError(f"unknown citation check: {self.citation_check}")
        if self.specification is not None and \
                self.specification not in SOURCE_SPECIFICATIONS:
            raise ValueError(f"unknown specification: {self.specification}")
        if self.fetch_method is not None and self.fetch_method not in FETCH_METHODS:
            raise ValueError(f"unknown fetch method: {self.fetch_method}")
        if (self.retrieved_at or self.content_hash) and not self.fetch_method:
            raise ValueError(
                f"{self.id}: a retrieval must say how the text was fetched")

    @property
    def citation(self) -> str:
        """Short locator for display; never a substitute for the record."""
        return self.section or self.edition or self.title

    @property
    def verified(self) -> bool:
        """Whether the provision text behind this record was actually fetched."""
        return bool(self.retrieved_at and self.content_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "framework": self.framework, "issuer": self.issuer,
            "title": self.title, "kind": self.kind, "section": self.section,
            "url": self.url, "edition": self.edition,
            "effective_date": self.effective_date,
            "application_date": self.application_date,
            "compliance_date": self.compliance_date,
            "provision_dates": [d.to_dict() for d in self.provision_dates],
            "status": self.status,
            "legal_status": self.legal_status,
            "legal_status_label": LEGAL_STATUS_LABELS[self.legal_status],
            "consolidated_as_of": self.consolidated_as_of,
            "amended_by": list(self.amended_by),
            "lifecycle": self.lifecycle,
            "lifecycle_label": LIFECYCLE_LABELS[self.lifecycle],
            "retrieved_at": self.retrieved_at, "content_hash": self.content_hash,
            "fetch_method": self.fetch_method,
            "redistributable": self.redistributable, "licence": self.licence,
            "reproduction": self.reproduction, "review_ref": self.review_ref,
            "verified": self.verified,
            "specification": self.specification,
            "citation_check": self.citation_check,
            "citation_check_label": CITATION_CHECKS[self.citation_check],
            "citation_check_note": self.citation_check_note,
            "citation": self.citation, "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
# Shared record fragments                                                      #
# --------------------------------------------------------------------------- #

_EU_LICENCE = "EU legal act published on EUR-Lex; reused as a paraphrase"
_US_FEDERAL_LICENCE = "U.S. federal regulation; public text, paraphrased here"
_CA_LICENCE = "California statute or regulation; public text, paraphrased here"
_PCI_LICENCE = "PCI SSC licence; text not redistributable"
_AICPA_LICENCE = "AICPA copyright; text not redistributable"

#: Research note carried by every EU record whose locator was only confirmed
#: from secondary sources.
_EU_SECONDARY = ("EUR-Lex refused automated access during the research, so this "
                 "was confirmed from secondary sources. Re-check it against the "
                 "Official Journal.")

_GDPR: dict[str, Any] = dict(framework="GDPR", issuer="European Parliament and Council",
             title="Regulation (EU) 2016/679 (General Data Protection Regulation)",
             kind="regulation", url="https://eur-lex.europa.eu/eli/reg/2016/679/oj",
             edition="OJ L 119, 4.5.2016", effective_date="2016-05-24",
             application_date="2018-05-25", licence=_EU_LICENCE)

#: The AI Act. Article-level records carry per-provision dates instead of the
#: Regulation's general application date, which does not hold for the
#: high-risk rules any more.
_AIACT: dict[str, Any] = dict(framework="EU AI Act", issuer="European Parliament and Council",
              title="Regulation (EU) 2024/1689 (Artificial Intelligence Act)",
              kind="regulation", url="https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
              edition="OJ L, 12.7.2024", effective_date="2024-08-01",
              licence=_EU_LICENCE)

#: The high-risk rules (Chapter III, Sections 1 to 3, which include Arts. 10,
#: 15 and 26) apply on these dates after Regulation (EU) 2026/1744.
_AIACT_HIGH_RISK_DATES = (
    ProvisionDate("High-risk AI systems listed in Annex III", "2027-12-02",
                  "As moved by Regulation (EU) 2026/1744. Re-check against "
                  "the Official Journal."),
    ProvisionDate("High-risk AI systems covered by the Union harmonisation "
                  "legislation in Annex I", "2028-08-02",
                  "As moved by Regulation (EU) 2026/1744. Re-check against "
                  "the Official Journal."),
)

_AIACT_HIGH_RISK: dict[str, Any] = dict(
    _AIACT, legal_status="future_effective",
    provision_dates=_AIACT_HIGH_RISK_DATES,
    amended_by=("aiact-omnibus-2026-1744",),
    citation_check="secondary_sources", citation_check_note=_EU_SECONDARY)

_AIACT_STAGING = ("Application is staged by Article 113, as amended by Regulation "
                  "(EU) 2026/1744: the high-risk obligations in Chapter III, "
                  "Sections 1-3 apply from 2027-12-02 for Annex III systems and "
                  "2028-08-02 for Annex I systems. These dates come from "
                  "secondary sources and must be re-checked against the "
                  "Official Journal.")

_HHS = "U.S. Department of Health and Human Services"

#: The date the HIPAA research read Part 164 through the eCFR API.
_ECFR_READ = "2026-09-23"

_ECFR_CHECKED = (f"Read from the eCFR API as of {_ECFR_READ} during the HIPAA "
                 "source research for this pack, including its "
                 "required/addressable label where it has one.")


def _ecfr(part: str, subpart: str, section: str, *, on: Optional[str] = None) -> str:
    """Deep link to one section on eCFR, optionally pinned to a dated version.

    45 CFR Parts 160 and 164 both sit under subchapter C, so the only thing
    that varies between a Part 160 definition and a Part 164 safeguard is the
    part and subpart segment. ``on`` links the point-in-time version instead
    of the current one.
    """
    version = f"on/{on}" if on else "current"
    return (f"https://www.ecfr.gov/{version}/title-45/subtitle-A/subchapter-C/"
            f"part-{part}/subpart-{subpart}/section-{section}")


#: The two original Security Rule records, both about §164.312. They keep
#: their ids because assessments, evidence reviews and policy templates were
#: authored against them; only the link was deepened to the section.
_HIPAA: dict[str, Any] = dict(framework="HIPAA", issuer=_HHS,
              title="HIPAA Security Rule, 45 CFR Part 164 Subpart C", kind="rule",
              url=("https://www.ecfr.gov/current/title-45/subtitle-A/"
                   "subchapter-C/part-164/subpart-C/section-164.312"),
              effective_date="2003-04-21", compliance_date="2005-04-20",
              licence=_US_FEDERAL_LICENCE)

#: Security Rule, 45 CFR Part 164 Subpart C. Effective 2003-04-21; most
#: covered entities had to comply by 2005-04-20. Amended by the HITECH
#: Omnibus Rule (2013).
_HIPAA_SECURITY: dict[str, Any] = dict(framework="HIPAA", issuer=_HHS, kind="rule",
                       title="HIPAA Security Rule, 45 CFR Part 164 Subpart C",
                       effective_date="2003-04-21", compliance_date="2005-04-20",
                       licence=_US_FEDERAL_LICENCE)

#: Breach Notification Rule, 45 CFR Part 164 Subpart D (HITECH Omnibus final
#: rule effective 2013-03-26, compliance 2013-09-23).
_HIPAA_BREACH: dict[str, Any] = dict(framework="HIPAA", issuer=_HHS, kind="rule",
                     title="HIPAA Breach Notification Rule, 45 CFR Part 164 Subpart D",
                     effective_date="2013-03-26", compliance_date="2013-09-23",
                     licence=_US_FEDERAL_LICENCE)

#: Privacy Rule, 45 CFR Part 164 Subpart E. The rule took effect on
#: 2001-04-14; 2003-04-14 is the compliance date for most covered entities.
_HIPAA_PRIVACY: dict[str, Any] = dict(framework="HIPAA", issuer=_HHS, kind="rule",
                      title="HIPAA Privacy Rule, 45 CFR Part 164 Subpart E",
                      effective_date="2001-04-14", compliance_date="2003-04-14",
                      licence=_US_FEDERAL_LICENCE)

#: Definitions live in Part 160, a different part of the same subchapter.
#: Published with the Privacy Rule: effective 2001-04-14, compliance 2003-04-14.
_HIPAA_DEFS: dict[str, Any] = dict(framework="HIPAA", issuer=_HHS, kind="rule",
                   title="HIPAA General Administrative Requirements, "
                         "45 CFR Part 160 Subpart A",
                   effective_date="2001-04-14", compliance_date="2003-04-14",
                   licence=_US_FEDERAL_LICENCE)

#: Applies to every implementation specification record below. §164.306(d)
#: is the provision that draws the line, so it is cited alongside the spec.
_ADDRESSABLE = ("Addressable implementation specification. Under §164.306(d)(3) "
                "an entity assesses whether the specification is a reasonable and "
                "appropriate safeguard; if it is not, it documents why and "
                "implements an equivalent alternative measure where reasonable. "
                "Addressable is not optional.")

_REQUIRED = ("Required implementation specification under §164.306(d)(2): it "
             "must be implemented as stated.")

_STANDARD = ("Standard, not an implementation specification. Standards are "
             "themselves mandatory under §164.306(c).")

_PRIVACY_SPEC = ("Privacy Rule implementation specification. The Security Rule's "
                 "required/addressable distinction does not apply to it.")

_CCPA: dict[str, Any] = dict(framework="CCPA/CPRA", issuer="State of California",
             title="California Consumer Privacy Act, as amended by the CPRA",
             kind="statute", effective_date="2020-01-01", application_date="2023-01-01",
             licence=_CA_LICENCE)

_CPPA_REGS_PDF = "https://cppa.ca.gov/regulations/pdf/ccpa_statute_eff_20260101.pdf"

#: The CPPA's regulations as consolidated from 2026-01-01.
_CPPA_REGS: dict[str, Any] = dict(framework="CCPA/CPRA",
                  issuer="California Privacy Protection Agency", kind="regulation",
                  title="CCPA Regulations, Cal. Code Regs. tit. 11, div. 6, ch. 1",
                  url=_CPPA_REGS_PDF, consolidated_as_of="2026-01-01",
                  licence=_CA_LICENCE)

_PCI: dict[str, Any] = dict(framework="PCI-DSS", issuer="PCI Security Standards Council",
            kind="contractual_standard", edition="v4.0.1",
            url="https://www.pcisecuritystandards.org/document_library/",
            redistributable=False, reproduction="link_only", licence=_PCI_LICENCE)

_PCI_LINK_ONLY = "Licensed standard: referenced by locator and link only."

_TSC_URL = ("https://www.aicpa-cima.com/resources/download/"
            "2017-trust-services-criteria-with-revised-points-of-focus-2022")

_TSC: dict[str, Any] = dict(framework="SOC 2", issuer="AICPA",
            kind="contractual_standard", edition="TSC 2017 (rev. 2022)",
            url=_TSC_URL, redistributable=False, reproduction="link_only",
            licence=_AICPA_LICENCE)


SOURCES: dict[str, RegulatorySource] = {
    source.id: source for source in [
        # ---- GDPR ------------------------------------------------------------
        RegulatorySource(id="gdpr-art-5", section="Art. 5",
                         notes="Principles relating to processing of personal data.",
                         **_GDPR),
        RegulatorySource(
            id="gdpr-art-5-1-e", section="Art. 5(1)(e)",
            citation_check="unverified",
            notes="Storage limitation: personal data is kept in a form that "
                  "identifies people for no longer than the purposes need. "
                  "Longer storage for archiving, research or statistics is "
                  "allowed with the safeguards of Art. 89(1).", **_GDPR),
        RegulatorySource(
            id="gdpr-art-5-1-f", section="Art. 5(1)(f)",
            citation_check="unverified",
            notes="Integrity and confidentiality: appropriate security of "
                  "personal data, including protection against unauthorised "
                  "or unlawful processing and accidental loss, destruction or "
                  "damage, by appropriate technical or organisational "
                  "measures.", **_GDPR),
        RegulatorySource(
            id="gdpr-art-12-3", section="Art. 12(3)",
            citation_check="secondary_sources", citation_check_note=_EU_SECONDARY,
            notes="The controller tells the data subject what it did about a "
                  "request under Arts. 15 to 22 without undue delay and within "
                  "one month of receipt. The period can be extended by two "
                  "further months where necessary, and the data subject is told "
                  "of the extension within the first month. VecShield does not "
                  "track this clock.", **_GDPR),
        RegulatorySource(id="gdpr-art-17", section="Art. 17",
                         citation_check="secondary_sources",
                         citation_check_note=_EU_SECONDARY,
                         notes="Right to erasure ('right to be forgotten').", **_GDPR),
        RegulatorySource(
            id="gdpr-art-17-3", section="Art. 17(3)",
            citation_check="secondary_sources", citation_check_note=_EU_SECONDARY,
            notes="Exceptions to erasure, where processing is necessary for "
                  "freedom of expression and information, a legal obligation or "
                  "public-interest task, public health, archiving, research or "
                  "statistics, or legal claims. Whether one applies is a legal "
                  "determination this product does not make.", **_GDPR),
        RegulatorySource(
            id="gdpr-art-19", section="Art. 19",
            citation_check="secondary_sources", citation_check_note=_EU_SECONDARY,
            notes="The controller tells each recipient to whom the data was "
                  "disclosed about an erasure, unless that proves impossible or "
                  "involves disproportionate effort, and tells the data subject "
                  "who the recipients are if asked. VecShield does not manage "
                  "that notification.", **_GDPR),
        RegulatorySource(id="gdpr-art-32", section="Art. 32",
                         notes="Security of processing.", **_GDPR),
        RegulatorySource(
            id="gdpr-art-32-1-b", section="Art. 32(1)(b)",
            citation_check="unverified",
            notes="Among the measures appropriate to the risk: the ability to "
                  "ensure the ongoing confidentiality, integrity, availability "
                  "and resilience of processing systems and services.", **_GDPR),
        RegulatorySource(
            id="edpb-cef-2025-erasure", framework="GDPR",
            issuer="European Data Protection Board",
            title="Coordinated Enforcement Framework 2025: report on the right "
                  "to erasure",
            kind="guidance", legal_status="guidance",
            edition="Adopted 2026-02-18", effective_date="2026-02-18",
            url="https://www.edpb.europa.eu/our-work-tools/our-documents_en",
            licence="EDPB publication; paraphrased here",
            citation_check="secondary_sources",
            citation_check_note="Adoption date and finding confirmed from "
                                "secondary sources. The URL is the EDPB "
                                "documents index; the report's own address is "
                                "not recorded here.",
            notes="Coordinated action by supervisory authorities on how "
                  "controllers handle erasure requests. Among its findings: "
                  "erasure often did not reach backups. Context for why the "
                  "backup statement is asked for; it is not itself an "
                  "obligation."),

        # ---- HIPAA: the two original §164.312 records ------------------------
        RegulatorySource(id="hipaa-164-312", section="45 CFR 164.312",
                         notes="Technical safeguards.", **_HIPAA),
        RegulatorySource(id="hipaa-164-312-a-1", section="45 CFR 164.312(a)(1)",
                         specification="standard", citation_check="primary_source",
                         citation_check_note=_ECFR_CHECKED,
                         notes="Access control standard. " + _STANDARD, **_HIPAA),

        # ---- Security Rule, 45 CFR Part 164 Subpart C -----------------------
        RegulatorySource(
            id="hipaa-164-304", section="45 CFR 164.304",
            url=_ecfr("164", "C", "164.304"), specification="definition",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Security Rule definitions, including 'security incident': an "
                  "attempted or successful unauthorized access, use, disclosure, "
                  "modification or destruction of information, or interference "
                  "with system operations in an information system. A "
                  "definitions section, not a standard.",
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-306-d", section="45 CFR 164.306(d)",
            url=_ecfr("164", "C", "164.306"),
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Implementation specifications: required versus addressable. "
                  "This is the provision that draws the distinction every "
                  "'(Required)'/'(Addressable)' note below depends on. "
                  "(d)(2) required specifications must be implemented; "
                  "(d)(3) addressable specifications are assessed, and where not "
                  "reasonable and appropriate the entity documents that "
                  "determination and implements an equivalent alternative "
                  "measure if reasonable and appropriate. "
                  "A 2025 proposed rule would change the Security Rule, "
                  "including this distinction; it is tracked as its own "
                  "record, hipaa-security-nprm-2025, and this pack follows the "
                  "rule in force.",
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-308-a-1-ii-a", section="45 CFR 164.308(a)(1)(ii)(A)",
            url=_ecfr("164", "C", "164.308"), specification="required",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Risk analysis. " + _REQUIRED + " An accurate and thorough "
                  "assessment of risks to the confidentiality, integrity and "
                  "availability of ePHI the entity holds — which reaches ePHI "
                  "held in a vector store and in embeddings derived from it.",
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-308-a-1-ii-b", section="45 CFR 164.308(a)(1)(ii)(B)",
            url=_ecfr("164", "C", "164.308"), specification="required",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Risk management. " + _REQUIRED,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-308-a-4", section="45 CFR 164.308(a)(4)",
            url=_ecfr("164", "C", "164.308"), specification="standard",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Information access management standard: administrative "
                  "policies and procedures for authorizing access to ePHI. "
                  + _STANDARD,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-308-a-4-ii-b", section="45 CFR 164.308(a)(4)(ii)(B)",
            url=_ecfr("164", "C", "164.308"), specification="addressable",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Access authorization. " + _ADDRESSABLE,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-308-a-4-ii-c", section="45 CFR 164.308(a)(4)(ii)(C)",
            url=_ecfr("164", "C", "164.308"), specification="addressable",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Access establishment and modification. " + _ADDRESSABLE,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-308-a-6", section="45 CFR 164.308(a)(6)",
            url=_ecfr("164", "C", "164.308"), specification="standard",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Security incident procedures standard. " + _STANDARD +
                  " 'Security incident' is defined in §164.304.",
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-308-a-6-ii", section="45 CFR 164.308(a)(6)(ii)",
            url=_ecfr("164", "C", "164.308"), specification="required",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Response and reporting. " + _REQUIRED,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-308-a-8", section="45 CFR 164.308(a)(8)",
            url=_ecfr("164", "C", "164.308"), specification="standard",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Evaluation: a periodic technical and non-technical evaluation "
                  "of how far security policies and procedures meet the rule. "
                  + _STANDARD + " It carries no implementation specifications.",
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-308-b-1", section="45 CFR 164.308(b)(1)",
            url=_ecfr("164", "C", "164.308"), specification="standard",
            notes="Business associate contracts and other arrangements. "
                  + _STANDARD + " Satisfactory assurances must be obtained before "
                  "ePHI is created, received, maintained or transmitted on the "
                  "entity's behalf.",
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-310-d-2-i", section="45 CFR 164.310(d)(2)(i)",
            url=_ecfr("164", "C", "164.310"), specification="required",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Disposal, under the device and media controls standard at "
                  "§164.310(d)(1): policies and procedures for the final "
                  "disposition of ePHI and of the hardware or electronic media "
                  "it is stored on. " + _REQUIRED + " It does not impose a "
                  "general duty to delete ePHI once it is no longer needed. "
                  "Physical safeguards are otherwise outside what this product "
                  "observes.",
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-312-a-2-i", section="45 CFR 164.312(a)(2)(i)",
            url=_ecfr("164", "C", "164.312"), specification="required",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Unique user identification. " + _REQUIRED,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-312-a-2-iv", section="45 CFR 164.312(a)(2)(iv)",
            url=_ecfr("164", "C", "164.312"), specification="addressable",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Encryption and decryption, under the access control standard. "
                  + _ADDRESSABLE,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-312-b", section="45 CFR 164.312(b)",
            url=_ecfr("164", "C", "164.312"), specification="standard",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Audit controls: hardware, software or procedural mechanisms "
                  "that record and examine activity in systems holding ePHI. "
                  + _STANDARD,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-312-c-1", section="45 CFR 164.312(c)(1)",
            url=_ecfr("164", "C", "164.312"), specification="standard",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Integrity: protect ePHI from improper alteration or "
                  "destruction. " + _STANDARD,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-312-c-2", section="45 CFR 164.312(c)(2)",
            url=_ecfr("164", "C", "164.312"), specification="addressable",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Mechanism to authenticate electronic protected health "
                  "information. " + _ADDRESSABLE,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-312-d", section="45 CFR 164.312(d)",
            url=_ecfr("164", "C", "164.312"), specification="standard",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Person or entity authentication. " + _STANDARD,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-312-e-1", section="45 CFR 164.312(e)(1)",
            url=_ecfr("164", "C", "164.312"), specification="standard",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Transmission security standard. " + _STANDARD,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-312-e-2-ii", section="45 CFR 164.312(e)(2)(ii)",
            url=_ecfr("164", "C", "164.312"), specification="addressable",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Encryption in transmission. " + _ADDRESSABLE,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-314-a", section="45 CFR 164.314(a)",
            url=_ecfr("164", "C", "164.314"),
            notes="Organizational requirements: what a business associate "
                  "contract must provide for. Read with §164.308(b)(1); this is "
                  "the content of the contract, not the duty to have one.",
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-316-b-1", section="45 CFR 164.316(b)(1)",
            url=_ecfr("164", "C", "164.316"), specification="standard",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Documentation: policies, procedures, and a written record of "
                  "any action, activity or assessment the rule requires to be "
                  "documented. " + _STANDARD,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-164-316-b-2-i", section="45 CFR 164.316(b)(2)(i)",
            url=_ecfr("164", "C", "164.316"), specification="required",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Time limit: retain the documentation for six years from its "
                  "creation date or the date it was last in effect, whichever is "
                  "later. " + _REQUIRED,
            **_HIPAA_SECURITY),
        RegulatorySource(
            id="hipaa-security-nprm-2025", framework="HIPAA", issuer=_HHS,
            kind="rule", status="proposed", legal_status="proposed",
            title="HIPAA Security Rule To Strengthen the Cybersecurity of "
                  "Electronic Protected Health Information (proposed rule)",
            section="90 FR 898 (RIN 0945-AA22)", edition="NPRM, 2025-01-06",
            url="https://www.federalregister.gov/documents/search"
                "?conditions[term]=0945-AA22",
            licence=_US_FEDERAL_LICENCE,
            citation_check="secondary_sources",
            citation_check_note="Publication confirmed during research; the "
                                "July 2027 target comes from the Fall 2025 "
                                "Unified Agenda as reported, not re-read.",
            notes="A notice of proposed rulemaking, not law. It would, among "
                  "other changes, remove the required/addressable distinction "
                  "and make encryption of ePHI generally required. The Unified "
                  "Agenda lists final action for July 2027; no final rule had "
                  "been published when this record was written. Nothing in "
                  "this pack is evaluated against it."),

        # ---- Privacy Rule, 45 CFR Part 164 Subpart E ------------------------
        RegulatorySource(
            id="hipaa-164-502-b", section="45 CFR 164.502(b)",
            url=_ecfr("164", "E", "164.502"), specification="standard",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Minimum necessary standard: limit PHI used, disclosed or "
                  "requested to the minimum necessary for the purpose. Its "
                  "implementation specifications are at §164.514(d). Exceptions "
                  "in §164.502(b)(2), including treatment disclosures, are a "
                  "legal determination this product does not make.",
            **_HIPAA_PRIVACY),
        RegulatorySource(
            id="hipaa-164-502-e", section="45 CFR 164.502(e)",
            url=_ecfr("164", "E", "164.502"), specification="standard",
            citation_check="unverified",
            citation_check_note="Added from the plan's audit (§4A.2, tagged [A]); "
                                "the locator was not re-read against eCFR.",
            notes="Disclosures to business associates: a covered entity may let "
                  "a business associate handle PHI on its behalf only with "
                  "satisfactory assurances, documented as §164.504(e) requires.",
            **_HIPAA_PRIVACY),
        RegulatorySource(
            id="hipaa-164-504-e", section="45 CFR 164.504(e)",
            url=_ecfr("164", "E", "164.504"), specification="implementation_specification",
            citation_check="unverified",
            citation_check_note="Added from the plan's audit (§4A.2, tagged [A]); "
                                "the locator was not re-read against eCFR.",
            notes="What a business associate contract must contain under the "
                  "Privacy Rule. " + _PRIVACY_SPEC,
            **_HIPAA_PRIVACY),
        RegulatorySource(
            id="hipaa-164-514-a", section="45 CFR 164.514(a)",
            url=_ecfr("164", "E", "164.514"), specification="standard",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="De-identification standard: health information that does not "
                  "identify an individual, and gives no reasonable basis to "
                  "believe it could, is not individually identifiable. The "
                  "methods for meeting it are the implementation specifications "
                  "at §164.514(b), with re-identification codes at §164.514(c).",
            **_HIPAA_PRIVACY),
        RegulatorySource(
            id="hipaa-164-514-b-1", section="45 CFR 164.514(b)(1)",
            url=_ecfr("164", "E", "164.514"),
            specification="implementation_specification",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Expert determination: a qualified person applies statistical "
                  "or scientific principles and documents the analysis. VecShield "
                  "is not that person and produces no part of that analysis. "
                  + _PRIVACY_SPEC,
            **_HIPAA_PRIVACY),
        RegulatorySource(
            id="hipaa-164-514-b-2", section="45 CFR 164.514(b)(2)",
            url=_ecfr("164", "E", "164.514"),
            specification="implementation_specification",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Safe Harbor: the eighteen identifier categories at "
                  "§164.514(b)(2)(i)(A) through (R) must be removed, and under "
                  "§164.514(b)(2)(ii) the entity must have no actual knowledge "
                  "that the remaining information could identify an individual. "
                  "Actual knowledge is not observable from content. "
                  + _PRIVACY_SPEC,
            **_HIPAA_PRIVACY),
        RegulatorySource(
            id="hipaa-164-514-c", section="45 CFR 164.514(c)",
            url=_ecfr("164", "E", "164.514"),
            specification="implementation_specification",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Re-identification: a code assigned to de-identified "
                  "information may not derive from or be translatable to "
                  "information about the individual, and the mechanism may not "
                  "be disclosed. Whether a code is derived from subject data is "
                  "not visible in chunk text. " + _PRIVACY_SPEC,
            **_HIPAA_PRIVACY),
        RegulatorySource(
            id="hipaa-164-514-d", section="45 CFR 164.514(d)",
            url=_ecfr("164", "E", "164.514"),
            specification="implementation_specification",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Minimum necessary requirements: the implementation "
                  "specifications for §164.502(b), including identifying the "
                  "workforce who need access to PHI and the categories they "
                  "need, and limiting routine disclosures and requests. "
                  + _PRIVACY_SPEC,
            **_HIPAA_PRIVACY),
        RegulatorySource(
            id="hipaa-164-524", section="45 CFR 164.524",
            url=_ecfr("164", "E", "164.524"),
            notes="Right of access: an individual's right of access to PHI in a "
                  "designated record set, with the response deadlines and "
                  "grounds for denial set out in the section.",
            **_HIPAA_PRIVACY),

        # ---- Breach Notification, 45 CFR Part 164 Subpart D -----------------
        RegulatorySource(
            id="hipaa-164-402", section="45 CFR 164.402",
            url=_ecfr("164", "D", "164.402"), specification="definition",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Definitions section, not a standard. The definition of "
                  "'breach' presumes an impermissible acquisition, access, use or "
                  "disclosure is a breach unless a risk assessment of at least "
                  "four factors — the nature and extent of the PHI including the "
                  "identifier types and likelihood of re-identification; the "
                  "unauthorized person involved; whether the PHI was actually "
                  "acquired or viewed; and the extent of mitigation — shows a "
                  "low probability of compromise. Locator note: the four factors "
                  "sit inside the definition of 'breach' rather than in a "
                  "numbered subsection of the section, so cite the definition, "
                  "not '164.402(2)' alone.",
            **_HIPAA_BREACH),
        RegulatorySource(
            id="hipaa-164-404-b", section="45 CFR 164.404(b)",
            url=_ecfr("164", "D", "164.404"),
            notes="Timeliness of notification to individuals: without "
                  "unreasonable delay and no later than 60 calendar days after "
                  "discovery. VecShield does not track this clock.",
            **_HIPAA_BREACH),
        RegulatorySource(
            id="hipaa-164-410", section="45 CFR 164.410",
            url=_ecfr("164", "D", "164.410"),
            notes="A business associate notifies the covered entity of a breach "
                  "it discovers. VecShield does not manage that notification.",
            **_HIPAA_BREACH),

        # ---- Definitions, 45 CFR Part 160 Subpart A ------------------------
        RegulatorySource(
            id="hipaa-160-103", section="45 CFR 160.103",
            url=_ecfr("160", "A", "160.103", on=_ECFR_READ),
            specification="definition", consolidated_as_of="2026-03-24",
            edition=f"eCFR point-in-time version as of {_ECFR_READ}, as amended "
                    "through 2026-03-24",
            citation_check="primary_source", citation_check_note=_ECFR_CHECKED,
            notes="Definitions, including 'electronic protected health "
                  "information', 'covered entity' and 'business associate'. "
                  "Part 160, not Part 164: a different part of the same "
                  "subchapter. The section was last amended on 2026-03-24; that "
                  "change renamed a defined term, and the link is pinned to a "
                  "dated version so a later change cannot alter what this "
                  "record describes. Whether an organization is a covered "
                  "entity or business associate is a legal determination, which "
                  "is why it is an applicability question rather than a check.",
            **_HIPAA_DEFS),

        # ---- PCI DSS (licensed: locator, link and our own few words) --------
        RegulatorySource(
            id="pci-dss-req-3", section="Requirement 3",
            title="PCI DSS v4.0.1, Requirement 3 (stored account data)",
            notes=_PCI_LINK_ONLY, **_PCI),
        RegulatorySource(
            id="pci-dss-req-3-2-1", section="Requirement 3.2.1",
            title="PCI DSS v4.0.1, Requirement 3.2.1 (account data retention)",
            citation_check="unverified",
            citation_check_note="Locator from the plan's audit (§4A.2, §4A.3); "
                                "not re-read against the licensed standard.",
            notes=_PCI_LINK_ONLY + " Concerns keeping stored account data to what "
                  "is needed and disposing of it when no longer needed. Known "
                  "coverage gap: no criterion evaluates it yet.", **_PCI),
        RegulatorySource(
            id="pci-dss-req-3-3-1", section="Requirement 3.3.1",
            title="PCI DSS v4.0.1, Requirement 3.3.1 (sensitive authentication "
                  "data after authorization)",
            citation_check="unverified",
            citation_check_note="Locator from the plan's audit (§4A.2, §4A.3); "
                                "not re-read against the licensed standard.",
            notes=_PCI_LINK_ONLY + " Concerns not keeping sensitive authentication "
                  "data, such as card verification codes, once authorization is "
                  "done. Codes pasted into support chats can end up embedded. "
                  "Known coverage gap: no criterion evaluates it yet.", **_PCI),
        RegulatorySource(
            id="pci-dss-req-3-5-1", section="Requirement 3.5.1",
            title="PCI DSS v4.0.1, Requirement 3.5.1 (protection of stored PAN)",
            notes=_PCI_LINK_ONLY + " Accepted approaches include keyed hashing of "
                  "the whole PAN (see 3.5.1.1), truncation, tokenization, and "
                  "strong encryption with managed keys.", **_PCI),
        RegulatorySource(
            id="pci-dss-req-3-5-1-2", section="Requirement 3.5.1.2",
            title="PCI DSS v4.0.1, Requirement 3.5.1.2 (storage-level encryption)",
            notes=_PCI_LINK_ONLY + " On non-removable media, encrypting the whole "
                  "disk or partition is not by itself enough to protect stored "
                  "PAN under 3.5.1.", **_PCI),
        RegulatorySource(
            id="pci-dss-req-4-2-1", section="Requirement 4.2.1",
            title="PCI DSS v4.0.1, Requirement 4.2.1 (PAN in transit over public "
                  "networks)",
            notes=_PCI_LINK_ONLY, **_PCI),
        RegulatorySource(
            id="pci-dss-req-8", section="Requirement 8",
            title="PCI DSS v4.0.1, Requirement 8 (user identification and "
                  "authentication)",
            notes=_PCI_LINK_ONLY, **_PCI),
        RegulatorySource(
            id="pci-dss-req-8-3-2", section="Requirement 8.3.2",
            title="PCI DSS v4.0.1, Requirement 8.3.2 (protection of stored and "
                  "transmitted authentication factors)",
            citation_check="unverified",
            citation_check_note="Locator from the plan's template audit (§4A.2, "
                                "tagged [A]); not re-read against the licensed "
                                "standard.",
            notes=_PCI_LINK_ONLY, **_PCI),
        RegulatorySource(
            id="pci-dss-req-8-6-2", section="Requirement 8.6.2",
            title="PCI DSS v4.0.1, Requirement 8.6.2 (no hard-coded passwords "
                  "for system and application accounts)",
            citation_check="unverified",
            citation_check_note="Locator from the plan's template audit (§4A.2, "
                                "tagged [A]); not re-read against the licensed "
                                "standard.",
            notes=_PCI_LINK_ONLY, **_PCI),

        # ---- AICPA Trust Services Criteria (licensed) ----------------------
        RegulatorySource(
            id="tsc-cc6-1", section="CC6.1",
            title="Trust Services Criteria, CC6.1 (logical access security)",
            notes="A SOC 2 conclusion is an auditor's opinion, not a scan result. "
                  "One of the points of focus for this criterion discusses using "
                  "encryption to supplement other protections for data at rest "
                  "where the assessed risk warrants it. Points of focus are "
                  "considerations, not requirements.", **_TSC),
        RegulatorySource(
            id="tsc-cc6-7", section="CC6.7",
            title="Trust Services Criteria, CC6.7 (transmission of information)",
            notes="A point of focus discusses encryption technologies or secure "
                  "communication channels. Points of focus are considerations, not "
                  "requirements; the conclusion is the auditor's opinion.", **_TSC),
        RegulatorySource(
            id="tsc-cc7-1", section="CC7.1",
            title="Trust Services Criteria, CC7.1 (detection of configuration "
                  "changes and vulnerabilities)",
            notes="Linked to the Trust Services Criteria download.", **_TSC),
        RegulatorySource(
            id="tsc-cc7-2", section="CC7.2",
            title="Trust Services Criteria, CC7.2 (monitoring for anomalies)",
            notes="Linked to the Trust Services Criteria download.", **_TSC),

        # ---- CCPA/CPRA -------------------------------------------------------
        RegulatorySource(
            id="ccpa-1798-105", section="Cal. Civ. Code § 1798.105",
            url="https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.105",
            notes="Consumers' right to delete personal information.", **_CCPA),
        RegulatorySource(
            id="ccpa-1798-105-d", section="Cal. Civ. Code § 1798.105(d)",
            url="https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.105",
            citation_check="primary_source",
            notes="Exceptions: a business or service provider need not delete "
                  "personal information that is reasonably necessary for listed "
                  "purposes, among them completing the transaction, security and "
                  "integrity, debugging, a legal obligation, and some internal "
                  "uses compatible with the consumer's expectations. Whether one "
                  "applies is a legal determination.", **_CCPA),
        RegulatorySource(
            id="ccpa-regs-7022", section="Cal. Code Regs. tit. 11, § 7022",
            citation_check="primary_source",
            notes="Requests to delete: how a business, service provider or "
                  "contractor handles them. Paragraph (d) lets a business delay "
                  "deleting personal information held on archived or backup "
                  "systems until that system is restored to active use or is "
                  "next accessed or used for a sale, disclosure or commercial "
                  "purpose.", **_CPPA_REGS),
        RegulatorySource(
            id="ccpa-cppa-cyberaudit", framework="CCPA/CPRA",
            issuer="California Privacy Protection Agency",
            title="CCPA Regulations, Cal. Code Regs. tit. 11, cybersecurity audits",
            kind="regulation", section="Cal. Code Regs. tit. 11, § 7123(c)(2)",
            effective_date="2026-01-01", url=_CPPA_REGS_PDF,
            consolidated_as_of="2026-01-01", licence=_CA_LICENCE,
            citation_check="primary_source",
            notes="Article 9 (§§ 7120-7124), approved by the Office of "
                  "Administrative Law on 2025-09-22. § 7123(c)(2) names "
                  "encryption of personal information, at rest and in transit, "
                  "as a component the cybersecurity audit assesses — if "
                  "applicable, as the auditor deems applicable (§ 7123(b)(2)). "
                  "It says what the audit assesses; it does not by itself "
                  "require the business to encrypt. "
                  "Thresholds, § 7120(b): the business meets Civ. Code § "
                  "1798.140(d)(1)(C), or meets (d)(1)(A) and in the preceding "
                  "year processed personal information of 250,000 or more "
                  "consumers or households, or sensitive personal information "
                  "of 50,000 or more consumers. First audit report due April 1 "
                  "of 2028, 2029 or 2030, set by gross revenue (§ 7121(a)); "
                  "annual thereafter (§ 7121(b)). Certification: § 7124."),
        RegulatorySource(
            id="ccpa-regs-7123-c-3", section="Cal. Code Regs. tit. 11, § 7123(c)(3)",
            effective_date="2026-01-01", citation_check="primary_source",
            notes="Account management and access controls, named as a component "
                  "the cybersecurity audit assesses where applicable. Like "
                  "§ 7123(c)(2), it describes the audit's scope rather than "
                  "imposing a control on its own.", **_CPPA_REGS),

        # ---- EU AI Act -------------------------------------------------------
        RegulatorySource(
            id="aiact-art-10", section="Art. 10",
            notes="Data and data governance for high-risk AI systems: a "
                  "provider's duty covering training, validation and testing "
                  "data sets. Kept only as a provider-side informational note. "
                  "No criterion in this pack cites it, because a deployer's "
                  "retrieval corpus is closer to input data under Art. 26(4). "
                  + _AIACT_STAGING, **_AIACT_HIGH_RISK),
        RegulatorySource(id="aiact-art-15", section="Art. 15",
                         notes="Accuracy, robustness and cybersecurity. States no "
                               "encryption requirement. " + _AIACT_STAGING,
                         **_AIACT_HIGH_RISK),
        RegulatorySource(
            id="aiact-art-15-5", section="Art. 15(5)",
            notes="High-risk AI systems are to resist attempts by unauthorised "
                  "third parties to change their use, outputs or performance by "
                  "exploiting vulnerabilities. The technical solutions address, "
                  "where appropriate, data poisoning, model poisoning, "
                  "adversarial inputs, confidentiality attacks and model flaws. "
                  "Art. 15 is a requirement on the system; making the system "
                  "meet it is the provider's obligation (Art. 16). "
                  + _AIACT_STAGING, **_AIACT_HIGH_RISK),
        RegulatorySource(
            id="aiact-art-26-4", section="Art. 26(4)",
            notes="Deployer obligation: where the deployer controls the input "
                  "data, it makes sure that data is relevant to, and "
                  "sufficiently representative for, the system's intended "
                  "purpose. " + _AIACT_STAGING, **_AIACT_HIGH_RISK),
        RegulatorySource(
            id="aiact-omnibus-2026-1744", framework="EU AI Act",
            issuer="European Parliament and Council",
            title="Regulation (EU) 2026/1744 (Digital Omnibus on AI)",
            kind="regulation", section="amending Art. 113",
            url="https://eur-lex.europa.eu/eli/reg/2026/1744/oj",
            edition="OJ L, 24.7.2026", effective_date="2026-07-27",
            licence=_EU_LICENCE,
            citation_check="secondary_sources", citation_check_note=_EU_SECONDARY,
            notes="In force from 2026-07-27. Moves the application of the "
                  "high-risk obligations, Arts. 10, 15 and 26 among them, to "
                  "2027-12-02 (Annex III) and 2028-08-02 (Annex I). Dates from "
                  "secondary sources; re-check against the Official Journal."),

        # ---- Cryptographic posture (docs/crypto_posture.md) -------------
        RegulatorySource(
            id="gdpr-art-32-1-a", section="Art. 32(1)(a)",
            notes="Pseudonymisation and encryption of personal data, named among "
                  "the measures a controller or processor implements as "
                  "appropriate to the risk. Risk-based, not universally "
                  "mandatory.", **_GDPR),
        RegulatorySource(
            id="ccpa-1798-150", section="Cal. Civ. Code § 1798.150",
            url="https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.150",
            notes="Private right of action where nonencrypted and nonredacted "
                  "personal information (as defined in § 1798.81.5(d)(1)(A)) is "
                  "breached following a failure to "
                  "maintain reasonable security. Supporting context for the "
                  "encryption criterion, not an encryption mandate.", **_CCPA),
        RegulatorySource(
            id="vecshield-baseline", framework="General", issuer="VecShield",
            title="VecShield vector-store security baseline", kind="internal_policy",
            status="internal", legal_status="guidance",
            lifecycle="technically_validated", licence="VecShield",
            notes="Product security guidance, not a legal or contractual obligation."),
    ]
}


def get_source(source_id: str) -> Optional[RegulatorySource]:
    return SOURCES.get(source_id)


def _unresolved(source_id: str) -> dict[str, Any]:
    """The record shown for an id with no maintained source behind it."""
    return {"id": source_id, "framework": None, "issuer": None,
            "title": "Unresolved source reference", "kind": None,
            "section": None, "url": None, "edition": None,
            "effective_date": None, "application_date": None,
            "compliance_date": None, "provision_dates": [],
            "status": "unresolved", "legal_status": None,
            "legal_status_label": "Unknown", "consolidated_as_of": None,
            "amended_by": [], "lifecycle": "draft",
            "lifecycle_label": LIFECYCLE_LABELS["draft"],
            "retrieved_at": None, "content_hash": None, "fetch_method": None,
            "redistributable": True, "licence": None, "reproduction": "link_only",
            "review_ref": None, "verified": False, "specification": None,
            "citation_check": "not_recorded",
            "citation_check_label": CITATION_CHECKS["not_recorded"],
            "citation_check_note": "", "citation": source_id,
            "notes": "No maintained record for this id."}


def resolve_sources(source_ids: list[str]) -> list[dict[str, Any]]:
    """Resolve ids to source records, skipping nothing silently.

    An unknown id yields an explicit unresolved record so a broken reference is
    visible in the UI instead of disappearing from the attribution.
    """
    return [SOURCES[source_id].to_dict() if source_id in SOURCES
            else _unresolved(source_id) for source_id in source_ids]


def least_advanced(states: list[str]) -> str:
    """The least advanced lifecycle state in ``states``; ``draft`` when empty."""
    if not states:
        return "draft"
    return min(states, key=LIFECYCLE.index)
