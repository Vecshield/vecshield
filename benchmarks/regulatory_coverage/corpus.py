"""The corpus: one obligation per case, with the span that carries it.

Every case is synthetic and written for this repository. The people are
invented, the credentials are values their vendors publish as examples, the
card numbers are the networks' test numbers, and the national identifiers are
check-digit-valid values computed for the purpose. Nothing here is real, and
the whole file is redistributable — which the public de-identification corpora
under a data use agreement are not.

Two design choices worth defending:

**Cases are indexed by obligation, not by detector.** A benchmark organised by
detector measures whether a tool reproduces *our* taxonomy. Organised by
obligation, it measures whether a tool would answer a regulator's question,
which is the thing a competing classifier can do better or worse than we do.

**Hard negatives carry the same weight as positives.** Over-flagging is the
failure mode that makes a compliance tool unusable: a reviewer who is shown a
hundred spurious findings stops reading them. Each negative names what it is
bait for, so a run that starts flagging it reports a precision regression
against a specific rule rather than a drifting aggregate.

Gold spans are declared as literal substrings and resolved to offsets at load
time. A case whose substring is not present, or is present more than once, is
a corpus bug and raises rather than silently scoring zero.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from benchmarks.ai4privacy.normalize.schema import Annotation, EvalSample

#: Frameworks as the criterion pack names them.
REGULATIONS = ("GDPR", "HIPAA", "PCI-DSS", "SOC 2", "CCPA/CPRA", "EU AI Act")


@dataclass(frozen=True)
class Case:
    """One document, and the obligation it exists to test."""

    id: str
    regulation: str
    #: The obligation in the product's own words. Not the regulation's text.
    obligation: str
    #: Provision locator, where one provision clearly governs.
    provision: str
    text: str
    #: (substring, category) pairs. Empty for a hard negative.
    spans: list[tuple[str, str]] = field(default_factory=list)
    #: For a negative: what the case is bait for, and why it must not fire.
    bait: str = ""
    #: For a negative: the categories that must not be reported. Naming them
    #: rather than demanding silence is the difference between a fair test and
    #: a rigged one. "An IMEI is not payment card data" is a claim about the
    #: PCI label; reporting the IMEI as a device identifier is correct, and a
    #: negative that failed the run for it would be measuring the wrong thing.
    #: Empty means nothing at all may be reported.
    must_not: tuple[str, ...] = ()

    @property
    def is_negative(self) -> bool:
        return not self.spans

    def to_sample(self) -> EvalSample:
        gold: list[Annotation] = []
        for needle, category in self.spans:
            first = self.text.find(needle)
            if first < 0:
                raise ValueError(f"{self.id}: gold span {needle!r} is not in the text")
            if self.text.find(needle, first + 1) >= 0:
                raise ValueError(
                    f"{self.id}: gold span {needle!r} appears more than once; "
                    "make it unambiguous rather than scoring the wrong one")
            gold.append(Annotation(start=first, end=first + len(needle),
                                   entity_type=category, text=needle))
        return EvalSample(id=self.id, text=self.text, gold=gold,
                          source=self.regulation)


CASES: list[Case] = [
    # ------------------------------------------------------------------ GDPR
    Case("gdpr-art9-union", "GDPR",
         "Trade union membership is special-category data.", "Art. 9(1)",
         "Escalation note: the complainant is a union member and asked that "
         "his steward attend the hearing.",
         [("union member", "SPECIAL_CATEGORY")]),
    Case("gdpr-art9-orientation", "GDPR",
         "Sexual orientation is special-category data.", "Art. 9(1)",
         "The customer came out as gay during the call and asked us not to "
         "record it on the account.",
         [("came out as gay", "SPECIAL_CATEGORY")]),
    Case("gdpr-art9-politics", "GDPR",
         "Political opinions are special-category data.", "Art. 9(1)",
         "Survey export row: political affiliation: Green Party, contact "
         "preference email.",
         [("political affiliation: Green Party", "SPECIAL_CATEGORY")]),
    Case("gdpr-art9-religion", "GDPR",
         "Religious or philosophical beliefs are special-category data.",
         "Art. 9(1)",
         "Dietary request form: religion: Muslim, no pork, halal where "
         "available.",
         [("religion: Muslim", "SPECIAL_CATEGORY")]),
    Case("gdpr-art9-ethnicity", "GDPR",
         "Racial or ethnic origin is special-category data.", "Art. 9(1)",
         "Monitoring record: ethnicity: Black British, collected for equality "
         "reporting under the published policy.",
         [("ethnicity: Black British", "SPECIAL_CATEGORY")]),
    Case("gdpr-art9-genetic", "GDPR",
         "Genetic data is special-category data.", "Art. 4(13), Art. 9(1)",
         "Counselling summary: the patient carries variant "
         "NM_000059.3:c.1234del and was referred for BRCA1 genetic testing.",
         [("NM_000059.3:c.1234del", "SPECIAL_CATEGORY"),
          ("BRCA1 genetic testing", "SPECIAL_CATEGORY")]),
    Case("gdpr-art9-biometric", "GDPR",
         "Biometric data for unique identification is special-category data.",
         "Art. 4(14), Art. 9(1)",
         "Onboarding log: enrolled the customer's voiceprint for telephone "
         "banking on the second attempt.",
         [("voiceprint", "SPECIAL_CATEGORY")]),
    Case("gdpr-art10-conviction", "GDPR",
         "Criminal convictions and offences have their own regime.", "Art. 10",
         "Vetting outcome: the applicant was convicted of fraud in 2019 and "
         "disclosed it on the form.",
         [("convicted of fraud", "CRIMINAL_OFFENCE")]),
    Case("gdpr-art8-child", "GDPR",
         "A child's personal data carries a different consent regime.",
         "Art. 8",
         "Support ticket: the account holder is 9 years old, so we need "
         "parental consent before the newsletter opt-in.",
         [("9 years old", "PII"), ("parental consent", "PII")]),
    # National identifiers. Each embeds a date of birth, so one match is more
    # than one identifier.
    Case("gdpr-id-fr", "GDPR", "A national identifier is personal data.",
         "Art. 4(1)",
         "Dossier: NIR 2 69 05 49 588 157 80 transmis par le service RH.",
         [("NIR 2 69 05 49 588 157 80", "PII")]),
    Case("gdpr-id-pl", "GDPR", "A national identifier is personal data.",
         "Art. 4(1)",
         "Zgloszenie: PESEL 44051401359 podany przez klienta.",
         [("PESEL 44051401359", "PII")]),
    Case("gdpr-id-de", "GDPR", "A national identifier is personal data.",
         "Art. 4(1)",
         "Steuerakte: Steuer-ID 86 095 742 719 wurde uebermittelt.",
         [("Steuer-ID 86 095 742 719", "PII")]),
    Case("gdpr-id-es", "GDPR", "A national identifier is personal data.",
         "Art. 4(1)",
         "Expediente del cliente con DNI 12345678Z adjunto al caso.",
         [("DNI 12345678Z", "PII")]),
    Case("gdpr-id-se", "GDPR", "A national identifier is personal data.",
         "Art. 4(1)",
         "Kundregister: personnummer 811218-9876 enligt underlaget.",
         [("personnummer 811218-9876", "PII")]),
    Case("gdpr-id-fi", "GDPR", "A national identifier is personal data.",
         "Art. 4(1)",
         "Asiakastiedot: henkilotunnus 131052-308T kirjattu.",
         [("henkilotunnus 131052-308T", "PII")]),
    Case("gdpr-erasure-subject", "GDPR",
         "Contact data identifying a subject who may request erasure.",
         "Art. 17",
         "Erasure request received from priya.raman@example.org, phone "
         "+44 20 7946 0958, reference ER-2026-114.",
         [("priya.raman@example.org", "PII"), ("+44 20 7946 0958", "PII")]),

    # ----------------------------------------------------------------- HIPAA
    Case("hipaa-sh-identifiers", "HIPAA",
         "Safe Harbor identifiers must be removed for de-identification.",
         "45 CFR 164.514(b)(2)(i)",
         "Discharge letter: MRN: A1234567, DOB: 1968-03-11, contact "
         "j.okafor@example.org.",
         [("MRN: A1234567", "PHI"), ("DOB: 1968-03-11", "PHI"),
          ("j.okafor@example.org", "PHI")]),
    Case("hipaa-min-necessary", "HIPAA",
         "A retrieval corpus holds no more PHI than its purpose needs.",
         "45 CFR 164.502(b)",
         "Guidance corpus entry (misfiled): clinic letter for a patient with "
         "medical record number MR4471829 and a date of birth of 1954-08-02.",
         [("MR4471829", "PHI"), ("1954-08-02", "PHI")]),
    Case("hipaa-vocab-ndc", "HIPAA",
         "Clinical codes are identifiers and health context.",
         "45 CFR 164.514(b)(2)(i)",
         "Pharmacy reconciliation: dispensed NDC 0069-4200-30 on admission, "
         "quantity thirty.",
         [("NDC 0069-4200-30", "PHI")]),
    Case("hipaa-vocab-cpt", "HIPAA",
         "Clinical codes are identifiers and health context.",
         "45 CFR 164.514(b)(2)(i)",
         "Billing export line: procedure code 99213 with modifier 25 applied.",
         [("procedure code 99213", "PHI")]),
    Case("hipaa-accession", "HIPAA",
         "A specimen identifier is a unique identifying code.",
         "45 CFR 164.514(b)(2)(i)(R)",
         "Pathology report header, Specimen No: S24-004512, reported by the "
         "duty registrar.",
         [("Specimen No: S24-004512", "PHI")]),
    Case("hipaa-trial", "HIPAA",
         "A trial registry number is a certificate or licence number.",
         "45 CFR 164.514(b)(2)(i)(K)",
         "The participant was enrolled in NCT01234567 and withdrew at week "
         "twelve.",
         [("NCT01234567", "PHI")]),
    Case("hipaa-device", "HIPAA",
         "A device identifier is a Safe Harbor identifier.",
         "45 CFR 164.514(b)(2)(i)(M)",
         "Handset issued to the ward, IMEI 49-015420-323751-8, returned on "
         "discharge.",
         # PHI, not PII: the surrounding text is a ward record, and a device
         # identifier tied to a patient is a Safe Harbor identifier. The first
         # draft of this case said PII and the benchmark reported a miss the
         # engine had not made.
         [("IMEI 49-015420-323751-8", "PHI")]),

    # --------------------------------------------------------------- PCI DSS
    Case("pci-pan", "PCI-DSS",
         "Account data must not be retained in the store unprotected.",
         "Requirement 3",
         "Dispute note: customer quoted card 4111 1111 1111 1111 expiring "
         "12/27 for the chargeback.",
         [("4111 1111 1111 1111", "PCI")]),
    Case("pci-track1", "PCI-DSS",
         "Sensitive authentication data must not be retained after "
         "authorisation.", "Requirement 3.3.1",
         "Terminal log line: %B4111111111111111^DOE/JANE^2512101000000000000000000? "
         "captured during the outage.",
         [("%B4111111111111111^DOE/JANE^2512101000000000000000000?", "PCI")]),
    Case("pci-track2", "PCI-DSS",
         "Sensitive authentication data must not be retained after "
         "authorisation.", "Requirement 3.3.1",
         "Raw read from the reader: ;4111111111111111=25121010000000000000? "
         "before the retry.",
         [(";4111111111111111=25121010000000000000?", "PCI")]),
    Case("pci-pin-block", "PCI-DSS",
         "A PIN block must never be retained.", "Requirement 3.3.1",
         "Debug capture attached to the ticket: PIN block: A1B2C3D4E5F60718 "
         "from the failed transaction.",
         [("PIN block: A1B2C3D4E5F60718", "PCI")]),
    Case("pci-iban", "PCI-DSS",
         "Financial account data in the store.", "Requirement 3",
         "Refund instruction quoting IBAN GB82 WEST 1234 5698 7654 32 for the "
         "settlement.",
         [("GB82 WEST 1234 5698 7654 32", "PCI")]),

    # ----------------------------------------------------------------- SOC 2
    Case("soc2-aws", "SOC 2",
         "Credentials are not stored in the embedded data layer.", "CC6.1",
         "Runbook step four: export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE "
         "before running the sync.",
         [("AKIAIOSFODNN7EXAMPLE", "SECRET")]),
    Case("soc2-azure", "SOC 2",
         "Credentials are not stored in the embedded data layer.", "CC6.1",
         "Connection string pasted into the incident timeline: "
         "DefaultEndpointsProtocol=https;AccountName=demo;AccountKey="
         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; "
         "rotated afterwards.",
         [("DefaultEndpointsProtocol=https;AccountName=demo;AccountKey="
           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
           "SECRET")]),
    Case("soc2-gcp", "SOC 2",
         "Credentials are not stored in the embedded data layer.", "CC6.1",
         'Service account blob in the vendor doc: {"type": "service_account", '
         '"project_id": "demo-analytics"}',
         [('"type": "service_account"', "SECRET")]),
    Case("soc2-private-key", "SOC 2",
         "Credentials are not stored in the embedded data layer.", "CC6.1",
         "Appendix: -----BEGIN PGP PRIVATE KEY BLOCK----- was committed to "
         "the wiki by mistake.",
         [("-----BEGIN PGP PRIVATE KEY BLOCK-----", "SECRET")]),

    # ------------------------------------------------------------ CCPA/CPRA
    Case("ccpa-spi-login", "CCPA/CPRA",
         "Log-in credentials in combination are sensitive personal "
         "information.", "Cal. Civ. Code s 1798.140(ae)",
         "Support transcript: the user gave their username as r.mcallister "
         "and password Hunter2Hunter2 so we could reproduce the fault.",
         [("r.mcallister", "PII"), ("Hunter2Hunter2", "SECRET")]),
    Case("ccpa-spi-geo", "CCPA/CPRA",
         "Precise geolocation is sensitive personal information.",
         "Cal. Civ. Code s 1798.140(ae)",
         "Telemetry row: last known position 37.774929, -122.419416 recorded "
         "at the time of the crash.",
         [("37.774929, -122.419416", "PII")]),
    Case("ccpa-delete-subject", "CCPA/CPRA",
         "A consumer deletion request must reach the embeddings.",
         "Cal. Civ. Code s 1798.105",
         "Deletion request from d.whitfield@example.net for all records tied "
         "to order 55120.",
         [("d.whitfield@example.net", "PII")]),

    # -------------------------------------------------------- EU AI Act
    Case("aiact-corpus-governance", "EU AI Act",
         "A high-risk system's retrieval corpus is governed, including the "
         "personal data in it.", "Art. 10",
         "Community contribution accepted without review: applicant "
         "s.nakamura@example.org, ethnicity: Japanese, added to the training "
         "corpus.",
         [("s.nakamura@example.org", "PII"),
          ("ethnicity: Japanese", "SPECIAL_CATEGORY")]),

    # ------------------------------------------------- hard negatives
    # Each names its bait. A run that starts flagging one of these is a
    # precision regression against a named rule, not a drifting average.
    Case("neg-union-eu", "GDPR", "Topic mention is not membership.",
         "Art. 9(1)",
         "The European Union published new guidance on retrieval systems this "
         "morning and we should read it.",
         bait="the word 'union' without membership",
         must_not=("SPECIAL_CATEGORY",)),
    Case("neg-religion-policy", "GDPR", "A policy is not a belief.",
         "Art. 9(1)",
         "We observe religious holidays in the leave policy and staff may "
         "swap public holidays.",
         bait="religious vocabulary in an HR policy",
         must_not=("SPECIAL_CATEGORY",)),
    Case("neg-charged-invoice", "GDPR", "Billing is not a conviction.",
         "Art. 10",
         "You were charged with the invoice amount in error and we have "
         "issued a credit note.",
         bait="'charged with' in its billing sense",
         must_not=("CRIMINAL_OFFENCE",)),
    Case("neg-adult-age", "GDPR", "An adult age is not a child's data.",
         "Art. 8",
         "The account holder is 42 years old and has been with us since the "
         "beta programme.",
         bait="an adult age, which must not read as health data",
         must_not=("PHI",)),
    Case("neg-phi-template", "HIPAA",
         "A template placeholder is not a disclosure.",
         "45 CFR 164.514(b)(2)(i)",
         "Letter template: Dear [PATIENT NAME], your appointment on [DATE] "
         "with [CLINICIAN] is confirmed.",
         bait="clinical letter shape with no identifiers",
         must_not=("PHI", "PII")),
    Case("neg-phi-age-only", "HIPAA",
         "An age under 90 is not a Safe Harbor identifier on its own.",
         "45 CFR 164.514(b)(2)(i)(C)",
         "Pathway guidance: an 18-year-old female presenting with polyuria "
         "should be screened for diabetes.",
         bait="clinical vocabulary plus an age below ninety",
         must_not=("PHI",)),
    Case("neg-pci-order", "PCI-DSS", "A number that fails Luhn is not a PAN.",
         "Requirement 3",
         "Order reference 1234567890123456 was raised against the wrong "
         "account and cancelled.",
         bait="a sixteen-digit number that fails the check digit",
         must_not=("PCI",)),
    Case("neg-pci-masked", "PCI-DSS", "A truncated PAN is permitted.",
         "Requirement 3.4",
         "Compliant record retained for the audit: 411111******1111 with the "
         "authorisation code only.",
         bait="a masked PAN, which is what the rule asks for",
         must_not=("PCI",)),
    Case("neg-secret-hash", "SOC 2", "A build hash is not a credential.",
         "CC6.1",
         "The pipeline recorded checksum a1b2c3d4e5f60718 for the artefact "
         "and published it.",
         bait="sixteen hex characters that are not a PIN block",
         must_not=("PCI", "SECRET")),
    Case("neg-secret-fingerprint", "SOC 2",
         "A certificate fingerprint is not biometric data.", "CC6.1",
         "Rotate the endpoint when the TLS certificate fingerprint SHA256 "
         "changes without a release.",
         bait="the word 'fingerprint' in its cryptographic sense",
         must_not=("SPECIAL_CATEGORY",)),
    Case("neg-genetic-ticket", "GDPR", "A ticket reference is not an rsID.",
         "Art. 9(1)",
         "Ticket rs12 filed against the ingest worker and closed the same "
         "day by the on-call engineer.",
         bait="an 'rs' prefix that is not a dbSNP identifier",
         must_not=("SPECIAL_CATEGORY",)),
    Case("neg-imei-not-card", "PCI-DSS",
         "A device identifier is not payment card data.", "Requirement 3",
         "Device inventory row: handset IMEI 49-015420-323751-8 assigned to "
         "the field team.",
         bait="a Luhn-valid fifteen-digit number that is not a card",
         must_not=("PCI",)),
]


def load_corpus(regulation: str | None = None) -> list[EvalSample]:
    """Build evaluation samples, optionally for one framework."""
    cases = [c for c in CASES if regulation is None or c.regulation == regulation]
    return [c.to_sample() for c in cases]


def case_index() -> dict[str, Case]:
    return {c.id: c for c in CASES}


def corpus_manifest() -> dict[str, object]:
    """What the corpus covers, for the report header."""
    by_regulation: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for case in CASES:
        by_regulation[case.regulation] = by_regulation.get(case.regulation, 0) + 1
        for _, category in case.spans:
            by_category[category] = by_category.get(category, 0) + 1
    return {
        "cases": len(CASES),
        "positives": sum(1 for c in CASES if not c.is_negative),
        "hard_negatives": sum(1 for c in CASES if c.is_negative),
        "gold_spans": sum(len(c.spans) for c in CASES),
        "by_regulation": dict(sorted(by_regulation.items())),
        "by_category": dict(sorted(by_category.items())),
        "provenance": (
            "Synthetic and wholly owned by this repository. Invented people, "
            "vendor-published example credentials, network test card numbers, "
            "and check-digit-valid national identifiers computed for the "
            "purpose. Redistributable without a data use agreement."),
        "note": (
            "Coverage of a category is not evidence that a detector is "
            "accurate on real data. This corpus asks whether a classifier "
            "sees the category at all, and whether it stays quiet on the "
            "hard negative beside it."),
    }
