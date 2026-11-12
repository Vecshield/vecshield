"""Coverage run for every built-in regex detector.

These samples are synthetic and intentionally high-signal. The goal is to make
sure the default regex engine exercises each detector class without requiring
optional NLP dependencies.
"""

from __future__ import annotations

import pytest

from vecshield.classify import classify_text
from vecshield.classify.regex_classifier import DETECTORS
from vecshield.models import SensitivityLabel

DETECTION_CASES = {
    "us_ssn": ("SSN 123-45-6789", SensitivityLabel.PII),
    "email": ("contact privacy@example.com", SensitivityLabel.PII),
    "us_phone": ("call +1 (415) 555-0132", SensitivityLabel.PII),
    "ipv4_address": ("last login from 203.0.113.42", SensitivityLabel.PII),
    "ipv6_address": (
        "last login from 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        SensitivityLabel.PII,
    ),
    "mac_address": ("device mac address 00:1A:2B:3C:4D:5E", SensitivityLabel.PII),
    "date_of_birth": ("DOB: 1980-01-02", SensitivityLabel.PII),
    "us_street_address": (
        "Ship to 123 Main Street Apt 4B tomorrow.",
        SensitivityLabel.PII,
    ),
    "us_zip_context": ("postal code: 94105-1234", SensitivityLabel.PII),
    "us_driver_license_context": ("driver license: D1234567", SensitivityLabel.PII),
    "passport_context": ("passport number X12345678", SensitivityLabel.PII),
    "tax_id_context": ("EIN: 12-3456789", SensitivityLabel.PII),
    "uk_nino_context": ("NI number: AB 12 34 56 C", SensitivityLabel.PII),
    "canada_sin_context": ("SIN: 046 454 286", SensitivityLabel.PII),
    "bank_routing": ("routing number 011000015", SensitivityLabel.PII),
    "bank_account_context": ("bank account: 123456789012", SensitivityLabel.PII),
    "iban": ("IBAN GB82 WEST 1234 5698 7654 32", SensitivityLabel.PCI),
    "medical_record_context": ("MRN: A1234567", SensitivityLabel.PHI),
    "us_medicare_mbi_context": ("Medicare number: 1EG4-TE5-MK73", SensitivityLabel.PHI),
    "npi_context": ("NPI: 1234567893", SensitivityLabel.PHI),
    "metadata_identifier": ("customer_id: cus_12345", SensitivityLabel.PII),
    "credit_card": ("card 4111 1111 1111 1111", SensitivityLabel.PCI),
    "aws_access_key": ("aws key AKIAIOSFODNN7EXAMPLE", SensitivityLabel.SECRET),
    "github_token": (
        "github token ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
        SensitivityLabel.SECRET,
    ),
    "slack_token": (
        "slack token xoxb-123456789012-123456789012-abcdefghijklmnopqrstuv",
        SensitivityLabel.SECRET,
    ),
    "google_api_key": ("google key AIza" + "A" * 35, SensitivityLabel.SECRET),
    "openai_key": ("openai key sk-proj-" + "A" * 24, SensitivityLabel.SECRET),
    "generic_secret_context": (
        "password = syntheticPassword12345",
        SensitivityLabel.SECRET,
    ),
    "bearer_token_context": (
        "Authorization: Bearer " + "a" * 32,
        SensitivityLabel.SECRET,
    ),
    "private_key_block": ("-----BEGIN PRIVATE KEY-----", SensitivityLabel.SECRET),
    "jwt": (
        "jwt eyJaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc",
        SensitivityLabel.SECRET,
    ),
    # International government IDs
    "india_pan": ("PAN card ABCPE1234F", SensitivityLabel.PII),
    "india_aadhaar_context": ("aadhaar 2345 6789 0123", SensitivityLabel.PII),
    "brazil_cpf_context": ("CPF 529.982.247-25", SensitivityLabel.PII),
    "china_resident_id": ("ID: 110101199003071233", SensitivityLabel.PII),
    "singapore_nric": ("NRIC S1234567D", SensitivityLabel.PII),
    "italy_fiscal_code": ("codice fiscale RSSMRA80A01H501T", SensitivityLabel.PII),
    "mexico_curp": ("CURP BADD110313HCMNNL09", SensitivityLabel.PII),
    "netherlands_bsn_context": ("BSN 123456782", SensitivityLabel.PII),
    "south_africa_id_context": (
        "South African ID 8001015009087",
        # credit_card (PCI) also fires on any 13-digit Luhn-valid number
        SensitivityLabel.PCI,
    ),
    "australia_tfn_context": ("tax file number 123 456 782", SensitivityLabel.PII),
    "uk_nhs_context": ("NHS number 401 023 2137", SensitivityLabel.PHI),
    "uk_utr_context": ("UTR 1234567890", SensitivityLabel.PII),
    # Additional financial
    "us_itin": ("ITIN 912-78-1234", SensitivityLabel.PII),
    "credit_card_cvv_context": ("CVV: 123", SensitivityLabel.PCI),
    "credit_card_expiry_context": ("expiry 12/26", SensitivityLabel.PCI),
    "swift_bic_code": ("SWIFT: DEUTDEDB", SensitivityLabel.PCI),
    # Additional PHI
    "us_dea_number_context": ("DEA number AB1234563", SensitivityLabel.PHI),
    "icd_code_context": ("ICD-10: A00.1", SensitivityLabel.PHI),
    # Platform secrets
    "stripe_api_key": ("sk_live_abcdefghijklmnopqrstuvwx", SensitivityLabel.SECRET),
    "anthropic_api_key": ("sk-ant-" + "a" * 70, SensitivityLabel.SECRET),
    "huggingface_token": ("hf_" + "a" * 34, SensitivityLabel.SECRET),
    "sendgrid_api_key": (
        "SG." + "a" * 22 + "." + "a" * 43,
        SensitivityLabel.SECRET,
    ),
    "npm_token": ("npm_" + "a" * 36, SensitivityLabel.SECRET),
    "database_url_credentials": (
        "postgres://admin:s3cr3tPass@db.example.com/prod",
        SensitivityLabel.SECRET,
    ),
    "basic_auth_header": (
        "Authorization: Basic dXNlcjpwYXNzd29yZA==",
        SensitivityLabel.SECRET,
    ),
    # Coverage-driven additions (ai4privacy benchmark)
    "ethereum_address": (
        "wallet 0xabcdef0123456789abcdef0123456789abcdef01",
        SensitivityLabel.PCI,
    ),
    "btc_ltc_address": (
        "send to 3rw7ivtioGVenUx3v1e28rAdxnhnueYU",
        SensitivityLabel.PCI,
    ),
    "user_agent_string": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15)",
        SensitivityLabel.PII,
    ),
    "gps_coordinate": ("location [-27.7672,27.6475]", SensitivityLabel.PII),
    "imei_number": ("device IMEI 49-015420-323751-8", SensitivityLabel.PII),
    "secondary_address": ("mailing Apt. 367", SensitivityLabel.PII),
    "county_name": ("resides in Franklin County", SensitivityLabel.PII),
    "zip_plus4": ("region 48076-1234", SensitivityLabel.PII),
    "us_ssn_spaced": ("SSN 410 51 2611", SensitivityLabel.PII),
    "us_ssn_context": ("SSN 987-65-4321", SensitivityLabel.PII),
    "prefixed_id": ("case ref HP-678901", SensitivityLabel.PII),
    "credit_card_issuer": ("payment via mastercard", SensitivityLabel.PCI),
    "card_like_number": ("number 9798924829336441", SensitivityLabel.PCI),
    "vehicle_vin": ("VIN 1HGBH41JXMN109186", SensitivityLabel.PII),
    "vehicle_vrm": ("plate KD85VAB", SensitivityLabel.PII),
    "street_name_context": ("lives on Willow Drive", SensitivityLabel.PII),
    "intl_phone": ("call +39-66-565 2431", SensitivityLabel.PII),
    "age_context": ("she is 97 years old", SensitivityLabel.PII),
    "username_handle": ("user Sienna_Skiles logged in", SensitivityLabel.PII),
    # --- Clinical vocabularies (all context-gated) ---
    "ndc_code_context": ("Dispensed NDC 0069-4200-30.", SensitivityLabel.PHI),
    "cpt_hcpcs_code_context": ("procedure code 99213 billed", SensitivityLabel.PHI),
    "loinc_code_context": ("LOINC 2345-7 glucose result", SensitivityLabel.PHI),
    "snomed_code_context": ("SNOMED CT 44054006 recorded", SensitivityLabel.PHI),
    "rxnorm_code_context": ("RxCUI 860975 dispensed", SensitivityLabel.PHI),
    "drg_code_context": ("MS-DRG 291 assigned on discharge", SensitivityLabel.PHI),
    "clinical_trial_nct": ("enrolled in NCT01234567", SensitivityLabel.PHI),
    "lab_accession_context": ("Specimen No: S24-004512", SensitivityLabel.PHI),
    # --- GDPR Art. 9 special categories ---
    "trade_union_membership": (
        "He is a union member and pays union dues.",
        SensitivityLabel.SPECIAL_CATEGORY,
    ),
    "sexual_orientation": (
        "The customer came out as gay to the agent.",
        SensitivityLabel.SPECIAL_CATEGORY,
    ),
    "political_opinion": (
        "political affiliation: Green Party",
        SensitivityLabel.SPECIAL_CATEGORY,
    ),
    "religious_belief": ("religion: Muslim", SensitivityLabel.SPECIAL_CATEGORY),
    "racial_ethnic_origin": (
        "ethnicity: Black British",
        SensitivityLabel.SPECIAL_CATEGORY,
    ),
    # --- GDPR Art. 10 ---
    "criminal_offence_context": (
        "The applicant was convicted of fraud in 2019.",
        SensitivityLabel.CRIMINAL_OFFENCE,
    ),
    # --- Children's data: a qualifier on an ordinary PII span ---
    "minor_age_context": ("the patient is 9 years old", SensitivityLabel.PII),
    "minor_school_context": (
        "needs parental consent before the trip",
        SensitivityLabel.PII,
    ),
    # --- PCI DSS sensitive authentication data (Req. 3.3.1) ---
    "card_track1_data": (
        "%B4111111111111111^DOE/JANE^2512101000000000000000000?",
        SensitivityLabel.PCI,
    ),
    "card_track2_data": (
        ";4111111111111111=25121010000000000000?",
        SensitivityLabel.PCI,
    ),
    "card_track2_equivalent": (
        "swipe log 4111111111111111=2512101000000",
        SensitivityLabel.PCI,
    ),
    "card_pin_block_context": (
        "PIN block: A1B2C3D4E5F60718",
        SensitivityLabel.PCI,
    ),
    "card_pin_context": ("card PIN: 4821", SensitivityLabel.PCI),
    # --- European national identifiers: context-gated and check-digited ---
    "france_nir_context": ("NIR 2 69 05 49 588 157 80", SensitivityLabel.PII),
    "poland_pesel_context": ("PESEL 44051401359", SensitivityLabel.PII),
    "germany_steuer_id_context": ("Steuer-ID 86 095 742 719", SensitivityLabel.PII),
    "spain_dni_nie_context": ("DNI 12345678Z", SensitivityLabel.PII),
    "sweden_personnummer_context": (
        "personnummer 811218-9876",
        SensitivityLabel.PII,
    ),
    "norway_fodselsnummer_context": (
        "fodselsnummer 010299 10185",
        SensitivityLabel.PII,
    ),
    "finland_hetu_context": ("henkilotunnus 131052-308T", SensitivityLabel.PII),
    "denmark_cpr_context": ("CPR-nummer 010203-1234", SensitivityLabel.PII),
    "belgium_rrn_context": (
        "rijksregisternummer 93.05.18-223.61",
        SensitivityLabel.PII,
    ),
    "ireland_ppsn_context": ("PPS number 1234567FA", SensitivityLabel.PII),
    "portugal_nif_context": ("NIF 501 442 600", SensitivityLabel.PII),
    "greece_amka_context": ("AMKA 01018010007", SensitivityLabel.PII),
    # --- Cloud and platform credentials ---
    "pgp_private_key_block": (
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        SensitivityLabel.SECRET,
    ),
    "azure_storage_connection_string": (
        "DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;",
        SensitivityLabel.SECRET,
    ),
    "azure_sas_token": (
        "https://x.blob.core.windows.net/c?sv=2021-06-08&ss=b&sig=abcdefghijklmnopqrstuvwxyz0123%2F",
        SensitivityLabel.SECRET,
    ),
    "gcp_service_account_key": (
        '{"type": "service_account", "project_id": "demo"}',
        SensitivityLabel.SECRET,
    ),
    "aws_secret_access_key_context": (
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        SensitivityLabel.SECRET,
    ),
    "vault_token": ("token hvs.CAESIJ1234567890abcdefghijk", SensitivityLabel.SECRET),
    "twilio_api_key": ("AC" + "0" * 32, SensitivityLabel.SECRET),
    "databricks_token": ("dapi" + "a" * 32, SensitivityLabel.SECRET),
    "shopify_access_token": ("shpat_" + "a" * 32, SensitivityLabel.SECRET),
    "square_access_token": ("sq0atp-" + "a" * 22, SensitivityLabel.SECRET),
    "atlassian_api_token": (
        "ATATT3xFfGF0abcdefghijklmnopqrst",
        SensitivityLabel.SECRET,
    ),
    "notion_token": ("secret_" + "a" * 43, SensitivityLabel.SECRET),
    "figma_token": ("figd_" + "a" * 44, SensitivityLabel.SECRET),
    "linear_api_key": ("lin_api_" + "a" * 40, SensitivityLabel.SECRET),
    "mailgun_api_key": ("key-" + "b" * 32, SensitivityLabel.SECRET),
    "datadog_api_key_context": ("DD_API_KEY=" + "c" * 32, SensitivityLabel.SECRET),
    "cloudflare_api_token_context": (
        "cloudflare_api_token: " + "d" * 40,
        SensitivityLabel.SECRET,
    ),
    # --- Biometric and genetic (Art. 9; Safe Harbor P) ---
    "biometric_reference": (
        "Enrolled the customer's voiceprint for phone banking.",
        SensitivityLabel.SPECIAL_CATEGORY,
    ),
    "genetic_variant_hgvs": (
        "Variant NM_000059.3:c.1234del confirmed",
        SensitivityLabel.SPECIAL_CATEGORY,
    ),
    "genetic_rsid": ("genotype at rs334 is AS", SensitivityLabel.SPECIAL_CATEGORY),
    "genetic_sequence_run": (
        "read ACGTACGTACGTACGTACGTACGTACGTACGT here",
        SensitivityLabel.SPECIAL_CATEGORY,
    ),
    "genetic_testing_context": (
        "referred for BRCA1 genetic testing",
        SensitivityLabel.SPECIAL_CATEGORY,
    ),
}


def test_detection_cases_cover_every_builtin_detector():
    detector_names = {detector.name for detector in DETECTORS}
    assert set(DETECTION_CASES) == detector_names


@pytest.mark.parametrize(
    ("detector", "text", "expected_label"),
    [(name, *case) for name, case in DETECTION_CASES.items()],
)
def test_each_builtin_detector_fires(detector, text, expected_label):
    result = classify_text(text)
    assert result.label == expected_label
    assert detector in result.detectors
    assert any(span["detector"] == detector for span in result.spans)


@pytest.mark.parametrize(
    "text, detector",
    [
        # Existing
        ("routing number 123456789", "bank_routing"),
        ("SIN: 123 456 789", "canada_sin_context"),
        ("NPI: 1234567890", "npi_context"),
        ("IBAN GB82 TEST 1234 5678 0000 00", "iban"),
        ("order number 4111 1111 1111 1112 confirmed", "credit_card"),
        ("last login from 999.999.999.999", "ipv4_address"),
        # New validators
        ("CPF 111.111.111-11", "brazil_cpf_context"),  # all-same digits
        ("BSN 123456789", "netherlands_bsn_context"),  # fails elfproef
        ("NHS number 401 023 2138", "uk_nhs_context"),  # wrong check digit
        ("ID: 110101199003071234", "china_resident_id"),  # wrong check char
        ("NRIC S1234567E", "singapore_nric"),  # wrong check letter
        ("tax file number 123 456 789", "australia_tfn_context"),  # bad checksum
        ("DEA number AB1234564", "us_dea_number_context"),  # wrong check digit
        ("South African ID 8001015009088", "south_africa_id_context"),  # bad Luhn
        # Track data whose PAN fails Luhn is not track data.
        ("reference 1234567890123456=2512101", "card_track2_equivalent"),
        # An adult age carries no minor qualifier.
        ("the account holder is 42 years old", "minor_age_context"),
        # Topic mentions are not statements about a person: Art. 9 detectors
        # must not fire on a corpus that merely discusses these subjects.
        ("The European Union published guidance today.", "trade_union_membership"),
        ("We observe religious holidays in the leave policy.", "religious_belief"),
        ("You were charged with the invoice amount.", "criminal_offence_context"),
        # A five-digit number is only a procedure code when it says so.
        ("order code 99213 for the widget", "cpt_hcpcs_code_context"),
        # Sixteen hex characters are not a PIN block unless named as one.
        ("checksum a1b2c3d4e5f60718 for the build", "card_pin_block_context"),
        # Every European identifier below is check-digited; a single wrong
        # digit must take the match with it.
        ("PESEL 44051401358", "poland_pesel_context"),
        ("DNI 12345678A", "spain_dni_nie_context"),
        ("Steuer-ID 86 095 742 718", "germany_steuer_id_context"),
        ("personnummer 811218-9875", "sweden_personnummer_context"),
        ("henkilotunnus 131052-308U", "finland_hetu_context"),
        # Newly validated: these two used to accept any run of the right shape.
        ("IMEI 490154203237519", "imei_number"),
        ("build id ABCDEFGH12345678Z", "vehicle_vin"),
        # "fingerprint" is this product's own vocabulary for finding identity,
        # and every runbook uses it for hashes. Only the biometric senses fire.
        ("the finding fingerprint is stable across runs", "biometric_reference"),
        ("TLS certificate fingerprint SHA256", "biometric_reference"),
        # Two digits is a ticket reference, not a dbSNP identifier.
        ("ticket rs12 filed", "genetic_rsid"),
        # A key-value store is not a Mailgun key.
        ("the key-value store holds 32 entries", "mailgun_api_key"),
    ],
)
def test_validated_detectors_reject_invalid_values(text, detector):
    result = classify_text(text)
    assert detector not in result.detectors
