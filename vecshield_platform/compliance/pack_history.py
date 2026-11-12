"""Digests of earlier criterion packs, and what changed since.

A reviewer decision is bound to a digest of the criterion it was made about
(``decisions.criterion_digest``). When the pack version moves, a decision is
carried forward only if the criterion is unchanged; this module records the
digests each earlier pack published so the change can be *computed*, not
asserted, and renders the migration note in
``docs/compliance/pack-draft-4-migration.md`` from that computation.

``PACK_DIGESTS`` holds, per earlier pack version and criterion, the full
decision digest and a short hash of each material field, so the migration note
can say which fields changed. The values were computed from the shipped pack
at that version; they are data and must never be edited by hand.

Regenerate the note with::

    python -m vecshield_platform.compliance.pack_history > \\
        docs/compliance/pack-draft-4-migration.md
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any

from vecshield_platform.compliance.criteria import NON_MATERIAL_FIELDS, PACK_VERSION

#: pack version -> criterion id -> {"digest": ..., "fields": {field: hash16}}
PACK_DIGESTS: dict[str, dict[str, dict[str, Any]]] = {
    "vecshield-vector-store-draft-3": {
        "AIACT-ART10-DATA-GOV-01": {
            "digest": "15bb69fd44636b16d77b70c054471fd1fac626f574844b508adc6e614178a262",
            "fields": {
                "applicability_questions": "f35f70285144731c",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "bffd209de47f4151",
                "id": "17e8af93c106bf7d",
                "interpretation_notes": "12ae32cb1ec02d01",
                "limitations": "8db0c243d85e6b00",
                "manual_evidence": "fb59e3126686c0e1",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "473099afb800a58e",
                "source_ids": "1380ee0050785986",
                "specification": "74234e98afe7498f",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "31e0c2c99c4a1945",
            },
        },
        "CCPA-CYBERAUDIT-ENCRYPTION-01": {
            "digest": "9abbfb6ce31921e5be8f16ebbdff217839bbb36607feebafb9c6c7c692c69822",
            "fields": {
                "applicability_questions": "e873566bbf28bb95",
                "fallback_evidence": "73d1641db879ffb6",
                "framework": "dc34bfa328e4e7d0",
                "id": "700438e815453ade",
                "interpretation_notes": "b09d6b97be7dd614",
                "limitations": "f2802277e001127e",
                "manual_evidence": "4f53cda18c2baa0c",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "9a19f4718d3458a9",
                "source_ids": "2c8b63d91c968139",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "9b6e2ab2afc240eb",
            },
        },
        "CCPA-DELETE-01": {
            "digest": "ddafb3a14938eda8afcb9a5b757708151125adea0617474b5c0fcbd846e4e0ee",
            "fields": {
                "applicability_questions": "f6dda716df881f67",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "dc34bfa328e4e7d0",
                "id": "ef5ee2d956f995fa",
                "interpretation_notes": "12ae32cb1ec02d01",
                "limitations": "a97259746c0f6c88",
                "manual_evidence": "db0a95c4304c751a",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "4b3ee20017bb7369",
                "source_ids": "5a6142fa2d63cc8a",
                "specification": "74234e98afe7498f",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "73ded984b42dce9a",
            },
        },
        "GDPR-32-1A-ENCRYPTION-01": {
            "digest": "934a1e3827a09ee9b18a71cdaac8cd1484fbd919f17de1cf7349fb870126618e",
            "fields": {
                "applicability_questions": "f87c68b2ab02e667",
                "fallback_evidence": "935fb38c079c2625",
                "framework": "507cec40bda725bb",
                "id": "72c06003f7274690",
                "interpretation_notes": "216f0ae96e854758",
                "limitations": "91aec2c687168ee0",
                "manual_evidence": "4f53cda18c2baa0c",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "b83bd99818816330",
                "source_ids": "93e0133b82f3feea",
                "specification": "7d584d9def09d82c",
                "specification_basis": "b4011ac863eaf9b5",
                "technical_checks": "9d039e38d3a9feb1",
            },
        },
        "GDPR-ERASURE-01": {
            "digest": "8d35629bdf9377b8d0e82244a45db96666fc04eb47ad6e18905b17be0ece6bec",
            "fields": {
                "applicability_questions": "15554952971709c9",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "507cec40bda725bb",
                "id": "ae02a15ee3e30495",
                "interpretation_notes": "12ae32cb1ec02d01",
                "limitations": "e7448021c139a32d",
                "manual_evidence": "acc56cdc5912abbc",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "4c02c7494972e6bd",
                "source_ids": "0a3a6a5dc2bc98ac",
                "specification": "74234e98afe7498f",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "73ded984b42dce9a",
            },
        },
        "GDPR-SECURITY-32-01": {
            "digest": "f86f4dc06d25d0e5e127878f0a7fcff96f64baa7f2b6c4c876060a3efc18bb09",
            "fields": {
                "applicability_questions": "f87c68b2ab02e667",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "507cec40bda725bb",
                "id": "a74867ceafb7cbde",
                "interpretation_notes": "12ae32cb1ec02d01",
                "limitations": "3210e94aad29ff4d",
                "manual_evidence": "f58945279303b7dd",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "424f2eaa644e8f39",
                "source_ids": "b874a53eda030837",
                "specification": "74234e98afe7498f",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "fb9dccb658def8c3",
            },
        },
        "GDPR-STORAGE-LIMITATION-01": {
            "digest": "6372872670d2385b2d29211113e5276ee77a5a181bb1cfa654a1841eee5070cc",
            "fields": {
                "applicability_questions": "15554952971709c9",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "507cec40bda725bb",
                "id": "305ba00965ef31a1",
                "interpretation_notes": "73652a8029ed62a0",
                "limitations": "f57ed0aec36f7a38",
                "manual_evidence": "e03b7ec2e0aec90a",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "239c5e6fc8ca9a0c",
                "source_ids": "d4bf3ec60fb7869a",
                "specification": "74234e98afe7498f",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "60768d0963a63e9e",
            },
        },
        "HIPAA-164-308-A1-RISK-01": {
            "digest": "d7ce5f9255f7fbfe76eb0f939e78b8b007cd256ad2921ba6bdaa71fcd0c2e563",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "af227f906421c52a",
                "interpretation_notes": "1338acb1a6a4b8a8",
                "limitations": "4a8296bc96f4165f",
                "manual_evidence": "f0391637ff5c7b49",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "43837ee116e77054",
                "source_ids": "04ba4d18d70ff278",
                "specification": "cf51937bad8b2f69",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "a46bbb7b0211ccc5",
            },
        },
        "HIPAA-164-308-A4-ACCESS-MGMT-01": {
            "digest": "5d285e86faf25f0621ffbf69bfbd27d04fabd73dbacba41441c65d50d32018fd",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "f1f956ba10725c7a",
                "interpretation_notes": "79690a2757b82926",
                "limitations": "bb02f24874f4ebf0",
                "manual_evidence": "ab6f63aad0b22aae",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "3a66ec7a4aefc316",
                "source_ids": "bafa13b490e6b817",
                "specification": "1c179957eb9585d8",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "fb9dccb658def8c3",
            },
        },
        "HIPAA-164-308-A6-INCIDENT-01": {
            "digest": "b0bd53f70c7ece274151e1ec2ff3290d5cf0999940127fe3aa10d5a29b2876b8",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "085989c9130344a1",
                "interpretation_notes": "599c7f13edd57d69",
                "limitations": "cbd0d00ae8509d4b",
                "manual_evidence": "b729bf04ef7e3447",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "d90d0337cd6640c3",
                "source_ids": "46954cc31643c0c0",
                "specification": "cf51937bad8b2f69",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "633bf68e1f469a2c",
            },
        },
        "HIPAA-164-308-A8-EVALUATION-01": {
            "digest": "84f8b2fe175aa9ec1eb7e4a5cb4f5cedd144a089018a8c1ada131e9f34c37a75",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "fd7974ac9bef554b",
                "interpretation_notes": "e8d021d5b117ff48",
                "limitations": "e184b6ac3cd7c935",
                "manual_evidence": "07f2a26173ec857f",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "1941a391a704f5a9",
                "source_ids": "4041a778f24a1f2f",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "8da66443cef6110d",
            },
        },
        "HIPAA-164-308-B1-BAA-01": {
            "digest": "106c290542d72183e72c987b1309797abbfc6e7719aa3536dc9f159f7034314c",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "d693f3a68b98cb79",
                "interpretation_notes": "ae51b2500560334e",
                "limitations": "d127dd62d8100cab",
                "manual_evidence": "5b53f995a7022ae2",
                "manual_evidence_only": "b5bea41b6c623f7c",
                "paraphrase": "4e84530650b2e526",
                "source_ids": "e19e0a33332d018a",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "4f53cda18c2baa0c",
            },
        },
        "HIPAA-164-310-D2-DISPOSAL-01": {
            "digest": "246c54901e6731b7088a0c29b2803cca91324eabc190e4cf00b05a16fc98a755",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "2eec1a2bce8ed41a",
                "interpretation_notes": "5fa3fe77f73afd5d",
                "limitations": "054fea0857ebf4bf",
                "manual_evidence": "3092f0b64e9ad378",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "73bb0c6fb9201f27",
                "source_ids": "9fa40a36e67e6e99",
                "specification": "cf51937bad8b2f69",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "d12f956144b80b88",
            },
        },
        "HIPAA-164-312-A1-ACCESS-CONTROL-01": {
            "digest": "b2efc6ad4c48331a6e39f1530cd3837da834335cd18f1573dcd4731d584ffb36",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "cd12982832c53aec",
                "interpretation_notes": "fa820bb784f862a7",
                "limitations": "87f648917192020b",
                "manual_evidence": "ab6f63aad0b22aae",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "25229c4b904755af",
                "source_ids": "661ccf836cad746f",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "fb9dccb658def8c3",
            },
        },
        "HIPAA-164-312-A2IV-ENCRYPTION-01": {
            "digest": "a89167b15cc4a51f507bfa0aaef439fae7a34447d315af22e6cc368b21845cf7",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "71b23a2c4489a44e",
                "framework": "ae8fe530dbd00095",
                "id": "30b0b85da9fc8e26",
                "interpretation_notes": "d533229dc14cb665",
                "limitations": "263f9037ef41d1f4",
                "manual_evidence": "4f53cda18c2baa0c",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "4ae6c14175f573a6",
                "source_ids": "ec962f7526e0f680",
                "specification": "1c179957eb9585d8",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "7d02b2d9a47685c2",
            },
        },
        "HIPAA-164-312-B-AUDIT-01": {
            "digest": "d58e7b4f8b357bdf649c55a6cf89c438ec62924bde0da114d2d68bf590afc9d6",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "c15012e4577c104f",
                "interpretation_notes": "46846044d984eb59",
                "limitations": "158d55e17c68e068",
                "manual_evidence": "0e7ac27d0d575183",
                "manual_evidence_only": "b5bea41b6c623f7c",
                "paraphrase": "db1a4b443111c85b",
                "source_ids": "0287fe3e16420871",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "4f53cda18c2baa0c",
            },
        },
        "HIPAA-164-312-C1-INTEGRITY-01": {
            "digest": "643b9fe85f3a09d3f52bec57e3c6f228202901736ccd1e1932649dd703100833",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "844ffaf10cc9208c",
                "interpretation_notes": "2da9e685714cc263",
                "limitations": "b2494984c81330dc",
                "manual_evidence": "d6dbfdc76c2190cf",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "c494b724f347b7b2",
                "source_ids": "2374cb640c2a6999",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "15b7cc2d58979e5b",
            },
        },
        "HIPAA-164-312-D-AUTHN-01": {
            "digest": "4d36e932fc3863c4216fdfddfbc898701585d9c01ee5cdbbe44a941f8382d1df",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "fe34d603caf62f22",
                "interpretation_notes": "4d913d7e23263167",
                "limitations": "2a6cd457cf11ca36",
                "manual_evidence": "6ed2d075af037698",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "df8d57760f696d38",
                "source_ids": "c61cebfadc44a195",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "5e92298df597dd03",
            },
        },
        "HIPAA-164-312-E1-TRANSMISSION-01": {
            "digest": "aece384b9cee5036e32119c80fbac91392ab0164b0c1f21011b9616911759e9b",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "67ef31cd6506f4e6",
                "framework": "ae8fe530dbd00095",
                "id": "03b32ec386d3207c",
                "interpretation_notes": "f48118c040d5681b",
                "limitations": "79a0bfd6f8c3ac57",
                "manual_evidence": "4f53cda18c2baa0c",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "255672f9dc8851ee",
                "source_ids": "906e207bad4a84b1",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "6238aedf6dd53081",
            },
        },
        "HIPAA-164-312-E2II-ENCRYPTION-01": {
            "digest": "4c7a503ef0f91aaf31e2de253ac86e91a0d55e2223ee34fd55627c35e4bfcf18",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "67ef31cd6506f4e6",
                "framework": "ae8fe530dbd00095",
                "id": "b8bf759cc1cd6ebf",
                "interpretation_notes": "a11303cec34d7a29",
                "limitations": "6eed174018a0a7dd",
                "manual_evidence": "4f53cda18c2baa0c",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "6eb76696e126e745",
                "source_ids": "991f624168152804",
                "specification": "1c179957eb9585d8",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "dee770cd7b1757b0",
            },
        },
        "HIPAA-164-316-B1-DOCUMENTATION-01": {
            "digest": "368d094c797f306ab70d04aec7f2f94bf65d41725c4ea9479c3ebe1870143096",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "529e68f63356e63d",
                "interpretation_notes": "54fba72cbdd8225b",
                "limitations": "de70c02c5e8a1448",
                "manual_evidence": "21a32137060d7c1e",
                "manual_evidence_only": "b5bea41b6c623f7c",
                "paraphrase": "7829d18943c28482",
                "source_ids": "5fbeee6fa9be2ecc",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "41c9cd36ae5bb7e2",
                "technical_checks": "4f53cda18c2baa0c",
            },
        },
        "HIPAA-164-402-BREACH-ASSESS-01": {
            "digest": "c4dc3619021f79ab690041a4af17aa7e1ffbc7c7717d408b6688a336fb7a4159",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "8390002ad172a006",
                "interpretation_notes": "2e6fa3268900d4d7",
                "limitations": "46ca531bbf667230",
                "manual_evidence": "2547b08a8772ac75",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "f20d274800b52b98",
                "source_ids": "0add44b34c09f579",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "f5a7072f27322f9f",
            },
        },
        "HIPAA-164-502-B-MIN-NECESSARY-01": {
            "digest": "103bfb8c2483e5a6eac7e19e1ea6a464aa8da8d23648491793136683d5fe5e82",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "e7789c03b70a6306",
                "interpretation_notes": "33ebd42aaadc2ef0",
                "limitations": "b27e1123b7c75206",
                "manual_evidence": "3cf78703bd362529",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "db74ee0f474c692d",
                "source_ids": "0022a77fd4eba11d",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "a46bbb7b0211ccc5",
            },
        },
        "HIPAA-164-514-B-DEIDENT-01": {
            "digest": "75f9a405cd8825a0e3bed83a242ec0c15875d6d890f79ad956e6e35e59d7687e",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "460aff759f293666",
                "interpretation_notes": "d4647e4d7ba2d8ae",
                "limitations": "7a0bf6955870ae1e",
                "manual_evidence": "29449d8ee6435b2f",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "f3f9915da37f8688",
                "source_ids": "98926231d3a38ddd",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "be1e6423ca00c13e",
            },
        },
        "HIPAA-164-524-ACCESS-01": {
            "digest": "c8008522bf3239faa9e524b6540d20e231f39a19a6056727d67f35abd3ad0852",
            "fields": {
                "applicability_questions": "e4383935b4e7b2eb",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "ae8fe530dbd00095",
                "id": "bf1392e403182258",
                "interpretation_notes": "838db1526c30f277",
                "limitations": "e35bf1eafb7eda98",
                "manual_evidence": "8eea2d67b06eb48c",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "751b2735c8ee10b4",
                "source_ids": "1601ee0548a2ac51",
                "specification": "cb2842d6687d19c6",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "73ded984b42dce9a",
            },
        },
        "PCI-DSS-3-STORAGE-01": {
            "digest": "f7ed2335b5cbedd1d67cfddfd1bf53db93a4a0a2415a6534408c40ddf5dc1da4",
            "fields": {
                "applicability_questions": "22cb727fabd146de",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "7d6b091e52ff9969",
                "id": "007888f26dd39d5c",
                "interpretation_notes": "18d600e84ca3c41f",
                "limitations": "c8fc3c68d8f66381",
                "manual_evidence": "fb5466bbc57e85ce",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "88d476b99074657c",
                "source_ids": "9e74eeb542b0a6e5",
                "specification": "74234e98afe7498f",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "354d191fab9f51cb",
            },
        },
        "PCI-DSS-4-2-1-TRANSMISSION-01": {
            "digest": "6b4d763cd542627b4e17b10aabc743552b656215f1f3660788660625f1679bb6",
            "fields": {
                "applicability_questions": "329bd3a1f02a88c1",
                "fallback_evidence": "dd920bb8b094d680",
                "framework": "7d6b091e52ff9969",
                "id": "a2ddc61c33305a2a",
                "interpretation_notes": "da77e480fdbdec87",
                "limitations": "db03bfb7260d6159",
                "manual_evidence": "4f53cda18c2baa0c",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "995620d469fd42b9",
                "source_ids": "40813b945109f467",
                "specification": "74234e98afe7498f",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "dee770cd7b1757b0",
            },
        },
        "SOC2-CC6.1-ENCRYPTION-01": {
            "digest": "a8de9f1d8e3f76ac844dd8d347a92f1f66b8074b36af33287690ad2f74160b96",
            "fields": {
                "applicability_questions": "9bace88cc8c62f69",
                "fallback_evidence": "4f8360bb1f37b0dd",
                "framework": "c5347d0b4e77de05",
                "id": "e6aac19d961fbd72",
                "interpretation_notes": "7100a528bc3f1004",
                "limitations": "9c363b4ddcbc12eb",
                "manual_evidence": "4f53cda18c2baa0c",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "373ae12c14f5c4f3",
                "source_ids": "15aa3c4c7bb0c9cf",
                "specification": "7d584d9def09d82c",
                "specification_basis": "989661f79645440a",
                "technical_checks": "7d02b2d9a47685c2",
            },
        },
        "SOC2-CC6.1-SECRETS-01": {
            "digest": "ec1c9afc175200f090e59e5b93e961f0e35f7f33d22095d859919ad772809b2e",
            "fields": {
                "applicability_questions": "9bace88cc8c62f69",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "c5347d0b4e77de05",
                "id": "b28efc04d3f4f4b0",
                "interpretation_notes": "1dd7ef3cb4f91edd",
                "limitations": "3149724222a32ad3",
                "manual_evidence": "7175d7a2fe2c9345",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "6e89597086e13cab",
                "source_ids": "15aa3c4c7bb0c9cf",
                "specification": "74234e98afe7498f",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "be1e6423ca00c13e",
            },
        },
        "SOC2-CC6.7-TRANSMISSION-01": {
            "digest": "bad185057feb145485e0ceca7ee0258c72781196e324164f5959f3016d1c0c67",
            "fields": {
                "applicability_questions": "9bace88cc8c62f69",
                "fallback_evidence": "959f70573209408d",
                "framework": "c5347d0b4e77de05",
                "id": "d61e80079b797e72",
                "interpretation_notes": "388793919be0bf47",
                "limitations": "59bd5b3fa80c2b42",
                "manual_evidence": "4f53cda18c2baa0c",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "c4ec0421764fa1b7",
                "source_ids": "4a092a268f06107e",
                "specification": "7d584d9def09d82c",
                "specification_basis": "115e9ed831a97ffc",
                "technical_checks": "dee770cd7b1757b0",
            },
        },
        "SOC2-CC7.2-ANOMALY-01": {
            "digest": "143dfec5341289e940780a8eda177c1497cbcec8727b5b7637c523715eccba90",
            "fields": {
                "applicability_questions": "9bace88cc8c62f69",
                "fallback_evidence": "4f53cda18c2baa0c",
                "framework": "c5347d0b4e77de05",
                "id": "87fba090a55be09e",
                "interpretation_notes": "12ae32cb1ec02d01",
                "limitations": "126bde3f59aa1285",
                "manual_evidence": "6233fdc078af9509",
                "manual_evidence_only": "fcbcf165908dd18a",
                "paraphrase": "dd54df6a1a8780a2",
                "source_ids": "bf65cd9324c28979",
                "specification": "74234e98afe7498f",
                "specification_basis": "74234e98afe7498f",
                "technical_checks": "a7ffbd10752ff9ce",
            },
        },
    },
}

#: The pack the current one replaced, for the migration note.
PREVIOUS_PACK = "vecshield-vector-store-draft-3"

#: What each material field means, for a reader of the migration note.
FIELD_LABELS = {
    "id": "criterion id",
    "framework": "framework",
    "paraphrase": "obligation wording",
    "source_ids": "cited sources",
    "technical_checks": "technical checks",
    "manual_evidence": "required artifacts",
    "fallback_evidence": "fallback artifacts",
    "applicability_questions": "applicability questions",
    "limitations": "limitations",
    "interpretation_notes": "interpretation notes",
    "specification": "specification kind",
    "specification_basis": "specification basis",
    "manual_evidence_only": "manual-evidence-only flag",
}


def field_hash(value: Any) -> str:
    """A short, stable hash of one field's value."""
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def material_field_hashes(criterion: Any) -> dict[str, str]:
    """Per-field hashes of what a criterion asks, without its pack version."""
    return {k: field_hash(v) for k, v in sorted(asdict(criterion).items())
            if k not in NON_MATERIAL_FIELDS and k != "pack_version"}


def compare(previous: str = PREVIOUS_PACK) -> dict[str, Any]:
    """How each criterion of ``previous`` fares in the current pack.

    ``unchanged``
        Same definition. Stored decisions carry forward.
    ``changed``
        Same id, different definition. Stored decisions are reported stale
        and not applied.
    ``replaced``
        The old id is now an alias of a different criterion. Decisions
        resolve to the successor and are reported stale.
    ``retired``
        No successor. Decisions are reported stale.

    ``added`` lists criteria with no counterpart in ``previous``.
    """
    from vecshield_platform.compliance.decisions import criterion_digest_as_of
    from vecshield_platform.compliance.packs import CRITERIA, CRITERION_ALIASES

    old = PACK_DIGESTS[previous]
    current = {c.id: c for c in CRITERIA}
    rows: list[dict[str, Any]] = []
    for old_id, record in sorted(old.items()):
        successor_id = old_id if old_id in current else CRITERION_ALIASES.get(old_id)
        if successor_id is None:
            rows.append({"criterion_id": old_id, "outcome": "retired",
                         "successor": None, "changed_fields": []})
            continue
        criterion = current[successor_id]
        fields = material_field_hashes(criterion)
        changed = sorted(f for f in set(fields) | set(record["fields"])
                         if fields.get(f) != record["fields"].get(f))
        if successor_id != old_id:
            outcome = "replaced"
        elif criterion_digest_as_of(criterion, previous) == record["digest"]:
            outcome = "unchanged"
        else:
            outcome = "changed"
        rows.append({"criterion_id": old_id, "outcome": outcome,
                     "successor": successor_id if successor_id != old_id else None,
                     "title": criterion.title, "changed_fields": changed})
    succeeded = {r["successor"] for r in rows if r["successor"]}
    added = sorted(cid for cid in current if cid not in old and cid not in succeeded)
    return {"previous": previous, "current": PACK_VERSION, "criteria": rows,
            "added": added,
            "counts": {outcome: sum(1 for r in rows if r["outcome"] == outcome)
                       for outcome in ("unchanged", "changed", "replaced", "retired")}}


def migration_markdown(previous: str = PREVIOUS_PACK) -> str:
    """The migration note, rendered from :func:`compare`. Never hand-edited."""
    from vecshield_platform.compliance.packs import get_criterion

    diff = compare(previous)
    counts = diff["counts"]
    lines = [
        f"# Criterion pack migration: {diff['previous']} to {diff['current']}",
        "",
        "Generated by `python -m vecshield_platform.compliance.pack_history`"
        " from the digests recorded in",
        "`vecshield_platform/compliance/pack_history.py`. Do not edit by hand;"
        " a test fails if this file",
        "and the generator disagree.",
        "",
        "## What happens to stored reviewer decisions",
        "",
        "A reviewer decision is bound to the pack version and a digest of the"
        " criterion it was made about.",
        "When the pack version moves, a decision recorded under the previous"
        " pack is **carried forward**",
        "only if the criterion's definition is unchanged: the digest recomputed"
        " with the old pack version",
        "reproduces the stored one. Otherwise it is reported **stale**"
        " (`pack_version_changed`) and not",
        "applied, and a reviewer records it again against the current wording."
        " A changed title never",
        "makes a decision stale.",
        "",
        f"- Unchanged, decisions carry forward: {counts['unchanged']}",
        f"- Changed, decisions go stale: {counts['changed']}",
        f"- Replaced by a new criterion, decisions go stale: {counts['replaced']}",
        f"- Retired, decisions go stale: {counts['retired']}",
        f"- New in {diff['current']}: {len(diff['added'])}",
        "",
        "Source records are not part of the digest. A corrected note, date or"
        " legal status on a cited",
        "source does not make a decision stale; adding or removing a cited"
        " source does.",
        "",
        "## Decisions that go stale",
        "",
        "| Criterion | Now | What changed |",
        "|---|---|---|",
    ]
    for row in diff["criteria"]:
        if row["outcome"] == "unchanged":
            continue
        what = ", ".join(FIELD_LABELS.get(f, f) for f in row["changed_fields"]
                         if f != "id") or "-"
        if row["outcome"] == "replaced":
            now = f"replaced by `{row['successor']}`"
        elif row["outcome"] == "retired":
            now = "retired"
        else:
            now = "changed"
        lines.append(f"| `{row['criterion_id']}` | {now} | {what} |")
    lines += ["", "## Decisions that carry forward", ""]
    lines += [f"- `{row['criterion_id']}`" for row in diff["criteria"]
              if row["outcome"] == "unchanged"] or ["- None"]
    lines += ["", f"## New criteria in {diff['current']}", ""]
    for cid in diff["added"]:
        criterion = get_criterion(cid)
        title = criterion.title if criterion else ""
        lines.append(f"- `{cid}`: {title}")
    if not diff["added"]:
        lines.append("- None")
    lines += [
        "",
        "## Why these changed",
        "",
        "The changes apply a citation audit of this pack's sources. Every"
        " criterion remains a draft",
        "mapping: none has been reviewed by a lawyer or other qualified"
        " reviewer, and none is",
        "evidence that a store meets the law.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - documentation generator
    print(migration_markdown(), end="")
