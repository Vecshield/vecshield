"""Default policies for training/fine-tuning data.

Same Policy engine as store-side policies, scoped to the
`training_data_classification` category. Stricter by intent: data here ends up in
model weights, so any SSN/medical record is a hard stop and the PII-density bar
is low (0.5%).
"""

from __future__ import annotations

from vecshield_platform.compliance.policy import Policy
from vecshield.models import Severity

# Datasets above this PII density should not be embedded/trained without review.
MAX_PII_DENSITY = 0.005  # 0.5%


def training_policies() -> list[Policy]:
    return [
        Policy(
            id="training-no-secrets",
            description="Secrets/credentials present in a training dataset",
            when={"category": "training_data_classification",
                  "requires_label": "secret"},
            action="purge_and_retrain",
            severity=Severity.CRITICAL,
        ),
        Policy(
            id="training-no-phi",
            description="Medical/health records in a training dataset",
            when={"category": "training_data_classification",
                  "requires_label": "phi"},
            action="purge_and_retrain",
            severity=Severity.CRITICAL,
        ),
        Policy(
            id="training-no-pci",
            description="Payment card data in a training dataset",
            when={"category": "training_data_classification",
                  "requires_label": "pci"},
            action="purge_and_retrain",
            severity=Severity.CRITICAL,
        ),
        Policy(
            id="training-pii-density",
            description=f"PII density above {MAX_PII_DENSITY:.1%} in a training dataset",
            when={"category": "training_data_classification",
                  "requires_label": "pii",
                  "evidence_gte": {"sensitivity.density": MAX_PII_DENSITY}},
            action="review_before_training",
            severity=Severity.HIGH,
        ),
    ]
