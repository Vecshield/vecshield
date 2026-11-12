"""Dagster asset check for a VecShield ingestion gate.

Run this file as a template inside a Dagster project with `dagster` installed.
"""

from __future__ import annotations

from vecshield import check_dataset


def vecshield_dataset_gate(dataset_dir: str) -> dict:
    report = check_dataset(dataset_dir)
    if report.has_pii:
        raise RuntimeError(
            f"VecShield blocked ingestion: {report.sensitive_records} sensitive "
            f"record(s) in {dataset_dir}"
        )
    return report.to_dict()


# --- Dagster shape ----------------------------------------------------------
# from dagster import AssetCheckResult, asset_check
#
# @asset_check(asset=chunked_documents)
# def pii_gate_check() -> AssetCheckResult:
#     report = check_dataset("/data/chunks")
#     return AssetCheckResult(
#         passed=not report.has_pii,
#         metadata=report.to_dict(),
#     )
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import sys

    print(vecshield_dataset_gate(sys.argv[1] if len(sys.argv) > 1 else "."))
