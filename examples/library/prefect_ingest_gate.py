"""Prefect task for blocking PII before embedding.

Use this as a template in a Prefect flow; the core callable has no Prefect
dependency so it is easy to test.
"""

from __future__ import annotations

from vecshield import check_dataset


def vecshield_gate(dataset_dir: str) -> dict:
    report = check_dataset(dataset_dir)
    if report.has_pii:
        raise RuntimeError(
            f"VecShield blocked ingestion: {report.sensitive_records} sensitive "
            f"record(s) in {dataset_dir}"
        )
    return report.to_dict()


# --- Prefect shape ----------------------------------------------------------
# from prefect import flow, task
#
# @task
# def pii_gate(dataset_dir: str) -> dict:
#     return vecshield_gate(dataset_dir)
#
# @flow
# def rag_ingestion_flow(dataset_dir: str) -> None:
#     report = pii_gate(dataset_dir)
#     embed_and_upsert.submit(dataset_dir, wait_for=[report])
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import sys

    print(vecshield_gate(sys.argv[1] if len(sys.argv) > 1 else "."))
