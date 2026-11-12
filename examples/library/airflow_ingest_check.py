"""Airflow task that fails the DAG when PII is found before embedding.

Drop a VecShield gate task between your chunking task and your embedding task.
If sensitive data is present, the task raises and the downstream embed/upsert
tasks never run.

    pip install vecshield apache-airflow
"""

from __future__ import annotations

from vecshield import check_dataset


def vecshield_gate(dataset_dir: str, *, fail_on_density: float = 0.0) -> dict:
    """Callable for a PythonOperator. Raises to fail the task on PII."""
    report = check_dataset(dataset_dir)
    if report.sensitive_records and report.density > fail_on_density:
        raise RuntimeError(
            f"VecShield blocked ingestion: {report.sensitive_records} sensitive "
            f"record(s) ({report.density:.1%}) in {dataset_dir}"
        )
    return report.to_dict()


# --- Real DAG shape ---------------------------------------------------------
# from airflow import DAG
# from airflow.operators.python import PythonOperator
# from datetime import datetime
#
# with DAG("rag_ingest", start_date=datetime(2026, 1, 1), schedule="@daily") as dag:
#     chunk = PythonOperator(task_id="chunk", python_callable=make_chunks)
#     gate = PythonOperator(
#         task_id="vecshield_gate",
#         python_callable=vecshield_gate,
#         op_kwargs={"dataset_dir": "/data/chunks"},
#     )
#     embed = PythonOperator(task_id="embed", python_callable=embed_and_upsert)
#     chunk >> gate >> embed          # embed only runs if the gate passes
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    print(vecshield_gate(sys.argv[1] if len(sys.argv) > 1 else "."))
