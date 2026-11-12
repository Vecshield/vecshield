#!/usr/bin/env python3
"""Seed the generated support/email corpus into a local Qdrant instance."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


VECTOR_SIZE = 384
PAYLOAD_INDEXES = [
    "tenant_id",
    "customer_id",
    "account_id",
    "source_system",
    "access_scope",
    "retention_class",
    "risk_tags",
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:6333", help="Qdrant HTTP URL.")
    parser.add_argument(
        "--points",
        default=Path(__file__).resolve().parent / "qdrant_points.jsonl",
        type=Path,
        help="Generated qdrant_points.jsonl file.",
    )
    parser.add_argument(
        "--no-recreate",
        action="store_true",
        help="Keep existing collections and upsert into them.",
    )
    parser.add_argument("--batch-size", type=int, default=128)
    args = parser.parse_args()

    try:
        from qdrant_client import QdrantClient, models
    except ImportError as exc:
        raise SystemExit(
            "qdrant-client is required. Install it with: pip install qdrant-client"
        ) from exc

    groups = read_points(args.points)
    client = QdrantClient(url=args.url)
    for collection, points in groups.items():
        ensure_collection(client, models, collection, recreate=not args.no_recreate)
        create_indexes(client, models, collection)
        upsert_points(client, models, collection, points, args.batch_size)
        print(f"Created collection {collection}: {len(points)} chunks")


def read_points(path: Path) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            missing = {"collection", "id", "vector", "payload"} - set(row)
            if missing:
                raise ValueError(f"{path}:{line_no} missing keys: {sorted(missing)}")
            groups[row["collection"]].append(row)
    return dict(groups)


def ensure_collection(client: Any, models: Any, name: str, *, recreate: bool) -> None:
    if recreate:
        try:
            client.delete_collection(collection_name=name)
        except Exception:
            pass
    try:
        client.create_collection(
            collection_name=name,
            vectors_config=models.VectorParams(size=VECTOR_SIZE, distance=models.Distance.COSINE),
        )
    except Exception:
        if recreate:
            raise


def create_indexes(client: Any, models: Any, collection: str) -> None:
    for field in PAYLOAD_INDEXES:
        try:
            client.create_payload_index(
                collection_name=collection,
                field_name=field,
                field_schema=models.PayloadSchemaType.KEYWORD,
            )
        except Exception:
            # Qdrant treats duplicate index creation as an error on some versions.
            pass


def upsert_points(
    client: Any,
    models: Any,
    collection: str,
    rows: list[dict[str, Any]],
    batch_size: int,
) -> None:
    for start in range(0, len(rows), batch_size):
        batch = rows[start:start + batch_size]
        points = [
            models.PointStruct(
                id=row["id"],
                vector=row["vector"],
                payload=row["payload"],
            )
            for row in batch
        ]
        client.upsert(collection_name=collection, points=points)


if __name__ == "__main__":
    main()
