# Architecture

The `vecshield` library is intentionally small: a local detection engine, local data
readers, an ingestion gate, and a stable CLI/SDK surface.

## Package layout

| Path | Purpose |
| --- | --- |
| `vecshield/cli.py` | Click-based command-line interface. |
| `vecshield/sdk.py` | Stable Python SDK functions. |
| `vecshield/models.py` | Dependency-light dataclasses and enums. |
| `vecshield/classify/` | Classifier interface, regex detectors, optional NLP detector, ensemble merge logic. |
| `vecshield/ingest/` | Chunk-level gate, redaction helpers, framework adapters. |
| `vecshield/datasources/` | Local file and directory readers. |
| `vecshield/datascan/` | Dataset scanning engine. |
| `vecshield/score/` | Sensitivity and inversion-risk scoring helpers. |

## Data flow

```text
text or records -> classifier -> classification -> gate/report -> caller policy
```

The classifier produces a `Classification` with a sensitivity label, confidence,
detectors, and masked span previews. The ingest gate maps classifications to
findings and separates blocked chunks from allowed chunks.

## Extension points

- Implement `Classifier.classify()` for project-specific detectors.
- Compose detectors with `merge()` or `EnsembleClassifier`.
- Add local file readers under `vecshield/datasources/formats/`.
- Add framework adapters under `vecshield/ingest/adapters/`.
