# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changes to the detection engine specifically are also tracked in
[`docs/library/detection-changelog.md`](docs/library/detection-changelog.md).

## [Unreleased]

## [0.1.0]

First open-source release, under Apache-2.0.

### Added

- `vecshield` — the detection library: regex and checksum classifiers with an
  optional Presidio/spaCy NER layer, an ingest gate, chunk-boundary analysis,
  dataset scanning, and framework adapters for LangChain, LlamaIndex, Airflow,
  Dagster and Prefect.
- `vecshield_platform` — the server: a FastAPI API and web console, thirteen
  vector-store connectors, and five assessment engines (scan, posture,
  integrity, access, compliance).
- Role-based access control (`viewer`, `operator`, `compliance`, `admin`) with
  static tokens, JWT, or local accounts; separation of duties on approvals; a
  hash-chained audit log; and an audited reveal path for masked values.
- Coverage states throughout: a check that could not observe something reports
  *unsupported* or *inconclusive* rather than passing, and a partial read exits
  `3` rather than `0`.
- A labelled benchmark corpus with precision and recall reported as Wilson
  intervals, plus confidence calibration derived from measurement. CI fails on
  a regression.
- A seeded demo estate — six stores, fourteen collections, fifteen scenarios
  across six regulatory frameworks — that verifies its own scenarios still
  fire, with a one-command Docker Compose stack.

[Unreleased]: https://github.com/vecshield/vecshield/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vecshield/vecshield/releases/tag/v0.1.0
