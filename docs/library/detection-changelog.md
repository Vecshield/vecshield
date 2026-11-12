# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows Semantic
Versioning before and after the `1.0.0` release.

## [Unreleased]

### Added

- Professional FOSS repository structure, contributor documentation, examples,
  and quality tooling.

## [0.0.1] - 2026-07-06

### Added

- Local PII/PHI/PCI/secret detection with a dependency-light regex classifier.
- Optional NLP detection through Presidio and spaCy.
- CLI commands for `detect`, `ingest-check`, `training-check`, and
  `redact-preview`.
- Python SDK helpers for text checks, chunk gates, dataset scans, and redaction.
- Local datasource readers for common training-data formats.

[Unreleased]: https://github.com/vecshield/vecshield/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/vecshield/vecshield/releases/tag/v0.0.1
