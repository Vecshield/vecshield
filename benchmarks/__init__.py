"""VecShield public benchmark harness.

Each benchmark lives in its own sub-package. Currently available:

* :mod:`benchmarks.ai4privacy` — the ai4privacy/pii-masking-200k benchmark
  (load + normalize the dataset, run VecShield, score standard span/document
  detection metrics).
* :mod:`benchmarks.bigcode_pii` — the bigcode/bigcode-pii-dataset benchmark
  (PII in source code across 31 programming languages; gated, requires an
  approved HuggingFace access request).
* :mod:`benchmarks.asq_phi` — the ASQ-PHI benchmark (adversarial synthetic
  clinical queries; PHI detection + over-redaction at the safe-handoff
  boundary; fully synthetic, MIT-licensed, no access gate).
"""
