"""ASQ-PHI benchmark for VecShield.

Loads + normalizes the ASQ-PHI adversarial synthetic clinical-query dataset
(1,051 short clinician-style prompts, 2,973 PHI spans across 13 HIPAA Safe
Harbor identifier types, plus 219 hard negatives that look PHI-like but are
not). Runs VecShield (regex / cascade / nlp) and scores standard span/document
detection metrics. Fully synthetic, MIT-licensed, end-to-end reproducible; see
``README.md`` in this directory.
"""
