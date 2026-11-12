"""Regulatory coverage benchmark: every category the engine claims, one corpus.

The other two benchmarks in this directory measure VecShield against public
datasets — ai4privacy for PII, ASQ-PHI for clinical PHI. Both are good, and
between them they cover two of the six frameworks in the criterion pack. There
is no public dataset for "trade union membership under GDPR Art. 9", for
magnetic-stripe track data under PCI DSS Requirement 3.3.1, or for a Polish
PESEL, so those categories have never been measured at all.

This benchmark closes that by carrying its own corpus: synthetic, wholly owned
by this repository, licence-clear, and organised by the obligation each case
exists to test rather than by the detector that happens to fire.

It is also *comparative*. The runner is a protocol, not a function, so the same
corpus can be scored against Presidio, a fine-tuned encoder, a zero-shot NER
model or an open-weight LLM — which is the question "is an open-source
classifier better than ours at this" actually reduces to.
"""
