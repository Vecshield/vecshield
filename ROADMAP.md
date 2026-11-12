# Roadmap

This is a statement of direction, not a set of commitments or dates. Issues
and discussions are where specifics get decided; nothing here is promised.

## What the project is trying to be

A tool that tells you the truth about what is in your vector stores — including
when it cannot tell. The things we will not trade away for a nicer-looking
report:

- **Unknown is never reported as safe.** If a connector cannot observe
  something, that is what the result says.
- **Detection stays separate from regulatory judgement.** A technical finding
  is not a compliance determination, and the data model keeps them apart.
- **Limitations stay documented.**
  [`docs/detection_limitations.md`](docs/detection_limitations.md) exists to be
  read, and it gets updated when coverage changes — in both directions.
- **Claims are measured.** A confidence class comes from the benchmark corpus,
  and CI rejects a calibration that claims more than the corpus supports.

## Known gaps we would like to close

These are documented limitations today, each with more detail in the linked
page.

- **Non-English detection.** The NER layer is English-only. Language is
  detected and reported in the coverage statement, so a non-English corpus is
  flagged rather than silently under-scanned, but that is a signpost, not a
  fix. See [detection limitations](docs/detection_limitations.md) §0.
- **Raw biometric templates.** `biometric_reference` detects the words around
  biometric data, not encoded templates themselves.
- **CPRA sensitive personal information** has no label of its own, and the
  co-occurrence rules that would support one are not implemented.
- **Non-EU national identifiers.** Twelve check-digited EU identifiers are
  covered; the non-EU list is not.
- **Crypto posture beyond the data plane.** Cloud KMS, volume encryption, HSMs
  and cloud IAM are deliberately out of scope and reported as not observable.
  Closing this would mean becoming a CSPM, which is a different tool.

## Directions under consideration

- More vector stores. The `Connector` ABC plus a `store_facts` module is the
  whole surface; [`tests/integration/README.md`](tests/integration/README.md)
  describes what proving a new one requires.
- Richer runtime monitoring of the retrieval path, beyond the current
  enumeration, bulk-retrieval and rate detectors.
- Reducing the annotation backlog so mypy can become a blocking gate instead of
  an advisory one.
- Making the React console in the dashboard a real option, or deciding not to.
  Today the shipped console is a hand-written bundle, and the half-built
  alternative has been removed rather than left to rot.

## How to influence this

Open an issue describing the problem you have, not only the feature you want —
the problem is the part we can design against. If you are considering a large
change, raise it in a discussion before building it, so the design conversation
happens before the diff.
