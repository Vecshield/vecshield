"""CLI: score every available classifier against the corpus.

    python -m benchmarks.regulatory_coverage.run
    python -m benchmarks.regulatory_coverage.run --json
    python -m benchmarks.regulatory_coverage.run --regulation GDPR

Runners whose dependencies are absent are listed with the reason rather than
skipped silently. "Not installed" and "scored zero" are different facts and the
report keeps them apart.
"""

from __future__ import annotations

import argparse
import json
import sys

from benchmarks.regulatory_coverage.corpus import (
    REGULATIONS, corpus_manifest, load_corpus)
from benchmarks.regulatory_coverage.report import render, run
from benchmarks.regulatory_coverage.runners import default_runners


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="regulatory_coverage")
    parser.add_argument("--regulation", choices=list(REGULATIONS), default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    samples = load_corpus(args.regulation)
    reports = [run(runner, samples) for runner in default_runners()]

    if args.json:
        print(json.dumps({"corpus": corpus_manifest(),
                          "runners": [r.to_dict() for r in reports]}, indent=2))
        return 0

    manifest = corpus_manifest()
    print("regulatory coverage benchmark")
    print(f"  corpus   {manifest['cases']} cases "
          f"({manifest['positives']} positive, "
          f"{manifest['hard_negatives']} hard negative), "
          f"{manifest['gold_spans']} gold spans")
    print(f"  scope    {args.regulation or 'all frameworks'}")
    print("")
    for report in reports:
        print(render(report))
        print("")
    print("Recall is over the spans a classifier can express. A category it "
          "has no label for\nis counted under n/a and excluded, because a "
          "vocabulary limit is not an accuracy\nresult. Nothing here rolls up "
          "into a single score.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
