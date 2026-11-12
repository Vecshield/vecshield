# Contributing to VecShield

Thanks for considering a contribution. This page is the development setup and
the gates a change has to pass.

## Setup

```bash
git clone https://github.com/vecshield/vecshield
cd vecshield
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,chroma]"          # what CI installs
```

Python 3.10 or newer. Add connector extras for what you work on:
`pip install -e ".[dev,chroma,qdrant,pgvector]"`.

## The gates

CI (`.github/workflows/ci.yml`) is the source of truth. Locally:

```bash
python -m ruff check .                  # enforced (rules F and E9 only)
python -m mypy vecshield_platform       # advisory; the annotation backlog is being paid down
python -m pytest                        # excludes the `integration` marker by default
python -m pytest --cov=vecshield_platform --cov=vecshield --cov-report=term-missing
```

**Check the skip report before calling a run green.** Many tests
`importorskip` optional SDKs, so without the right extras whole suites skip
rather than fail:

```bash
python -m pytest -rs                    # -rs shows why things skipped
```

Container-backed tests are opt-in and need Docker:

```bash
pip install -e ".[integration,chroma]"
python -m pytest -m integration
```

### Console changes

The console that ships is the hand-written bundle in
`vecshield_platform/api/dashboard/dist/` (`dashboard.js`, `dashboard.css`,
`theme.js`). Edit those files directly — there is no build step.

```bash
cd vecshield_platform/api/dashboard
npm ci
npm run check                           # syntax-check the bundles
npm test                                # all tests/*.test.mjs against dist/
```

Things the console tests enforce, so you do not have to remember them:

- `boot();` stays the last line of `dashboard.js` — the test harness loads the
  file into a `vm` sandbox and strips that call.
- The shell carries no inline script or style; a strict CSP forbids it.
- Brand colours come from `--brand-*` tokens in `dashboard.css`
  (`brand.test.mjs`, `contrast.test.mjs`), and the comment at the top of that
  file lists the rest of the contracts.
- Fonts are self-hosted in `dist/assets/fonts/`; the CSP allows same-origin
  files only.
- `parity.test.mjs` resolves every workflow in
  `tests/fixtures/console-parity-checklist.md` against the console's own area
  registry, so a screen cannot quietly lose a workflow.

### Detector changes

Detector changes must also clear the benchmark gates:

```bash
python -m vecshield_platform.cli benchmark run \
    --corpus benchmark/corpus --out benchmark/results.json
python -m vecshield_platform.cli benchmark compare \
    --baseline benchmark/baseline.json --candidate benchmark/results.json --tolerance 0.02
python -m vecshield_platform.cli benchmark calibrate \
    --corpus benchmark/corpus --out benchmark/calibration.json --check
```

`compare` fails if precision regressed. If your change legitimately moves the
numbers, update the baseline **in the same pull request** and say in the
description what moved and why.

The NLP variants (`baseline.nlp.json`, `calibration.nlp.json`) run only in the
nightly job with `VECSHIELD_NLP_MODE=required` and a real spaCy model; see
[docs/nlp_models.md](docs/nlp_models.md).

If you add a detector, add labelled cases to `benchmark/corpus/` — including a
**hard negative**, something that looks like a hit but is not. A detector with
no negative case has not been shown to be precise.

## Things this project is strict about

These are not style preferences; they are what the tool is for.

- **Never report unknown as safe.** When a connector cannot observe something,
  it raises `UnsupportedCapability` and the result is *unsupported* or
  *inconclusive*. Do not let a missing capability become a pass. `coverage.py`
  carries these states and they must survive all the way to the API, console
  and reports.
- **A partial read is not a clean read.** If a chunk cap was hit or the
  connector could not read some rows, the run is partial and the CLI exits `3`.
- **Keep detection separate from regulatory judgement.** Applicability, the
  technical result, evidence sufficiency and a reviewer's conclusion are four
  separate fields. Read `docs/architecture.md` § Regulatory content before
  touching `compliance/`.
- **Server-side authorization.** Every route gets a role dependency, and
  `tests/test_route_authorization.py` is the regression suite. Add your route's
  gate there too.
- **No secrets anywhere they can leak.** Not in commits, logs, diagnostics,
  error messages or test fixtures. Secrets are referenced through an allowlist
  (ADR 0003) and masked by the admin API.
- **Masked by default.** Chunk values are masked unless explicitly revealed
  through `reveal.py`, which is audit-logged.

## Tests

| Path | Scope |
|---|---|
| `tests/` | The platform |
| `tests/community/` | The detection library |
| `tests/system/` | Benchmark-level checks |
| `tests/integration/` | Docker-backed, opt-in |

`tests/assessment_contract.py` is the store-agnostic end-to-end check of a full
audit: seeded issues plus the outcome every check must report. **Changing a
check's outcome, or adding or renaming a check, means updating it.** Proving a
new store works means running that contract against it — see
`tests/integration/README.md`.

## Architecture decisions

Significant decisions live in `docs/adr/`. Add one when you change an
interface, a security boundary, or a default that users depend on. Follow the
format of the existing records.

## Pull requests

- Describe what changed and how you verified it. Name the checks you actually
  ran; "tests pass" without a skip report is not evidence.
- Keep unrelated changes out. A rename and a behaviour change in one diff is
  hard to review and harder to revert.
- Match the surrounding code's tone. This codebase states limitations plainly
  and marks uncertainty as uncertainty. Please do not replace a careful hedge
  with a confident claim.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under
Apache-2.0, matching [LICENSE](LICENSE).
