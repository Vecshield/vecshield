# NLP models for NER detection

VecShield's regex detectors (emails, card numbers, national identifiers, keys
and the rest) need nothing extra. Names, addresses, locations and organisations
come from Presidio running a spaCy pipeline, and that pipeline is a separate
package that has to be installed before a scan.

## The default model

| | |
| --- | --- |
| Package | `en_core_web_trf` 3.8.0 |
| What it is | Explosion's English RoBERTa-base pipeline for `spacy>=3.8`, loaded through `spacy-curated-transformers` on CPU PyTorch |
| Wheel | `https://github.com/explosion/spacy-models/releases/download/en_core_web_trf-3.8.0/en_core_web_trf-3.8.0-py3-none-any.whl` |
| SHA-256 | `272a31e9d8530d1e075351d30a462d7e80e31da23574f1b274e200f3fff35bf5` |
| Wheel size | about 460 MB, plus PyTorch (`torch>=2.6,<2.15`) |
| Weights licence | MIT |
| Memory | 2.2-3.2 GB per process after load, at batch 64 (measured 2.24 / 2.89 GB on macOS arm64 and 2.81 GB peak in the Linux image) |

The default is set in `vecshield_platform/nlp_models.py` (`DEFAULT_MODEL`)
and re-exported as `detection.DEFAULT_NLP_MODEL`. The model is not bundled with
the Python package: the wheel is several hundred megabytes, it brings in
PyTorch, and some deployments deliberately run a smaller model or regex only.
Scans never download it; detection loads only what is already installed.

Why `trf`: on the repository's own corpus (57 non-injection items,
`benchmark/corpus`) it finds two names and addresses the regex detectors miss
**without adding a false positive** (26 TP / 4 FP / 2 FN / 25 TN, committed as
`benchmark/baseline.nlp.json`). `en_core_web_lg` gains the same recall but
flags six more clean items, mostly product names read as organisations.

### Slim image: `en_core_web_lg`

The `slim` Docker target ships `en_core_web_lg` 3.8.0 (CNN with word vectors,
MIT) and no PyTorch. It uses about 0.8-1.3 GB of memory and is roughly three
times faster per chunk than `trf`, at the cost of more organisation false
positives. It is also the Community default.

### About `en_core_web_hftrf`

`en_core_web_hftrf` 3.8.1 (the same RoBERTa model repackaged with safetensors
weights) was the previous default. It stays in the catalog, but it does
**not load** with `spacy-transformers` 1.4.0, the newest release: support for
its weights landed upstream after that release and has not been published. It
also requires Python 3.11 or later. Revisit it when a released
`spacy-transformers` can read it. `en_core_web_trf` has no Python floor beyond
spaCy's own, so the project's Python 3.10 support is unaffected.

`vecshield-platform nlp catalog` lists every supported model with its
pinned version, languages, size and wheel URL, and marks the default. The
catalog holds `en_core_web_trf`, `en_core_web_hftrf`, `en_core_web_lg`,
`en_core_web_md` and `en_core_web_sm`, and the small German, French, Spanish,
Italian, Dutch, Portuguese, Polish and Swedish pipelines used for non-English
names.

## Checking what is installed

```sh
vecshield-platform nlp status          # human-readable
vecshield-platform nlp status --json   # for scripts
vecshield-platform detection-status    # what the scanner itself reports
```

When the requested model is missing, `detection-status` and the console
include an `install_command`, for example
`vecshield-platform nlp install en_core_web_trf`.

## Installing

### On a host or in a virtual environment

```sh
vecshield-platform nlp install --default            # the configured model
vecshield-platform nlp install --default --extras   # plus other languages
vecshield-platform nlp install en_core_web_lg       # a specific catalog model
vecshield-platform nlp install --default --dry-run  # show the pip commands only
```

`install` runs `python -m pip` with the interpreter that runs VecShield, in
three steps:

1. It installs the runtime dependencies: Presidio, spaCy 3.8, and for
   transformer models `spacy-curated-transformers` and torch (or
   `spacy-transformers` for hftrf). Pip leaves anything already satisfied
   alone. On Linux, install CPU torch first
   (`pip install --index-url https://download.pytorch.org/whl/cpu "torch>=2.6,<2.15"`),
   or pip pulls the CUDA build, several GB larger.
2. It installs the model wheels from a requirements file in pip's
   `--require-hashes --no-deps` mode, pinned to the SHA-256 published on the
   GitHub release. A substituted or corrupted wheel fails the install.
3. It loads each model in a fresh interpreter with `HF_HUB_OFFLINE=1` and
   `TRANSFORMERS_OFFLINE=1`, and checks that the pipeline has an `ner`
   component. `--no-verify` skips this step.

The command exits non-zero if any step fails. Restart running VecShield
processes afterwards, because a process that has already fallen back to regex
keeps that state until it restarts.

To load a model again without reinstalling it, run `vecshield-platform nlp
verify [MODELS...] [--extras]`.

### pip installs

A model wheel cannot be a pip dependency (the wheels live on GitHub releases,
and PyPI refuses direct-URL dependencies), so `pip install vecshield-platform`
never turns NER on by itself. The extras install the runtime:

```sh
pip install "vecshield-platform[nlp-trf]"   # the default model's runtime (PyTorch)
pip install "vecshield-platform[nlp-lg]"    # en_core_web_lg's runtime, no PyTorch
vecshield-platform nlp install --default    # then the model itself
```

`nlp-transformer` is kept as a deprecated alias of `nlp-trf`. Without a model,
pip installs stay in `auto` mode and `serve` and `scan` print a one-line
warning with the install command at start.

### Docker image

Both targets install the model at build time, verify it by loading it in an
offline interpreter, and set `VECSHIELD_NLP_MODE=required`, so a model that
fails to load stops the start instead of degrading silently.

```sh
docker build -t vecshield-platform .                        # full: en_core_web_trf
docker build --target slim -t vecshield-platform:slim .     # slim: en_core_web_lg, no torch
docker build --build-arg VECSHIELD_NLP_LANGUAGE_MODELS=--extras .          # plus other languages
docker build --build-arg VECSHIELD_NLP_LANGUAGE_MODELS="de_core_news_sm" . # one extra language
docker build --target slim --build-arg VECSHIELD_NLP_MODEL=none \
             --build-arg VECSHIELD_NLP_MODE=disabled .                     # regex only
```

| Build argument | Default | Meaning |
| --- | --- | --- |
| `VECSHIELD_NLP_MODEL` | `en_core_web_trf` (full), `en_core_web_lg` (slim) | Catalog model to install; also set as the image's `VECSHIELD_NLP_MODEL`. `none` for a regex-only image |
| `VECSHIELD_NLP_MODE` | `required` | Image's `VECSHIELD_NLP_MODE`; must be `disabled` with `none` |
| `VECSHIELD_NLP_LANGUAGE_MODELS` | empty | Non-English models: `--extras` or catalog names. Not in the image by default |
| `VECSHIELD_NLP_WHEELHOUSE` | empty | Offline wheel directory inside the build context |
| `TORCH_INDEX_URL` | CPU wheel index | Full target only; `""` resolves torch from `PIP_INDEX_URL` |

`VECSHIELD_NLP_MODELS` from earlier releases is refused with a message
pointing at these arguments, rather than ignored.

Measured on an Apple M4 Pro (Docker Desktop, linux/arm64) with a warm pip
cache for the base layers: full target 73-84 s to build, 3.13 GB on disk
(0.91 GB compressed); slim 60-64 s, 1.99 GB (0.64 GB compressed). x86-64
images and cold caches will differ. `nlp verify` passes offline
(`--network none`) in both. In the full image a started server reported
`loading` after 3 s and `ready` after 5 s, with no scan run.

PyTorch comes from the CPU wheel index by default, because the default Linux
wheel on PyPI includes several GB of CUDA libraries that a CPU scanner never
uses. The torch layer is installed before the source is copied, so a code
change does not download it again.

### Air-gapped installs (wheelhouse)

On a machine with internet access, collect the model wheels. They are
platform-independent and checked against their hashes:

```sh
vecshield-platform nlp fetch ./wheelhouse --default --extras
```

The runtime dependencies (spaCy, Presidio, spacy-curated-transformers, torch)
are platform-specific, so download them for the target platform too. For
example: `pip download --dest ./wheelhouse --platform manylinux2014_x86_64
--python-version 3.12 --only-binary=:all: "spacy>=3.8,<3.9"
"spacy-curated-transformers>=0.2.2,<1.0" "presidio-analyzer>=2.2,<2.3"`, and
CPU torch from `https://download.pytorch.org/whl/cpu`. A hashed lock for
these runtime dependencies is not shipped yet.

Then install without any index:

```sh
vecshield-platform nlp install --default --wheelhouse ./wheelhouse
# or: VECSHIELD_NLP_WHEELHOUSE=./wheelhouse vecshield-platform nlp install --default
```

This runs `pip install --no-index --find-links <dir>`, still hash-pinned. For
Docker, put the directory in the build context and pass `--build-arg
VECSHIELD_NLP_WHEELHOUSE=/app/wheelhouse`. To make the base package install
offline as well, pass `PIP_NO_INDEX=1` and `PIP_FIND_LINKS=/app/wheelhouse`.

### Private package index

`--index-url URL` sends both the dependency and model installs through your
mirror, which must host the spaCy model wheels. The hashes still apply. Pass
credentials in the `PIP_INDEX_URL` environment variable rather than on the
command line, where other users can see them in the process list. The CLI
hides credentials in anything it prints.

The index must be `https://`. The model wheels are hash-pinned, but the
runtime dependencies (spaCy, Presidio, and `spacy-curated-transformers` and
torch for the transformer default) are installed by version range, not by hash, so a
plain-HTTP index would let anyone on the network path substitute them.
`--allow-insecure-index` permits an `http://` index on a network you trust;
the CLI marks its host as trusted for pip and prints a warning. For a
tamper-evident install of the dependencies too, build a wheelhouse from a
hashed requirements file (`pip download --require-hashes -r ...`) and install
with `--wheelhouse`, or bake them into the image and pass
`--skip-dependencies`.

### Hashes and models outside the catalog

- `--hashes FILE` supplies or overrides hashes, one `<model> sha256:<hex>`
  per line. A single spec such as `en_core_web_lg@sha256:<hex>` does the same.
- A model outside the catalog needs an explicit source and opt-in:
  `--allow-unlisted my_model=https://host/my_model-1.0-py3-none-any.whl@sha256:<hex>`,
  or a local `.whl` path. Only `https://` URLs are accepted. Without a hash
  pip cannot verify the file, and the CLI says so.

## Configuration

| Variable | Meaning |
| --- | --- |
| `VECSHIELD_NLP_MODE` | `auto` (default: use NLP if installed, otherwise report degraded coverage), `required` (fail if the model cannot load), `disabled` (regex only) |
| `VECSHIELD_NLP_MODEL` | Model package name or local model directory; default `en_core_web_trf` |
| `VECSHIELD_NER_MODELS` | Extra languages, e.g. `de=de_core_news_sm,fr=fr_core_news_sm`; `none` turns them off. Default: the eight small news pipelines |
| `VECSHIELD_NLP_WHEELHOUSE` | Default `--wheelhouse` for `nlp install` |
| `VECSHIELD_NLP_ENTITIES` | Comma-separated Presidio entity types to request. Default: `PERSON, EMAIL_ADDRESS, PHONE_NUMBER, LOCATION, US_SSN, US_DRIVER_LICENSE, US_PASSPORT, IP_ADDRESS, NRP, ORGANIZATION, URL, CREDIT_CARD, US_BANK_NUMBER, IBAN_CODE, MEDICAL_LICENSE, DATE_TIME`. An unknown name is an error |
| `VECSHIELD_NLP_ALLOW_LIST` | Comma-separated terms the NER layer must never report (product, brand or fictional names) |
| `VECSHIELD_NLP_ALLOW_LIST_FILE` | File of such terms, one per line, `#` comments; combined with the variable above. An unreadable file makes detection `unavailable` |
| `VECSHIELD_NLP_TIME_BUDGET_S` | Seconds of NER model time one store scan may spend; unset or `0` means no budget |
| `VECSHIELD_NLP_WARMUP` | `off` stops `serve` loading the model in the background at start |

### Organisations and the allow-list

`ORGANIZATION` stays in the default entity list: an employer or a clinic named
next to a person is personal (or health) information. Where company and
product names are not personal data for a deployment, remove it with
`VECSHIELD_NLP_ENTITIES`, or list the specific names in the allow-list.
Allow-list matching is exact on the whole span, ignoring case and spacing, the
same semantics as Presidio's `allow_list`. It applies only to Presidio's
spans: pattern detectors still fire, so allow-listing a name never hides an
e-mail address or a card number. Detection status reports
`requested_entities` and `allow_list_terms` (the count, not the terms).

## Ingest gate severity for NLP-only spans

The model gives every name the same fixed score, so it cannot tell
"Taylor Swift" in "Ask Alexa to play Taylor Swift" from a customer's name. At
the ingest gate, a `PERSON`, `LOCATION`, `ORGANIZATION` or `NRP` span found by
the model alone therefore rates **MEDIUM**, below the default HIGH block bar.
It keeps its label's severity (HIGH for personal data) when corroborated by:

- a pattern (regex) detector firing in the same chunk;
- clinical context (the span was labelled PHI); or
- a second kind of direct identifier from the model in the same chunk (a
  person *and* a location).

A blocked finding records `severity_basis` (`pattern`, `nlp_corroborated` or
`nlp_only`), and every sensitive chunk allowed below the bar is listed in the
gate report's `below_threshold`, so a downgrade is visible. Known limit:
fiction that names a person and a place ("Sherlock Holmes lived at 221B Baker
Street") is corroborated by the second-identifier rule; use the allow-list.
Store scans are unaffected by this rule; it applies to the gate's block
decision only.

## Start-up, throughput and coverage

- **Warm-up.** `serve` loads the configured model on a background thread, so
  detection status reads `loading` and then `ready` (or `degraded` /
  `unavailable` with the reason) without a scan, and the first scan does not
  pay the 4-40 s load. In `required` mode, a model that is not installed stops
  `serve` before it binds.
- **Batching.** Scans classify 64 chunks at a time through `classify_batch`
  (spaCy `nlp.pipe`). In the Linux image this measured 93 ms per ~700-character
  chunk against 256 ms one at a time for `trf`.
- **Time budget.** With `VECSHIELD_NLP_TIME_BUDGET_S` set, a store scan that
  spends its budget classifies the remaining chunks with pattern detectors
  only, marks each affected collection partial with the count
  (`chunks_without_nlp`), and records `nlp_classification` as inconclusive.
  Nothing is skipped silently. Plan for about 40 ms of model time per chunk on
  a 2-4 vCPU pod: the default cap of 50,000 chunks per collection is over half
  an hour.
- **Long surfaces.** Each text surface is classified up to 5,000 characters.
  A longer one is recorded (`surfaces_truncated`, `chars_not_classified`) and
  makes the collection's coverage partial; the ingest gate lists such chunks in
  `truncated_surfaces`.


## What "degraded" means

In `auto` mode with no model installed, scans still run with the regex
detectors, and detection status is `degraded` with a reason and an
`install_command`. A model whose declared runtime is missing (for example
`en_core_web_trf` without `spacy-curated-transformers` or torch) is degraded
the same way. An installed model reads `unverified` until a process has loaded
it, `loading` while the warm-up (or a first scan) loads it, and `ready` only
after that load succeeds. A load that failed in `required` mode reads
`unavailable` with the error. This is reduced coverage, not a clean
result: every classification outcome in a degraded or NLP-disabled run is
partial, and the crypto gate does not pass it. Names,
addresses and locations are not detected, and a scan with no findings under
degraded detection does not show that a collection contains no personal
data. Use `required` mode where a missing model should stop the scan instead.
Extra language models work the same way: text in a language with no loaded
model gets regex-only coverage for names.

## Security: no web-triggered installs

Installing is only possible from the CLI on the host or during an image build.
There is no API endpoint or console button that installs packages, and none
should be added. Installing a package runs code from that package, so an
endpoint that installs on request would let anyone who can reach it run code
on the server and push a malicious package into it. The console shows the
command to run and leaves running it to an operator. The installer passes
argument lists to pip and never uses a shell. It pins model wheels by hash
and accepts sources outside the catalog only with `--allow-unlisted`.
