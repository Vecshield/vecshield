"""Catalog and install planning for the spaCy models the NER detectors use.

Detection never downloads weights at classification time (see
``vecshield_platform.detection``). Models are installed ahead of time by an
operator -- at image build or with ``vecshield-platform nlp install`` -- and
this module decides *what* that install runs:

* a pinned catalog of supported models, each with the wheel URL on the
  explosion/spacy-models GitHub release and the SHA-256 published there;
* pure functions that turn a request into ``pip`` argv lists (never a shell
  string) for three sources: the public release, an offline wheelhouse, or a
  private package index;
* hash pinning in ``pip --require-hashes`` form, so a tampered or substituted
  wheel fails the install instead of being loaded into the scanner.

There is deliberately no HTTP entry point for any of this. Installing packages
in response to a web request would turn the API into a remote code execution
and supply-chain surface; installs are an operator action on the host or in
the image build.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import metadata
import json
from pathlib import Path
import re
from typing import Iterable, Mapping, Sequence

RELEASE_BASE = "https://github.com/explosion/spacy-models/releases/download"
INSTALL_COMMAND = "vecshield-platform nlp install"

SPACY_REQUIREMENT = "spacy>=3.8.0,<3.9.0"
# Every NER path goes through Presidio; the model alone is not enough.
RUNTIME_REQUIREMENTS: tuple[str, ...] = ("presidio-analyzer>=2.2",)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HASH_SUFFIX = re.compile(r"@sha256:([0-9A-Fa-f]{64})$")
_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")
_VERSION = re.compile(r"^[0-9][0-9A-Za-z.+!-]{0,40}$")
#: A URL's scheme and authority: the authority runs to the first "/", "?",
#: "#" or whitespace, as ``urllib.parse.urlsplit`` delimits the netloc.
_URL_AUTHORITY = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^\s/?#]*)")


class ModelSpecError(ValueError):
    """A requested model, source or hash is not acceptable."""


@dataclass(frozen=True)
class ModelSpec:
    """One supported spaCy pipeline, pinned to a single published wheel."""

    name: str
    version: str
    languages: tuple[str, ...]
    sha256: str
    size_bytes: int
    requires: tuple[str, ...]
    description: str
    transformer: bool = False

    @property
    def wheel_filename(self) -> str:
        return f"{self.name}-{self.version}-py3-none-any.whl"

    @property
    def wheel_url(self) -> str:
        return f"{RELEASE_BASE}/{self.name}-{self.version}/{self.wheel_filename}"

    @property
    def approx_size_mb(self) -> int:
        return round(self.size_bytes / 1_000_000)

    @property
    def default(self) -> bool:
        return self.name == DEFAULT_MODEL


def _spec(name: str, version: str, languages: tuple[str, ...], sha256: str,
          size_bytes: int, description: str, *, extra: tuple[str, ...] = (),
          transformer: bool = False) -> ModelSpec:
    return ModelSpec(name=name, version=version, languages=languages, sha256=sha256,
                     size_bytes=size_bytes, requires=(SPACY_REQUIREMENT, *extra),
                     description=description, transformer=transformer)


#: The default model (full image and ``VECSHIELD_NLP_MODEL`` unset).
DEFAULT_MODEL = "en_core_web_trf"
#: The slim image's model: no PyTorch, about 1 GB of memory.
SLIM_MODEL = "en_core_web_lg"

# Checksums and sizes are the ones published on each GitHub release (asset
# digest for hftrf, "Checksum .whl" in the release notes for the others).
CATALOG: dict[str, ModelSpec] = {spec.name: spec for spec in (
    _spec("en_core_web_trf", "3.8.0", ("en",),
          "272a31e9d8530d1e075351d30a462d7e80e31da23574f1b274e200f3fff35bf5",
          457_421_864,
          "English RoBERTa transformer (curated-transformers, CPU PyTorch); the "
          "default model. 2.2-3.2 GB of memory.",
          extra=("spacy-curated-transformers>=0.2.2,<1.0.0", "torch>=2.6,<2.15"),
          transformer=True),
    _spec("en_core_web_hftrf", "3.8.1", ("en",),
          "a9d611edc8735f8d79ea6f9fbd840f7a66d2da350be4870fa5f1ab98475615f0",
          460_326_531,
          "English RoBERTa transformer (en_core_web_trf 3.6.1 repackaged with "
          "safetensors weights). Not loadable with spacy-transformers 1.4.0, the "
          "latest release; kept for when a release reads its weights.",
          extra=("spacy-transformers>=1.4.0,<1.5.0",), transformer=True),
    _spec("en_core_web_lg", "3.8.0", ("en",),
          "293e9547a655b25499198ab15a525b05b9407a75f10255e405e8c3854329ab63",
          400_658_291, "English CNN with large word vectors; the slim-image "
          "default. About 1 GB of memory, no PyTorch."),
    _spec("en_core_web_md", "3.8.0", ("en",),
          "5e6329fe3fecedb1d1a02c3ea2172ee0fede6cea6e4aefb6a02d832dba78a310",
          33_480_380, "English CNN with medium word vectors."),
    _spec("en_core_web_sm", "3.8.0", ("en",),
          "1932429db727d4bff3deed6b34cfc05df17794f4a52eeb26cf8928f7c1a0fb85",
          12_806_118, "English CNN without word vectors; lowest recall."),
    _spec("de_core_news_sm", "3.8.0", ("de",),
          "fec69fec52b1780f2d269d5af7582a5e28028738bd3190532459aeb473bfa3e7",
          14_639_490, "German news pipeline (small)."),
    _spec("fr_core_news_sm", "3.8.0", ("fr",),
          "7d6ad14cd5078e53147bfbf70fb9d433c6a3865b695fda2657140bbc59a27e29",
          16_271_721, "French news pipeline (small)."),
    _spec("es_core_news_sm", "3.8.0", ("es",),
          "e451a83d6df79b87e9eed0cb553f03e99e36a3bab18a7b79f0dcfd1fdf875e12",
          12_884_212, "Spanish news pipeline (small)."),
    _spec("it_core_news_sm", "3.8.0", ("it",),
          "3f617bf9a8ae0418953cf1fbf014e10272684c4229e882a7fd748b637d0100bf",
          13_030_943, "Italian news pipeline (small)."),
    _spec("nl_core_news_sm", "3.8.0", ("nl",),
          "a76978477821f213ca76a46c686df1b1d41462905d4868bc53eac086adca8b7e",
          12_825_227, "Dutch news pipeline (small)."),
    _spec("pt_core_news_sm", "3.8.0", ("pt",),
          "c304fa04db3af73cd08a250feacf560506e15a2ec2469bd1b09f06847f6b455c",
          12_985_007, "Portuguese news pipeline (small)."),
    _spec("pl_core_news_sm", "3.8.0", ("pl",),
          "9b536db854b0cdb9132a74f68b392b8112ab6030f971bb03282462362a940dbb",
          20_213_213, "Polish news pipeline (small)."),
    _spec("sv_core_news_sm", "3.8.0", ("sv",),
          "be4929fb30523dca0b6672f999cdbf4d64f165419f1eed0014ca3a36599b8b4d",
          12_741_934, "Swedish news pipeline (small)."),
)}


@dataclass(frozen=True)
class ModelTarget:
    """A resolved install request: what to install, from where, and its hash."""

    name: str
    version: str | None
    source: str | None          # explicit https URL or absolute local path (unlisted)
    sha256: str | None
    requires: tuple[str, ...]
    listed: bool
    notes: tuple[str, ...] = ()

    @property
    def hash_pinned(self) -> bool:
        return self.sha256 is not None


@dataclass(frozen=True)
class InstallOptions:
    python: str
    wheelhouse: str | None = None
    index_url: str | None = None
    install_dependencies: bool = True
    #: Permit a plain-http index. Off by default: an index serves the
    #: dependency step, which is not hash-pinned, so anyone on the path could
    #: substitute packages. Explicit, and the CLI warns when it is used.
    allow_insecure_index: bool = False


@dataclass(frozen=True)
class InstallStep:
    purpose: str
    argv: tuple[str, ...]
    requirements_path: str | None = None
    requirements_text: str | None = None


@dataclass(frozen=True)
class InstallPlan:
    targets: tuple[ModelTarget, ...]
    steps: tuple[InstallStep, ...]
    notes: tuple[str, ...] = field(default=())

    @property
    def download_bytes(self) -> int:
        return sum(CATALOG[t.name].size_bytes for t in self.targets
                   if t.listed and t.name in CATALOG)


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


def install_hint(model: str | None) -> str | None:
    """The CLI command that installs ``model``, when the catalog knows it."""
    if model and model in CATALOG:
        return f"{INSTALL_COMMAND} {model}"
    return None


def redact(value: str) -> str:
    """Hide URL credentials (``https://user:token@host``) in displayed text.

    The host follows the *last* "@" in the authority, so a password that
    itself contains "@" is hidden whole rather than cut at its first "@".
    """
    def hide(match: re.Match) -> str:
        scheme, authority = match.group(1), match.group(2)
        if "@" not in authority:
            return match.group(0)
        return f"{scheme}***@{authority.rpartition('@')[2]}"

    return _URL_AUTHORITY.sub(hide, value)


def redact_argv(argv: Iterable[str]) -> list[str]:
    return [redact(part) for part in argv]


def normalise_sha256(value: str) -> str:
    digest = value.strip()
    if digest.lower().startswith("sha256:"):
        digest = digest[7:]
    digest = digest.lower()
    if not _SHA256.match(digest):
        raise ModelSpecError("SHA-256 must be 64 hexadecimal characters")
    return digest


def split_model_args(values: Iterable[str]) -> list[str]:
    """Accept space- or comma-separated names; keep first-seen order."""
    seen: dict[str, None] = {}
    for value in values:
        for part in value.split(","):
            if part.strip():
                seen.setdefault(part.strip(), None)
    return list(seen)


def parse_hashes_file(text: str) -> dict[str, str]:
    """Parse operator-supplied hashes.

    Accepted lines (``#`` comments and blanks ignored)::

        en_core_web_trf sha256:<hex>
        en_core_web_trf==3.8.0 --hash=sha256:<hex>
        en_core_web_trf=<hex>
    """
    hashes: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.search(r"(?:sha256[:=])?([0-9A-Fa-f]{64})\b", line)
        head = re.split(r"[\s=@]", line, maxsplit=1)[0].strip()
        if not match or not head or not _NAME.match(head):
            raise ModelSpecError(f"hashes file line {number}: expected '<model> sha256:<hex>'")
        digest = normalise_sha256(match.group(1))
        if hashes.get(head, digest) != digest:
            raise ModelSpecError(f"hashes file line {number}: conflicting hash for {head}")
        hashes[head] = digest
    return hashes


def _validate_name(name: str) -> str:
    if not _NAME.match(name):
        raise ModelSpecError(f"{name!r} is not a valid model package name")
    return name


def _validate_source(source: str) -> str:
    lowered = source.lower()
    if "://" in source:
        if not lowered.startswith("https://"):
            raise ModelSpecError("model URLs must use https:// (or pass a local file path)")
        return source
    if not (lowered.endswith(".whl") or lowered.endswith(".tar.gz")):
        raise ModelSpecError("a local model source must be a .whl or .tar.gz file")
    return str(Path(source).expanduser().absolute())


def parse_model_spec(spec: str, *, allow_unlisted: bool = False,
                     hashes: Mapping[str, str] | None = None) -> ModelTarget:
    """Resolve one requested model.

    ``NAME``                       catalog model at its pinned version
    ``NAME==VERSION``              the same, only if VERSION is the pinned one
    ``NAME@sha256:HEX``            operator-supplied hash (overrides the catalog)
    ``NAME=URL_OR_PATH[@sha256:HEX]``  unlisted source; needs ``allow_unlisted``
    """
    text = spec.strip()
    if not text:
        raise ModelSpecError("empty model name")
    supplied_hash: str | None = None
    if match := _HASH_SUFFIX.search(text):
        supplied_hash = normalise_sha256(match.group(1))
        text = text[:match.start()]
    source: str | None = None
    version: str | None = None
    # Split on the first '=' only, so a source URL may itself contain '='.
    head, separator, rest = text.partition("=")
    if separator and rest.startswith("="):
        text, version = head, rest[1:].strip()
        if not _VERSION.match(version):
            raise ModelSpecError(f"{spec!r}: invalid version")
    elif separator:
        text, source = head, rest.strip()
        if not source:
            raise ModelSpecError(f"{spec!r}: missing source after '='")
    name = _validate_name(text.strip())
    if supplied_hash is None and hashes and name in hashes:
        supplied_hash = normalise_sha256(hashes[name])
    catalog = CATALOG.get(name)
    notes: list[str] = []

    if source is not None:
        if not allow_unlisted:
            raise ModelSpecError(
                f"{spec!r} names an explicit source; pass --allow-unlisted to install it")
        source = _validate_source(source)
        if supplied_hash is None:
            notes.append(f"{name}: not hash-pinned; supply NAME=SOURCE@sha256:<hex> "
                         "or --hashes to have pip verify it")
        requires = catalog.requires if catalog else (SPACY_REQUIREMENT,)
        return ModelTarget(name=name, version=None, source=source, sha256=supplied_hash,
                           requires=requires, listed=False, notes=tuple(notes))

    if catalog is None:
        supported = ", ".join(sorted(CATALOG))
        hint = ("pass --allow-unlisted NAME=<https-url-or-path>" if allow_unlisted
                else "use --allow-unlisted NAME=<https-url-or-path> for a model outside it")
        raise ModelSpecError(f"{name!r} is not in the supported catalog ({supported}); {hint}")
    if version is not None and version != catalog.version:
        raise ModelSpecError(
            f"{name} is pinned to {catalog.version}; for {version} use "
            f"--allow-unlisted {name}=<https-url-or-path>")
    if supplied_hash is not None and supplied_hash != catalog.sha256:
        notes.append(f"{name}: operator hash overrides the published checksum")
    return ModelTarget(name=name, version=catalog.version, source=None,
                       sha256=supplied_hash or catalog.sha256, requires=catalog.requires,
                       listed=True, notes=tuple(notes))


def resolve_targets(specs: Sequence[str], *, allow_unlisted: bool = False,
                    hashes: Mapping[str, str] | None = None) -> list[ModelTarget]:
    targets: dict[str, ModelTarget] = {}
    for spec in split_model_args(specs):
        target = parse_model_spec(spec, allow_unlisted=allow_unlisted, hashes=hashes)
        if target.name in targets and targets[target.name] != target:
            raise ModelSpecError(f"{target.name} was requested twice with different sources")
        targets[target.name] = target
    return list(targets.values())


def _source_flags(options: InstallOptions) -> list[str]:
    if options.wheelhouse and options.index_url:
        raise ModelSpecError("--wheelhouse and --index-url are mutually exclusive")
    if options.wheelhouse:
        return ["--no-index", "--find-links", options.wheelhouse]
    if options.index_url:
        lowered = options.index_url.lower()
        if not lowered.startswith(("https://", "http://")):
            raise ModelSpecError("--index-url must be an http(s) URL")
        if lowered.startswith("http://"):
            if not options.allow_insecure_index:
                raise ModelSpecError(
                    "--index-url must use https://; a plain-http index lets anyone on "
                    "the network path substitute the (not hash-pinned) dependency "
                    "packages. Pass --allow-insecure-index only for a trusted network.")
            from urllib.parse import urlsplit

            host = urlsplit(options.index_url).netloc.rpartition("@")[2]
            # pip ignores a plain-http index unless its host is trusted.
            return ["--index-url", options.index_url, "--trusted-host", host]
        return ["--index-url", options.index_url]
    return []


def _requirement_line(target: ModelTarget, options: InstallOptions) -> str:
    """One requirement for the model itself, as a ``pip install`` argument or
    a requirements-file line (the hash is appended by the caller)."""
    if target.source is not None:
        if options.wheelhouse and "://" in target.source:
            raise ModelSpecError(
                f"{target.name}: wheelhouse installs are offline; give a local path, not a URL")
        location = target.source if "://" in target.source else Path(target.source).as_uri()
        return f"{target.name} @ {location}"
    if options.wheelhouse or options.index_url:
        return f"{target.name}=={target.version}"
    return f"{target.name} @ {CATALOG[target.name].wheel_url}"


def _pip(options: InstallOptions, verb: str = "install") -> list[str]:
    return [options.python, "-m", "pip", verb, "--disable-pip-version-check", "--no-input"]


def plan_install(targets: Sequence[ModelTarget], options: InstallOptions, *,
                 requirements_path: str) -> InstallPlan:
    """Build the ordered pip invocations for ``targets``.

    1. Runtime dependencies (spaCy, Presidio, transformer backends), resolved
       normally so pip keeps what is already satisfied.
    2. Hash-pinned model wheels, from a requirements file under
       ``--require-hashes --no-deps`` (hash-checking mode cannot mix with
       unhashed transitive dependencies, which is why step 1 exists).
    3. Unpinned unlisted models, only when the operator chose that explicitly.
    """
    if not targets:
        raise ModelSpecError("no models selected")
    source = _source_flags(options)
    steps: list[InstallStep] = []
    notes: list[str] = [note for target in targets for note in target.notes]

    if options.install_dependencies:
        requirements: dict[str, None] = dict.fromkeys(RUNTIME_REQUIREMENTS)
        for target in targets:
            requirements.update(dict.fromkeys(target.requires))
        steps.append(InstallStep(
            purpose="runtime dependencies",
            argv=tuple(_pip(options) + source + list(requirements))))

    pinned = [t for t in targets if t.hash_pinned]
    if pinned:
        lines = [f"{_requirement_line(t, options)} --hash=sha256:{t.sha256}" for t in pinned]
        steps.append(InstallStep(
            purpose="hash-pinned models: " + ", ".join(t.name for t in pinned),
            argv=tuple(_pip(options) + ["--no-deps", "--require-hashes"] + source
                       + ["-r", requirements_path]),
            requirements_path=requirements_path,
            requirements_text="\n".join(lines) + "\n"))
    for target in (t for t in targets if not t.hash_pinned):
        steps.append(InstallStep(
            purpose=f"unpinned model: {target.name}",
            argv=tuple(_pip(options) + source + [_requirement_line(target, options)])))
    return InstallPlan(targets=tuple(targets), steps=tuple(steps), notes=tuple(notes))


def plan_download(targets: Sequence[ModelTarget], *, python: str, dest: str,
                  requirements_path: str) -> InstallStep:
    """``pip download`` the pinned model wheels into ``dest`` to seed an
    offline wheelhouse. Model wheels are platform-independent; the runtime
    dependencies (spaCy, torch) are not and must be fetched for the target
    platform separately."""
    listed = [t for t in targets if t.listed]
    if len(listed) != len(targets) or not listed:
        raise ModelSpecError("fetch supports catalog models only")
    lines = [f"{t.name} @ {CATALOG[t.name].wheel_url} --hash=sha256:{t.sha256}" for t in listed]
    argv = [python, "-m", "pip", "download", "--disable-pip-version-check", "--no-input",
            "--no-deps", "--require-hashes", "--dest", dest, "-r", requirements_path]
    return InstallStep(purpose="download model wheels", argv=tuple(argv),
                       requirements_path=requirements_path,
                       requirements_text="\n".join(lines) + "\n")


# Runs in a child interpreter so a broken model (or a missing torch) cannot
# take down the caller, and so the result reflects a fresh import state.
VERIFY_SCRIPT = r"""
import json, sys, time
started = time.monotonic()
import spacy
nlp = spacy.load(sys.argv[1])
doc = nlp("Alice Johnson moved from Boston to Berlin in March 2021.")
meta = nlp.meta
print(json.dumps({
    "package": (meta.get("lang", "") + "_" + meta.get("name", "")).strip("_"),
    "version": meta.get("version"), "lang": nlp.lang,
    "pipeline": list(nlp.pipe_names), "spacy_version": spacy.__version__,
    "entity_labels": sorted({ent.label_ for ent in doc.ents}),
    "seconds": round(time.monotonic() - started, 2)}))
"""

# Verification must prove the model loads from local files alone.
OFFLINE_ENV = {"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_DATASETS_OFFLINE": "1"}


def verify_argv(python: str, model: str) -> list[str]:
    return [python, "-c", VERIFY_SCRIPT, model]


def evaluate_verification(model: str, returncode: int, stdout: str,
                          stderr: str) -> dict:
    """Interpret one verification child process. ``ok`` requires a clean
    exit, parseable output and an ``ner`` component, since NER is the only
    thing the detectors use the model for."""
    result: dict = {"model": model, "ok": False}
    payload = None
    for line in reversed(stdout.strip().splitlines()):
        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except ValueError:
                payload = None
            break
    if returncode != 0 or payload is None:
        tail = [line for line in stderr.strip().splitlines() if line.strip()][-3:]
        result["error"] = redact(" | ".join(tail) or f"exit status {returncode}")
        return result
    result.update(payload)
    catalog = CATALOG.get(model)
    warnings: list[str] = []
    if catalog and payload.get("version") and payload["version"] != catalog.version:
        warnings.append(f"installed {payload['version']}, catalog pins {catalog.version}")
    if "ner" not in payload.get("pipeline", []):
        result["error"] = "pipeline has no 'ner' component; the detectors cannot use it"
        return result
    result["warnings"] = warnings
    result["ok"] = True
    return result


# --------------------------------------------------------------------------
# Environment inspection (reads installed distribution metadata only)
# --------------------------------------------------------------------------


def installed_version(model: str) -> str | None:
    try:
        return metadata.version(model)
    except (metadata.PackageNotFoundError, ValueError):
        pass
    meta_path = Path(model) / "meta.json"
    try:
        if meta_path.is_file():
            return json.loads(meta_path.read_text()).get("version")
    except (OSError, ValueError):
        return None
    return None


def model_state(model: str) -> dict:
    catalog = CATALOG.get(model)
    version = installed_version(model)
    state: dict = {"name": model, "installed": version is not None, "version": version,
                   "listed": catalog is not None,
                   "catalog_version": catalog.version if catalog else None}
    if catalog is not None:
        state["matches_catalog"] = version == catalog.version if version else None
        state["approx_size_mb"] = catalog.approx_size_mb
    if version is None and (hint := install_hint(model)):
        state["install_command"] = hint
    return state
