"""``vecshield-platform nlp``: inspect, install and verify NER models.

The commands run ``python -m pip`` and a verification interpreter as child
processes with argv lists (never a shell). They are an operator tool for a
host or an image build; nothing here is reachable from the HTTP API.
"""

from __future__ import annotations

from importlib import metadata
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

import rich_click as click
from rich.text import Text

from vecshield.cli_output import make_console
from vecshield_platform import nlp_models
from vecshield_platform.nlp_models import (CATALOG, InstallOptions, ModelSpecError,
                                             ModelTarget)

INSTALL_TIMEOUT_S = 3600
VERIFY_TIMEOUT_S = 600
_PACKAGES = ("spacy", "presidio-analyzer", "spacy-transformers",
             "spacy-curated-transformers", "torch")

console = make_console()
err_console = make_console(stderr=True)


def _say(*parts: str | tuple[str, str], err: bool = False) -> None:
    """Print one line built from plain and (text, style) parts.

    Never parsed as markup, since model names, paths and pip arguments contain
    brackets, and never wrapped, so lines stay copy-pasteable and grep-able."""
    (err_console if err else console).print(Text.assemble(*parts), soft_wrap=True)


def _package_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def _configured() -> tuple[str, str]:
    """The detection mode and requested model, exactly as detection reads them."""
    from vecshield_platform.detection import DetectionConfigurationError, _configuration

    try:
        return _configuration(None, None)
    except DetectionConfigurationError as exc:
        raise click.UsageError(str(exc)) from exc


def _extra_models() -> dict[str, str]:
    from vecshield.classify.presidio_classifier import resolve_extra_models

    return resolve_extra_models()


def _default_model() -> str:
    _, model = _configured()
    if model not in CATALOG and Path(model).is_dir():
        raise click.UsageError(
            f"VECSHIELD_NLP_MODEL points at a local model directory ({model}); "
            "there is nothing to install. Use `nlp verify` to check it.")
    return model


def _selected(models: tuple[str, ...], use_default: bool, extras: bool) -> list[str]:
    selected = nlp_models.split_model_args(models)
    if use_default:
        selected.insert(0, _default_model())
    if extras:
        selected.extend(_extra_models().values())
    return list(dict.fromkeys(selected))


def _status_payload() -> dict:
    mode, model = _configured()
    requested = nlp_models.model_state(model)
    extras = [{"language": lang, **nlp_models.model_state(name)}
              for lang, name in sorted(_extra_models().items())]
    packages = {name: _package_version(name) for name in _PACKAGES}
    from vecshield_platform.detection import _missing_requirements

    # Installed is not loadable: a transformer model also needs its declared
    # runtime (spacy-curated-transformers and torch for en_core_web_trf).
    missing = _missing_requirements(model) if requested["installed"] else []
    ready = bool(requested["installed"] and packages["spacy"] and packages["presidio-analyzer"]
                 and not missing)
    if missing:
        requested["missing_requirements"] = missing
    missing_extras = [item["name"] for item in extras if not item["installed"]]
    payload = {
        "mode": mode, "requested_model": model, "requested": requested,
        "nlp_ready": ready, "extra_models": extras, "packages": packages,
        "wheelhouse": os.environ.get("VECSHIELD_NLP_WHEELHOUSE") or None,
        "python": sys.executable,
    }
    if missing_extras:
        payload["extras_install_command"] = f"{nlp_models.INSTALL_COMMAND} --extras"
    return payload


@click.group(name="nlp")
def nlp() -> None:
    """Inspect, install and verify the spaCy models used for NER detection."""


@nlp.command(name="status")
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON.")
def status_cmd(as_json: bool) -> None:
    """Show the requested model, extra language models and NLP packages."""
    payload = _status_payload()
    if as_json:
        click.echo(json.dumps(payload, indent=2))
        return
    requested = payload["requested"]
    state = ((f"installed {requested['version']}", "ok") if requested["installed"]
             else ("NOT INSTALLED", "error"))
    _say(("mode: ", "bold"), payload["mode"])
    _say(("requested model: ", "bold"), f"{payload['requested_model']} (", state, ")")
    if requested.get("matches_catalog") is False:
        _say(("  note: ", "warn"), f"catalog pins {requested['catalog_version']}")
    if requested.get("install_command"):
        _say("  install: ", (requested["install_command"], "info"))
    _say(("extra language models:", "bold"))
    for item in payload["extra_models"]:
        mark = (item["version"], "ok") if item["installed"] else ("not installed", "warn")
        _say(f"  {item['language']}: {item['name']} (", mark, ")")
    if not payload["extra_models"]:
        _say(("  (none configured)", "muted"))
    _say(("packages:", "bold"))
    for name, version in payload["packages"].items():
        _say(f"  {name}: ", (version, "ok") if version else ("not installed", "muted"))
    _say(("NLP ready: ", "bold"),
         ("yes", "ok") if payload["nlp_ready"] else ("no", "error"))


@nlp.command(name="catalog")
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON.")
def catalog_cmd(as_json: bool) -> None:
    """List the supported models, pinned versions, sizes and wheel URLs."""
    rows: list[dict] = [{"name": s.name, "version": s.version, "languages": list(s.languages),
             "approx_size_mb": s.approx_size_mb, "transformer": s.transformer,
             "default": s.default,
             "requires": list(s.requires), "sha256": s.sha256, "wheel_url": s.wheel_url,
             "description": s.description} for s in CATALOG.values()]
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    for row in rows:
        _say((f"{row['name']}=={row['version']}", "bold"),
             f"  [{','.join(row['languages'])}]  ~{row['approx_size_mb']} MB  "
             f"{row['description']}",
             ("  (default)", "ok") if row["default"] else "")


def _run(argv: list[str] | tuple[str, ...], timeout: int,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), check=False, timeout=timeout, env=env,
                          stdin=subprocess.DEVNULL)


def _verify_one(model: str, timeout: int) -> dict:
    env = {**os.environ, **nlp_models.OFFLINE_ENV}
    try:
        proc = subprocess.run(nlp_models.verify_argv(sys.executable, model), check=False,
                              capture_output=True, text=True, timeout=timeout, env=env,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"model": model, "ok": False, "error": f"load timed out after {timeout}s"}
    except OSError as exc:
        return {"model": model, "ok": False, "error": f"could not start Python: {exc}"}
    return nlp_models.evaluate_verification(model, proc.returncode, proc.stdout, proc.stderr)


def _report_verification(results: list[dict]) -> bool:
    ok = True
    for result in results:
        if result["ok"]:
            _say(("verified", "ok"), f" {result['model']} {result.get('version')}: "
                 f"pipeline={','.join(result.get('pipeline', []))} "
                 f"entities={','.join(result.get('entity_labels', [])) or 'none'} ",
                 (f"({result.get('seconds')}s)", "muted"))
            for warning in result.get("warnings", []):
                _say(("  warning: ", "warn"), str(warning))
        else:
            ok = False
            _say(("FAILED", "error"), f" {result['model']}: {result.get('error')}", err=True)
    return ok


def _verify_many(models: list[str], timeout: int, *, precheck: bool = True) -> list[dict]:
    # After an install the child interpreter is the authority: this process's
    # view of site-packages may predate what pip just wrote.
    results = []
    for model in models:
        if precheck and nlp_models.installed_version(model) is None:
            hint = nlp_models.install_hint(model)
            results.append({"model": model, "ok": False,
                            "error": "not installed" + (f"; run `{hint}`" if hint else "")})
            continue
        results.append(_verify_one(model, timeout))
    return results


@nlp.command(name="verify")
@click.argument("models", nargs=-1)
@click.option("--extras", is_flag=True, help="Also verify the configured extra-language models.")
@click.option("--timeout", default=VERIFY_TIMEOUT_S, show_default=True, type=int,
              help="Seconds allowed to load each model.")
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON.")
def verify_cmd(models: tuple[str, ...], extras: bool, timeout: int, as_json: bool) -> None:
    """Load each model in a fresh, offline interpreter and check it has NER.

    With no MODELS, verifies the configured model (VECSHIELD_NLP_MODEL)."""
    selected = nlp_models.split_model_args(models)
    if not selected:
        selected = [_configured()[1]]
    if extras:
        selected.extend(name for name in _extra_models().values() if name not in selected)
    results = _verify_many(selected, timeout)
    if as_json:
        click.echo(json.dumps(results, indent=2))
        ok = all(result["ok"] for result in results)
    else:
        ok = _report_verification(results)
    if not ok:
        sys.exit(1)


def _describe_plan(plan: nlp_models.InstallPlan) -> None:
    for target in plan.targets:
        catalog = CATALOG.get(target.name)
        where = (nlp_models.redact(target.source) if target.source
                 else f"{target.version}" + (f", ~{catalog.approx_size_mb} MB" if catalog else ""))
        pin = ("sha256-pinned", "ok") if target.hash_pinned else ("NOT hash-pinned", "alert")
        _say("model ", (target.name, "bold"), f" ({where}; ", pin, ")")
    for note in plan.notes:
        _say(("  note: ", "warn"), str(note))
    for number, step in enumerate(plan.steps, start=1):
        _say((f"step {number}: ", "bold"), step.purpose)
        # Quoted for copy-paste: requirement specifiers contain '<' and '>'.
        _say(("  $ ", "muted"), (shlex.join(nlp_models.redact_argv(step.argv)), "info"))
        if step.requirements_text:
            for line in step.requirements_text.splitlines():
                _say((f"    {nlp_models.redact(line)}", "muted"))


@nlp.command(name="install")
@click.argument("models", nargs=-1)
@click.option("--default", "use_default", is_flag=True,
              help="Install the configured model (VECSHIELD_NLP_MODEL, default "
                   f"{nlp_models.DEFAULT_MODEL}).")
@click.option("--extras", is_flag=True,
              help="Install the configured extra-language models (VECSHIELD_NER_MODELS).")
@click.option("--wheelhouse", default=None, envvar="VECSHIELD_NLP_WHEELHOUSE",
              help="Offline directory of wheels; installs with --no-index "
                   "(env VECSHIELD_NLP_WHEELHOUSE).")
@click.option("--index-url", default=None,
              help="Private package index (https://) for models and dependencies. "
                   "Prefer the PIP_INDEX_URL environment variable when it carries "
                   "credentials.")
@click.option("--allow-insecure-index", is_flag=True,
              help="Permit a plain-http --index-url (trusted networks only; the "
                   "dependency packages it serves are not hash-pinned).")
@click.option("--hashes", "hashes_file", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="File of '<model> sha256:<hex>' lines overriding or adding hashes.")
@click.option("--allow-unlisted", is_flag=True,
              help="Permit NAME=<https-url-or-path> models outside the catalog.")
@click.option("--skip-dependencies", is_flag=True,
              help="Do not install spaCy/Presidio/transformer dependencies first.")
@click.option("--dry-run", is_flag=True, help="Print the pip commands without running them.")
@click.option("--verify/--no-verify", default=True, show_default=True,
              help="Load each installed model afterwards.")
@click.option("--timeout", default=INSTALL_TIMEOUT_S, show_default=True, type=int,
              help="Seconds allowed for each pip invocation.")
def install_cmd(models, use_default, extras, wheelhouse, index_url, allow_insecure_index,
                hashes_file, allow_unlisted, skip_dependencies, dry_run, verify,
                timeout) -> None:
    """Install spaCy models for NER detection with pip.

    MODELS are catalog names (see `nlp catalog`), comma or space separated.
    Model wheels are verified against pinned SHA-256 checksums. The runtime
    dependencies (spaCy, Presidio, transformer support) are installed by
    version range and are not hash-pinned; for a reproducible, tamper-evident
    install, pre-build a wheelhouse from a hashed requirements file and pass
    --wheelhouse, or use --skip-dependencies with an image built that way."""
    selected = _selected(models, use_default, extras)
    if not selected:
        raise click.UsageError("name at least one model, or pass --default / --extras")
    wheelhouse = (wheelhouse or "").strip() or None
    if wheelhouse:
        if not Path(wheelhouse).is_dir():
            raise click.UsageError(f"wheelhouse {wheelhouse!r} is not a directory")
        wheelhouse = str(Path(wheelhouse).absolute())
    try:
        hashes = (nlp_models.parse_hashes_file(Path(hashes_file).read_text())
                  if hashes_file else None)
        targets: list[ModelTarget] = nlp_models.resolve_targets(
            selected, allow_unlisted=allow_unlisted, hashes=hashes)
        for target in targets:
            if target.source and "://" not in target.source and not dry_run \
                    and not Path(target.source).is_file():
                raise ModelSpecError(f"{target.name}: {target.source} does not exist")
        options = InstallOptions(python=sys.executable, wheelhouse=wheelhouse,
                                 index_url=(index_url or "").strip() or None,
                                 install_dependencies=not skip_dependencies,
                                 allow_insecure_index=allow_insecure_index)
        preview = nlp_models.plan_install(targets, options,
                                          requirements_path="<tmp>/model-requirements.txt")
    except ModelSpecError as exc:
        raise click.UsageError(str(exc)) from exc

    if options.index_url and options.index_url.lower().startswith("http://"):
        _say(("WARNING:", "alert"), " installing from a plain HTTP index "
             f"({nlp_models.redact(options.index_url)}). Model wheels are still "
             "hash-checked, but the dependency packages are not, and anyone on the "
             "network path can substitute them.", err=True)
    total = preview.download_bytes
    _say((f"{'Plan' if dry_run else 'Installing'}:", "bold"), f" {len(targets)} model(s)"
         + (f", ~{round(total / 1_000_000)} MB of model wheels" if total else "")
         + (" from wheelhouse" if wheelhouse else ""))
    _describe_plan(preview)
    if dry_run:
        _say(("dry run: nothing was installed", "muted"))
        return

    with tempfile.TemporaryDirectory(prefix="vecshield-nlp-") as tmp:
        plan = nlp_models.plan_install(
            targets, options, requirements_path=str(Path(tmp) / "model-requirements.txt"))
        for number, step in enumerate(plan.steps, start=1):
            if step.requirements_path and step.requirements_text:
                Path(step.requirements_path).write_text(step.requirements_text)
            _say((f"running step {number}: ", "bold"), step.purpose)
            try:
                proc = _run(step.argv, timeout)
            except subprocess.TimeoutExpired:
                _say(("FAILED", "error"), f" step {number} ({step.purpose}): pip timed out "
                     f"after {timeout}s", err=True)
                sys.exit(1)
            except OSError as exc:
                _say(("FAILED", "error"), f" step {number}: could not start pip: {exc}",
                     err=True)
                sys.exit(1)
            if proc.returncode != 0:
                _say(("FAILED", "error"), f" step {number} ({step.purpose}): pip exited "
                     f"{proc.returncode}. Nothing later was attempted; see pip's "
                     "output above.", err=True)
                sys.exit(1)

    if not verify:
        _say(("installed", "ok"), "; verification skipped (--no-verify)")
        return
    ok = _report_verification(_verify_many([t.name for t in targets], VERIFY_TIMEOUT_S,
                                           precheck=False))
    if not ok:
        _say(("installation finished but verification failed", "error"), "; detection "
             "would remain degraded for the models above", err=True)
        sys.exit(1)
    _say(("done.", "ok"), " Restart running VecShield processes so they load the new model(s).")


@nlp.command(name="fetch")
@click.argument("dest", type=click.Path(file_okay=False))
@click.argument("models", nargs=-1)
@click.option("--default", "use_default", is_flag=True, help="Include the configured model.")
@click.option("--extras", is_flag=True, help="Include the configured extra-language models.")
@click.option("--dry-run", is_flag=True, help="Print the pip command without running it.")
@click.option("--timeout", default=INSTALL_TIMEOUT_S, show_default=True, type=int)
def fetch_cmd(dest, models, use_default, extras, dry_run, timeout) -> None:
    """Download hash-checked model wheels into DEST to seed an offline wheelhouse."""
    selected = _selected(models, use_default, extras)
    if not selected:
        raise click.UsageError("name at least one model, or pass --default / --extras")
    try:
        targets = nlp_models.resolve_targets(selected)
        preview = nlp_models.plan_download(targets, python=sys.executable, dest=dest,
                                           requirements_path="<tmp>/model-requirements.txt")
    except ModelSpecError as exc:
        raise click.UsageError(str(exc)) from exc
    _say(("  $ ", "muted"), (shlex.join(preview.argv), "info"))
    for line in (preview.requirements_text or "").splitlines():
        _say((f"    {line}", "muted"))
    if dry_run:
        _say(("dry run: nothing was downloaded", "muted"))
        return
    Path(dest).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vecshield-nlp-") as tmp:
        step = nlp_models.plan_download(targets, python=sys.executable, dest=dest,
                                        requirements_path=str(Path(tmp) / "req.txt"))
        Path(step.requirements_path or "").write_text(step.requirements_text or "")
        try:
            proc = _run(step.argv, timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            _say(("FAILED:", "error"), f" {type(exc).__name__}: {exc}", err=True)
            sys.exit(1)
    if proc.returncode != 0:
        _say(("FAILED:", "error"), f" pip download exited {proc.returncode}", err=True)
        sys.exit(1)
    _say(("wheels saved", "ok"), f" to {dest}. Runtime dependencies (spaCy, Presidio, torch) "
         "are platform-specific; download them for the target platform too.")
