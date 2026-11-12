"""NLP model catalog, install planning, the `nlp` CLI and install hints.

No test touches the network or installs anything: subprocess is mocked, and
the one real pip invocation runs `--dry-run` against a locally built wheel.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
import zipfile

import pytest
from click.testing import CliRunner

from vecshield_platform import detection, nlp_cli, nlp_models
from vecshield_platform.cli import cli
from vecshield_platform.nlp_models import (CATALOG, InstallOptions, ModelSpecError,
                                             parse_model_spec, plan_install)
from vecshield.classify.presidio_classifier import DEFAULT_EXTRA_MODELS

PY = "/usr/bin/python3"


# --------------------------------------------------------------------------
# Catalog
# --------------------------------------------------------------------------


def test_catalog_contains_default_and_every_extra_language_model():
    assert detection.DEFAULT_NLP_MODEL in CATALOG
    assert CATALOG[detection.DEFAULT_NLP_MODEL].version == detection.DEFAULT_MODEL_VERSION
    assert set(DEFAULT_EXTRA_MODELS.values()) <= set(CATALOG)
    assert {"en_core_web_sm", "en_core_web_md", "en_core_web_lg", "en_core_web_trf"} <= set(CATALOG)


@pytest.mark.parametrize("spec", list(CATALOG.values()), ids=lambda s: s.name)
def test_catalog_entries_are_pinned_and_well_formed(spec):
    assert re.fullmatch(r"[0-9a-f]{64}", spec.sha256)
    assert spec.wheel_url == (
        f"https://github.com/explosion/spacy-models/releases/download/"
        f"{spec.name}-{spec.version}/{spec.name}-{spec.version}-py3-none-any.whl")
    assert spec.size_bytes > 1_000_000
    assert spec.languages and all(len(lang) == 2 for lang in spec.languages)
    assert spec.requires[0] == nlp_models.SPACY_REQUIREMENT
    if spec.transformer:
        assert any("transformers" in req for req in spec.requires)


def test_hftrf_uses_spacy_transformers_and_trf_uses_curated():
    assert "spacy-transformers>=1.4.0,<1.5.0" in CATALOG["en_core_web_hftrf"].requires
    assert any(r.startswith("spacy-curated-transformers")
               for r in CATALOG["en_core_web_trf"].requires)
    assert len({spec.sha256 for spec in CATALOG.values()}) == len(CATALOG)


# --------------------------------------------------------------------------
# Spec parsing
# --------------------------------------------------------------------------


def test_catalog_name_resolves_to_pinned_hash():
    target = parse_model_spec("en_core_web_hftrf")
    assert target.listed and target.version == "3.8.1"
    assert target.sha256 == CATALOG["en_core_web_hftrf"].sha256


def test_unknown_model_is_rejected():
    with pytest.raises(ModelSpecError, match="not in the supported catalog"):
        parse_model_spec("xx_evil_model")


def test_other_version_of_catalog_model_is_rejected():
    assert parse_model_spec("en_core_web_sm==3.8.0").version == "3.8.0"
    with pytest.raises(ModelSpecError, match="pinned to 3.8.0"):
        parse_model_spec("en_core_web_sm==3.7.1")


@pytest.mark.parametrize("bad", ["--index-url=https://evil", "-e .", "a b", "../x", ""])
def test_names_that_could_become_pip_options_are_rejected(bad):
    with pytest.raises(ModelSpecError):
        parse_model_spec(bad, allow_unlisted=True)


def test_explicit_source_requires_allow_unlisted():
    with pytest.raises(ModelSpecError, match="--allow-unlisted"):
        parse_model_spec("my_model=https://host/my_model-1.0-py3-none-any.whl")
    target = parse_model_spec("my_model=https://host/m.whl?sig=a==", allow_unlisted=True)
    assert not target.listed and target.source == "https://host/m.whl?sig=a=="
    assert not target.hash_pinned and "not hash-pinned" in target.notes[0]


def test_unlisted_sources_must_be_https_or_local_wheels(tmp_path):
    with pytest.raises(ModelSpecError, match="https"):
        parse_model_spec("m=http://host/m.whl", allow_unlisted=True)
    with pytest.raises(ModelSpecError, match="https"):
        parse_model_spec("m=file:///etc/passwd", allow_unlisted=True)
    with pytest.raises(ModelSpecError, match=".whl"):
        parse_model_spec("m=/etc/passwd", allow_unlisted=True)
    local = parse_model_spec(f"m={tmp_path}/m-1.0-py3-none-any.whl", allow_unlisted=True)
    assert local.source == str(tmp_path / "m-1.0-py3-none-any.whl")


def test_operator_hash_overrides_catalog_and_is_noted():
    digest = "ab" * 32
    target = parse_model_spec(f"en_core_web_lg@sha256:{digest.upper()}")
    assert target.sha256 == digest
    assert "overrides the published checksum" in target.notes[0]
    unlisted = parse_model_spec(f"m=https://h/m.whl@sha256:{digest}", allow_unlisted=True)
    assert unlisted.sha256 == digest and unlisted.source == "https://h/m.whl"


def test_hashes_file_formats_and_errors():
    digest, other = "cd" * 32, "ef" * 32
    parsed = nlp_models.parse_hashes_file(
        f"# comment\nen_core_web_lg sha256:{digest}\n"
        f"de_core_news_sm==3.8.0 --hash=sha256:{other}\n\nfr_core_news_sm={digest}\n")
    assert parsed == {"en_core_web_lg": digest, "de_core_news_sm": other,
                      "fr_core_news_sm": digest}
    with pytest.raises(ModelSpecError, match="line 1"):
        nlp_models.parse_hashes_file("en_core_web_lg nothex\n")
    with pytest.raises(ModelSpecError, match="conflicting"):
        nlp_models.parse_hashes_file(f"m {digest}\nm {other}\n")
    target = parse_model_spec("en_core_web_lg", hashes=parsed)
    assert target.sha256 == digest


def test_split_model_args_accepts_commas_and_dedupes():
    assert nlp_models.split_model_args(["a,b", "b", " c ", ","]) == ["a", "b", "c"]


# --------------------------------------------------------------------------
# Install planning
# --------------------------------------------------------------------------


def _plan(specs, **options):
    targets = nlp_models.resolve_targets(specs, allow_unlisted=True)
    return plan_install(targets, InstallOptions(python=PY, **options),
                        requirements_path="/tmp/req.txt")


def test_online_plan_installs_dependencies_then_hash_pinned_wheels():
    plan = _plan(["en_core_web_hftrf"])
    deps, models = plan.steps
    assert deps.argv[:4] == (PY, "-m", "pip", "install")
    assert "spacy-transformers>=1.4.0,<1.5.0" in deps.argv
    assert "presidio-analyzer>=2.2" in deps.argv
    assert {"--no-deps", "--require-hashes"} <= set(models.argv)
    assert models.argv[-2:] == ("-r", "/tmp/req.txt")
    spec = CATALOG["en_core_web_hftrf"]
    assert models.requirements_text == (
        f"en_core_web_hftrf @ {spec.wheel_url} --hash=sha256:{spec.sha256}\n")
    assert plan.download_bytes == spec.size_bytes
    for step in plan.steps:
        assert all(isinstance(part, str) for part in step.argv)


def test_wheelhouse_plan_is_offline():
    plan = _plan(["en_core_web_sm", "de_core_news_sm"], wheelhouse="/wh")
    for step in plan.steps:
        assert "--no-index" in step.argv
        assert step.argv[step.argv.index("--find-links") + 1] == "/wh"
        assert "--index-url" not in step.argv
    lines = plan.steps[1].requirements_text.splitlines()
    assert lines[0] == f"en_core_web_sm==3.8.0 --hash=sha256:{CATALOG['en_core_web_sm'].sha256}"
    assert "github.com" not in plan.steps[1].requirements_text


def test_wheelhouse_rejects_remote_unlisted_source():
    with pytest.raises(ModelSpecError, match="offline"):
        _plan(["m=https://h/m.whl@sha256:" + "a" * 64], wheelhouse="/wh")


def test_index_url_plan_passes_through_and_is_redacted_for_display():
    plan = _plan(["en_core_web_lg"], index_url="https://bob:s3cret@pypi.internal/simple")
    for step in plan.steps:
        assert "https://bob:s3cret@pypi.internal/simple" in step.argv
        assert "s3cret" not in " ".join(nlp_models.redact_argv(step.argv))
    assert plan.steps[1].requirements_text.startswith("en_core_web_lg==3.8.0 --hash=")


def test_wheelhouse_and_index_url_are_exclusive():
    with pytest.raises(ModelSpecError, match="mutually exclusive"):
        _plan(["en_core_web_sm"], wheelhouse="/wh", index_url="https://i/simple")


def test_unpinned_unlisted_model_gets_its_own_step_and_skip_dependencies():
    plan = _plan(["en_core_web_sm", "m=https://h/m-1.0-py3-none-any.whl"],
                 install_dependencies=False)
    assert [s.purpose for s in plan.steps] == ["hash-pinned models: en_core_web_sm",
                                               "unpinned model: m"]
    assert plan.steps[1].argv[-1] == "m @ https://h/m-1.0-py3-none-any.whl"
    assert "--require-hashes" not in plan.steps[1].argv


def test_download_plan_seeds_wheelhouse_with_hash_checking():
    step = nlp_models.plan_download(nlp_models.resolve_targets(["en_core_web_sm"]),
                                    python=PY, dest="/wh", requirements_path="/tmp/r")
    assert "download" in step.argv and "--require-hashes" in step.argv
    assert step.argv[step.argv.index("--dest") + 1] == "/wh"


def _fake_wheel(directory, name="en_core_web_sm", version="3.8.0"):
    files = {f"{name}/__init__.py": b"",
             f"{name}-{version}.dist-info/METADATA":
                 f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode(),
             f"{name}-{version}.dist-info/WHEEL":
                 b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
    record = [f"{path},sha256={base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()},{len(data)}"
              for path, data in files.items()]
    record.append(f"{name}-{version}.dist-info/RECORD,,")
    files[f"{name}-{version}.dist-info/RECORD"] = "\n".join(record).encode()
    path = directory / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in files.items():
            archive.writestr(member, data)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("use_real_hash", [False, True])
def test_pip_enforces_the_planned_hashes_offline(tmp_path, use_real_hash):
    """Real pip, --dry-run, local wheelhouse: the catalog hash rejects a
    substituted wheel and an operator-supplied matching hash accepts it."""
    _, digest = _fake_wheel(tmp_path)
    hashes = {"en_core_web_sm": digest} if use_real_hash else None
    targets = nlp_models.resolve_targets(["en_core_web_sm"], hashes=hashes)
    requirements = tmp_path / "req.txt"
    plan = plan_install(targets, InstallOptions(python=sys.executable, wheelhouse=str(tmp_path),
                                                install_dependencies=False),
                        requirements_path=str(requirements))
    step = plan.steps[0]
    requirements.write_text(step.requirements_text)
    proc = subprocess.run([*step.argv, "--dry-run", "--ignore-installed"],
                          capture_output=True, text=True, timeout=120)
    if "no such option: --dry-run" in proc.stderr:
        pytest.skip("pip too old for --dry-run")
    if use_real_hash:
        assert proc.returncode == 0, proc.stderr
        assert "Would install en_core_web_sm-3.8.0" in proc.stdout
    else:
        assert proc.returncode != 0
        assert "HASHES" in proc.stderr.upper() and digest in proc.stderr


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def test_evaluate_verification_success_warning_and_failures():
    good = json.dumps({"package": "en_core_web_sm", "version": "3.7.1", "lang": "en",
                       "pipeline": ["tok2vec", "ner"], "entity_labels": ["PERSON"]})
    result = nlp_models.evaluate_verification("en_core_web_sm", 0, "noise\n" + good, "")
    assert result["ok"] and "catalog pins 3.8.0" in result["warnings"][0]
    no_ner = json.dumps({"version": "3.8.0", "pipeline": ["tok2vec"]})
    assert not nlp_models.evaluate_verification("en_core_web_sm", 0, no_ner, "")["ok"]
    crashed = nlp_models.evaluate_verification(
        "en_core_web_hftrf", 1, "", "Traceback\nOSError: [E050] Can't find model "
        "'en_core_web_hftrf' at https://u:p@x\n")
    assert not crashed["ok"] and "E050" in crashed["error"] and "u:p" not in crashed["error"]


def test_verify_argv_passes_model_as_data_not_code():
    argv = nlp_models.verify_argv(PY, "x'); import os; os.system('id'); ('")
    assert argv[:2] == [PY, "-c"] and argv[2] == nlp_models.VERIFY_SCRIPT
    assert argv[3].startswith("x')")


# --------------------------------------------------------------------------
# CLI (subprocess mocked)
# --------------------------------------------------------------------------


class Recorder:
    def __init__(self, pip_rc=0, verify_stdout=None, verify_rc=0):
        self.calls = []
        self.requirements = []
        self.pip_rc = pip_rc
        self.verify_rc = verify_rc
        self.verify_stdout = verify_stdout if verify_stdout is not None else json.dumps(
            {"package": "en_core_web_trf", "version": "3.8.0", "lang": "en",
             "pipeline": ["transformer", "ner"], "entity_labels": ["GPE", "PERSON"],
             "seconds": 1.0})

    def __call__(self, argv, **kwargs):
        assert isinstance(argv, list) and "shell" not in kwargs
        self.calls.append((argv, kwargs))
        if "-r" in argv:
            self.requirements.append(open(argv[argv.index("-r") + 1]).read())
        if argv[1] == "-c":
            assert kwargs["env"]["HF_HUB_OFFLINE"] == "1"
            return subprocess.CompletedProcess(argv, self.verify_rc, self.verify_stdout,
                                               "Traceback\nOSError: boom\n")
        return subprocess.CompletedProcess(argv, self.pip_rc)


@pytest.fixture
def runner(monkeypatch):
    monkeypatch.delenv("VECSHIELD_NLP_MODEL", raising=False)
    monkeypatch.delenv("VECSHIELD_NLP_WHEELHOUSE", raising=False)
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "auto")
    monkeypatch.setenv("VECSHIELD_NER_MODELS", "de=de_core_news_sm")
    return CliRunner()


def test_status_json_reports_requested_model_and_install_command(runner, monkeypatch):
    monkeypatch.setattr(nlp_models, "installed_version", lambda model: None)
    result = runner.invoke(cli, ["nlp", "status", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["requested_model"] == "en_core_web_trf"
    assert payload["requested"]["installed"] is False
    assert payload["requested"]["install_command"] == \
        "vecshield-platform nlp install en_core_web_trf"
    assert payload["extra_models"][0]["name"] == "de_core_news_sm"
    assert payload["extras_install_command"] == "vecshield-platform nlp install --extras"
    assert payload["nlp_ready"] is False
    assert set(payload["packages"]) >= {"spacy", "presidio-analyzer", "spacy-transformers"}


def test_status_text_mode(runner, monkeypatch):
    monkeypatch.setattr(nlp_models, "installed_version",
                        lambda model: "3.8.0" if model == "en_core_web_trf" else None)
    result = runner.invoke(cli, ["nlp", "status"])
    assert result.exit_code == 0
    assert "en_core_web_trf (installed 3.8.0)" in result.output
    assert "de: de_core_news_sm (not installed)" in result.output


def test_install_dry_run_runs_nothing(runner, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    result = runner.invoke(cli, ["nlp", "install", "--default", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert rec.calls == []
    assert "en_core_web_trf-3.8.0-py3-none-any.whl --hash=sha256:" in result.output
    assert "'spacy>=3.8.0,<3.9.0'" in result.output
    assert "dry run: nothing was installed" in result.output


def test_install_runs_pip_then_verifies(runner, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    result = runner.invoke(cli, ["nlp", "install", "--default"])
    assert result.exit_code == 0, result.output
    argvs = [argv for argv, _ in rec.calls]
    assert argvs[0][1:4] == ["-m", "pip", "install"] and "spacy-curated-transformers>=0.2.2,<1.0.0" in argvs[0]
    assert "--require-hashes" in argvs[1]
    assert CATALOG["en_core_web_trf"].sha256 in rec.requirements[0]
    assert argvs[2][1] == "-c" and argvs[2][3] == "en_core_web_trf"
    assert "verified en_core_web_trf 3.8.0" in result.output
    assert "Restart running VecShield processes" in result.output


def test_install_extras_and_wheelhouse_from_env(runner, monkeypatch, tmp_path):
    rec = Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    monkeypatch.setenv("VECSHIELD_NLP_WHEELHOUSE", str(tmp_path))
    result = runner.invoke(cli, ["nlp", "install", "--extras", "--no-verify"])
    assert result.exit_code == 0, result.output
    for argv, _ in rec.calls:
        assert "--no-index" in argv and str(tmp_path) in argv
    assert rec.requirements[0].startswith("de_core_news_sm==3.8.0 --hash=sha256:")
    assert "verification skipped" in result.output


def test_install_failure_stops_and_exits_nonzero(runner, monkeypatch):
    rec = Recorder(pip_rc=1)
    monkeypatch.setattr(subprocess, "run", rec)
    result = runner.invoke(cli, ["nlp", "install", "en_core_web_sm"])
    assert result.exit_code == 1
    assert len(rec.calls) == 1
    assert "FAILED step 1" in result.output


def test_install_timeout_is_reported(runner, monkeypatch):
    def slow(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
    monkeypatch.setattr(subprocess, "run", slow)
    result = runner.invoke(cli, ["nlp", "install", "en_core_web_sm", "--timeout", "5"])
    assert result.exit_code == 1 and "timed out after 5s" in result.output


def test_verification_failure_after_install_exits_nonzero(runner, monkeypatch):
    rec = Recorder(verify_rc=1, verify_stdout="")
    monkeypatch.setattr(subprocess, "run", rec)
    result = runner.invoke(cli, ["nlp", "install", "en_core_web_sm"])
    assert result.exit_code == 1
    assert "FAILED en_core_web_sm: Traceback | OSError: boom" in result.output
    assert "verification failed" in result.output


@pytest.mark.parametrize("args, message", [
    (["nlp", "install"], "name at least one model"),
    (["nlp", "install", "xx_unknown"], "not in the supported catalog"),
    (["nlp", "install", "m=https://h/m.whl"], "--allow-unlisted"),
    (["nlp", "install", "en_core_web_sm", "--wheelhouse", "/does/not/exist"], "not a directory"),
    (["nlp", "install", "en_core_web_sm", "--index-url", "ftp://x"], "http(s)"),
])
def test_install_usage_errors(runner, monkeypatch, args, message):
    monkeypatch.setattr(subprocess, "run", Recorder())
    result = runner.invoke(cli, args)
    assert result.exit_code == 2
    assert message in result.output


def test_install_hashes_file(runner, monkeypatch, tmp_path):
    rec = Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    hashes = tmp_path / "hashes.txt"
    hashes.write_text("en_core_web_sm sha256:" + "a" * 64 + "\n")
    result = runner.invoke(cli, ["nlp", "install", "en_core_web_sm", "--hashes", str(hashes),
                                 "--no-verify", "--skip-dependencies"])
    assert result.exit_code == 0, result.output
    assert len(rec.calls) == 1
    assert rec.requirements[0].endswith("--hash=sha256:" + "a" * 64 + "\n")
    assert "overrides the published checksum" in result.output


def test_verify_command_reports_missing_and_loaded(runner, monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(subprocess, "run", rec)
    monkeypatch.setattr(nlp_models, "installed_version",
                        lambda model: "3.8.0" if model == "en_core_web_trf" else None)
    ok = runner.invoke(cli, ["nlp", "verify"])
    assert ok.exit_code == 0, ok.output
    missing = runner.invoke(cli, ["nlp", "verify", "en_core_web_lg", "--json"])
    assert missing.exit_code == 1
    payload = json.loads(missing.output)
    assert payload[0]["error"].startswith("not installed; run `vecshield-platform nlp install")
    assert len(rec.calls) == 1  # the missing model never spawned a loader


def test_fetch_dry_run(runner, monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", Recorder())
    result = runner.invoke(cli, ["nlp", "fetch", str(tmp_path / "wh"), "--default", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "pip download" in result.output and "--require-hashes" in result.output


def test_catalog_command_json(runner):
    result = runner.invoke(cli, ["nlp", "catalog", "--json"])
    names = [row["name"] for row in json.loads(result.output)]
    assert names[0] == "en_core_web_trf" and len(names) == len(CATALOG)


def test_nlp_cli_module_never_uses_a_shell():
    import inspect

    for module in (nlp_cli, nlp_models):
        source = inspect.getsource(module)
        assert "shell=True" not in source and "os.system" not in source


# --------------------------------------------------------------------------
# Detection hints
# --------------------------------------------------------------------------


@pytest.fixture
def fresh_detection(monkeypatch):
    monkeypatch.delenv("VECSHIELD_NLP_MODEL", raising=False)
    monkeypatch.setenv("VECSHIELD_NER_MODELS", "none")
    detection.reset_classifier_cache()
    yield
    detection.reset_classifier_cache()


def test_detection_status_includes_install_command_when_model_missing(monkeypatch,
                                                                       fresh_detection):
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "auto")
    monkeypatch.setattr(detection, "_model_installed", lambda model: False)
    status = detection.detection_status()
    assert status["status"] == "degraded"
    assert status["install_command"] == "vecshield-platform nlp install en_core_web_trf"
    assert "not installed" in status["reason"]
    assert "vecshield-platform nlp install en_core_web_trf" in status["reason"]


def test_detection_status_omits_install_command_when_disabled_or_unlisted(monkeypatch,
                                                                          fresh_detection):
    monkeypatch.setattr(detection, "_model_installed", lambda model: False)
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "disabled")
    assert "install_command" not in detection.detection_status()
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "auto")
    monkeypatch.setenv("VECSHIELD_NLP_MODEL", "/opt/models/custom")
    status = detection.detection_status()
    assert "install_command" not in status
    assert "docs/nlp_models.md" in status["reason"]


def test_degraded_classifier_metadata_and_error_carry_the_hint(monkeypatch, fresh_detection):
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "auto")
    monkeypatch.setattr(detection, "_model_installed", lambda model: False)
    classifier = detection.build_classifier()
    meta = classifier.detection_metadata()
    assert meta["status"] == "degraded"
    assert meta["install_command"] == "vecshield-platform nlp install en_core_web_trf"
    assert detection.detection_status()["install_command"] == meta["install_command"]
    with pytest.raises(detection.DetectionUnavailableError,
                       match=r"not installed; install it with `vecshield-platform nlp install"):
        detection.build_classifier(use_nlp=True)


def test_load_failure_of_installed_model_does_not_suggest_reinstall(monkeypatch,
                                                                    fresh_detection):
    def broken(model):
        raise detection.DetectionUnavailableError("could not load (ImportError)")

    monkeypatch.setenv("VECSHIELD_NLP_MODE", "auto")
    monkeypatch.setattr(detection, "_model_installed", lambda model: True)
    monkeypatch.setattr(detection, "_build_nlp", broken)
    assert "install_command" not in detection.build_classifier().detection_metadata()


# ---- credentials and transport for private indexes --------------------------

@pytest.mark.parametrize("url, secret", [
    ("https://bob:p@ss@pypi.internal/simple", "p@ss"),
    ("https://bob:s3cret@pypi.internal/simple", "s3cret"),
    ("https://token@pypi.internal/simple", "token"),
    ("https://bob:a@b@c@pypi.internal:8443/simple?x=1", "a@b@c"),
])
def test_redact_hides_the_whole_userinfo_even_with_at_signs(url, secret):
    shown = nlp_models.redact(url)
    assert secret not in shown and "ss@" not in shown
    assert shown.startswith("https://***@pypi.internal")
    assert nlp_models.redact(f"--index-url={url} next") .endswith(" next")
    assert secret not in nlp_models.redact(f"--index-url={url} next")


def test_redact_leaves_urls_without_credentials_alone():
    for text in ("https://pypi.internal/simple", "see https://x.example/a@b",
                 "user@example.com", "no url here"):
        assert nlp_models.redact(text) == text


def test_plain_http_index_is_refused_without_an_explicit_opt_in():
    with pytest.raises(ModelSpecError, match="https"):
        _plan(["en_core_web_sm"], index_url="http://pypi.internal/simple")
    plan = _plan(["en_core_web_sm"], index_url="http://pypi.internal:8080/simple",
                 allow_insecure_index=True)
    for step in plan.steps:
        assert "http://pypi.internal:8080/simple" in step.argv
        assert step.argv[step.argv.index("--trusted-host") + 1] == "pypi.internal:8080"


def test_cli_refuses_http_index_and_warns_when_allowed(runner, monkeypatch):
    monkeypatch.setattr(subprocess, "run", Recorder())
    refused = runner.invoke(cli, ["nlp", "install", "en_core_web_sm", "--dry-run",
                                  "--index-url", "http://pypi.internal/simple"])
    assert refused.exit_code == 2 and "--allow-insecure-index" in refused.output
    allowed = runner.invoke(cli, ["nlp", "install", "en_core_web_sm", "--dry-run",
                                  "--index-url", "http://pypi.internal/simple",
                                  "--allow-insecure-index"])
    assert allowed.exit_code == 0, allowed.output
    assert "WARNING" in allowed.output and "plain HTTP" in allowed.output
