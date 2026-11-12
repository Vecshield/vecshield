"""VecShield platform CLI.

    vecshield-platform serve    --config ./vecshield.json
    vecshield-platform audit    --connector chroma --path ./chroma_data
    vecshield-platform posture  --connector chroma --path ./chroma_data
    vecshield-platform schedule --config ./vecshield.json --interval 86400

Wraps the `vecshield` detection library with self-hosted governance:
dashboards, scheduled audits, vector-DB posture, runtime monitoring, and
compliance evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import rich_click as click
from rich.markup import escape
from rich.table import Table

from vecshield_platform.connectors import AVAILABLE, build_connector
from vecshield.models import ScanJob, Severity
from vecshield_platform.scan import scan_store
from vecshield_platform.detection import build_classifier, detection_status
from vecshield.cli_output import SEV_STYLE, glyph, make_console, prepare_stdio

console = make_console()
err_console = make_console(stderr=True)


# Shared connector options. `build_connector` filters these down to the kwargs
# each store kind actually understands, so a single decorator can safely feed
# every scan-family command without per-kind branching in the CLI.
_CONNECTOR_OPTIONS = [
    click.option("--connector", "kind", default="chroma",
                 type=click.Choice(AVAILABLE), help="Vector store kind."),
    click.option("--host", default=None, help="Remote host."),
    click.option("--port", default=None, type=int, help="Remote port."),
    click.option("--path", default=None, help="Chroma local persistent store path."),
    click.option("--dsn", default=None, help="pgvector connection string."),
    click.option("--dbname", default=None, help="pgvector database name."),
    click.option("--user", default=None, help="pgvector / opensearch user."),
    click.option("--password", default=None, help="pgvector / opensearch / redis password."),
    click.option("--schema", default=None, help="pgvector schema."),
    click.option("--sslmode", default=None,
                 type=click.Choice(["disable", "allow", "prefer", "require",
                                    "verify-ca", "verify-full"]),
                 help="pgvector TLS mode (libpq sslmode)."),
    click.option("--tables", default=None,
                 help="Comma-separated pgvector tables to restrict the scan to."),
    click.option("--retrieval-role", "retrieval_role", default=None,
                 help="pgvector role the RAG application retrieves as; its grants and "
                      "row-security bypass are judged (a role name, never a password)."),
    click.option("--url", default=None,
                 help="Endpoint URL (qdrant / weaviate / redis / opensearch)."),
    click.option("--api-key", "api_key", default=None,
                 help="API key (pinecone / openai / qdrant / weaviate / azure_search)."),
    click.option("--uri", default=None, help="Connection URI (milvus / mongodb)."),
    click.option("--endpoint", default=None, help="Service endpoint (azure_search)."),
    click.option("--region", default=None, help="Cloud region (bedrock_kb)."),
    click.option("--project", default=None, help="GCP project (vertex_ai)."),
    click.option("--location", default=None, help="GCP location (vertex_ai)."),
    click.option("--endpoint-id", "endpoint_id", default=None,
                 help="Deployed index endpoint id (vertex_ai) — enables query()."),
    click.option("--credentials-json", "credentials_json", default=None,
                 help="Path to a GCP service-account JSON (vertex_ai)."),
    click.option("--token", default=None, help="Auth token (milvus)."),
    click.option("--db-name", "db_name", default=None, help="Database name (milvus)."),
    click.option("--db", default=None, type=int, help="DB index (redis)."),
    click.option("--grpc-port", "grpc_port", default=None, type=int,
                 help="gRPC port (weaviate)."),
    click.option("--secure/--insecure", "secure", default=None,
                 help="Use TLS (weaviate)."),
    click.option("--aws-access-key-id", "aws_access_key_id", default=None,
                 help="AWS access key id (bedrock_kb)."),
    click.option("--aws-secret-access-key", "aws_secret_access_key", default=None,
                 help="AWS secret access key (bedrock_kb)."),
]


def connector_options(f):
    """Attach the shared connector options to a command.

    The decorated command must accept ``**conn`` and build its connector with
    :func:`_connector_from_opts`, which applies Chroma's localhost defaults.
    """
    for option in reversed(_CONNECTOR_OPTIONS):
        f = option(f)
    return f


def classification_options(f):
    """Keep classifier overrides consistent across classification commands."""
    f = click.option("--nlp-model", default=None,
                     help="Installed spaCy NLP model; defaults to VECSHIELD_NLP_MODEL.")(f)
    return click.option("--no-nlp", is_flag=True,
                        help="Disable the NLP layer; retain regex and contextual rules.")(f)


def _classifier_from_options(no_nlp: bool, nlp_model: str | None):
    try:
        return build_classifier(use_nlp=False if no_nlp else None, model=nlp_model)
    except (ValueError, RuntimeError) as e:
        raise click.ClickException(f"Detection unavailable: {e}") from e


def _connector_from_opts(conn: dict):
    """Build a connector from collected CLI options (mutates/consumes ``conn``).

    Pops ``kind`` and applies the Chroma localhost:8000 defaults so bare
    ``--connector chroma`` keeps working. All other options are forwarded to
    ``build_connector``, which drops the ones the chosen kind doesn't accept.
    """
    kind = conn.pop("kind")
    if kind == "chroma" and not conn.get("host") and not conn.get("path"):
        conn["host"] = "localhost"
    if kind == "chroma" and conn.get("port") is None:
        conn["port"] = 8000
    return build_connector(kind, **conn)


def _load_json_file(path: str, what: str):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise click.ClickException(f"{what}: cannot read {path} ({type(e).__name__})") from e


def _fail_problems(what: str, problems: list[str]) -> None:
    if problems:
        raise click.ClickException(f"{what} is invalid:\n  - " + "\n  - ".join(problems))


def _store_control_overrides(retention_path, residency_path, processors_path,
                             manifest_path) -> dict:
    """Validated store controls from the audit command's files (strict)."""
    from vecshield_platform.api.config_store import (
        validate_processor_register,
        validate_residency_policy,
        validate_retention_document,
        validate_source_manifest,
    )
    from vecshield_platform.scan.retention_schedule import ScheduleError, validate_schedule

    overrides: dict = {}
    if retention_path:
        raw = _load_json_file(retention_path, "--retention-schedule")
        if isinstance(raw, dict) and ("global" in raw or "stores" in raw):
            doc, problems = validate_retention_document(raw)
            _fail_problems("--retention-schedule", problems)
            overrides["retention_schedule"] = doc.get("global")
        else:
            try:
                validate_schedule(raw)
            except ScheduleError as e:
                _fail_problems("--retention-schedule", e.problems)
            overrides["retention_schedule"] = raw
    if residency_path:
        raw = _load_json_file(residency_path, "--residency-policy")
        if isinstance(raw, dict) and ("default" in raw or "stores" in raw):
            raw = raw.get("default")
        _, problems = validate_residency_policy(raw)
        _fail_problems("--residency-policy", problems)
        overrides["residency_policy"] = raw
    if processors_path:
        raw = _load_json_file(processors_path, "--processor-register")
        if isinstance(raw, dict):
            raw = raw.get("processors")
        _, problems = validate_processor_register(raw)
        _fail_problems("--processor-register", problems)
        overrides["processor_register"] = raw
    if manifest_path:
        raw = _load_json_file(manifest_path, "--source-manifest")
        _, problems = validate_source_manifest(raw)
        _fail_problems("--source-manifest", problems)
        overrides["source_manifest"] = raw
    return overrides


def _feed_state_dir(config_path: str, state_dir: str | None) -> str:
    """Where the advisory feed lives: the state dir, else beside the config."""
    return str(Path(state_dir) if state_dir else Path(config_path).resolve().parent)


@click.group()
@click.version_option(package_name="vecshield")
def cli() -> None:
    """Self-hosted vector/RAG security posture management."""
    prepare_stdio()


@cli.command(name="detection-status")
def detection_status_cmd() -> None:
    """Print local detection configuration as JSON without loading/downloading models."""
    try:
        click.echo(json.dumps(detection_status(), indent=2))
    except ValueError as e:
        raise click.ClickException(f"Invalid detection configuration: {e}") from e


@cli.command()
@connector_options
@classification_options
@click.option("--max-chunks", default=None, type=int, help="Cap chunks per collection.")
@click.option("--json", "json_out", default=None, help="Write findings JSON to path.")
def scan(no_nlp, nlp_model, max_chunks, json_out, **conn) -> None:
    """Scan a vector store for sensitive data and posture findings."""
    kind = conn.get("kind")
    if not no_nlp and nlp_model is None:
        from rich.markup import escape as _escape

        _nlp_startup_warning(_escape)
    classifier = _classifier_from_options(no_nlp, nlp_model)

    try:
        connector = _connector_from_opts(conn)
        with connector:
            console.print(f"[bold]Scanning[/] {kind} store…")
            job = scan_store(
                connector,
                classifier=classifier,
                max_chunks_per_collection=max_chunks,
            )
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Scan failed:[/] {e}")
        sys.exit(1)

    _render(job)

    if json_out:
        with open(json_out, "w") as f:
            json.dump(job.to_dict(), f, indent=2)
        console.print(f"\n[muted]Findings written to {json_out}[/]")

    # Non-zero exit if anything high+ was found, or the store was not fully
    # read (useful in CI).
    _exit_for_job(job)


@cli.command(name="probe-isolation")
@connector_options
@click.option("--collection", required=True, help="Collection / table to probe.")
@click.option("--tenant-field", required=True,
              help="Metadata field that identifies the tenant (e.g. tenant_id).")
@click.option("--top-k", default=10, type=int,
              help="Deprecated and ignored: the check now queries every tenant with "
                   "a result size that covers the whole collection.")
@click.option("--json", "json_out", default=None, help="Write findings JSON to path.")
def probe_isolation_cmd(collection, tenant_field, top_k, json_out, **conn) -> None:
    """Probe a collection for cross-tenant data bleed."""
    from vecshield_platform.access import probe_isolation

    try:
        connector = _connector_from_opts(conn)
        with connector:
            console.print(f"[bold]Probing isolation[/] of '{collection}'…")
            job = probe_isolation(connector, collection,
                                  tenant_field=tenant_field, top_k=top_k)
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Probe failed:[/] {e}")
        sys.exit(1)

    _render(job)
    if json_out:
        with open(json_out, "w") as f:
            json.dump(job.to_dict(), f, indent=2)
        console.print(f"\n[muted]Findings written to {json_out}[/]")
    _exit_for_job(job)


@cli.command(name="scan-integrity")
@connector_options
@click.option("--collection", required=True, help="Collection / table to scan.")
@click.option("--z-threshold", default=3.5, type=float, help="Anomaly z-score cutoff.")
@click.option("--json", "json_out", default=None, help="Write findings JSON to path.")
def scan_integrity_cmd(collection, z_threshold, json_out, **conn) -> None:
    """Scan a collection for RAG-poisoning: injections, anomalies, provenance."""
    from vecshield_platform.integrity import scan_integrity

    try:
        connector = _connector_from_opts(conn)
        with connector:
            console.print(f"[bold]Integrity scan[/] of '{collection}'…")
            job = scan_integrity(connector, collection, z_threshold=z_threshold)
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Integrity scan failed:[/] {e}")
        sys.exit(1)

    _render(job)
    if json_out:
        with open(json_out, "w") as f:
            json.dump(job.to_dict(), f, indent=2)
        console.print(f"\n[muted]Findings written to {json_out}[/]")
    _exit_for_job(job)


@cli.command(name="audit")
@connector_options
@classification_options
@click.option("--tenant-field", default=None, help="Tenant field for isolation probe.")
@click.option("--no-integrity", is_flag=True, help="Skip RAG integrity scans.")
@click.option("--no-posture", is_flag=True,
              help="Skip the network / TLS / CVE posture audit.")
@click.option("--cve-offline", is_flag=True,
              help="Skip the OSV.dev CVE network lookup during posture.")
@click.option("--tls-probe", is_flag=True,
              help="Active check: attempt a plaintext connection (without "
                   "credentials) to see whether the store refuses it.")
@click.option("--retrieval-probe", is_flag=True,
              help="Active check: replay stored vectors as queries and classify "
                   "what an authenticated retrieval client gets back.")
@click.option("--report", "report_path", default=None, help="Write HTML report to path.")
@click.option("--json", "json_out", default=None, help="Write audit JSON to path.")
@click.option("--parallel", default=1, type=int,
              help="Scan up to N collections concurrently (default 1 = serial). "
                   "Only safe with a thread-safe connector.")
@click.option("--retention-schedule", "retention_schedule_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="JSON retention schedule ({rules, default_max_age_days} or "
                   "{global, stores}); validated before the audit starts.")
@click.option("--residency-policy", "residency_policy_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="JSON residency policy ({allowed_regions, allowed_countries, "
                   "allowed_jurisdictions, data_subject_regimes}).")
@click.option("--processor-register", "processor_register_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="JSON sub-processor register ([{provider, dpa, baa, regions}]).")
@click.option("--source-manifest", "source_manifest_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="JSON source manifest ([{source, version|hash|updated_at, "
                   "deleted}]) for outdated-chunk detection.")
@click.option("--state-dir", "state_dir", default=None, envvar="VECSHIELD_STATE_DIR",
              help="Server state directory whose advisory feed to use (default: "
                   "the bundled seed). The audit never refreshes the feed.")
def audit_cmd(tenant_field, no_integrity, no_posture, cve_offline, tls_probe,
              retrieval_probe, report_path, json_out, parallel,
              retention_schedule_path, residency_policy_path, processor_register_path,
              source_manifest_path, state_dir, no_nlp, nlp_model,
              **conn) -> None:
    """Run every applicable scan + policy eval against a store (full audit)."""
    from vecshield_platform.assessment_settings import (apply_settings_scope,
                                                          resolve_store_controls,
                                                          supported_audit_kwargs)
    from vecshield_platform.compliance import build_report
    from vecshield_platform.orchestrator import run_full_audit

    overrides = _store_control_overrides(retention_schedule_path, residency_policy_path,
                                         processor_register_path, source_manifest_path)
    control_kwargs, controls = resolve_store_controls(None, None, state_dir=state_dir,
                                                      overrides=overrides)
    control_scope = {"store_controls": controls}
    kind = conn.get("kind")
    classifier = _classifier_from_options(no_nlp, nlp_model)
    try:
        connector = _connector_from_opts(conn)
        with connector:
            console.print(f"[bold]Full audit[/] of {kind} store…")
            result = run_full_audit(connector, tenant_field=tenant_field,
                                    classifier=classifier,
                                    include_integrity=not no_integrity,
                                    include_posture=not no_posture,
                                    cve_offline=cve_offline,
                                    tls_probe=tls_probe,
                                    retrieval_probe=retrieval_probe,
                                    max_workers=parallel,
                                    **supported_audit_kwargs(run_full_audit, control_kwargs,
                                                             control_scope))
            apply_settings_scope(result.scope, control_scope)
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Audit failed:[/] {e}")
        sys.exit(1)

    summary = result.severity_summary()
    console.print(
        f"\n[bold]{result.store}[/] — "
        f"{len(result.all_findings())} findings, "
        f"{len(result.violations)} policy violations\n"
        f"CRITICAL {summary['critical']}  HIGH {summary['high']}  "
        f"MEDIUM {summary['medium']}  LOW {summary['low']}  INFO {summary['info']}"
    )
    if result.violations:
        table = Table(title="Policy violations", show_lines=True)
        for c in ("Severity", "Policy", "Action", "Collection"):
            table.add_column(c, overflow="fold")
        for v in sorted(result.violations, key=lambda x: -x.severity.rank):
            style = SEV_STYLE.get(v.severity, "")
            table.add_row(f"[{style}]{v.severity.value.upper()}[/]", v.policy_id,
                          v.action, v.collection or "-")
        console.print(table)
    from vecshield_platform.coverage import job_read_shortfalls, read_shortfall

    shortfalls = [*(o for o in result.check_outcomes if read_shortfall(o)),
                  *(o for job in result.jobs for o in job_read_shortfalls(job))]
    _render_coverage(result.coverage, result.all_check_outcomes(), shortfalls)

    if report_path:
        build = build_report(result.jobs, title=f"VecShield — {result.store}",
                             violations=result.violations,
                             generated_at=result.finished_at, assessment=result.to_dict())
        with open(report_path, "w") as f:
            f.write(build)
        console.print(f"[muted]Report written to {report_path}[/]")
    if json_out:
        with open(json_out, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        console.print(f"[muted]Audit JSON written to {json_out}[/]")
    _exit_for(result.max_severity, shortfalls)


@cli.command(name="serve")
@click.option("--config", "config_path", required=True,
              help="Path to the admin config store (JSON, created if absent). "
                   "Stores and policies are persisted here.")
@click.option("--state-dir", "state_dir", default=None,
              envvar="VECSHIELD_STATE_DIR",
              help="Directory for scan history, runtime alerts, and audit logs. "
                   "When omitted, legacy paths beside --config are used.")
@click.option("--host", default="127.0.0.1", help="Bind host (default localhost).")
@click.option("--port", default=8088, type=int)
@click.option("--token", default=None,
              envvar=["LOCAL_ADMIN_TOKEN", "CUSTOMER_API_TOKEN"],
              help="Bearer token to require. Falls back to env LOCAL_ADMIN_TOKEN "
                   "or CUSTOMER_API_TOKEN.")
@click.option("--admin-token", "admin_token", default=None,
              envvar="VECSHIELD_ADMIN_TOKEN",
              help="Separate admin token. When set, --token becomes read-only "
                   "and state-changing routes (store/policy writes, erasure/DSAR "
                   "execute) require this token. Falls back to env "
                   "VECSHIELD_ADMIN_TOKEN.")
@click.option("--log-level", "log_level", default=None,
              envvar="VECSHIELD_LOG_LEVEL",
              help="Log level (DEBUG/INFO/WARNING/ERROR). Falls back to env "
                   "VECSHIELD_LOG_LEVEL / LOG_LEVEL, then INFO.")
@click.option("--log-format", "log_format",
              type=click.Choice(["text", "json"]), default=None,
              help="Log output format. Falls back to env VECSHIELD_LOG_FORMAT.")
@click.option("--cors-origin", "cors_origins", multiple=True,
              help="Allowed CORS origin (repeatable). Omit for same-origin only.")
@click.option("--max-body-mb", "max_body_mb", type=float, default=None,
              help="Reject request bodies larger than this many MiB (413).")
@click.option("--rate-limit", "rate_limit", type=int, default=None,
              help="Max requests per --rate-window seconds per caller (429).")
@click.option("--rate-window", "rate_window", type=float, default=60.0,
              help="Rate-limit window in seconds (default 60).")
@click.option("--jwt-secret", "jwt_secret", default=None,
              envvar="VECSHIELD_JWT_SECRET",
              help="HS256 secret to accept OIDC JWT bearer tokens (Okta/Entra/"
                   "Auth0/Keycloak). Tokens carry a real subject + roles claim. "
                   "Falls back to env VECSHIELD_JWT_SECRET.")
@click.option("--jwt-audience", "jwt_audience", default=None,
              envvar="VECSHIELD_JWT_AUDIENCE",
              help="Required JWT audience (aud) claim, if set.")
@click.option("--jwt-issuer", "jwt_issuer", default=None,
              envvar="VECSHIELD_JWT_ISSUER",
              help="Required JWT issuer (iss) claim, if set.")
@click.option("--separation-of-duties", "separation_of_duties", default=None,
              type=click.Choice(["required", "admin_may_self_approve", "off"]),
              help="Whether a person may approve a plan or exception they proposed. "
                   "Default: 'required' with authentication, 'admin_may_self_approve' "
                   "without (env VECSHIELD_SEPARATION_OF_DUTIES).")
@click.option("--no-login", "no_login", is_flag=True, default=False,
              help="Disable local accounts and console sign-in (also env "
                   "VECSHIELD_LOGIN=off). Bearer tokens/JWT still apply; with none "
                   "configured the API is unauthenticated and loopback-only.")
def serve_cmd(config_path, state_dir, host, port, token, admin_token, log_level, log_format,
              cors_origins, max_body_mb, rate_limit, rate_window,
              jwt_secret, jwt_audience, jwt_issuer, separation_of_duties,
              no_login) -> None:
    """Run the VecShield admin console + REST API.

    Stores and policies are managed through the dashboard (or admin API) and
    persisted to the config file, so setup survives restarts.

    Local accounts are on by default: the first start creates ``admin`` with
    password ``admin`` (or env VECSHIELD_INITIAL_ADMIN_PASSWORD), which must be
    changed at first sign-in. Bound beyond localhost, serve refuses to start
    while that password would be, or still is, ``admin``: set
    VECSHIELD_INITIAL_ADMIN_PASSWORD before the first start. That variable must
    pass the password policy on any host. Pass --no-login to turn console
    sign-in off.

    Single-writer expectation: the config file is guarded by an advisory file
    lock, but run a single server process (one worker) as the writer. Scaling to
    multiple uvicorn workers is not supported for config mutations; front the API
    with a load balancer and keep --workers at 1 (the default) if you edit stores
    or policies at runtime.
    """
    try:
        import uvicorn
    except ImportError:
        console.print("[error]uvicorn not installed.[/] pip install uvicorn")
        sys.exit(1)
    from vecshield_platform.api import create_app
    from vecshield_platform.api.config_store import ConfigStore
    from vecshield_platform.compliance import AuditIntegrityError, AuditLog
    from vecshield_platform.history import ScanHistory
    from vecshield_platform.logging_config import configure_logging
    from vecshield_platform.runtime import AlertStore
    from vecshield_platform.api.state import resolve_state_paths
    import os

    configure_logging(
        log_level,
        json_format=(None if log_format is None else log_format == "json"),
    )

    login_env = os.environ.get("VECSHIELD_LOGIN", "").strip().lower()
    login_enabled = not no_login and login_env not in {"off", "0", "false", "no", "disabled"}

    # Refuse to expose an unauthenticated API on a non-loopback interface.
    loopback = _is_loopback(host)
    if (not login_enabled and not token and not admin_token and not jwt_secret
            and not loopback):
        console.print(
            f"[error]Refusing to bind {host}:{port} without an auth token.[/] "
            "Set --token (or env LOCAL_ADMIN_TOKEN / CUSTOMER_API_TOKEN), a JWT "
            "secret (--jwt-secret), keep local sign-in enabled (drop --no-login / "
            "VECSHIELD_LOGIN=off), or bind to localhost (127.0.0.1) for "
            "unauthenticated local use."
        )
        sys.exit(1)

    config = ConfigStore(path=config_path)
    paths = resolve_state_paths(config_path, state_dir)
    from rich.markup import escape as _escape
    user_store = None
    if login_enabled:
        from vecshield_platform.api.users import UserStore
        _refuse_weak_admin_bootstrap(host, port, paths.users_db, loopback=loopback)
        user_store = UserStore(paths.users_db)
        if not loopback and user_store.default_admin_password_active():
            user_store.close()
            console.print(
                f"[error]Refusing to bind {_escape(f'{host}:{port}')}: the account admin still has "
                "the default password admin.[/] Anyone who reaches the console first "
                "would choose its password. Start once bound to 127.0.0.1, sign in and "
                "change it, then bind beyond localhost. (Or move "
                f"{_escape(str(paths.users_db))} aside to bootstrap afresh with "
                "VECSHIELD_INITIAL_ADMIN_PASSWORD; that discards every local account.)")
            sys.exit(1)
    hist = ScanHistory(paths.history_db)
    alert_store = AlertStore(paths.alerts_db)
    from vecshield_platform.compliance.audit import AuditLogLockedError
    try:
        audit = AuditLog.open(str(paths.audit_log))
    except AuditLogLockedError as e:
        console.print(f"[error]Audit log unavailable:[/] {_escape(str(e))}")
        sys.exit(1)
    except AuditIntegrityError as e:
        console.print(f"[error]Audit log integrity check failed:[/] {_escape(str(e))}")
        console.print("[warn]Investigate the tampered log before restarting.[/]")
        sys.exit(1)
    except OSError as e:
        console.print(f"[error]Cannot open the audit log {_escape(str(paths.audit_log))}:[/] "
                      f"{_escape(str(e))}")
        sys.exit(1)
    for note in audit.recovery_notes:
        console.print(
            f"[alert]Audit log recovered:[/] removed a torn final line "
            f"({note.get('torn_bytes')} bytes) left by an interrupted write; the "
            "bytes are preserved in an audit_log_recovered entry on the chain.")
    console.print(
        f"[bold]VecShield admin console[/] on http://{host}:{port}  "
        f"({len(config.stores)} store(s), {len(config.policies)} policies, "
        f"{len(audit.entries)} audit entries)"
        + (f"  [muted]state: {paths.history_db.parent.parent}[/]" if not paths.legacy else "")
        + ("" if (login_enabled or token or admin_token or jwt_secret)
           else "  [warn](no auth token — bound to localhost)[/]")
    )
    if user_store is not None:
        console.print(f"  local sign-in: on  [muted]accounts: {paths.users_db}[/]")
        if user_store.default_admin_password_active():
            console.print(
                "  [alert]The default account admin / admin is still in effect.[/] "
                "Sign in and change it now; it cannot do anything else until then.")
    else:
        console.print("  local sign-in: off")
    app = create_app(config_store=config, scan_history=hist,
                     audit_log=audit, auth_token=token, admin_token=admin_token,
                     alert_store=alert_store,
                     jwt_secret=jwt_secret, jwt_audience=jwt_audience,
                     jwt_issuer=jwt_issuer,
                     cors_origins=list(cors_origins) or None,
                     max_body_bytes=(int(max_body_mb * 1024 * 1024)
                                     if max_body_mb else None),
                     rate_limit=rate_limit, rate_window_s=rate_window,
                     separation_of_duties=separation_of_duties,
                     user_store=user_store,
                     state_dir=_feed_state_dir(config_path, state_dir),
                     vulnfeed_scheduler=True)
    policy = app.state.separation_of_duties
    if policy.mode != "required":
        console.print(f"  [warn]separation of duties: {policy.mode} ({policy.source}) — "
                      f"self-approval: {policy.to_dict()['self_approval']}[/]")
    _start_nlp(_escape)
    try:
        uvicorn.run(app, host=host, port=port)
    finally:
        if getattr(app.state, "feed_scheduler", None) is not None:
            app.state.feed_scheduler.stop()


def _is_loopback(host: str) -> bool:
    """True for a bind address only this machine can reach."""
    import ipaddress

    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False  # a hostname or wildcard: assume it is reachable


def _refuse_weak_admin_bootstrap(host: str, port: int, users_db, *,
                                 loopback: bool) -> None:
    """Exit before a first start creates ``admin`` with a password anyone could guess.

    Beyond localhost the default ``admin`` is refused outright; Helm already
    refuses to render without an initial password, and this is the same rule
    for ``docker run`` and a plain ``serve``. On any host, an initial password
    from the environment must pass the password policy, because the restart
    check (the default password still in effect) only recognises ``admin``.
    Only runs while no account exists, so an established deployment's
    accounts are never touched.
    """
    import os

    from rich.markup import escape

    from vecshield_platform.api.users import (
        BOOTSTRAP_ADMIN, INITIAL_PASSWORD_ENV, PasswordPolicyError,
        bootstrap_pending, check_password_policy,
    )

    if not bootstrap_pending(users_db):
        return
    bind = escape(f"{host}:{port}")
    password = os.environ.get(INITIAL_PASSWORD_ENV) or None
    if password is None:
        if loopback:
            return
        console.print(
            f"[error]Refusing to bind {bind}: the first start would create the "
            "account admin with the default password admin.[/] Anyone who reaches the "
            "console first would choose its password. Set "
            f"{INITIAL_PASSWORD_ENV} (for example "
            f"-e {INITIAL_PASSWORD_ENV}=\"$(openssl rand -base64 18)\"), or bind to "
            "127.0.0.1.")
        sys.exit(1)
    try:
        check_password_policy(password, username=BOOTSTRAP_ADMIN)
    except PasswordPolicyError as e:
        console.print(
            f"[error]Refusing to bind {bind}: {INITIAL_PASSWORD_ENV} is not an "
            f"acceptable password ({escape(str(e))}).[/]")
        sys.exit(1)


def _nlp_startup_warning(escape) -> None:
    """One line when NLP will not run in ``auto`` mode, with the fix."""
    from vecshield_platform.detection import startup_warning

    if warning := startup_warning():
        console.print(f"  [alert]WARNING:[/] {escape(warning)}")


def _start_nlp(escape) -> None:
    """Check NLP before serving and warm the model up in the background.

    ``required`` mode (the container images) with a model that is not
    installed stops the start here, loudly, rather than serving a console
    whose scans will all fail. Otherwise the model loads on a background
    thread, so detection status reads ``loading`` and then ``ready`` without
    a scan, and the first scan does not pay the load. VECSHIELD_NLP_WARMUP=off
    skips the warm-up (the model then loads on first use).
    """
    import os

    from vecshield_platform.detection import detection_status, start_warm_up

    try:
        status = detection_status()
    except ValueError as e:
        console.print(f"[error]Invalid detection configuration:[/] {escape(str(e))}")
        sys.exit(1)
    if status["mode"] == "required" and status["status"] == "unavailable":
        console.print("[error]NLP detection is required but unavailable:[/] "
                      f"{escape(status.get('reason') or '')}")
        sys.exit(1)
    _nlp_startup_warning(escape)
    if status["mode"] == "disabled":
        console.print("  NLP detection: disabled (pattern detectors only)")
        return
    if os.environ.get("VECSHIELD_NLP_WARMUP", "").strip().lower() in {"0", "off", "false", "no"}:
        console.print(f"  NLP detection: {escape(status['requested_model'])} loads on first "
                      "use (warm-up off)")
        return
    if status["status"] in ("unverified", "loading") and start_warm_up() is not None:
        console.print(f"  NLP detection: loading {escape(status['requested_model'])} in the "
                      f"background ({status['mode']} mode)")


@cli.command(name="discover")
@click.option("--targets", required=True,
              help="Comma-separated hosts/IPs/CIDRs/ranges "
                   "(e.g. 10.0.0.0/24,192.168.1.5,10.0.0.1-10.0.0.20).")
@click.option("--ports", default=None, help="Extra ports to scan (comma-separated).")
@click.option("--timeout", default=0.6, type=float, help="Per-probe timeout (s).")
@click.option("--json", "json_out", default=None, help="Write results JSON to path.")
def discover_cmd(targets, ports, timeout, json_out) -> None:
    """Discover vector-store instances on a network (TCP + HTTP fingerprint)."""
    from vecshield_platform.discovery import discover

    extra = None
    if ports:
        extra = []
        for raw in ports.split(","):
            token = raw.strip()
            if not token:
                continue
            try:
                extra.append(int(token))
            except ValueError:
                raise click.BadParameter(
                    f"invalid port {token!r}: ports must be integers",
                    param_hint="--ports",
                )
        extra = extra or None
    console.print(f"[bold]Scanning[/] {targets}…")
    found = discover(targets, ports=extra, timeout=timeout)

    if not found:
        console.print("[warn]No vector-store instances found.[/]")
    else:
        table = Table(title=f"Discovered {len(found)} instance(s)", show_lines=True)
        for c in ("Host", "Port", "Kind", "Version", "Endpoint"):
            table.add_column(c, overflow="fold")
        for d in found:
            table.add_row(d.host, str(d.port), d.kind, d.version or "—", d.endpoint)
        console.print(table)
    if json_out:
        with open(json_out, "w") as f:
            json.dump([d.to_dict() for d in found], f, indent=2)
        console.print(f"[muted]Results written to {json_out}[/]")


def _print_verification(verification) -> None:
    """Show which checks ran, what they found, and what could not be checked.

    A verification that only re-enumerated is a weaker result than one that also
    re-read ids and replayed vectors, so the methods are always printed — an
    operator should never have to guess how thoroughly a pass was established.
    """
    if verification is None:
        console.print("[warn]No verification was run.[/]")
        return
    methods = ", ".join(verification.methods) or "none"
    console.print(f"Verification: [bold]{verification.outcome}[/] (checks: {methods})")
    for hit in verification.ghost_hits:
        console.print(
            f"  [bad]Still served:[/] {hit['collection']}/{hit['chunk_id']} "
            f"via {hit['method']} — {hit['detail']}"
        )
    for limitation in verification.method_limitations:
        console.print(f"  [warn]Not checked:[/] {limitation}")


@cli.command(name="erasure")
@connector_options
@click.option("--subject", required=True, help="Data subject (email, name, id…).")
@click.option("--execute", is_flag=True, default=False,
              help="Execute the deletion (default: dry-run only).")
@click.option("--no-verify", is_flag=True, default=False,
              help="Skip post-delete verification scan (only applies with --execute).")
@click.option("--json", "json_out", default=None, help="Write report JSON to path.")
@click.option("--receipt", "receipt_out", default=None,
              help="Write the erasure receipt to path (only applies with --execute).")
def erasure_cmd(subject, execute, no_verify, json_out, receipt_out, **conn) -> None:
    """GDPR/CCPA erasure: find (and optionally delete) all chunks referencing a subject.

    Without --execute this is a dry-run: no data is modified.
    With --execute, chunks are deleted and (unless --no-verify) a verification
    pass is run to produce evidence that no references remain.
    """
    from vecshield_platform.compliance import (
        build_erasure_receipt, erasure_impact, execute_erasure, plan_erasure,
    )
    from vecshield_platform.connectors.base import UnsupportedCapability
    from vecshield_platform.execution import ExecutionError

    try:
        connector = _connector_from_opts(conn)
        with connector:
            console.print(f"[bold]Erasure impact[/] for '{subject}'…")
            report = erasure_impact(connector, subject)

            if execute and report.chunks_to_delete > 0:
                plan = plan_erasure(report)
                console.print(
                    f"[warn]Executing deletion:[/] {plan.total_chunks} chunk(s) "
                    f"across {len(plan.by_collection)} collection(s)…"
                )
                try:
                    execution = execute_erasure(connector, plan, verify=not no_verify)
                except UnsupportedCapability as e:
                    console.print(f"[error]Cannot delete:[/] {e}")
                    sys.exit(1)
                except ExecutionError as e:
                    console.print(f"[error]Erasure refused:[/] {escape(str(e))}")
                    sys.exit(1)
                ok_str = "[ok]OK[/]" if execution.ok else "[bad]FAILED[/]"
                console.print(
                    f"Deleted {execution.total_deleted} chunk(s). Status: {ok_str}"
                )
                if execution.errors:
                    for col, err in execution.errors.items():
                        console.print(f"  [bad]Error in {col}:[/] {err}")
                _print_verification(execution.verification)
                receipt = build_erasure_receipt(
                    execution, store=connector.describe().name, actor="cli",
                    store_kind=connector.kind, scope=list(execution.deleted))
                console.print(f"[muted]Receipt {receipt['receipt_hash'][:12]}… — "
                              f"{receipt['method_note']}[/]")
                if receipt_out:
                    with open(receipt_out, "w") as f:
                        json.dump(receipt, f, indent=2)
                    console.print(f"[muted]Receipt written to {receipt_out}[/]")
                if json_out:
                    with open(json_out, "w") as f:
                        json.dump({**execution.to_dict(), "receipt": receipt}, f, indent=2)
                    console.print(f"[muted]Execution report written to {json_out}[/]")
                if not execution.verified:
                    sys.exit(2)
                return
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Erasure assessment failed:[/] {e}")
        sys.exit(1)

    d = report.to_dict()
    console.print(
        f"\n[bold]{d['chunks_to_delete']}[/] chunk(s) to delete across "
        f"[bold]{len(d['collections_affected'])}[/] collection(s); "
        f"reindex cost {glyph('approx')} {d['reindex_chunk_cost']} chunks"
    )
    if not report.content_enumerable:
        console.print(
            f"[warn]{glyph('warn')} Inventory-only store:[/] no per-chunk enumeration API, so "
            "a zero-match result does NOT prove the subject's data is absent. "
            "Erase in the backing store (e.g. OpenSearch/pgvector) instead."
        )
    if execute and report.chunks_to_delete == 0:
        if report.coverage_complete:
            console.print("[ok]No matches observed in the fully inspected scope.[/]")
        else:
            console.print("[warn]Discovery incomplete — zero observed matches is inconclusive.[/]")
    if report.matches:
        table = Table(title="Erasure matches (dry-run)", show_lines=True)
        for col in ("Collection", "Chunk", "Matched on", "Preview"):
            table.add_column(col, overflow="fold")
        for m in report.matches[:50]:
            table.add_row(m.collection, m.chunk_id, m.matched_on, m.preview)
        console.print(table)
    if json_out:
        with open(json_out, "w") as f:
            json.dump(d, f, indent=2)
        console.print(f"[muted]Report written to {json_out}[/]")


@cli.command(name="verify-erasure")
@connector_options
@click.option("--subject", required=True, help="Data subject (email, name, id…).")
@click.option("--expected-deleted", default=0, type=int,
              help="Number of chunks expected to have been deleted.")
@click.option("--json", "json_out", default=None, help="Write verification JSON to path.")
def verify_erasure_cmd(subject, expected_deleted, json_out, **conn) -> None:
    """Verify a completed erasure workflow left no subject references behind."""
    from vecshield_platform.compliance import verify_erasure

    try:
        connector = _connector_from_opts(conn)
        with connector:
            console.print(f"[bold]Verifying erasure[/] for '{subject}'…")
            verification = verify_erasure(
                connector,
                subject,
                expected_deleted=expected_deleted,
            )
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Erasure verification failed:[/] {e}")
        sys.exit(1)

    d = verification.to_dict()
    _print_verification(verification)
    if verification.ok:
        console.print(f"[ok]{glyph('ok')} Erasure verified: no remaining matches.[/]")
    else:
        console.print(
            f"[error]Erasure {verification.outcome}:[/] {d['remaining_matches']} "
            f"observed remaining match(es); coverage {verification.remaining.coverage_status}."
        )
        table = Table(title="Remaining matches", show_lines=True)
        for col in ("Collection", "Chunk", "Matched on", "Preview"):
            table.add_column(col, overflow="fold")
        for m in verification.remaining.matches[:50]:
            table.add_row(m.collection, m.chunk_id, m.matched_on, m.preview)
        console.print(table)

    if json_out:
        with open(json_out, "w") as f:
            json.dump(d, f, indent=2)
        console.print(f"[muted]Verification written to {json_out}[/]")
    if not verification.ok:
        sys.exit(2)


@cli.command(name="monitor-replay")
@click.option("--events", "events_path", required=True,
              help="JSONL of query events (principal, collection, timestamp, "
                   "result_ids, query_vector).")
@click.option("--bulk-threshold", default=500, type=int)
@click.option("--bulk-window", default=600.0, type=float)
@click.option("--cooldown", default=300.0, type=float)
@click.option("--sizes", "sizes_path", default=None,
              help="JSON dict of {collection: size} to enable the "
                   "collection-sweep detector.")
@click.option("--sweep-fraction", default=0.8, type=float,
              help="Fraction of a collection's vectors that constitutes a sweep.")
@click.option("--sweep-window", default=600.0, type=float,
              help="Window (s) over which sweep coverage is accumulated.")
@click.option("--json", "json_out", default=None, help="Write alerts JSON to path.")
def monitor_replay_cmd(events_path, bulk_threshold, bulk_window,
                       cooldown, sizes_path, sweep_fraction, sweep_window,
                       json_out) -> None:
    """Replay a query-event log through the monitor (forensics / tuning)."""
    from vecshield_platform.runtime import (
        BulkVolumeDetector, CollectionSweepDetector, EnumerationDetector,
        InMemorySink, MonitorEngine, RateBaselineDetector,
    )
    from vecshield_platform.runtime.events import QueryEvent

    sizes: dict[str, int] = {}
    if sizes_path:
        with open(sizes_path) as f:
            sizes = {str(k): int(v) for k, v in json.load(f).items()}

    sink = InMemorySink()
    engine = MonitorEngine(
        detectors=[
            BulkVolumeDetector(threshold=bulk_threshold, window_s=bulk_window),
            CollectionSweepDetector(
                fraction=sweep_fraction, window_s=sweep_window,
                size_fn=lambda c: sizes.get(c)),
            EnumerationDetector(),
            RateBaselineDetector(),
        ],
        sinks=[sink], cooldown_s=cooldown,
    )

    n = 0
    with open(events_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            engine.process(QueryEvent(
                principal=d["principal"], collection=d.get("collection", "?"),
                timestamp=float(d["timestamp"]),
                query_vector=d.get("query_vector"),
                result_ids=d.get("result_ids", []),
            ))
            n += 1

    console.print(f"\n[bold]Replayed {n} events[/] — {len(sink)} alert(s)")
    if sink.alerts:
        table = Table(title="Alerts", show_lines=True)
        for col in ("Severity", "Rule", "Principal", "Message"):
            table.add_column(col, overflow="fold")
        for a in sorted(sink.alerts, key=lambda x: -x.severity.rank):
            style = SEV_STYLE.get(a.severity, "")
            table.add_row(f"[{style}]{a.severity.value.upper()}[/]", a.rule,
                          a.principal, a.message)
        console.print(table)

    if json_out:
        with open(json_out, "w") as f:
            json.dump([a.to_dict() for a in sink.alerts], f, indent=2)
        console.print(f"[muted]Alerts written to {json_out}[/]")
    if any(a.severity.rank >= Severity.HIGH.rank for a in sink.alerts):
        sys.exit(2)


@cli.command(name="monitor-live")
@connector_options
@click.option("--collection", required=True,
              help="Collection to sample vectors from and query through the monitor.")
@click.option("--samples", default=10, type=int,
              help="Number of sample queries to issue.")
@click.option("--top-k", "top_k", default=10, type=int)
@click.option("--principal", default="cli-monitor",
              help="Principal attributed to the issued queries.")
@click.option("--bulk-threshold", default=500, type=int)
@click.option("--bulk-window", default=600.0, type=float)
@click.option("--cooldown", default=300.0, type=float)
@click.option("--sweep-fraction", default=0.8, type=float)
@click.option("--sweep-window", default=600.0, type=float)
@click.option("--json", "json_out", default=None, help="Write alerts JSON to path.")
def monitor_live_cmd(collection, samples, top_k, principal, bulk_threshold,
                     bulk_window, cooldown, sweep_fraction, sweep_window,
                     json_out, **conn) -> None:
    """Drive live queries through the runtime monitor against a real store.

    Samples up to --samples embedded vectors from the collection and replays them
    as queries via a MonitoredConnector, so the same detectors used by
    monitor-replay observe a live store. Useful for smoke-testing detection
    wiring and establishing a baseline.
    """
    from vecshield_platform.runtime import (
        BulkVolumeDetector, CollectionSweepDetector, EnumerationDetector,
        InMemorySink, MonitorEngine, MonitoredConnector, RateBaselineDetector,
        collection_size_fn,
    )

    connector = _connector_from_opts(conn)
    if "query" not in connector.capabilities():
        console.print(f"[error]monitor-live unsupported:[/] {connector.kind} "
                      f"has no query capability")
        sys.exit(1)
    max_top_k = getattr(connector, "max_top_k", None)
    if isinstance(max_top_k, int) and 0 < max_top_k < top_k:
        console.print(f"[warn]--top-k {top_k} exceeds {connector.kind}'s limit; "
                      f"using {max_top_k}.[/]")
        top_k = max_top_k

    vectors: list[list[float]] = []
    sink = InMemorySink()
    try:
        engine = MonitorEngine(
            detectors=[
                BulkVolumeDetector(threshold=bulk_threshold, window_s=bulk_window),
                CollectionSweepDetector(fraction=sweep_fraction,
                                        window_s=sweep_window,
                                        size_fn=collection_size_fn(connector)),
                EnumerationDetector(),
                RateBaselineDetector(),
            ],
            sinks=[sink], cooldown_s=cooldown,
        )
        mon = MonitoredConnector(connector, engine, principal=principal)

        for ch in connector.iter_chunks(collection):
            if ch.embedding:
                vectors.append(list(ch.embedding))
            if len(vectors) >= samples:
                break
        if not vectors:
            console.print(f"[error]No embedded vectors found in[/] '{collection}' "
                          f"— cannot issue sample queries.")
            sys.exit(1)

        for vec in vectors:
            mon.query(collection, vec, top_k=top_k)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]monitor-live failed:[/] {e}")
        sys.exit(1)
    finally:
        close = getattr(connector, "close", None)
        if callable(close):
            try:
                close()
            except Exception:  # noqa: BLE001
                pass

    console.print(f"\n[bold]Issued {len(vectors)} live queries[/] — "
                  f"{len(sink)} alert(s)")
    if sink.alerts:
        table = Table(title="Alerts", show_lines=True)
        for col in ("Severity", "Rule", "Principal", "Message"):
            table.add_column(col, overflow="fold")
        for a in sorted(sink.alerts, key=lambda x: -x.severity.rank):
            style = SEV_STYLE.get(a.severity, "")
            table.add_row(f"[{style}]{a.severity.value.upper()}[/]", a.rule,
                          a.principal, a.message)
        console.print(table)

    if json_out:
        with open(json_out, "w") as f:
            json.dump([a.to_dict() for a in sink.alerts], f, indent=2)
        console.print(f"[muted]Alerts written to {json_out}[/]")
    if any(a.severity.rank >= Severity.HIGH.rank for a in sink.alerts):
        sys.exit(2)


@cli.command(name="ingest-monitor")
@click.option("--events", "events_path", required=True,
              help="JSONL of ingest batches: {\"principal\":..,\"dataset\":..,"
                   "\"timestamp\":..,\"chunks\":[{\"id\":..,\"text\":..}]}.")
@click.option("--mode", default="soft", type=click.Choice(["soft", "hard"]),
              help="Gate mode passed to the ingest gate.")
@classification_options
@click.option("--json", "json_out", default=None, help="Write alerts JSON to path.")
def ingest_monitor_cmd(events_path, mode, no_nlp, nlp_model, json_out) -> None:
    """Replay ingest batches through the real-time IngestMonitor.

    Each JSONL line is one ingested batch. Batches whose chunks carry blockable
    PII raise an alert through the same sink architecture as the query monitor.
    """
    from vecshield.ingest import IngestGate
    from vecshield.models import Chunk
    from vecshield_platform.runtime import InMemorySink, IngestMonitor

    classifier = _classifier_from_options(no_nlp, nlp_model)

    sink = InMemorySink()
    gate = IngestGate(classifier=classifier, mode=mode)
    mon = IngestMonitor(gate, sinks=[sink])

    n = 0
    blocked_batches = 0
    try:
        with open(events_path) as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                dataset = d.get("dataset", "ingest")
                raw = d.get("chunks", [])
                chunks = [
                    Chunk(id=str(c.get("id", f"{i}-{j}")),
                          collection=c.get("collection", dataset),
                          text=c.get("text", "") or "",
                          metadata=c.get("metadata") or {})
                    for j, c in enumerate(raw)
                ]
                report = mon.observe(
                    chunks,
                    principal=d.get("principal", "anonymous"),
                    dataset=dataset,
                    timestamp=float(d.get("timestamp", i)),
                )
                if report.blocked:
                    blocked_batches += 1
                n += 1
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Ingest monitor failed:[/] {e}")
        sys.exit(1)

    console.print(f"\n[bold]Observed {n} batch(es)[/] — "
                  f"{blocked_batches} with blocked PII, {len(sink)} alert(s)")
    if sink.alerts:
        table = Table(title="Ingest alerts", show_lines=True)
        for col in ("Severity", "Rule", "Principal", "Message"):
            table.add_column(col, overflow="fold")
        for a in sorted(sink.alerts, key=lambda x: -x.severity.rank):
            style = SEV_STYLE.get(a.severity, "")
            table.add_row(f"[{style}]{a.severity.value.upper()}[/]", a.rule,
                          a.principal, a.message)
        console.print(table)

    if json_out:
        with open(json_out, "w") as f:
            json.dump([a.to_dict() for a in sink.alerts], f, indent=2)
        console.print(f"[muted]Alerts written to {json_out}[/]")
    if any(a.severity.rank >= Severity.HIGH.rank for a in sink.alerts):
        sys.exit(2)


@cli.command(name="validate-stores")
@click.option("--config", "config_path", required=True,
              help="Path to a VecShield admin config JSON with registered stores.")
@click.option("--store-id", default=None,
              help="Validate only one registered store.")
@click.option("--max-collections", default=5, type=int,
              help="Maximum collections sampled per store.")
@click.option("--sample-chunks", default=5, type=int,
              help="Maximum chunks sampled/scanned per collection.")
@click.option("--no-scan", is_flag=True,
              help="Skip bounded classification scan.")
@click.option("--no-query", is_flag=True,
              help="Skip query capability probe.")
@click.option("--no-key-audit", is_flag=True,
              help="Skip API key introspection/audit.")
@click.option("--json", "json_out", default=None,
              help="Write validation JSON to path.")
def validate_stores_cmd(config_path, store_id, max_collections, sample_chunks,
                        no_scan, no_query, no_key_audit, json_out) -> None:
    """Validate registered stores against the live connector contract."""
    from vecshield_platform.api.config_store import ConfigStore
    from vecshield_platform.validation import validate_connector

    cfg = ConfigStore(path=config_path)
    registry = cfg.build_registry()
    stores = registry.list()
    if store_id:
        stores = [s for s in stores if s.store_id == store_id]
        if not stores:
            console.print(f"[error]Unknown store:[/] {store_id}")
            sys.exit(1)

    results = []
    for s in stores:
        console.print(f"[bold]Validating[/] {s.store_id} ({s.kind})…")
        conn = registry.open(s.store_id)
        try:
            res = validate_connector(
                conn,
                max_collections=max_collections,
                sample_chunks=sample_chunks,
                run_scan=not no_scan,
                run_query=not no_query,
                run_key_audit=not no_key_audit,
            )
        finally:
            conn.close()
        results.append({"store_id": s.store_id, **res.to_dict()})

    table = Table(title=f"Validated {len(results)} store(s)", show_lines=True)
    for col in ("Store ID", "Kind", "OK", "Checks", "Findings", "Top Severity"):
        table.add_column(col, overflow="fold")
    for r in results:
        ok = "yes" if r["ok"] else "no"
        checks = ", ".join(
            c["name"] + ("=skip" if c["skipped"] else ("=ok" if c["ok"] else "=fail"))
            for c in r["checks"]
        )
        table.add_row(r["store_id"], r["kind"], ok, checks,
                      str(len(r["findings"])), r["max_severity"])
    console.print(table)

    if json_out:
        with open(json_out, "w") as f:
            json.dump({"stores": results}, f, indent=2)
        console.print(f"[muted]Validation JSON written to {json_out}[/]")
    if any(not r["ok"] for r in results):
        sys.exit(1)
    if any(r["max_severity"] in ("high", "critical") for r in results):
        sys.exit(2)


@cli.command(name="audit-keys")
@click.option("--keys", "keys_path", required=True,
              help="JSON file containing provider/API key inventory.")
@click.option("--store-name", default="unknown",
              help="Store/provider name for findings.")
@click.option("--sensitive-namespace", "sensitive_namespaces", multiple=True,
              help="Namespace/collection known to hold sensitive data. Repeatable.")
@click.option("--stale-days", default=90, type=int,
              help="Days unused before a key is considered stale.")
@click.option("--json", "json_out", default=None,
              help="Write findings JSON to path.")
def audit_keys_cmd(keys_path, store_name, sensitive_namespaces, stale_days,
                   json_out) -> None:
    """Audit API key inventory exported from a vector/cloud provider."""
    from vecshield_platform.access import api_keys_from_dicts, audit_api_keys

    with open(keys_path) as f:
        data = json.load(f)
    items = data.get("keys", data) if isinstance(data, dict) else data
    keys = api_keys_from_dicts(items)
    findings = audit_api_keys(
        keys,
        store_name=store_name,
        sensitive_namespaces=set(sensitive_namespaces),
        stale_days=stale_days,
    )

    console.print(f"\n[bold]{store_name}[/] — {len(keys)} key(s), "
                  f"{len(findings)} finding(s)")
    if findings:
        table = Table(title="API key findings", show_lines=True)
        for col in ("Severity", "Finding", "Detail"):
            table.add_column(col, overflow="fold")
        for fnd in sorted(findings, key=lambda x: -x.severity.rank):
            style = SEV_STYLE.get(fnd.severity, "")
            table.add_row(f"[{style}]{fnd.severity.value.upper()}[/]",
                          fnd.title, fnd.description)
        console.print(table)
    else:
        console.print(f"[ok]{glyph('ok')} No key findings.[/]")

    if json_out:
        with open(json_out, "w") as f:
            json.dump([fnd.to_dict() for fnd in findings], f, indent=2)
        console.print(f"[muted]Findings written to {json_out}[/]")
    if any(fnd.severity.rank >= Severity.HIGH.rank for fnd in findings):
        sys.exit(2)


@cli.command(name="rbac-diff")
@click.option("--intended", "intended_path", required=True,
              help="JSON file of intended access grants "
                   "(list of {principal, namespace, action}).")
@click.option("--actual", "actual_path", required=True,
              help="JSON file of actual/live access grants (same shape).")
@click.option("--store-name", default="unknown",
              help="Store name for findings.")
@click.option("--json", "json_out", default=None,
              help="Write findings JSON to path.")
def rbac_diff_cmd(intended_path, actual_path, store_name, json_out) -> None:
    """Diff intended vs. actual RBAC grants (over-grants + drift)."""
    from vecshield_platform.access import diff_access, grants_from_dicts

    def _load(path):
        with open(path) as f:
            data = json.load(f)
        items = data.get("grants", data) if isinstance(data, dict) else data
        return grants_from_dicts(items)

    try:
        intended = _load(intended_path)
        actual = _load(actual_path)
    except (KeyError, ValueError, TypeError) as e:
        console.print(f"[error]Invalid grants file:[/] {e}")
        sys.exit(1)

    findings = diff_access(intended, actual, store_name=store_name)
    _render_findings(
        findings,
        header=f"{store_name} — {len(intended)} intended vs {len(actual)} actual grant(s)",
    )

    if json_out:
        with open(json_out, "w") as f:
            json.dump([fnd.to_dict() for fnd in findings], f, indent=2)
        console.print(f"[muted]Findings written to {json_out}[/]")
    if any(fnd.severity.rank >= Severity.HIGH.rank for fnd in findings):
        sys.exit(2)


@cli.command(name="posture-check")
@click.option("--connector", "kind", default="chroma",
              type=click.Choice(AVAILABLE), help="Vector store kind.")
@click.option("--host", default=None)
@click.option("--port", default=None, type=int)
@click.option("--path", default=None, help="Chroma local persistent store path.")
@click.option("--dsn", default=None, help="pgvector connection string.")
@click.option("--url", default=None, help="Endpoint URL (qdrant/weaviate/redis…).")
@click.option("--no-cve", is_flag=True, help="Skip the OSV.dev CVE lookup.")
@click.option("--no-dns", is_flag=True, help="Skip DNS resolution (offline-safe).")
@click.option("--strict-private", is_flag=True,
              help="Also flag managed SaaS endpoints as public.")
@click.option("--json", "json_out", default=None, help="Write findings JSON to path.")
def posture_cmd(kind, host, port, path, dsn, url, no_cve, no_dns,
                strict_private, json_out) -> None:
    """network exposure + TLS + CVE configuration audit."""
    from vecshield_platform.posture import run_posture_audit

    if kind == "chroma" and not host and not path:
        host = "localhost"
    if kind == "chroma" and port is None:
        port = 8000
    try:
        connector = build_connector(kind, host=host, port=port, path=path,
                                    dsn=dsn, url=url)
        with connector:
            console.print(f"[bold]Posture check[/] of {kind} store…")
            job = run_posture_audit(connector, resolve_dns=not no_dns,
                                    include_cve=not no_cve,
                                    flag_managed_public=strict_private)
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Posture check failed:[/] {e}")
        sys.exit(1)

    _render(job)
    if json_out:
        with open(json_out, "w") as f:
            json.dump(job.to_dict(), f, indent=2)
        console.print(f"\n[muted]Findings written to {json_out}[/]")
    _exit_for_job(job)


@cli.command(name="cve-scan")
@click.option("--connector", "kind", default=None, type=click.Choice(AVAILABLE),
              help="Scan one connector's client library (default: all installed).")
@click.option("--offline", is_flag=True, help="Skip the OSV.dev network query.")
@click.option("--json", "json_out", default=None, help="Write findings JSON to path.")
def cve_scan_cmd(kind, offline, json_out) -> None:
    """Scan installed connector client libraries against OSV.dev for known CVEs."""
    from vecshield_platform.posture import scan_cves

    console.print("[bold]CVE scan[/] against OSV.dev…")
    findings = scan_cves(kinds=[kind] if kind else None, offline=offline)
    job = ScanJob(id="cve-scan", store="dependencies")
    for f in findings:
        job.add(f)
    _render_findings(job.findings, header=f"{len(findings)} CVE finding(s)")
    if json_out:
        with open(json_out, "w") as f:
            json.dump(job.to_dict(), f, indent=2)
        console.print(f"\n[muted]Findings written to {json_out}[/]")
    if job.max_severity.rank >= Severity.HIGH.rank:
        sys.exit(2)


@cli.command(name="pia")
@connector_options
@classification_options
@click.option("--purpose", default="Retrieval-augmented generation (RAG)",
              help="Stated processing purpose for the DPIA.")
@click.option("--html", "html_out", default=None, help="Write the DPIA HTML to path.")
@click.option("--json", "json_out", default=None, help="Write the DPIA JSON to path.")
def pia_cmd(purpose, html_out, json_out, no_nlp, nlp_model, **conn) -> None:
    """Generate a GDPR Article 35 DPIA from a full audit of a store."""
    from vecshield_platform.compliance import build_pia_html, generate_pia
    from vecshield_platform.orchestrator import run_full_audit

    kind = conn.get("kind")
    classifier = _classifier_from_options(no_nlp, nlp_model)
    try:
        connector = _connector_from_opts(conn)
        with connector:
            console.print(f"[bold]DPIA[/] — auditing {kind} store…")
            result = run_full_audit(connector, classifier=classifier)
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]DPIA failed:[/] {e}")
        sys.exit(1)

    pia = generate_pia(result, purpose=purpose)
    flag = "[bad]HIGH RISK[/]" if pia.high_risk else "[ok]standard risk[/]"
    console.print(
        f"\n[bold]{pia.store}[/] — {flag}, residual {pia.residual_risk.upper()}\n"
        f"Data categories: {', '.join(pia.data_categories) or 'none detected'}\n"
        f"Risks: {len(pia.risks)}  ·  DPO sign-off required: "
        f"{'YES' if pia.dpo_action_required else 'no'}"
    )
    if html_out:
        with open(html_out, "w") as f:
            f.write(build_pia_html(pia, generated_at=result.finished_at))
        console.print(f"[muted]DPIA HTML written to {html_out}[/]")
    if json_out:
        with open(json_out, "w") as f:
            json.dump(pia.to_dict(), f, indent=2)
        console.print(f"[muted]DPIA JSON written to {json_out}[/]")


def _render_findings(findings, *, header: str = "") -> None:
    if header:
        console.print(f"\n[bold]{header}[/]")
    if not findings:
        console.print(f"[ok]{glyph('ok')} No findings.[/]")
        return
    table = Table(title="Findings", show_lines=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Finding")
    table.add_column("Detail", overflow="fold")
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        style = SEV_STYLE.get(f.severity, "")
        table.add_row(f"[{style}]{f.severity.value.upper()}[/]", f.title, f.description)
    console.print(table)


def _render(job: ScanJob) -> None:
    s = job.stats
    if "tenants" in s:  # isolation probe job
        console.print(
            f"\n[bold]{job.store}[/] — collection '{s.get('collection')}', "
            f"{s.get('tenant_count', 0)} tenants "
            f"({', '.join(s.get('tenants', [])) or 'none'}), "
            f"{s.get('chunks_examined', 0)} chunks examined"
        )
    elif "injections" in s:  # integrity scan job
        console.print(
            f"\n[bold]{job.store}[/] — collection '{s.get('collection')}', "
            f"{s.get('chunks_scanned', 0)} chunks, "
            f"{s.get('vectors_checked', 0)} vectors, "
            f"{s.get('injections', 0)} injections, "
            f"provenance {s.get('provenance_coverage', 0):.0%}"
        )
    elif "records_scanned" in s:  # training-data scan job
        console.print(
            f"\n[bold]{job.store}[/] — "
            f"{s.get('datasets', 0)} dataset(s), "
            f"{s.get('records_scanned', 0)} records scanned, "
            f"{s.get('sensitive_records', 0)} sensitive "
            f"[muted]({s.get('source_kind', '?')})[/]"
        )
    else:  # data-classification scan job
        console.print(
            f"\n[bold]{job.store}[/] — "
            f"{s.get('collections', 0)} collections, "
            f"{s.get('chunks_scanned', 0)} chunks scanned, "
            f"{s.get('sensitive_chunks', 0)} sensitive"
        )

    coverage = job.stats.get("coverage")
    if not job.findings:
        if coverage is None or coverage.get("complete"):
            console.print(f"[ok]{glyph('ok')} No findings.[/]")
        else:
            console.print(f"[warn]{glyph('warn')} No findings in what was checked, but "
                          "coverage is partial, so this is not a clean result.[/]")
    else:
        table = Table(title="Findings", show_lines=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Collection")
        table.add_column("Finding")
        table.add_column("Detail", overflow="fold")

        for f in sorted(job.findings, key=lambda x: -x.severity.rank):
            style = SEV_STYLE.get(f.severity, "")
            table.add_row(
                f"[{style}]{f.severity.value.upper()}[/]",
                f.collection or "-",
                f.title,
                f.description,
            )
        console.print(table)
        console.print(f"\n[bold]Highest severity:[/] {job.max_severity.value.upper()}")
    if coverage is not None:
        from vecshield_platform.coverage import job_outcomes, job_read_shortfalls

        _render_coverage(coverage, job_outcomes(job), job_read_shortfalls(job))


def _render_coverage(coverage: dict, outcomes: list[dict], shortfalls: list[dict]) -> None:
    """Print the coverage status and every requested check that did not complete.

    Opt-in checks nobody asked for and properties the database cannot report
    are counted, not listed: neither is a gap in this run.
    """
    from vecshield_platform.coverage import capability_limited, not_requested

    expected, complete = coverage.get("checks_expected", 0), coverage.get("checks_complete", 0)
    status = coverage.get("status", "unknown")
    extras = [f"{n} {what}" for n, what in (
        (coverage.get("checks_not_requested", 0), "not requested"),
        (coverage.get("checks_not_supported", 0), "not reportable by this store")) if n]
    style = "ok" if coverage.get("complete") else "warn"
    console.print(f"\n[{style}]Coverage: {status}[/] — {complete} of {expected} checks "
                  f"complete" + (f" ({', '.join(extras)})" if extras else ""))
    incomplete = [o for o in outcomes
                  if not (o.get("coverage") or {}).get("complete")
                  and not not_requested(o) and not capability_limited(o)]
    if not incomplete:
        return
    short_keys = {(o.get("check"), o.get("collection")) for o in shortfalls}
    table = Table(title="Incomplete checks", show_lines=True)
    for column in ("Check", "Collection", "Outcome", "Reason"):
        table.add_column(column, overflow="fold")
    for o in incomplete:
        short = (o.get("check"), o.get("collection")) in short_keys
        outcome = escape(str(o.get("outcome")))
        table.add_row(escape(str(o.get("check"))), escape(str(o.get("collection") or "-")),
                      f"[bad]{outcome}, read shortfall[/]" if short else outcome,
                      escape(str(o.get("reason") or "")))
    console.print(table)


def _exit_for(max_severity: Severity, shortfalls: list[dict]) -> None:
    """Exit 2 on a high or critical finding, else 3 when the store was not fully read.

    A partial read with no high finding is not a pass: the unread part was not
    examined. Checks inconclusive by their nature (too few vectors, NLP off, no
    tenant field) are listed but keep exit 0, because the store was read.
    """
    if max_severity.rank >= Severity.HIGH.rank:
        sys.exit(2)
    if shortfalls:
        console.print(f"\n[warn]{glyph('warn')} {len(shortfalls)} check(s) did not read the "
                      "whole store or failed, so the result is incomplete (exit 3).[/]")
        sys.exit(3)


def _exit_for_job(job: ScanJob) -> None:
    from vecshield_platform.coverage import job_read_shortfalls

    _exit_for(job.max_severity, job_read_shortfalls(job))


@cli.command(name="dsar")
@click.option("--subject", required=True,
              help="Data subject identifier (email, user ID, name…).")
@click.option("--config", "config_path", required=True,
              help="Path to VecShield config store (JSON) — all registered stores are scanned.")
@click.option("--stores", "store_filter", default=None,
              help="Comma-separated store IDs to limit scope (default: all).")
@click.option("--execute", is_flag=True, default=False,
              help="Execute deletions after the impact scan.")
@click.option("--no-verify", is_flag=True, default=False,
              help="Skip post-delete verification (only with --execute).")
@click.option("--out", "out_path", default=None,
              help="Write evidence bundle JSON to this path.")
def dsar_cmd(subject, config_path, store_filter, execute, no_verify, out_path) -> None:
    """DSAR workflow: scan all stores for a subject, then optionally execute.

    \b
    Without --execute:  read-only impact scan across every registered store.
    With --execute:     delete all matching chunks + produce evidence bundle.

    The evidence bundle (--out) is the file you hand to your DPO.
    """
    from vecshield_platform.api.config_store import ConfigStore
    from vecshield_platform.compliance.dsar import create_dsar, execute_dsar, scan_all_stores

    config = ConfigStore(path=config_path)
    registry = config.build_registry()
    store_ids = [s.strip() for s in store_filter.split(",")] if store_filter else None

    dsar = create_dsar(subject)
    console.print(
        f"\n[bold]DSAR impact scan[/] for '[bold]{escape(subject)}[/]' "
        f"across {len(registry.list())} store(s)…"
    )

    scan_all_stores(dsar, registry, store_ids=store_ids)

    # Impact summary table
    table = Table(title="Impact by store", show_lines=False)
    table.add_column("Store")
    table.add_column("Kind")
    table.add_column("Chunks found", justify="right")
    table.add_column("Collections", justify="right")
    table.add_column("Status")
    for r in dsar.stores:
        status = "[bad]error[/]" if r.error else (
            "[warn]match[/]" if r.chunks_found else "[ok]clean[/]")
        table.add_row(
            r.store_id, r.kind, str(r.chunks_found),
            str(len(r.impact.collections_affected) if r.impact else 0), status)
    console.print(table)
    console.print(
        f"\n[bold]{dsar.total_chunks_found}[/] chunk(s) to delete "
        f"across [bold]{len(dsar.stores_with_matches)}[/] store(s)  "
        f"(DSAR id: [muted]{dsar.id}[/])"
    )
    if dsar.stores_with_errors:
        for r in dsar.stores_with_errors:
            console.print(f"  [bad]{glyph('warn')} {r.store_id}:[/] {r.error}")

    if not execute:
        if dsar.total_chunks_found:
            console.print(
                "\n[muted]Re-run with [bold]--execute[/] to delete these chunks "
                "and generate an evidence bundle.[/]"
            )
        if out_path:
            import json
            with open(out_path, "w") as f:
                json.dump(dsar.to_dict(), f, indent=2)
            console.print(f"[muted]Impact report written to {out_path}[/]")
        return

    if dsar.total_chunks_found == 0:
        console.print("[ok]No matches — nothing to delete.[/]")
        return

    console.print(
        f"\n[warn]Executing deletions[/] across "
        f"{len(dsar.stores_with_matches)} store(s)…"
    )
    from vecshield_platform.execution import ExecutionError

    try:
        execute_dsar(dsar, registry, store_ids=store_ids, verify=not no_verify)
    except ExecutionError as e:
        console.print(f"[error]Erasure refused:[/] {escape(str(e))}")
        sys.exit(1)

    # Execution summary
    etable = Table(title="Execution results", show_lines=False)
    etable.add_column("Store")
    etable.add_column("Deleted", justify="right")
    etable.add_column("Verified")
    etable.add_column("Status")
    for r in dsar.stores:
        if r.chunks_found == 0:
            continue
        ok = r.execution.ok if r.execution else False
        verified = "—"
        if r.execution and r.execution.verification:
            verified = (f"[ok]{glyph('ok')}[/]" if r.execution.verification.ok
                        else f"[bad]{glyph('fail')}[/]")
        status = "[bad]error[/]" if r.error else ("[ok]ok[/]" if ok else "[warn]warn[/]")
        etable.add_row(r.store_id, str(r.chunks_deleted), verified, status)
    console.print(etable)

    overall = "[ok]COMPLETE[/]" if dsar.status == "executed" else "[warn]PARTIAL ERROR[/]"
    console.print(
        f"\nDSAR {dsar.id} — {overall}  "
        f"[bold]{dsar.total_chunks_deleted}[/] chunk(s) deleted"
    )

    if out_path:
        import json
        with open(out_path, "w") as f:
            json.dump(dsar.evidence_bundle(), f, indent=2)
        console.print(f"\n[bold]Evidence bundle written to {out_path}[/]  "
                      f"[muted](attach to DSAR ticket for DPO)[/]")


@cli.command(name="scan-dataset")
@click.option("--source", "kind", default="local",
              help="Data source kind: local, s3, gcs, azure_blob, huggingface.")
@click.option("--path", default=None, help="Local directory path (local source).")
@click.option("--bucket", default=None, help="Bucket name (s3/gcs).")
@click.option("--container", default=None, help="Container name (azure_blob).")
@click.option("--prefix", default="", help="Key prefix (s3/gcs/azure_blob).")
@click.option("--region", default=None, help="AWS region (s3).")
@click.option("--dataset", default=None, help="HuggingFace dataset name.")
@click.option("--split", default=None, help="HuggingFace split (e.g. train).")
@click.option("--text-field", default=None,
              help="Record field that holds the text (jsonl/csv/parquet/hf).")
@click.option("--format", "fmt", default=None,
              help="Force a format reader (jsonl/csv/parquet/text/pdf).")
@classification_options
@click.option("--max-records", default=None, type=int,
              help="Cap records scanned per dataset.")
@click.option("--json", "json_out", default=None, help="Write findings JSON to path.")
def scan_dataset_cmd(kind, path, bucket, container, prefix, region, dataset, split,
                     text_field, fmt, no_nlp, nlp_model, max_records, json_out) -> None:
    """Scan raw training/fine-tuning data for sensitive content."""
    from vecshield_platform.datasources import build_datasource
    from vecshield.datascan import scan_datasource

    classifier = _classifier_from_options(no_nlp, nlp_model)

    try:
        source = build_datasource(
            kind, path=path, bucket=bucket, container=container, prefix=prefix,
            region=region, dataset=dataset, split=split, text_field=text_field,
            format=fmt)
        with source:
            console.print(f"[bold]Scanning[/] {kind} data source…")
            job = scan_datasource(source, classifier=classifier,
                                  max_records_per_dataset=max_records)
            job.stats["detection"] = classifier.detection_metadata()
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Dataset scan failed:[/] {e}")
        sys.exit(1)

    _render(job)
    if json_out:
        with open(json_out, "w") as f:
            json.dump(job.to_dict(), f, indent=2)
        console.print(f"\n[muted]Findings written to {json_out}[/]")
    if job.max_severity.rank >= Severity.HIGH.rank:
        sys.exit(2)


@cli.command(name="gate-ingest")
@click.option("--source", "kind", default="local",
              help="Data source kind to read chunks from.")
@click.option("--path", default=None, help="Local directory path (local source).")
@click.option("--bucket", default=None, help="Bucket name (s3/gcs).")
@click.option("--prefix", default="", help="Key prefix.")
@click.option("--text-field", default=None, help="Record text field.")
@click.option("--format", "fmt", default=None, help="Force a format reader.")
@click.option("--mode", default="soft", type=click.Choice(["soft", "hard"]),
              help="soft = report only; hard = exit non-zero if blocked.")
@click.option("--redact", is_flag=True,
              help="Mask sensitive spans in place instead of blocking whole chunks.")
@click.option("--write", is_flag=True,
              help="Write clean/allowed chunks to a target store (needs --target*).")
@click.option("--target", default="chroma", type=click.Choice(AVAILABLE),
              help="Target store kind for --write.")
@click.option("--target-path", "target_path", default=None,
              help="Chroma local persistent path (write target).")
@click.option("--target-host", "target_host", default=None,
              help="Chroma server host (write target).")
@click.option("--target-port", "target_port", default=None, type=int,
              help="Chroma server port (write target).")
@click.option("--target-url", "target_url", default=None,
              help="Endpoint URL for url-based write targets.")
@click.option("--collection", default=None,
              help="Target collection for --write (defaults to each chunk's own).")
@classification_options
@click.option("--json", "json_out", default=None, help="Write gate report JSON.")
def gate_ingest_cmd(kind, path, bucket, prefix, text_field, fmt, mode, redact, write,
                    target, target_path, target_host, target_port, target_url,
                    collection, no_nlp, nlp_model, json_out) -> None:
    """Gate a data source's records through the ingest PII gate.

    Reads every record and runs the gate + boundary analyzer. By default this is
    a dry run reporting what would be blocked before embedding. ``--redact``
    masks sensitive spans in place (so the chunk survives instead of being
    blocked) and ``--write`` persists the clean/allowed chunks to a target store.
    """
    from vecshield_platform.datasources import build_datasource
    from vecshield.ingest import ChunkBoundaryAnalyzer, IngestGate
    from vecshield.ingest.adapters import guarded_ingest

    classifier = _classifier_from_options(no_nlp, nlp_model)

    target_conn = None
    spans_redacted = 0
    try:
        source = build_datasource(kind, path=path, bucket=bucket, prefix=prefix,
                                  text_field=text_field, format=fmt)
        chunks = []
        with source:
            for ds in source.describe().datasets:
                chunks.extend(source.iter_records(ds.name))
        gate = IngestGate(classifier=classifier, mode=mode)
        if redact:
            chunks, spans_redacted = gate.redact(chunks)
        if write:
            target_opts = {k: v for k, v in {
                "path": target_path, "host": target_host,
                "port": target_port, "url": target_url}.items() if v is not None}
            if target == "chroma" and target_path:
                # A write target, unlike a store being assessed, may be new:
                # the clean chunks can start a local store.
                from vecshield_platform.connectors.chroma import ChromaConnector

                target_conn = ChromaConnector(path=target_path, create=True)
            else:
                target_conn = build_connector(target, **target_opts)
            if not hasattr(target_conn, "add_chunks"):
                console.print(f"[error]--write unsupported:[/] {target} "
                              f"has no add_chunks()")
                sys.exit(1)
        result = guarded_ingest(chunks, gate=gate, connector=target_conn,
                                collection=collection,
                                boundary_analyzer=ChunkBoundaryAnalyzer(classifier=classifier))
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Gate failed:[/] {e}")
        sys.exit(1)
    finally:
        if target_conn is not None:
            close = getattr(target_conn, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001
                    pass

    rep = result.report
    console.print(
        f"\n[bold]Ingest gate[/] — {rep.total} chunks, "
        f"[bad]{len(rep.blocked_chunks)} blocked[/], "
        f"[ok]{len(rep.allowed_chunks)} allowed[/], "
        f"PII density {rep.pii_density:.1%}"
    )
    if redact:
        console.print(f"[info]{spans_redacted} sensitive span(s) redacted in place[/]")
    if write:
        target_label = collection or "(per-chunk collection)"
        console.print(f"[ok]{result.ingested} chunk(s) written to "
                      f"{target} '{target_label}'[/]")
    if result.boundary_findings:
        console.print(f"[warn]{len(result.boundary_findings)} boundary-split "
                      f"PII finding(s)[/]")
    if rep.findings or result.boundary_findings:
        table = Table(title="Blocked / boundary findings", show_lines=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Category")
        table.add_column("Finding")
        for f in sorted(rep.findings + result.boundary_findings,
                        key=lambda x: -x.severity.rank):
            style = SEV_STYLE.get(f.severity, "")
            table.add_row(f"[{style}]{f.severity.value.upper()}[/]", f.category, f.title)
        console.print(table)

    if json_out:
        out = result.to_dict()
        out["detection"] = classifier.detection_metadata()
        if redact:
            out["spans_redacted"] = spans_redacted
        with open(json_out, "w") as f:
            json.dump(out, f, indent=2)
        console.print(f"\n[muted]Gate report written to {json_out}[/]")

    if mode == "hard" and rep.blocked:
        sys.exit(2)


@cli.command(name="analyze-boundaries")
@click.option("--chunks", "chunks_path", required=True,
              help="JSONL of ordered chunks: {\"id\":..,\"text\":..,\"collection\":..}.")
@click.option("--collection", default="kb", help="Collection label for findings.")
@click.option("--zone", default=64, type=int, help="Tail/head chars joined per cut.")
@classification_options
@click.option("--json", "json_out", default=None, help="Write findings JSON.")
def analyze_boundaries_cmd(chunks_path, collection, zone, no_nlp, nlp_model, json_out) -> None:
    """Detect PII split across adjacent chunk boundaries."""
    from vecshield.ingest import ChunkBoundaryAnalyzer
    from vecshield.models import Chunk

    classifier = _classifier_from_options(no_nlp, nlp_model)

    chunks = []
    try:
        with open(chunks_path) as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                chunks.append(Chunk(id=str(obj.get("id", i)),
                                    collection=obj.get("collection", collection),
                                    text=obj.get("text", "")))
        analyzer = ChunkBoundaryAnalyzer(classifier=classifier, zone_chars=zone)
        findings = analyzer.analyze(chunks)
    except Exception as e:  # noqa: BLE001
        console.print(f"[error]Boundary analysis failed:[/] {e}")
        sys.exit(1)

    console.print(f"\n[bold]Boundary analysis[/] — {len(chunks)} chunks, "
                  f"[warn]{len(findings)} straddling-PII finding(s)[/]")
    if findings:
        table = Table(title="Boundary findings", show_lines=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Between")
        table.add_column("Finding")
        for f in findings:
            style = SEV_STYLE.get(f.severity, "")
            between = (f"{f.evidence.get('left_chunk')} {glyph('arrow')} "
                       f"{f.evidence.get('right_chunk')}")
            table.add_row(f"[{style}]{f.severity.value.upper()}[/]", between, f.title)
        console.print(table)

    if json_out:
        with open(json_out, "w") as f:
            json.dump([fd.to_dict() for fd in findings], f, indent=2)
        console.print(f"\n[muted]Findings written to {json_out}[/]")
    if findings:
        sys.exit(2)


@cli.command(name="schedule")
@classification_options
@click.option("--config", "config_path", required=True,
              help="VecShield admin config JSON with registered stores.")
@click.option("--state-dir", "state_dir", default=None,
              envvar="VECSHIELD_STATE_DIR",
              help="Directory for scan history. When omitted, legacy path beside "
                   "--config is used.")
@click.option("--interval", default=86400, type=int,
              help="Seconds between audit runs (default: daily).")
@click.option("--once", is_flag=True,
              help="Run a single audit pass and exit (for cron/Kubernetes CronJob).")
@click.option("--tenant-field", default=None, help="Tenant field for isolation probes.")
def schedule_cmd(config_path, state_dir, interval, once, tenant_field, no_nlp, nlp_model) -> None:
    """Run scheduled full audits of every registered store.

    Designed to run self-hosted: as a long-lived process (`--interval`) or
    as a one-shot invoked by an external scheduler such as cron or a Kubernetes
    CronJob (`--once`). Results are persisted to local scan history; nothing
    leaves your environment.
    """
    import time

    from vecshield_platform.api.config_store import ConfigStore
    from vecshield_platform.api.state import resolve_state_paths
    from vecshield_platform.assessment_settings import (apply_settings_scope,
                                                          resolve_audit_settings,
                                                          supported_audit_kwargs)
    from vecshield_platform.history import ScanHistory
    from vecshield_platform.orchestrator import run_full_audit
    from vecshield_platform.runtime import build_sinks

    classifier = _classifier_from_options(no_nlp, nlp_model)
    config = ConfigStore(path=config_path)
    paths = resolve_state_paths(config_path, state_dir)
    hist = ScanHistory(paths.history_db)

    alerting = config.get_alerting()
    sinks = build_sinks(alerting) if alerting.enabled else []
    alert_min = Severity(alerting.min_severity)
    if sinks:
        console.print(f"[muted]Alerting on: {len(sinks)} sink(s), "
                      f"min severity {alert_min.value.upper()}[/]")

    def _run_once() -> None:
        registry = config.build_registry()
        stores = registry.list()
        console.print(f"[bold]Scheduled audit[/] — {len(stores)} store(s)")
        for s in stores:
            conn = None
            try:
                settings = resolve_audit_settings(
                    config, s, tenant_field=tenant_field,
                    state_dir=_feed_state_dir(config_path, state_dir))
                conn = registry.open(s.store_id)
                result = run_full_audit(conn, tenant_field=settings.tenant_field,
                                        classifier=classifier,
                                        policies=settings.policies,
                                        suppressor=settings.suppress,
                                        sinks=sinks, alert_min_severity=alert_min,
                                        **supported_audit_kwargs(run_full_audit,
                                                                 settings.audit_kwargs,
                                                                 settings.scope))
                apply_settings_scope(result.scope, settings.scope)
                hist.save_audit(result, store_id=s.store_id)
                extra = (f", {result.alerts_dispatched} alert(s) sent"
                         if result.alerts_dispatched else "")
                console.print(
                    f"  {s.store_id}: {len(result.all_findings())} findings, "
                    f"max {result.max_severity.value.upper()}{extra}"
                )
            except Exception as e:  # noqa: BLE001
                console.print(f"  [bad]{s.store_id}: audit failed:[/] {e}")
            finally:
                if conn is not None:
                    conn.close()

    try:
        _run_once()
        if once:
            return
        while True:
            console.print(f"[muted]Sleeping {interval}s until next audit…[/]")
            time.sleep(interval)
            _run_once()
    finally:
        hist.close()


# `posture` is the name used throughout the docs; keep it as an alias for the
# canonical `posture-check` command so documented invocations work.
@cli.group(name="benchmark")
def benchmark_group() -> None:
    """Measure the detectors against a labelled corpus."""


@benchmark_group.command(name="run")
@click.option("--corpus", "corpus_path", default="benchmark/corpus",
              type=click.Path(exists=True, file_okay=False),
              help="Directory of labelled corpus files.")
@click.option("--out", "out_path", default=None, type=click.Path(),
              help="Write the full result as JSON here.")
@click.option("--quiet", is_flag=True, help="Write the file without printing the report.")
def benchmark_run_cmd(corpus_path, out_path, quiet) -> None:
    """Score the detectors and report the failures alongside the successes."""
    from vecshield_platform.benchmark import (
        format_report, load_corpus, load_manifest, run)

    root = Path(corpus_path)
    results = run(load_corpus(root))
    if out_path:
        Path(out_path).write_text(json.dumps(results, indent=2))
        console.print(f"[ok]Wrote[/] {out_path}")
    if not quiet:
        console.print(format_report(results, manifest=load_manifest(root)),
                      markup=False, highlight=False, soft_wrap=True)


@benchmark_group.command(name="calibrate")
@click.option("--corpus", "corpus_path", default="benchmark/corpus",
              type=click.Path(exists=True, file_okay=False))
@click.option("--out", "out_path", default="benchmark/calibration.json",
              type=click.Path())
@click.option("--check", is_flag=True,
              help="Verify the committed file rather than rewriting it. Fails if it "
                   "claims a stronger class than the corpus supports.")
def benchmark_calibrate_cmd(corpus_path, out_path, check) -> None:
    """Record which confidence class each detector has earned.

    A class is earned from the lower bound of a measured precision. A detector
    that has earned nothing reports 'uncertain', which is the honest default
    rather than a failure.
    """
    from vecshield_platform.benchmark import calibration, load_corpus, run
    from vecshield_platform.explain import CONFIDENCE_CLASSES

    result = calibration(run(load_corpus(Path(corpus_path))))
    if check:
        # The only thing that can put a confidence claim into the product is a
        # measurement. Editing the file by hand has to fail here, or the class
        # means nothing.
        try:
            committed = json.loads(Path(out_path).read_text()).get("detectors") or {}
        except (OSError, ValueError) as exc:
            raise SystemExit(f"cannot read {out_path}: {exc}") from exc
        overclaimed = []
        for detector, entry in sorted(committed.items()):
            claimed = entry.get("class", "uncertain")
            earned = result["detectors"].get(detector, {}).get("class", "uncertain")
            if claimed not in CONFIDENCE_CLASSES:
                overclaimed.append(f"{detector}: unknown class {claimed!r}")
            elif CONFIDENCE_CLASSES.index(claimed) < CONFIDENCE_CLASSES.index(earned):
                overclaimed.append(
                    f"{detector}: file claims '{claimed}', corpus supports '{earned}'")
        if overclaimed:
            console.print("[bad]Calibration claims more than the corpus supports:[/]")
            for line in overclaimed:
                console.print(f"  {line}")
            raise SystemExit(1)
        console.print(f"[ok]{out_path} matches the corpus.[/] "
                      f"{len(committed)} detector(s) checked.")
        return
    Path(out_path).write_text(json.dumps(result, indent=2))
    earned = {d: e["class"] for d, e in result["detectors"].items()}
    claimed = {d: c for d, c in earned.items() if c != "uncertain"}
    console.print(f"[ok]Wrote[/] {out_path}")
    console.print(f"{len(claimed)} of {len(earned)} detectors earned a confidence class.")
    for detector, entry in sorted(result["detectors"].items()):
        colour = "green" if entry["class"] != "uncertain" else "yellow"
        console.print(f"  [{colour}]{entry['class']:10}[/] {detector} — {entry['reason']}")


@benchmark_group.command(name="compare")
@click.option("--baseline", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--candidate", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--tolerance", default=0.0, type=float,
              help="Permitted drop in a rate before it counts as a regression.")
def benchmark_compare_cmd(baseline, candidate, tolerance) -> None:
    """Fail when a detector got worse, or stopped being measured at all."""
    from vecshield_platform.benchmark import compare

    report = compare(json.loads(Path(baseline).read_text()),
                     json.loads(Path(candidate).read_text()), tolerance=tolerance)
    for item in report["improvements"]:
        console.print(f"[ok]improved[/] {item['group']} {item['metric']} "
                      f"+{item['delta']}")
    for item in report["regressions"]:
        detail = item.get("detail") or f"{item.get('before')} -> {item.get('after')}"
        console.print(f"[bad]regression[/] {item['group']} {item['metric']}: {detail}")
    if not report["ok"]:
        raise SystemExit(1)
    console.print("[ok]No regressions.[/]")


cli.add_command(posture_cmd, name="posture")
from vecshield_platform.nlp_cli import nlp as nlp_group  # noqa: E402
cli.add_command(nlp_group)


# --------------------------------------------------------------------------- #
# Staged actions                                                              #
# --------------------------------------------------------------------------- #

@cli.group(name="actions")
def actions_group() -> None:
    """Suggest and stage changes to a vector store. Nothing here executes."""


@actions_group.command(name="suggest")
@connector_options
@click.option("--findings", "findings_path", required=True,
              type=click.Path(exists=True, dir_okay=False),
              help="Findings JSON from `scan --json`.")
@click.option("--store", "store_id", default=None,
              help="Store id to attribute the suggestions to. Defaults to the "
                   "store recorded on the findings.")
@click.option("--out", "out_path", default=None, type=click.Path(),
              help="Write the suggestions JSON here, ready for `actions stage`.")
@click.option("--include-disputed", is_flag=True,
              help="Also propose actions on chunks whose every match is disputed as "
                   "not a live value (published examples, test keys, placeholders, "
                   "reserved domains). Off by default.")
def actions_suggest_cmd(findings_path, store_id, out_path, include_disputed, **conn) -> None:
    """Propose actions for findings, and report the ones refused.

    The refusals are printed alongside the proposals. A delete withheld for
    want of a measured detector is the most useful line in the output.
    """
    from vecshield_platform.actions import suggest_all

    conn.pop("kind", None)
    document = json.loads(Path(findings_path).read_text())
    records = document.get("findings", document) if isinstance(document, dict) else document
    if store_id:
        records = [{**f, "store": store_id} for f in records]
    suggestions, withheld = suggest_all(records, include_disputed=include_disputed)

    console.print(f"[bold]{len(suggestions)} suggestion(s)[/] from {len(records)} finding(s)."
                  + (" Disputed chunks included at your request." if include_disputed else ""))
    for suggestion in suggestions:
        item = suggestion.to_dict()
        mark = "green" if item["calibrated"] else "yellow"
        console.print(f"  [{mark}]{item['action']:22}[/] {item['title']}")
        console.print(f"    {escape(item['collection'] or '(store scope)')} · "
                      f"{len(item['chunk_ids'])} chunk id(s) · "
                      f"{'reversible' if item['reversible'] else 'IRREVERSIBLE'}")
        console.print(f"    [muted]{escape(item['rationale'])}[/]")
        for held in item.get("excluded") or []:
            console.print(f"    [muted]held back {escape(held['chunk_id'])}: "
                          f"{escape(held['reason'])}[/]")
    if withheld:
        console.print(f"\n[bold]{len(withheld)} withheld[/], with reasons:")
        for refusal in withheld:
            console.print(f"  [muted]{refusal.action:22}[/] " + escape(refusal.reason))
    if out_path:
        Path(out_path).write_text(json.dumps(
            {"suggestions": [s.to_dict() for s in suggestions],
             "withheld": [w.to_dict() for w in withheld]}, indent=2))
        console.print(f"\n[ok]Wrote[/] {out_path}")


@actions_group.command(name="stage")
@connector_options
@click.option("--suggestions", "suggestions_path", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("--store", "store_id", required=True)
@click.option("--staged-by", required=True, help="Who is staging this plan.")
@click.option("--note", default="", help="Why this plan is being staged.")
@click.option("--out", "out_path", default=None, type=click.Path())
def actions_stage_cmd(suggestions_path, store_id, staged_by, note, out_path, **conn) -> None:
    """Freeze suggestions into a plan resolved against the store as it is now."""
    from vecshield_platform.actions import ActionError, Suggestion, diff, format_diff, stage

    connector = _connector_from_opts(conn)
    document = json.loads(Path(suggestions_path).read_text())
    chosen = document.get("suggestions", document)
    try:
        suggestions = [Suggestion(
            id=item["id"], action=item["action"], finding_id=item["finding_id"],
            store=store_id, collection=item.get("collection"),
            chunk_ids=tuple(item.get("chunk_ids") or ()),
            rests_on=tuple(item.get("rests_on") or ()),
            calibrated=bool(item.get("calibrated")), rationale=item.get("rationale", ""),
            observed_chunks=int(item.get("observed_chunks") or 0),
            named_chunks=int(item.get("named_chunks") or 0),
            excluded=tuple((str(e.get("chunk_id")), str(e.get("reason")))
                           for e in item.get("excluded") or () if isinstance(e, dict)),
        ) for item in chosen]
        plan = stage(suggestions, connector=connector, store=store_id,
                     staged_by=staged_by, note=note)
    except (ActionError, KeyError) as exc:
        console.print(f"[error]Cannot stage:[/] {exc}")
        raise SystemExit(1) from exc

    report = diff(plan)
    # Plain text carrying store content: a chunk preview containing square
    # brackets would otherwise be read as Rich markup and silently disappear
    # from the diff a reviewer is relying on.
    console.print(format_diff(report), markup=False)
    if out_path:
        Path(out_path).write_text(json.dumps(plan.to_dict(), indent=2))
        console.print(f"[ok]Wrote[/] {out_path}")


@actions_group.command(name="diff")
@click.option("--plan", "plan_path", required=True,
              type=click.Path(exists=True, dir_okay=False))
def actions_diff_cmd(plan_path) -> None:
    """Re-read a staged plan and print its diff.

    Verifies the stored body still hashes to what was recorded. A plan edited
    after staging is refused rather than rendered.
    """
    from vecshield_platform.actions import EXECUTION_NOTE, verify_body, warnings_for

    body = json.loads(Path(plan_path).read_text())
    if not verify_body(body):
        console.print("[error]This plan does not match its own hash.[/] "
                      "It was altered after staging and cannot be reviewed. Re-stage it.")
        raise SystemExit(1)
    console.print(f"Plan {body['id']}  ({body['plan_hash'][:12]})", markup=False)
    for warning in warnings_for(body):
        console.print("  [warn]![/] " + escape(warning))
    console.print(f"\n[muted]{EXECUTION_NOTE}[/]")


@actions_group.command(name="approve")
@click.option("--plan", "plan_path", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("--approver", required=True, help="Who is authorizing this.")
@click.option("--reason", required=True, help="Why it is being authorized.")
@click.option("--type-store-id", "typed_store_id", default="",
              help="Required to confirm an irreversible operation.")
@click.option("--out", "out_path", default=None, type=click.Path())
def actions_approve_cmd(plan_path, approver, reason, typed_store_id, out_path) -> None:
    """Authorize one exact plan. The approver may not be the stager."""
    from vecshield_platform.execution import ApprovalError, approve

    body = json.loads(Path(plan_path).read_text())
    try:
        approval = approve(body, approver=approver, reason=reason,
                           typed_store_id=typed_store_id)
    except ApprovalError as exc:
        console.print("[error]Not approved:[/] " + escape(str(exc)))
        raise SystemExit(1) from exc
    console.print(f"[ok]Approved[/] {approval.id} for plan {approval.plan_id}")
    console.print(f"  scoped to hash {approval.plan_hash[:12]}, "
                  f"covering {', '.join(approval.operations)}")
    if out_path:
        Path(out_path).write_text(json.dumps(approval.to_dict(), indent=2))
        console.print(f"[ok]Wrote[/] {out_path}")


@actions_group.command(name="execute")
@connector_options
@click.option("--plan", "plan_path", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("--approval", "approval_path", required=True,
              type=click.Path(exists=True, dir_okay=False))
@click.option("--executed-by", required=True)
@click.option("--out", "out_path", default=None, type=click.Path())
def actions_execute_cmd(plan_path, approval_path, executed_by, out_path, **conn) -> None:
    """Carry out an approved plan, then read the store back.

    Blocked by safe mode unless the deployment has explicitly permitted writes.
    """
    from vecshield_platform.actions import is_stale, plan_from_body
    from vecshield_platform.execution import (Approval, ExecutionError, execute,
                                                format_execution, verify_plan)

    connector = _connector_from_opts(conn)
    body = json.loads(Path(plan_path).read_text())
    record = json.loads(Path(approval_path).read_text())
    approval = Approval(
        id=record["id"], plan_id=record["plan_id"], plan_hash=record["plan_hash"],
        approver=record["approver"], reason=record["reason"],
        approved_at=record["approved_at"],
        typed_store_id=record.get("typed_store_id", ""),
        operations=tuple(record.get("operations") or ()))
    try:
        outcome = execute(body, approval, connector=connector, executed_by=executed_by,
                          staleness=is_stale(plan_from_body(body), connector))
    except ExecutionError as exc:
        console.print("[error]Not executed:[/] " + escape(str(exc)))
        raise SystemExit(1) from exc

    verification = verify_plan(outcome, body, connector=connector)
    # Plain text carrying store content; Rich must not parse it.
    console.print(format_execution(outcome, verification), markup=False)
    if out_path:
        Path(out_path).write_text(json.dumps(
            {**outcome.to_dict(), "verification": verification.to_dict()}, indent=2))
        console.print(f"[ok]Wrote[/] {out_path}")


@actions_group.command(name="safe-mode")
def actions_safe_mode_cmd() -> None:
    """Report whether this deployment permits writes."""
    from vecshield_platform.execution import (EXECUTABLE_ACTIONS, SAFE_MODE_ENV,
                                                safe_mode)

    if safe_mode():
        console.print(f"[warn]Safe mode is on.[/] Nothing writes to a store. "
                      f"Set {SAFE_MODE_ENV}=0 to permit execution.")
    else:
        console.print(f"[bad]Safe mode is off.[/] {SAFE_MODE_ENV} permits writes.")
    console.print(f"Executable in this build: {', '.join(EXECUTABLE_ACTIONS)}")


@cli.command(name="crypto-gate")
@click.option("--config", "config_path", required=True,
              help="VecShield admin config JSON with registered stores.")
@click.option("--state-dir", "state_dir", default=None,
              envvar="VECSHIELD_STATE_DIR",
              help="Directory for scan history. When omitted, legacy path beside "
                   "--config is used.")
@click.option("--store", "store_id", required=True, help="Registered store id.")
@click.option("--audit-id", "audit_id", default=None,
              help="Saved audit to decide from (default: the store's latest).")
@click.option("--requires-at-rest-encryption", is_flag=True,
              help="Your policy requires encryption at rest; ask for evidence "
                   "wherever it is not verified.")
@click.option("--fail-on-warn", is_flag=True, help="Exit 1 on a warning too.")
@click.option("--json", "json_out", default=None, help="Write the decision JSON to path.")
def crypto_gate_cmd(config_path, state_dir, store_id, audit_id,
                    requires_at_rest_encryption, fail_on_warn, json_out) -> None:
    """Decide block / request evidence / warn / pass from a saved audit.

    For a pipeline step before promoting a store. Exit codes: 0 pass (or warn),
    1 evidence needed (or warn with --fail-on-warn), 2 block. Reads history
    only; never connects to the store.
    """
    from vecshield_platform.api.state import resolve_state_paths
    from vecshield_platform.crypto.gate import accepted_pairs, evaluate_gate
    from vecshield_platform.evidence import EvidenceArtifact
    from vecshield_platform.history import ScanHistory

    hist = ScanHistory(resolve_state_paths(config_path, state_dir).history_db)
    try:
        if audit_id:
            snapshot = hist.get_audit(audit_id)
        else:
            listed = hist.list_audits(store_id=store_id, limit=1)
            snapshot = hist.get_audit(listed[0]["id"]) if listed else None
        if snapshot is None or snapshot.get("store_id") not in (None, store_id):
            console.print(f"[error]No saved audit for '{store_id}'"
                          + (f" with id '{audit_id}'" if audit_id else "") + ".[/]")
            sys.exit(2)
        artifacts = {a["id"]: EvidenceArtifact(**a).to_dict()
                     for a in hist.list_artifacts()}
        result = evaluate_gate(
            snapshot, store_id=store_id,
            accepted_evidence=accepted_pairs(hist.list_reviews(), artifacts,
                                             scope=store_id),
            settings={"requires_at_rest_encryption": requires_at_rest_encryption})
    finally:
        hist.close()

    colour = {"block": "red", "request_evidence": "yellow", "warn": "yellow",
              "pass": "green"}[result["decision"]]
    console.print(f"[bold {colour}]{result['decision'].upper()}[/] — {store_id}, "
                  f"audit {result['audit_id']}")
    for rule in result["rules"]:
        if rule["status"] == "not_triggered":
            continue
        mark = "cleared" if rule["status"] == "cleared" else rule["decision"]
        console.print(f"  [{mark}] {rule['description']}")
        for reason in rule["reasons"]:
            console.print(f"      {reason}")
    for item in result["evidence_needed"]:
        console.print(f"  evidence that would clear it: {item['requirement']} "
                      f"({item['criterion_id']})")
    if json_out:
        with open(json_out, "w") as f:
            json.dump(result, f, indent=2)
    if result["decision"] == "block":
        sys.exit(2)
    if result["decision"] == "request_evidence" or (
            fail_on_warn and result["decision"] == "warn"):
        sys.exit(1)


# --------------------------------------------------------------------------- #
# Server advisory feed, estate inventory, CCPA risk assessment                #
# --------------------------------------------------------------------------- #

_STATE_DIR_OPTION = click.option(
    "--state-dir", "state_dir", default=None, envvar="VECSHIELD_STATE_DIR",
    help="Server state directory (history, audit log, advisory feed).")


def _state_dir_or_config(config_path: str | None, state_dir: str | None) -> str:
    if not state_dir and not config_path:
        raise click.UsageError("give --state-dir (or VECSHIELD_STATE_DIR) or --config")
    return _feed_state_dir(config_path or ".", state_dir)


@cli.group(name="vulnfeed")
def vulnfeed_group() -> None:
    """The local advisory feed the server-vulnerability checks read.

    Refreshing contacts api.osv.dev, api.github.com, services.nvd.nist.gov,
    www.postgresql.org, www.cisa.gov and endoflife.date; nothing about your
    stores is sent. Tokens come from VECSHIELD_GITHUB_TOKEN / VECSHIELD_NVD_API_KEY.
    """


@vulnfeed_group.command(name="refresh")
@click.option("--config", "config_path", default=None,
              help="Admin config JSON; the feed is stored beside it when no --state-dir.")
@_STATE_DIR_OPTION
@click.option("--product", "products", multiple=True, help="Limit to a product (repeatable).")
@click.option("--timeout", default=30.0, type=float, help="Per-request timeout (s).")
def vulnfeed_refresh_cmd(config_path, state_dir, products, timeout) -> None:
    """Fetch every advisory source now and write the feed atomically."""
    from vecshield_platform.posture import vulnfeed

    argv = ["--refresh", _state_dir_or_config(config_path, state_dir),
            "--timeout", str(timeout)]
    for product in products:
        argv += ["--product", product]
    sys.exit(vulnfeed.main(argv))


@vulnfeed_group.command(name="status")
@click.option("--config", "config_path", default=None,
              help="Admin config JSON; the feed is read beside it when no --state-dir.")
@_STATE_DIR_OPTION
def vulnfeed_status_cmd(config_path, state_dir) -> None:
    """Which feed copy audits use (state or bundled seed) and how old it is."""
    from vecshield_platform.posture import vulnfeed

    sys.exit(vulnfeed.main(["--status", _state_dir_or_config(config_path, state_dir)]))


def _cli_latest_inventory(hist, store_id: str, declarations: dict | None):
    from vecshield_platform.drift import inventory_of

    for row in hist.list_audits(store_id=store_id, limit=20):
        snapshot = hist.get_audit(row["id"])
        if inventory_of(snapshot) is not None:
            return _cli_latest_inventory_of(snapshot, store_id, declarations)
    return None


@cli.group(name="inventory")
def inventory_group() -> None:
    """Vector-store and personal-data inventory, from saved audits."""


@inventory_group.command(name="export")
@click.option("--config", "config_path", required=True,
              help="VecShield admin config JSON with registered stores.")
@_STATE_DIR_OPTION
@click.option("--format", "fmt", type=click.Choice(["csv", "json"]), default="json")
@click.option("--out", "out_path", required=True, type=click.Path(dir_okay=False),
              help="File to write.")
def inventory_export_cmd(config_path, state_dir, fmt, out_path) -> None:
    """Export every registered store's latest inventory (never connects to a store)."""
    from vecshield_platform.api.config_store import ConfigStore
    from vecshield_platform.api.state import resolve_state_paths
    from vecshield_platform.history import ScanHistory
    from vecshield_platform.inventory import inventory_to_csv, inventory_to_json

    config = ConfigStore(path=config_path)
    hist = ScanHistory(resolve_state_paths(config_path, state_dir).history_db)
    inventories, missing = [], []
    try:
        for store_id in sorted(config.stores):
            inventory = _cli_latest_inventory(hist, store_id,
                                              config.get_inventory_declarations(store_id))
            if inventory is None:
                missing.append(store_id)
            else:
                inventories.append(inventory)
    finally:
        hist.close()
    if fmt == "csv":
        content = inventory_to_csv(inventories)
    else:
        document = json.loads(inventory_to_json(inventories))
        document["stores_without_inventory"] = [
            {"store_id": sid, "reason": "no saved audit carries an inventory"}
            for sid in missing]
        content = json.dumps(document, indent=2, sort_keys=True)
    Path(out_path).write_text(content, encoding="utf-8")
    console.print(f"[ok]Wrote[/] {escape(out_path)}: {len(inventories)} store(s)"
                  + (f"; [warn]{len(missing)} without an inventory: "
                     f"{escape(', '.join(missing))}[/]" if missing else ""))


@cli.command(name="ccpa-risk")
@click.option("--config", "config_path", required=True,
              help="VecShield admin config JSON (saved business inputs live here).")
@_STATE_DIR_OPTION
@click.option("--store", "store_id", required=True, help="Registered store id.")
@click.option("--audit", "audit_id", default=None,
              help="Saved audit to prefill from (default: the store's latest).")
@click.option("--inputs", "inputs_path", default=None,
              type=click.Path(exists=True, dir_okay=False),
              help="JSON business inputs; default: the latest version saved in the console.")
@click.option("--html", "html_out", default=None, type=click.Path(dir_okay=False),
              help="Write the workbook as HTML here.")
@click.option("--json", "json_out", default=None, type=click.Path(dir_okay=False),
              help="Write the workbook JSON here (default: print it).")
def ccpa_risk_cmd(config_path, state_dir, store_id, audit_id, inputs_path,
                  html_out, json_out) -> None:
    """CCPA risk-assessment workbook (11 CCR §§ 7150-7157) from a saved audit.

    Prefills what the audit observed and marks what the business must supply;
    it never concludes that an assessment is or is not required.
    """
    from vecshield_platform.api.config_store import ConfigStore
    from vecshield_platform.api.state import resolve_state_paths
    from vecshield_platform.compliance.ccpa_risk import (build_ccpa_risk_html,
                                                           prefill_ccpa_risk_assessment,
                                                           validate_business_inputs)
    from vecshield_platform.history import ScanHistory

    config = ConfigStore(path=config_path)
    if inputs_path:
        raw = _load_json_file(inputs_path, "--inputs")
        if isinstance(raw, dict) and "review_and_approval" in raw:
            _fail_problems("--inputs", ["review_and_approval is recorded by an approval, "
                                        "not in the inputs file"])
        inputs, problems = validate_business_inputs(raw)
        _fail_problems("--inputs", problems)
        approval = None
    else:
        record = config.ccpa_record(store_id)
        latest = record["versions"][-1] if record["versions"] else None
        inputs = dict((latest or {}).get("inputs") or {})
        approval = next((a for a in reversed(record["approvals"])
                         if latest and a["version"] == latest["version"]), None)
        if approval is not None:
            approver = {"name": approval["approved_by"]}
            if approval.get("position"):
                approver["position"] = approval["position"]
            inputs["review_and_approval"] = {"date": approval["approved_at"][:10],
                                             "approvers": [approver]}
    hist = ScanHistory(resolve_state_paths(config_path, state_dir).history_db)
    try:
        if audit_id:
            snapshot = hist.get_audit(audit_id)
        else:
            listed = hist.list_audits(store_id=store_id, limit=1)
            snapshot = hist.get_audit(listed[0]["id"]) if listed else None
        if snapshot is None or snapshot.get("store_id") not in (None, store_id):
            raise click.ClickException(f"no saved audit for '{store_id}'"
                                       + (f" with id '{audit_id}'" if audit_id else ""))
        inventory = _cli_latest_inventory_of(snapshot, store_id,
                                             config.get_inventory_declarations(store_id))
    finally:
        hist.close()
    assessment = prefill_ccpa_risk_assessment(snapshot, inventory=inventory,
                                              business_inputs=inputs, store=store_id)
    if html_out:
        Path(html_out).write_text(build_ccpa_risk_html(assessment), encoding="utf-8")
        console.print(f"[ok]Wrote[/] {escape(html_out)}")
    payload = json.dumps(assessment.to_dict(), indent=2, default=str)
    if json_out:
        Path(json_out).write_text(payload, encoding="utf-8")
        console.print(f"[ok]Wrote[/] {escape(json_out)}")
    elif not html_out:
        click.echo(payload)
    err_console.print(f"[muted]{escape(assessment.completeness['summary'])}[/]")


def _cli_latest_inventory_of(snapshot: dict, store_id: str, declarations: dict | None):
    from vecshield_platform.api.config_store import merge_declarations
    from vecshield_platform.drift import inventory_of

    inventory = inventory_of(snapshot)
    if inventory is None:
        return None
    inventory = dict(inventory)
    inventory["store"] = {**(inventory.get("store") or {})}
    if not inventory["store"].get("id"):
        inventory["store"]["id"] = store_id
    return merge_declarations(inventory, declarations)


if __name__ == "__main__":
    cli()
