"""Posture audit engine — network, transport, authentication, CVE and crypto checks.

Produces a single ScanJob so posture findings flow through the same report,
policy, and history machinery as data-classification findings.

Each check records a structured outcome alongside its findings. A check that
could not answer — an endpoint that never responded, a store kind with no
unauthenticated probe — is reported as inconclusive rather than disappearing,
because a posture audit that silently drops a check reads as a clean one.

The crypto checks (transport_encryption, transport_tls_enforcement,
at_rest_encryption, field_encryption) record a ``crypto_state`` beside the
outcome, and access_grants an ``access_state``. What the store cannot expose
is ``not_observable`` and never fails.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from vecshield_platform.connectors.base import Connector
from vecshield_platform.coverage import check_outcome, set_job_coverage
from vecshield_platform.posture.limits import observe_result_ceiling
from vecshield.models import Finding, ScanJob, Severity, VectorStore
from vecshield_platform.crypto.states import (
    NOT_APPLICABLE,
    NOT_OBSERVABLE,
    NOT_VERIFIED,
    OBSERVED_EXPOSURE,
    TLS_ENFORCEMENT,
    TRANSPORT_ENCRYPTION,
    VERIFIED,
    crypto_outcome,
)
from vecshield_platform.posture.at_rest import (
    at_rest_check,
    field_encryption_checks,
    observe_at_rest,
)
from vecshield_platform.posture.at_rest_support import support_for
from vecshield_platform.posture.authentication import (
    authentication_status,
    check_authentication,
)
from vecshield_platform.posture.cve import scan_cves
from vecshield_platform.posture.encryption import (
    check_tls_certificate_verification,
    check_transport_encryption,
    transport_status,
)
from vecshield_platform.posture.network import check_network_exposure, classify_endpoint
from vecshield_platform.posture.tls_probe import probe_tls_enforcement

#: The contract's vocabulary for where a transport verdict came from. DSN and
#: environment settings are connector configuration too; the raw source is
#: kept alongside as ``config_source``.
_SOURCE_VOCABULARY = {"dsn": "connector_flag", "environment": "connector_flag"}


def _capabilities(connector: Any) -> set[str]:
    try:
        return set(connector.capabilities())
    except Exception:  # noqa: BLE001 - a connector that cannot say supports nothing extra
        return set()


def _session_info(connector: Any, caps: set[str]) -> tuple[Optional[dict], Optional[str]]:
    if "transport_introspection" not in caps:
        return None, None
    try:
        info = connector.transport_session_info()
    except Exception as exc:  # noqa: BLE001
        return None, type(exc).__name__
    return (info if isinstance(info, dict) else None), None


def _session_auth(connector: Any, caps: set[str]) -> Optional[dict]:
    if "session_auth_introspection" not in caps:
        return None
    try:
        info = connector.session_auth_info()
    except Exception as exc:  # noqa: BLE001 - introspection must never break a scan
        return {"observed": False, "authenticated": None, "auth_method": None,
                "source": "session_auth_info", "reason": type(exc).__name__}
    return info if isinstance(info, dict) else None


def _transport_outcome(store: VectorStore, status: dict, *, require_tls: bool,
                       session_error: Optional[str]) -> dict:
    raw_source = str(status.get("source") or "")
    details: dict[str, Any] = {
        "scheme": status.get("scheme"), "encrypted": status.get("encrypted"),
        "source": _SOURCE_VOCABULARY.get(raw_source, raw_source) or None,
        "protocol": status.get("protocol"), "cipher": status.get("cipher"),
    }
    if raw_source in _SOURCE_VOCABULARY:
        details["config_source"] = raw_source
    for key in ("sslmode", "certificate_verification"):
        if key in status:
            details[key] = status[key]
    if session_error:
        details["session_error"] = session_error
    if not require_tls:
        return check_outcome(TRANSPORT_ENCRYPTION, store.name, None, outcome="skipped",
                             reason="TLS was not required for this run.",
                             crypto_state=NOT_VERIFIED, control="VCR-01", **details)
    if status.get("encrypted") is True:
        reason = status.get("reason", "")
        if status.get("certificate_verification") is False:
            # Still encrypted, so still verified here; the missing certificate
            # check is its own finding (tls_certificate_verification).
            reason = (f"{reason} The server certificate is not verified, so the "
                      "connection is open to interception.").strip()
        return crypto_outcome(TRANSPORT_ENCRYPTION, store.name, state=VERIFIED,
                              complete=True, reason=reason, **details)
    if status.get("encrypted") is False:
        return crypto_outcome(TRANSPORT_ENCRYPTION, store.name, state=OBSERVED_EXPOSURE,
                              outcome="failed", complete=True,
                              reason=status.get("reason", ""), **details)
    if raw_source == "filesystem":
        return crypto_outcome(TRANSPORT_ENCRYPTION, store.name, state=NOT_APPLICABLE,
                              complete=True, reason=status.get("reason", ""), **details)
    return crypto_outcome(TRANSPORT_ENCRYPTION, store.name, state=NOT_VERIFIED,
                          reason="Transport encryption could not be determined from the "
                                 f"connection. {status.get('reason', '')}".strip(),
                          **details)


def _tls_enforcement(connector: Any, caps: set[str], store: VectorStore, status: dict, *,
                     tls_probe: bool, prober: Callable[..., dict],
                     timeout: float) -> tuple[dict, list[Finding]]:
    """transport_tls_enforcement: passive catalog first, then the opt-in probe."""
    name = store.name
    if status.get("source") == "filesystem":
        return crypto_outcome(TLS_ENFORCEMENT, name, state=NOT_APPLICABLE, complete=True,
                              reason="A filesystem-backed store has no network "
                                     "transport to enforce TLS on.",
                              method=None, plaintext_accepted=None), []
    if status.get("encrypted") is False and status.get("sslmode") != "allow":
        # VecShield itself is connected in plaintext; that settles it without a
        # probe. The transport_encryption finding already reports it.
        return crypto_outcome(TLS_ENFORCEMENT, name, state=OBSERVED_EXPOSURE,
                              outcome="failed", complete=True,
                              reason="The store accepted VecShield's own unencrypted "
                                     "connection.",
                              method="connection", plaintext_accepted=True), []

    passive: Optional[dict] = None
    if "tls_enforcement_introspection" in caps:
        try:
            passive = connector.tls_enforcement_info()
        except Exception as exc:  # noqa: BLE001
            passive = {"plaintext_accepted": None, "method": "catalog",
                       "reason": f"the catalog could not be read ({type(exc).__name__})"}
        if not isinstance(passive, dict):
            passive = {"plaintext_accepted": None, "method": "catalog",
                       "reason": "the connector returned no answer"}

    result: Optional[dict] = None
    if passive is not None and passive.get("plaintext_accepted") is not None:
        result = passive
    elif tls_probe:
        try:
            result = prober(store.endpoint, kind=store.kind, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            result = {"plaintext_accepted": None, "method": "active_probe",
                      "reason": f"the probe failed ({type(exc).__name__})"}

    if result is None:
        if passive is not None:
            return crypto_outcome(
                TLS_ENFORCEMENT, name, state=NOT_OBSERVABLE,
                reason=f"{passive.get('reason', 'The catalog did not settle it')}. The "
                       "opt-in plaintext probe was not requested.",
                method="catalog", plaintext_accepted=None), []
        return check_outcome(
            TLS_ENFORCEMENT, name, None, outcome="skipped",
            reason="Whether the store refuses plaintext clients needs the opt-in "
                   "TLS enforcement probe, which was not requested, and the store "
                   "exposes no catalog that answers it.",
            crypto_state=NOT_VERIFIED, control="VCR-02", opt_in=True,
            method=None, plaintext_accepted=None), []

    accepted = result.get("plaintext_accepted")
    method = result.get("method")
    reason = str(result.get("reason") or "")
    details: dict[str, Any] = {"method": method, "plaintext_accepted": accepted,
               "evidence": result.get("evidence") or {}}
    if accepted is True:
        finding = Finding(
            id=f"find-{uuid.uuid4().hex[:10]}",
            title=f"Vector store '{name}' accepts connections without TLS",
            severity=Severity.HIGH,
            category=TLS_ENFORCEMENT,
            store=name,
            description=(f"{reason}. Any client configured without TLS — or "
                         "downgraded by someone on the network path — sends its "
                         "credentials, queries and the returned text in plaintext."),
            evidence={"endpoint": store.endpoint, "method": method,
                      **(result.get("evidence") or {})},
            remediation="Configure the store to refuse unencrypted connections "
                        "(hostssl-only pg_hba rules, TLS-only listeners, no plain "
                        "HTTP port) and repeat this check.",
        )
        return crypto_outcome(TLS_ENFORCEMENT, name, state=OBSERVED_EXPOSURE,
                              outcome="failed", complete=True, reason=reason,
                              **details), [finding]
    if accepted is False:
        return crypto_outcome(TLS_ENFORCEMENT, name, state=VERIFIED, complete=True,
                              reason=reason, **details), []
    if method is None:
        return crypto_outcome(TLS_ENFORCEMENT, name, state=NOT_OBSERVABLE,
                              reason=reason, **details), []
    return crypto_outcome(TLS_ENFORCEMENT, name, state=NOT_VERIFIED, reason=reason,
                          **details), []


def run_posture_audit(
    connector: Connector,
    *,
    resolve_dns: bool = True,
    require_tls: bool = True,
    flag_managed_public: bool = False,
    include_cve: bool = True,
    cve_offline: bool = False,
    cve_timeout: float = 10.0,
    include_auth: bool = True,
    auth_probe: bool = True,
    auth_timeout: float = 3.0,
    tls_probe: bool = False,
    tls_prober: Optional[Callable[..., dict]] = None,
    tls_probe_timeout: float = 3.0,
    store_controls: bool = False,
    facts: Any = None,
    sensitive_labels_by_collection: Optional[dict[str, dict[str, int]]] = None,
    residency_policy: Optional[dict] = None,
    processor_register: Optional[list[dict]] = None,
    vuln_feed: Any = None,
    vuln_feed_dir: Optional[str] = None,
    now: Optional[datetime] = None,
) -> ScanJob:
    """Run all configuration checks against one store.

    ``tls_probe`` opts in to the active plaintext probe for
    transport_tls_enforcement where the store has no catalog that answers it.
    The probe receives the endpoint string only, never a credential.
    ``tls_prober`` replaces it (tests).

    ``store_controls`` adds the checks that rest on the store's own facts:
    ``model_egress``, ``data_residency``, ``server_vulnerability`` and
    ``server_support_status``. ``facts`` is a
    :class:`~vecshield_platform.store_facts.GatheredFacts` the caller already
    read, so the store is asked once per assessment; without it the facts are
    read here. ``sensitive_labels_by_collection`` is the classification
    scan's ``label_counts`` per collection (egress severity);
    ``residency_policy`` the store's resolved policy; ``processor_register``
    the declared sub-processors; ``vuln_feed`` a loaded advisory feed (else
    it is loaded from ``vuln_feed_dir``, or the bundled seed).
    """
    store = connector.describe()
    caps = _capabilities(connector)
    job = ScanJob(id=f"posture-{uuid.uuid4().hex[:12]}", store=store.name)
    outcomes: list[dict] = []

    def _record(check: str, findings: list, *, complete: bool, reason: str = "",
                **coverage) -> None:
        worst = max((f.severity.rank for f in findings), default=-1)
        if not complete:
            status = "inconclusive"
        elif worst >= Severity.HIGH.rank:
            status = "failed"
        else:
            status = "passed"
        outcomes.append(check_outcome(check, store.name, None, outcome=status,
                                      reason=reason, complete=complete, **coverage))

    exposure = classify_endpoint(store.endpoint, kind=connector.kind,
                                 resolve=resolve_dns)

    net_findings = check_network_exposure(store, resolve=resolve_dns,
                                          flag_managed=flag_managed_public)
    for f in net_findings:
        job.add(f)
    _record("network_exposure", net_findings,
            complete=exposure.exposure != "unknown",
            reason=("The endpoint could not be classified, so its reachability is "
                    "unestablished." if exposure.exposure == "unknown" else ""),
            exposure=exposure.exposure)

    session, session_error = _session_info(connector, caps)
    status = transport_status(store.endpoint, kind=store.kind, metadata=store.metadata,
                              session=session)
    tls_findings = check_transport_encryption(store, require_tls=require_tls,
                                              session=session)
    for f in tls_findings:
        job.add(f)
    if require_tls:
        for f in check_tls_certificate_verification(store, status=status):
            job.add(f)
    outcomes.append(_transport_outcome(store, status, require_tls=require_tls,
                                       session_error=session_error))

    enforcement, enforcement_findings = _tls_enforcement(
        connector, caps, store, status, tls_probe=tls_probe,
        prober=tls_prober or probe_tls_enforcement, timeout=tls_probe_timeout)
    for f in enforcement_findings:
        job.add(f)
    outcomes.append(enforcement)

    collection_names = [c.name for c in (store.collections or [])]
    at_rest_supported = "at_rest_introspection" in caps
    store_obs, per_collection = observe_at_rest(
        connector, collection_names, supported=at_rest_supported)
    at_rest, at_rest_findings = at_rest_check(
        store.name, store_obs, per_collection,
        support=support_for(getattr(connector, "kind", "") or store.kind),
        capability_limit=not at_rest_supported)
    for f in at_rest_findings:
        job.add(f)
    outcomes.append(at_rest)
    outcomes.extend(field_encryption_checks(
        connector, store.name, collection_names,
        supported="field_encryption_introspection" in caps))

    auth_findings: list = []
    if include_auth:
        session_auth = _session_auth(connector, caps)
        auth_status = authentication_status(store.endpoint, kind=connector.kind,
                                            metadata=store.metadata,
                                            session_auth=session_auth)
        auth_findings = check_authentication(store, probe=auth_probe,
                                             timeout=auth_timeout,
                                             exposure=exposure.exposure,
                                             session_auth=session_auth)
        for f in auth_findings:
            job.add(f)
        if auth_status["mode"] == "not_applicable":
            # A store with no service to authenticate has not passed this check;
            # the check does not apply to it. Saying "passed" would read as
            # "a credential is required here", which is not what was found.
            outcomes.append(check_outcome(
                "authentication", store.name, None, outcome="unsupported",
                reason=auth_status["reason"], complete=False, probed=False))
        else:
            settled = not any(f.severity is Severity.MEDIUM for f in auth_findings)
            observed = {f"auth_{k}" if k != "auth_method" else k: auth_status[k]
                        for k in ("mode", "auth_method", "source") if auth_status.get(k)}
            _record("authentication", auth_findings, complete=settled,
                    reason=("Whether the store requires a credential was not "
                            "established." if not settled else auth_status["reason"]),
                    probed=auth_probe, **observed)
    else:
        outcomes.append(check_outcome("authentication", store.name, None,
                                      outcome="skipped",
                                      reason="The authentication check was excluded "
                                             "from this run."))

    # Least privilege of the retrieval role and row-security bypass, from the
    # store's own catalog (access/grants.py). Unsupported where the connector
    # cannot report roles; never a pass. Imported here: access.grants reads
    # its rules through this package.
    from vecshield_platform.access.grants import check_access_grants

    try:
        grant_findings, grant_outcome = check_access_grants(connector, store, caps)
    except Exception as exc:  # noqa: BLE001 - one check never costs the others
        grant_findings, grant_outcome = [], _control_error("access_grants", store.name, exc)
    for f in grant_findings:
        job.add(f)
    outcomes.append(grant_outcome)

    cve_findings: list = []
    if include_cve:
        cve_findings = scan_cves(kinds=[connector.kind], offline=cve_offline,
                                 timeout=cve_timeout, store_label=store.name)
        for f in cve_findings:
            job.add(f)
        # The "could not reach OSV" notice is itself a `cve` finding, so the
        # check is only complete when no package was left unqueried.
        unreachable = sorted(str((f.evidence or {}).get("package"))
                             for f in cve_findings
                             if (f.evidence or {}).get("osv_unreachable"))
        reachable = not unreachable and not any(f.category == "coverage"
                                                for f in cve_findings)
        _record("cve", [f for f in cve_findings if f.category == "cve"
                        and not (f.evidence or {}).get("osv_unreachable")],
                complete=not cve_offline and reachable,
                reason=("The vulnerability database was not consulted."
                        if cve_offline else
                        "" if reachable else
                        "The vulnerability database was unreachable for: "
                        + (", ".join(unreachable) or "one or more packages") + "."))
    else:
        outcomes.append(check_outcome("cve", store.name, None, outcome="skipped",
                                      reason="CVE scanning was excluded from this run."))

    job.stats = {
        "store_kind": connector.kind,
        "endpoint": store.endpoint,
        "checks": ["network_exposure", "transport_encryption",
                   "transport_tls_enforcement", "at_rest_encryption", "field_encryption",
                   "access_grants"]
                  + (["authentication"] if include_auth else [])
                  + (["cve"] if include_cve else []),
        "cve_findings": sum(1 for f in cve_findings if f.category == "cve"
                            and f.severity.rank >= 1),
        "tls_probe": tls_probe,
    }
    # Result ceiling. Always `passed`: it raises no finding and makes no
    # control claim, so `failed` would assert a judgement the product cannot
    # make. It is recorded so a reviewer has the number in front of them when
    # they assess whether bulk extraction is constrained.
    ceiling = observe_result_ceiling(connector, store)
    outcomes.append(check_outcome(
        "query_result_ceiling", store.name, None,
        outcome="passed", reason=ceiling.summary(), complete=True,
        **{k: v for k, v in ceiling.to_dict().items() if k != "summary"}))

    if store_controls:
        control_findings, control_outcomes = _store_control_checks(
            connector, store, facts=facts,
            sensitive_labels_by_collection=sensitive_labels_by_collection,
            residency_policy=residency_policy, processor_register=processor_register,
            vuln_feed=vuln_feed, vuln_feed_dir=vuln_feed_dir, now=now)
        for f in control_findings:
            job.add(f)
        outcomes.extend(control_outcomes)
        job.stats["checks"] = job.stats["checks"] + list(STORE_CONTROL_CHECKS)

    set_job_coverage(job, outcomes)
    job.finished_at = datetime.now(timezone.utc)
    return job


#: Checks :func:`run_posture_audit` adds with ``store_controls=True``.
STORE_CONTROL_CHECKS = ("model_egress", "data_residency", "server_vulnerability",
                        "server_support_status", "server_hardening")


def _control_error(check: str, store: str, exc: BaseException) -> dict:
    return check_outcome(check, store, None, outcome="error", complete=False,
                         reason=f"The check could not complete ({type(exc).__name__}).")


def _dedupe_advisories(findings: list[Finding]) -> list[Finding]:
    """One finding per advisory and component (finding ids are random per run)."""
    seen: set[tuple[str, str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        advisory = (f.evidence or {}).get("advisory_id")
        if advisory:
            key = (str(advisory), str((f.evidence or {}).get("component") or ""), f.store)
            if key in seen:
                continue
            seen.add(key)
        out.append(f)
    return out


def _store_control_checks(connector: Any, store: VectorStore, *, facts: Any,
                          sensitive_labels_by_collection: Optional[dict],
                          residency_policy: Optional[dict],
                          processor_register: Optional[list[dict]],
                          vuln_feed: Any, vuln_feed_dir: Optional[str],
                          now: Optional[datetime]) -> tuple[list[Finding], list[dict]]:
    """model_egress, data_residency, server_vulnerability, server_support_status,
    server_hardening.

    Each is isolated: one raising leaves the others' outcomes intact.
    """
    from vecshield_platform import store_facts
    from vecshield_platform.posture.egress import assess_model_egress
    from vecshield_platform.posture.residency import assess_residency
    from vecshield_platform.posture.server_vulns import (
        SERVER_SUPPORT_STATUS,
        SERVER_VULNERABILITY,
        run_server_vulnerability_checks,
    )

    if facts is None:
        facts = store_facts.gather(connector, ("server_info", "store_location",
                                               "model_integrations"))

    def reader(name: str) -> Optional[Callable[[], Any]]:
        return facts.reader(name) if facts.gathered(name) else None

    findings: list[Finding] = []
    outcomes: list[dict] = []

    try:
        egress_findings, egress_outcome = assess_model_egress(
            connector, store,
            sensitive_labels_by_collection=dict(sensitive_labels_by_collection or {}),
            declared_processors=processor_register,
            integrations_reader=reader("model_integrations"))
        findings.extend(egress_findings)
        outcomes.append(egress_outcome)
    except Exception as exc:  # noqa: BLE001 - one check never costs the others
        outcomes.append(_control_error("model_egress", store.name, exc))

    try:
        outcomes_before = len(outcomes)
        location, integrations = _residency_inputs(facts)
        residency_findings, residency_outcome = assess_residency(
            location, policy=residency_policy, integrations=integrations,
            subject_counts=None, store=store.name)
        findings.extend(residency_findings)
        outcomes.append(residency_outcome)
    except Exception as exc:  # noqa: BLE001
        del outcomes[outcomes_before:]
        outcomes.append(_control_error("data_residency", store.name, exc))

    try:
        feed = vuln_feed
        if feed is None:
            from vecshield_platform.posture.vulnfeed import load_feed

            feed = load_feed(vuln_feed_dir)
        vuln_findings, vuln_outcomes = run_server_vulnerability_checks(
            connector, store, feed=feed, now=now, info_reader=reader("server_info"))
        findings.extend(_dedupe_advisories(vuln_findings))
        outcomes.extend(vuln_outcomes)
    except Exception as exc:  # noqa: BLE001
        outcomes.extend(_control_error(check, store.name, exc)
                        for check in (SERVER_VULNERABILITY, SERVER_SUPPORT_STATUS))

    try:
        hardening_findings, hardening_outcome = _server_hardening(
            connector, store, reader("server_info"))
        findings.extend(hardening_findings)
        outcomes.append(hardening_outcome)
    except Exception as exc:  # noqa: BLE001
        outcomes.append(_control_error("server_hardening", store.name, exc))
    return findings, outcomes


def _server_hardening(connector: Any, store: VectorStore,
                      info_reader: Optional[Callable[[], Any]]) -> tuple[list[Finding], dict]:
    """server_hardening for a pgvector store; unsupported for every other kind."""
    from vecshield_platform import store_facts
    from vecshield_platform.posture.pg_hardening import (
        SERVER_HARDENING,
        check_server_hardening,
    )

    if getattr(connector, "kind", "") != "pgvector":
        return [], check_outcome(
            SERVER_HARDENING, store.name, None, outcome="unsupported",
            reason="VecShield has server-hardening rules for PostgreSQL (pgvector) only.",
            capability_limit=True)
    try:
        info = info_reader() if info_reader is not None else store_facts.server_info(connector)
    except Exception as exc:  # noqa: BLE001 - an unread configuration is unknown, not clean
        return check_server_hardening(store, None, info_error=(
            f"The server's configuration could not be read ({type(exc).__name__})."))
    hba = None
    if "tls_enforcement_introspection" in _capabilities(connector):
        try:
            hba = connector.tls_enforcement_info()
        except Exception:  # noqa: BLE001 - hba rules then read as not evaluated
            hba = None
    return check_server_hardening(store, info if isinstance(info, dict) else None, hba=hba)


def _residency_inputs(facts: Any) -> tuple[Optional[dict], Optional[list[dict]]]:
    """``assess_residency``'s location and integrations from gathered facts.

    An unsupported location read is ``None`` (a capability limit); a refused
    or failed one is an unobservable location with the reason, so it reads as
    inconclusive rather than as a property of the product.
    """
    location: Optional[dict] = None
    status = facts.status.get("store_location") or {}
    if status.get("state") == "observed" and isinstance(facts.get("store_location"), dict):
        location = dict(facts.get("store_location"))
    elif status.get("state") in ("denied", "error"):
        location = {"provider": None, "region": None, "observable": False,
                    "reason": status.get("reason") or "The store's location could not be read."}
    integrations: Optional[list[dict]] = None
    report = facts.get("model_integrations")
    if isinstance(report, dict) and report.get("observable") is True:
        integrations = [dict(i) for i in report.get("integrations") or []
                        if isinstance(i, dict)]
    return location, integrations
