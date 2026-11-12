"""The authentication posture check: what it asserts, and what it refuses to."""

import pytest
from vecshield.models import Severity, VectorStore

from vecshield_platform.posture import (
    authentication_status,
    check_authentication,
    run_posture_audit,
)
from vecshield_platform.posture.authentication import probe_anonymous_access


def _store(kind, endpoint, name="s", metadata=None):
    return VectorStore(kind=kind, name=name, endpoint=endpoint, metadata=metadata or {})


def _prober(**overrides):
    base = {"probed": True, "anonymous": None, "reach": "none", "path": None,
            "status": None, "reason": "no answer"}
    base.update(overrides)
    return lambda endpoint, **kwargs: base


# --- the configuration verdict, with no network at all ----------------------

@pytest.mark.parametrize("endpoint,kind,mode,authenticated", [
    ("file:///srv/chroma", "chroma", "not_applicable", None),
    ("/srv/chroma", "chroma", "not_applicable", None),
    ("https://x.svc.pinecone.io", "pinecone", "provider_credential", True),
    ("postgresql://user:pw@db:5432/app", "pgvector", "connection_credential", True),
    ("redis://:secret@cache:6379", "redis", "connection_credential", True),
    ("http://localhost:6333", "qdrant", "undetermined", None),
    ("http://opensearch:9200", "opensearch", "undetermined", None),
])
def test_configuration_verdict(endpoint, kind, mode, authenticated):
    status = authentication_status(endpoint, kind=kind)
    assert status["mode"] == mode
    assert status["authenticated"] is authenticated
    assert status["reason"]


@pytest.mark.parametrize("metadata", [
    {"credential_configured": True, "credential_sources": ["dsn_password"]},
    {"credential_configured": True, "credential_sources": ["password_file"]},
])
def test_keyword_dsn_with_a_configured_credential_is_recognised(metadata):
    """A keyword DSN has no user:password@ to see; the connector lists its sources."""
    status = authentication_status("host=db dbname=app user=app password=***",
                                   kind="pgvector", metadata=metadata)
    assert status["mode"] == "connection_credential" and status["authenticated"] is True
    assert metadata["credential_sources"][0] in status["reason"]
    assert check_authentication(_store("pgvector", "host=db dbname=app", metadata=metadata),
                                probe=False) == []


def test_observed_server_authentication_beats_configuration():
    session = {"observed": True, "authenticated": True, "auth_method": "scram-sha-256",
               "source": "system_user",
               "reason": "the server authenticated this session with scram-sha-256"}
    status = authentication_status("host=db dbname=app", kind="pgvector",
                                   session_auth=session)
    assert status == {"authenticated": True, "mode": "server_authenticated",
                      "auth_method": "scram-sha-256", "source": "system_user",
                      "reason": session["reason"]}
    assert check_authentication(_store("pgvector", "host=db dbname=app"),
                                session_auth=session) == []


@pytest.mark.parametrize("exposure,severity", [("public", Severity.CRITICAL),
                                                ("private", Severity.HIGH)])
def test_a_session_the_server_never_authenticated_is_a_finding(exposure, severity):
    """system_user is NULL under trust: configured credentials don't matter."""
    session = {"observed": True, "authenticated": False, "auth_method": None,
               "source": "system_user", "reason": "system_user is NULL for this session"}
    store = _store("pgvector", "postgresql://app:***@db/app",
                   metadata={"credential_configured": True})
    findings = check_authentication(store, session_auth=session, exposure=exposure)
    assert len(findings) == 1
    assert findings[0].severity == severity
    assert findings[0].evidence["mode"] == "server_admitted_unauthenticated"
    assert "pg_hba.conf" in findings[0].remediation


def test_an_unobserved_session_falls_back_to_configuration():
    session = {"observed": False, "authenticated": None, "auth_method": None,
               "source": "system_user", "reason": "system_user needs PostgreSQL 16 or later"}
    status = authentication_status("host=db dbname=app", kind="pgvector",
                                   session_auth=session)
    assert status["mode"] == "undetermined"


def test_configured_api_key_is_recognised():
    status = authentication_status("http://qdrant:6333", kind="qdrant",
                                   metadata={"api_key_configured": True})
    assert status["authenticated"] is True


# --- findings ----------------------------------------------------------------

def test_filesystem_store_raises_nothing():
    assert check_authentication(_store("chroma", "file:///srv/chroma")) == []


def test_anonymous_data_access_on_a_public_endpoint_is_critical():
    prober = _prober(anonymous=True, reach="data", path="/collections", status=200,
                     reason="an unauthenticated GET /collections returned 200")
    findings = check_authentication(_store("qdrant", "http://5.6.7.8:6333"),
                                    prober=prober, exposure="public")
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].category == "authentication"
    assert "public internet" in findings[0].description
    assert findings[0].evidence["probe"]["reach"] == "data"


def test_anonymous_data_access_behind_a_private_endpoint_is_still_high():
    prober = _prober(anonymous=True, reach="data", path="/collections", status=200,
                     reason="anonymous read succeeded")
    findings = check_authentication(_store("qdrant", "http://10.0.0.5:6333"),
                                    prober=prober, exposure="private")
    assert findings[0].severity is Severity.HIGH
    assert "inside the network perimeter" in findings[0].description


def test_a_configured_key_the_server_ignores_is_called_out():
    """The case a config-only check cannot see: key set, server not enforcing."""
    prober = _prober(anonymous=True, reach="data", path="/collections", status=200,
                     reason="anonymous read succeeded")
    findings = check_authentication(
        _store("qdrant", "http://q:6333", metadata={"api_key_configured": True}),
        prober=prober, exposure="private")
    assert "not enforcing the one it was given" in findings[0].description


def test_refusal_produces_no_finding():
    prober = _prober(anonymous=False, reach="denied", reason="refused")
    assert check_authentication(_store("qdrant", "http://q:6333"), prober=prober) == []


def test_undetermined_is_reported_as_undetermined_not_as_clean():
    findings = check_authentication(_store("qdrant", "http://q:6333"),
                                    prober=_prober())
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "evidence the check could not establish that it is closed" \
        in findings[0].description


def test_a_liveness_endpoint_answering_is_not_treated_as_data_access():
    prober = _prober(anonymous=None, reach="liveness",
                     reason="a liveness endpoint answered anonymously")
    findings = check_authentication(_store("qdrant", "http://q:6333"), prober=prober)
    assert findings[0].severity is Severity.MEDIUM  # unverified, not open


def test_probe_is_skipped_when_asked():
    findings = check_authentication(_store("qdrant", "http://q:6333"), probe=False)
    assert findings[0].evidence["probe"]["probed"] is False


def test_no_probe_is_defined_for_non_http_kinds():
    result = probe_anonymous_access("postgresql://db:5432", kind="pgvector")
    assert result["probed"] is False
    assert result["anonymous"] is None


# --- engine wiring -----------------------------------------------------------

class _Conn:
    kind = "chroma"

    def describe(self):
        return _store("chroma", "file:///srv/demo", name="demo")


class _PgConn:
    kind = "pgvector"

    def __init__(self, session):
        self.session = session

    def capabilities(self):
        return {"session_auth_introspection"}

    def describe(self):
        return _store("pgvector", "host=10.0.0.7 dbname=app user=app", name="pg")

    def session_auth_info(self):
        if isinstance(self.session, Exception):
            raise self.session
        return self.session


def test_posture_audit_uses_the_observed_session_authentication():
    job = run_posture_audit(_PgConn({"observed": True, "authenticated": True,
                                     "auth_method": "scram-sha-256", "source": "system_user",
                                     "reason": "authenticated with scram-sha-256"}),
                            resolve_dns=False, include_cve=False)
    auth = next(o for o in job.stats["check_outcomes"] if o["check"] == "authentication")
    assert auth["outcome"] == "passed" and auth["coverage"]["complete"] is True
    assert auth["coverage"]["auth_method"] == "scram-sha-256"
    assert auth["coverage"]["auth_mode"] == "server_authenticated"
    exposure = next(o for o in job.stats["check_outcomes"]
                    if o["check"] == "network_exposure")
    assert exposure["outcome"] != "inconclusive"


def test_a_failing_session_read_leaves_authentication_unverified():
    job = run_posture_audit(_PgConn(RuntimeError("boom")), resolve_dns=False,
                            include_cve=False)
    auth = next(o for o in job.stats["check_outcomes"] if o["check"] == "authentication")
    assert auth["outcome"] == "inconclusive"


def test_posture_audit_records_an_outcome_for_every_check():
    job = run_posture_audit(_Conn(), resolve_dns=False, include_cve=False)
    checks = {o["check"] for o in job.stats["check_outcomes"]}
    assert checks == {"network_exposure", "transport_encryption", "authentication", "cve",
                      "transport_tls_enforcement", "at_rest_encryption",
                      "field_encryption", "query_result_ceiling", "access_grants"}
    assert "authentication" in job.stats["checks"]
    # A filesystem store has no transport, so enforcement is not applicable
    # rather than an unrequested opt-in probe, and counts. Chroma cannot report
    # encryption at rest or field encryption at all: those are capability
    # limits of the product, recorded but not expected of the run, and so is
    # access_grants: the fake reports no roles or grants.
    # Six, not five: the result-ceiling check reads connector metadata and so
    # runs on every store, including a file-backed one with no transport.
    assert job.stats["coverage"]["checks_expected"] == 6
    assert job.stats["coverage"]["checks_not_supported"] == 3


def test_a_store_with_nothing_to_authenticate_is_unsupported_not_passed():
    """A file-backed store has not passed this check; the check does not apply."""
    job = run_posture_audit(_Conn(), resolve_dns=False, include_cve=False)
    auth = [o for o in job.stats["check_outcomes"] if o["check"] == "authentication"][0]
    assert auth["outcome"] == "unsupported"
    assert "filesystem-backed" in auth["reason"]
    assert auth["coverage"]["complete"] is False


def test_excluding_the_auth_check_is_recorded_as_skipped_not_passed():
    job = run_posture_audit(_Conn(), resolve_dns=False, include_cve=False,
                            include_auth=False)
    auth = [o for o in job.stats["check_outcomes"] if o["check"] == "authentication"]
    assert auth[0]["outcome"] == "skipped"
    assert "authentication" not in job.stats["checks"]
