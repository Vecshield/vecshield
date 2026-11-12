"""What can be done about one finding: a remediation catalogue per finding kind.

:mod:`actions` knows how to stage, and :mod:`execution` how to carry out and
verify, a change to a store. This module decides *which* changes fit a finding,
and it is where the product is honest about the difference between two kinds of
remediation:

* **Executable.** VecShield performs it, through a capability the connector
  declares, behind the same stage → review → approve → execute → verify path
  as every other action. These are ordinary :class:`actions.Suggestion`
  objects; nothing here is a side door around approval or safe mode.
* **Guided.** A person performs it, somewhere VecShield cannot reach: a server
  setting, a key in the store's own console, the ingestion pipeline. The
  procedure is written for the store kind with the finding's own values filled
  in (the endpoint, the key id, the tenant field), and it ends in a re-scan
  that VecShield *does* run. A guided remediation is never reported as done
  because someone said so: marking it done records the claim, and only a
  re-scan that no longer observes the finding verifies it.

Findings that name a condition rather than chunks ("412 chunks carry no
tenant_id") are answered with a *selector*: the condition itself, resolved
against the store at staging into a concrete list a reviewer approves.

Nothing here reads or writes a store except :func:`rescan`, which re-runs the
check behind a finding, read-only, the same way an assessment would.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlparse

from vecshield_platform.actions import (
    ACTION_TEMPLATES,
    ActionError,
    Suggestion,
    Withheld,
    detectors_by_chunk,
    detectors_in,
    disputes_by_chunk,
    gate_chunks,
    suggest,
)
from vecshield_platform.explain import CALIBRATED

#: Provenance keys, in the order provenance analysis reads them. Mirrored from
#: integrity.provenance so a selector finds exactly the chunks it counted.
from vecshield_platform.integrity.provenance import _SOURCE_KEYS as SOURCE_KEYS  # noqa: E402

# --------------------------------------------------------------------------- #
# Finding kinds                                                                #
# --------------------------------------------------------------------------- #

#: kind -> (label a person reads, the check family a re-scan re-runs, and the
#: check outcome within that family that says whether it saw everything)
KINDS: dict[str, tuple[str, str, str]] = {
    "sensitive_data": ("Sensitive data in stored chunks", "data_classification",
                       "data_classification"),
    "prompt_injection": ("Prompt-injection content", "rag_integrity", "prompt_injection"),
    "embedding_anomaly": ("Anomalous embeddings", "rag_integrity", "embedding_anomaly"),
    "provenance_incomplete": ("Chunks with no recorded source", "rag_integrity",
                              "provenance"),
    "provenance_rare_source": ("Chunks from rare sources", "rag_integrity", "provenance"),
    "tenant_filter_not_enforced": ("Tenant filter not enforced", "tenant_isolation",
                                   "tenant_isolation"),
    "tenant_convention_only": ("Tenant isolation by convention only", "tenant_isolation",
                               "tenant_isolation"),
    "tenant_untagged": ("Chunks with no tenant value", "tenant_isolation",
                        "tenant_isolation"),
    "isolation_not_verified": ("Tenant isolation not verified", "tenant_isolation",
                               "tenant_isolation"),
    "ann_post_filter": ("Filtered searches can come back short", "tenant_isolation",
                        "tenant_isolation"),
    "pan_readable": ("Full card numbers stored readable", "data_representation",
                     "pan_representation"),
    "protection_drift": ("Protection applied inconsistently", "data_representation",
                         "data_representation"),
    "retrieval_exposure": ("Plaintext returned by retrieval", "retrieval_exposure",
                           "retrieval_exposure"),
    "network_exposure": ("Store reachable from the public internet",
                         "configuration_posture", "network_exposure"),
    "authentication": ("Store serves data without a credential", "configuration_posture",
                       "authentication"),
    "transport_encryption": ("Connection is not encrypted", "configuration_posture",
                             "transport_encryption"),
    "transport_tls_enforcement": ("Store accepts plaintext connections",
                                  "configuration_posture", "transport_tls_enforcement"),
    "tls_certificate_verification": ("Server certificate is not verified",
                                     "configuration_posture", "transport_encryption"),
    "at_rest_encryption": ("Encryption at rest is disabled", "configuration_posture",
                           "at_rest_encryption"),
    "cve": ("Vulnerable client library", "configuration_posture", "cve"),
    "cve_scan_gap": ("Vulnerability scan could not run", "configuration_posture", "cve"),
    "api_key": ("Over-privileged or stale API key", "access_control", ""),
    "rbac_grant": ("Access grant that differs from intent", "", ""),
    "coverage_gap": ("Part of the store was not assessed", "", ""),
    "training_data": ("Sensitive data in a training source", "", ""),
    "retention_unknown": ("No retention horizon recorded", "data_classification",
                          "data_classification"),
    "retention_schedule": ("Records older than the declared retention maximum",
                           "data_classification", "retention_schedule"),
    "biometric_templates": ("Collection holds face or voice templates",
                            "data_classification", "biometric_templates"),
    "model_egress": ("Chunk text sent to an outside model provider",
                     "configuration_posture", "model_egress"),
    "data_residency": ("Data held or sent outside the residency policy",
                       "configuration_posture", "data_residency"),
    "server_vulnerability": ("Database server affected by a known advisory",
                             "configuration_posture", "server_vulnerability"),
    "server_support_status": ("Database server release line at or near end of life",
                              "configuration_posture", "server_support_status"),
    "access_grants": ("Retrieval role holds more access than reading needs",
                      "configuration_posture", "access_grants"),
    "server_hardening": ("Database server configuration weakens the store",
                         "configuration_posture", "server_hardening"),
    "corpus_duplication": ("Duplicated or clustered chunks", "rag_integrity",
                           "corpus_duplication"),
    "retrieval_hubness": ("Chunks retrieved for many unrelated queries", "rag_integrity",
                          "retrieval_hubness"),
    "ingestion_burst": ("Burst of chunks from new or rare sources", "rag_integrity",
                        "ingestion_burst"),
    "chunk_versions": ("Superseded or conflicting chunk versions", "rag_integrity",
                       "chunk_versions"),
    "no_action": ("A passing check, recorded", "", ""),
    "other": ("Finding", "", ""),
}

_TLS_CATEGORIES = ("transport_encryption", "transport_tls_enforcement",
                   "tls_certificate_verification", "at_rest_encryption",
                   "network_exposure", "authentication")

#: Finding categories that are their own remediation kind: each check names its
#: findings' category after itself (retention_schedule, biometric, egress,
#: residency, server advisories and the integrity checks).
_STORE_CONTROL_KINDS = ("retention_schedule", "biometric_templates", "model_egress",
                        "data_residency", "server_vulnerability", "server_support_status",
                        "access_grants", "server_hardening",
                        "corpus_duplication", "retrieval_hubness", "ingestion_burst",
                        "chunk_versions")


def finding_kind(finding: dict) -> str:
    """Classify a finding into the kind its remediation is keyed on."""
    category = str(finding.get("category") or "").lower()
    title = str(finding.get("title") or "").lower()
    evidence = finding.get("evidence") or {}
    if category == "data_classification":
        return "sensitive_data"
    if category == "rag_integrity":
        if "injection" in title or any(
                isinstance(e, dict) and e.get("categories")
                for e in evidence.get("examples") or []):
            return "prompt_injection"
        if "anomal" in title:
            return "embedding_anomaly"
        if "rare provenance" in title or evidence.get("rare_sources"):
            return "provenance_rare_source"
        if "provenance" in title:
            return "provenance_incomplete"
        return "other"
    if category == "isolation":
        if "not enforced" in title:
            return "tenant_filter_not_enforced"
        if "convention-only" in title or "convention only" in title:
            return "tenant_convention_only"
        if "without a tenant" in title or "untagged" in evidence:
            return "tenant_untagged"
        if "approximate index" in title:
            return "ann_post_filter"
        if str(finding.get("severity") or "").lower() == "info":
            return "no_action"
        return "other"
    if category == "coverage":
        if "tenant isolation" in title:
            return "isolation_not_verified"
        return "coverage_gap"
    if category == "pan_representation":
        return "pan_readable"
    if category == "data_representation":
        return "protection_drift"
    if category == "retrieval_exposure":
        return "retrieval_exposure"
    if category in _TLS_CATEGORIES:
        return category
    if category == "cve":
        return "cve" if evidence.get("vuln_id") else "cve_scan_gap"
    if category == "access_control":
        return "api_key" if evidence.get("key_id") else "rbac_grant"
    if category == "training_data_classification":
        return "training_data"
    if category == "retention":
        return "retention_unknown"
    if category in _STORE_CONTROL_KINDS:
        return category
    return "other"


# --------------------------------------------------------------------------- #
# Guided remediations                                                          #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Setting:
    """One concrete change a person makes: where, which key, what value."""

    where: str
    key: str
    value: str
    note: str = ""

    def to_dict(self) -> dict:
        return {"where": self.where, "key": self.key, "value": self.value,
                "note": self.note}


@dataclass(frozen=True)
class Guided:
    """A procedure a person carries out, which VecShield verifies by re-scanning.

    ``verify`` says what the re-scan checks; ``check`` is the check it re-runs.
    ``id`` is stable for a finding and procedure, so an attestation recorded
    against it can be found again.
    """

    id: str
    finding_id: str
    kind: str
    title: str
    summary: str
    steps: tuple[str, ...]
    owner: str
    risk: str = "low"
    reversible: bool = True
    undo: str = ""
    settings: tuple[Setting, ...] = ()
    verify: str = ""
    check: str = ""
    link: Optional[dict] = None
    #: Why VecShield cannot perform this itself. Said on every guided step so
    #: nobody reads a checklist as a job the product will do.
    not_executable_because: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "mode": "guided", "finding_id": self.finding_id,
            "kind": self.kind, "title": self.title, "summary": self.summary,
            "steps": list(self.steps), "owner": self.owner, "risk": self.risk,
            "reversible": self.reversible, "undo": self.undo,
            "settings": [s.to_dict() for s in self.settings],
            "verify": self.verify, "check": self.check, "link": self.link,
            "not_executable_because": self.not_executable_because,
            "rescan_supported": self.check in RESCANNABLE,
        }


@dataclass
class Catalogue:
    """Everything that could be done about one finding."""

    finding_id: str
    kind: str
    suggestions: list[Suggestion] = field(default_factory=list)
    withheld: list[Withheld] = field(default_factory=list)
    guided: list[Guided] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        label, check, _ = KINDS.get(self.kind, KINDS["other"])
        return {"finding_id": self.finding_id, "kind": self.kind, "kind_label": label,
                "check": check, "rescan_supported": check in RESCANNABLE,
                "executable": [proposal_dict(s) for s in self.suggestions],
                "withheld": [w.to_dict() for w in self.withheld],
                "guided": [g.to_dict() for g in self.guided],
                "note": self.note}


def _host_port(endpoint: Any) -> tuple[str, str]:
    raw = str(endpoint or "")
    if not raw:
        return "", ""
    parsed = urlparse(raw if "://" in raw else f"tcp://{raw}")
    return parsed.hostname or "", str(parsed.port or "")


def _sid(finding: dict, name: str) -> str:
    return f"{finding.get('id')}:{name}"


# ---- per-store settings. Only settings the store documents; where a store has
# no native switch the step says so and names the conventional alternative.

_AUTH_SETTINGS: dict[str, list[Setting]] = {
    "chroma": [
        Setting("Chroma server environment", "CHROMA_SERVER_AUTHN_PROVIDER",
                "chromadb.auth.token_authn.TokenAuthenticationServerProvider"),
        Setting("Chroma server environment", "CHROMA_SERVER_AUTHN_CREDENTIALS",
                "<a long random token from your secret store>",
                "Give the retrieving application its own token."),
    ],
    "qdrant": [
        Setting("config/production.yaml, or QDRANT__SERVICE__API_KEY", "service.api_key",
                "<a long random key from your secret store>"),
        Setting("config/production.yaml, or QDRANT__SERVICE__READ_ONLY_API_KEY",
                "service.read_only_api_key", "<a separate key for the retriever>"),
    ],
    "weaviate": [
        Setting("Weaviate environment", "AUTHENTICATION_ANONYMOUS_ACCESS_ENABLED", "false"),
        Setting("Weaviate environment", "AUTHENTICATION_APIKEY_ENABLED", "true"),
        Setting("Weaviate environment", "AUTHENTICATION_APIKEY_ALLOWED_KEYS",
                "<comma-separated keys>"),
        Setting("Weaviate environment", "AUTHENTICATION_APIKEY_USERS",
                "<one user per key, in the same order>"),
    ],
    "milvus": [
        Setting("milvus.yaml", "common.security.authorizationEnabled", "true",
                "Then change the default root password before anything else connects."),
    ],
    "opensearch": [
        Setting("opensearch.yml", "plugins.security.disabled", "false"),
    ],
    "pgvector": [
        Setting("pg_hba.conf", "METHOD on every host line", "scram-sha-256",
                "Never trust. Reload with SELECT pg_reload_conf()."),
        Setting("postgresql.conf", "password_encryption", "scram-sha-256"),
    ],
    "redis": [
        Setting("redis.conf (or ACL file)", "user default", "off",
                "Then create a named ACL user per application: ACL SETUSER <app> on "
                ">password ~<prefix>* +@read"),
        Setting("redis.conf", "protected-mode", "yes"),
    ],
    "mongodb": [
        Setting("mongod.conf", "security.authorization", "enabled"),
    ],
}

_TLS_SETTINGS: dict[str, list[Setting]] = {
    "chroma": [
        Setting("chroma run", "--host", "127.0.0.1",
                "Chroma serves plain HTTP; bind it to loopback so only the proxy reaches it."),
        Setting("reverse proxy (nginx, Envoy, a cloud load balancer)",
                "listen 443 ssl; proxy_pass", "http://127.0.0.1:<chroma port>",
                "Terminate TLS here and point every client at https://."),
    ],
    "qdrant": [
        Setting("config/production.yaml, or QDRANT__SERVICE__ENABLE_TLS",
                "service.enable_tls", "true"),
        Setting("config/production.yaml", "tls.cert / tls.key",
                "<paths to the server certificate and key>"),
    ],
    "weaviate": [
        Setting("ingress or reverse proxy in front of Weaviate", "TLS termination",
                "enabled for every listener",
                "Weaviate serves plain HTTP itself; expose only the TLS listener."),
    ],
    "milvus": [
        Setting("milvus.yaml", "common.security.tlsMode", "1",
                "1 is server-side TLS; 2 also requires client certificates."),
        Setting("milvus.yaml", "tls.serverPemPath / tls.serverKeyPath / tls.caPemPath",
                "<certificate, key and CA paths>"),
    ],
    "opensearch": [
        Setting("opensearch.yml", "plugins.security.ssl.http.enabled", "true"),
        Setting("opensearch.yml",
                "plugins.security.ssl.http.pemcert_filepath / pemkey_filepath / "
                "pemtrustedcas_filepath", "<certificate, key and CA paths>"),
    ],
    "pgvector": [
        Setting("postgresql.conf", "ssl", "on"),
        Setting("postgresql.conf", "ssl_min_protocol_version", "'TLSv1.2'"),
        Setting("pg_hba.conf", "connection type", "hostssl",
                "Replace host with hostssl, and add: hostnossl all all 0.0.0.0/0 reject"),
    ],
    "redis": [
        Setting("redis.conf", "tls-port", "6379"),
        Setting("redis.conf", "port", "0", "Turns the plaintext listener off."),
        Setting("redis.conf", "tls-cert-file / tls-key-file / tls-ca-cert-file",
                "<certificate, key and CA paths>"),
    ],
    "mongodb": [
        Setting("mongod.conf", "net.tls.mode", "requireTLS"),
        Setting("mongod.conf", "net.tls.certificateKeyFile", "<PEM with certificate and key>"),
    ],
}

_BIND_SETTINGS: dict[str, list[Setting]] = {
    "chroma": [Setting("chroma run", "--host", "127.0.0.1 or a private interface address")],
    "qdrant": [Setting("config/production.yaml, or QDRANT__SERVICE__HOST", "service.host",
                       "a private interface address, not 0.0.0.0")],
    "redis": [Setting("redis.conf", "bind", "127.0.0.1 -::1 or the private interface"),
              Setting("redis.conf", "protected-mode", "yes")],
    "mongodb": [Setting("mongod.conf", "net.bindIp", "the private interface address only")],
    "pgvector": [Setting("postgresql.conf", "listen_addresses",
                         "'localhost' or the private interface address")],
    "opensearch": [Setting("opensearch.yml", "network.host", "a private interface address")],
}

#: How each store enforces tenant separation natively, where it has a way.
_TENANCY_SETTINGS: dict[str, list[Setting]] = {
    "weaviate": [Setting("collection definition", "multiTenancyConfig.enabled", "true",
                         "Each tenant becomes a shard; a query must name its tenant.")],
    "qdrant": [Setting("payload index on the tenant field", "is_tenant", "true",
                       "Pair it with a filter on every query, derived from the caller.")],
    "milvus": [Setting("collection schema, tenant field", "is_partition_key", "true")],
    "pgvector": [Setting("SQL", "ALTER TABLE <table> ENABLE ROW LEVEL SECURITY",
                         "CREATE POLICY tenant_isolation ON <table> USING "
                         "(<tenant field> = current_setting('app.tenant_id'))",
                         "The application sets app.tenant_id per connection from the "
                         "authenticated caller.")],
    "pinecone": [Setting("index layout", "namespace", "one namespace per tenant")],
    "opensearch": [Setting("security role", "document-level security",
                           "a DLS query on the tenant field bound to the user")],
}

_MANAGED = {"pinecone", "openai", "openai_vs", "azure_search", "bedrock_kb", "vertex_ai"}

_VERIFY_TLS: dict[str, Setting] = {
    "opensearch": Setting("VecShield store registration", "verify_certs", "True",
                          "And give the client the CA that signed the cluster's certificate."),
    "pgvector": Setting("VecShield store registration (DSN)", "sslmode",
                        "verify-full", "Point sslrootcert at the CA that signed the server."),
    "mongodb": Setting("VecShield store registration (connection string)",
                       "tlsInsecure / tlsAllowInvalidCertificates", "remove both",
                       "Set tlsCAFile if the server uses a private CA."),
    "redis": Setting("VecShield store registration", "ssl_cert_reqs", "'required'",
                     "And ssl_ca_certs to the CA that signed the server's certificate."),
}


def _store_settings(table: dict[str, list[Setting]], kind: str) -> tuple[Setting, ...]:
    return tuple(table.get(kind, ()))


def _rescan_step(check_label: str) -> str:
    return (f"Mark this done here, then run the re-scan: VecShield re-runs the "
            f"{check_label} check and records whether the finding is still observed.")


def _guided_for(finding: dict, kind: str, *, store_id: str, store_kind: str,
                tenant_field: Optional[str]) -> list[Guided]:
    """The guided procedures for one finding, filled in with its values."""
    ev = finding.get("evidence") or {}
    fid = str(finding.get("id") or "")
    collection = finding.get("collection") or ""
    store_kind = (store_kind or "").lower()
    host, port = _host_port(ev.get("endpoint") or finding.get("store"))
    where_store = f"{store_id} ({store_kind or 'unknown kind'})"
    out: list[Guided] = []

    def add(name: str, **kw) -> None:
        kw.setdefault("check", KINDS.get(kind, KINDS["other"])[1])
        out.append(Guided(id=_sid(finding, name), finding_id=fid, kind=kind, **kw))

    if kind == "sensitive_data":
        labels = sorted((ev.get("label_counts") or {}).keys())
        add("ingest-gate",
            title="Stop it arriving: gate chunks before they are embedded",
            summary=(f"{', '.join(labels) or 'Sensitive'} content reached "
                     f"'{collection}' through ingestion. Cleaning stored chunks does "
                     "not stop the next batch."),
            steps=(
                "In the ingestion job that writes to "
                f"'{collection}', run each batch through the ingest gate before "
                "embedding: from vecshield.ingest import IngestGate; "
                "report = IngestGate(mode=\"hard\").inspect(chunks)",
                "Or dry-run the source first: vecshield-platform gate-ingest "
                "--source local --path <source dir> --mode soft",
                "Decide per label whether a hit blocks the chunk or is masked "
                "(--redact) before it is embedded.",
                _rescan_step("data classification"),
            ),
            owner="ingestion pipeline owner", risk="low",
            undo="Remove the gate from the pipeline.",
            verify=("A re-scan of the collection. It confirms the stored chunks, not "
                    "the pipeline: new data is only covered once the gate runs."),
            link={"view": "ingest", "label": "Try the gate on a sample"},
            not_executable_because="The ingestion pipeline is the customer's code, "
                                   "outside any store connector.")
        sensitivity = ev.get("sensitivity") or {}
        inversion = sensitivity.get("inversion_risk")
        if isinstance(inversion, (int, float)) and inversion >= 0.7:
            add("reembed",
                title="Re-embed with a lower-inversion model, or restrict the vectors",
                summary=(f"Inversion risk is {inversion:.2f}: the vectors themselves can "
                         "leak the text they encode, so removing the text does not remove "
                         "the exposure."),
                steps=(
                    "Restrict query access to this collection to the services that need "
                    "it (see the access-control findings for its keys).",
                    "Re-embed the collection with a model of lower inversion risk, from "
                    "text with the sensitive spans removed, into a new collection.",
                    "Point the application at the new collection, then retire "
                    f"'{collection}'.",
                    _rescan_step("data classification"),
                ),
                owner="application team", risk="medium",
                undo="Point the application back at the original collection.",
                verify="A re-scan reports the inversion risk of the collection it reads.",
                not_executable_because="Re-embedding needs the model the collection "
                                       "was built with, which VecShield does not have.")
        if disputes_by_chunk(finding):
            add("suppress",
                title="Record known-benign matches as false positives",
                summary=("Some matches are disputed as not live values (a published "
                         "example, a test key). Suppressing them tags the finding in "
                         "later runs; it does not hide it."),
                steps=("Open False positives and add an allow-list rule or a time-boxed "
                       "suppression for the disputed value, with the reason.",
                       _rescan_step("data classification")),
                owner="security reviewer", risk="low",
                undo="Remove the rule; later runs report the match again.",
                verify="A re-scan shows the finding tagged as suppressed.",
                link={"view": "falsepositives", "label": "Open False positives"},
                not_executable_because="A suppression is a reviewer's judgement, "
                                       "recorded in the console rather than the store.")

    elif kind == "prompt_injection":
        add("ingest-filter",
            title="Filter injection at ingestion and fence retrieved text",
            summary=("Removing the flagged chunks treats this copy; the source that "
                     "supplied them will supply them again."),
            steps=(
                f"Find the source of the flagged chunks in '{collection}' (the chunk "
                "metadata's source field) and remove or correct the document there.",
                "Scan documents before ingestion with the same rules: "
                "vecshield-platform scan-integrity against a staging collection.",
                "In the prompt, place retrieved chunks in a delimited context block and "
                "instruct the model that text inside it is data, not instructions.",
                _rescan_step("RAG integrity"),
            ),
            owner="application team", risk="low",
            undo="Remove the filter or the prompt change.",
            verify="A re-scan of the collection counts the injection payloads left.",
            not_executable_because="Sources and prompts live in the customer's "
                                   "application, outside any store connector.")

    elif kind == "embedding_anomaly":
        add("review",
            title="Review the outlier chunks against their provenance",
            summary=("An outlier is a statistical observation, not a verdict: diverse "
                     "data produces outliers too. Concentration in one source is the "
                     "signal worth acting on."),
            steps=(
                "Open the Chunks tab and read each outlier with its source metadata.",
                "If several come from one source, check that source is authorised; if "
                "they are legitimate, record that on the case.",
                _rescan_step("RAG integrity"),
            ),
            owner="security reviewer", risk="low", undo="Nothing to undo.",
            verify="A re-scan recomputes the outliers for the collection.",
            not_executable_because="Whether an outlier is poisoned is a judgement "
                                   "about the data, which a scan cannot make.")

    elif kind == "provenance_incomplete":
        add("record-source",
            title="Record a source on every chunk at ingestion",
            summary=(f"{ev.get('with_source', '?')} of {ev.get('total', '?')} chunks in "
                     f"'{collection}' carry a traceable source."),
            steps=(
                "In the ingestion job, set a source on every chunk before it is written.",
                "Re-ingest, or backfill the source on the untagged chunks from the "
                "system they came from.",
                _rescan_step("RAG integrity"),
            ),
            settings=(Setting("chunk metadata written at ingestion", "source",
                              "<document URI or id>"),
                      Setting("chunk metadata written at ingestion", "ingested_at",
                              "<ISO-8601 timestamp>")),
            owner="ingestion pipeline owner", risk="low",
            undo="Nothing to undo; the fields only add information.",
            verify="A re-scan recomputes provenance coverage; it clears at 95%.",
            not_executable_because="The true source of an untraceable chunk is known "
                                   "only to the system that produced it.")

    elif kind == "provenance_rare_source":
        rare = [str(s) for s in ev.get("rare_sources") or []]
        add("confirm-sources",
            title="Confirm each rare source is expected and authorised",
            summary=(f"{len(rare)} source(s) contribute a tiny share of '{collection}': "
                     + ", ".join(rare[:5]) + ("…" if len(rare) > 5 else "")),
            steps=(
                "For each source, confirm with its owner that it is meant to feed this "
                "collection.",
                "Add confirmed sources to the ingestion allow-list; remove the chunks of "
                "any that are not (the executable quarantine above does that reversibly).",
                _rescan_step("RAG integrity"),
            ),
            owner="data owner", risk="low", undo="Nothing to undo.",
            verify="A re-scan lists the rare sources that remain.",
            not_executable_because="Whether a source is authorised is an "
                                   "organisational fact, not something a store records.")

    elif kind in ("tenant_filter_not_enforced", "tenant_convention_only"):
        field_name = ev.get("tenant_field") or tenant_field or "tenant_id"
        native = _store_settings(_TENANCY_SETTINGS, store_kind)
        add("enforce-tenancy",
            title="Enforce the tenant boundary where the store can hold it",
            summary=("Isolation that depends on every query remembering a filter fails "
                     "the first time one does not. Move the boundary into the store, "
                     "and derive the tenant from the authenticated caller."),
            steps=(
                ("Use the store's native tenancy for this collection (settings below)."
                 if native else
                 f"{store_kind or 'This store'} has no native per-tenant boundary VecShield "
                 "knows of: use a collection per tenant (the executable split above "
                 "prepares one)."),
                f"In every query path, add a filter on '{field_name}' whose value comes "
                "from the authenticated caller's identity, never from request input: "
                f"collection.query(..., where={{\"{field_name}\": tenant_of(caller)}})",
                "Give each tenant-facing service a credential scoped to its own "
                "collection or namespace where the store supports it.",
                _rescan_step("tenant isolation"),
            ),
            settings=native, owner="application team", risk="medium",
            undo="Revert the query and configuration change.",
            verify=("A re-scan re-runs the canary and per-tenant probes against "
                    f"'{collection}'."),
            not_executable_because="The query path is the customer's application; "
                                   "the store's tenancy settings are its server config.")

    elif kind == "tenant_untagged":
        field_name = ev.get("tenant_field") or tenant_field or "tenant_id"
        add("reject-untagged",
            title=f"Make ingestion reject chunks without '{field_name}'",
            summary=(f"{ev.get('untagged', 'Some')} chunk(s) in '{collection}' carry no "
                     f"'{field_name}'. Fixing these does not stop the next one."),
            steps=(
                f"In the ingestion job, refuse to write a chunk whose '{field_name}' is "
                "missing or empty.",
                "Move genuinely shared content to a collection of its own rather than "
                "leaving it untagged in a tenant collection.",
                _rescan_step("tenant isolation"),
            ),
            owner="ingestion pipeline owner", risk="low",
            undo="Remove the check.",
            verify="A re-scan counts the chunks with no tenant value.",
            not_executable_because="The ingestion pipeline is the customer's code.")

    elif kind == "isolation_not_verified":
        field_name = ev.get("tenant_field") or tenant_field or "tenant_id"
        add("configure-check",
            title="Make the isolation check able to run",
            summary=str(finding.get("description") or ""),
            steps=(
                f"Confirm which metadata field identifies the tenant in '{collection}' "
                f"(currently '{field_name}') and set it on the store registration.",
                "If the connector cannot query or enumerate, register the backing store "
                "with a connector that can.",
                _rescan_step("tenant isolation"),
            ),
            settings=(Setting(f"VecShield store registration: {store_id}", "tenant_field",
                              f"<the field that holds the tenant; now '{field_name}'>"),),
            owner="VecShield administrator", risk="low", undo="Change the field back.",
            verify="A re-scan runs the isolation check with the configured field.",
            link={"view": "stores", "label": "Open the store registration"},
            not_executable_because="Which field names a tenant is a fact about the "
                                   "customer's data model, stated by a person.")

    elif kind == "ann_post_filter":
        setting = f"{ev.get('index_type') or 'hnsw'}.iterative_scan"
        mode = "relaxed_order" if ev.get("index_type") == "ivfflat" else "strict_order"
        add("iterative-scan",
            title="Let filtered searches keep scanning the index",
            summary=str(finding.get("description") or ""),
            steps=(
                str(finding.get("remediation") or "Turn on iterative index scans."),
                "Do not fix short results by searching as a role that bypasses row "
                "security or by dropping the tenant filter: that trades lost recall "
                "for a leak.",
                f"The behaviour is documented at {ev.get('source_url')}: "
                f"\"{ev.get('quote', '')}\"",
                _rescan_step("tenant isolation"),
            ),
            settings=(Setting("PostgreSQL (the application's role)", setting, mode,
                              "pgvector 0.8.0 or later"),),
            owner="database administrator", risk="low",
            undo=f"ALTER ROLE <app role> RESET {setting}.",
            verify=("A re-scan reads the role's setting again and retries short filtered "
                    "views with the iterative scan on."),
            not_executable_because="Role settings are changed by a database "
                                   "administrator; connectors only read the catalog.")

    elif kind == "pan_readable":
        add("tokenize",
            title="Tokenize or truncate card numbers before they are embedded",
            summary=("PCI DSS 3.5.1 requires stored PAN to be unreadable. Disk or "
                     "database encryption does not meet it for a vector store "
                     "(3.5.1.2)."),
            steps=(
                "Tokenize or truncate PAN in the source (first six and last four at most) "
                "before chunking and embedding.",
                f"Purge the readable records from '{collection}' and re-ingest them "
                "from the tokenized source; the vectors must be recomputed too, because "
                "they encode the full number.",
                "The PCI data-classification finding for this collection carries "
                "chunk-level actions for the records it named.",
                _rescan_step("data classification"),
            ),
            owner="payments engineering", risk="medium",
            undo="Re-ingest from the untokenized source (not recommended).",
            verify="A re-scan counts full PAN still stored readable.",
            not_executable_because="Tokenization needs the customer's token vault, and "
                                   "re-embedding needs the collection's model.")

    elif kind == "protection_drift":
        fields = [f.get("path") for f in ev.get("fields") or [] if isinstance(f, dict)]
        add("apply-consistently",
            title="Apply the protection on every ingestion path",
            summary=("These fields hold protected values in most records and plaintext "
                     "in others: " + ", ".join(str(f) for f in fields[:6])),
            steps=(
                "Find the ingestion path that writes these fields without the "
                "protection the rest of the collection uses, and apply it there.",
                "Re-process the plaintext records through the protected path.",
                _rescan_step("data classification"),
            ),
            settings=tuple(Setting("chunk metadata field", str(f), "the protected form "
                                   "the rest of the collection uses") for f in fields[:6]),
            owner="ingestion pipeline owner", risk="low", undo="Nothing to undo.",
            verify="A re-scan measures each field's protected fraction.",
            not_executable_because="The protection mechanism (tokenizer, key) belongs "
                                   "to the customer's pipeline.")

    elif kind == "retrieval_exposure":
        add("limit-payload",
            title="Return only what the retriever needs",
            summary=str(finding.get("description") or ""),
            steps=(
                "Limit the payload fields each query returns to the ones the prompt uses.",
                "Mask, tokenize or pseudonymize sensitive values before ingestion so "
                "retrieval hands back only the protected form.",
                _rescan_step("retrieval exposure"),
            ),
            owner="application team", risk="low", undo="Revert the query change.",
            verify="A re-scan replays the retrieval probe; it is opt-in and active.",
            not_executable_because="What a query returns is set by the application.")

    elif kind == "network_exposure":
        settings = _store_settings(_BIND_SETTINGS, store_kind) + (
            Setting("cloud security group / firewall",
                    f"inbound rule for port {port or '<store port>'}",
                    "allow only the application subnet CIDR; deny 0.0.0.0/0"),)
        add("private-network",
            title="Take the store off the public internet",
            summary=(f"{host or 'The endpoint'} is reachable from the public internet "
                     f"({ev.get('reason') or ev.get('exposure') or 'public address'})."),
            steps=(
                "Move the store onto a private subnet, or bind it to a private interface "
                "(settings below).",
                "Restrict inbound traffic to the application's addresses; front "
                "operator access with a VPN or bastion.",
                "Update the store registration in VecShield if the endpoint changes.",
                _rescan_step("configuration posture"),
            ),
            settings=settings, owner="platform / infrastructure", risk="medium",
            undo="Restore the previous listener and rule.",
            verify="A re-scan resolves the endpoint and classifies its address again.",
            link={"view": "stores", "label": "Open the store registration"},
            not_executable_because="Network placement is infrastructure, outside "
                                   "any store connector.")

    elif kind == "authentication":
        settings = _store_settings(_AUTH_SETTINGS, store_kind)
        add("require-credential",
            title="Require a credential for every request",
            summary=(f"{host or 'The store'} answered an unauthenticated request "
                     f"({ev.get('probe_reason') or 'anonymous access'})."),
            steps=(
                ("Turn authentication on (settings below)." if settings else
                 f"Turn authentication on in {store_kind or 'the store'}'s server "
                 "configuration."),
                "Issue each application its own credential, read-only where it only "
                "retrieves, and keep them in a secret store.",
                "Update the credential VecShield uses on the store registration.",
                _rescan_step("configuration posture"),
            ),
            settings=settings, owner="platform / infrastructure", risk="medium",
            undo="Revert the server setting (and re-open the exposure).",
            verify="A re-scan repeats the anonymous probe and expects a refusal.",
            link={"view": "stores", "label": "Open the store registration"},
            not_executable_because="Server authentication is the store's own "
                                   "configuration, which connectors cannot change.")

    elif kind in ("transport_encryption", "transport_tls_enforcement"):
        settings = _store_settings(_TLS_SETTINGS, store_kind)
        managed = store_kind in _MANAGED
        add("enable-tls",
            title=("Refuse plaintext connections" if kind == "transport_tls_enforcement"
                   else "Encrypt the connection to the store"),
            summary=(f"{ev.get('endpoint') or host or 'The endpoint'}: "
                     + ("the store accepts clients that do not use TLS."
                        if kind == "transport_tls_enforcement"
                        else "the connection VecShield holds is not encrypted.")),
            steps=(
                ("This is a managed service: register the https:// endpoint rather than "
                 "an http:// one." if managed else
                 "Enable TLS on the server (settings below)."),
                ("Close the plaintext listener so a client cannot fall back to it."
                 if kind == "transport_tls_enforcement" else
                 "Point every client, VecShield included, at the TLS endpoint."),
                _rescan_step("configuration posture"),
            ),
            settings=settings, owner="platform / infrastructure", risk="medium",
            undo="Re-enable the plaintext listener (and re-open the exposure).",
            verify="A re-scan inspects the session and, where it can, the server's "
                   "enforcement setting.",
            link={"view": "stores", "label": "Open the store registration"},
            not_executable_because="TLS is the store server's configuration.")

    elif kind == "tls_certificate_verification":
        setting = _VERIFY_TLS.get(store_kind, Setting(
            "VecShield store registration", "certificate verification", "on",
            "Trust only the CA that issued the store's certificate."))
        add("verify-cert",
            title="Verify the store's certificate",
            summary="The connection is encrypted but the server it reached was not "
                    "authenticated, so a man in the middle would not be noticed.",
            steps=(f"Change the registration of {where_store} as below.",
                   _rescan_step("configuration posture")),
            settings=(setting,), owner="VecShield administrator", risk="low",
            undo="Turn verification off again (not recommended).",
            verify="A re-scan reads the connection's verification setting.",
            link={"view": "stores", "label": "Open the store registration"},
            not_executable_because="Connection credentials are registered "
                                   "out-of-band and are never written by the console.")

    elif kind == "at_rest_encryption":
        add("encrypt-at-rest",
            title="Enable encryption at rest",
            summary=str(finding.get("description") or ""),
            steps=(str(finding.get("remediation") or
                       "Enable the database's native encryption at rest."),
                   "If disk- or KMS-level encryption is already in place, record it as "
                   "evidence on the criterion rather than treating this as fixed.",
                   _rescan_step("configuration posture")),
            owner="platform / infrastructure", risk="medium",
            undo="Encryption at rest is not normally turned off again.",
            verify="A re-scan reads the encryption state the data plane reports.",
            link={"view": "evidence", "label": "Register evidence"},
            not_executable_because="Encryption at rest is set when the store or "
                                   "volume is provisioned.")

    elif kind == "cve":
        package = ev.get("package") or "the client library"
        installed = ev.get("installed_version") or "?"
        fixed = ev.get("fixed_version")
        add("upgrade",
            title=f"Upgrade {package}",
            summary=(f"{package} {installed} is affected by {ev.get('vuln_id')}"
                     + (f" ({', '.join(ev.get('aliases') or [])})" if ev.get("aliases") else "")
                     + "."),
            steps=(
                (f"Upgrade {package} from {installed} to {fixed} or later in the "
                 "environment VecShield runs in, and in any application that uses it."
                 if fixed else
                 f"No fixed release is recorded for {ev.get('vuln_id')}: follow the "
                 "advisory for mitigations, or replace the dependency."),
                ("Rebuild and redeploy; pin the new version in the lockfile." if fixed else
                 "Record the mitigation, or the replacement, on the case."),
                _rescan_step("configuration posture (CVE)"),
            ),
            settings=((Setting("requirements / lockfile", str(package), f">={fixed}"),)
                      if fixed else ()),
            owner="platform / infrastructure", risk="low",
            undo=f"Pin {package}=={installed} again.",
            verify="A re-scan reads the installed version and queries OSV again; it "
                   "needs network access to api.osv.dev.",
            not_executable_because="Upgrading software is a deployment change.")

    elif kind == "cve_scan_gap":
        add("enable-cve-scan",
            title="Let the vulnerability scan run",
            summary=str(finding.get("description") or finding.get("title") or ""),
            steps=(str(finding.get("remediation") or
                       "Allow egress to api.osv.dev and re-run the assessment."),
                   _rescan_step("configuration posture (CVE)")),
            owner="platform / infrastructure", risk="low", undo="Nothing to undo.",
            verify="A re-scan with network access queries OSV.",
            not_executable_because="Network egress is infrastructure.")

    elif kind == "api_key":
        key_id = ev.get("key_id") or "?"
        key_name = ev.get("key_name") or key_id
        title = str(finding.get("title") or "").lower()
        revoke = "stale" in title or "never-used" in title
        add("key",
            title=(f"Revoke key '{key_name}'" if revoke
                   else f"Reduce what key '{key_name}' can do"),
            summary=str(finding.get("description") or ""),
            steps=(
                (f"Confirm nothing still uses key {key_id} (its last use is in the "
                 "finding), then revoke it in the store's key management."
                 if revoke else
                 f"Create a replacement for key {key_id} scoped to the namespaces it "
                 "needs, without write, delete or admin unless required."),
                ("Remove it from every secret store and configuration that holds it."
                 if revoke else
                 "Move each consumer to the replacement, then revoke the original."),
                _rescan_step("access control"),
            ),
            settings=(Setting(f"{store_kind or 'store'} key management", f"key {key_id}",
                              "revoked" if revoke else
                              f"scoped to: {', '.join(ev.get('namespaces') or []) or '<namespaces>'}"),),
            owner="security / platform", risk="medium",
            undo="Issue a new key; a revoked key cannot be restored.",
            verify="A re-scan lists the store's keys again and re-audits them.",
            not_executable_because=("VecShield can list this store's keys but no "
                                    "connector here can revoke or rotate one."))

    elif kind == "rbac_grant":
        principal = ev.get("principal") or "?"
        namespace = ev.get("namespace") or "?"
        action = ev.get("action") or ev.get("actions") or "?"
        add("grant",
            title=f"Reconcile {principal}'s access to {namespace}",
            summary=str(finding.get("description") or ""),
            steps=(str(finding.get("remediation") or
                       f"Change {principal}'s grant on {namespace} to match intent."),
                   _rescan_step("access control")),
            settings=(Setting("store access policy", f"{principal} on {namespace}",
                              f"{action}: as intended"),),
            owner="security / platform", risk="medium",
            undo="Restore the previous grant.",
            verify="A re-scan compares the live policy with intent again.",
            not_executable_because="Grants are changed in the store's own policy.")

    elif kind == "coverage_gap":
        add("coverage",
            title="Close the coverage gap",
            summary=str(finding.get("description") or ""),
            steps=(str(finding.get("remediation") or "Resolve the cause and re-run."),
                   "Run a new assessment; a gap is closed only when the check completes."),
            owner="VecShield administrator", risk="low", undo="Nothing to undo.",
            verify="A new assessment records the check's coverage.",
            check="coverage",
            link={"view": "assess", "label": "Run an assessment"},
            not_executable_because="The cause (access, a connector, a limit) is "
                                   "configuration outside the store's data.")

    elif kind == "training_data":
        add("fix-source",
            title="Clean the training source before it is used",
            summary=str(finding.get("description") or ""),
            steps=(str(finding.get("remediation") or "Remove or mask the records."),
                   "Gate the source before embedding: vecshield-platform gate-ingest "
                   "--mode hard --redact",
                   "Run a new dataset scan."),
            owner="data owner", risk="low", undo="Nothing to undo.",
            verify="A new dataset scan of the source.", check="",
            link={"view": "ingest", "label": "Open Ingest"},
            not_executable_because="A training source is a file or bucket, not a "
                                   "registered vector store.")

    elif kind == "retention_unknown":
        add("record-ingest-time",
            title="Record when each chunk was ingested",
            summary=str(finding.get("description") or ""),
            steps=(
                f"In the ingestion job that writes to '{collection}', set an ingestion "
                "timestamp on every chunk's metadata at write time.",
                "Existing chunks cannot be dated retrospectively; the horizon starts "
                "from the change, so record that date on the case.",
                _rescan_step("data classification"),
            ),
            settings=(Setting("chunk metadata written at ingestion", "ingested_at",
                              "<ISO-8601 timestamp>"),),
            owner="ingestion pipeline owner", risk="low",
            undo="Nothing to undo; the field only adds information.",
            verify="A re-scan reads the timestamps back and reports the horizon.",
            not_executable_because="When a chunk was ingested is known only to the "
                                   "pipeline that wrote it.")

    elif kind in _STORE_CONTROL_KINDS:
        _guided_store_controls(finding, kind, store_kind=store_kind, add=add)

    elif kind == "other" and finding.get("remediation"):
        add("scanner",
            title="Follow the scanner's recommendation",
            summary=str(finding.get("description") or ""),
            steps=(str(finding["remediation"]), "Run a new assessment."),
            owner="unassigned", risk="low", undo="",
            verify="A new assessment.", check="",
            not_executable_because="No specific remediation is catalogued for this "
                                   "kind of finding yet.")
    return out


def _own_remediation(finding: dict, fallback: str) -> str:
    """The finding's own recommendation: checks build it from cited data."""
    return str(finding.get("remediation") or fallback).strip()


def _guided_store_controls(finding: dict, kind: str, *, store_kind: str,
                           add: Callable[..., None]) -> None:
    """Guided procedures for the store-control and integrity checks.

    Every procedure leads with the recommendation the check itself wrote,
    which is assembled from the check's own sources (the advisory, the egress
    catalogue, the declared schedule), and adds only what the product knows:
    where the fix is recorded and which re-scan confirms it.
    """
    ev = finding.get("evidence") or {}
    collection = finding.get("collection") or ""
    description = str(finding.get("description") or "")

    if kind == "retention_schedule":
        exceeded = [r for r in ev.get("rules") or [] if isinstance(r, dict) and r.get("over_max")]
        ids = [cid for r in exceeded for cid in r.get("examples") or []]
        add("apply-schedule",
            title="Delete or anonymise records past your declared maximum",
            summary=description,
            steps=(
                _own_remediation(finding, "Delete or anonymise the records older than the "
                                          "declared maximum."),
                ("The oldest over-limit chunk ids are in the evidence ("
                 + ", ".join(str(i) for i in ids[:5]) + "); the executable quarantine "
                 "proposal above names them. Delete them yourself once no hold applies."
                 if ids else
                 "Find the over-limit records by their record time in the source system."),
                "Fix the cause as well: add an expiry job to the ingestion pipeline that "
                "deletes chunks once they pass the declared maximum.",
                _rescan_step("data classification (retention schedule)"),
            ),
            settings=tuple(Setting("declared retention schedule",
                                   f"rule for '{r.get('category')}'",
                                   f"max_age_days = {r.get('max_age_days')}",
                                   f"basis: {r.get('basis') or 'not stated'}")
                           for r in exceeded[:5]),
            owner="data owner", risk="medium",
            undo="Deleted records cannot be restored; quarantined ones can.",
            verify="A re-scan compares every chunk's age with the schedule again.",
            link={"view": "settings", "label": "Review the retention schedule"},
            not_executable_because="Whether a legal hold or another clock applies is a "
                                   "judgement only the organisation can make.")

    elif kind == "biometric_templates":
        refs = [r for r in ev.get("references") or [] if isinstance(r, dict)]
        add("biometric-obligations",
            title="Evidence the obligations that attach to a biometric database",
            summary=description,
            steps=(
                _own_remediation(finding, "Record consent, a retention schedule and an "
                                          "impact assessment for the templates."),
                "Declare a retention rule covering this collection so the schedule check "
                "evaluates it on every scan.",
                "Record the consent, DPIA and retention evidence on the criteria that "
                "cite " + (", ".join(str(r.get("citation")) for r in refs[:4])
                           or "the biometric regimes") + ".",
                _rescan_step("data classification (biometric templates)"),
            ),
            owner="privacy / legal", risk="low", undo="Nothing to undo.",
            verify=("A re-scan re-reads the declared model and metadata. The finding stays "
                    "while the collection holds templates; the evidence is what closes the "
                    "criteria."),
            link={"view": "evidence", "label": "Register evidence"},
            not_executable_because="Consent, purpose and retention are organisational "
                                   "facts; the store cannot record them.")

    elif kind == "model_egress":
        provider = ev.get("provider_name") or ev.get("provider") or \
            ", ".join(str(p) for p in ev.get("providers") or []) or "the provider"
        labels = [str(label) for label in ev.get("labels") or []]
        settings: tuple[Setting, ...] = ()
        if ev.get("provider"):
            settings = (Setting("VecShield processor register", str(ev.get("provider")),
                                "dpa: true" + (", baa: true" if "phi" in labels else ""),
                                "Only once the agreement is actually signed."),)
        add("egress",
            title=f"Stop or paper the flow to {provider}",
            summary=description,
            steps=(
                _own_remediation(finding, "Embed client-side, or use a model in your own "
                                          "cloud tenant."),
                "If the flow is intended, record the provider with its DPA"
                + (" and signed BAA" if "phi" in labels else "")
                + " in the processor register (Settings) and in your records of "
                  "processing.",
                _rescan_step("configuration posture (model egress)"),
            ),
            settings=settings, owner="platform / privacy", risk="medium",
            undo="Re-enable the integration, or remove the register entry.",
            verify=("A re-scan reads the store's model configuration again and compares "
                    "it with the processor register."),
            link={"view": "settings", "label": "Open the processor register"},
            not_executable_because="Model integrations are the store's own configuration, "
                                   "and agreements with providers are signed by people.")

    elif kind == "data_residency":
        where = ev.get("region") or ev.get("jurisdiction") or ev.get("country") or ""
        add("residency",
            title="Bring the data back inside the residency policy",
            summary=description,
            steps=(
                _own_remediation(finding, "Move the data to an allowed region, or record "
                                          "the transfer mechanism that covers it."),
                ("For the transfer rules named above, keep the mechanism relied on "
                 "(adequacy, SCCs, BCRs) as evidence on the criterion."
                 if ev.get("transfer_status") else
                 "Declare the data-subject regimes in the residency policy so transfer "
                 "rules can be evaluated."),
                _rescan_step("configuration posture (data residency)"),
            ),
            settings=((Setting("residency policy", "allowed_regions",
                               f"add '{where}' only if a transfer mechanism covers it"),)
                      if where else ()),
            owner="platform / privacy", risk="high",
            undo="Moving data back is a second migration.",
            verify="A re-scan reads the store's reported location and model endpoints again.",
            link={"view": "settings", "label": "Open the residency policy"},
            not_executable_because="Data location is chosen when the store is "
                                   "provisioned, outside any connector.")

    elif kind == "server_vulnerability":
        product = ev.get("product") or store_kind or "the server"
        upgrade = ev.get("recommended_upgrade") or {}
        target = ev.get("same_line_fix") or upgrade.get("version")
        workaround = ev.get("workaround") if isinstance(ev.get("workaround"), dict) else {}
        steps = [_own_remediation(finding, f"Upgrade {product} to a fixed release.")]
        if workaround.get("text") and not workaround.get("none_known"):
            steps.append(f"Until you can upgrade, the advisory's own workaround: "
                         f"{workaround['text']} (source: {workaround.get('source_url')}).")
        if ev.get("applicability") and ev.get("applicability_reason"):
            steps.append(f"Exposure: {ev['applicability_reason']}")
        steps.append(_rescan_step("configuration posture (server advisories)"))
        add("upgrade-server",
            title=(f"Upgrade {product} to {target}" if target else
                   f"Resolve {ev.get('advisory_id') or 'the advisory'} on {product}"),
            summary=description[:600],
            steps=tuple(steps),
            settings=((Setting(f"{product} deployment", "server version",
                               f"{target} or later",
                               f"running {ev.get('running_version') or '?'}; "
                               f"{upgrade.get('reason') or ''}".strip("; ")),)
                      if target else ()),
            owner="platform / infrastructure", risk="medium",
            undo="Roll back to the previous release (and re-open the advisory).",
            verify=("A re-scan reads the server version again and matches it against the "
                    "advisory feed; refresh the feed first if it is stale."),
            not_executable_because="Upgrading the database server is a deployment change.")

    elif kind == "server_support_status":
        add("supported-line",
            title="Move to a supported release line",
            summary=description,
            steps=(_own_remediation(finding, "Upgrade to a supported release line."),
                   _rescan_step("configuration posture (server support status)")),
            settings=((Setting("database deployment", "release line",
                               ", ".join(str(x) for x in ev.get("supported_lines") or [])),)
                      if ev.get("supported_lines") else ()),
            owner="platform / infrastructure", risk="medium",
            undo="Roll back to the previous release.",
            verify="A re-scan reads the server version and the vendor's end-of-life dates.",
            not_executable_because="Upgrading the database server is a deployment change.")

    elif kind in ("access_grants", "server_hardening"):
        # Both checks write their remediation from a cited rule
        # (posture/data/pg_hardening_rules.json); the guide adds the source and
        # who changes it.
        access = kind == "access_grants"
        steps = [_own_remediation(finding, "Apply the change the rule names.")]
        if ev.get("principal_assumed"):
            steps.append("No retrieval role is declared for this store, so this was judged "
                         "for the role VecShield connected as. Declare the application's "
                         "role (retrieval_role on the store registration) and re-scan "
                         "before changing grants.")
        if ev.get("source_url"):
            steps.append(f"The rule rests on {ev['source_url']}: \"{ev.get('quote', '')}\"")
        steps.append(_rescan_step("configuration posture"))
        add(kind.replace("_", "-"),
            title=str(finding.get("title") or KINDS[kind][0]),
            summary=description,
            steps=tuple(steps),
            owner="database administrator", risk="medium",
            undo=("Re-grant the privilege or attribute that was removed." if access else
                  "Restore the previous postgresql.conf or pg_hba.conf value and reload."),
            verify=("A re-scan reads the roles, row-security settings and grants from "
                    "the catalog again." if access else
                    "A re-scan reads pg_settings and pg_hba_file_rules again; rules whose "
                    "settings the auditing role cannot read stay not evaluated."),
            link={"view": "stores", "label": "Open the store registration"},
            not_executable_because=("Roles and grants are changed by a database "
                                    "administrator; VecShield's connectors only read "
                                    "the catalog." if access else
                                    "Server configuration is changed on the database "
                                    "host, outside any connector."))

    else:  # corpus_duplication, retrieval_hubness, ingestion_burst, chunk_versions
        label = KINDS[kind][0].lower()
        add(kind.replace("_", "-"),
            title=f"Review and correct: {label}",
            summary=description,
            steps=(
                _own_remediation(finding, "Review the named chunks and correct ingestion."),
                f"Open the Chunks tab for '{collection}' and read the chunks the evidence "
                "names with their source metadata before removing anything.",
                "Change the ingestion job so the pattern does not recur (key chunks by "
                "source and position, record the ingesting principal, deduplicate on write).",
                _rescan_step("RAG integrity"),
            ),
            owner="ingestion pipeline owner", risk="low",
            undo="Restore quarantined chunks from vecshield_quarantine.",
            verify=f"A re-scan of '{collection}' recomputes the {label} check.",
            not_executable_because="Which copy or version is authoritative is known to the "
                                   "source system, not the store.")


def _named_ids(finding: dict, *keys: str) -> tuple[str, ...]:
    """Chunk ids a finding names in its examples (``chunk_id`` and id lists)."""
    ev = finding.get("evidence") or {}
    ids: list[str] = []
    for example in ev.get("examples") or []:
        if not isinstance(example, dict):
            continue
        for key in keys or ("chunk_ids", "chunk_id"):
            value = example.get(key)
            if isinstance(value, (list, tuple)):
                ids.extend(str(v) for v in value if v)
            elif value:
                ids.append(str(value))
    return tuple(dict.fromkeys(ids))


# --------------------------------------------------------------------------- #
# Executable proposals for non-classification findings                         #
# --------------------------------------------------------------------------- #

def _proposal(finding: dict, action: str, *, store: str, kind: str,
              chunk_ids: Iterable[str] = (), selector: Optional[dict] = None,
              params: Optional[dict] = None, observed: int = 0, rationale: str = "",
              rests_on: Iterable[str] = (), excluded: Iterable = (),
              basis: str = "") -> Suggestion:
    ids = tuple(chunk_ids)
    detectors = tuple(sorted(set(rests_on)))
    return Suggestion(
        id=f"sug-{uuid.uuid4().hex[:12]}", action=action,
        finding_id=str(finding.get("id") or ""), store=store,
        collection=finding.get("collection"), chunk_ids=ids,
        rests_on=detectors,
        calibrated=bool(detectors) and all(d in CALIBRATED for d in detectors),
        rationale=rationale, observed_chunks=max(observed, len(ids)),
        named_chunks=len(ids), selector=selector, params=dict(params or {}),
        kind=kind, excluded=tuple(excluded), basis=basis)


def _example_ids(finding: dict) -> tuple[str, ...]:
    ev = finding.get("evidence") or {}
    ids = [str(e.get("chunk_id")) for e in ev.get("examples") or []
           if isinstance(e, dict) and e.get("chunk_id")]
    return tuple(dict.fromkeys(ids))


def _executable_for(finding: dict, kind: str, *, store: str,
                    tenant_field: Optional[str]) -> tuple[list[Suggestion], list[Withheld]]:
    ev = finding.get("evidence") or {}
    fid = str(finding.get("id") or "")
    collection = finding.get("collection")
    made: list[Suggestion] = []
    refused: list[Withheld] = []

    def need_collection(action: str) -> bool:
        if collection:
            return True
        refused.append(Withheld(action, fid, "The finding is not scoped to a "
                                             "collection, so there is nothing to act on."))
        return False

    if kind == "prompt_injection" and need_collection("quarantine_chunks"):
        ids = _example_ids(finding)
        if not ids:
            refused.append(Withheld("quarantine_chunks", fid,
                                    "The finding retained no chunk ids to move."))
        else:
            reach, excluded = gate_chunks(ACTION_TEMPLATES["quarantine_chunks"], ids,
                                          detectors_by_chunk(finding), detectors_in(finding))
            count = int(ev.get("count") or len(ids))
            made.append(_proposal(
                finding, "quarantine_chunks", store=store, kind=kind, chunk_ids=reach,
                observed=count, rests_on=detectors_in(finding), excluded=excluded,
                rationale=(f"{count} chunk(s) carry injection payloads; the finding "
                           f"named {len(ids)}. Moving them out of '{collection}' stops "
                           "retrieval over it returning them, and keeps each one "
                           "restorable.")))

    elif kind == "embedding_anomaly" and need_collection("tag_review"):
        ids = _example_ids(finding)
        count = int(ev.get("count") or len(ids))
        if not ids:
            refused.append(Withheld("tag_review", fid,
                                    "The finding retained no chunk ids to flag."))
        else:
            made.append(_proposal(
                finding, "tag_review", store=store, kind=kind, chunk_ids=ids,
                params={"reason": "anomalous_embedding"}, observed=count,
                basis="statistical",
                rationale=(f"{count} vector(s) are statistical outliers; flagging the "
                           f"{len(ids)} named ones records that a person should read "
                           "them, without withdrawing anything.")))
            made.append(_proposal(
                finding, "quarantine_chunks", store=store, kind=kind, chunk_ids=ids,
                observed=count, basis="statistical",
                rationale=("For outliers already judged suspicious: moves them out of "
                           "retrieval, restorably. An outlier alone is weak evidence; "
                           "prefer the flag until someone has read them.")))

    elif kind == "provenance_incomplete" and need_collection("tag_provenance"):
        total = int(ev.get("total") or 0)
        untraced = max(total - int(ev.get("with_source") or 0), 0)
        made.append(_proposal(
            finding, "tag_provenance", store=store, kind=kind,
            selector={"match": "missing_all", "fields": list(SOURCE_KEYS)},
            params={"status": "unverified"}, observed=untraced,
            basis="condition",
            rationale=(f"{untraced} chunk(s) carry none of the source fields provenance "
                       "analysis reads. Tagging them makes the gap filterable and "
                       "auditable where the data lives.")))

    elif kind == "provenance_rare_source" and need_collection("tag_review"):
        rare = [str(s) for s in ev.get("rare_sources") or []]
        if not rare:
            refused.append(Withheld("tag_review", fid, "The finding names no sources."))
        else:
            selector = {"match": "source_in", "keys": list(SOURCE_KEYS), "values": rare}
            made.append(_proposal(
                finding, "tag_review", store=store, kind=kind, selector=selector,
                params={"reason": "rare_source"}, basis="condition",
                rationale=(f"Flags every chunk from the {len(rare)} rare source(s) for a "
                           "person to confirm.")))
            made.append(_proposal(
                finding, "quarantine_chunks", store=store, kind=kind, selector=selector,
                basis="condition",
                rationale=("For sources confirmed as unauthorised: moves their chunks out "
                           "of retrieval, restorably.")))

    elif kind == "tenant_untagged" and need_collection("assign_tenant"):
        field_name = ev.get("tenant_field") or tenant_field
        untagged = int(ev.get("untagged") or 0)
        if not field_name:
            refused.append(Withheld("assign_tenant", fid,
                                    "Neither the finding nor the store names a tenant field."))
        else:
            selector = {"match": "missing_field", "field": field_name}
            made.append(_proposal(
                finding, "assign_tenant", store=store, kind=kind, selector=selector,
                params={"tenant_field": field_name}, observed=untagged,
                basis="condition",
                rationale=(f"{untagged} chunk(s) carry no '{field_name}'. Assigning the "
                           "owning tenant puts them inside that tenant's filter and out "
                           "of everyone else's. You supply the tenant when staging.")))
            made.append(_proposal(
                finding, "tag_exclude", store=store, kind=kind, selector=selector,
                observed=untagged, basis="condition",
                rationale=("If the owner is not known yet: marks the untagged chunks for "
                           "exclusion so a retriever that honours the mark skips them.")))
            made.append(_proposal(
                finding, "quarantine_chunks", store=store, kind=kind, selector=selector,
                observed=untagged, basis="condition",
                rationale=("Moves the untagged chunks out of the shared collection, "
                           "restorably, until their owner is known.")))

    elif kind in ("tenant_convention_only", "tenant_filter_not_enforced") \
            and need_collection("split_by_tenant"):
        field_name = tenant_field or ev.get("tenant_field")
        tenants = ev.get("tenants") or ev.get("leaking_tenants") or []
        if not field_name:
            refused.append(Withheld("split_by_tenant", fid,
                                    "The store has no tenant field configured, so there "
                                    "is nothing to split on."))
        else:
            made.append(_proposal(
                finding, "split_by_tenant", store=store, kind=kind,
                selector={"match": "has_field", "field": field_name},
                params={"tenant_field": field_name}, basis="condition",
                rationale=(f"{len(tenants) or 'Several'} tenants share '{collection}'. "
                           "Copying each into its own collection makes isolation "
                           "structural once the application queries those instead.")))
        if kind == "tenant_filter_not_enforced":
            made.append(_proposal(
                finding, "quarantine_collection", store=store, kind=kind,
                basis="check",
                rationale=("The store ignores the tenant filter, so every tenant can read "
                           "every other tenant's chunks here. Quarantining records that "
                           "the collection must not be served until isolation is "
                           "structural.")))

    elif kind == "retention_schedule" and need_collection("quarantine_chunks"):
        ids = tuple(dict.fromkeys(
            str(cid) for rule in ev.get("rules") or [] if isinstance(rule, dict)
            for cid in rule.get("examples") or []))
        over = int(ev.get("over_max") or len(ids))
        if not ids:
            refused.append(Withheld("quarantine_chunks", fid,
                                    "The finding retained no chunk ids to act on."))
        else:
            made.append(_proposal(
                finding, "quarantine_chunks", store=store, kind=kind, chunk_ids=ids,
                observed=over, basis="check",
                rationale=(f"{over} chunk(s) are older than the declared maximum; the "
                           f"finding named the {len(ids)} oldest. Quarantine takes them "
                           "out of retrieval and keeps each restorable while a legal hold "
                           "is ruled out.")))
            # No delete proposal. Deleting is what the schedule requires once no
            # hold applies, but that is the organisation's call, and a delete
            # offered here would skip the confidence bar the other delete paths
            # keep. The guided "apply-schedule" procedure covers it.

    elif kind in ("retrieval_hubness", "ingestion_burst", "corpus_duplication") \
            and str(finding.get("severity") or "").lower() != "info" \
            and need_collection("quarantine_chunks"):
        title = str(finding.get("title") or "").lower()
        suspicious = (kind != "corpus_duplication"
                      or "poisoning" in title or "clustered" in title)
        ids = _named_ids(finding)
        if not suspicious:
            refused.append(Withheld("quarantine_chunks", fid,
                                    "Which copy is authoritative is not known to the store; "
                                    "remove the stale copy at its source."))
        elif not ids:
            refused.append(Withheld("quarantine_chunks", fid,
                                    "The finding retained no chunk ids to act on."))
        else:
            reason = "anomalous_embedding" if kind == "retrieval_hubness" else "rare_source"
            count = int(ev.get("chunks") or len(ids))
            made.append(_proposal(
                finding, "tag_review", store=store, kind=kind, chunk_ids=ids,
                params={"reason": reason}, observed=count, basis="statistical",
                rationale=(f"Flags the {len(ids)} named chunk(s) for a person to read; the "
                           "signal is statistical and legitimate content can produce it.")))
            made.append(_proposal(
                finding, "quarantine_chunks", store=store, kind=kind, chunk_ids=ids,
                observed=count, basis="statistical",
                rationale=("For chunks already judged unauthorised: moves them out of "
                           "retrieval, restorably.")))

    elif kind == "chunk_versions" and need_collection("quarantine_chunks"):
        title = str(finding.get("title") or "").lower()
        if "superseded" in title:
            ids = _named_ids(finding, "superseded_ids")
        elif "deleted sources" in title or "older than the current source" in title:
            ids = _named_ids(finding)
        else:
            ids = ()
            refused.append(Withheld("quarantine_chunks", fid,
                                    "Which of the conflicting texts is current is known to "
                                    "the source, not the store."))
        if ids:
            made.append(_proposal(
                finding, "quarantine_chunks", store=store, kind=kind, chunk_ids=ids,
                observed=int(ev.get("superseded_chunks") or ev.get("chunks") or len(ids)),
                basis="check",
                rationale=("Moves the named out-of-date chunks out of retrieval, restorably, "
                           "so the current version is the one returned.")))

    elif kind == "pan_readable" and need_collection("quarantine_collection"):
        made.append(_proposal(
            finding, "quarantine_collection", store=store, kind=kind,
            observed=int(ev.get("records_with_pan") or 0),
            basis="check",
            rationale=("Full card numbers are readable in this collection. Quarantining "
                       "records that it must not be served until the PAN is tokenized.")))
    return made, refused


# --------------------------------------------------------------------------- #
# The catalogue                                                                #
# --------------------------------------------------------------------------- #

def catalogue(finding: dict, *, store_id: str, store_kind: str = "",
              tenant_field: Optional[str] = None,
              include_disputed: bool = False) -> Catalogue:
    """Every remediation for one finding: executable, withheld, and guided.

    ``finding['store']`` is taken to be ``store_id``: a suggestion is staged
    against the registered store, never against the connector's own name.
    """
    fid = str(finding.get("id") or "")
    finding = {**finding, "store": store_id}
    kind = finding_kind(finding)
    result = Catalogue(finding_id=fid, kind=kind)
    if kind == "no_action":
        result.note = "This records a check that passed. There is nothing to remediate."
        return result
    if kind in ("sensitive_data", "prompt_injection"):
        try:
            made, refused = suggest(finding, include_disputed=include_disputed)
        except ActionError as exc:
            made, refused = [], [Withheld("tag_exclude", fid, str(exc))]
        result.suggestions.extend(_with_kind(made, kind))
        result.withheld.extend(refused)
    made, refused = _executable_for(finding, kind, store=store_id,
                                    tenant_field=tenant_field)
    result.suggestions.extend(made)
    result.withheld.extend(refused)
    result.suggestions = recommended_first(result.suggestions, kind)
    result.guided.extend(_guided_for(finding, kind, store_id=store_id,
                                     store_kind=store_kind, tenant_field=tenant_field))
    if not result.suggestions and not result.guided:
        result.note = ("Nothing is catalogued for this finding. Its own recommendation "
                       "is on the Summary tab.")
    return result


#: The executable fix the console offers first for each kind, in order of
#: preference. The first one the catalogue actually proposed leads; the rest
#: keep their order. A preference, not a verdict: every alternative stays
#: listed, and one the store cannot perform is passed over by the console.
RECOMMENDED: dict[str, tuple[str, ...]] = {
    # Removing the value beats hiding the chunk, which beats labelling it.
    "sensitive_data": ("redact_text", "tag_exclude", "label_sensitivity",
                       "quarantine_collection"),
    "prompt_injection": ("quarantine_chunks", "tag_exclude", "label_sensitivity"),
    # An outlier is weak evidence: flag it for a person before moving it.
    "embedding_anomaly": ("tag_review", "quarantine_chunks"),
    "provenance_incomplete": ("tag_provenance",),
    "provenance_rare_source": ("tag_review", "quarantine_chunks"),
    "tenant_untagged": ("assign_tenant", "tag_exclude", "quarantine_chunks"),
    "tenant_convention_only": ("split_by_tenant",),
    "tenant_filter_not_enforced": ("split_by_tenant", "quarantine_collection"),
    "pan_readable": ("quarantine_collection",),
    # Reversible only: a legal hold may still apply to over-limit records, so
    # deleting them is a guided step, not one VecShield offers to run.
    "retention_schedule": ("quarantine_chunks",),
    "retrieval_hubness": ("tag_review", "quarantine_chunks"),
    "ingestion_burst": ("tag_review", "quarantine_chunks"),
    "corpus_duplication": ("tag_review", "quarantine_chunks"),
    "chunk_versions": ("quarantine_chunks",),
}


def recommended_first(suggestions: list[Suggestion], kind: str) -> list[Suggestion]:
    """``suggestions`` with the kind's preferred action first, otherwise stable."""
    order = RECOMMENDED.get(kind, ())
    rank = {action: i for i, action in enumerate(order)}
    return sorted(suggestions, key=lambda s: rank.get(s.action, len(order)))


#: Actions that remove, move or re-tag exactly what the finding's check
#: observes, so a re-scan can stop observing it. Every other action marks or
#: fences the data and leaves it in place, and the check still sees it.
_CLEARS = frozenset({"redact_text", "delete_chunks", "quarantine_chunks", "assign_tenant"})


def rescan_expectation(action: str, *, reaches_all_observed: bool = True) -> dict:
    """What a re-scan should say after ``action`` runs, stated before it runs.

    Said up front so that "still observed" after a tag is the expected answer
    rather than a surprise, and so a tag is never mistaken for a fix.
    """
    if action in _CLEARS and reaches_all_observed:
        return {"rescan_expect": "clears",
                "rescan_text": "Removes what the check observes: a re-scan should stop "
                               "observing the finding."}
    if action in _CLEARS:
        return {"rescan_expect": "partial",
                "rescan_text": "Reaches only the chunks the finding named; a re-scan "
                               "still observes any others."}
    return {"rescan_expect": "contains",
            "rescan_text": "Contains the exposure but leaves the data in place: a re-scan "
                           "still observes the finding."}


def proposal_dict(suggestion: Suggestion) -> dict:
    """A proposal as the API returns it, with what a re-scan should then show."""
    record = suggestion.to_dict()
    return {**record, **rescan_expectation(
        suggestion.action, reaches_all_observed=bool(record.get("reaches_all_observed")))}


def _with_kind(suggestions: list[Suggestion], kind: str) -> list[Suggestion]:
    from dataclasses import replace

    return [replace(s, kind=kind) for s in suggestions]


def catalogue_all(findings: Iterable[dict], *, store_id: str, store_kind: str = "",
                  tenant_field: Optional[str] = None,
                  include_disputed: bool = False) -> list[Catalogue]:
    return [catalogue(f, store_id=store_id, store_kind=store_kind,
                      tenant_field=tenant_field, include_disputed=include_disputed)
            for f in findings]


# --------------------------------------------------------------------------- #
# Verification by re-scan                                                      #
# --------------------------------------------------------------------------- #

#: The checks :func:`rescan` can re-run in-process for one finding.
RESCANNABLE = ("data_classification", "data_representation", "rag_integrity",
               "tenant_isolation", "configuration_posture", "access_control",
               "retrieval_exposure")


@dataclass(frozen=True)
class Rescan:
    """What re-running the check behind one finding observed.

    ``outcome`` is ``resolved`` only when the check ran to completion over the
    finding's scope and the finding's fingerprint was not observed. A check
    that could not see everything is ``inconclusive``, however clean it looks.
    """

    finding_id: str
    fingerprint: str
    check: str
    outcome: str                    # resolved | still_present | inconclusive | unsupported
    job: Any = None
    reason: str = ""
    observed: Optional[dict] = None  # the matching finding in the new run, if any

    def to_dict(self) -> dict:
        return {"finding_id": self.finding_id, "fingerprint": self.fingerprint,
                "check": self.check, "outcome": self.outcome,
                "job_id": getattr(self.job, "id", None), "reason": self.reason,
                "observed": self.observed}


def _complete(job: Any, collection: Optional[str], subcheck: str) -> tuple[bool, str]:
    """Whether the job's own coverage says ``subcheck`` saw everything in scope."""
    outcomes = (getattr(job, "stats", None) or {}).get("check_outcomes") or []
    scoped = [o for o in outcomes
              if (not subcheck or o.get("check") == subcheck)
              and (collection is None or o.get("collection") in (None, collection))]
    if not scoped:
        return False, f"The re-run recorded no outcome for {subcheck or 'this check'}."
    for item in scoped:
        cov = item.get("coverage") or {}
        if item.get("outcome") in ("unsupported", "error", "skipped", "inconclusive") \
                or cov.get("complete") is not True:
            return False, (item.get("reason") or
                           f"The {item.get('check')} check did not complete.")
    return True, ""


def rescan(finding: dict, connector: Any, *, tenant_field: Optional[str] = None,
           classifier: Any = None,
           runners: Optional[dict[str, Callable[..., Any]]] = None,
           controls: Optional[dict] = None) -> Rescan:
    """Re-run the check behind ``finding`` and report whether it is still observed.

    Read-only. ``runners`` replaces the check functions, for tests.
    ``controls`` carries the store's declarations the checks compare against,
    as an assessment passes them: ``retention_schedule``, ``residency_policy``,
    ``processor_register``, ``vuln_feed_dir``, ``source_manifest``. Without
    them a check that needs one cannot complete, and the re-scan says so
    rather than reporting the finding resolved.
    """
    from vecshield_platform.compliance.fingerprint import (apply_fingerprints,
                                                             fingerprint_finding)
    from vecshield.models import Finding, Severity

    kind = finding_kind(finding)
    _, check, subcheck = KINDS.get(kind, KINDS["other"])
    fid = str(finding.get("id") or "")
    collection = finding.get("collection")
    evidence = finding.get("evidence") or {}
    fingerprint = str(finding.get("fingerprint") or evidence.get("fingerprint") or "")

    def logical_fingerprint(store_name: str) -> str:
        """The finding's fingerprint as the re-run's store would record it.

        Findings carry the connector's own name for the store; recomputing
        under the re-run's name compares like with like.
        """
        try:
            return fingerprint_finding(Finding(
                id=fid, title=str(finding.get("title") or ""),
                severity=Severity(str(finding.get("severity") or "info").lower()),
                category=str(finding.get("category") or ""), store=store_name,
                collection=collection, description="", evidence=dict(evidence)))
        except Exception:  # noqa: BLE001
            return ""

    if check not in RESCANNABLE:
        return Rescan(fid, fingerprint, check, "unsupported",
                      reason=("This finding comes from a check that is re-run by a full "
                              "assessment, not from here."))
    runners = runners or {}
    try:
        job = _run(check, connector, collection=collection, tenant_field=tenant_field,
                   classifier=classifier, runner=runners.get(check),
                   controls=controls or {})
    except Exception as exc:  # noqa: BLE001 — a failed re-run is an outcome
        return Rescan(fid, fingerprint, check, "inconclusive",
                      reason=f"The re-run could not complete ({type(exc).__name__}).")
    findings = list(getattr(job, "findings", []) or [])
    apply_fingerprints(findings)
    wanted = {fp for fp in (fingerprint, logical_fingerprint(str(getattr(job, "store", ""))))
              if fp}
    same = [f for f in findings if (f.evidence or {}).get("fingerprint") in wanted]
    # A finding of the same kind on the same collection counts too. A title
    # reworded between versions would otherwise read as "resolved", which is
    # the one wrong answer this check must never give.
    identity = {"api_key": ("key_id",), "cve": ("package", "vuln_id"),
                "server_vulnerability": ("advisory_id", "component"),
                "model_egress": ("provider",),
                "data_residency": ("role", "provider", "region")}.get(kind, ())
    similar = [f for f in findings
               if f.collection == collection and finding_kind(
                   {"category": f.category, "title": f.title,
                    "severity": f.severity.value, "evidence": f.evidence}) == kind
               and all((f.evidence or {}).get(k) == evidence.get(k) for k in identity)]
    hit = (same or similar or [None])[0]
    if hit is not None:
        return Rescan(fid, fingerprint, check, "still_present", job=job,
                      reason=("The re-run observed the same finding" if same else
                              "The re-run observed a finding of the same kind here")
                      + f": {hit.description}",
                      observed={"id": hit.id, "title": hit.title,
                                "severity": hit.severity.value,
                                "description": hit.description})
    complete, why = ((True, "") if check == "access_control"
                     else _complete(job, collection, subcheck))
    if not complete:
        return Rescan(fid, fingerprint, check, "inconclusive", job=job,
                      reason=("The finding was not observed, but the re-run did not see "
                              f"everything it needed to. {why}"))
    return Rescan(fid, fingerprint, check, "resolved", job=job,
                  reason=("The re-run completed over the finding's scope and did not "
                          "observe it."))


def _run(check: str, connector: Any, *, collection: Optional[str],
         tenant_field: Optional[str], classifier: Any, runner: Any,
         controls: Optional[dict] = None) -> Any:
    controls = controls or {}
    if runner is not None:
        return runner(connector, collection=collection, tenant_field=tenant_field)
    if check == "data_classification":
        from vecshield_platform.detection import build_classifier
        from vecshield_platform.scan.engine import scan_store

        return scan_store(connector, classifier=classifier or build_classifier(),
                          retention_schedule=controls.get("retention_schedule"))
    if check == "data_representation":
        from vecshield_platform.crypto.representation import RepresentationObserver
        from vecshield_platform.detection import build_classifier
        from vecshield_platform.scan.engine import scan_store

        observer = RepresentationObserver(collections=connector.describe().collections)
        classified = scan_store(connector, classifier=classifier or build_classifier(),
                                observer=observer)
        return observer.job(connector.describe().name, classification=classified)
    if check == "rag_integrity":
        from vecshield_platform import store_facts
        from vecshield_platform.integrity.engine import scan_integrity

        if not collection:
            raise ActionError("an integrity re-scan needs a collection")
        # The same distance metric the assessment used, or hubness and norm
        # scoring would be judged in a different geometry.
        meta = next((c for c in connector.describe().collections if c.name == collection),
                    None)
        if meta is not None:
            store_facts.fill_distance_metrics(connector, [meta])
        return scan_integrity(connector, collection, collection_meta=meta,
                              source_manifest=controls.get("source_manifest"))
    if check == "tenant_isolation":
        from vecshield_platform.access.isolation import probe_isolation

        if not collection or not tenant_field:
            raise ActionError("an isolation re-scan needs a collection and a tenant field")
        return probe_isolation(connector, collection, tenant_field=tenant_field)
    if check == "configuration_posture":
        from vecshield_platform.posture import run_posture_audit

        return run_posture_audit(connector, cve_offline=False, store_controls=True,
                                 residency_policy=controls.get("residency_policy"),
                                 processor_register=controls.get("processor_register"),
                                 vuln_feed_dir=controls.get("vuln_feed_dir"))
    if check == "retrieval_exposure":
        from vecshield_platform.crypto.retrieval import probe_retrieval_exposure

        return probe_retrieval_exposure(connector, collection, classifier=classifier)
    if check == "access_control":
        from vecshield.models import ScanJob
        from vecshield_platform.access.keyaudit import audit_api_keys

        job = ScanJob(id=f"keys-{uuid.uuid4().hex[:12]}",
                      store=connector.describe().name)
        for found in audit_api_keys(connector.list_api_keys(),
                                    store_name=connector.describe().name):
            job.add(found)
        return job
    raise ActionError(f"no re-run for {check}")


__all__ = ["KINDS", "finding_kind", "Guided", "Setting", "Catalogue", "catalogue",
           "RECOMMENDED", "recommended_first", "rescan_expectation", "proposal_dict",
           "catalogue_all", "Rescan", "rescan", "RESCANNABLE", "SOURCE_KEYS"]
