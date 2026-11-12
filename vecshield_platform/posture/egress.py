"""Model egress: the database sending chunk text to an outside AI provider.

Several vector databases call an embedding, reranking or generative model on
their own — a Weaviate vectorizer module, an Azure AI Search vectorizer, an
OpenSearch ML Commons connector, a Milvus embedding function, MongoDB
Automated Embedding. The text then leaves the store without passing through
the customer's code, and the provider becomes a recipient (GDPR Art. 28
sub-processor, HIPAA business associate, CCPA service provider) that the
customer's own records may not show.

The connector reports what the store is configured to do
(``model_integrations()``, capability ``egress_introspection``, answered by the
connector itself or by its kind's ``store_facts`` adapter). This module
joins that with the sensitive labels the data scan found per collection and
with the customer's declared sub-processor register, and decides:

* **Who receives the text.** Each integration is classed as a
  ``third_party_processor`` (a company other than the store's operator and the
  customer's own cloud tenant), ``customer_cloud_service`` (a model service in
  the customer's own account: Azure OpenAI, Bedrock, Vertex AI),
  ``store_operator`` (the store's own operator runs the model: Pinecone
  Inference for a Pinecone index) or ``local`` (a model the customer runs).
  The provider registry is ``data/model_providers.json``.

* **How bad an undeclared flow is.** Severity follows what the collection
  holds, because that decides which regime the disclosure engages:

  - secrets → HIGH: a credential sent to a provider is a credential disclosed.
  - PHI → HIGH unless the provider is declared with a BAA: a covered entity may
    disclose PHI to a business associate only under a BAA (45 CFR 164.502(e),
    164.308(b)); without one the disclosure itself is the violation.
  - PCI → HIGH: cardholder data sent to a provider brings it into PCI DSS scope.
  - special category / criminal offence data → HIGH: GDPR Art. 9 and 10
    processing needs its own condition on top of Art. 28 terms.
  - other personal data → MEDIUM: an Art. 28 contract and a register entry are
    the gap, not the processing itself.

  A flow to the store's own operator is capped at MEDIUM: no new company
  receives the text, but the model service may sit outside the agreement that
  covers the database.

* **What the customer declared.** A provider in the register with a DPA (and a
  BAA where PHI flows) turns the finding into an INFO record: the flow is known
  and papered. The check still lists it.

What this module never does: guess. A connector that cannot read the store's
model configuration yields an ``inconclusive`` outcome with evidence to
supply; a database with no store-side model features at all yields
``unsupported`` marked ``capability_limit``. Neither is a failure. Evidence
never carries a secret: API keys, header values and anything that looks like a
key are dropped before a finding is built.
"""

from __future__ import annotations

import json
import re
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlparse

from vecshield.models import Finding, Severity
from vecshield_platform.connectors.base import ConnectorAuthError, UnsupportedCapability
from vecshield_platform.coverage import check_outcome
from vecshield_platform.posture.network import classify_endpoint

CHECK = "model_egress"
CATEGORY = "model_egress"
CAPABILITY = "egress_introspection"

THIRD_PARTY = "third_party_processor"
CUSTOMER_CLOUD = "customer_cloud_service"
STORE_OPERATOR = "store_operator"
LOCAL = "local"
CLASSES = (THIRD_PARTY, CUSTOMER_CLOUD, STORE_OPERATOR, LOCAL)

#: Manual evidence names this check asks for. Criteria and the console use
#: these names; keep them stable.
SUB_PROCESSOR_REGISTER = "sub_processor_register"
DATA_PROCESSING_AGREEMENT = "data_processing_agreement"
BUSINESS_ASSOCIATE_AGREEMENT = "business_associate_agreement"

#: Labels that make a flow a disclosure worth reporting. ``source_code`` is not
#: personal data and is left out; ``none`` is not a label.
SENSITIVE_LABELS = ("secret", "phi", "pci", "special_category", "criminal_offence", "pii")

_DATA_DIR = Path(__file__).with_name("data")

_RANK = {s: s.rank for s in Severity}


@lru_cache(maxsize=None)
def _load(name: str) -> dict:
    with (_DATA_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


def provider_registry() -> dict:
    """The provider registry (``data/model_providers.json``)."""
    return _load("model_providers.json")


def egress_support() -> dict:
    """Per-kind store-side model support and remediation (``data/egress_support.json``)."""
    return _load("egress_support.json")


def support_for(kind: str) -> dict:
    entry = egress_support()["stores"].get((kind or "").lower())
    if entry is not None:
        return entry
    return {"database": kind or "Unknown store", "store_side_models": "unknown",
            "features": None, "remediation": {}, "sources": []}


# --------------------------------------------------------------------------- #
# Secret-free evidence                                                         #
# --------------------------------------------------------------------------- #

_SECRET_KEY = re.compile(
    r"(api[_-]?key|apikey|secret|token|password|passwd|authorization|credential|"
    r"bearer|signature|private[_-]?key|access[_-]?key|subscription[_-]?key|"
    r"(?:^|[_-])sas(?:$|[_-])|^headers?$|cookie)",
    re.IGNORECASE)
#: Values that look like a key whatever field they are in: provider-prefixed
#: keys, JWTs, AWS access key ids.
_SECRET_VALUE = re.compile(
    r"(sk-[A-Za-z0-9_\-]{8,}|pk-[A-Za-z0-9_\-]{8,}|hf_[A-Za-z0-9]{8,}|nvapi-[A-Za-z0-9_\-]{8,}|"
    r"AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]+)?)")
#: Long unbroken runs of key-like characters that mix letters and digits. A
#: resource path (``projects/x/locations/y``) has separators and is kept.
_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9+=_\-])[A-Za-z0-9+=_\-]{32,}(?![A-Za-z0-9+=_\-])")
_REDACTED = "[redacted]"


def _redact_text(text: str) -> str:
    text = _SECRET_VALUE.sub(_REDACTED, text)

    def _long(m: re.Match) -> str:
        token = m.group(0)
        mixed = re.search(r"[A-Za-z]", token) and re.search(r"\d", token)
        return _REDACTED if mixed else token
    return _LONG_TOKEN.sub(_long, text)


def scrub(value: Any, _depth: int = 0) -> Any:
    """A copy of ``value`` with anything secret-like removed.

    Keys whose name suggests a credential are dropped outright; string values
    that look like a key are replaced. Connectors are already asked to drop
    secrets; this is the second fence, because a finding is stored, exported
    and shown to people who may not hold the key.
    """
    if _depth > 6:
        return None
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            if key.lower() == "auth":  # the contract's enumeration, not a secret
                out[key] = v if v in ("managed_identity", "api_key", "none", "unknown") else _REDACTED
                continue
            if _SECRET_KEY.search(key):
                continue
            out[key] = scrub(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [scrub(v, _depth + 1) for v in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _host_only(value: Any) -> Optional[str]:
    """Hostname from whatever the connector reported; userinfo, path and query dropped."""
    if not value:
        return None
    text = str(value).strip()
    parsed = urlparse(text if "://" in text else f"//{text}")
    host = (parsed.hostname or "").strip(".").lower()
    return host or None


# --------------------------------------------------------------------------- #
# Provider resolution                                                          #
# --------------------------------------------------------------------------- #

def _norm(name: Any) -> str:
    return str(name or "").strip().lower().replace(" ", "_")


def _provider_from_host(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    for pid, entry in provider_registry()["providers"].items():
        if host in (entry.get("hosts") or []) or host in (entry.get("regional_hosts") or {}):
            return pid
        if any(host.endswith(s) for s in entry.get("host_suffixes") or []):
            return pid
        if any(re.match(p, host) for p in entry.get("host_patterns") or []):
            return pid
    return None


def resolve_provider(provider: Any, endpoint_host: Optional[str] = None) -> tuple[str, dict]:
    """Registry id and entry for a reported provider, using the host to disambiguate.

    ``google`` alone is ambiguous (Vertex AI in the customer's project, or the
    Gemini API, a third party); it resolves by host, and without one it stays
    an unidentified provider rather than being assumed to be the safer one.
    """
    registry = provider_registry()
    providers, aliases = registry["providers"], registry["aliases"]
    name = _norm(provider)
    name = aliases.get(name, name)
    by_host = _provider_from_host(endpoint_host)
    if name in providers and name != "unknown":
        # A host that names a different provider wins only for ambiguous names.
        return name, providers[name]
    if by_host:
        return by_host, providers[by_host]
    if name == "google":
        entry = dict(providers["unknown"])
        entry["display_name"] = "Google (Vertex AI or Gemini API: not determinable)"
        return "google_unresolved", entry
    return "unknown", providers["unknown"]


def _store_operators(store: Any, kind: str) -> set[str]:
    """Operator ids that already hold the store's data."""
    host = _host_only(getattr(store, "endpoint", None)) or ""
    ops: set[str] = set()
    if kind == "pinecone":
        ops.add("pinecone")
    if kind == "openai":
        ops.add("openai")
    if kind == "mongodb" and host.endswith(".mongodb.net"):
        ops.add("mongodb_atlas")
    if kind == "qdrant" and host.endswith(".cloud.qdrant.io"):
        ops.add("qdrant_cloud")
    if kind == "weaviate" and (host.endswith(".weaviate.cloud") or host.endswith(".weaviate.network")):
        ops.add("weaviate_cloud")
    return ops


def classify_integration(provider_id: str, entry: dict, *, endpoint_host: Optional[str],
                         store_operators: set[str]) -> tuple[str, list[str]]:
    """The recipient class and any notes that qualify it."""
    notes: list[str] = []
    klass = entry.get("class", THIRD_PARTY)
    same = set(entry.get("same_operator_as") or [])
    if provider_id in store_operators or (same & store_operators):
        klass = STORE_OPERATOR
    if provider_id == "openai" and "openai" in store_operators:
        klass = STORE_OPERATOR
    if endpoint_host:
        exposure = classify_endpoint(endpoint_host, resolve=False).exposure
        if exposure in ("private", "local"):
            if provider_id in ("unknown", "google_unresolved"):
                klass = LOCAL
                notes.append("The endpoint is a private or local host; treated as a model "
                             "the customer runs.")
            elif klass != LOCAL:
                notes.append("The endpoint is a private host (a gateway or proxy?). Where it "
                             "forwards the text is not visible here.")
    return klass, notes


# --------------------------------------------------------------------------- #
# Declared processors                                                          #
# --------------------------------------------------------------------------- #

def _declared_index(declared: Optional[list[dict]]) -> dict[str, dict]:
    aliases = provider_registry()["aliases"]
    out: dict[str, dict] = {}
    for item in declared or []:
        if not isinstance(item, dict) or not item.get("provider"):
            continue
        pid = _norm(item["provider"])
        pid = aliases.get(pid, pid)
        out[pid] = {"dpa": item.get("dpa") is True, "baa": item.get("baa") is True,
                    "regions": [str(r) for r in item.get("regions") or []]}
    return out


# --------------------------------------------------------------------------- #
# Severity                                                                     #
# --------------------------------------------------------------------------- #

def _present(labels: dict[str, int]) -> list[str]:
    return [lbl for lbl in SENSITIVE_LABELS if int(labels.get(lbl) or 0) > 0]


def flow_severity(labels: list[str], *, klass: str, baa_declared: bool) -> tuple[Severity, str]:
    """Severity of an undeclared flow of ``labels`` and the rule that set it."""
    if not labels or klass in (LOCAL, CUSTOMER_CLOUD):
        return Severity.INFO, "no sensitive data leaves the customer's control"
    if "secret" in labels:
        sev, why = Severity.HIGH, "credentials are sent to the provider"
    elif "phi" in labels and not baa_declared:
        sev, why = Severity.HIGH, "PHI is sent to a provider with no declared BAA"
    elif "pci" in labels:
        sev, why = Severity.HIGH, "cardholder data is sent to the provider"
    elif "special_category" in labels or "criminal_offence" in labels:
        sev, why = Severity.HIGH, "special-category or criminal-offence data is sent to the provider"
    else:
        sev, why = Severity.MEDIUM, "personal data is sent to a provider not in the sub-processor register"
    if klass == STORE_OPERATOR and sev.rank > Severity.MEDIUM.rank:
        sev = Severity.MEDIUM
        why += " (capped: the store's own operator runs the model)"
    return sev, why


# --------------------------------------------------------------------------- #
# OpenSearch trusted endpoints                                                 #
# --------------------------------------------------------------------------- #

_ARBITRARY_PROBES = ("https://vecshield-egress-probe.invalid/v1/embeddings",
                     "https://203.0.113.7/v1/embeddings")
_PLAINTEXT_PROBES = ("http://vecshield-egress-probe.invalid/v1/embeddings",
                     "http://api.openai.com/v1/embeddings",
                     "http://api.cohere.ai/v1/embed",
                     "http://bedrock-runtime.us-east-1.amazonaws.com/model/x/invoke")


def evaluate_trusted_endpoints(patterns: Iterable[Any]) -> dict:
    """Which allow-list patterns admit any host, or plaintext HTTP.

    A pattern is judged by full match against probe URLs, the strictest reading
    of how the allow-list is applied, so a pattern reported here admits the
    probe under any reading. A pattern Python cannot compile is listed as not
    evaluated rather than guessed at.
    """
    over_broad, plaintext, not_evaluated, evaluated = [], [], [], []
    for raw in patterns or []:
        text = str(raw)
        try:
            rx = re.compile(text)
        except re.error:
            not_evaluated.append(text)
            continue
        evaluated.append(text)
        if any(rx.fullmatch(p) for p in _ARBITRARY_PROBES):
            over_broad.append(text)
        if any(rx.fullmatch(p) for p in _PLAINTEXT_PROBES):
            plaintext.append(text)
    return {"evaluated": evaluated, "over_broad": over_broad, "plaintext": plaintext,
            "not_evaluated": not_evaluated}


# --------------------------------------------------------------------------- #
# The check                                                                    #
# --------------------------------------------------------------------------- #

def _capabilities(connector: Any) -> set[str]:
    """Store-fact capabilities: the connector's own method or its kind's adapter.

    ``store_facts`` answers ``model_integrations()`` for connectors that do not
    implement it themselves, so the connector's ``capabilities()`` alone would
    under-report what can be read.
    """
    from vecshield_platform import store_facts

    try:
        return set(store_facts.supported(connector))
    except Exception:  # noqa: BLE001 - a connector that cannot say supports nothing extra
        return set()


def _finding(store: str, collection: Optional[str], title: str, severity: Severity,
             description: str, evidence: dict, remediation: str) -> Finding:
    return Finding(id=f"find-{uuid.uuid4().hex[:10]}", title=title, severity=severity,
                   category=CATEGORY, store=store, collection=collection,
                   description=description, evidence=scrub(evidence), remediation=remediation)


def _provider_context(entry: dict) -> dict:
    """Documented statements for a reviewer; each keeps its source URL."""
    return {k: entry.get(k) for k in ("operator", "legal_entity", "training_use", "retention",
                                      "baa", "eu_residency") if entry.get(k) is not None}


def _not_assessed(store_name: str, kind: str, *, outcome: str, reason: str,
                  capability_limit: bool = False, **extra: Any) -> tuple[list[Finding], dict]:
    entry = support_for(kind)
    details: dict[str, Any] = {
        "database": entry.get("database"),
        "store_side_models": entry.get("store_side_models"),
        "flows": [],
        "evidence_to_supply": [SUB_PROCESSOR_REGISTER],
        "sources": list(entry.get("sources") or []),
        **extra,
    }
    if capability_limit:
        details["capability_limit"] = True
    else:
        details["evidence_to_supply"].append("model_integration_configuration")
    return [], check_outcome(CHECK, store_name, None, outcome=outcome, reason=reason,
                             complete=False, **details)


def assess_model_egress(connector: Any, store: Any, *,
                        sensitive_labels_by_collection: dict[str, dict[str, int]],
                        declared_processors: Optional[list[dict]] = None,
                        integrations_reader: Optional[Callable[[], Any]] = None,
                        ) -> tuple[list[Finding], dict]:
    """Findings and one store-level ``model_egress`` outcome.

    ``sensitive_labels_by_collection`` maps collection → ``{label: chunk count}``
    as the data-classification scan recorded it (``label_counts``). A collection
    missing from the map was not scanned: its flows are "labels unknown", which
    keeps the check from passing but never fails it. ``declared_processors`` is
    the customer's sub-processor register: ``[{provider, dpa, baa, regions}]``.
    ``integrations_reader`` returns the ``model_integrations()`` report (or
    raises its failure); an assessment passes one that replays the report it
    already gathered, so the store is asked once. The default reads it through
    ``store_facts``.
    """
    store_name = getattr(store, "name", None) or str(store or "")
    kind = (getattr(connector, "kind", None) or getattr(store, "kind", "") or "").lower()
    support = support_for(kind)
    database = support.get("database")

    if CAPABILITY not in _capabilities(connector):
        if support.get("store_side_models") is False:
            return _not_assessed(
                store_name, kind, outcome="unsupported", capability_limit=True,
                reason=support.get("not_supported_reason")
                or f"{database} has no store-side model integrations.")
        return _not_assessed(
            store_name, kind, outcome="inconclusive",
            reason=f"{database} can call model providers itself, but this connector cannot "
                   "read that configuration. Supply the store's model configuration and "
                   "your sub-processor register.")

    if integrations_reader is None:
        from vecshield_platform import store_facts

        def integrations_reader() -> Any:
            return store_facts.model_integrations(connector)
    try:
        report = integrations_reader()
    except UnsupportedCapability:
        return _not_assessed(
            store_name, kind, outcome="inconclusive",
            reason=f"This connector cannot read {database or 'the store'}'s model "
                   "integration settings. This is not evidence that no model is called.")
    except ConnectorAuthError:
        return _not_assessed(
            store_name, kind, outcome="inconclusive",
            reason="The credential cannot read the store's model integration settings "
                   "(permission denied). This is not evidence that no model is called.")
    except Exception as exc:  # noqa: BLE001 - an audit never crashes on one store call
        _, record = _not_assessed(
            store_name, kind, outcome="error",
            reason=f"Model integrations could not be read ({type(exc).__name__}).")
        return [], record

    if not isinstance(report, dict):
        return _not_assessed(store_name, kind, outcome="error",
                             reason="The connector returned no model-integration report.")
    if report.get("observable") is not True:
        reason = str(report.get("reason") or "The store did not report its model integrations.")
        return _not_assessed(store_name, kind, outcome="inconclusive",
                             reason=reason + " This is not evidence that no model is called.",
                             source=report.get("source"))

    declared = _declared_index(declared_processors)
    operators = _store_operators(store, kind)
    remediation = support.get("remediation") or {}
    findings: list[Finding] = []
    flows: list[dict] = []

    # ---- normalise and group integrations -------------------------------- #
    grouped: dict[tuple[Optional[str], str], dict] = {}
    for raw in report.get("integrations") or []:
        if not isinstance(raw, dict):
            continue
        host = _host_only(raw.get("endpoint_host"))
        pid, entry = resolve_provider(raw.get("provider"), host)
        klass, notes = classify_integration(pid, entry, endpoint_host=host,
                                            store_operators=operators)
        collection = raw.get("collection") or None
        key = (collection, pid)
        g = grouped.setdefault(key, {
            "collection": collection, "provider": pid,
            "provider_name": entry.get("display_name") or pid, "class": klass,
            "stages": [], "models": [], "modules": [], "endpoint_hosts": [], "auth": [],
            "notes": [], "entry": entry, "evidence": []})
        for field, value in (("stages", raw.get("stage")), ("models", raw.get("model")),
                             ("modules", raw.get("module")), ("endpoint_hosts", host),
                             ("auth", raw.get("auth") or "unknown")):
            if value and value not in g[field]:
                g[field].append(value)
        g["notes"].extend(n for n in notes if n not in g["notes"])
        g["evidence"].append(scrub(raw.get("evidence") or {}))

    used_providers = {pid for (col, pid) in grouped if col is not None}
    blocking_high = 0
    open_medium = 0
    unknown_labels = 0
    configured_unused: list[dict] = []
    api_key_integrations: list[dict] = []

    for (collection, pid), g in sorted(grouped.items(), key=lambda kv: (kv[0][0] or "", kv[0][1])):
        klass, entry = g["class"], g["entry"]
        decl = declared.get(pid)
        if collection is None:
            if pid not in used_providers and klass != LOCAL:
                configured_unused.append(g)
            if "api_key" in g["auth"] and klass != LOCAL:
                api_key_integrations.append(g)
            flows.append(_flow_record(g, labels=[], declared=bool(decl and decl["dpa"]),
                                      status="configured_not_observed_in_use"))
            continue

        if "api_key" in g["auth"] and klass != LOCAL:
            api_key_integrations.append(g)

        if collection not in sensitive_labels_by_collection:
            labels: list[str] = []
            label_status = "unknown"
        else:
            labels = _present(sensitive_labels_by_collection.get(collection) or {})
            label_status = "observed"

        needs_baa = "phi" in labels
        covered = bool(decl and decl["dpa"] and (decl["baa"] or not needs_baa))
        status = "no_sensitive_labels"
        if klass in (LOCAL, CUSTOMER_CLOUD):
            status = "within_customer_control"
        elif label_status == "unknown":
            status = "labels_unknown"
            if not covered:
                unknown_labels += 1
        elif labels:
            sev, rule = flow_severity(labels, klass=klass, baa_declared=bool(decl and decl["baa"]))
            asks = [SUB_PROCESSOR_REGISTER, DATA_PROCESSING_AGREEMENT]
            if needs_baa:
                asks.append(BUSINESS_ASSOCIATE_AGREEMENT)
            if covered and decl is not None:
                status = "declared"
                findings.append(_declared_finding(store_name, collection, g, labels, decl))
            else:
                status = "undeclared"
                if sev == Severity.HIGH:
                    blocking_high += 1
                else:
                    open_medium += 1
                findings.append(_flow_finding(store_name, collection, g, labels, sev, rule,
                                              decl, asks, remediation, database))
        flows.append(_flow_record(g, labels=labels, declared=covered, status=status,
                                  label_status=label_status))

    if configured_unused:
        findings.append(_configured_unused_finding(store_name, configured_unused, remediation,
                                                   database))
    if api_key_integrations:
        findings.append(_api_key_finding(store_name, api_key_integrations, remediation, database))

    controls = report.get("controls") or {}
    trusted = None
    if isinstance(controls, dict) and "trusted_endpoints" in controls:
        trusted = evaluate_trusted_endpoints(controls.get("trusted_endpoints") or [])
        if trusted["over_broad"] or trusted["plaintext"]:
            findings.append(_trusted_endpoint_finding(store_name, trusted, remediation, database))

    # ---- outcome ----------------------------------------------------------- #
    evidence_to_supply: list[str] = []
    for f in findings:
        for item in f.evidence.get("evidence_to_supply") or []:
            if item not in evidence_to_supply:
                evidence_to_supply.append(item)
    if unknown_labels and SUB_PROCESSOR_REGISTER not in evidence_to_supply:
        evidence_to_supply.append(SUB_PROCESSOR_REGISTER)

    third_party_flows = [f for f in flows if f["class"] in (THIRD_PARTY, STORE_OPERATOR)
                         and f["collection"] is not None]
    if blocking_high:
        outcome, complete = "failed", True
        reason = (f"{blocking_high} undeclared flow(s) send high-risk data (PHI without a "
                  "BAA, cardholder data, special-category data or secrets) from this store "
                  "to an outside model provider.")
    elif open_medium or unknown_labels:
        outcome, complete = "inconclusive", False
        parts = []
        if open_medium:
            parts.append(f"{open_medium} flow(s) send personal data to a provider not in the "
                         "sub-processor register")
        if unknown_labels:
            parts.append(f"{unknown_labels} flow(s) come from collections this run did not "
                         "classify")
        reason = "; ".join(parts) + ". Declare the providers or supply the register."
    else:
        outcome, complete = "passed", True
        reason = ("No store-side model integration was reported." if not flows else
                  "Every store-side model flow stays local or in the customer's cloud, carries "
                  "no sensitive data, or goes to a declared processor.")
        config = [f for f in findings if f.severity.rank >= Severity.LOW.rank]
        if config:
            reason += (f" {len(config)} configuration finding(s) (unused integrations, stored "
                       "keys or endpoint allow-list) are raised separately.")

    details = {
        "database": database,
        "store_side_models": support.get("store_side_models"),
        "source": report.get("source"),
        "flows": flows,
        "third_party_flows": len(third_party_flows),
        "controls": {"trusted_endpoints": trusted} if trusted is not None else {},
        "declared_processors": sorted(declared),
        "evidence_to_supply": evidence_to_supply,
        "sources": list(support.get("sources") or []),
    }
    return findings, check_outcome(CHECK, store_name, None, outcome=outcome, reason=reason,
                                   complete=complete, **details)


def _flow_record(g: dict, *, labels: list[str], declared: bool, status: str,
                 label_status: str = "not_applicable") -> dict:
    return {
        "collection": g["collection"],
        "stage": ", ".join(g["stages"]) or None,
        "stages": list(g["stages"]),
        "provider": g["provider"],
        "provider_name": g["provider_name"],
        "class": g["class"],
        "model": ", ".join(g["models"]) or None,
        "module": ", ".join(g["modules"]) or None,
        "endpoint_host": ", ".join(g["endpoint_hosts"]) or None,
        "auth": ", ".join(g["auth"]) or "unknown",
        "labels": labels,
        "label_status": label_status,
        "declared": declared,
        "status": status,
        "notes": list(g["notes"]),
    }


def _where(g: dict) -> str:
    stages = "/".join(g["stages"]) or "use"
    return f"{g['provider_name']} ({stages})"


def _flow_finding(store: str, collection: str, g: dict, labels: list[str], severity: Severity,
                  rule: str, decl: Optional[dict], asks: list[str], remediation: dict,
                  database: Optional[str]) -> Finding:
    entry = g["entry"]
    who = {THIRD_PARTY: "an outside provider",
           STORE_OPERATOR: "a model service run by the store's own operator"}.get(g["class"], "a provider")
    missing = []
    if not decl:
        missing.append("the provider is not in the declared sub-processor register")
    else:
        if not decl["dpa"]:
            missing.append("no DPA is declared")
        if "phi" in labels and not decl["baa"]:
            missing.append("no BAA is declared")
    description = (
        f"{database or 'The store'} sends text from collection '{collection}' to "
        f"{_where(g)}, {who}. The collection holds {', '.join(labels)} data; "
        f"{'; '.join(missing)}. Severity: {rule}. The integration is configured in the "
        "store; VecShield did not observe individual requests.")
    for note in g["notes"]:
        description += " " + note
    fix = remediation.get("third_party") or ("Embed client-side, use a model in your own "
                                             "cloud tenant, or declare the provider.")
    fix += (" If the flow is intended, add the provider to the sub-processor register with "
            "its DPA" + (" and a signed BAA" if "phi" in labels else "") + ".")
    return _finding(
        store, collection,
        f"Collection '{collection}' sends {', '.join(labels).upper()} data to {g['provider_name']}",
        severity, description,
        {"provider": g["provider"], "provider_name": g["provider_name"], "class": g["class"],
         "stages": g["stages"], "models": g["models"], "modules": g["modules"],
         "endpoint_hosts": g["endpoint_hosts"], "auth": g["auth"], "labels": labels,
         "declared": decl or None, "severity_rule": rule, "evidence_to_supply": asks,
         "provider_documentation": _provider_context(entry),
         "connector_evidence": g["evidence"]},
        fix)


def _declared_finding(store: str, collection: str, g: dict, labels: list[str],
                      decl: dict) -> Finding:
    return _finding(
        store, collection,
        f"Collection '{collection}' sends data to declared processor {g['provider_name']}",
        Severity.INFO,
        f"Text from collection '{collection}' ({', '.join(labels)}) goes to {_where(g)}. The "
        "provider is in the declared sub-processor register with a DPA"
        + (" and a BAA" if decl.get("baa") else "") + ". Recorded for the register; not a gap.",
        {"provider": g["provider"], "class": g["class"], "stages": g["stages"],
         "models": g["models"], "labels": labels, "declared": decl,
         "provider_documentation": _provider_context(g["entry"])},
        "Keep the register entry and agreements current.")


def _configured_unused_finding(store: str, groups: list[dict], remediation: dict,
                               database: Optional[str]) -> Finding:
    names = sorted({g["provider_name"] for g in groups})
    modules = sorted({m for g in groups for m in g["modules"]})
    return _finding(
        store, None,
        f"Model integrations configured but not observed in use on '{store}'",
        Severity.LOW,
        f"{database or 'The store'} has {len(groups)} store-wide model integration(s) enabled "
        f"that no collection was seen using: {', '.join(names)}. Configured is not the same "
        "as used; an enabled integration is one schema change away from sending data.",
        {"providers": sorted({g['provider'] for g in groups}), "modules": modules,
         "evidence_to_supply": []},
        remediation.get("configured_unused") or "Disable integrations you do not use.")


def _api_key_finding(store: str, groups: list[dict], remediation: dict,
                     database: Optional[str]) -> Finding:
    names = sorted({g["provider_name"] for g in groups})
    return _finding(
        store, None,
        f"Model provider API keys held in '{store}' configuration",
        Severity.LOW,
        f"{database or 'The store'} authenticates to {', '.join(names)} with an API key held in "
        "its own configuration. Anyone who can read or export that configuration holds the "
        "key. The key itself is not recorded here.",
        {"providers": sorted({g['provider'] for g in groups}),
         "collections": sorted({g["collection"] for g in groups if g["collection"]}),
         "evidence_to_supply": []},
        remediation.get("api_key_auth") or "Use a managed identity or keep keys in a secret "
                                           "manager, and rotate keys that were stored.")


def _trusted_endpoint_finding(store: str, trusted: dict, remediation: dict,
                              database: Optional[str]) -> Finding:
    problems = []
    if trusted["over_broad"]:
        problems.append(f"{len(trusted['over_broad'])} pattern(s) admit any host")
    if trusted["plaintext"]:
        problems.append(f"{len(trusted['plaintext'])} pattern(s) admit plaintext http://")
    return _finding(
        store, None,
        f"Trusted model endpoint allow-list on '{store}' is over-broad",
        Severity.MEDIUM,
        f"{database or 'The store'}'s allow-list for model connector endpoints is meant to "
        f"restrict where the cluster may send data; {' and '.join(problems)}. A connector "
        "created by anyone with connector rights can then send indexed text to an arbitrary "
        "server.",
        {"over_broad": trusted["over_broad"], "plaintext": trusted["plaintext"],
         "not_evaluated": trusted["not_evaluated"], "evidence_to_supply": []},
        remediation.get("trusted_endpoints") or "Restrict the allow-list to anchored HTTPS "
                                                 "patterns for approved hosts.")
