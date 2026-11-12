"""Data residency: where the store keeps its data, and where its models send it.

Three questions, answered only from what the provider's own API reports:

1. **Where is the data?** The connector's ``store_location()`` names the
   provider and region exactly as the provider reports them. The region is
   mapped to a country with ``data/cloud_regions.json``, built from each
   cloud's official region list. A region missing from the catalogue is
   reported as unknown, never guessed; IP geolocation is never used.

2. **Is that inside the customer's policy?** The policy is the customer's own
   declaration (allowed regions, countries or jurisdictions, and the data
   subject regimes that apply). A location outside it fails the check. Where
   GDPR or UK GDPR applies, the severity depends on whether the destination
   has an adequacy finding (``data/transfer_adequacy.json``): none means a
   transfer mechanism (SCCs, the UK IDTA or Addendum) is needed and is asked
   for as evidence; the US is only ever ``conditional_dpf``, because the Data
   Privacy Framework covers certified organisations, which VecShield cannot
   verify.

3. **Where do the store's own model calls go?** Integrations from
   ``model_integrations()`` are located only from what is reported (an Azure
   OpenAI resource region, a Bedrock runtime host) or from a documented
   regional endpoint (OpenAI's ``eu.api.openai.com``, Vertex AI's EU
   multi-region host). Everything else is "destination not observable", which
   is never a failure.

It also flags the US DOJ Data Security Program (28 CFR Part 202) bulk
thresholds when distinct-subject counts reach them. That finding is
informational: VecShield cannot see who has access to the data, which is what
decides whether a transaction is restricted or prohibited.
"""

from __future__ import annotations

import json
import re
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Optional

from vecshield.models import Finding, Severity
from vecshield_platform.coverage import check_outcome
from vecshield_platform.posture.egress import resolve_provider

CHECK = "data_residency"
CATEGORY = "data_residency"
CAPABILITY = "location_introspection"

DATA_RESIDENCY_STATEMENT = "data_residency_statement"
TRANSFER_MECHANISM = "transfer_mechanism"

_DATA_DIR = Path(__file__).with_name("data")

#: Regimes this module has adequacy data for. Others are recorded, not graded.
ADEQUACY_REGIMES = ("GDPR", "UK_GDPR")

#: Hyperscaler for model services whose reported region is a cloud region id.
_PROVIDER_CLOUD = {"azure_openai": "azure", "aws_bedrock": "aws", "google_vertex": "gcp"}


@lru_cache(maxsize=None)
def _load(name: str) -> dict:
    with (_DATA_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


def region_catalogue() -> dict:
    return _load("cloud_regions.json")


def adequacy_data() -> dict:
    return _load("transfer_adequacy.json")


def doj_data() -> dict:
    return _load("us_doj_dsp.json")


# --------------------------------------------------------------------------- #
# Countries and jurisdictions                                                  #
# --------------------------------------------------------------------------- #

def _country_code(value: Any) -> str:
    code = str(value or "").strip().upper()
    return "GB" if code == "UK" else code


def eu_members() -> frozenset[str]:
    return frozenset(region_catalogue()["jurisdictions"]["EU"])


def eea_members() -> frozenset[str]:
    j = region_catalogue()["jurisdictions"]
    return frozenset(j["EU"]) | frozenset(j["EEA_NON_EU"])


def jurisdictions_for(country: str) -> list[str]:
    """Tags a policy can name for a country: the ISO code, plus EU/EEA, plus UK for GB."""
    code = _country_code(country)
    if not code:
        return []
    tags = [code]
    if code in eu_members():
        tags += ["EU", "EEA"]
    elif code in eea_members():
        tags.append("EEA")
    if code == "GB":
        tags.append("UK")
    return tags


def _jurisdiction_countries(tag: str) -> Optional[frozenset[str]]:
    """Countries a jurisdiction tag covers, or None for an unknown tag."""
    t = str(tag or "").strip().upper()
    if t == "EU":
        return eu_members()
    if t == "EEA":
        return eea_members()
    if t == "UK":
        return frozenset({"GB"})
    if re.fullmatch(r"[A-Z]{2}", t):
        return frozenset({t})
    return None


# --------------------------------------------------------------------------- #
# Region resolution                                                            #
# --------------------------------------------------------------------------- #

#: Spellings of the three hyperscalers a connector may report.
_CLOUD_ALIASES = {"google": "gcp", "google_cloud": "gcp", "gcp": "gcp", "amazon": "aws",
                  "amazon_web_services": "aws", "aws": "aws", "microsoft": "azure",
                  "microsoft_azure": "azure", "azure": "azure"}


def _norm_region(cloud: str, region: str) -> str:
    r = str(region or "").strip().lower()
    if cloud == "azure":
        r = r.replace(" ", "")  # "West Europe" → "westeurope", the programmatic name
    return r


def resolve_region(provider: Any, region: Any, *, cloud: Any = None) -> Optional[dict]:
    """Country and jurisdictions for a region id, or None when it is not in the catalogue.

    ``provider`` is the hosting provider the connector reported. For a service
    that places data in a hyperscaler region under the same identifier
    (Pinecone), ``provider_regions`` maps it; for others the connector may pass
    the hosting ``cloud`` it read from the provider's API. Nothing else is
    inferred.
    """
    if not region:
        return None
    cat = region_catalogue()
    clouds = cat["clouds"]
    prov = str(provider or "").strip().lower()
    prov = _CLOUD_ALIASES.get(prov, prov)
    hint = str(cloud or "").strip().lower()
    hint = _CLOUD_ALIASES.get(hint, hint)
    target: Optional[tuple[str, str]] = None
    if prov in clouds:
        target = (prov, _norm_region(prov, region))
    elif prov in cat["provider_regions"] and prov != "_about":
        mapped = cat["provider_regions"][prov].get(str(region).strip().lower())
        if mapped:
            c, r = mapped.split(":", 1)
            target = (c, r)
    if target is None and hint in clouds:
        target = (hint, _norm_region(hint, region))
    if target is None:
        return None
    c, r = target
    rec = clouds[c].get(r)
    if rec is None:
        return None
    country = rec["country"]
    return {"cloud": c, "region": r, "name": rec.get("name"), "country": country,
            "country_name": cat["countries"].get(country), "location": rec.get("location"),
            "jurisdictions": jurisdictions_for(country), "sovereign": rec.get("sovereign"),
            "partition": rec.get("partition"), "access": rec.get("access")}


# --------------------------------------------------------------------------- #
# Transfer status                                                              #
# --------------------------------------------------------------------------- #

def transfer_status(regime: str, country: str) -> dict:
    """What the regime's adequacy data says about ``country`` as a destination.

    Statuses: ``within_area`` (no transfer: EEA for GDPR, the UK for UK GDPR),
    ``adequate``, ``partial`` (sector or organisation scope only),
    ``conditional_dpf`` (certified US organisations only), ``none`` (no
    adequacy: a transfer mechanism is needed), ``not_evaluated`` (a regime
    this module has no data for).
    """
    reg = adequacy_data()["regimes"].get(str(regime or "").upper())
    code = _country_code(country)
    if reg is None:
        return {"regime": regime, "status": "not_evaluated"}
    if regime.upper() == "GDPR" and code in eea_members():
        return {"regime": "GDPR", "status": "within_area"}
    if regime.upper() == "UK_GDPR":
        if code == "GB":
            return {"regime": "UK_GDPR", "status": "within_area"}
        if reg.get("eea_adequate") and code in eea_members():
            return {"regime": "UK_GDPR", "status": "adequate", "scope": "EEA"}
    dest = reg["destinations"].get(code)
    if dest is None:
        return {"regime": regime.upper(), "status": "none",
                "mechanism": reg.get("transfer_mechanism")}
    out = {"regime": regime.upper(), **dest}
    if dest["status"] in ("partial", "conditional_dpf"):
        out["mechanism"] = reg.get("transfer_mechanism")
    return out


# --------------------------------------------------------------------------- #
# Policy                                                                       #
# --------------------------------------------------------------------------- #

def _policy_lists(policy: Optional[dict]) -> tuple[set[str], set[str], list[str], list[str]]:
    p = policy or {}
    regions = {str(r).strip().lower().replace(" ", "") for r in p.get("allowed_regions") or []}
    countries = {_country_code(c) for c in p.get("allowed_countries") or []}
    jurisdictions = [str(j).strip().upper() for j in p.get("allowed_jurisdictions") or []]
    regimes = [str(r).strip().upper() for r in p.get("data_subject_regimes") or []]
    return regions, countries, jurisdictions, regimes


def has_location_policy(policy: Optional[dict]) -> bool:
    regions, countries, jurisdictions, _ = _policy_lists(policy)
    return bool(regions or countries or jurisdictions)


def _allowed_countries(countries: set[str], jurisdictions: list[str]) -> set[str]:
    allowed = set(countries)
    for tag in jurisdictions:
        allowed |= set(_jurisdiction_countries(tag) or ())
    return allowed


def region_allowed(resolved: dict, policy: Optional[dict]) -> bool:
    regions, countries, jurisdictions, _ = _policy_lists(policy)
    if resolved["region"] in regions or f"{resolved['cloud']}:{resolved['region']}" in regions:
        return True
    return resolved["country"] in _allowed_countries(countries, jurisdictions)


def destination_allowed(countries_in_scope: frozenset[str], policy: Optional[dict]) -> Optional[bool]:
    """True if every possible destination country is allowed, False if none is, None if some."""
    _, countries, jurisdictions, _ = _policy_lists(policy)
    allowed = _allowed_countries(countries, jurisdictions)
    inside = countries_in_scope & allowed
    if inside == countries_in_scope:
        return True
    if not inside:
        return False
    return None


# --------------------------------------------------------------------------- #
# Model egress destinations                                                    #
# --------------------------------------------------------------------------- #

_BEDROCK_HOST = re.compile(r"^bedrock-runtime(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com$")
#: A Bedrock model id with a leading geography segment ("us.anthropic...", an
#: inference-profile ARN) is served by cross-region inference.
_INFERENCE_PROFILE = re.compile(r"(^[a-z]{2,6}\.[a-z0-9-]+\.[^.]|inference-profile)")


def locate_integration(integration: dict) -> dict:
    """Where one model integration processes data, when it can be told.

    Returns ``{"basis", "country"|None, "countries": [...], "jurisdiction"|None,
    "region"|None, "reason"}``. ``basis`` is ``reported_region``,
    ``endpoint_region``, ``regional_endpoint``, ``data_zone`` or
    ``not_observable``.
    """
    host = str(integration.get("endpoint_host") or "").strip().lower() or None
    pid, entry = resolve_provider(integration.get("provider"), host)
    evidence = integration.get("evidence") or {}
    unknown: dict[str, Any] = {"basis": "not_observable", "provider": pid, "country": None, "countries": [],
               "jurisdiction": None, "region": None}
    if entry.get("class") == "local" or pid in ("local", "self_hosted", "ollama", "transformers"):
        return {**unknown, "basis": "local",
                "reason": "A model the customer runs; its location is the customer's own host."}

    deployment = str(evidence.get("deployment_type") or "").lower()
    reported_region = evidence.get("region") or integration.get("region")
    cloud = _PROVIDER_CLOUD.get(pid)

    if pid == "azure_openai" and "global" in deployment:
        return {**unknown, "reason": "A Global deployment may process prompts in any "
                "geography where the model is deployed."}
    if pid == "aws_bedrock":
        model = str(integration.get("model") or "")
        if _INFERENCE_PROFILE.search(model):
            return {**unknown, "reason": "A cross-region inference profile chooses the "
                    "processing Region per request."}
        m = _BEDROCK_HOST.match(host or "")
        if m and not reported_region:
            resolved = resolve_region("aws", m.group(1))
            if resolved:
                return {"basis": "endpoint_region", "provider": pid, "country": resolved["country"],
                        "countries": [resolved["country"]], "jurisdiction": None,
                        "region": resolved["region"],
                        "reason": "The Bedrock runtime endpoint names the Region."}
    if cloud and reported_region:
        resolved = resolve_region(cloud, reported_region)
        if resolved:
            if pid == "azure_openai" and "datazone" in deployment.replace(" ", "").replace("_", ""):
                zone = ("EU" if resolved["country"] in eu_members() else
                        "US" if resolved["country"] == "US" else None)
                if zone:
                    return {"basis": "data_zone", "provider": pid, "country": None,
                            "countries": sorted(_jurisdiction_countries(zone) or ()),
                            "jurisdiction": zone, "region": resolved["region"],
                            "reason": f"A DataZone deployment may process prompts anywhere in the {zone} data zone."}
                return {**unknown, "reason": "A DataZone deployment outside the EU or US; the zone's "
                        "extent is not recorded here."}
            return {"basis": "reported_region", "provider": pid, "country": resolved["country"],
                    "countries": [resolved["country"]], "jurisdiction": None,
                    "region": resolved["region"], "reason": "The provider reported the region."}
    regional = (entry.get("regional_hosts") or {}).get(host or "")
    if regional:
        zone = regional["jurisdiction"]
        return {"basis": "regional_endpoint", "provider": pid, "country": None,
                "countries": sorted(_jurisdiction_countries(zone) or ()), "jurisdiction": zone,
                "region": None, "reason": f"{host} is the provider's documented {zone} endpoint."}
    return {**unknown, "reason": "The destination region is not observable from the store's "
            "configuration."}


# --------------------------------------------------------------------------- #
# DOJ Data Security Program                                                    #
# --------------------------------------------------------------------------- #

def _listed_group_by_detector() -> dict[str, str]:
    groups = doj_data()["listed_identifiers"]
    return {d: g for g, dets in groups.items() if not g.startswith("_") for d in dets}


def doj_categories_for(detectors: Iterable[str]) -> set[str]:
    """DOJ categories one record (a chunk) falls into, from the detectors that fired in it.

    Covered personal identifiers follow 28 CFR 202.212: a listed identifier
    combined with another listed identifier or with other sensitive personal
    data, except demographic/contact data linked only to demographic/contact
    data and network/authentication/call-detail data linked only to each other.
    """
    dets = {str(d) for d in detectors}
    mapping = doj_data()["detector_mapping"]
    cats = {c for c, names in mapping.items()
            if not c.startswith("_") and c != "not_evaluated" and dets & set(names)}
    by_group = _listed_group_by_detector()
    listed = {d for d in dets if d in by_group}
    groups = {by_group[d] for d in listed}
    if listed:
        other_sensitive = bool(cats)
        combined = len(listed) >= 2
        only_contact = groups <= {"demographic_contact"}
        only_network = groups <= {"network_id", "account_authentication", "call_detail"}
        if other_sensitive or (combined and not only_contact and not only_network):
            cats.add("covered_personal_identifiers")
    return cats


def doj_subject_counts(rows: Iterable[tuple[str, Iterable[str]]]) -> dict[str, int]:
    """Distinct subjects per DOJ category.

    ``rows`` holds ``(subject_key, detectors_in_the_same_chunk)`` for every
    subject-index location. A subject counts once per category however many
    chunks place them there.
    """
    seen: dict[str, set[str]] = {}
    for subject, detectors in rows:
        if not subject:
            continue
        for cat in doj_categories_for(detectors):
            seen.setdefault(cat, set()).add(subject)
    return {cat: len(keys) for cat, keys in seen.items()}


def bulk_status(subject_counts: dict[str, int]) -> dict:
    """Per category: count, threshold and whether it is *more than* the threshold."""
    data = doj_data()
    thresholds = {k: v for k, v in data["bulk_thresholds"].items() if not k.startswith("_")}
    not_evaluated = list(data["detector_mapping"]["not_evaluated"])
    out = {}
    for cat, spec in thresholds.items():
        if cat in not_evaluated and cat not in subject_counts:
            out[cat] = {"count": None, "more_than": spec["more_than"], "unit": spec["unit"],
                        "cite": spec["cite"], "reached": None, "evaluated": False}
            continue
        n = int(subject_counts.get(cat) or 0)
        out[cat] = {"count": n, "more_than": spec["more_than"], "unit": spec["unit"],
                    "cite": spec["cite"], "reached": n > spec["more_than"], "evaluated": True}
    return out


def country_of_concern(country: Optional[str]) -> Optional[str]:
    code = _country_code(country)
    names = {k: v for k, v in doj_data()["countries_of_concern"].items() if not k.startswith("_")}
    return names.get(code)


# --------------------------------------------------------------------------- #
# The check                                                                    #
# --------------------------------------------------------------------------- #

def _finding(store: str, title: str, severity: Severity, description: str, evidence: dict,
             remediation: str) -> Finding:
    return Finding(id=f"find-{uuid.uuid4().hex[:10]}", title=title, severity=severity,
                   category=CATEGORY, store=store, collection=None, description=description,
                   evidence=evidence, remediation=remediation)


def _grade(country: Optional[str], countries: list[str], regimes: list[str]) -> tuple[Severity, list[dict], list[str]]:
    """Severity for data outside policy, the transfer status per regime, and evidence asks."""
    statuses: list[dict] = []
    asks: list[str] = []
    severity = Severity.MEDIUM
    targets = [country] if country else countries
    for regime in regimes:
        if regime not in ADEQUACY_REGIMES:
            statuses.append({"regime": regime, "status": "not_evaluated"})
            continue
        worst = None
        for c in targets:
            st = transfer_status(regime, c)
            statuses.append({**st, "country": c})
            rank = {"within_area": 0, "adequate": 0, "partial": 1, "conditional_dpf": 1,
                    "none": 2}.get(st["status"], 0)
            worst = max(worst or 0, rank)
        if worst == 2:
            severity = Severity.HIGH
        if worst and TRANSFER_MECHANISM not in asks:
            asks.append(TRANSFER_MECHANISM)
    return severity, statuses, asks


def _describe(resolved: dict) -> str:
    extra = f", {resolved['sovereign'].replace('_', ' ')} partition" if resolved.get("sovereign") else ""
    return (f"{resolved['cloud']} {resolved['region']} ({resolved.get('country_name') or resolved['country']}"
            f"{extra})")


def _outside_policy_finding(store: str, where: str, what: str, severity: Severity,
                            statuses: list[dict], asks: list[str], evidence: dict,
                            regimes: list[str]) -> Finding:
    lines = []
    for st in statuses:
        if st["status"] == "none":
            lines.append(f"{st['regime']}: {st.get('country')} has no adequacy finding; a transfer "
                         f"needs {st.get('mechanism')}.")
        elif st["status"] == "conditional_dpf":
            lines.append(f"{st['regime']}: {st.get('country')} is adequate only for "
                         f"{st.get('scope', 'certified organisations').lower()}; confirm the "
                         "recipient's certification or use a transfer mechanism.")
        elif st["status"] == "partial":
            lines.append(f"{st['regime']}: {st.get('country')} is adequate only for: "
                         f"{st.get('scope')}.")
    description = (f"{what} is in {where}, outside the declared residency policy."
                   + (" " + " ".join(lines) if lines else "")
                   + ("" if regimes else " No data-subject regime was declared, so no transfer "
                      "rule was evaluated."))
    return _finding(store, f"Data for '{store}' is outside its residency policy: {where}",
                    severity, description,
                    {**evidence, "transfer_status": statuses, "evidence_to_supply": asks},
                    "Move the data (or the replica, or the model deployment) to an allowed "
                    "region, or update the residency policy with the transfer mechanism that "
                    "covers it.")


def assess_residency(location: Optional[dict], *, policy: Optional[dict] = None,
                     integrations: Optional[list[dict]] = None,
                     subject_counts: Optional[dict] = None,
                     store: str = "") -> tuple[list[Finding], dict]:
    """Findings and one store-level ``data_residency`` outcome.

    ``location`` is ``store_location()`` as returned, or None when the
    connector has no ``location_introspection``. ``policy`` is the customer's
    declaration for this store: ``{allowed_regions, allowed_countries,
    allowed_jurisdictions, data_subject_regimes}``. ``integrations`` is the
    ``integrations`` list from ``model_integrations()``. ``subject_counts``
    holds distinct subjects per DOJ category (see ``doj_subject_counts``).
    """
    loc = location or {}
    store_name = store or str(loc.get("store") or "")
    regimes = _policy_lists(policy)[3]
    policy_declared = has_location_policy(policy)
    findings: list[Finding] = []
    details: dict[str, Any] = {"provider": loc.get("provider"), "source": loc.get("source"),
                               "policy_declared": policy_declared,
                               "data_subject_regimes": regimes}

    # ---- where the store is -------------------------------------------- #
    provider = str(loc.get("provider") or "").lower()
    capability_limit = location is None or provider == "self_hosted" or \
        loc.get("capability_limit") is True
    observable = bool(location) and loc.get("observable") is True and bool(loc.get("region"))
    cloud_hint = loc.get("cloud") or (loc.get("evidence") or {}).get("cloud")

    stored: list[dict] = []
    unresolved: list[str] = []
    if observable:
        for role, region in [("primary", loc.get("region"))] + \
                [("replica", r) for r in loc.get("replica_regions") or []]:
            resolved = resolve_region(provider, region, cloud=cloud_hint)
            if resolved is None:
                unresolved.append(str(region))
                stored.append({"role": role, "reported_region": region, "resolved": None})
            else:
                stored.append({"role": role, "reported_region": region, "resolved": resolved})
    details["locations"] = stored

    # ---- where the models send it -------------------------------------- #
    destinations = []
    for integ in integrations or []:
        if not isinstance(integ, dict):
            continue
        located = locate_integration(integ)
        destinations.append({"collection": integ.get("collection"), "stage": integ.get("stage"),
                             "provider": located["provider"], **{k: located[k] for k in
                             ("basis", "country", "jurisdiction", "region", "reason")},
                             "countries": located["countries"]})
    details["egress_destinations"] = destinations

    # ---- DOJ bulk thresholds ------------------------------------------- #
    concern_locations = [
        {"where": "store " + s["role"], "region": s["resolved"]["region"],
         "country": s["resolved"]["country"], "country_of_concern": country_of_concern(s["resolved"]["country"])}
        for s in stored if s["resolved"] and country_of_concern(s["resolved"]["country"])]
    concern_locations += [
        {"where": f"model egress ({d['provider']})", "region": d["region"], "country": d["country"],
         "country_of_concern": country_of_concern(d["country"])}
        for d in destinations if d["country"] and country_of_concern(d["country"])]
    if subject_counts is not None:
        bulk = bulk_status(subject_counts)
        reached = {k: v for k, v in bulk.items() if v["reached"]}
        details["doj_bulk"] = bulk
        if reached:
            findings.append(_doj_finding(store_name, reached, bulk, concern_locations))
    else:
        details["doj_bulk"] = None
    details["countries_of_concern"] = concern_locations

    # ---- outcome --------------------------------------------------------- #
    if not observable:
        reason = str(loc.get("reason") or "") if location else ""
        if capability_limit:
            reason = reason or ("The connector cannot report where this store keeps its data: "
                                "for a self-hosted store the location is the host's, which the "
                                "database API does not expose.")
            return findings, check_outcome(
                CHECK, store_name, None, outcome="unsupported", reason=reason, complete=False,
                capability_limit=True, evidence_to_supply=[DATA_RESIDENCY_STATEMENT], **details)
        reason = (reason or "The store's location was not reported.") + \
            " VecShield does not infer a location from IP addresses."
        return findings, check_outcome(
            CHECK, store_name, None, outcome="inconclusive", reason=reason, complete=False,
            evidence_to_supply=[DATA_RESIDENCY_STATEMENT], **details)

    if not policy_declared:
        where = ", ".join(_describe(s["resolved"]) if s["resolved"] else str(s["reported_region"])
                          for s in stored)
        # The location was observed in full; what is missing is the customer's
        # own policy to judge it against. Like an undeclared retention
        # schedule, that is an input the run was not given, not a gap in what
        # the run could see, so it does not make the run partial. Criteria
        # still read `inconclusive` and ask for the policy.
        return findings, check_outcome(
            CHECK, store_name, None, outcome="inconclusive",
            reason=f"No residency policy declared. The store reports: {where}.",
            complete=True, policy_missing=True,
            evidence_to_supply=["residency_policy"], **details)

    outside = 0
    undetermined: list[str] = list(unresolved)
    for s in stored:
        res = s["resolved"]
        if res is None:
            continue
        allowed = region_allowed(res, policy)
        s["allowed"] = allowed
        if allowed:
            continue
        outside += 1
        severity, statuses, asks = _grade(res["country"], [], regimes)
        findings.append(_outside_policy_finding(
            store_name, _describe(res),
            "The store's data" if s["role"] == "primary" else "A replica of the store's data",
            severity, statuses, asks,
            {"role": s["role"], "region": res["region"], "cloud": res["cloud"],
             "country": res["country"], "jurisdictions": res["jurisdictions"],
             "sovereign": res.get("sovereign"), "source": loc.get("source")}, regimes))

    not_observable_egress = 0
    for d in destinations:
        if d["basis"] in ("local",):
            d["allowed"] = True
            continue
        if not d["countries"]:
            not_observable_egress += 1
            d["allowed"] = None
            continue
        verdict = destination_allowed(frozenset(d["countries"]), policy)
        d["allowed"] = verdict
        if verdict is None:
            undetermined.append(f"model egress to {d['provider']} ({d['jurisdiction']})")
            continue
        if verdict:
            continue
        outside += 1
        severity, statuses, asks = _grade(d["country"], d["countries"], regimes)
        where = (f"{d['provider']} {d['region'] or d['jurisdiction']}"
                 f" ({d['country'] or d['jurisdiction']})")
        findings.append(_outside_policy_finding(
            store_name, where,
            f"Text sent by the store to {d['provider']}"
            + (f" from collection '{d['collection']}'" if d["collection"] else ""),
            severity, statuses, asks,
            {"role": "model_egress", "provider": d["provider"], "basis": d["basis"],
             "region": d["region"], "country": d["country"], "jurisdiction": d["jurisdiction"],
             "collection": d["collection"], "stage": d["stage"]}, regimes))

    details["not_observable_egress"] = not_observable_egress
    details["undetermined"] = undetermined
    if outside:
        outcome, complete = "failed", True
        reason = f"{outside} location(s) holding or receiving this store's data are outside the residency policy."
    elif undetermined or not_observable_egress:
        outcome, complete = "inconclusive", False
        parts = []
        if undetermined:
            parts.append(f"{len(undetermined)} location(s) could not be placed against the policy "
                         f"({', '.join(undetermined)})")
        if not_observable_egress:
            parts.append(f"{not_observable_egress} model-egress destination(s) are not observable")
        reason = "Stored data observed within policy; " + "; ".join(parts) + "."
        details["evidence_to_supply"] = [DATA_RESIDENCY_STATEMENT]
    else:
        outcome, complete = "passed", True
        reason = "Every reported location of this store's data, including replicas and model calls, is within the residency policy."
    return findings, check_outcome(CHECK, store_name, None, outcome=outcome, reason=reason,
                                   complete=complete, **details)


def _doj_finding(store: str, reached: dict, bulk: dict, concern_locations: list[dict]) -> Finding:
    in_concern = bool(concern_locations)
    labels = doj_data()["bulk_thresholds"]
    listing = "; ".join(f"{labels[c]['label']}: {v['count']} (more than {v['more_than']} "
                        f"{v['unit']}, {v['cite']})" for c, v in reached.items())
    description = (
        f"Distinct subjects in this store reach the 28 CFR Part 202 bulk threshold for: "
        f"{listing}. Counts are of distinct subjects seen by the scan, whether or not they are "
        "U.S. persons, and cover only what the detectors recognise. Bulk data is not "
        "prohibited: the rule restricts or prohibits transactions that give a country of "
        "concern or a covered person access to it. VecShield cannot see who has access; "
        "assess vendor, employment and investment agreements and data brokerage involving "
        "this data.")
    if in_concern:
        description += (" This store's data is held in, or sent to, a location in a country of "
                        "concern: " + ", ".join(f"{c['where']} {c['region'] or ''} "
                                               f"({c['country_of_concern']})".replace("  ", " ")
                                               for c in concern_locations) + ".")
    return _finding(
        store, "Bulk U.S. sensitive personal data thresholds reached (28 CFR Part 202)",
        Severity.MEDIUM if in_concern else Severity.LOW, description,
        {"reached": reached, "bulk": bulk, "countries_of_concern": concern_locations,
         "not_evaluated": [c for c, v in bulk.items() if not v["evaluated"]],
         "evidence_to_supply": ["country_of_concern_access_assessment"],
         "sources": doj_data()["_sources"]},
        "Inventory who can access this data (vendors, employees, investors, data buyers) and "
        "whether any is a country of concern or covered person; for restricted transactions "
        "apply the CISA security requirements (28 CFR 202.248) and keep the records Part 202 "
        "requires.")
