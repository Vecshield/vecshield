"""Server vulnerability and support-status assessment against a local feed.

Feeds here are built from normalised records (the format ``vulnfeed`` stores),
trimmed from real advisories; no network access.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vecshield_platform.connectors.base import UnsupportedCapability

from vecshield.models import Severity
from vecshield_platform.coverage import capability_limited
from vecshield_platform.posture import server_vulns as sv
from vecshield_platform.posture import vulnfeed as vf
from vecshield_platform.posture.versions import (
    is_pseudo_version,
    parse_server_version,
    parse_version,
    release_line,
)

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)
UPDATED = "2026-09-28T12:00:00Z"


def cvss(vector: str, score: float) -> list[dict]:
    return [{"version": vector.split("/")[0].split(":")[1], "vector": vector, "score": score,
             "score_basis": "stated"}]


MILVUS_RECORDS = [
    {"id": "GHSA-mhjq-8c7m-3f7p", "aliases": ["CVE-2025-64513"],
     "summary": "Milvus Proxy has a Critical Authentication Bypass Vulnerability",
     "details": "An unauthenticated attacker can exploit this vulnerability to bypass all "
                "authentication mechanisms in the Milvus Proxy component.",
     "severity_label": "CRITICAL", "cwe": ["CWE-287"],
     "cvss": [{"version": "4.0", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/"
                                           "SC:N/SI:N/SA:N", "score": None, "score_basis": "none"}],
     "ranges": [{"introduced": "0.10.4", "fixed": "2.4.24"},
                {"introduced": "2.5.0", "fixed": "2.5.21"},
                {"introduced": "2.6.0", "fixed": "2.6.5"}],
     "advisory_url": "https://github.com/milvus-io/milvus/security/advisories/GHSA-mhjq-8c7m-3f7p",
     "workaround": {"heading": "Workarounds", "text": "If immediate upgrade is not possible, a "
                    "temporary mitigation can be applied by removing the sourceID header from "
                    "all incoming requests at the gateway.",
                    "source_url": "https://github.com/milvus-io/milvus/security/advisories/"
                                  "GHSA-mhjq-8c7m-3f7p"},
     "published": "2025-11-13T15:55:00Z"},
    {"id": "GHSA-7ppg-37fh-vcr6", "aliases": ["CVE-2026-26190"],
     "summary": "Unauthenticated Access to Restful API on Metrics Port (9091)",
     "details": "Milvus exposes TCP port 9091 by default with two critical authentication "
                "bypass vulnerabilities.",
     "severity_label": "CRITICAL",
     "cvss": cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
     "ranges": [{"fixed": "2.5.27"}, {"introduced": "2.6.0", "fixed": "2.6.10"}],
     "advisory_url": "https://github.com/milvus-io/milvus/security/advisories/GHSA-7ppg-37fh-vcr6",
     "published": "2026-02-11T19:49:44Z"},
]


def make_feed(sources: dict, *, updated: str = UPDATED, overlay: dict | None = None,
              kev: dict | None = None) -> vf.Feed:
    raw = {"schema": 1, "updated_at": updated, "sources": dict(sources)}
    if kev is not None:
        raw["sources"]["kev"] = {"kind": "kev", "product": "", "data": {"entries": kev}}
    return vf.Feed(raw, origin="state", overlay=overlay or {"advisories": [], "products": {}})


def advisory_source(product: str, records: list[dict], *, kind: str = "osv_package",
                    component: str = "server") -> dict:
    return {f"{kind}:{product}:{component}:x": {"kind": kind, "product": product,
                                                 "component": component, "data": records}}


def milvus_feed(**kw) -> vf.Feed:
    return make_feed(advisory_source("milvus", MILVUS_RECORDS), **kw)


def outcome(outcomes: list[dict], check: str) -> dict:
    return next(o for o in outcomes if o["check"] == check)


# --- version parsing --------------------------------------------------------------

@pytest.mark.parametrize("product,raw,expected", [
    ("postgresql", "PostgreSQL 16.4 (Debian 16.4-1.pgdg120+1) on x86_64-pc-linux-gnu, "
                   "compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit", "16.4"),
    ("postgresql", "16.4 (Debian 16.4-1.pgdg120+1)", "16.4"),
    ("postgresql", "160004", "16.4"),
    ("postgresql", "90624", "9.6.24"),
    ("postgresql", "9.6.24", "9.6.24"),
    ("postgresql", "17beta2", "17.0-beta.2"),
    ("redis", "7.2.4", "7.2.4"),
    ("mongodb", "7.0.12", "7.0.12"),
    ("milvus", "v2.5.12", "2.5.12"),
    ("weaviate", "1.31.0-rc.0", "1.31.0-rc.0"),
    ("qdrant", "1.15.5", "1.15.5"),
    ("opensearch", "2.11.1", "2.11.1"),
    ("chroma", "1.0.20", "1.0.20"),
])
def test_server_version_parsing(product, raw, expected):
    parsed = parse_server_version(product, raw)
    assert str(parsed.version) == expected


@pytest.mark.parametrize("product,raw", [
    ("postgresql", "16"), ("postgresql", "PostgreSQL devel build"), ("redis", ""),
    ("qdrant", "latest"), ("milvus", None), ("mongodb", "unknown"),
])
def test_unparseable_versions_are_none(product, raw):
    assert parse_server_version(product, raw).version is None


def test_suffixes_are_recorded_and_compare_conservatively():
    hotfix = parse_server_version("milvus", "v2.4.15-hotfix")
    assert str(hotfix.version) == "2.4.15" and "hotfix" in hotfix.note
    assert parse_version("1.31.0-rc.0") < parse_version("1.31.0") < parse_version("1.31.1")
    assert parse_version("1.9.0-dev") < parse_version("1.9.0")
    assert parse_version("7.0") == parse_version("7.0.0")
    assert parse_version("2.19.4.0") > parse_version("2.19.3")
    assert parse_version("0.10.3-0.20251107071934-6102f001a971") is None
    assert is_pseudo_version("v0.0.0-20240101010101-abcdefabcdef")


def test_release_lines():
    assert release_line("postgresql", parse_version("16.4")) == "16"
    assert release_line("postgresql", parse_version("9.6.24")) == "9.6"
    assert release_line("redis", parse_version("7.4.2")) == "7.4"
    assert release_line("milvus", parse_version("2.5.12")) == "2.5"


# --- matching and remediation -------------------------------------------------------

def test_same_line_fix_and_single_all_clearing_upgrade():
    assessment = sv.assess_server({"product": "milvus", "version": "v2.5.12"}, milvus_feed(),
                                  now=NOW)
    matches = {m.id: m for m in assessment.matches}
    assert set(matches) == {"CVE-2025-64513", "CVE-2026-26190"}
    assert matches["CVE-2025-64513"].same_line_fix == "2.5.21"      # not 2.6.5
    assert matches["CVE-2026-26190"].same_line_fix == "2.5.27"
    upgrade = assessment.components[0].recommended_upgrade
    assert upgrade["version"] == "2.5.27" and upgrade["same_line"] is True
    assert sorted(upgrade["clears"]) == ["CVE-2025-64513", "CVE-2026-26190"]


def test_patched_versions_and_other_lines_are_clean():
    for version in ("2.5.27", "2.6.10", "2.7.0"):
        assessment = sv.assess_server({"product": "milvus", "version": version}, milvus_feed(),
                                      now=NOW)
        assert assessment.matches == [], version
    findings, outcomes = sv.findings_and_outcomes(
        sv.assess_server({"product": "milvus", "version": "2.6.10"}, milvus_feed(), now=NOW), "m")
    assert outcome(outcomes, "server_vulnerability")["outcome"] == "passed"
    assert outcome(outcomes, "server_vulnerability")["coverage"]["complete"] is True
    assert not [f for f in findings if f.category == "server_vulnerability"]


def test_no_fix_on_line_points_to_next_line_and_upgrade_avoids_other_advisories():
    records = [
        {"id": "CVE-2026-0001", "summary": "a", "cvss": cvss(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
         "ranges": [{"fixed": "8.6.3"}]},
        {"id": "CVE-2026-0002", "summary": "b", "cvss": cvss(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
         "ranges": [{"introduced": "8.6.0", "fixed": "8.6.4"}]},    # hits 8.6.3 itself
    ]
    feed = make_feed(advisory_source("redis", records, kind="nvd_cpe"))
    assessment = sv.assess_server({"product": "redis", "version": "7.4.2"}, feed, now=NOW)
    match = assessment.matches[0]
    assert match.same_line_fix is None and match.next_fix == "8.6.3"
    assert "no fix is recorded for the 7.4 line" in match.fix_note
    upgrade = assessment.components[0].recommended_upgrade
    assert upgrade["version"] == "8.6.4"                  # 8.6.3 is itself affected by -0002
    assert upgrade["same_line"] is False


def test_prerelease_fix_is_recommended_as_its_final_release():
    feed = make_feed(advisory_source("weaviate", [
        {"id": "CVE-2026-11500", "summary": "authz", "ranges": [{"fixed": "1.38.0-rc.0"}]}]))
    match = sv.assess_server({"product": "weaviate", "version": "1.37.2"}, feed,
                             now=NOW).matches[0]
    assert match.next_fix == "1.38.0" and "pre-release 1.38.0-rc.0" in match.fix_note


def test_listed_versions_and_same_line_inference():
    records = [{"id": "CVE-2026-9999", "summary": "x", "ranges": [{"introduced": "0.8.0",
                                                                   "fixed": "0.8.2"}],
                "versions": ["0.6.0", "0.7.0", "0.8.0", "0.8.1"]}]
    feed = make_feed(advisory_source("postgresql", records, kind="osv_git",
                                     component="pgvector"))
    info = {"product": "postgresql", "version": "16.4", "features": {"pgvector": "0.7.4"}}
    assessment = sv.assess_server(info, feed, now=NOW)
    match = assessment.matches[0]
    assert match.component == "pgvector" and match.basis["basis"] == "inferred_same_line"
    info["features"]["pgvector"] = "0.8.2"
    assert sv.assess_server(info, feed, now=NOW).matches == []


def test_overlay_override_ranges_win_and_cite_source():
    overlay = vf.load_overlay()
    records = [{"id": "CVE-2026-3172", "summary": "pgvector buffer overflow in parallel HNSW",
                "ranges": [{"introduced": "0.8.0", "fixed": "0.8.2"}, {"version": "0.7.0"}],
                "versions": ["0.6.0", "0.7.0", "0.8.0", "0.8.1"]}]
    feed = make_feed(advisory_source("postgresql", records, kind="osv_git",
                                     component="pgvector"), overlay=overlay)
    info = {"product": "postgresql", "version": "16.4",
            "features": {"pgvector": "0.7.4", "max_parallel_maintenance_workers": 0}}
    assessment = sv.assess_server(info, feed, now=NOW)
    match = next(m for m in assessment.matches if m.id == "CVE-2026-3172")
    assert match.basis == {"basis": "range", "interval": {"introduced": "0.6.0", "fixed": "0.8.2"}}
    assert match.advisory["range_source"]["url"] == "https://github.com/pgvector/pgvector/issues/959"
    assert match.applicability["state"] == sv.AFFECTED_NOT_EXPOSED
    assert match.same_line_fix is None and match.next_fix == "0.8.2"


PGVECTOR_RECORDS = [{"id": "CVE-2026-9999", "summary": "x", "ranges": [{"fixed": "0.8.2"}]}]


def test_pgvector_installed_package_is_judged_before_extversion():
    """Backends run the package's library; extversion lags until ALTER EXTENSION."""
    feed = make_feed(advisory_source("postgresql", PGVECTOR_RECORDS, kind="nvd_cpe",
                                     component="pgvector"))
    upgraded = {"product": "postgresql", "version": "16.4",
                "features": {"pgvector": "0.8.1", "pgvector_package": "0.8.7",
                             "extensions": {"vector": "0.8.1"}}}
    assessment = sv.assess_server(upgraded, feed, now=NOW)
    pgv = next(c for c in assessment.components if c.component == "pgvector")
    assert str(pgv.version) == "0.8.7" and pgv.version_source == "pgvector_package"
    assert assessment.matches == []
    findings, _ = sv.findings_and_outcomes(assessment, "pg")
    lag = [f for f in findings if "extension objects" in f.title]
    assert len(lag) == 1 and lag[0].severity == Severity.LOW
    assert lag[0].evidence["installed_package_version"] == "0.8.7"
    assert lag[0].evidence["extension_catalog_version"] == "0.8.1"
    assert "ALTER EXTENSION vector UPDATE" in lag[0].remediation

    # Without the package read (older facts), extversion is still judged.
    del upgraded["features"]["pgvector_package"]
    assessment = sv.assess_server(upgraded, feed, now=NOW)
    assert [m.id for m in assessment.matches] == ["CVE-2026-9999"]
    match_finding = next(f for f in sv.findings_and_outcomes(assessment, "pg")[0]
                         if f.evidence.get("advisory_id") == "CVE-2026-9999")
    assert match_finding.evidence["version_source"] == "pgvector"
    assert not any("extension objects" in f.title
                   for f in sv.findings_and_outcomes(assessment, "pg")[0])


@pytest.mark.parametrize("package,affected", [("0.8.6", True), ("0.5.1", True),
                                              ("0.8.7", False), ("0.9.0", False)])
def test_overlay_only_advisory_is_matched_before_the_sources_carry_it(package, affected):
    """CVE-2026-103484 was public on the vendor tracker before NVD/OSV listed it."""
    feed = make_feed(advisory_source("postgresql", [], kind="nvd_cpe", component="pgvector"),
                     overlay=vf.load_overlay())
    info = {"product": "postgresql", "version": "17.6",
            "features": {"pgvector": package, "pgvector_package": package}}
    assessment = sv.assess_server(info, feed, now=NOW)
    ids = [m.id for m in assessment.matches]
    assert ("CVE-2026-103484" in ids) is affected
    if not affected:
        return
    match = next(m for m in assessment.matches if m.id == "CVE-2026-103484")
    assert match.severity == Severity.HIGH
    assert "advisory overlay" in match.severity_reason
    assert match.advisory["range_source"]["kind"] == "overlay"
    assert match.advisory["range_source"]["url"].startswith("https://security-tracker.debian")
    assert match.advisory["sources"] == ["overlay"]
    assert (match.same_line_fix or match.next_fix) == "0.8.7"


def test_live_record_text_and_score_win_over_the_overlay_advisory():
    live = [{"id": "CVE-2026-103484", "summary": "live summary", "details": "live details",
             "cvss": cvss("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
             "ranges": [{"fixed": "0.8.7"}]}]
    feed = make_feed(advisory_source("postgresql", live, kind="nvd_cpe", component="pgvector"),
                     overlay=vf.load_overlay())
    merged = [a for a in feed.advisories("postgresql", "pgvector")
              if a["id"] == "CVE-2026-103484"]
    assert len(merged) == 1
    assert merged[0]["summary"] == "live summary" and merged[0]["cvss_best"]["score"] == 8.8
    assert merged[0]["sources"] == ["nvd_cpe", "overlay"]


def test_overlay_advisory_stays_in_its_component():
    feed = make_feed(advisory_source("postgresql", [], kind="postgresql_org"),
                     overlay=vf.load_overlay())
    assert "CVE-2026-103484" not in {a["id"] for a in feed.advisories("postgresql")}


# --- applicability ----------------------------------------------------------------

WEAVIATE_RECORDS = [{
    "id": "GHSA-7v39-2hx7-7c43", "aliases": ["CVE-2025-67818"],
    "summary": "Weaviate OSS has a Path Traversal Vulnerability via Backup ZipSlip",
    "details": "An attacker with access to insert data into the database can craft an entry "
               "name with an absolute path to escape the restore root when a backup is restored.",
    "cvss": cvss("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H", 7.2), "severity_label": "HIGH",
    "ranges": [{"fixed": "1.30.20"}, {"introduced": "1.31.0-rc.0", "fixed": "1.31.19"},
               {"introduced": "1.32.0-rc.0", "fixed": "1.32.16"},
               {"introduced": "1.33.0-rc.0", "fixed": "1.33.4"}]}]


@pytest.mark.parametrize("features,state,severity", [
    ({"modules": {"backup-filesystem": {}, "text2vec-openai": {}}},
     sv.AFFECTED_AND_EXPOSED, Severity.HIGH),
    ({"modules": {"text2vec-openai": {}}}, sv.AFFECTED_NOT_EXPOSED, Severity.MEDIUM),
    ({}, sv.AFFECTED_CONDITION_UNKNOWN, Severity.HIGH),
])
def test_condition_overlay_evaluated_against_features(features, state, severity):
    feed = make_feed(advisory_source("weaviate", WEAVIATE_RECORDS), overlay=vf.load_overlay())
    assessment = sv.assess_server({"product": "weaviate", "version": "1.32.3",
                                   "features": features}, feed, now=NOW)
    match = assessment.matches[0]
    assert match.applicability["state"] == state
    assert match.severity == severity and match.base_severity == Severity.HIGH
    assert match.applicability["source_url"].startswith("https://weaviate.io/blog/")
    assert match.same_line_fix == "1.32.16"
    findings, _ = sv.findings_and_outcomes(assessment, "w")
    finding = next(f for f in findings if f.category == "server_vulnerability")
    assert finding.evidence["applicability"] == state
    assert "backup* entries" in finding.remediation            # vendor workaround, quoted
    if state == sv.AFFECTED_NOT_EXPOSED:
        assert "lowered one band" in finding.evidence["severity_reason"]


def test_postgres_component_applicability():
    records = [
        {"id": "CVE-2026-19385", "summary": "PostgreSQL pg_dump heap buffer overflow executes "
         "arbitrary code", "pg_component": "client",
         "cvss": cvss("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
         "ranges": [{"introduced": "16.0", "fixed": "16.15"}]},
        {"id": "CVE-2026-2005", "summary": "PostgreSQL pgcrypto heap buffer overflow executes "
         "arbitrary code", "pg_component": "contrib module",
         "cvss": cvss("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
         "ranges": [{"introduced": "16.0", "fixed": "16.12"}]},
    ]
    overlay = vf.load_overlay()
    feed = make_feed(advisory_source("postgresql", records, kind="postgresql_org"),
                     overlay=overlay)

    def states(features):
        a = sv.assess_server({"product": "postgresql", "version": "16.4", "features": features},
                             feed, now=NOW)
        return {m.id: (m.applicability["state"], m.severity) for m in a.matches}

    got = states({"extensions": {"plpgsql": "1.0", "pgcrypto": "1.3"}})
    assert got["CVE-2026-19385"] == (sv.AFFECTED_NOT_EXPOSED, Severity.MEDIUM)
    assert got["CVE-2026-2005"] == (sv.AFFECTED_AND_EXPOSED, Severity.HIGH)
    assert states({"extensions": ["plpgsql", "vector"]})["CVE-2026-2005"][0] == \
        sv.AFFECTED_NOT_EXPOSED
    assert states({})["CVE-2026-2005"][0] == sv.AFFECTED_CONDITION_UNKNOWN


def test_nvd_platform_condition():
    feed = make_feed(advisory_source("mongodb", [{
        "id": "CVE-2019-2390", "summary": "Windows only", "platforms": ["microsoft:windows"],
        "ranges": [{"introduced": "4.0.0", "fixed": "4.0.11"}]}], kind="nvd_cpe"))
    assessment = sv.assess_server({"product": "mongodb", "version": "4.0.3",
                                   "features": {"os": "Ubuntu 22.04"}}, feed, now=NOW)
    # platforms are carried through the merge from the chosen range record
    assert assessment.matches[0].applicability["state"] == sv.AFFECTED_NOT_EXPOSED


# --- KEV --------------------------------------------------------------------------

KEV_ENTRY = {"CVE-2025-14847": {"date_added": "2025-12-29", "due_date": "2026-01-19",
                                "required_action": "Apply mitigations per vendor instructions, "
                                                   "follow applicable BOD 22-01 guidance.",
                                "vulnerability_name": "MongoDB Improper Handling of Length"}}


def mongo_feed(score: float = 5.3) -> vf.Feed:
    records = [{"id": "CVE-2025-14847", "summary": "Mismatched length fields in Zlib compressed "
                "protocol headers may allow a read of uninitialized heap memory by an "
                "unauthenticated client.",
                "cvss": cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", score),
                "ranges": [{"introduced": "7.0.0", "fixed": "7.0.28"},
                           {"introduced": "8.0.0", "fixed": "8.0.17"}]}]
    return make_feed(advisory_source("mongodb", records, kind="nvd_cpe"),
                     overlay=vf.load_overlay(), kev=KEV_ENTRY)


def test_kev_escalates_to_high_and_cites_cisa():
    assessment = sv.assess_server({"product": "mongodb", "version": "7.0.12", "features": {
        "network_compressors": ["snappy", "zstd", "zlib"]}}, mongo_feed(), now=NOW)
    match = assessment.matches[0]
    assert match.base_severity == Severity.MEDIUM and match.severity == Severity.HIGH
    assert "CISA KEV" in match.severity_reason
    findings, outcomes = sv.findings_and_outcomes(assessment, "mongo")
    finding = next(f for f in findings if f.category == "server_vulnerability")
    assert finding.evidence["known_exploited"] is True
    assert finding.evidence["kev"]["due_date"] == "2026-01-19"
    assert "2026-01-19" in finding.remediation and "BOD 22-01" in finding.remediation
    assert "explicitly omits zlib" in finding.remediation           # vendor workaround
    assert "7.0.28" in finding.remediation
    cov = outcome(outcomes, "server_vulnerability")["coverage"]
    assert cov["known_exploited_matched"] == ["CVE-2025-14847"]


def test_kev_not_exposed_floor_is_medium():
    assessment = sv.assess_server({"product": "mongodb", "version": "7.0.12", "features": {
        "network_compressors": "snappy,zstd"}}, mongo_feed(score=2.0), now=NOW)
    match = assessment.matches[0]
    assert match.applicability["state"] == sv.AFFECTED_NOT_EXPOSED
    assert match.severity == Severity.MEDIUM


# --- support status ---------------------------------------------------------------

def eol_feed(cycles: list[dict]) -> vf.Feed:
    sources = advisory_source("postgresql", [])
    sources["eol:postgresql"] = {"kind": "eol", "product": "postgresql", "data": {
        "kind": "endoflife", "cycles": cycles, "source_url": "https://endoflife.date/postgresql",
        "policy_url": "https://www.postgresql.org/support/versioning/"}}
    return make_feed(sources)


@pytest.mark.parametrize("cycle,status,check_outcome_,finding_severity", [
    ({"cycle": "13", "eol": "2025-11-13", "latest": "13.22"}, "eol", "failed", Severity.HIGH),
    ({"cycle": "13", "eol": "2026-11-13", "latest": "13.22"}, "eol_within_90_days", "passed",
     Severity.LOW),
    ({"cycle": "13", "eol": "2028-11-13", "latest": "13.22"}, "supported", "passed", None),
    ({"cycle": "12", "eol": "2024-11-14"}, "unknown", "inconclusive", None),
])
def test_eol_states(cycle, status, check_outcome_, finding_severity):
    assessment = sv.assess_server({"product": "postgresql", "version": "13.16"},
                                  eol_feed([cycle]), now=NOW)
    assert assessment.support["status"] == status
    findings, outcomes = sv.findings_and_outcomes(assessment, "pg")
    got = outcome(outcomes, "server_support_status")
    assert got["outcome"] == check_outcome_
    support = [f for f in findings if f.category == "server_support_status"]
    if finding_severity is None:
        assert support == []
    else:
        assert support[0].severity == finding_severity
        assert support[0].evidence["source_url"] == "https://endoflife.date/postgresql"
    if status in ("eol", "eol_within_90_days", "supported"):
        assert assessment.support["latest_on_line"] == "13.22"


def test_policy_not_published_is_a_capability_limit():
    assessment = sv.assess_server({"product": "qdrant", "version": "1.15.5"},
                                  make_feed(advisory_source("qdrant", []),
                                            overlay=vf.load_overlay()), now=NOW)
    assert assessment.support["status"] == "policy_not_published"
    _, outcomes = sv.findings_and_outcomes(assessment, "q")
    got = outcome(outcomes, "server_support_status")
    assert got["outcome"] == "unsupported" and capability_limited(got)
    assert assessment.support["upgrade_notes"]["source_url"] == \
        "https://qdrant.tech/documentation/upgrades/"


@pytest.mark.parametrize("version,status", [("1.37.4", "supported"), ("1.36.9", "eol"),
                                            ("1.40.0", "unknown")])
def test_weaviate_three_minor_policy(version, status):
    sources = advisory_source("weaviate", [])
    sources["eol:weaviate"] = {"kind": "eol", "product": "weaviate", "data": {
        "kind": "latest_n_minors", "n": 3, "latest": "1.39.7",
        "latest_source": "https://github.com/weaviate/weaviate/releases/tag/v1.39.7",
        "policy_url": "https://weaviate.io/weaviate-eol-policy"}}
    assessment = sv.assess_server({"product": "weaviate", "version": version},
                                  make_feed(sources), now=NOW)
    assert assessment.support["status"] == status
    assert assessment.support["policy_url"] == "https://weaviate.io/weaviate-eol-policy"


# --- outcomes for unknowns -----------------------------------------------------------

def test_managed_service_without_version_is_provider_patched():
    assessment = sv.assess_server({"product": "qdrant", "version": None, "managed": True,
                                   "reason": "Qdrant Cloud does not expose the version"},
                                  milvus_feed(), now=NOW)
    assert assessment.status == "not_applicable"
    findings, outcomes = sv.findings_and_outcomes(assessment, "cloud")
    for check in ("server_vulnerability", "server_support_status"):
        got = outcome(outcomes, check)
        assert got["outcome"] == "unsupported" and capability_limited(got)
        assert got["coverage"]["applicability"] == "not_applicable"
        assert got["collection"] is None
    assert findings[0].severity == Severity.INFO


def test_unknown_version_is_inconclusive_never_clean():
    for info in ({"product": "milvus", "version": None},
                 {"product": "milvus", "version": "nightly"}):
        assessment = sv.assess_server(info, milvus_feed(), now=NOW)
        assert assessment.status == "inconclusive"
        _, outcomes = sv.findings_and_outcomes(assessment, "m")
        assert {o["outcome"] for o in outcomes} == {"inconclusive"}
        assert all(o["coverage"]["complete"] is False for o in outcomes)


def test_uncatalogued_product_and_missing_feed():
    assessment = sv.assess_server({"product": "cassandra", "version": "4.1.0"}, milvus_feed(),
                                  now=NOW)
    _, outcomes = sv.findings_and_outcomes(assessment, "c")
    assert outcome(outcomes, "server_vulnerability")["outcome"] == "unsupported"
    assert not capability_limited(outcome(outcomes, "server_vulnerability"))
    empty = vf.Feed({}, origin="none", overlay={"advisories": [], "products": {}})
    assessment = sv.assess_server({"product": "milvus", "version": "2.5.12"}, empty, now=NOW)
    assert assessment.status == "inconclusive"


def test_feed_age_is_reported_and_old_feed_is_partial():
    fresh = sv.findings_and_outcomes(sv.assess_server(
        {"product": "milvus", "version": "2.5.12"}, milvus_feed(), now=NOW), "m")[1]
    cov = outcome(fresh, "server_vulnerability")["coverage"]
    assert cov["feed_age_days"] == 1.0 and cov["feed_stale"] is False and cov["complete"] is True
    stale = milvus_feed(updated=(NOW - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    cov = outcome(sv.findings_and_outcomes(sv.assess_server(
        {"product": "milvus", "version": "2.5.12"}, stale, now=NOW), "m")[1],
        "server_vulnerability")["coverage"]
    assert cov["feed_stale"] is True and cov["complete"] is True
    old = milvus_feed(updated=(NOW - timedelta(days=45)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    got = outcome(sv.findings_and_outcomes(sv.assess_server(
        {"product": "milvus", "version": "2.5.12"}, old, now=NOW), "m")[1],
        "server_vulnerability")
    assert got["outcome"] == "failed" and got["coverage"]["complete"] is False


def test_undetermined_known_exploited_advisory_makes_run_inconclusive():
    feed = make_feed(advisory_source("redis", [
        {"id": "CVE-2099-1111", "summary": "platform issue",
         "unparsed": "CPE without a version (not version-identified)"}], kind="nvd_cpe"),
        kev={"CVE-2099-1111": {"date_added": "2026-01-01", "due_date": "2026-01-21"}})
    findings, outcomes = sv.findings_and_outcomes(
        sv.assess_server({"product": "redis", "version": "7.4.2"}, feed, now=NOW), "r")
    got = outcome(outcomes, "server_vulnerability")
    assert got["outcome"] == "inconclusive" and got["coverage"]["undetermined"] == ["CVE-2099-1111"]
    assert findings[0].severity == Severity.INFO


def test_overlay_exclusion_is_reported_not_matched():
    feed = make_feed(advisory_source("redis", [
        {"id": "CVE-2022-0543", "summary": "Debian-specific Lua sandbox escape",
         "unparsed": "CPE without a version"}], kind="nvd_cpe"), overlay=vf.load_overlay())
    _, outcomes = sv.findings_and_outcomes(
        sv.assess_server({"product": "redis", "version": "6.0.16"}, feed, now=NOW), "r")
    cov = outcome(outcomes, "server_vulnerability")["coverage"]
    assert cov["not_version_assessed"] == ["CVE-2022-0543"] and cov["undetermined"] == []
    assert outcome(outcomes, "server_vulnerability")["outcome"] == "passed"


# --- entry point -------------------------------------------------------------------

class FakeConnector:
    def __init__(self, kind: str, info=None, caps=("server_info",), raises=None):
        self.kind = kind
        self._info = info
        self._caps = set(caps)
        self._raises = raises

    def capabilities(self):
        return self._caps

    def server_info(self):
        if self._raises:
            raise self._raises
        return self._info


class Store:
    name = "prod-milvus"


def test_entry_point_produces_findings_with_complete_evidence():
    info = {"product": "milvus", "version": "v2.5.12", "edition": None, "managed": False,
            "source": "GetVersion", "reason": "",
            "features": {"api_key": "sk-secret", "metrics_port_reachable": True}}
    findings, outcomes = sv.run_server_vulnerability_checks(
        FakeConnector("milvus", info), Store(), feed=milvus_feed(overlay=vf.load_overlay()),
        now=NOW)
    assert {o["check"] for o in outcomes} == {"server_vulnerability", "server_support_status"}
    assert all(o["store"] == "prod-milvus" and o["collection"] is None for o in outcomes)
    assert outcome(outcomes, "server_vulnerability")["outcome"] == "failed"
    finding = next(f for f in findings if f.evidence.get("advisory_id") == "CVE-2025-64513")
    ev = finding.evidence
    for key in ("advisory_id", "aliases", "description", "cvss", "cwe", "affected_ranges",
                "fixed_versions", "recommended_upgrade", "workaround", "applicability",
                "applicability_reason", "known_exploited", "references", "same_line_fix"):
        assert key in ev, key
    assert ev["description"].startswith("An unauthenticated attacker")
    assert ev["same_line_fix"] == "2.5.21" and ev["fixed_versions"] == ["2.4.24", "2.5.21", "2.6.5"]
    assert ev["workaround"]["source_url"].endswith("GHSA-mhjq-8c7m-3f7p")
    assert finding.severity == Severity.CRITICAL and finding.collection is None
    assert "from 2.5.12 to 2.5.21" in finding.remediation
    assert "upgrade to 2.5.27" in finding.remediation
    assert "sk-secret" not in repr([f.to_dict() for f in findings]) + repr(outcomes)
    metrics = next(f for f in findings if f.evidence.get("advisory_id") == "CVE-2026-26190")
    assert metrics.evidence["applicability"] == sv.AFFECTED_AND_EXPOSED
    assert metrics.evidence["cvss"]["score"] == 9.8


@pytest.mark.parametrize("kind,expected,limit", [("pinecone", "unsupported", True),
                                                 ("qdrant", "inconclusive", False)])
def test_connector_without_server_info(kind, expected, limit, monkeypatch):
    # Neither the connector nor its kind's store_facts adapter can answer.
    from vecshield_platform import store_facts

    monkeypatch.setattr(store_facts, "supported", lambda connector: set())
    _, outcomes = sv.run_server_vulnerability_checks(
        FakeConnector(kind, caps=()), "store", feed=milvus_feed(), now=NOW)
    assert {o["outcome"] for o in outcomes} == {expected}
    assert all(capability_limited(o) is limit for o in outcomes)


def test_capability_is_decided_by_store_facts_not_the_connector_flag():
    """A connector implementing server_info() is read even if capabilities() is empty."""
    info = {"product": "milvus", "version": "2.5.12", "features": {}}
    _, outcomes = sv.run_server_vulnerability_checks(
        FakeConnector("milvus", info, caps=()), Store(), feed=milvus_feed(), now=NOW)
    assert outcome(outcomes, "server_vulnerability")["outcome"] == "failed"


def test_info_reader_replays_gathered_facts_and_unsupported_is_not_an_error():
    class Unreachable(FakeConnector):
        def server_info(self):
            raise AssertionError("the store must not be asked twice")

    info = {"product": "milvus", "version": "2.5.12", "features": {}}
    _, outcomes = sv.run_server_vulnerability_checks(
        Unreachable("milvus"), Store(), feed=milvus_feed(), now=NOW, info_reader=lambda: info)
    assert outcome(outcomes, "server_vulnerability")["outcome"] == "failed"

    def unsupported():
        raise UnsupportedCapability("no")

    _, outcomes = sv.run_server_vulnerability_checks(
        Unreachable("pinecone"), Store(), feed=milvus_feed(), now=NOW,
        info_reader=unsupported)
    assert {o["outcome"] for o in outcomes} == {"unsupported"}
    assert all(capability_limited(o) for o in outcomes)


def test_server_info_failure_is_an_error_outcome():
    _, outcomes = sv.run_server_vulnerability_checks(
        FakeConnector("qdrant", raises=ConnectionError("down")), "s", feed=milvus_feed(),
        now=NOW)
    assert {o["outcome"] for o in outcomes} == {"error"}


def test_bundled_seed_grounds_milvus_remediation():
    """Recorded data: the shipped seed gives the 2.5-line fix for CVE-2025-64513."""
    feed = vf.load_feed(None)
    assessment = sv.assess_server({"product": "milvus", "version": "2.5.12"}, feed, now=NOW)
    match = next(m for m in assessment.matches if m.id == "CVE-2025-64513")
    assert match.same_line_fix == "2.5.21"
    assert "sourceID header" in match.advisory["workaround"]["text"]


def test_no_workaround_statement_is_not_presented_as_a_mitigation():
    record = dict(MILVUS_RECORDS[1], workaround={
        "heading": "Workarounds", "text": "There are no known workarounds.", "none_known": True,
        "source_url": "https://example.org/a"})
    feed = make_feed(advisory_source("milvus", [record]))
    findings, _ = sv.findings_and_outcomes(
        sv.assess_server({"product": "milvus", "version": "2.5.12"}, feed, now=NOW), "m")
    text = findings[0].remediation
    assert "states there is no workaround" in text and "Until you can upgrade" not in text
