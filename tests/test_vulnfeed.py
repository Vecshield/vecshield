"""Advisory feed: normalisation, atomic persistence, partial failure, seed, schedule.

All network traffic is replaced by a fake ``fetch`` serving trimmed copies of
real responses recorded from OSV, GitHub, NVD, postgresql.org, CISA KEV and
endoflife.date. No test touches the network.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vecshield_platform.posture import vulnfeed as vf
from vecshield_platform.posture.cvss import score_to_severity, v3_base_score
from vecshield.models import Severity

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)

# --- recorded fixtures (trimmed) ---------------------------------------------------

OSV_MILVUS_GHSA = {
    "id": "GHSA-mhjq-8c7m-3f7p",
    "aliases": ["BIT-milvus-2025-64513", "CVE-2025-64513", "GO-2025-4114"],
    "summary": "Milvus Proxy has a Critical Authentication Bypass Vulnerability",
    "details": (
        "### Impact\n_What kind of vulnerability is it? Who is impacted?_\nAn unauthenticated "
        "attacker can exploit this vulnerability to bypass all authentication mechanisms in the "
        "Milvus Proxy component.\n\n### Patches\nThis issue has been fixed in the following "
        "versions:\n\t•\tMilvus 2.4.24\n\t•\tMilvus 2.5.21\n\t•\tMilvus 2.6.5\n\n"
        "### Workarounds\n_Is there a way for users to fix or remediate the vulnerability "
        "without upgrading?_\nIf immediate upgrade is not possible, a temporary mitigation can "
        "be applied by removing the sourceID header from all incoming requests at the gateway, "
        "API gateway, or load balancer level before they reach the Milvus Proxy.\n\n"
        "### References\n_Are there any links users can visit to find out more?_\n"),
    "severity": [{"type": "CVSS_V4",
                  "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
    "affected": [
        {"package": {"name": "github.com/milvus-io/milvus", "ecosystem": "Go"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.10.4"}, {"fixed": "2.4.24"}]}]},
        {"package": {"name": "github.com/milvus-io/milvus", "ecosystem": "Go"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.5.0"}, {"fixed": "2.5.21"}]}]},
        {"package": {"name": "github.com/milvus-io/milvus", "ecosystem": "Go"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.6.0"}, {"fixed": "2.6.5"}]}]},
        {"package": {"name": "github.com/milvus-io/milvus", "ecosystem": "Go"},
         "ranges": [{"type": "SEMVER", "events": [
             {"introduced": "0"}, {"fixed": "0.10.3-0.20251107071934-6102f001a971"}]}]},
    ],
    "references": [{"type": "WEB",
                    "url": "https://github.com/milvus-io/milvus/security/advisories/"
                           "GHSA-mhjq-8c7m-3f7p"}],
    "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-287"]},
    "published": "2025-11-13T15:55:00Z", "modified": "2026-02-20T09:26:04Z",
}

OSV_MILVUS_GO = {
    "id": "GO-2025-4114",
    "aliases": ["BIT-milvus-2025-64513", "CVE-2025-64513", "GHSA-mhjq-8c7m-3f7p"],
    "summary": "Milvus Proxy has a Critical Authentication Bypass Vulnerability in "
               "github.com/milvus-io/milvus",
    "details": "Milvus Proxy has a Critical Authentication Bypass Vulnerability",
    "affected": [{
        "package": {"name": "github.com/milvus-io/milvus", "ecosystem": "Go"},
        "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "0.10.3-0.20251107071934-6102f001a971"},
            {"introduced": "0.10.4"}]}],
        "ecosystem_specific": {"custom_ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "2.4.24"}, {"introduced": "2.5.0"},
            {"fixed": "2.5.21"}, {"introduced": "2.6.0"}, {"fixed": "2.6.5"}]}]},
    }],
    "published": "2025-11-17T19:11:25Z", "modified": "2026-02-20T09:26:04Z",
}

OSV_MILVUS_METRICS = {
    "id": "GHSA-7ppg-37fh-vcr6",
    "aliases": ["CVE-2026-26190", "GO-2026-4481"],
    "summary": "Milvus: Unauthenticated Access to Restful API on Metrics Port (9091)",
    "details": ("## Summary\nMilvus exposes TCP port 9091 by default.\n\n## Remediation\n\n"
                "### Recommended Fixes\n1. Remove the `/expr` endpoint.\n\n"
                "### User Mitigations (until patched)\n\n- Block external access to port 9091 "
                "using firewall rules or network policies.\n\n## Credit\nsomeone"),
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {"package": {"name": "github.com/milvus-io/milvus", "ecosystem": "Go"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.5.27"}]}]},
        {"package": {"name": "github.com/milvus-io/milvus", "ecosystem": "Go"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.6.0"}, {"fixed": "2.6.10"}]}]},
    ],
    "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-306"]},
    "published": "2026-02-11T19:49:44Z",
}

GITHUB_MILVUS = [{
    "ghsa_id": "GHSA-jh4h-22hq-x74p", "cve_id": None, "state": "published",
    "html_url": "https://github.com/milvus-io/milvus/security/advisories/GHSA-jh4h-22hq-x74p",
    "summary": "Import bypasses collection-level RBAC and reads Milvus internal storage",
    "description": "### Impact\nImport bypasses RBAC.\n\n### Workarounds\nGrant the Import "
                   "privilege only to fully trusted roles until you\nupgrade.\n",
    "severity": "medium", "cvss_severities": {"cvss_v3": {"vector_string":
                                                          "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                                                          "score": 6.5}},
    "cwe_ids": ["CWE-862"],
    "vulnerabilities": [
        {"package": {"ecosystem": "go", "name": "github.com/milvus-io/milvus"},
         "vulnerable_version_range": "< 2.6.25", "patched_versions": "2.6.25"},
        {"package": {"ecosystem": "go", "name": "github.com/milvus-io/milvus"},
         "vulnerable_version_range": ">= 3.0.0, < 3.0.3", "patched_versions": "3.0.3"}],
    "published_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-02T00:00:00Z",
}]

NVD_MILVUS = {"totalResults": 1, "vulnerabilities": [{"cve": {
    "id": "CVE-2026-10814", "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "A vulnerability has been found in milvus-io "
                                             "milvus up to 2.6.13. It uses a weak hash."}],
    "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
        "vectorString": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L", "baseScore": 4.2}}]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-327"}]}],
    "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:milvus:milvus:*:*:*:*:*:*:*:*",
         "versionEndIncluding": "2.6.13"}]}]}],
    "references": [{"url": "https://github.com/milvus-io/milvus/pull/50060"}],
    "published": "2026-06-04T00:00:00", "lastModified": "2026-07-01T00:00:00",
}}]}

KEV = {"catalogVersion": "2026.09.27", "dateReleased": "2026-09-27T21:30:35Z",
       "vulnerabilities": [
           {"cveID": "CVE-2025-64513", "vendorProject": "Milvus", "product": "Milvus",
            "vulnerabilityName": "Milvus Proxy Authentication Bypass (fixture)",
            "dateAdded": "2026-01-10", "dueDate": "2026-01-31",
            "requiredAction": "Apply mitigations per vendor instructions.",
            "knownRansomwareCampaignUse": "Unknown", "shortDescription": "fixture"},
           {"cveID": "CVE-2099-0001", "vendorProject": "Acme", "product": "Widget",
            "dateAdded": "2026-01-01", "dueDate": "2026-01-21", "requiredAction": "x"}]}

PG_SECURITY_PAGE = """
<table class="table table-striped"><tbody>
      <tr>
        <td>
          <span class="nobr"><a href="/support/security/CVE-2025-1094/">CVE-2025-1094</a></span><br/>
          <a href="/about/news/postgresql-173-167-1511-1416-and-1319-released-3015/">Announcement</a><br/>
        </td>
        <td>17, 16, 15, 14</td>
        <td>17.3, 16.7, 15.11, 14.16</td>
        <td>core server<br/>
          <a href="https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H">8.1</a><br/><span class="cvssvector">AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</span>
    </td>
        <td>PostgreSQL quoting APIs miss neutralizing quoting syntax in text that fails encoding validation<br/><br/><a href="/support/security/CVE-2025-1094/">more details</a></td>
      </tr>
</tbody></table>
"""

PG_CVE_PAGE = """
<h1>CVE-2025-1094 <i class="fas fa-lock"></i></h1>
<h3>PostgreSQL quoting APIs miss neutralizing quoting syntax</h3>
<p>Improper neutralization of quoting syntax in PostgreSQL libpq functions allows SQL injection.
Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.</p>
<h2>Version Information</h2>
<table class="table"><tbody>
<tr><td> 17 </td><td><a href="/docs/release/17.3"> 17.3 </a></td><td>2025-02-13</td></tr>
<tr><td> 16 </td><td><a href="/docs/release/16.7"> 16.7 </a></td><td>2025-02-13</td></tr>
<tr><td> 13 </td><td><a href="/docs/release/13.19"> 13.19 </a></td><td>2025-02-13</td></tr>
</tbody></table>
"""

EOL_POSTGRES = {"result": {"links": {"releasePolicy": "https://www.postgresql.org/support/versioning/"},
                           "releases": [
                               {"name": "17", "releaseDate": "2024-09-26", "isEol": False,
                                "eolFrom": "2029-11-08", "isMaintained": True,
                                "latest": {"name": "17.11", "date": "2026-08-10"}},
                               {"name": "13", "releaseDate": "2020-09-24", "isEol": True,
                                "eolFrom": "2025-11-13", "isMaintained": False,
                                "latest": {"name": "13.22", "date": "2025-08-14"}}]}}


class FakeFetch:
    """Serves recorded payloads by URL; records every request."""

    def __init__(self, routes: dict[str, object], fail: tuple[str, ...] = ()) -> None:
        self.routes = routes
        self.fail = fail
        self.calls: list[tuple[str, str, bytes | None]] = []

    def __call__(self, url, *, method="GET", body=None, headers=None, timeout=30.0):
        self.calls.append((method, url, body))
        for needle in self.fail:
            if needle in url or (body and needle.encode() in body):
                raise vf.FetchError(f"simulated outage for {needle}")
        for needle, payload in self.routes.items():
            if needle in url or (body and needle.encode() in body):
                if isinstance(payload, (bytes, str)):
                    return payload.encode() if isinstance(payload, str) else payload
                return json.dumps(payload).encode()
        raise vf.FetchError(f"no fixture for {url}")


def milvus_routes() -> dict[str, object]:
    return {
        "github.com/milvus-io/milvus": {"vulns": [OSV_MILVUS_GHSA, OSV_MILVUS_GO,
                                                  OSV_MILVUS_METRICS]},
        "repos/milvus-io/milvus/security-advisories": GITHUB_MILVUS,
        "cpe%3A2.3%3Aa%3Amilvus%3Amilvus": NVD_MILVUS,
        "known_exploited_vulnerabilities": KEV,
    }


def refresh(tmp_path: Path, fetch: FakeFetch, **kw) -> vf.RefreshResult:
    return vf.refresh_feed(tmp_path, products=["milvus"], fetch=fetch, now=NOW,
                           sleep=lambda _s: None, base=kw.pop("base", {}), **kw)


# --- CVSS -------------------------------------------------------------------------

@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),       # Redis CVE-2025-49844
    ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.5),       # Qdrant CVE-2026-25628
    ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),                # PostgreSQL page, bare
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:L", 3.8),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_v3_base_score_matches_first_calculator(vector, score):
    assert v3_base_score(vector) == score


def test_v4_and_garbage_vectors_are_not_scored():
    assert v3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert v3_base_score("not a vector") is None
    assert score_to_severity(None, "MODERATE") == Severity.MEDIUM
    assert score_to_severity(None, "") is None


# --- text -------------------------------------------------------------------------

def test_clean_text_drops_code_and_template_prompts():
    text = vf.clean_text("### Impact\n_Who is impacted?_\nAll users.\n```python\nexploit()\n```\n"
                         "See [the fix](https://example.org/fix).")
    assert "exploit()" not in text and "Who is impacted" not in text
    assert "All users." in text and "the fix" in text and "[code omitted]" in text


def test_workaround_extracted_verbatim_from_advisory_heading():
    url = "https://github.com/x/y/security/advisories/GHSA-1"
    got = vf.extract_workaround(OSV_MILVUS_GHSA["details"], url)
    assert got["heading"] == "Workarounds"
    assert got["text"].startswith("If immediate upgrade is not possible, a temporary mitigation")
    assert "Is there a way" not in got["text"] and got["source_url"] == url


def test_workaround_nested_mitigation_section_and_sentence_fallback():
    got = vf.extract_workaround(OSV_MILVUS_METRICS["details"], "u")
    assert got["heading"] == "User Mitigations (until patched)"
    assert "Block external access to port 9091" in got["text"] and "Credit" not in got["text"]
    nvd = ("Versions 8.2.1 and below allow a use-after-free. This issue is fixed in version "
           "8.2.2. To workaround this issue without patching the redis-server executable is to "
           "prevent users from executing Lua scripts. This can be done using ACL to restrict "
           "EVAL and EVALSHA commands.")
    got = vf.extract_workaround(nvd, "n")
    assert got["heading"] == "" and "prevent users from executing Lua scripts" in got["text"]
    assert vf.extract_workaround("No mitigations section here at all, just words.", "u") is None


# --- ranges -----------------------------------------------------------------------

def test_osv_events_split_into_intervals_and_pseudo_ranges_dropped():
    assert vf.events_to_ranges([{"introduced": "0"}, {"fixed": "2.4.24"},
                                {"introduced": "2.5.0"}, {"fixed": "2.5.21"}]) == [
        {"fixed": "2.4.24"}, {"introduced": "2.5.0", "fixed": "2.5.21"}]
    assert vf.events_to_ranges([{"introduced": "0"},
                                {"fixed": "0.10.3-0.20251107071934-6102f001a971"},
                                {"introduced": "0.10.4"}]) == []
    assert vf.events_to_ranges([{"introduced": "0.4.17"}, {"last_affected": "1.5.9"}]) == [
        {"introduced": "0.4.17", "last_affected": "1.5.9"}]


@pytest.mark.parametrize("vulnerable,patched,expected", [
    ("All", "6.2.20, 7.2.11, 7.4.6, 8.0.4, 8.2.2",
     [{"fixed": "6.2.20"}, {"introduced": "6.3.0", "fixed": "7.2.11"},
      {"introduced": "7.3.0", "fixed": "7.4.6"}, {"introduced": "7.5.0", "fixed": "8.0.4"},
      {"introduced": "8.1.0", "fixed": "8.2.2"}]),
    ("7.0 and newer", "7.0.13, 7.2.1",
     [{"introduced": "7.0", "fixed": "7.0.13"}, {"introduced": "7.1.0", "fixed": "7.2.1"}]),
    ("< 2.6.25", "2.6.25", [{"fixed": "2.6.25"}]),
    (">= 3.0.0, < 3.0.3", "3.0.3", [{"introduced": "3.0.0", "fixed": "3.0.3"}]),
    ("<1.20", "1.20.6, 1.19.13, and 1.18.6",
     [{"fixed": "1.18.6"}, {"introduced": "1.19.0", "fixed": "1.19.13"},
      {"introduced": "1.20.0", "fixed": "1.20.6"}]),
    ("1.0.0–2.19.3,3.0.0–3.1.0", ">=2.19.4.0,>=3.2.0.0",
     [{"introduced": "1.0.0", "fixed": "2.19.4.0"},
      {"introduced": "2.20.0", "fixed": "3.2.0.0"}]),
    ("All", "TBD", [{}]),
    (">= 7.0.0", "TBD", [{"introduced": "7.0.0"}]),
])
def test_github_repo_ranges(vulnerable, patched, expected):
    ranges, raw = vf.parse_github_ranges("redis", vulnerable, patched)
    assert raw == "" and ranges == expected


def test_github_unclear_ranges_are_kept_as_text_not_guessed():
    ranges, raw = vf.parse_github_ranges("redis", "some builds before spring", "TBD")
    assert ranges == [] and "some builds before spring" in raw
    ranges, raw = vf.parse_github_ranges("milvus", "<2.4.24, <2.5.21", "")
    assert ranges == [] and raw


def test_normalise_osv_keeps_release_ranges_only():
    spec = vf.SourceSpec("osv_package", ecosystem="Go", package="github.com/milvus-io/milvus")
    record = vf.normalise_osv(OSV_MILVUS_GHSA, spec)
    assert record["ranges"] == [{"introduced": "0.10.4", "fixed": "2.4.24"},
                                {"introduced": "2.5.0", "fixed": "2.5.21"},
                                {"introduced": "2.6.0", "fixed": "2.6.5"}]
    assert record["cwe"] == ["CWE-287"] and record["severity_label"] == "CRITICAL"
    assert record["cvss"][0]["score"] is None                 # v4 vector: never estimated
    assert record["workaround"]["heading"] == "Workarounds"
    go = vf.normalise_osv(OSV_MILVUS_GO, spec)                 # custom_ranges carry releases
    assert {"introduced": "2.5.0", "fixed": "2.5.21"} in go["ranges"]
    assert vf.normalise_osv({**OSV_MILVUS_GHSA, "withdrawn": "2026-01-01"}, spec) is None


def test_normalise_nvd_and_configurations():
    spec = vf.SourceSpec("nvd_cpe", cpe="cpe:2.3:a:mongodb:mongodb")
    with_app = {"cve": {"id": "CVE-2014-8180", "descriptions": [{"lang": "en", "value": "x"}],
                        "configurations": [{"operator": "AND", "nodes": [
                            {"cpeMatch": [{"vulnerable": True,
                                           "criteria": "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"}]},
                            {"cpeMatch": [{"vulnerable": False,
                                           "criteria": "cpe:2.3:a:redhat:satellite:6.0:*:*:*:*:*:*:*"}]}]}]}}
    record = vf.normalise_nvd(with_app, spec)
    assert "ranges" not in record and "redhat:satellite" in record["unparsed"]
    on_os = json.loads(json.dumps(with_app))
    on_os["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "4.0.10"
    on_os["cve"]["configurations"][0]["nodes"][1]["cpeMatch"][0]["criteria"] = \
        "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"
    record = vf.normalise_nvd(on_os, spec)
    assert record["ranges"] == [{"fixed": "4.0.10"}] and record["platforms"] == ["microsoft:windows"]
    no_version = json.loads(json.dumps(with_app))
    no_version["cve"]["configurations"] = [{"nodes": [{"cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:mongodb:mongodb:-:*:*:*:*:*:*:*"}]}]}]
    assert "not version-identified" in vf.normalise_nvd(no_version, spec)["unparsed"]


def test_postgres_security_page_and_cve_page():
    rows = vf.parse_postgres_security_page(PG_SECURITY_PAGE)
    assert rows[0]["id"] == "CVE-2025-1094" and rows[0]["component"] == "core server"
    assert rows[0]["fixed"] == ["17.3", "16.7", "15.11", "14.16"] and rows[0]["score"] == 8.1
    detail = vf.parse_postgres_cve_page(PG_CVE_PAGE)
    assert detail["description"].startswith("Improper neutralization of quoting syntax")
    assert ("13", "13.19") in detail["versions"]
    assert vf._pg_ranges(detail["versions"])[-1] == {"introduced": "13.0", "fixed": "13.19"}


# --- refresh / persistence --------------------------------------------------------

def test_refresh_writes_feed_and_meta_atomically(tmp_path):
    fetch = FakeFetch(milvus_routes())
    result = refresh(tmp_path, fetch)
    assert result.ok
    folder = tmp_path / "vulnfeed"
    assert sorted(p.name for p in folder.iterdir()) == ["feed.json", "meta.json"]
    raw = (folder / "feed.json").read_bytes()
    meta = json.loads((folder / "meta.json").read_text())
    import hashlib
    assert meta["feed_hash"] == hashlib.sha256(raw).hexdigest() == result.feed_hash
    assert meta["updated_at"] == "2026-09-29T12:00:00Z"
    assert all(s["ok"] for s in meta["sources"].values())
    assert oct(os.stat(folder / "feed.json").st_mode & 0o777) == "0o600"
    # Only the fixed catalogue endpoints were contacted, over HTTPS.
    assert all(url.startswith("https://") for _m, url, _b in fetch.calls)
    feed = vf.load_feed(tmp_path)
    assert feed.origin == "state"
    advisories = {a["id"]: a for a in feed.advisories("milvus")}
    merged = advisories["CVE-2025-64513"]
    assert {"GHSA-mhjq-8c7m-3f7p", "GO-2025-4114"} <= set(merged["aliases"])
    assert merged["range_source"]["kind"] == "osv_ghsa"
    assert merged["kev"]["due_date"] == "2026-01-31"
    kev_entries = feed.raw["sources"]["kev"]["data"]["entries"]
    assert "CVE-2099-0001" not in kev_entries              # unrelated products filtered out
    assert advisories["CVE-2026-10814"]["range_source"]["kind"] == "nvd_cpe"
    assert advisories["GHSA-jh4h-22hq-x74p"]["workaround"]["text"].endswith("until you upgrade.")


def test_partial_failure_keeps_previous_source_data(tmp_path):
    refresh(tmp_path, FakeFetch(milvus_routes()))
    before = json.loads((tmp_path / "vulnfeed" / "feed.json").read_text())
    later = NOW + timedelta(days=1)
    fetch = FakeFetch(milvus_routes(), fail=("repos/milvus-io/milvus",))
    result = vf.refresh_feed(tmp_path, products=["milvus"], fetch=fetch, now=later,
                             sleep=lambda _s: None)
    assert not result.ok
    key = "github_repo:milvus:server:milvus-io/milvus"
    status = result.sources[key]
    assert status["ok"] is False and status["kept_previous"] is True and status["count"] == 1
    assert "simulated outage" in status["error"]
    after = json.loads((tmp_path / "vulnfeed" / "feed.json").read_text())
    assert after["sources"][key] == before["sources"][key]          # never wiped
    assert after["updated_at"] == "2026-09-30T12:00:00Z"            # other sources updated
    meta = json.loads((tmp_path / "vulnfeed" / "meta.json").read_text())
    assert meta["sources"][key]["ok"] is False


def test_total_failure_keeps_old_timestamp(tmp_path):
    refresh(tmp_path, FakeFetch(milvus_routes()))
    result = vf.refresh_feed(tmp_path, products=["milvus"], now=NOW + timedelta(days=3),
                             fetch=FakeFetch({}, fail=("",)), sleep=lambda _s: None)
    assert not result.ok and result.updated_at == "2026-09-29T12:00:00Z"
    assert vf.load_feed(tmp_path).age_days(NOW + timedelta(days=3)) == 3.0


def test_failed_write_leaves_previous_file_and_no_temp(tmp_path, monkeypatch):
    target = tmp_path / "feed.json"
    vf.atomic_write_json(target, {"v": 1})

    def boom(*_a, **_k):
        raise OSError("disk full")
    monkeypatch.setattr(vf.os, "replace", boom)
    with pytest.raises(OSError):
        vf.atomic_write_json(target, {"v": 2})
    assert json.loads(target.read_text()) == {"v": 1}
    assert [p.name for p in tmp_path.iterdir()] == ["feed.json"]


def test_unknown_product_rejected(tmp_path):
    with pytest.raises(ValueError):
        vf.refresh_feed(tmp_path, products=["nosuchdb"], fetch=FakeFetch({}))


def test_postgres_detail_pages_reused_on_later_refresh(tmp_path):
    routes = {"/support/security/CVE-2025-1094/": PG_CVE_PAGE,
              "support/security/": PG_SECURITY_PAGE, "endoflife.date": EOL_POSTGRES,
              "known_exploited": KEV, "pgvector": {"vulns": []},
              "services.nvd.nist.gov": {"totalResults": 0, "vulnerabilities": []}}
    fetch = FakeFetch(routes)
    vf.refresh_feed(tmp_path, products=["postgresql"], fetch=fetch, now=NOW,
                    sleep=lambda _s: None, base={})
    assert sum("CVE-2025-1094/" in u for _m, u, _b in fetch.calls) == 1
    fetch2 = FakeFetch(routes)
    vf.refresh_feed(tmp_path, products=["postgresql"], fetch=fetch2, now=NOW,
                    sleep=lambda _s: None)
    assert sum("CVE-2025-1094/" in u for _m, u, _b in fetch2.calls) == 0
    advisory = vf.load_feed(tmp_path).advisories("postgresql")[0]
    assert advisory["pg_component"] == "core server"
    assert {"introduced": "13.0", "fixed": "13.19"} in advisory["ranges"]
    assert vf.load_feed(tmp_path).eol("postgresql")["cycles"][0]["latest"] == "17.11"


# --- load / seed ------------------------------------------------------------------

def test_load_prefers_state_then_seed_then_none(tmp_path):
    seed = tmp_path / "seed.json"
    seed.write_text(json.dumps({"updated_at": "2026-09-01T00:00:00Z",
                                "sources": {"x": {"kind": "osv_package", "product": "qdrant",
                                                  "data": []}}}))
    state = tmp_path / "state"
    feed = vf.load_feed(state, seed_path=seed)
    assert feed.origin == "seed" and feed.error == ""
    assert feed.age_days(NOW) == pytest.approx(28.5)
    (state / "vulnfeed").mkdir(parents=True)
    (state / "vulnfeed" / "feed.json").write_text("{corrupt")
    feed = vf.load_feed(state, seed_path=seed)
    assert feed.origin == "seed" and "could not be read" in feed.error
    refresh(state, FakeFetch(milvus_routes()))
    assert vf.load_feed(state, seed_path=seed).origin == "state"
    none = vf.load_feed(tmp_path / "empty", seed_path=tmp_path / "missing.json")
    assert none.origin == "none" and not none.available


def test_bundled_seed_is_present_and_covers_catalogue():
    feed = vf.load_feed(None)
    assert feed.origin == "seed" and feed.available
    products = {entry.get("product") for entry in feed.raw["sources"].values()}
    assert set(vf.PRODUCTS) <= products
    ids = {a["id"] for a in feed.advisories("milvus")}
    assert "CVE-2025-64513" in ids
    assert oct(os.stat(vf.SEED_PATH).st_mode & 0o044) == "0o44"   # readable package data


def test_overlay_entries_cite_their_sources():
    overlay = vf.load_overlay()
    assert overlay["advisories"]
    for entry in overlay["advisories"]:
        cited = [entry.get(k) for k in ("condition", "affected_override",
                                        "exclude_from_version_matching", "advisory")
                 if entry.get(k)]
        assert cited and all(c.get("source_url", "").startswith("https://") for c in cited)
        assert all(c.get("quote") for c in cited)
        assert entry["product"] in vf.PRODUCTS


# --- schedule ---------------------------------------------------------------------

def test_schedule_defaults_off_and_clamps_interval():
    settings = vf.FeedSchedule()
    assert settings.auto_update is False and not vf.due(settings, NOW)
    assert vf.FeedSchedule(interval_hours=1).interval_hours == vf.MIN_INTERVAL_HOURS
    assert vf.FeedSchedule.from_dict({"interval_hours": "bad"}).interval_hours == 24
    round_trip = vf.FeedSchedule.from_dict(vf.FeedSchedule(True, 12, "a", "b", "e").to_dict())
    assert round_trip == vf.FeedSchedule(True, 12, "a", "b", "e")


def test_schedule_due_logic():
    iso = vf._iso
    on = vf.FeedSchedule(auto_update=True, interval_hours=24)
    assert vf.due(on, NOW)                                             # never ran
    on.last_success = on.last_attempt = iso(NOW - timedelta(hours=5))
    assert not vf.due(on, NOW)
    on.last_success = on.last_attempt = iso(NOW - timedelta(hours=25))
    assert vf.due(on, NOW)
    on.last_attempt = iso(NOW - timedelta(minutes=10))                 # failed just now
    assert not vf.due(on, NOW)
    on.last_attempt = iso(NOW - timedelta(hours=2))
    assert vf.due(on, NOW)


def test_refresh_if_due_updates_and_persists_settings(tmp_path):
    settings = vf.FeedSchedule(auto_update=False)
    same, result = vf.refresh_if_due(tmp_path, settings, now=NOW, fetch=FakeFetch({}))
    assert result is None and same.last_attempt is None
    settings, result = vf.refresh_if_due(tmp_path, settings, now=NOW, force=True,
                                         products=["milvus"], fetch=FakeFetch(milvus_routes()),
                                         sleep=lambda _s: None)
    assert result.ok and settings.last_success == "2026-09-29T12:00:00Z"
    assert vf.load_schedule(tmp_path).last_success == settings.last_success
    failing = FakeFetch({}, fail=("",))
    later = NOW + timedelta(days=2)
    settings.auto_update = True
    settings, result = vf.refresh_if_due(tmp_path, settings, now=later, products=["milvus"],
                                         fetch=failing, sleep=lambda _s: None)
    assert settings.last_success == "2026-09-29T12:00:00Z"
    assert settings.last_attempt == "2026-10-01T12:00:00Z" and "failed" in settings.last_error
    # The previous good data is still loadable after the failed tick.
    assert vf.load_feed(tmp_path).advisories("milvus")


def test_refresh_if_due_never_raises(tmp_path, monkeypatch):
    def explode(*_a, **_k):
        raise RuntimeError("token=abc123 leaked?")
    monkeypatch.setattr(vf, "refresh_feed", explode)
    settings, result = vf.refresh_if_due(tmp_path, vf.FeedSchedule(auto_update=True), now=NOW)
    assert result is None and "abc123" not in settings.last_error


@pytest.mark.parametrize("text", ["None.", "There is no recommended work around.",
                                  "There are no known workarounds to fix or remediate this."])
def test_no_workaround_statements_are_flagged(text):
    got = vf.extract_workaround(f"### Workarounds\n{text}\n", "u")
    assert got["none_known"] is True and got["text"] == text
