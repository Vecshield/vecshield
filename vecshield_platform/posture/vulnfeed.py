"""Local, versioned advisory feed for database *server* vulnerabilities.

``posture/cve.py`` checks the client libraries VecShield talks through. This
module keeps the data needed to check the database servers themselves: the
advisories that affect each server product, CISA's Known Exploited
Vulnerabilities catalog, and published end-of-life schedules.

Where the data comes from (every mapping below was verified against the live
APIs when this module was written; see ``PRODUCTS``):

* OSV.dev, per package ecosystem (Qdrant: crates.io ``qdrant``; Weaviate and
  Milvus: Go modules; Chroma: PyPI ``chromadb``; OpenSearch: Maven, including
  the security plugin) and per upstream Git repository (OSV's ``GIT``
  ecosystem, which is where pgvector and several Qdrant/Chroma CVEs live).
* GitHub repository security advisories (vendor-published; the only source of
  per-release-line fixed versions and workarounds for Redis, and of recent
  Milvus advisories not yet in OSV).
* NVD CVE API 2.0 by CPE (Redis, PostgreSQL, MongoDB, and a second opinion for
  every vector database).
* The PostgreSQL project's own security page and per-CVE pages (vendor fixed
  versions per major, CVSS vector, component).
* CISA KEV, endoflife.date, and the Weaviate release feed for its documented
  "three most recent minors" support policy.

The feed is customer-controlled: refreshing is an explicit call (an admin
action, or the scheduler when an admin has enabled auto-update), requests go
only to the fixed HTTPS endpoints in this file, nothing about the customer is
sent, and the result is written under the customer's state directory. A
bundled seed snapshot (``data/vulnfeed_seed.json``) makes the checks work
offline; ``load_feed`` reports which copy it used and how old it is.

Layout on disk (``<state_dir>/vulnfeed/``):

* ``feed.json`` — ``{"schema", "updated_at", "sources": {key: {...}}}``. Each
  source keeps its own normalised records, so a failed source keeps its last
  good data and the others still update.
* ``meta.json`` — ``{"updated_at", "last_attempt", "feed_hash", "sources":
  {key: {"ok", "count", "error", "fetched_at", "kept_previous"}}}``.
* ``schedule.json`` — the auto-update settings (``FeedSchedule``).

Regenerate the seed with ``python -m vecshield_platform.posture.vulnfeed
--write-seed``.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from vecshield_platform.posture.cvss import normalise_cvss
from vecshield_platform.posture.versions import (
    Version,
    is_pseudo_version,
    next_line_floor,
    parse_version,
)

SCHEMA_VERSION = 1
FEED_DIRNAME = "vulnfeed"
DATA_DIR = Path(__file__).resolve().parent / "data"
SEED_PATH = DATA_DIR / "vulnfeed_seed.json"
OVERLAY_PATH = DATA_DIR / "advisory_conditions.json"

USER_AGENT = "VecShield-vulnfeed/1 (self-hosted advisory mirror)"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
DETAILS_LIMIT = 1500
SUMMARY_LIMIT = 240
WORKAROUND_LIMIT = 900
MAX_REFERENCES = 8
MAX_EXPLICIT_VERSIONS = 400
NVD_PAGE_SIZE = 2000
NVD_MIN_INTERVAL_S = 6.5          # public NVD limit: 5 requests / 30 s without a key
POSTGRES_DETAIL_PAGE_LIMIT = 120

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API = "https://api.github.com"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ENDOFLIFE_URL = "https://endoflife.date/api/v1/products/{slug}/"
POSTGRES_SECURITY_URL = "https://www.postgresql.org/support/security/"


# --- product catalogue ---------------------------------------------------------

@dataclass(frozen=True)
class SourceSpec:
    """One advisory source for one product component."""

    kind: str               # osv_package | osv_git | github_repo | nvd_cpe | postgresql_org
    component: str = "server"
    ecosystem: str = ""
    package: str = ""
    repo: str = ""
    cpe: str = ""

    @property
    def target(self) -> str:
        return self.package or self.repo or self.cpe or "security-page"

    def key(self, product: str) -> str:
        return f"{self.kind}:{product}:{self.component}:{self.target}"


@dataclass(frozen=True)
class EolSpec:
    kind: str                           # endoflife | latest_n_minors | not_published
    slug: str = ""                      # endoflife.date product
    n: int = 0                          # latest_n_minors
    repo: str = ""                      # latest_n_minors: GitHub repo for the latest release
    policy_url: str = ""
    note: str = ""


@dataclass(frozen=True)
class ProductSpec:
    label: str
    sources: tuple[SourceSpec, ...]
    eol: EolSpec
    #: KEV vendorProject/product keywords that belong to this product.
    kev_keywords: tuple[str, ...] = ()
    #: server_info.features paths holding a component's version.
    components: dict[str, tuple[str, ...]] = field(default_factory=dict)


PRODUCTS: dict[str, ProductSpec] = {
    "qdrant": ProductSpec(
        label="Qdrant",
        sources=(
            SourceSpec("osv_package", ecosystem="crates.io", package="qdrant"),
            SourceSpec("osv_git", repo="https://github.com/qdrant/qdrant"),
            SourceSpec("github_repo", repo="qdrant/qdrant"),
            SourceSpec("nvd_cpe", cpe="cpe:2.3:a:qdrant:qdrant"),
        ),
        eol=EolSpec("not_published",
                    policy_url="https://qdrant.tech/documentation/upgrades/",
                    note="Qdrant documents an upgrade path but no end-of-support dates "
                         "for self-hosted releases."),
        kev_keywords=("qdrant",),
    ),
    "weaviate": ProductSpec(
        label="Weaviate",
        sources=(
            SourceSpec("osv_package", ecosystem="Go", package="github.com/weaviate/weaviate"),
            SourceSpec("github_repo", repo="weaviate/weaviate"),
            SourceSpec("nvd_cpe", cpe="cpe:2.3:a:weaviate:weaviate"),
        ),
        eol=EolSpec("latest_n_minors", n=3, repo="weaviate/weaviate",
                    policy_url="https://weaviate.io/weaviate-eol-policy",
                    note="Minor releases will be supported for the 3 most recent minor "
                         "versions."),
        kev_keywords=("weaviate",),
    ),
    "milvus": ProductSpec(
        label="Milvus",
        sources=(
            SourceSpec("osv_package", ecosystem="Go", package="github.com/milvus-io/milvus"),
            SourceSpec("github_repo", repo="milvus-io/milvus"),
            SourceSpec("nvd_cpe", cpe="cpe:2.3:a:milvus:milvus"),
        ),
        eol=EolSpec("not_published",
                    note="The Milvus project does not publish end-of-support dates for "
                         "open-source release lines."),
        kev_keywords=("milvus",),
    ),
    "chroma": ProductSpec(
        label="Chroma",
        sources=(
            SourceSpec("osv_package", ecosystem="PyPI", package="chromadb"),
            SourceSpec("osv_git", repo="https://github.com/chroma-core/chroma"),
            SourceSpec("github_repo", repo="chroma-core/chroma"),
            SourceSpec("nvd_cpe", cpe="cpe:2.3:a:trychroma:chromadb"),
        ),
        eol=EolSpec("not_published",
                    note="Chroma does not publish end-of-support dates for release lines."),
        kev_keywords=("chroma",),
    ),
    "opensearch": ProductSpec(
        label="OpenSearch",
        sources=(
            SourceSpec("osv_package", ecosystem="Maven", package="org.opensearch:opensearch"),
            SourceSpec("github_repo", repo="opensearch-project/OpenSearch"),
            SourceSpec("nvd_cpe", cpe="cpe:2.3:a:amazon:opensearch"),
            SourceSpec("osv_package", component="opensearch-security", ecosystem="Maven",
                       package="org.opensearch.plugin:opensearch-security"),
            SourceSpec("github_repo", component="opensearch-security",
                       repo="opensearch-project/security"),
            SourceSpec("nvd_cpe", component="opensearch-security",
                       cpe="cpe:2.3:a:amazon:opensearch_security"),
        ),
        eol=EolSpec("endoflife", slug="opensearch"),
        kev_keywords=("opensearch",),
        components={"opensearch-security": ("plugins.opensearch-security",
                                            "plugins.opensearch_security",
                                            "opensearch-security")},
    ),
    "postgresql": ProductSpec(
        label="PostgreSQL",
        sources=(
            SourceSpec("postgresql_org"),
            SourceSpec("nvd_cpe", cpe="cpe:2.3:a:postgresql:postgresql"),
            SourceSpec("osv_git", component="pgvector",
                       repo="https://github.com/pgvector/pgvector"),
            SourceSpec("nvd_cpe", component="pgvector",
                       cpe="cpe:2.3:a:pgvector_project:pgvector"),
        ),
        eol=EolSpec("endoflife", slug="postgresql"),
        kev_keywords=("postgresql", "pgvector"),
        # The installed package first: the C library it ships is what new
        # backends load, while pg_extension's extversion only moves on
        # ALTER EXTENSION vector UPDATE (store_facts/pgvector.py).
        components={"pgvector": ("pgvector_package", "pgvector", "extensions.vector",
                                 "extensions.pgvector")},
    ),
    "redis": ProductSpec(
        label="Redis",
        sources=(
            SourceSpec("github_repo", repo="redis/redis"),
            SourceSpec("nvd_cpe", cpe="cpe:2.3:a:redis:redis"),
            SourceSpec("nvd_cpe", cpe="cpe:2.3:a:redislabs:redis"),
        ),
        eol=EolSpec("endoflife", slug="redis"),
        kev_keywords=("redis",),
    ),
    "mongodb": ProductSpec(
        label="MongoDB",
        sources=(SourceSpec("nvd_cpe", cpe="cpe:2.3:a:mongodb:mongodb"),),
        eol=EolSpec("endoflife", slug="mongodb"),
        kev_keywords=("mongodb server", "mongodb and mongodb server"),
    ),
}

#: Server products a connector may report under another name.
PRODUCT_ALIASES = {"postgres": "postgresql", "pgvector": "postgresql", "chromadb": "chroma",
                   "mongo": "mongodb", "redis-stack": "redis"}


def canonical_product(name: object) -> str:
    key = str(name or "").strip().lower()
    return PRODUCT_ALIASES.get(key, key)


# --- HTTP ----------------------------------------------------------------------

FetchFn = Callable[..., bytes]


class FetchError(RuntimeError):
    pass


def default_fetch(url: str, *, method: str = "GET", body: Optional[bytes] = None,
                  headers: Optional[dict[str, str]] = None, timeout: float = 30.0) -> bytes:
    """HTTPS GET/POST with a size cap. Only catalogue URLs are ever passed in."""
    if not url.startswith("https://"):
        raise FetchError(f"refusing non-HTTPS URL {url!r}")
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    req_headers.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URLs
            data = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise FetchError(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError(f"network error reaching {urllib.parse.urlsplit(url).netloc}: "
                         f"{getattr(exc, 'reason', exc)}") from exc
    if len(data) > MAX_RESPONSE_BYTES:
        raise FetchError("response exceeded the size limit")
    return data


def _json(fetch: FetchFn, url: str, *, timeout: float, method: str = "GET",
          payload: Optional[dict] = None, headers: Optional[dict[str, str]] = None) -> Any:
    body = json.dumps(payload).encode() if payload is not None else None
    hdrs = dict(headers or {})
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    raw = fetch(url, method=method, body=body, headers=hdrs, timeout=timeout)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FetchError(f"invalid JSON from {urllib.parse.urlsplit(url).netloc}") from exc


# --- text helpers --------------------------------------------------------------

_CODE_FENCE = re.compile(r"```.*?(```|$)", re.S)
_MD_LINK = re.compile(r"!?\[([^\]]*)\]\((https?://[^)\s]+)\)")
_HTML_TAG = re.compile(r"<[^>]+>")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_text(text: object, limit: int = DETAILS_LIMIT) -> str:
    """Markdown/HTML to plain, trimmed text. Code blocks (PoCs) are dropped."""
    if not text:
        return ""
    out = str(text).replace("\r\n", "\n")
    out = _TEMPLATE_PROMPT.sub("", out)
    out = _CODE_FENCE.sub(" [code omitted] ", out)
    out = _MD_LINK.sub(lambda m: m.group(1) or m.group(2), out)
    out = _HTML_TAG.sub(" ", out)
    out = html.unescape(out)
    out = _CTRL.sub("", out)
    out = re.sub(r"^\s{0,3}#{1,6}\s*", "", out, flags=re.M)
    out = re.sub(r"[*_`]{1,3}(\S[^*_`]*?)[*_`]{1,3}", r"\1", out)
    out = re.sub(r"^\s*[-*•]\s+", "- ", out, flags=re.M)
    out = re.sub(r"[ \t ￼]+", " ", out)
    out = re.sub(r"\n\s*\n+", "\n", out).strip()
    return trim(out, limit)


def trim(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(",;:")
    return cut + " …"


_HEADING = re.compile(r"^(#{1,6})\s*(.+?)\s*#*\s*$", re.M)
#: GitHub's advisory template prompts ("_Is there a way for users to fix ...?_").
_TEMPLATE_PROMPT = re.compile(r"^\s*_[^_\n]+\?_\s*$", re.M)
_WORKAROUND_HEADING = re.compile(r"workaround|mitigat", re.I)
_WORKAROUND_SENTENCE = re.compile(r"[^.\n]*\b(?:workaround|mitigat\w*)\b[^.\n]*(?:\.[^.\n]*?"
                                  r"(?:ACL|restrict|disabl|config)[^.\n]*)*\.?", re.I)


#: Sections that say there is nothing to do but upgrade.
_NO_WORKAROUND = re.compile(r"^\s*(none\b|n/a\b|no\b[^.]*\bwork ?arounds?\b|there (is|are) no\b)",
                            re.I)
#: A workaround sentence must tell the reader to do something.
_ACTION = re.compile(r"\b(prevent|restrict|disabl\w*|block|remov\w*|set|limit|avoid|deny|"
                     r"configur\w*|upgrad\w*|apply|revok\w*|rotat\w*|firewall)\b", re.I)


def extract_workaround(markdown: str, source_url: str) -> Optional[dict]:
    """The advisory's own workaround/mitigation text, verbatim (trimmed).

    GitHub advisories carry it under a ``### Workarounds`` or ``Mitigation``
    heading; CVE descriptions carry it as a sentence ("To workaround this issue
    ..."). Nothing is paraphrased; text with no such section yields None.
    """
    if not markdown:
        return None
    headings = list(_HEADING.finditer(markdown))
    for index, match in enumerate(headings):
        title = match.group(2).strip()
        if not _WORKAROUND_HEADING.search(title):
            continue
        level = len(match.group(1))
        end = len(markdown)
        for later in headings[index + 1:]:
            if len(later.group(1)) <= level:
                end = later.start()
                break
        section = _TEMPLATE_PROMPT.sub("", markdown[match.end():end])
        body = re.sub(r"\n(?!- )", " ", clean_text(section, WORKAROUND_LIMIT))
        if body:
            found = {"heading": clean_text(title, 120), "text": body, "source_url": source_url}
            if _NO_WORKAROUND.match(body):
                found["none_known"] = True
            return found
    plain = clean_text(markdown, 4000)
    sentences = [s.strip() for s in _WORKAROUND_SENTENCE.findall(plain)
                 if len(s.strip()) > 25 and _ACTION.search(s)]
    if sentences:
        return {"heading": "", "text": trim(" ".join(sentences), WORKAROUND_LIMIT),
                "source_url": source_url}
    return None


def first_sentence(text: str, limit: int = SUMMARY_LIMIT) -> str:
    text = clean_text(text, 2000)
    match = re.match(r"(.+?[.!?])(\s|$)", text, re.S)
    return trim((match.group(1) if match else text).strip(), limit)


# --- range helpers -----------------------------------------------------------

def events_to_ranges(events: Iterable[dict]) -> list[dict]:
    """OSV range events -> intervals (``introduced``/``fixed``/``last_affected``).

    A range that contains a Go pseudo-version is in the module-commit namespace,
    not the server release namespace, so the whole range is dropped.
    """
    events = list(events or [])
    for event in events:
        for value in event.values():
            if isinstance(value, str) and is_pseudo_version(value):
                return []
    ranges: list[dict] = []
    start: Optional[str] = None
    started = False
    for event in events:
        if "introduced" in event:
            start, started = str(event["introduced"]), True
        elif "fixed" in event and started:
            ranges.append(_interval(start, fixed=str(event["fixed"])))
            started = False
        elif "last_affected" in event and started:
            ranges.append(_interval(start, last_affected=str(event["last_affected"])))
            started = False
        elif "limit" in event and started:
            ranges.append(_interval(start, before=str(event["limit"])))
            started = False
    if started:
        ranges.append(_interval(start))
    return [r for r in ranges if _interval_parseable(r)]


def _interval(start: Optional[str], **end: str) -> dict:
    out: dict[str, Any] = {}
    if start and start not in ("0", "0.0.0"):
        out["introduced"] = start.lstrip("vV") if start[:1] in "vV" else start
    for key, value in end.items():
        out[key] = value.lstrip("vV") if value[:1] in "vV" else value
    return out


def _interval_parseable(interval: dict) -> bool:
    for key in ("introduced", "fixed", "last_affected", "before", "version"):
        if key in interval and parse_version(interval[key]) is None:
            return False
    return True


def parse_github_ranges(product: str, vulnerable: str, patched: str) -> tuple[list[dict], str]:
    """GitHub repository advisory ranges -> intervals, or ([], raw) when unclear.

    Vendors write these by hand: ``"< 2.6.25"``, ``">= 3.0.0, < 3.0.3"``,
    ``"All"`` with patched ``"6.2.20, 7.2.11, 7.4.6, 8.0.4, 8.2.2"``,
    ``"1.0.0–2.19.3,3.0.0–3.1.0"`` with ``">=2.19.4.0,>=3.2.0.0"``. A patched
    list names one fixed release per maintenance line, so it is read as: every
    version below the highest fix is affected, except versions on a fixed line
    at or above that line's fix. A lower bound (``>=``, ``and newer``, ``X–Y``)
    clips the start. Anything that does not parse cleanly is kept as text and
    the advisory is reported as undetermined, never guessed.
    """
    vulnerable = (vulnerable or "").strip()
    patched = (patched or "").strip()
    raw = f"affected: {vulnerable or '?'}; patched: {patched or '?'}"
    fixes = []
    if patched and not re.search(r"\b(tbd|none|n/a|unpatched)\b", patched, re.I):
        for token in re.findall(r"\d+(?:\.\d+)+", patched):
            parsed = parse_version(token)
            if parsed is not None:
                fixes.append(parsed)
    lower = _github_lower_bound(vulnerable)
    if fixes:
        fixes = sorted(set(fixes))
        ranges: list[dict] = []
        start: Optional[Version] = lower
        for fix in fixes:
            if start is None or start < fix:
                entry = {"fixed": fix.raw}
                if start is not None:
                    entry["introduced"] = start.raw
                ranges.append(entry)
            start = next_line_floor(product, fix)
            if lower is not None and start < lower:
                start = lower
        return ranges, ""
    # No usable patched list: accept only a single simple conjunction.
    if re.fullmatch(r"(?i)all( versions)?", vulnerable):
        return [{}], ""
    parts = [p.strip() for p in vulnerable.split(",") if p.strip()]
    interval: dict[str, str] = {}
    for part in parts:
        match = re.fullmatch(r"(>=|>|<=|<|=)\s*v?(\d+(?:\.\d+)*)", part)
        if not match:
            return [], raw
        op, value = match.groups()
        key = {">=": "introduced", ">": "introduced", "<": "before", "<=": "last_affected",
               "=": "version"}[op]
        if key in interval:
            return [], raw                       # two upper bounds: ambiguous
        interval[key] = value
        if op == ">":
            interval["introduced_exclusive"] = "1"
    if not interval:
        return [], raw
    return [interval], ""


def _github_lower_bound(text: str) -> Optional[Version]:
    candidates: list[Version] = []
    for match in re.finditer(r"(>=|=>|>)\s*v?(\d+(?:\.\d+)*)", text):
        parsed = parse_version(match.group(2))
        if parsed:
            candidates.append(parsed)
    for match in re.finditer(r"v?(\d+(?:\.\d+)*)\s*(?:and newer|or newer|or later|\+)", text):
        parsed = parse_version(match.group(1))
        if parsed:
            candidates.append(parsed)
    for match in re.finditer(r"v?(\d+(?:\.\d+)+)\s*[–-]\s*v?\d+(?:\.\d+)+", text):
        parsed = parse_version(match.group(1))
        if parsed:
            candidates.append(parsed)
    return min(candidates) if candidates else None


# --- normalisers -----------------------------------------------------------------

def _record(**fields: Any) -> dict:
    """Drop empty values so the stored feed stays compact."""
    return {k: v for k, v in fields.items() if v not in (None, "", [], {})}


def _advisory_url(osv: dict) -> str:
    for ref in osv.get("references") or []:
        url = ref.get("url", "")
        if "/security/advisories/GHSA-" in url:
            return url
    vid = osv.get("id", "")
    if vid.startswith("GHSA-"):
        return f"https://github.com/advisories/{vid}"
    return f"https://osv.dev/vulnerability/{vid}"


def normalise_osv(osv: dict, spec: SourceSpec) -> Optional[dict]:
    if osv.get("withdrawn"):
        return None
    ranges: list[dict] = []
    versions: list[str] = []
    repo = spec.repo.rstrip("/").lower()
    for affected in osv.get("affected") or []:
        package = affected.get("package") or {}
        if spec.kind == "osv_package":
            if (package.get("ecosystem") != spec.ecosystem
                    or package.get("name", "").lower() != spec.package.lower()):
                continue
        for rng in affected.get("ranges") or []:
            rtype = rng.get("type")
            if rtype in ("SEMVER", "ECOSYSTEM"):
                ranges.extend(events_to_ranges(rng.get("events")))
            elif rtype == "GIT":
                if spec.kind == "osv_git" and (rng.get("repo") or "").rstrip("/").lower() != repo:
                    continue
                extracted = (rng.get("database_specific") or {}).get("extracted_events")
                if extracted:
                    ranges.extend(events_to_ranges(extracted))
        for custom in (affected.get("ecosystem_specific") or {}).get("custom_ranges") or []:
            ranges.extend(events_to_ranges(custom.get("events")))
        if spec.kind == "osv_git" or not affected.get("ranges"):
            for version in affected.get("versions") or []:
                cleaned = str(version).lstrip("vV")
                if parse_version(cleaned) is not None:
                    versions.append(cleaned)
    if not ranges and not versions:
        return None
    ds = osv.get("database_specific") or {}
    advisory_url = _advisory_url(osv)
    details = osv.get("details") or ""
    cvss = [c for c in (normalise_cvss(s.get("score", ""), source="osv")
                        for s in osv.get("severity") or []) if c]
    return _record(
        id=osv.get("id"), aliases=sorted(set(osv.get("aliases") or [])),
        component=spec.component,
        summary=trim(clean_text(osv.get("summary") or "", SUMMARY_LIMIT), SUMMARY_LIMIT)
        or first_sentence(details),
        details=clean_text(details), cvss=cvss, severity_label=str(ds.get("severity") or ""),
        cwe=sorted(set(ds.get("cwe_ids") or [])), ranges=_dedupe(ranges),
        versions=sorted(set(versions))[:MAX_EXPLICIT_VERSIONS],
        published=osv.get("published"), modified=osv.get("modified"),
        references=_refs([advisory_url] + [r.get("url", "") for r in osv.get("references") or []]),
        advisory_url=advisory_url,
        workaround=extract_workaround(details, advisory_url),
    )


def normalise_github(advisory: dict, spec: SourceSpec, product: str) -> Optional[dict]:
    if advisory.get("withdrawn_at") or advisory.get("state") not in (None, "published"):
        return None
    ranges: list[dict] = []
    unparsed: list[str] = []
    for vuln in advisory.get("vulnerabilities") or []:
        got, raw = parse_github_ranges(product, vuln.get("vulnerable_version_range") or "",
                                       vuln.get("patched_versions") or "")
        ranges.extend(got)
        if raw:
            unparsed.append(raw)
    cvss: list[dict] = []
    severities = advisory.get("cvss_severities") or {}
    for key in ("cvss_v3", "cvss_v4"):
        item = severities.get(key) or {}
        entry = normalise_cvss(item.get("vector_string") or "", item.get("score"),
                               source="github")
        if entry:
            cvss.append(entry)
    legacy = advisory.get("cvss") or {}
    if not cvss and legacy.get("vector_string"):
        entry = normalise_cvss(legacy["vector_string"], legacy.get("score"), source="github")
        if entry:
            cvss.append(entry)
    url = advisory.get("html_url") or ""
    description = advisory.get("description") or ""
    cve = advisory.get("cve_id")
    refs = [url] + [r if isinstance(r, str) else r.get("url", "")
                    for r in advisory.get("references") or []]
    return _record(
        id=advisory.get("ghsa_id"), aliases=[cve] if cve else [], component=spec.component,
        summary=trim(clean_text(advisory.get("summary") or "", SUMMARY_LIMIT), SUMMARY_LIMIT),
        details=clean_text(description), cvss=cvss,
        severity_label=str(advisory.get("severity") or "").upper(),
        cwe=sorted({c.get("cwe_id") if isinstance(c, dict) else c
                    for c in advisory.get("cwe_ids") or advisory.get("cwes") or []} - {None}),
        ranges=_dedupe(ranges), unparsed="; ".join(unparsed) if not ranges else "",
        published=advisory.get("published_at"), modified=advisory.get("updated_at"),
        references=_refs(refs), advisory_url=url,
        workaround=extract_workaround(description, url),
    )


def normalise_nvd(item: dict, spec: SourceSpec) -> Optional[dict]:
    cve = item.get("cve") or {}
    if cve.get("vulnStatus") == "Rejected":
        return None
    prefix = spec.cpe.lower() + ":"
    ranges: list[dict] = []
    unparsed = []
    platforms: set[str] = set()
    for config in cve.get("configurations") or []:
        # An AND configuration pairs the product with a platform it runs on
        # (an OS) or a product it must be combined with (an application).
        companions = [str(m.get("criteria", "")).lower()
                      for node in config.get("nodes") or []
                      for m in node.get("cpeMatch") or []
                      if not m.get("vulnerable")] if config.get("operator") == "AND" else []
        with_apps = sorted({":".join(c.split(":")[3:5]) for c in companions
                            if c.startswith("cpe:2.3:a:") and not c.startswith(prefix)})
        on_os = sorted({":".join(c.split(":")[3:5]) for c in companions
                        if c.startswith("cpe:2.3:o:")})
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = (match.get("criteria") or "").lower()
                if not match.get("vulnerable") or not criteria.startswith(prefix):
                    continue
                if with_apps:
                    unparsed.append("affects this product only in combination with "
                                    + ", ".join(with_apps))
                    continue
                platforms.update(on_os)
                parts = criteria.split(":")
                version = parts[5] if len(parts) > 5 else "*"
                update = parts[6] if len(parts) > 6 else "*"
                if version == "-":
                    unparsed.append("CPE without a version (not version-identified)")
                    continue
                if version != "*":
                    exact = version if update in ("*", "-") else f"{version}-{update}"
                    if parse_version(exact):
                        ranges.append({"version": exact})
                    continue
                interval: dict[str, str] = {}
                if match.get("versionStartIncluding"):
                    interval["introduced"] = match["versionStartIncluding"]
                if match.get("versionStartExcluding"):
                    interval["introduced"] = match["versionStartExcluding"]
                    interval["introduced_exclusive"] = "1"
                if match.get("versionEndExcluding"):
                    interval["fixed"] = match["versionEndExcluding"]
                if match.get("versionEndIncluding"):
                    interval["last_affected"] = match["versionEndIncluding"]
                if _interval_parseable(interval):
                    ranges.append(interval)
    description = next((d.get("value", "") for d in cve.get("descriptions") or []
                        if d.get("lang") == "en"), "")
    if not ranges and not unparsed:
        return None
    cvss: list[dict] = []
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = sorted(metrics.get(key) or [], key=lambda m: m.get("type") != "Primary")
        for metric in entries[:1]:
            data = metric.get("cvssData") or {}
            entry = normalise_cvss(data.get("vectorString") or "", data.get("baseScore"),
                                   source=f"nvd:{metric.get('source', '')[:40]}")
            if entry:
                cvss.append(entry)
    cwes = sorted({d.get("value") for w in cve.get("weaknesses") or []
                   for d in w.get("description") or []
                   if str(d.get("value", "")).startswith("CWE-")})
    url = f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}"
    kev = _record(date_added=cve.get("cisaExploitAdd"), due_date=cve.get("cisaActionDue"),
                  required_action=cve.get("cisaRequiredAction"),
                  vulnerability_name=cve.get("cisaVulnerabilityName"))
    return _record(
        id=cve.get("id"), component=spec.component, summary=first_sentence(description),
        details=clean_text(description), cvss=cvss, cwe=cwes, ranges=_dedupe(ranges),
        unparsed="; ".join(sorted(set(unparsed))) if not ranges else "",
        published=cve.get("published"), modified=cve.get("lastModified"),
        references=_refs([url] + [r.get("url", "") for r in cve.get("references") or []]),
        advisory_url=url, workaround=extract_workaround(description, url), kev_hint=kev,
        platforms=sorted(platforms) if ranges else [],
    )


def _refs(urls: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for url in urls:
        if url and url.startswith("https://") and url not in seen:
            seen.append(url)
    return seen[:MAX_REFERENCES]


def _dedupe(ranges: list[dict]) -> list[dict]:
    out: list[dict] = []
    for item in ranges:
        if item not in out:
            out.append(item)
    return out


# --- fetchers (one per source kind) --------------------------------------------

@dataclass
class FetchContext:
    fetch: FetchFn
    timeout: float
    sleep: Callable[[float], None]
    github_token: Optional[str] = None
    nvd_api_key: Optional[str] = None
    previous: dict = field(default_factory=dict)
    _last_nvd: float = 0.0

    def github_headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def nvd_wait(self) -> None:
        interval = 0.7 if self.nvd_api_key else NVD_MIN_INTERVAL_S
        wait = self._last_nvd + interval - time.monotonic()
        if self._last_nvd and wait > 0:
            self.sleep(wait)
        self._last_nvd = time.monotonic()


def fetch_osv(ctx: FetchContext, spec: SourceSpec) -> list[dict]:
    if spec.kind == "osv_git":
        package = {"name": spec.repo, "ecosystem": "GIT"}
    else:
        package = {"name": spec.package, "ecosystem": spec.ecosystem}
    records: list[dict] = []
    token: Optional[str] = None
    for _ in range(50):
        payload: dict[str, Any] = {"package": package}
        if token:
            payload["page_token"] = token
        data = _json(ctx.fetch, OSV_QUERY_URL, timeout=ctx.timeout, method="POST",
                     payload=payload)
        for vuln in data.get("vulns") or []:
            record = normalise_osv(vuln, spec)
            if record:
                records.append(record)
        token = data.get("next_page_token")
        if not token:
            break
    return records


def fetch_github(ctx: FetchContext, spec: SourceSpec, product: str) -> list[dict]:
    records: list[dict] = []
    for page in range(1, 11):
        url = (f"{GITHUB_API}/repos/{spec.repo}/security-advisories?"
               f"per_page=100&page={page}&state=published")
        data = _json(ctx.fetch, url, timeout=ctx.timeout, headers=ctx.github_headers())
        if not isinstance(data, list):
            raise FetchError("unexpected GitHub response")
        for advisory in data:
            record = normalise_github(advisory, spec, product)
            if record:
                records.append(record)
        if len(data) < 100:
            break
    return records


def fetch_nvd(ctx: FetchContext, spec: SourceSpec) -> list[dict]:
    records: list[dict] = []
    start = 0
    headers = {"apiKey": ctx.nvd_api_key} if ctx.nvd_api_key else {}
    while True:
        ctx.nvd_wait()
        query = urllib.parse.urlencode({"virtualMatchString": spec.cpe,
                                        "resultsPerPage": NVD_PAGE_SIZE, "startIndex": start})
        data = _json(ctx.fetch, f"{NVD_CVES_URL}?{query}", timeout=max(ctx.timeout, 60),
                     headers=headers)
        items = data.get("vulnerabilities") or []
        for item in items:
            record = normalise_nvd(item, spec)
            if record:
                records.append(record)
        start += len(items)
        if not items or start >= int(data.get("totalResults") or 0):
            break
    return records


_PG_ROW = re.compile(r"<tr>(.*?)</tr>", re.S)
_PG_CELL = re.compile(r"<td>(.*?)</td>", re.S)


def _strip(html_text: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(_HTML_TAG.sub(" ", html_text))).strip()


def parse_postgres_security_page(page: str) -> list[dict]:
    """Rows of https://www.postgresql.org/support/security/ (supported majors)."""
    rows = []
    for row in _PG_ROW.findall(page):
        cells = _PG_CELL.findall(row)
        if len(cells) < 5:
            continue
        cve = re.search(r"(CVE-\d{4}-\d+)", cells[0])
        if not cve:
            continue
        announce = re.search(r'href="(/about/news/[^"]+)"', cells[0])
        component_cell = cells[3].split("<br", 1)[0]
        vector = re.search(r'class="cvssvector">([^<]+)<', cells[3])
        score = re.search(r">(\d+(?:\.\d+)?)</a>", cells[3])
        rows.append({
            "id": cve.group(1),
            "affected": [a.strip() for a in _strip(cells[1]).split(",") if a.strip()],
            "fixed": [f.strip() for f in _strip(cells[2]).split(",") if f.strip()],
            "component": _strip(component_cell),
            "vector": vector.group(1).strip() if vector else "",
            "score": float(score.group(1)) if score else None,
            "summary": _strip(cells[4].split("<br", 1)[0]),
            "announcement": ("https://www.postgresql.org" + announce.group(1)) if announce else "",
        })
    return rows


def parse_postgres_cve_page(page: str) -> dict:
    """Description and the full per-major fix table of one CVE page."""
    description = ""
    match = re.search(r"</h3>\s*(.*?)<h2>\s*Version Information", page, re.S)
    if match:
        description = _strip(match.group(1))
    table: list[tuple[str, str]] = []
    info = page.split("Version Information", 1)[-1].split("</table>", 1)[0]
    for row in _PG_ROW.findall(info):
        cells = [_strip(c) for c in _PG_CELL.findall(row)]
        if len(cells) >= 2 and re.fullmatch(r"\d+(?:\.\d+)?", cells[0]):
            table.append((cells[0], cells[1]))
    return {"description": description, "versions": table}


def _pg_ranges(affected_fixed: list[tuple[str, str]]) -> list[dict]:
    ranges = []
    for major, fixed in affected_fixed:
        floor = f"{major}.0" if "." not in major else f"{major}.0"
        fix = parse_version(fixed) if re.fullmatch(r"\d+(?:\.\d+)+", fixed or "") else None
        if fix is not None:
            ranges.append({"introduced": floor, "fixed": fix.raw})
        else:
            base = parse_version(floor)
            if base is not None:
                ranges.append({"introduced": floor,
                               "before": next_line_floor("postgresql", base).raw})
    return ranges


def fetch_postgresql_org(ctx: FetchContext, spec: SourceSpec) -> list[dict]:
    page = ctx.fetch(POSTGRES_SECURITY_URL, headers={"Accept": "text/html"},
                     timeout=ctx.timeout).decode("utf-8", "replace")
    rows = parse_postgres_security_page(page)
    if not rows:
        raise FetchError("the PostgreSQL security page had no advisory rows")
    previous = {r.get("id"): r for r in ctx.previous.get("data") or []}
    records = []
    fetched = 0
    for row in rows:
        url = f"https://www.postgresql.org/support/security/{row['id']}/"
        prior = previous.get(row["id"])
        description, table = "", []
        if prior and prior.get("details") and prior.get("_pg_table"):
            description, table = prior["details"], [tuple(t) for t in prior["_pg_table"]]
        elif fetched < POSTGRES_DETAIL_PAGE_LIMIT:
            fetched += 1
            try:
                detail = parse_postgres_cve_page(
                    ctx.fetch(url, headers={"Accept": "text/html"},
                              timeout=ctx.timeout).decode("utf-8", "replace"))
                description, table = detail["description"], detail["versions"]
            except FetchError:
                pass
        if not table:
            table = list(zip(row["affected"], row["fixed"]))
        cvss = [c for c in [normalise_cvss(row["vector"], row["score"],
                                           source="postgresql.org")] if c]
        records.append(_record(
            id=row["id"], component="server", summary=trim(row["summary"], SUMMARY_LIMIT),
            details=clean_text(description) or row["summary"], cvss=cvss,
            ranges=_pg_ranges(table), pg_component=row["component"],
            references=_refs([url, row["announcement"]]), advisory_url=url,
            workaround=extract_workaround(description, url),
            _pg_table=[list(t) for t in table],
        ))
    return records


def fetch_kev(ctx: FetchContext) -> dict:
    data = _json(ctx.fetch, KEV_URL, timeout=max(ctx.timeout, 60))
    entries = {}
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cveID")
        if not cve:
            continue
        entries[cve] = _record(
            vendor=item.get("vendorProject"), product=item.get("product"),
            vulnerability_name=item.get("vulnerabilityName"),
            date_added=item.get("dateAdded"), due_date=item.get("dueDate"),
            required_action=item.get("requiredAction"),
            known_ransomware_use=item.get("knownRansomwareCampaignUse"),
            short_description=trim(item.get("shortDescription") or "", 400),
            notes=trim(item.get("notes") or "", 400),
        )
    return {"catalog_version": data.get("catalogVersion"),
            "date_released": data.get("dateReleased"), "entries": entries}


def fetch_endoflife(ctx: FetchContext, spec: EolSpec) -> dict:
    data = _json(ctx.fetch, ENDOFLIFE_URL.format(slug=spec.slug), timeout=ctx.timeout)
    result = data.get("result") or {}
    cycles = []
    for release in result.get("releases") or []:
        latest = release.get("latest") or {}
        cycles.append(_record(
            cycle=str(release.get("name")), release_date=release.get("releaseDate"),
            eol=release.get("eolFrom"), is_eol=bool(release.get("isEol")),
            is_maintained=release.get("isMaintained"), latest=latest.get("name"),
            latest_date=latest.get("date")))
    if not cycles:
        raise FetchError(f"endoflife.date returned no cycles for {spec.slug}")
    return {"kind": "endoflife", "cycles": cycles,
            "policy_url": (result.get("links") or {}).get("releasePolicy") or "",
            "source_url": f"https://endoflife.date/{spec.slug}"}


def fetch_latest_release(ctx: FetchContext, spec: EolSpec) -> dict:
    url = f"{GITHUB_API}/repos/{spec.repo}/releases/latest"
    data = _json(ctx.fetch, url, timeout=ctx.timeout, headers=ctx.github_headers())
    tag = str(data.get("tag_name") or "")
    if parse_version(tag.lstrip("vV")) is None:
        raise FetchError(f"unrecognised latest release tag {tag!r}")
    return {"kind": "latest_n_minors", "n": spec.n, "latest": tag.lstrip("vV"),
            "latest_published": data.get("published_at"),
            "latest_source": f"https://github.com/{spec.repo}/releases/tag/{tag}",
            "policy_url": spec.policy_url, "policy_quote": spec.note}


# --- persistence -----------------------------------------------------------------

_LOCK = threading.Lock()


def feed_dir(state_dir: str | os.PathLike) -> Path:
    return Path(state_dir) / FEED_DIRNAME


def atomic_write_json(path: Path, payload: Any) -> str:
    """Write JSON via tmp + fsync + rename; returns the SHA-256 of the bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass                                   # directory fsync is best effort
    return hashlib.sha256(data).hexdigest()


def _read_json(path: Path) -> Optional[Any]:
    try:
        with open(path, "rb") as handle:
            return json.loads(handle.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _now(now: Optional[datetime] = None) -> datetime:
    value = now or datetime.now(timezone.utc)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: object) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# --- refresh ------------------------------------------------------------------

@dataclass
class RefreshResult:
    ok: bool
    updated_at: str
    feed_hash: str
    sources: dict[str, dict]
    path: str

    def to_dict(self) -> dict:
        return asdict(self)


def refresh_feed(state_dir: str | os.PathLike, *, products: Optional[Iterable[str]] = None,
                 timeout: float = 30.0, fetch: Optional[FetchFn] = None,
                 now: Optional[datetime] = None, sleep: Callable[[float], None] = time.sleep,
                 github_token: Optional[str] = None, nvd_api_key: Optional[str] = None,
                 base: Optional[dict] = None, include_kev: bool = True,
                 include_eol: bool = True) -> RefreshResult:
    """Fetch every catalogued source and write the feed atomically.

    Each source is fetched independently. A source that fails keeps the records
    it had before (from the state copy, else the bundled seed) and its error is
    recorded in ``meta.json``; good data is never wiped. Tokens are optional,
    used only for request authentication and never written to disk.
    """
    fetch = fetch or default_fetch
    now = _now(now)
    wanted = [canonical_product(p) for p in (products or PRODUCTS)]
    unknown = [p for p in wanted if p not in PRODUCTS]
    if unknown:
        raise ValueError(f"unknown products: {', '.join(unknown)}")
    target = feed_dir(state_dir)
    with _LOCK:
        if base is None:
            base = _read_json(target / "feed.json") or _read_seed() or {}
        previous_sources: dict[str, dict] = copy.deepcopy(base.get("sources") or {})
        sources = dict(previous_sources)
        status: dict[str, dict] = {}
        ctx = FetchContext(fetch=fetch, timeout=timeout, sleep=sleep,
                           github_token=github_token, nvd_api_key=nvd_api_key)

        def run(key: str, product: str, kind: str, component: str,
                job: Callable[[], Any], count: Callable[[Any], int]) -> None:
            ctx.previous = previous_sources.get(key) or {}
            try:
                data = job()
            except Exception as exc:  # noqa: BLE001 - one bad source never stops the rest
                kept = key in previous_sources
                status[key] = {"ok": False, "error": _safe_error(exc), "kept_previous": kept,
                               "count": count(previous_sources[key].get("data")) if kept else 0,
                               "fetched_at": (previous_sources.get(key) or {}).get("fetched_at")}
                return
            entry = {"kind": kind, "product": product, "component": component,
                     "fetched_at": _iso(now), "data": data}
            sources[key] = entry
            status[key] = {"ok": True, "error": "", "kept_previous": False,
                           "count": count(data), "fetched_at": _iso(now)}

        for product in wanted:
            spec = PRODUCTS[product]
            for source in spec.sources:
                key = source.key(product)
                job: Callable[[], Any]
                if source.kind in ("osv_package", "osv_git"):
                    job = partial(fetch_osv, ctx, source)
                elif source.kind == "github_repo":
                    job = partial(fetch_github, ctx, source, product)
                elif source.kind == "nvd_cpe":
                    job = partial(fetch_nvd, ctx, source)
                elif source.kind == "postgresql_org":
                    job = partial(fetch_postgresql_org, ctx, source)
                else:                                   # pragma: no cover - catalogue bug
                    continue
                run(key, product, source.kind, source.component, job,
                    lambda d: len(d or []))
            if include_eol and spec.eol.kind == "endoflife":
                run(f"eol:{product}", product, "eol", "server",
                    partial(fetch_endoflife, ctx, spec.eol),
                    lambda d: len((d or {}).get("cycles") or []))
            elif include_eol and spec.eol.kind == "latest_n_minors":
                run(f"eol:{product}", product, "eol", "server",
                    partial(fetch_latest_release, ctx, spec.eol),
                    lambda d: 1 if d else 0)
        if include_kev:
            run("kev", "", "kev", "", lambda: _filter_kev(fetch_kev(ctx), sources),
                lambda d: len((d or {}).get("entries") or {}))

        any_ok = any(s["ok"] for s in status.values())
        previous_meta = _read_json(target / "meta.json") or {}
        feed = {"schema": SCHEMA_VERSION,
                "updated_at": _iso(now) if any_ok else base.get("updated_at"),
                "sources": sources}
        feed_hash = atomic_write_json(target / "feed.json", feed)
        merged_status = dict(previous_meta.get("sources") or {})
        merged_status.update(status)
        meta = {"schema": SCHEMA_VERSION, "updated_at": feed["updated_at"],
                "last_attempt": _iso(now), "feed_hash": feed_hash, "sources": merged_status}
        atomic_write_json(target / "meta.json", meta)
    return RefreshResult(ok=all(s["ok"] for s in status.values()) if status else False,
                         updated_at=str(feed["updated_at"] or ""), feed_hash=feed_hash,
                         sources=status, path=str(target / "feed.json"))


def _safe_error(exc: BaseException) -> str:
    text = str(exc) or type(exc).__name__
    return trim(re.sub(r"(?i)(token|key|authorization)[=:]\s*\S+", r"\1=***", text), 300)


def _filter_kev(kev: dict, sources: dict) -> dict:
    """Keep only KEV entries for catalogued products (by CVE or vendor keyword)."""
    ids: set[str] = set()
    for entry in sources.values():
        if entry.get("kind") in ("eol", "kev"):
            continue
        for record in entry.get("data") or []:
            ids.add(record.get("id", ""))
            ids.update(record.get("aliases") or [])
    keywords = [k for spec in PRODUCTS.values() for k in spec.kev_keywords]
    kept = {}
    for cve, item in (kev.get("entries") or {}).items():
        text = f"{item.get('vendor', '')} {item.get('product', '')}".lower()
        if cve in ids or any(k in text for k in keywords):
            kept[cve] = item
    return {**kev, "entries": kept}


# --- seed ---------------------------------------------------------------------

def _read_seed() -> Optional[dict]:
    return _read_json(SEED_PATH)


def write_seed(*, fetch: Optional[FetchFn] = None, timeout: float = 30.0,
               github_token: Optional[str] = None, nvd_api_key: Optional[str] = None,
               path: Path = SEED_PATH) -> RefreshResult:
    """Regenerate the bundled seed from the live sources (developer action)."""
    with tempfile.TemporaryDirectory() as tmp:
        result = refresh_feed(tmp, fetch=fetch, timeout=timeout, github_token=github_token,
                              nvd_api_key=nvd_api_key, base={})
        feed = _read_json(feed_dir(tmp) / "feed.json") or {}
        meta = _read_json(feed_dir(tmp) / "meta.json") or {}
    feed["meta"] = {"generated_at": feed.get("updated_at"), "sources": meta.get("sources"),
                    "note": "Bundled seed snapshot; refresh_feed() replaces it at runtime."}
    atomic_write_json(path, feed)
    os.chmod(path, 0o644)                       # package data, readable by everyone
    return result


# --- loading and merging ------------------------------------------------------

#: Lower is better. Text comes from the most descriptive vendor source; ranges
#: from the most precise one that also names a fix.
_TEXT_RANK = {"github_repo": 0, "osv_ghsa": 1, "postgresql_org": 1, "nvd_cpe": 2,
              "osv_other": 3, "osv_git": 4, "overlay": 5}
_RANGE_RANK = {"overlay": -1, "postgresql_org": 0, "osv_ghsa": 1, "github_repo": 2,
               "osv_other": 2, "nvd_cpe": 3, "osv_git": 4}


def _rank_kind(kind: str, record: dict) -> str:
    if kind == "osv_package":
        return "osv_ghsa" if str(record.get("id", "")).startswith("GHSA-") else "osv_other"
    return kind


def load_overlay(path: Path = OVERLAY_PATH) -> dict:
    data = _read_json(path) or {}
    return {"advisories": data.get("advisories") or [], "products": data.get("products") or {}}


class Feed:
    """A loaded feed: merged advisories per product, KEV, and support data."""

    def __init__(self, raw: dict, *, origin: str, path: str = "", meta: Optional[dict] = None,
                 error: str = "", overlay: Optional[dict] = None) -> None:
        self.raw = raw or {}
        self.origin = origin                      # "state" | "seed" | "none"
        self.path = path
        self.meta = meta or self.raw.get("meta") or {}
        self.error = error
        self.overlay = overlay if overlay is not None else load_overlay()
        self._cache: dict[tuple[str, str], list[dict]] = {}

    @property
    def available(self) -> bool:
        return bool(self.raw.get("sources"))

    @property
    def updated_at(self) -> Optional[datetime]:
        return parse_time(self.raw.get("updated_at"))

    def age_days(self, now: Optional[datetime] = None) -> Optional[float]:
        updated = self.updated_at
        if updated is None:
            return None
        return round((_now(now) - updated).total_seconds() / 86400.0, 2)

    def source_entries(self, product: str) -> list[tuple[str, dict]]:
        return [(k, v) for k, v in (self.raw.get("sources") or {}).items()
                if v.get("product") == product and v.get("kind") not in ("eol", "kev")]

    def kev(self, ids: Iterable[str]) -> Optional[dict]:
        entries = ((self.raw.get("sources") or {}).get("kev") or {}).get("data") or {}
        for vid in ids:
            item = (entries.get("entries") or {}).get(vid)
            if item:
                return {"cve": vid, **item}
        return None

    def kev_catalog(self) -> dict:
        data = ((self.raw.get("sources") or {}).get("kev") or {}).get("data") or {}
        return {k: data.get(k) for k in ("catalog_version", "date_released")}

    def eol(self, product: str) -> Optional[dict]:
        return ((self.raw.get("sources") or {}).get(f"eol:{product}") or {}).get("data")

    def product_notes(self, product: str) -> dict:
        return (self.overlay.get("products") or {}).get(product) or {}

    def advisories(self, product: str, component: str = "server") -> list[dict]:
        key = (product, component)
        if key not in self._cache:
            self._cache[key] = merge_advisories(
                product, component, self.source_entries(product), self.overlay, self)
        return self._cache[key]

    def status(self, now: Optional[datetime] = None) -> dict:
        return {"origin": self.origin, "updated_at": self.raw.get("updated_at"),
                "age_days": self.age_days(now), "error": self.error,
                "sources": self.meta.get("sources") or {},
                "kev_catalog": self.kev_catalog()}


def load_feed(state_dir: Optional[str | os.PathLike] = None, *,
              seed_path: Path = SEED_PATH, overlay: Optional[dict] = None) -> Feed:
    """The state copy when present and readable, else the bundled seed."""
    error = ""
    if state_dir is not None:
        target = feed_dir(state_dir)
        raw = _read_json(target / "feed.json")
        if isinstance(raw, dict) and raw.get("sources"):
            return Feed(raw, origin="state", path=str(target / "feed.json"),
                        meta=_read_json(target / "meta.json") or {}, overlay=overlay)
        if (target / "feed.json").exists():
            error = "the local feed copy could not be read; using the bundled seed"
    seed = _read_json(seed_path)
    if isinstance(seed, dict) and seed.get("sources"):
        return Feed(seed, origin="seed", path=str(seed_path), error=error, overlay=overlay)
    return Feed({}, origin="none", error=error or "no advisory feed is available",
                overlay=overlay)


def merge_advisories(product: str, component: str, entries: list[tuple[str, dict]],
                     overlay: dict, feed: Optional[Feed] = None) -> list[dict]:
    """Group records from all sources by shared IDs/aliases into advisories."""
    records: list[tuple[str, dict]] = []
    for _key, entry in entries:
        if entry.get("component", "server") != component:
            continue
        for record in entry.get("data") or []:
            records.append((_rank_kind(entry.get("kind", ""), record), record))
    records.extend(("overlay", record) for record in _overlay_records(overlay, product, component))
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    for _kind, record in records:
        ids = [record.get("id", "")] + list(record.get("aliases") or [])
        ids = [i for i in ids if i]
        for other in ids[1:]:
            union(ids[0], other)
    groups: dict[str, list[tuple[str, dict]]] = {}
    for kind, record in records:
        groups.setdefault(find(record.get("id", "")), []).append((kind, record))
    overlay_index = _overlay_index(overlay, product)
    merged = [_merge_group(product, component, members, overlay_index, feed)
              for members in groups.values()]
    merged.sort(key=lambda a: (a.get("published") or "", a["id"]), reverse=True)
    return merged


def _overlay_records(overlay: dict, product: str, component: str) -> list[dict]:
    """Advisories the overlay records itself, for ones the sources do not carry yet.

    A fresh CVE can be public (vendor issue, distribution tracker) days before
    NVD or OSV list it. The overlay's cited record joins any live record that
    shares its ID, and the live sources' text and scores take precedence.
    """
    out = []
    for entry in overlay.get("advisories") or []:
        advisory = entry.get("advisory")
        if not advisory or entry.get("product") != product \
                or entry.get("component", "server") != component:
            continue
        ids = list(entry.get("ids") or [])
        if not ids:
            continue
        out.append(_record(
            id=ids[0], aliases=ids[1:], summary=advisory.get("summary"),
            details=advisory.get("details"), severity_label=advisory.get("severity_label"),
            published=advisory.get("published"), references=advisory.get("references"),
            advisory_url=advisory.get("source_url")))
    return out


def _overlay_index(overlay: dict, product: str) -> dict[str, dict]:
    index = {}
    for entry in overlay.get("advisories") or []:
        if entry.get("product") not in (None, product):
            continue
        for vid in entry.get("ids") or []:
            index[vid] = entry
    return index


def _merge_group(product: str, component: str, members: list[tuple[str, dict]],
                 overlay_index: dict[str, dict], feed: Optional[Feed]) -> dict:
    ids: set[str] = set()
    for _kind, record in members:
        ids.add(record.get("id", ""))
        ids.update(record.get("aliases") or [])
    ids.discard("")
    cves = sorted(i for i in ids if i.startswith("CVE-"))
    ghsas = sorted(i for i in ids if i.startswith("GHSA-"))
    primary = (cves or ghsas or sorted(ids))[0]
    by_text = sorted(members, key=lambda m: _TEXT_RANK.get(m[0], 9))

    def first(field_name: str) -> Any:
        for _kind, record in by_text:
            if record.get(field_name):
                return record[field_name]
        return None

    cvss: list[dict] = []
    for _kind, record in by_text:
        for entry in record.get("cvss") or []:
            if entry.get("vector") not in [c.get("vector") for c in cvss]:
                cvss.append(entry)
    best = next((c for c in cvss if c.get("score") is not None
                 and str(c.get("version", "")).startswith("3")), None) \
        or next((c for c in cvss if c.get("score") is not None), None)
    cwe = sorted({c for _k, r in members for c in r.get("cwe") or []})
    references: list[str] = []
    for _kind, record in by_text:
        for url in record.get("references") or []:
            if url not in references:
                references.append(url)
    overlay = next((overlay_index[i] for i in sorted(ids) if i in overlay_index), None)

    # Ranges: the best-ranked source that names a fix, else the best with any.
    candidates = [(kind, r) for kind, r in members if r.get("ranges") or r.get("versions")]
    range_source = None
    ranges: list[dict] = []
    versions: list[str] = []
    platforms: list[str] = []
    if overlay and overlay.get("affected_override"):
        override = overlay["affected_override"]
        ranges, range_source = list(override.get("ranges") or []), {
            "kind": "overlay", "url": override.get("source_url", ""),
            "quote": override.get("quote", "")}
    elif candidates:
        def score(item: tuple[str, dict]) -> tuple:
            kind, record = item
            has_fix = any("fixed" in r for r in record.get("ranges") or [])
            return (0 if has_fix else 1, _RANGE_RANK.get(kind, 9))
        kind, chosen = sorted(candidates, key=score)[0]
        ranges = list(chosen.get("ranges") or [])
        versions = list(chosen.get("versions") or []) if kind == "osv_git" else []
        range_source = {"kind": kind, "record": chosen.get("id"),
                        "url": chosen.get("advisory_url", "")}
        platforms = list(chosen.get("platforms") or [])
    unparsed = "; ".join(sorted({r.get("unparsed", "") for _k, r in members} - {""}))
    fixed_versions = sorted({r["fixed"] for r in ranges if "fixed" in r},
                            key=lambda v: parse_version(v) or Version(v, (0,)))
    workaround = None
    for _kind, record in by_text:
        if record.get("workaround"):
            workaround = record["workaround"]
            break
    if overlay and overlay.get("workaround") and not workaround:
        workaround = overlay["workaround"]
    kev = feed.kev(cves) if feed is not None else None
    if kev is None:
        hint = next((r.get("kev_hint") for _k, r in members if r.get("kev_hint")), None)
        if hint:
            kev = {"cve": cves[0] if cves else primary, **hint, "source": "nvd"}
    pg_component = next((r.get("pg_component") for _k, r in members if r.get("pg_component")),
                        None)
    published = min((str(r["published"]) for _k, r in members if r.get("published")),
                    default=None)
    modified = max((str(r["modified"]) for _k, r in members if r.get("modified")),
                   default=None)
    return _record(
        id=primary, aliases=sorted(ids - {primary}), product=product, component=component,
        summary=first("summary"), details=first("details"), cvss=cvss[:4], cvss_best=best,
        severity_label=first("severity_label"), cwe=cwe, ranges=ranges, versions=versions,
        range_source=range_source, unparsed=unparsed if not ranges and not versions else "",
        fixed_versions=fixed_versions, published=published, modified=modified,
        references=references[:MAX_REFERENCES], advisory_url=first("advisory_url"),
        workaround=workaround, kev=kev, pg_component=pg_component,
        sources=sorted({k for k, _r in members}), overlay=overlay, platforms=platforms,
    )


# --- auto-update schedule ----------------------------------------------------

MIN_INTERVAL_HOURS = 6
DEFAULT_INTERVAL_HOURS = 24
RETRY_AFTER_FAILURE_HOURS = 1


@dataclass
class FeedSchedule:
    """Admin-controlled auto-update settings. Off by default (no egress)."""

    auto_update: bool = False
    interval_hours: int = DEFAULT_INTERVAL_HOURS
    last_attempt: Optional[str] = None
    last_success: Optional[str] = None
    last_error: str = ""

    def __post_init__(self) -> None:
        try:
            hours = int(self.interval_hours)
        except (TypeError, ValueError):
            hours = DEFAULT_INTERVAL_HOURS
        self.interval_hours = max(MIN_INTERVAL_HOURS, hours)
        self.auto_update = bool(self.auto_update)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "FeedSchedule":
        data = data or {}
        return cls(auto_update=bool(data.get("auto_update", False)),
                   interval_hours=data.get("interval_hours", DEFAULT_INTERVAL_HOURS),
                   last_attempt=data.get("last_attempt"), last_success=data.get("last_success"),
                   last_error=str(data.get("last_error") or ""))


def due(settings: FeedSchedule, now: Optional[datetime] = None) -> bool:
    """True when auto-update is on and the last success is an interval old.

    After a failed attempt the next try waits at least an hour, so an outage
    of a source does not turn the scheduler into a retry loop.
    """
    if not settings.auto_update:
        return False
    now = _now(now)
    last_success = parse_time(settings.last_success)
    last_attempt = parse_time(settings.last_attempt)
    if last_success is not None and now - last_success < timedelta(hours=settings.interval_hours):
        return False
    if last_attempt is not None and (last_success is None or last_attempt > last_success):
        return now - last_attempt >= timedelta(hours=RETRY_AFTER_FAILURE_HOURS)
    return True


def load_schedule(state_dir: str | os.PathLike) -> FeedSchedule:
    return FeedSchedule.from_dict(_read_json(feed_dir(state_dir) / "schedule.json"))


def save_schedule(state_dir: str | os.PathLike, settings: FeedSchedule) -> None:
    atomic_write_json(feed_dir(state_dir) / "schedule.json", settings.to_dict())


def refresh_if_due(state_dir: str | os.PathLike, settings: Optional[FeedSchedule] = None, *,
                   now: Optional[datetime] = None, force: bool = False,
                   persist: bool = True, **refresh_kwargs: Any
                   ) -> tuple[FeedSchedule, Optional[RefreshResult]]:
    """Refresh when due (or ``force`` for an admin's "update now").

    Returns the updated settings and the refresh result (None when not due).
    A refresh where some sources failed still counts as a success when at least
    one source updated; the failures are in ``meta.json`` and ``last_error``.
    """
    settings = settings or load_schedule(state_dir)
    now = _now(now)
    if not force and not due(settings, now):
        return settings, None
    settings.last_attempt = _iso(now)
    result: Optional[RefreshResult] = None
    try:
        result = refresh_feed(state_dir, now=now, **refresh_kwargs)
    except Exception as exc:  # noqa: BLE001 - a scheduler tick never raises
        settings.last_error = _safe_error(exc)
    else:
        failures = [k for k, s in result.sources.items() if not s["ok"]]
        if any(s["ok"] for s in result.sources.values()):
            settings.last_success = _iso(now)
        settings.last_error = (f"{len(failures)} source(s) failed: {', '.join(failures[:5])}"
                               if failures else "")
    if persist:
        save_schedule(state_dir, settings)
    return settings, result


# --- CLI -------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m vecshield_platform.posture.vulnfeed",
                                     description="Manage the server advisory feed.")
    parser.add_argument("--write-seed", action="store_true",
                        help="regenerate the bundled seed from the live sources")
    parser.add_argument("--refresh", metavar="STATE_DIR", help="refresh the feed in STATE_DIR")
    parser.add_argument("--status", metavar="STATE_DIR", help="print feed status")
    parser.add_argument("--product", action="append", help="limit refresh to a product")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args(argv)
    github_token = os.environ.get("VECSHIELD_GITHUB_TOKEN") or None
    nvd_key = os.environ.get("VECSHIELD_NVD_API_KEY") or None
    if args.write_seed:
        result = write_seed(timeout=args.timeout, github_token=github_token, nvd_api_key=nvd_key)
    elif args.refresh:
        result = refresh_feed(args.refresh, products=args.product, timeout=args.timeout,
                              github_token=github_token, nvd_api_key=nvd_key)
    elif args.status:
        print(json.dumps(load_feed(args.status).status(), indent=2, default=str))
        return 0
    else:
        parser.print_help()
        return 2
    print(json.dumps({k: v for k, v in result.to_dict().items()}, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":                              # pragma: no cover
    sys.exit(main())
