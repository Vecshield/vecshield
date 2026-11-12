"""Version parsing and comparison for database server releases.

Advisory sources describe versions in several dialects (SemVer with
pre-releases, PEP 440, Go module pseudo-versions, PostgreSQL's two-part
numbers, NVD CPE fields), and servers report their own version strings with
distro and build decorations. Everything here is conservative:

* a string that cannot be read is ``None`` — the caller reports the check as
  inconclusive, never as clean;
* a Go pseudo-version (``0.10.3-0.20251107071934-6102f001a971``) names a
  commit in the Go module namespace, not a server release, and is flagged so
  ranges built on it are not compared with release numbers;
* an unrecognised suffix (``-hotfix``, ``-1.pgdg120+1``, ``-ent``) is ignored
  and recorded, so the release is compared as its base version. That can only
  over-report (a hotfix build that already carries a fix is still flagged),
  never hide an affected version.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import total_ordering
from typing import Optional

_PHASES = {"dev": 0, "snapshot": 0, "a": 1, "alpha": 1, "m": 1, "b": 2, "beta": 2,
           "pre": 3, "preview": 3, "c": 3, "rc": 3}
_RELEASE_PHASE = 4
_POST_PHASE = 5

_PSEUDO = re.compile(
    r"^v?\d+\.\d+\.\d+-(?:(?:0|[0-9a-z.]+\.0)\.)?\d{14}-[0-9a-f]{12}(?:\+incompatible)?$")
_CORE = re.compile(r"^v?(\d+(?:\.\d+)*)(.*)$", re.IGNORECASE)
_PRE = re.compile(r"^[-._]?(dev|snapshot|alpha|beta|preview|pre|rc|a|b|c|m)[-._]?(\d*)(.*)$",
                  re.IGNORECASE)
_POST = re.compile(r"^[-._]?(?:post|p)[-._]?(\d+)(.*)$", re.IGNORECASE)


def is_pseudo_version(text: str) -> bool:
    return bool(_PSEUDO.match((text or "").strip()))


@total_ordering
@dataclass(frozen=True)
class Version:
    raw: str
    release: tuple[int, ...]
    phase: int = _RELEASE_PHASE
    phase_num: int = 0
    ignored_suffix: str = field(default="", compare=False)

    @property
    def _key(self) -> tuple:
        padded = self.release + (0,) * (4 - len(self.release))
        return (padded, self.phase, self.phase_num)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self._key == other._key

    def __lt__(self, other: "Version") -> bool:
        return self._key < other._key

    def __hash__(self) -> int:
        return hash(self._key)

    @property
    def is_prerelease(self) -> bool:
        return self.phase < _RELEASE_PHASE

    def part(self, index: int) -> int:
        return self.release[index] if index < len(self.release) else 0

    def __str__(self) -> str:  # the normalised form, e.g. "2.5.12" or "1.31.0-rc.0"
        base = ".".join(str(n) for n in self.release)
        if self.phase == _RELEASE_PHASE:
            return base
        names = {0: "dev", 1: "alpha", 2: "beta", 3: "rc", 5: "post"}
        return f"{base}-{names[self.phase]}.{self.phase_num}"


def parse_version(text: object) -> Optional[Version]:
    """Parse one version token. None for empty, unparseable or pseudo-versions."""
    if text is None:
        return None
    raw = str(text).strip()
    if not raw or raw in ("*", "-"):
        return None
    if is_pseudo_version(raw):
        return None
    candidate = raw.split("+", 1)[0]          # SemVer build metadata never orders
    match = _CORE.match(candidate)
    if not match:
        return None
    try:
        release = tuple(int(n) for n in match.group(1).split("."))
    except ValueError:
        return None
    rest = match.group(2)
    if not rest:
        return Version(raw, release)
    pre = _PRE.match(rest)
    if pre and not pre.group(3).strip("-._0123456789"):
        num = int(pre.group(2)) if pre.group(2) else 0
        # "1.31.0-rc.0" keeps its number after a dot: rc + ".0"
        tail = pre.group(3).strip("-._")
        if not pre.group(2) and tail.isdigit():
            num = int(tail)
        return Version(raw, release, _PHASES[pre.group(1).lower()], num)
    post = _POST.match(rest)
    if post and not post.group(2):
        return Version(raw, release, _POST_PHASE, int(post.group(1)))
    return Version(raw, release, ignored_suffix=rest)


#: Products whose release line is the major version (PostgreSQL 10+, and the
#: endoflife.date cycles for OpenSearch are majors as well).
_MAJOR_LINE_FROM = {"postgresql": 10, "opensearch": 0}


def release_line(product: str, version: Version) -> str:
    """The maintenance line a version belongs to.

    PostgreSQL 10 and later is maintained per major (``16``); 9.x and earlier per
    ``major.minor`` (``9.6``). OpenSearch ships fixes as new minors within a
    supported major (``2``), which is also how its support schedule is published.
    Every other catalogued product ships patch releases per ``major.minor``
    (Redis 7.4, MongoDB 8.0, Milvus 2.5, Weaviate 1.33, ...).
    """
    threshold = _MAJOR_LINE_FROM.get(product)
    if threshold is not None and version.part(0) >= threshold:
        return str(version.part(0))
    return f"{version.part(0)}.{version.part(1)}"


def line_floor(product: str, line: str) -> Optional[Version]:
    """The first possible version of a release line (``"2.5"`` -> 2.5.0)."""
    return parse_version(line if "." in line else f"{line}.0")


def next_line_floor(product: str, version: Version) -> Version:
    """The first version of the line after ``version``'s line."""
    threshold = _MAJOR_LINE_FROM.get(product)
    if threshold is not None and version.part(0) >= threshold:
        return Version(f"{version.part(0) + 1}.0", (version.part(0) + 1, 0))
    nxt = (version.part(0), version.part(1) + 1, 0)
    return Version(".".join(map(str, nxt)), nxt)


# --- server-reported version strings -----------------------------------------

_PG_VERSION = re.compile(
    r"^(?:postgresql\s+)?(\d+)(?:\.(\d+))?(?:\.(\d+))?((?:alpha|beta|rc)\d+|devel)?",
    re.IGNORECASE)
_GENERIC_TOKEN = re.compile(r"v?\d+(?:\.\d+)+(?:[-._]?(?:alpha|beta|rc|dev|preview|pre)"
                            r"[-._]?\d*)?", re.IGNORECASE)


@dataclass(frozen=True)
class ServerVersion:
    raw: str
    version: Optional[Version]
    note: str = ""


def parse_server_version(product: str, raw: object) -> ServerVersion:
    """Read the version a server reported, conservatively.

    ``"PostgreSQL 16.4 (Debian 16.4-1.pgdg120+1) on x86_64-pc-linux-gnu, ..."``,
    ``"16.4 (Debian 16.4-1.pgdg120+1)"``, ``"160004"`` (``server_version_num``)
    and ``"v2.5.12"`` all parse; ``"16"`` (a PostgreSQL major with no minor) and
    anything without a version number do not.
    """
    text = "" if raw is None else str(raw).strip()
    if not text:
        return ServerVersion(text, None, "the server reported no version")
    if product == "postgresql":
        return _parse_postgres(text)
    match = _GENERIC_TOKEN.search(text)
    if not match:
        return ServerVersion(text, None, "no version number in the reported string")
    token = match.group(0)
    # Keep the directly attached suffix (e.g. "-hotfix") so it is recorded.
    tail = re.match(r"^[-+][0-9A-Za-z.+-]+", text[match.end():])
    parsed = parse_version(token + (tail.group(0) if tail else ""))
    if parsed is None:
        return ServerVersion(text, None, "unrecognised version format")
    note = ""
    if parsed.ignored_suffix:
        note = (f"suffix {parsed.ignored_suffix!r} was ignored; compared as "
                f"{'.'.join(map(str, parsed.release))}")
    if text != token and not note and match.start() > 0:
        note = f"version {token} read from {text!r}"
    return ServerVersion(text, parsed, note)


def _parse_postgres(text: str) -> ServerVersion:
    if re.fullmatch(r"\d{5,6}", text):                       # server_version_num
        num = int(text)
        if num >= 100000:
            return ServerVersion(text, parse_version(f"{num // 10000}.{num % 100}"),
                                 "read from server_version_num")
        return ServerVersion(
            text, parse_version(f"{num // 10000}.{(num // 100) % 100}.{num % 100}"),
            "read from server_version_num")
    match = _PG_VERSION.match(text)
    if not match:
        return ServerVersion(text, None, "no PostgreSQL version number in the string")
    major, minor, patch, pre = match.groups()
    major_n = int(major)
    if pre:
        suffix = "-dev" if pre.lower() == "devel" else "-" + pre.lower()
        base = f"{major}.0" if major_n >= 10 else f"{major}.{minor or 0}.0"
        return ServerVersion(text, parse_version(base + suffix),
                             f"pre-release build {pre!r}")
    if major_n >= 10:
        if minor is None:
            return ServerVersion(text, None, "PostgreSQL major without a minor release")
        return ServerVersion(text, parse_version(f"{major}.{minor}"),
                             "" if text == f"{major}.{minor}" else
                             f"version {major}.{minor} read from the version string")
    if minor is None:
        return ServerVersion(text, None, "PostgreSQL 9.x major without a minor release")
    return ServerVersion(text, parse_version(f"{major}.{minor}.{patch or 0}"),
                         "" if patch else "patch level missing; compared as .0")
