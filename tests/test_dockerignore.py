"""The Docker build contexts are allowlists, so local state never ships.

`COPY . /app` bakes whatever the context holds into the image. With a denylist,
any new local artefact (demo-state/, *.db, audit logs, node_modules) is shipped
by default. These checks pin the allowlist shape; the exact context was
verified with a `FROM scratch` export build.

There are two contexts. The repository root serves the production image. The
demo image needs `demo/` as well, and BuildKit prefers
`<dockerfile>.dockerignore` over the root file, so the demo's wider context
cannot widen the production one.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Needed by every image: pyproject names NOTICE in `license-files`, so a build
#: without it fails outright.
PACKAGING = {
    "pyproject.toml", "README.md", "LICENSE*", "NOTICE",
    "vecshield/", "vecshield_platform/", "wheelhouse/",
    "vecshield_platform/api/dashboard/dist/",
}

STATE_PATTERNS = ("**/node_modules", "**/*.db*", "**/demo-state",
                  "**/__pycache__", "**/.venv*", "**/*.jsonl")


def _rules(path: Path) -> list[str]:
    return [ln.strip() for ln in path.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


def _allowed(rules: list[str]) -> set[str]:
    return {r[1:] for r in rules if r.startswith("!")}


def test_context_starts_by_excluding_everything():
    for name in (".dockerignore", "demo/Dockerfile.dockerignore"):
        assert _rules(ROOT / name)[0] == "*", name


def test_only_packages_and_packaging_metadata_are_allowed():
    assert _allowed(_rules(ROOT / ".dockerignore")) == PACKAGING


def test_the_demo_context_adds_only_the_demo():
    assert _allowed(_rules(ROOT / "demo" / "Dockerfile.dockerignore")) == PACKAGING | {"demo/"}


def test_the_production_image_does_not_ship_the_demo():
    # The production Dockerfile is a `COPY . /app`, so the demo stays out of it
    # by being absent from the root context, not by being skipped in the COPY.
    assert "!demo/" not in _rules(ROOT / ".dockerignore")


def test_state_and_dependencies_are_excluded_after_the_allowlist():
    for name in (".dockerignore", "demo/Dockerfile.dockerignore"):
        rules = _rules(ROOT / name)
        last_allow = max(i for i, r in enumerate(rules) if r.startswith("!"))
        trailing = set(rules[last_allow + 1:])
        for pattern in STATE_PATTERNS:
            assert pattern in trailing, f"{pattern} missing from {name}"


def test_the_console_bundle_the_image_serves_is_in_the_allowed_tree():
    dist = ROOT / "vecshield_platform" / "api" / "dashboard" / "dist"
    assert (dist / "index.html").is_file()
    assert (dist / "assets" / "dashboard.js").is_file()
    assert (dist / "assets" / "dashboard.css").is_file()
