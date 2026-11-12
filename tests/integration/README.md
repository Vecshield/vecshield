# Integration tests

Container-backed tests that exercise the connectors against **real** vector
stores (not SDK fakes), spun up on demand with
[`testcontainers`](https://testcontainers-python.readthedocs.io/).

They are **excluded from the default `pytest` run** because they need a running
Docker daemon and are slow. They carry the `integration` marker and the default
`addopts` in `pyproject.toml` deselects that marker.

## Requirements

- A running Docker daemon
- The optional deps: `pip install -e ".[dev,integration]"` plus the extras for
  the stores you want to test (e.g. `pgvector`, `qdrant`, `opensearch`, `redis`).

## Running

```bash
# All integration tests
pytest -m integration

# A single module
pytest -m integration tests/integration/test_pgvector_integration.py -v
```

Without Docker (or without `testcontainers` installed) the suite **skips**
cleanly rather than failing — see `conftest.py` and the module-level
`importorskip` guards.

## CI

The `integration` job in `.github/workflows/ci.yml` runs this suite nightly and
on manual dispatch, kept out of the blocking PR gate.

## Adding a store

Follow `test_pgvector_integration.py` as the reference pattern:

1. `pytest.importorskip(...)` for `testcontainers` and the store's client.
2. Add `pytestmark = pytest.mark.integration`.
3. Depend on the `docker_available` fixture to skip gracefully.
4. Start the container, point the real connector at it, and assert on
   `describe()` / `list_collections()` / `iter_chunks()`.
5. Add the store to `test_assessment_contract_containers.py`: seed it with
   `assessment_contract.scenario()`, run a full audit through the API, and
   call `assert_contract`. That proves the whole assessment, not just the
   connector, works on that store.

## The assessment contract

`tests/assessment_contract.py` seeds two collections from fixed seeds. One is
clean. The other carries one instance of each issue the assessment claims to
find: identifiers, a prompt injection, a poison cluster, a hub, an outlier,
superseded versions, an ingestion burst, and chunks with no tenant value.
`assert_contract` checks what every check concluded, not only which findings
exist. It also checks that coverage stays honest: no errors, no unexplained
`unsupported`, and a summary that matches the outcomes.

- `tests/test_full_assessment_contract.py` runs it on embedded Chroma in the
  default suite, with no Docker needed. It also checks that the outcomes
  survive into history and the HTML report.
- `test_assessment_contract_containers.py` runs it on pgvector and Qdrant
  containers. It also does a real pgvector erasure.

Container stores pin only the posture outcomes the other container tests
establish (`strict=False`). Once a nightly run shows a store's full outcome
table, pin it and switch that store to `strict=True`.

Target stores per the roadmap: Chroma, pgvector, Qdrant, OpenSearch, Redis.
