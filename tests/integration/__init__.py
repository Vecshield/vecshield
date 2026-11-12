"""Container-backed integration tests (improvement plan 1.10).

These tests exercise the connectors against **real** vector stores spun up in
throwaway Docker containers via ``testcontainers`` — unlike the unit tests,
which use monkeypatched SDK fakes. They are deliberately kept out of the default
``pytest`` run because they require a running Docker daemon and are slow.

Run them explicitly::

    pytest -m integration                 # all integration tests
    pytest -m integration tests/integration/test_chroma_integration.py

Or via the nightly / manually-dispatched ``integration`` CI job.

Every module here is guarded by :func:`pytest.importorskip` for
``testcontainers`` and a Docker-availability check (see ``conftest.py``), so a
machine without Docker skips them cleanly rather than erroring.
"""
