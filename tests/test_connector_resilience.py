"""Tests for connector resilience & error taxonomy (improvement plan 1.11):
typed error hierarchy, retry/backoff for idempotent reads, and distinct
error-category reporting in validate_connector."""

from __future__ import annotations

from typing import Iterator

import pytest

from vecshield_platform.connectors.base import (
    Connector,
    ConnectorAuthError,
    ConnectorError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    UnsupportedCapability,
    retry_read,
)
from vecshield.models import Chunk, Collection, VectorStore
from vecshield_platform.validation import (
    classify_connector_error,
    validate_connector,
)


# --------------------------------------------------------------------------- #
# Error taxonomy                                                              #
# --------------------------------------------------------------------------- #

def test_transient_errors_are_connector_errors():
    assert issubclass(ConnectorTimeout, ConnectorError)
    assert issubclass(ConnectorUnavailable, ConnectorError)
    assert issubclass(ConnectorAuthError, ConnectorError)
    assert issubclass(ConnectorNotFound, ConnectorError)


@pytest.mark.parametrize("exc,expected", [
    (ConnectorAuthError("x"), "auth"),
    (ConnectorTimeout("x"), "timeout"),
    (ConnectorUnavailable("x"), "unavailable"),
    (ConnectorNotFound("x"), "not_found"),
    (UnsupportedCapability("x"), "unsupported"),
    (RuntimeError("x"), "error"),
])
def test_classify_connector_error(exc, expected):
    assert classify_connector_error(exc) == expected


# --------------------------------------------------------------------------- #
# retry_read                                                                  #
# --------------------------------------------------------------------------- #

def test_retry_read_returns_immediately_on_success():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        return "ok"

    assert retry_read(fn, sleep=lambda _s: None) == "ok"
    assert calls["n"] == 1


def test_retry_read_recovers_after_transient_errors():
    calls = {"n": 0}
    slept: list[float] = []

    def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectorUnavailable("blip")
        return "ok"

    out = retry_read(fn, attempts=3, delay=0.1, backoff=2.0,
                     sleep=slept.append)
    assert out == "ok"
    assert calls["n"] == 3
    # Two sleeps between three attempts, with exponential backoff.
    assert slept == [0.1, 0.2]


def test_retry_read_raises_last_transient_after_exhausting():
    def fn():
        raise ConnectorTimeout("still down")

    with pytest.raises(ConnectorTimeout, match="still down"):
        retry_read(fn, attempts=3, sleep=lambda _s: None)


def test_retry_read_does_not_retry_auth_errors():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise ConnectorAuthError("bad key")

    with pytest.raises(ConnectorAuthError):
        retry_read(fn, attempts=5, sleep=lambda _s: None)
    assert calls["n"] == 1  # not retried


def test_retry_read_respects_max_delay():
    slept: list[float] = []
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        if calls["n"] < 4:
            raise ConnectorUnavailable("blip")
        return "ok"

    retry_read(fn, attempts=4, delay=3.0, backoff=10.0, max_delay=5.0,
               sleep=slept.append)
    # 3.0, then min(30.0, 5.0)=5.0, then min(300.0, 5.0)=5.0
    assert slept == [3.0, 5.0, 5.0]


def test_retry_read_rejects_invalid_attempts():
    with pytest.raises(ValueError):
        retry_read(lambda: None, attempts=0)


# --------------------------------------------------------------------------- #
# validate_connector reports categories                                       #
# --------------------------------------------------------------------------- #

class _BaseConn(Connector):
    kind = "fake"

    def describe(self) -> VectorStore:
        return VectorStore(kind=self.kind, name="fake://x", endpoint="fake://x",
                           collections=[Collection(name="docs", count=1, dimension=3)])

    def list_collections(self) -> list[Collection]:
        return self.describe().collections

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        yield Chunk(id="a", collection=collection, text="hello", embedding=[0.1, 0.2, 0.3])


def test_validate_connector_reports_auth_category():
    class AuthBroken(_BaseConn):
        def iter_chunks(self, collection: str, batch_size: int = 256):
            raise ConnectorAuthError("denied")

    result = validate_connector(AuthBroken(), run_scan=False, run_query=False,
                                run_key_audit=False)
    assert not result.ok
    check = next(c for c in result.checks if c.name == "sample_chunks")
    assert not check.ok
    assert check.data["error_category"] == "auth"


def test_validate_connector_reports_generic_category_for_untyped():
    class Broken(_BaseConn):
        def iter_chunks(self, collection: str, batch_size: int = 256):
            raise RuntimeError("boom")

    result = validate_connector(Broken(), run_scan=False, run_query=False,
                                run_key_audit=False)
    check = next(c for c in result.checks if c.name == "sample_chunks")
    assert check.data["error_category"] == "error"
