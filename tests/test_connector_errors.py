"""The shared SDK-error mapper and per-collection read errors in connectors/base."""

from __future__ import annotations

import pytest

from vecshield_platform.connectors.base import (
    ConnectorAuthError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    UnsupportedCapability,
    error_class_for_status,
    mapped_call,
    mapped_errors,
    retry_read,
    translate_error,
)
from vecshield_platform.coverage import count_known, read_errors_for
from vecshield.models import Collection
from vecshield_platform.connectors.base import Connector


class FakeConnector(Connector):
    kind = "fake"

    def __init__(self, sizes):
        self.sizes = sizes

    def describe(self):
        raise NotImplementedError

    def list_collections(self):
        return [Collection(n, c) for n, c in self.sizes.items()]

    def iter_chunks(self, collection, batch_size=256):
        return iter(())


class HttpError(Exception):
    def __init__(self, status_code, message="boom"):
        super().__init__(message)
        self.status_code = status_code


class ResponseError(Exception):
    def __init__(self, status):
        super().__init__("x")
        self.response = type("R", (), {"status_code": status})()


class _Code:
    def __init__(self, name):
        self.name = name


class RpcError(Exception):
    def __init__(self, name):
        super().__init__("rpc")
        self._name = name

    def code(self):
        return _Code(self._name)


class SdkThing(Exception):
    pass


@pytest.mark.parametrize("status, expected", [
    (401, ConnectorAuthError), (403, ConnectorAuthError), (404, ConnectorNotFound),
    (408, ConnectorTimeout), (504, ConnectorTimeout), (429, ConnectorUnavailable),
    (500, ConnectorUnavailable), (503, ConnectorUnavailable), (400, None), (True, None),
    ("nope", None)])
def test_status_codes_map_to_the_taxonomy(status, expected):
    assert error_class_for_status(status) is expected


def test_auth_failures_are_not_retryable():
    calls = []

    def read():
        calls.append(1)
        raise HttpError(403)

    with pytest.raises(ConnectorAuthError):
        retry_read(mapped_call(read, kind="x"), sleep=lambda _: None)
    assert len(calls) == 1


def test_transient_failures_are_retried_after_mapping():
    calls = []

    def read():
        calls.append(1)
        if len(calls) < 3:
            raise HttpError(503)
        return "ok"

    assert retry_read(mapped_call(read, kind="x"), sleep=lambda _: None) == "ok"
    assert len(calls) == 3


@pytest.mark.parametrize("exc, expected", [
    (ResponseError(401), ConnectorAuthError),
    (RpcError("UNAUTHENTICATED"), ConnectorAuthError),
    (RpcError("DEADLINE_EXCEEDED"), ConnectorTimeout),
    (RpcError("UNAVAILABLE"), ConnectorUnavailable),
    (RpcError("NOT_FOUND"), ConnectorNotFound),
    (type("ReadTimeout", (Exception,), {})(), ConnectorTimeout),
    (type("UnauthorizedException", (Exception,), {})(), ConnectorAuthError),
    (type("CollectionNotFound", (Exception,), {})(), ConnectorNotFound),
    (TimeoutError(), ConnectorTimeout),
    (ConnectionRefusedError(), ConnectorUnavailable),
])
def test_exceptions_are_recognised(exc, expected):
    assert isinstance(translate_error(exc, kind="x"), expected)


def test_registered_sdk_classes_win_and_subclasses_inherit():
    class Sub(SdkThing):
        pass

    out = translate_error(Sub(), kind="x", extra={SdkThing: ConnectorNotFound})
    assert isinstance(out, ConnectorNotFound)
    out = translate_error(SdkThing(), kind="x", extra={"SdkThing": ConnectorAuthError})
    assert isinstance(out, ConnectorAuthError)


def test_unrecognised_and_taxonomy_errors_pass_through():
    err = ValueError("bad input")
    assert translate_error(err, kind="x") is err
    unsupported = UnsupportedCapability("no")
    assert translate_error(unsupported, kind="x") is unsupported


def test_the_message_never_carries_the_sdk_text():
    out = translate_error(HttpError(401, "api-key=sk-live-123 rejected"), kind="qdrant")
    assert str(out) == "qdrant: HttpError (status 401)"
    assert "sk-live" not in str(out)


def test_mapped_errors_chains_the_original():
    with pytest.raises(ConnectorUnavailable) as info:
        with mapped_errors("x"):
            raise HttpError(502)
    assert isinstance(info.value.__cause__, HttpError)
    with pytest.raises(KeyError):
        with mapped_errors("x"):
            raise KeyError("k")


def test_read_errors_are_recorded_per_collection_and_reset():
    conn = FakeConnector({"a": 1})
    assert conn.read_errors() == []
    conn._record_read_error("a", item_id="1", error_type="Timeout")
    conn._record_read_error(None, operation="list")
    errors = conn.read_errors()
    assert errors[0] == {"collection": "a", "item_id": "1", "error_type": "Timeout"}
    assert len(read_errors_for(errors, "a")) == 2
    assert read_errors_for(errors, "b") == [errors[1]]
    errors.clear()  # a copy: the caller cannot clear the connector's list
    assert len(conn.read_errors()) == 2
    conn.reset_read_errors()
    assert conn.read_errors() == []


def test_count_known_defaults_to_true():
    assert count_known(Collection("a", 0)) is True
    assert count_known(Collection("a", 0, metadata={"count_known": False})) is False


def test_a_database_error_code_is_not_read_as_an_http_status():
    class OperationFailure(Exception):
        code = 401  # a server error number, not HTTP

    err = OperationFailure()
    assert translate_error(err, kind="mongodb") is err
