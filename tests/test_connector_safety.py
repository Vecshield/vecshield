"""Connector hardening regression tests."""

from __future__ import annotations

import pytest


def test_milvus_filter_escapes_string_values():
    from vecshield_platform.connectors.milvus import _filter

    expr = _filter({"tenant_id": 'acme" or tenant_id != "acme'})
    assert expr == 'tenant_id == "acme\\" or tenant_id != \\"acme"'


def test_milvus_filter_rejects_unsafe_field_names():
    from vecshield_platform.connectors.milvus import _filter

    with pytest.raises(ValueError):
        _filter({"tenant_id or true": "acme"})


def test_pgvector_quotes_identifiers():
    from vecshield_platform.connectors.pgvector import _quote_ident

    assert _quote_ident('weird"name') == '"weird""name"'


def test_chroma_collection_name_supports_string_and_object():
    from vecshield_platform.connectors.chroma import _collection_name

    class CollectionLike:
        name = "docs"

    assert _collection_name("docs") == "docs"
    assert _collection_name(CollectionLike()) == "docs"
