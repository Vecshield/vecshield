"""Datasource connectors: credentials, listing and read behaviour.

Covers: the huggingface format-reader alias (latent trap), the object/file size
cap that guards against OOM, local path containment, and the HF split-discovery
fallback now logging instead of silently swallowing.
"""

from __future__ import annotations

import logging

import pytest

from vecshield.classify import RegexClassifier
from vecshield.datascan import scan_datasource
from vecshield.models import Severity
from vecshield_platform.datasources import build_datasource
from vecshield_platform.datasources._object import ObjectStoreDataSource
from vecshield_platform.datasources.formats import read_records


# --------------------------------------------------------------------------- #
# §6.1 huggingface format reader (no longer a missing-reader trap)
# --------------------------------------------------------------------------- #

def test_huggingface_format_reader_parses_like_jsonl():
    data = b'{"text":"leak AKIAIOSFODNN7EXAMPLE","id":1}\n{"text":"clean"}\n'
    recs = list(read_records("huggingface", data, text_field="text"))
    assert len(recs) == 2
    assert "AKIA" in recs[0][0]
    assert recs[0][1].get("id") == 1  # non-text fields become metadata


# --------------------------------------------------------------------------- #
# §6.2 object/file size cap (OOM guard)
# --------------------------------------------------------------------------- #

class _FakeObjectStore(ObjectStoreDataSource):
    kind = "fake"

    def __init__(self, blobs: dict[str, bytes]):
        self._blobs = blobs
        self._endpoint = "fake://bucket"
        self._text_field = "text"
        self._format = None
        self.list_calls = 0

    def _list_blobs(self):
        self.list_calls += 1
        return [(k, len(v)) for k, v in self._blobs.items()]

    def _fetch(self, key: str) -> bytes:
        return self._blobs[key]


def test_object_store_skips_oversized_blob(caplog):
    small = b'{"text":"hi"}\n'
    big = b'{"text":"' + b"x" * 200 + b'"}\n'
    src = _FakeObjectStore({"small.jsonl": small, "big.jsonl": big})
    src.max_object_bytes = 50

    assert len(list(src.iter_records("small.jsonl"))) == 1
    with caplog.at_level(logging.WARNING):
        assert list(src.iter_records("big.jsonl")) == []
    assert "oversized object" in caplog.text
    # size index is built once and reused across iter_records calls
    assert src.list_calls == 1


def test_object_store_scan_still_works_under_cap():
    src = _FakeObjectStore(
        {"a.jsonl": b'{"text":"secret AKIAIOSFODNN7EXAMPLE"}\n'})
    job = scan_datasource(src, classifier=RegexClassifier())
    assert job.max_severity.rank >= Severity.HIGH.rank


def test_local_source_skips_oversized_file(tmp_path, caplog):
    p = tmp_path / "d.jsonl"
    p.write_text('{"text":"AKIAIOSFODNN7EXAMPLE"}\n')
    src = build_datasource("local", path=str(tmp_path), text_field="text")

    src.max_object_bytes = 5
    with caplog.at_level(logging.WARNING):
        assert list(src.iter_records("d.jsonl")) == []
    assert "oversized file" in caplog.text

    src.max_object_bytes = None
    assert len(list(src.iter_records("d.jsonl"))) == 1


# --------------------------------------------------------------------------- #
# path containment (local)
# --------------------------------------------------------------------------- #

def test_local_source_rejects_path_traversal(tmp_path):
    (tmp_path / "d.jsonl").write_text('{"text":"x"}\n')
    src = build_datasource("local", path=str(tmp_path))
    with pytest.raises(ValueError):
        list(src.iter_records("../../../../etc/passwd"))


# --------------------------------------------------------------------------- #
# §6.4 HF split-discovery fallback now logs
# --------------------------------------------------------------------------- #

def test_hf_split_fallback_logs(monkeypatch, caplog):
    pytest.importorskip("datasets")
    import datasets  # noqa: F401
    from vecshield_platform.datasources.huggingface import HuggingFaceDataSource

    src = HuggingFaceDataSource(dataset="acme/does-not-exist")  # no split set

    def boom(*args, **kwargs):
        raise RuntimeError("offline")

    monkeypatch.setattr("datasets.get_dataset_split_names", boom)
    with caplog.at_level(logging.WARNING):
        infos = src.list_datasets()

    assert [i.name for i in infos] == ["train"]
    assert "falling back to ['train']" in caplog.text
