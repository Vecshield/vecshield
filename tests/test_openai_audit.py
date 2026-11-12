"""OpenAI vector stores: file splitting, unreadable files, dates, paging, deletes.

No network: the client is a fake shaped like openai 1.66+ (``vector_stores``
at top level, cursor pages with ``data``/``has_more``, ``files.content()``).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("openai")

from vecshield.classify import RegexClassifier  # noqa: E402
from vecshield.classify.surfaces import MAX_SURFACE_CHARS, chunk_text_surfaces  # noqa: E402
from vecshield.models import Severity  # noqa: E402
from vecshield_platform.connectors.base import ConnectorAuthError  # noqa: E402
from vecshield_platform.connectors.openai_vs import (  # noqa: E402
    OpenAIVectorStoreConnector,
    file_id_of,
    split_text,
)
from vecshield_platform.coverage import count_known  # noqa: E402
from vecshield_platform.scan import scan_store  # noqa: E402

COLLECTION = "kb (vs_1)"


def _long_text(words: int) -> str:
    paragraphs = []
    for p in range(words // 50):
        paragraphs.append(" ".join(f"word{p}x{i}" for i in range(50)))
    return "\n\n".join(paragraphs)


def _file(fid, status="completed", created_at=1_700_000_000):
    return SimpleNamespace(id=fid, status=status, usage_bytes=10, attributes={},
                           created_at=created_at)


class _Files:
    def __init__(self, files, texts, page_size=100):
        self.files, self.texts, self.page_size = files, texts, page_size
        self.list_calls: list[dict] = []
        self.content_calls: list[str] = []
        self.deleted: list[str] = []

    def list(self, vector_store_id=None, limit=None, after=None):
        self.list_calls.append({"limit": limit, "after": after})
        ids = [f.id for f in self.files]
        start = ids.index(after) + 1 if after else 0
        size = min(limit or 100, self.page_size)
        data = self.files[start:start + size]
        return SimpleNamespace(data=data, has_more=start + size < len(self.files))

    def content(self, vector_store_id=None, file_id=None):
        self.content_calls.append(file_id)
        text = self.texts[file_id]
        if isinstance(text, Exception):
            raise text
        return [SimpleNamespace(text=text, type="text")]

    def delete(self, vector_store_id=None, file_id=None):
        self.deleted.append(file_id)


def _connector(files, texts, *, page_size=100, file_counts=True):
    conn = OpenAIVectorStoreConnector.__new__(OpenAIVectorStoreConnector)
    store_files = _Files(files, texts, page_size)
    store = SimpleNamespace(id="vs_1", name="kb",
                            file_counts=SimpleNamespace(total=len(files))
                            if file_counts else None)
    conn._c = SimpleNamespace(vector_stores=SimpleNamespace(
        files=store_files,
        list=lambda limit=None, after=None: SimpleNamespace(data=[store], has_more=False)))
    conn._endpoint = "openai://vector_stores"
    conn._read_errors = []
    conn.delete_file_objects = False
    conn._file_deletions = {"attempted": 0, "deleted": 0, "failed": 0}
    return conn, store_files


def test_split_text_respects_limit_and_boundaries():
    text = _long_text(2000)
    pieces = split_text(text, 4000)
    assert len(pieces) > 1 and "".join(pieces) == text
    assert all(len(p) <= 4000 for p in pieces)
    # Cuts fall on whitespace: no word is split across two pieces.
    words = set(text.split())
    assert all(w in words for p in pieces for w in p.split())
    # A run with no whitespace is still cut at the limit.
    assert [len(p) for p in split_text("x" * 9000, 4000)] == [4000, 4000, 1000]
    assert split_text("   \n\n  ", 4000) == []


def test_long_file_is_split_into_numbered_pieces_under_the_window():
    secret = "aws key AKIAIOSFODNN7EXAMPLE leaked"
    text = _long_text(2000) + "\n\n" + secret
    assert len(text) > 3 * MAX_SURFACE_CHARS
    conn, _ = _connector([_file("file-big"), _file("file-small")],
                         {"file-big": text, "file-small": "short note"})
    chunks = list(conn.iter_chunks(COLLECTION))
    big = [c for c in chunks if c.id.startswith("file-big")]
    assert [c.id for c in big] == [f"file-big#{n}" for n in range(len(big))]
    assert len(big) > 1
    assert all(len(c.text.strip()) < MAX_SURFACE_CHARS for c in big)
    assert all(not s.truncated_chars for c in big for s in chunk_text_surfaces(c))
    assert all(c.metadata["pieces"] == len(big) for c in big)
    # A file that fits keeps its bare id.
    assert [c.id for c in chunks if c.id.startswith("file-small")] == ["file-small"]
    # The secret near the end is now classified, not cut off.
    job = scan_store(conn, classifier=RegexClassifier())
    assert job.max_severity == Severity.CRITICAL


def test_created_at_is_in_chunk_metadata():
    conn, _ = _connector([_file("file-a", created_at=1_690_000_000)], {"file-a": "hello"})
    (chunk,) = list(conn.iter_chunks(COLLECTION))
    assert chunk.metadata["created_at"] == 1_690_000_000


def test_unfinished_and_empty_files_are_read_errors_for_their_collection():
    files = [_file("file-ok"), _file("file-pending", status="in_progress"),
             _file("file-failed", status="failed"), _file("file-empty")]
    conn, store_files = _connector(files, {"file-ok": "fine", "file-empty": "  "})
    chunks = {c.id: c for c in conn.iter_chunks(COLLECTION)}
    assert chunks["file-ok"].text == "fine"
    for fid in ("file-pending", "file-failed", "file-empty"):
        assert chunks[fid].text is None and chunks[fid].metadata["content_unreadable"]
    # Unfinished files are not read at all.
    assert store_files.content_calls == ["file-ok", "file-empty"]
    errors = {e["file_id"]: e for e in conn.read_errors()}
    assert set(errors) == {"file-pending", "file-failed", "file-empty"}
    assert all(e["collection"] == COLLECTION for e in errors.values())
    assert errors["file-pending"]["error_type"] == "FileNotCompleted"
    assert errors["file-pending"]["file_status"] == "in_progress"
    assert errors["file-empty"]["error_type"] == "EmptyContent"


def test_read_errors_reset_between_passes():
    conn, _ = _connector([_file("file-x", status="failed")], {})
    first = scan_store(conn, classifier=RegexClassifier())
    second = scan_store(conn, classifier=RegexClassifier())
    assert first.stats["content_read_errors"] == 1
    assert second.stats["content_read_errors"] == 1  # not 2: the first pass was cleared
    conn.reset_read_errors()
    assert conn.read_errors() == []


def test_file_listing_follows_the_cursor():
    files = [_file(f"file-{i}") for i in range(5)]
    conn, store_files = _connector(files, {f.id: "t" for f in files}, page_size=2)
    assert [c.id for c in conn.iter_chunks(COLLECTION)] == [f.id for f in files]
    assert [c["after"] for c in store_files.list_calls] == [None, "file-1", "file-3"]
    assert all(c["limit"] == 100 for c in store_files.list_calls)


def test_auth_failure_on_content_raises_mapped():
    import httpx
    import openai

    request = httpx.Request("GET", "https://api.openai.com/v1/x")
    denied = openai.AuthenticationError(
        "bad key", response=httpx.Response(401, request=request), body=None)
    conn, _ = _connector([_file("file-a")], {"file-a": denied})
    with pytest.raises(ConnectorAuthError):
        list(conn.iter_chunks(COLLECTION))


def test_missing_file_counts_is_an_unknown_count():
    conn, _ = _connector([_file("file-a")], {"file-a": "x"}, file_counts=False)
    (col,) = conn.list_collections()
    assert col.name == COLLECTION and col.count == 0 and not count_known(col)


def test_delete_maps_pieces_to_files_once():
    conn, store_files = _connector([], {})
    ids = ["file-big#0", "file-big#1", "file-big#2", "file-small"]
    assert file_id_of("file-big#12") == "file-big" and file_id_of("file-small") == "file-small"
    assert conn.delete_chunks(COLLECTION, ids) == 4
    assert store_files.deleted == ["file-big", "file-small"]


def test_delete_failure_names_the_type_not_the_message():
    conn, store_files = _connector([], {})

    def fail(vector_store_id=None, file_id=None):
        raise RuntimeError("sk-secret-in-message")
    store_files.delete = fail
    with pytest.raises(RuntimeError) as info:
        conn.delete_chunks(COLLECTION, ["file-a#0", "file-a#1"])
    assert "sk-secret" not in str(info.value) and "1/1 file(s)" in str(info.value)
