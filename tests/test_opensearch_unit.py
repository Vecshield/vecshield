"""Unit test for the OpenSearch connector's scroll pagination (no live server).

The live OpenSearch flow is covered by ``test_opensearch.py`` (gated on a
reachable cluster). This drives ``iter_chunks`` through a fake client so the
Scroll-API pagination — which replaced the 10k-capped from+size loop — is
covered without opensearch-py or a running server.
"""
from __future__ import annotations

from vecshield_platform.connectors.opensearch import OpenSearchConnector


class _FakeOS:
    def __init__(self, pages: list[list[dict]]) -> None:
        self._pages = pages
        self._i = 0
        self.cleared = False
        self.scroll_calls = 0

    def search(self, index=None, scroll=None, body=None):
        page = self._pages[0] if self._pages else []
        self._i = 1
        return {"_scroll_id": "sid-1", "hits": {"hits": page}}

    def scroll(self, body=None):
        self.scroll_calls += 1
        page = self._pages[self._i] if self._i < len(self._pages) else []
        self._i += 1
        return {"_scroll_id": "sid-1", "hits": {"hits": page}}

    def clear_scroll(self, body=None):
        self.cleared = True


def _hit(doc_id: str, tenant: str) -> dict:
    return {"_id": doc_id,
            "_source": {"content": f"doc {doc_id}", "tenant_id": tenant,
                        "embedding": [0.1, 0.2, 0.3, 0.4]}}


def _make_connector(fake: _FakeOS) -> OpenSearchConnector:
    c = OpenSearchConnector.__new__(OpenSearchConnector)
    c._c = fake
    c._endpoint = "http://fake:9200"
    c._layout = {"idx": {"vec": "embedding", "text": "content", "dim": 4}}
    return c


def test_iter_chunks_scrolls_past_first_page():
    # Two full pages then an empty page — proves iteration continues past the
    # first batch (the old from+size loop would still work here, but this also
    # locks in the scroll wiring and metadata surfacing).
    pages = [[_hit("0", "acme"), _hit("1", "acme")],
             [_hit("2", "globex"), _hit("3", "globex")],
             []]
    fake = _FakeOS(pages)
    c = _make_connector(fake)

    chunks = list(c.iter_chunks("idx", batch_size=2))

    assert [ch.id for ch in chunks] == ["0", "1", "2", "3"]
    assert all(ch.embedding == [0.1, 0.2, 0.3, 0.4] for ch in chunks)
    assert all(ch.metadata.get("tenant_id") for ch in chunks)
    # embedding column must not leak into metadata
    assert all("embedding" not in ch.metadata for ch in chunks)
    assert fake.cleared is True


def test_iter_chunks_handles_empty_index():
    fake = _FakeOS([[]])
    c = _make_connector(fake)
    assert list(c.iter_chunks("idx")) == []
    assert fake.cleared is True
