"""The schema explorer never returns a raw metadata value.

``GET /stores/{id}/schema`` is open to every role, and it reports each
metadata field's most common values and a few examples. Raw values otherwise
need the compliance role, a reason and an audit entry (``reveal.py``), so the
explorer masks them the way the masked chunk view does: an identifying key
masks the whole value, and anything the classifier finds is masked in place.
"""

from __future__ import annotations

from typing import Iterator

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from vecshield.models import Chunk, Collection, VectorStore  # noqa: E402
from vecshield_platform.api import create_app  # noqa: E402
from vecshield_platform.api.registry import StoreRegistry  # noqa: E402
from vecshield_platform.connectors.base import Connector  # noqa: E402

VIEWER = {"Authorization": "Bearer read-tok"}

# Synthetic values; none of them is real.
LONG_NOTE = "x" * 130 + " reach bob.smith@example.org now"  # the email straddles the cut
CHUNK_METADATA = [
    {"tenant": "t1", "email": "jane.doe@example.com",
     "note": "call jane.doe@example.com today",
     "profile": {"phone": "(415) 555-0132", "plan": "gold"},
     "contacts": ["ops@example.com"], "long": LONG_NOTE},
    {"tenant": "t2", "email": "jake.roe@example.com",
     "note": "nothing personal here",
     "profile": {"phone": "(415) 555-0199", "plan": "gold"},
     # Identifying keys inside arrays of objects, which the field walk reports
     # as one value at the array's path; and a parent whose name merely
     # contains an identifying fragment ("settings" holds "tin").
     "people": [{"ssn": "987654321", "user_id": "u4242", "name": "Jo"}],
     "nested": [[{"ssn": "876543219"}]],
     "settings": {"plan": "gold"}},
]
COLLECTION_METADATA = {"owner": "kb-admin@example.com", "description": "support KB"}
RAW = ["jane.doe@example.com", "jake.roe@example.com", "ops@example.com",
       "555-0132", "555-0199", "bob.sm", "kb-admin@example.com",
       "987654321", "u4242", "876543219"]


class _MetadataStore(Connector):
    kind = "fake"

    def capabilities(self) -> set[str]:
        return set()

    def describe(self) -> VectorStore:
        return VectorStore(kind=self.kind, name="fake://store", endpoint="fake://store",
                           collections=self.list_collections())

    def list_collections(self) -> list[Collection]:
        return [Collection(name="docs", count=len(CHUNK_METADATA),
                           metadata=dict(COLLECTION_METADATA))]

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        for i, metadata in enumerate(CHUNK_METADATA):
            yield Chunk(id=f"c{i}", collection=collection, text="body", metadata=metadata)

    def query(self, collection, vector, top_k=10, where=None):
        return []


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("VECSHIELD_NLP_MODE", "disabled")
    monkeypatch.delenv("VECSHIELD_NLP_MODEL", raising=False)
    reg = StoreRegistry()
    reg.register("meta", "fake", factory=_MetadataStore)
    app = create_app(reg, serve_ui=False, auth_token="read-tok", admin_token="admin-tok")
    c = TestClient(app)
    yield c
    app.state.jobs.shutdown(wait=False)


def _fields(body):
    return {f["path"]: f for f in body["collections"][0]["metadata_fields"]}


@pytest.mark.parametrize("url", ["/stores/meta/schema", "/admin/stores/meta/schema"])
def test_viewer_gets_no_raw_metadata_value(client, url):
    r = client.get(url, headers=VIEWER)
    assert r.status_code == 200, r.text
    for raw in RAW:
        assert raw not in r.text, raw
    assert r.json()["values_masked"] is True


def test_masked_values_keep_the_schema_useful(client):
    body = client.get("/stores/meta/schema", headers=VIEWER).json()
    fields = _fields(body)

    # Values that identify nobody stay readable: the tenant field is still
    # discoverable, and so is a plain category.
    assert {v["value"] for v in fields["tenant"]["top_values"]} == {"t1", "t2"}
    assert fields["profile.plan"]["top_values"] == [{"value": "gold", "count": 2}]
    # Judged by its own key, as the chunk view judges it, not by its parent's.
    assert fields["settings.plan"]["top_values"] == [{"value": "gold", "count": 1}]
    # The array is masked element by element under each element's own keys.
    assert '"name": "Jo"' in fields["people"]["top_values"][0]["value"]

    # An identifying key masks the whole value, nested or not. Two addresses
    # that mask alike are counted together rather than listed twice.
    assert fields["email"]["top_values"] == [{"value": "ja" + "*" * 16 + "om", "count": 2}]
    assert fields["email"]["examples"] == ["ja" + "*" * 16 + "om"]
    phones = {v["value"] for v in fields["profile.phone"]["top_values"]}
    assert all("555" not in p for p in phones)

    # Elsewhere only the detected span is masked, and the text around it stays.
    notes = {v["value"] for v in fields["note"]["top_values"]}
    assert "nothing personal here" in notes
    assert any(n.startswith("call ja") and n.endswith(" today") for n in notes)

    # Masked before the preview is cut: no half of an address survives.
    long_value = fields["long"]["top_values"][0]["value"]
    assert long_value.endswith("...") and "bob.sm" not in long_value

    collection_metadata = body["collections"][0]["metadata"]
    assert collection_metadata["description"] == "support KB"
    assert "@" not in collection_metadata["owner"]


def test_unavailable_required_model_is_503_not_store_failure(client, monkeypatch):
    import vecshield_platform.api.app as app_module

    def unavailable(**_):
        raise RuntimeError("model missing")

    monkeypatch.setattr(app_module, "build_classifier", unavailable)
    r = client.get("/stores/meta/schema", headers=VIEWER)
    assert r.status_code == 503
    assert "jane.doe" not in r.text
    # An unknown store is still a 404, whatever the model's state.
    assert client.get("/stores/nope/schema", headers=VIEWER).status_code == 404
