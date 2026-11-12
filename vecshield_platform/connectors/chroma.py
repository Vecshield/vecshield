"""Chroma connector.

Supports both a remote Chroma server (HttpClient) and a local persistent
directory (PersistentClient). chromadb is imported lazily so the rest of
VecShield works without it installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterator, Optional, TypeVar

from vecshield_platform.connectors.base import (
    Connector,
    ConnectorAuthError,
    ConnectorError,
    ConnectorNotFound,
    ConnectorUnavailable,
    UnsupportedCapability,
    mapped_call,
    retry_read,
)
from vecshield_platform.connectors.redact import redact_credentials
from vecshield.models import Chunk, Collection, QueryHit, VectorStore

#: chromadb.errors classes by name (chromadb is imported lazily). Their
#: ``code()`` is a method, so the shared status mapping cannot see it, and
#: "AuthorizationError"/"AuthError" match no generic name pattern.
_ERRORS: dict[str, type[ConnectorError]] = {
    "AuthorizationError": ConnectorAuthError,
    "ChromaAuthError": ConnectorAuthError,
    "NotFoundError": ConnectorNotFound,
    "RateLimitError": ConnectorUnavailable,
    "InternalError": ConnectorUnavailable,
}
#: Collections per list_collections page.
_COLLECTION_PAGE = 100

_T = TypeVar("_T")


class ChromaConnector(Connector):
    kind = "chroma"

    def __init__(
        self,
        host: Optional[str] = None,
        port: int = 8000,
        path: Optional[str] = None,
        *,
        ssl: bool = False,
        headers: Optional[dict[str, str]] = None,
        tenant: Optional[str] = None,
        database: Optional[str] = None,
        create: bool = False,
    ):
        """Either host/port (remote server) or path (local persistent store).

        ``ssl`` and ``headers`` apply to a remote server only. ``tenant`` and
        ``database`` select where collections are listed; chromadb's defaults
        apply when they are not given.

        ``path`` must already hold a Chroma store (its ``chroma.sqlite3``):
        chromadb would otherwise create an empty one there, and a mistyped
        path would be audited as an empty, clean store. ``create=True``
        allows a new store for direct callers; build_connector() never
        passes it, so configured stores are never created.
        """
        try:
            import chromadb
        except ImportError as e:  # pragma: no cover
            raise ImportError(
                "chromadb not installed. Run: pip install 'vecshield[chroma]'"
            ) from e

        scope: dict[str, Any] = {}
        if tenant:
            scope["tenant"] = str(tenant)
        if database:
            scope["database"] = str(database)
        if path:
            if not create and not (Path(path) / "chroma.sqlite3").is_file():
                raise ConnectorNotFound(
                    f"chroma: no Chroma store at {path!r} (no chroma.sqlite3 there); "
                    "check the configured path")
            self._client = chromadb.PersistentClient(path=path, **scope)
            self._endpoint = f"file://{path}"
        else:
            host = host or "localhost"
            secure = _truthy(ssl)
            self._client = chromadb.HttpClient(
                host=host, port=port, ssl=secure,
                headers=dict(headers) if headers else None, **scope)
            scheme = "https" if secure else "http"
            # Header values are credentials; only the endpoint is displayed.
            self._endpoint = redact_credentials(f"{scheme}://{host}:{port}")

    def capabilities(self) -> set[str]:
        # No key management API in Chroma OSS, so no "api_keys".
        return {"query", "delete", "write", "redact", "metadata_write",
                "collection_metadata_write", "collection_create"}

    def _read(self, fn: Callable[[], _T]) -> _T:
        """An idempotent read: errors translated, transient ones retried."""
        return retry_read(mapped_call(fn, kind=self.kind, extra=_ERRORS))

    def _call(self, fn: Callable[[], _T]) -> _T:
        """A write: errors translated, never retried."""
        return mapped_call(fn, kind=self.kind, extra=_ERRORS)()

    def _collection(self, name: str) -> Any:
        return self._read(lambda: self._client.get_collection(name))

    def query(
        self,
        collection: str,
        vector: list[float],
        top_k: int = 10,
        where: Optional[dict[str, Any]] = None,
    ) -> list[QueryHit]:
        return self.query_many(collection, [vector], top_k=top_k, where=where)[0]

    def query_many(
        self,
        collection: str,
        vectors: list[list[float]],
        top_k: int = 10,
        where: Optional[dict[str, Any]] = None,
    ) -> list[list[QueryHit]]:
        """Several vectors in one Chroma request, results in input order."""
        if not vectors:
            return []
        col = self._collection(collection)
        res = self._read(lambda: col.query(
            query_embeddings=list(vectors),
            n_results=top_k,
            where=where or None,
            include=["documents", "metadatas", "distances"],
        ))
        return [_hits(res, row) for row in range(len(vectors))]

    def describe(self) -> VectorStore:
        return VectorStore(
            kind=self.kind,
            name=self._endpoint,
            endpoint=self._endpoint,
            collections=self.list_collections(),
        )

    def _all_collections(self) -> list[Any]:
        """Every collection, a page at a time (list_collections is paginated)."""
        out: list[Any] = []
        offset = 0
        while True:
            page = list(self._read(lambda: self._client.list_collections(
                limit=_COLLECTION_PAGE, offset=offset)) or [])
            out.extend(page)
            if len(page) < _COLLECTION_PAGE:
                return out
            offset += len(page)

    def list_collections(self) -> list[Collection]:
        out: list[Collection] = []
        for c in self._all_collections():
            name = _collection_name(c)
            col = c if hasattr(c, "count") and hasattr(c, "peek") else self._collection(name)
            # From the collection, not the listing: chromadb 0.6 lists bare
            # names, which carry no metadata (and so no declared model).
            metadata = dict(getattr(col, "metadata", None) or {})
            dim = None
            try:
                sample = self._read(lambda: col.peek(limit=1))
                embs = sample.get("embeddings") if sample else None
                if embs is not None and len(embs) > 0 and embs[0] is not None:
                    dim = len(embs[0])
            except Exception:  # noqa: BLE001 - the dimension is optional
                pass
            try:
                count = int(self._read(col.count))
            except Exception:  # noqa: BLE001
                # Zero would read as "empty" and pass every count cross-check.
                count = 0
                metadata["count_known"] = False
            out.append(
                Collection(
                    name=name,
                    count=count,
                    dimension=dim,
                    # Chroma has no first-class embedding-model field, so the
                    # convention is a metadata key. Without it the inversion
                    # scorer falls back to its cautious default of 0.55, which
                    # sits below every threshold that asks about invertibility —
                    # so a collection that says which model it used was being
                    # scored as though it had not.
                    embedding_model=_declared_model(metadata),
                    metadata=metadata,
                )
            )
        return out

    def iter_chunks(self, collection: str, batch_size: int = 256) -> Iterator[Chunk]:
        """Every record, paged until the store returns an empty page.

        Paging is not bounded by count(), and a short page does not end it: a
        stale count, or a server that caps the page below ``batch_size``, must
        not end the read early.
        """
        col = self._collection(collection)
        batch_size = max(1, int(batch_size))
        offset = 0
        while True:
            batch = self._read(lambda: col.get(
                limit=batch_size,
                offset=offset,
                include=["documents", "metadatas", "embeddings"],
            ))
            ids = batch.get("ids", []) or []
            docs = batch.get("documents") or [None] * len(ids)
            metas = batch.get("metadatas") or [{}] * len(ids)
            embs = batch.get("embeddings")
            if embs is None:
                embs = [None] * len(ids)
            for i, _id in enumerate(ids):
                yield Chunk(
                    id=_id,
                    collection=collection,
                    text=docs[i] if i < len(docs) else None,
                    embedding=_floats(embs[i] if i < len(embs) else None),
                    metadata=dict(metas[i]) if i < len(metas) and metas[i] else {},
                )
            if not ids:
                break
            offset += len(ids)


    def add_chunks(self, collection: str, chunks: list[Chunk]) -> int:
        """Upsert chunks into a collection, creating it if needed.

        Explicit embeddings are written when every chunk carries one; otherwise
        the documents are written and Chroma's configured embedding function
        embeds them at write time.
        """
        if not chunks:
            return 0
        col = self._call(lambda: self._client.get_or_create_collection(collection))
        ids = [str(c.id) for c in chunks]
        docs = [c.text if c.text is not None else "" for c in chunks]
        # Chroma rejects an empty metadata dict but accepts None per record, so
        # a chunk without metadata is None and the others keep theirs. Dropping
        # the whole list whenever one chunk had none lost every chunk's.
        metas = [dict(c.metadata) if c.metadata else None for c in chunks]
        kwargs: dict[str, Any] = {"ids": ids, "documents": docs}
        if all(c.embedding is not None for c in chunks):
            kwargs["embeddings"] = [_floats(c.embedding) for c in chunks]
        if any(m is not None for m in metas):
            kwargs["metadatas"] = metas
        self._call(lambda: col.upsert(**kwargs))
        return len(ids)

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        col = self._collection(collection)
        self._call(lambda: col.delete(ids=ids))
        # Chroma's delete returns nothing and ignores unknown ids, so this is
        # the number of ids *requested*, not a confirmed count; erasure
        # verification re-reads the ids to establish what is gone.
        return len(ids)

    def set_chunk_metadata(self, collection: str,
                           updates: dict[str, dict[str, Any]]) -> int:
        """Merge fields into each named chunk's metadata.

        Reads the current metadata and writes the union, because Chroma's
        update() replaces the metadata document rather than merging into it.
        Ids that are not in the collection are skipped and not counted: a
        caller must not be told it marked a chunk that was not there.
        """
        if not updates:
            return 0
        col = self._collection(collection)
        ids = [str(i) for i in updates]
        existing = self._read(lambda: col.get(ids=ids, include=["metadatas"]))
        found = list(existing.get("ids") or [])
        if not found:
            return 0
        current = existing.get("metadatas") or []
        merged = [{**(dict(current[i]) if i < len(current) and current[i] else {}),
                   **updates[found[i]]}
                  for i in range(len(found))]
        self._call(lambda: col.update(ids=found, metadatas=merged))
        return len(found)

    def get_chunks(self, collection: str, ids: list[str]) -> list[Chunk]:
        col = self._collection(collection)
        got = self._read(lambda: col.get(ids=[str(i) for i in ids],
                                         include=["documents", "metadatas", "embeddings"]))
        found = list(got.get("ids") or [])
        docs = got.get("documents") or []
        metas = got.get("metadatas") or []
        embs = got.get("embeddings")
        out = []
        for i, cid in enumerate(found):
            emb = embs[i] if embs is not None and i < len(embs) and embs[i] is not None else None
            out.append(Chunk(
                id=cid, collection=collection,
                text=docs[i] if i < len(docs) else None,
                embedding=_floats(emb),
                metadata=dict(metas[i]) if i < len(metas) and metas[i] else {}))
        return out

    def replace_chunk_text(self, collection: str, chunk_id: str, text: str,
                           metadata_updates: Optional[dict[str, Any]] = None) -> bool:
        """Replace the document, re-supplying the stored vector.

        Passing the existing embedding back is the whole point: an update with
        a document and no embedding makes Chroma call the collection's
        embedding function, which on a locked-down deployment fails and on any
        deployment embeds with a model that is not the one the neighbours used.
        """
        col = self._collection(collection)
        current = self._read(lambda: col.get(ids=[chunk_id],
                                             include=["metadatas", "embeddings"]))
        if not current.get("ids"):
            return False
        embs = current.get("embeddings")
        embedding = (_floats(embs[0]) if embs is not None and len(embs) and embs[0] is not None
                     else None)
        if embedding is None:
            # No stored vector to carry over, so an update would have to embed.
            # Refuse rather than let the store pick a model.
            raise UnsupportedCapability(
                f"{chunk_id} has no stored embedding; replacing its text would "
                "require the store to embed it with a model this product cannot vouch for")
        metas = current.get("metadatas") or [{}]
        merged = {**(dict(metas[0]) if metas[0] else {}), **(metadata_updates or {})}
        kwargs: dict[str, Any] = {"ids": [chunk_id], "documents": [text],
                                  "embeddings": [embedding]}
        if merged:
            kwargs["metadatas"] = [merged]
        self._call(lambda: col.update(**kwargs))
        return True

    def create_collection_like(self, source: str, name: str,
                               metadata: Optional[dict[str, Any]] = None) -> bool:
        """Create ``name`` with ``source``'s index configuration, or reuse it.

        The configuration is what makes a copy search like the original: a
        collection created with defaults uses L2 distance, and vectors written
        for cosine similarity would then rank differently. Returns whether the
        collection was newly created.
        """
        src = self._collection(source)
        existed = name in {_collection_name(c) for c in self._all_collections()}
        meta = {**dict(src.metadata or {}), **(metadata or {})}
        kwargs: dict[str, Any] = {"metadata": meta}
        configuration = getattr(src, "configuration", None)
        if configuration:
            kwargs["configuration"] = configuration
        col = self._call(lambda: self._client.get_or_create_collection(name, **kwargs))
        if existed and metadata:
            self._call(lambda: col.modify(metadata={**dict(col.metadata or {}), **metadata}))
        return not existed

    def set_collection_metadata(self, collection: str, updates: dict[str, Any]) -> bool:
        """Merge fields into the collection's own metadata."""
        if not updates:
            return False
        col = self._collection(collection)
        current = dict(col.metadata or {})
        self._call(lambda: col.modify(metadata={**current, **updates}))
        return True


#: Keys a collection may use to declare the model its vectors came from. More
#: than one because no convention is established; the first present wins.
_MODEL_KEYS = ("embedding_model", "embedding-model", "model", "hnsw:model")


def _hits(res: Any, row: int) -> list[QueryHit]:
    """The hits of one query row of a Chroma ``query`` response."""
    def column(name: str) -> list:
        values = res.get(name) or []
        return (values[row] if row < len(values) else None) or []

    ids, docs, metas, dists = (column("ids"), column("documents"),
                               column("metadatas"), column("distances"))
    hits: list[QueryHit] = []
    for i, _id in enumerate(ids):
        d = dists[i] if i < len(dists) and dists[i] is not None else 0.0
        hits.append(
            QueryHit(
                id=_id,
                # Negated distance: higher is closer, as for every other
                # store, and the distance itself is not distorted.
                score=-float(d),
                text=docs[i] if i < len(docs) else None,
                metadata=dict(metas[i]) if i < len(metas) and metas[i] else {},
            )
        )
    return hits


def _declared_model(metadata: dict) -> str | None:
    for key in _MODEL_KEYS:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _floats(vector: Any) -> Optional[list[float]]:
    """An embedding as plain Python floats; chromadb returns numpy arrays."""
    if vector is None:
        return None
    return [float(x) for x in vector]


def _truthy(value: Any) -> bool:
    """``ssl`` from config may arrive as a string ("true", "0")."""
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _collection_name(collection) -> str:
    if isinstance(collection, str):
        return collection
    return collection.name