"""OpenAI Vector Stores connector (managed mode).

OpenAI exposes vector stores + files + file content, but NOT raw embedding
vectors and only text (not vector) search. So this is a *managed-store* connector:
it inventories stores, reads file/chunk text + metadata for classification and
RAG-integrity scans, but advertises no `query` capability (no embedding-anomaly
or vector isolation probing). openai SDK imported lazily; it needs the
top-level ``client.vector_stores`` API with ``files.content()``.

Chunks
------
OpenAI returns text per *file*, not at the store's own chunk boundaries. The
classifier reads at most ``MAX_SURFACE_CHARS`` of a chunk's text, so a long
file read as one chunk had everything past that point go unexamined. A file
whose text is longer than ``_PIECE_CHARS`` is split, on paragraph, line or
whitespace boundaries where it can be, into pieces with ids ``<file id>#<n>``.
A file that fits in one piece keeps its bare file id, so findings recorded
against it before keep their identity. ``delete_chunks()`` maps every piece
back to its file.

Files that are not ``completed``, whose content cannot be retrieved, or that
return no text are recorded in ``read_errors()`` for their vector store and
yielded as an empty chunk marked ``content_unreadable``, never as clean text.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Iterator, Optional, TypeVar

from vecshield.classify.surfaces import MAX_SURFACE_CHARS
from vecshield_platform.connectors.base import (
    Connector,
    ConnectorAuthError,
    ConnectorNotFound,
    ConnectorTimeout,
    ConnectorUnavailable,
    ErrorRegistry,
    mapped_call,
    mapped_errors,
    retry_read,
)
from vecshield.models import Chunk, Collection, VectorStore

#: openai SDK exceptions by class name. APIStatusError subclasses also carry
#: ``status_code``; APITimeoutError is matched before its parent.
_ERRORS: ErrorRegistry = {
    "AuthenticationError": ConnectorAuthError,
    "PermissionDeniedError": ConnectorAuthError,
    "NotFoundError": ConnectorNotFound,
    "APITimeoutError": ConnectorTimeout,
    "RateLimitError": ConnectorUnavailable,
    "InternalServerError": ConnectorUnavailable,
    "APIConnectionError": ConnectorUnavailable,
}

#: Largest piece of a file's text, comfortably inside the classifier's window
#: (it strips each surface before measuring it, so whitespace is no concern).
_PIECE_CHARS = MAX_SURFACE_CHARS * 4 // 5
#: The list endpoints' maximum page size.
_LIST_LIMIT = 100
_PIECE_SUFFIX = re.compile(r"#\d+$")

_T = TypeVar("_T")


class OpenAIVectorStoreConnector(Connector):
    kind = "openai"

    def __init__(self, *, api_key: Optional[str] = None,
                 delete_file_objects: bool = False, **_ignored):
        try:
            from openai import OpenAI
        except ImportError as e:  # pragma: no cover
            raise ImportError("openai not installed. pip install 'vecshield[openai]'") from e
        if not api_key:
            raise ValueError("openai requires api_key")
        self._c = OpenAI(api_key=api_key)
        self._endpoint = "openai://vector_stores"
        # Files whose content could not be read during iter_chunks(); see
        # read_errors(). Surfaced by the scan engine as a coverage finding so a
        # failed read never masquerades as a clean (empty) file.
        self._read_errors: list[dict] = []
        # F6: removing a file from a vector store erases what that store
        # retrieves. Deleting the underlying File object as well also removes
        # it from every other assistant and vector store that uses it, so it
        # happens only when the store's config opts in.
        self.delete_file_objects = _flag(delete_file_objects)
        self._file_deletions: dict[str, int] = {"attempted": 0, "deleted": 0, "failed": 0}

    def capabilities(self) -> set[str]:
        return {"delete"}  # managed: no raw vectors, but files can be deleted

    def _read(self, fn: Callable[[], _T]) -> _T:
        """An idempotent read, with SDK errors mapped and transient ones retried."""
        return retry_read(mapped_call(fn, kind=self.kind, extra=_ERRORS))

    def _paged(self, fetch: Callable[[Optional[str]], Any]) -> Iterator[Any]:
        """Every item of a cursor-paged list, one retried request per page."""
        after: Optional[str] = None
        while True:
            page = self._read(lambda: fetch(after))
            if isinstance(page, list):  # an already-materialised list
                yield from page
                return
            items = list(_attr(page, "data", None) or [])
            yield from items
            if not items or _attr(page, "has_more", None) is not True:
                return
            after = _attr(items[-1], "id")
            if not after:
                return

    def describe(self) -> VectorStore:
        return VectorStore(kind=self.kind, name=self._endpoint, endpoint=self._endpoint,
                           collections=self.list_collections(),
                           metadata={"managed": True, "vectors_exposed": False})

    def list_collections(self) -> list[Collection]:
        out = []
        stores = self._c.vector_stores
        for vs in self._paged(lambda after: stores.list(**_page_args(after))):
            vid = _attr(vs, "id")
            name = _attr(vs, "name") or vid
            counts = _attr(vs, "file_counts")
            total = _attr(counts, "total") if counts else None
            metadata: dict[str, Any] = {"vector_store_id": vid}
            if total is None:
                metadata["count_known"] = False
            out.append(Collection(name=f"{name} ({vid})", count=int(total or 0),
                                  dimension=None, metadata=metadata))
        return out

    def iter_chunks(self, collection: str, batch_size: int = 100) -> Iterator[Chunk]:
        vid = _vector_store_id(collection)
        files = self._c.vector_stores.files
        for f in self._paged(lambda after: files.list(vector_store_id=vid,
                                                      **_page_args(after))):
            fid = str(_attr(f, "id"))
            status = _attr(f, "status")
            meta = {"status": status,
                    "usage_bytes": _attr(f, "usage_bytes"),
                    "attributes": _attr(f, "attributes", {}),
                    # When the file was added to this store, for retention.
                    "created_at": _attr(f, "created_at")}
            if status != "completed":
                self._record_read_error(
                    collection, file_id=fid, vector_store_id=vid, operation="iter_chunks",
                    error_type="FileNotCompleted", file_status=status,
                    reason=f"The file's status is {status!s}, not completed, so its "
                           "content was not read.")
                yield _unreadable(fid, collection, meta)
                continue
            text, read_ok = self._file_text(collection, vid, fid)
            if not read_ok:
                yield _unreadable(fid, collection, meta)
                continue
            pieces = split_text(text or "", _PIECE_CHARS)
            if not pieces:
                self._record_read_error(
                    collection, file_id=fid, vector_store_id=vid, operation="iter_chunks",
                    error_type="EmptyContent",
                    reason="The file returned no text, so nothing in it was classified.")
                yield _unreadable(fid, collection, meta)
                continue
            if len(pieces) == 1:
                yield Chunk(id=fid, collection=collection, text=pieces[0],
                            embedding=None, metadata=meta)
                continue
            for n, piece in enumerate(pieces):
                yield Chunk(id=f"{fid}#{n}", collection=collection, text=piece,
                            embedding=None,
                            metadata={**meta, "piece": n, "pieces": len(pieces)})

    def _file_text(self, collection: str, vid: str, fid: str) -> tuple[Optional[str], bool]:
        """Return (text, read_ok). On failure records the error and returns (None, False).

        The error entry names the exception type only: SDK messages can echo
        request details.
        """
        files = self._c.vector_stores.files
        try:
            parts = self._read(lambda: list(files.content(vector_store_id=vid, file_id=fid)))
        except ConnectorAuthError:
            raise  # the credential fails for every file alike
        except Exception as exc:  # noqa: BLE001 - recorded, never read as clean
            self._record_read_error(
                collection, file_id=fid, vector_store_id=vid, operation="file_content",
                error_type=type(exc).__name__,
                reason="The file's content could not be retrieved.")
            return (None, False)
        texts = [(_attr(p, "text") or "") for p in parts]
        return ("\n".join(t for t in texts if t), True)

    def delete_chunks(self, collection: str, ids: list[str]) -> int:
        """Remove files from the vector store; optionally delete the File objects.

        Removing a file from the vector store is what erases the subject's
        retrievable content from this store. Piece ids (``<file id>#<n>``)
        map back to their file, and each file is removed once. The count is
        the requested ids whose file was removed, so a file split into three
        pieces counts three. The underlying File object is deleted only when
        ``delete_file_objects`` is set in the store's config, because it may be
        shared with other assistants and vector stores (F6); :meth:`erasure_notes`
        says which happened. If any vector-store removal fails we raise so the
        erasure workflow records an error instead of reporting a false success.
        """
        vid = _vector_store_id(collection)
        file_ids = list(dict.fromkeys(file_id_of(i) for i in ids))
        removed: set[str] = set()
        failures: list[str] = []
        for fid in file_ids:
            try:
                with mapped_errors(self.kind, _ERRORS):
                    self._c.vector_stores.files.delete(vector_store_id=vid, file_id=fid)
            except Exception as exc:  # noqa: BLE001 - collected and raised below
                failures.append(f"{fid}: {type(exc).__name__}")
                continue
            removed.add(fid)
            if self.delete_file_objects:
                # Opted in: best-effort, and counted so the receipt can say so.
                self._file_deletions["attempted"] += 1
                try:
                    self._c.files.delete(fid)
                    self._file_deletions["deleted"] += 1
                except Exception:  # noqa: BLE001 - the store removal already landed
                    self._file_deletions["failed"] += 1
        deleted = sum(1 for i in ids if file_id_of(i) in removed)
        if failures:
            raise RuntimeError(
                f"failed to remove {len(failures)}/{len(file_ids)} file(s) from vector "
                f"store {vid} (deleted {deleted}): " + "; ".join(failures[:5])
            )
        return deleted

    def erasure_notes(self) -> dict:
        """What erasure did beyond removing files from the vector store."""
        counts = dict(self._file_deletions)
        if self.delete_file_objects:
            statement = (f"File objects: {counts['deleted']} of {counts['attempted']} "
                         "underlying OpenAI File object(s) were also deleted "
                         "(delete_file_objects is on)"
                         + (f"; {counts['failed']} could not be deleted and remain "
                            "in the project." if counts["failed"] else "."))
        else:
            statement = ("File objects: not deleted. Files were removed from this "
                         "vector store only; the underlying OpenAI File objects remain "
                         "in the project and may still be used by other assistants or "
                         "vector stores (set delete_file_objects to delete them).")
        limitation = (statement if not self.delete_file_objects or counts["failed"]
                      else None)
        return {"file_objects_deleted": self.delete_file_objects and counts["deleted"] > 0,
                "delete_file_objects": self.delete_file_objects,
                "file_object_deletions": counts,
                "statement": statement,
                "limitation": limitation}


def split_text(text: str, limit: int) -> list[str]:
    """``text`` in pieces of at most ``limit`` characters, blank pieces dropped.

    Each cut falls on the last paragraph break, else line break, else
    whitespace in the second half of the window, so a value is rarely split
    across two pieces; a run with no whitespace at all is cut at the limit.
    """
    if limit < 2:
        raise ValueError("limit must be at least 2")
    pieces: list[str] = []
    rest = text
    floor = limit // 2
    while len(rest) > limit:
        window = rest[:limit]
        cut = window.rfind("\n\n")
        if cut < floor:
            cut = window.rfind("\n")
        if cut < floor:
            cut = max(window.rfind(" "), window.rfind("\t"), window.rfind("\r"))
        if cut < floor:
            cut = limit
        pieces.append(rest[:cut])
        rest = rest[cut:]
    pieces.append(rest)
    return [p for p in pieces if p.strip()]


def file_id_of(chunk_id: str) -> str:
    """The file a chunk id belongs to: ``file-abc#2`` -> ``file-abc``."""
    return _PIECE_SUFFIX.sub("", str(chunk_id))


def _vector_store_id(collection: str) -> str:
    """``"name (vs_123)"`` -> ``vs_123``; a bare id is returned as is."""
    return collection.split("(")[-1].rstrip(")").strip() if "(" in collection else collection


def _page_args(after: Optional[str]) -> dict[str, Any]:
    args: dict[str, Any] = {"limit": _LIST_LIMIT}
    if after:
        args["after"] = after
    return args


def _unreadable(fid: str, collection: str, meta: dict) -> Chunk:
    return Chunk(id=fid, collection=collection, text=None, embedding=None,
                 metadata={**meta, "content_unreadable": True})


def _flag(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _attr(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)
