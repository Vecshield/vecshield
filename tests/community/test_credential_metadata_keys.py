"""Credential-named metadata keys give the scan the context a bare secret lacks."""

from __future__ import annotations

from vecshield.classify import RegexClassifier
from vecshield.classify.surfaces import _sensitive_key, chunk_text_surfaces, classify_chunk
from vecshield.models import Chunk


def test_credential_keys_are_matched_on_whole_tokens():
    for key in ("password", "api_key", "apiKey", "clientSecret", "auth.token",
                "access_token", "private_key", "db-passwd", "credentials"):
        assert _sensitive_key(key), key
    for key in ("max_tokens", "author", "keywords", "title", "monkey"):
        assert not _sensitive_key(key), key


def test_a_password_in_metadata_is_classified_through_its_key():
    chunk = Chunk(id="c1", collection="docs", text="Service config.",
                  metadata={"password": "S3cr3tPassw0rdXyz"})
    names = [s.name for s in chunk_text_surfaces(chunk)]
    assert "metadata_key.password" in names

    result = classify_chunk(RegexClassifier(), chunk)
    assert any(span.get("detector") == "generic_secret_context"
               and span.get("surface") == "metadata_key.password"
               for span in result.spans), result.spans
