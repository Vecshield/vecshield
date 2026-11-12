"""Remediation catalogue for the store-control and integrity finding kinds."""

from __future__ import annotations

from vecshield_platform import remediation as rem


def _finding(category, title="t", severity="medium", evidence=None, remediation="",
             collection="docs"):
    return {"id": f"f-{category}", "category": category, "title": title,
            "severity": severity, "collection": collection, "store": "s",
            "evidence": evidence or {}, "remediation": remediation}


def test_each_new_category_is_its_own_kind_with_a_rescan_check():
    for category in ("retention_schedule", "biometric_templates", "model_egress",
                     "data_residency", "server_vulnerability", "server_support_status",
                     "corpus_duplication", "retrieval_hubness", "ingestion_burst",
                     "chunk_versions"):
        assert rem.finding_kind(_finding(category)) == category
        _, check, subcheck = rem.KINDS[category]
        assert check in rem.RESCANNABLE and subcheck == category


def test_server_vulnerability_guidance_uses_the_advisory_fix_and_workaround():
    finding = _finding("server_vulnerability", severity="critical", collection=None,
                       remediation="Upgrade Milvus from 2.5.12 to 2.5.21.",
                       evidence={"advisory_id": "CVE-2025-64513", "product": "milvus",
                                 "running_version": "2.5.12", "same_line_fix": "2.5.21",
                                 "recommended_upgrade": {"version": "2.5.27",
                                                         "reason": "clears all"},
                                 "workaround": {"text": "Strip the sourceID header.",
                                                "source_url": "https://example.org/a"}})
    guided = rem.catalogue(finding, store_id="s", store_kind="milvus").guided[0]
    assert guided.title == "Upgrade milvus to 2.5.21"
    assert guided.steps[0] == "Upgrade Milvus from 2.5.12 to 2.5.21."
    assert any("sourceID header" in step and "example.org" in step for step in guided.steps)
    assert guided.check == "configuration_posture"


def test_no_known_workaround_is_not_offered_as_a_mitigation():
    finding = _finding("server_vulnerability", evidence={
        "advisory_id": "X", "workaround": {"text": "There are no known workarounds.",
                                           "none_known": True}})
    steps = rem.catalogue(finding, store_id="s").guided[0].steps
    assert not any("Until you can upgrade" in s for s in steps)


def test_statistical_integrity_findings_offer_review_then_quarantine():
    finding = _finding("retrieval_hubness", title="Retrieval hubs in 'docs'",
                       evidence={"examples": [{"chunk_id": "a"}, {"chunk_id": "b"}]})
    cat = rem.catalogue(finding, store_id="s")
    assert [s.action for s in cat.suggestions] == ["tag_review", "quarantine_chunks"]
    assert cat.suggestions[0].params == {"reason": "anomalous_embedding"}
    info = dict(finding, severity="info")
    assert rem.catalogue(info, store_id="s").suggestions == []


def test_retention_offers_quarantine_and_leaves_delete_to_the_organisation():
    finding = _finding("retention_schedule", evidence={
        "over_max": 4, "rules": [{"over_max": 4, "category": "PII", "max_age_days": 30,
                                  "examples": ["a", "b"]}]})
    cat = rem.catalogue(finding, store_id="s")
    assert [s.action for s in cat.suggestions] == ["quarantine_chunks"]
    guided = cat.guided[0]
    assert "legal hold" in guided.not_executable_because
    assert any("Delete them yourself" in step for step in guided.steps)


def test_plain_duplicates_and_conflicts_are_not_moved_automatically():
    dup = _finding("corpus_duplication", title="Duplicated chunk text in 'docs'",
                   evidence={"examples": [{"chunk_id": "a", "chunk_ids": ["a", "b"]}]})
    cat = rem.catalogue(dup, store_id="s")
    assert cat.suggestions == [] and cat.withheld and cat.guided
    conflict = _finding("chunk_versions",
                        title="Conflicting chunks at the same document position in 'docs'",
                        evidence={"examples": [{"chunk_id": "a", "chunk_ids": ["a", "b"]}]})
    assert rem.catalogue(conflict, store_id="s").suggestions == []


def test_superseded_versions_quarantine_the_named_old_generation():
    finding = _finding("chunk_versions",
                       title="Superseded document versions still stored in 'docs'",
                       evidence={"superseded_chunks": 3,
                                 "examples": [{"source": "d", "superseded_ids": ["o1", "o2"]}]})
    cat = rem.catalogue(finding, store_id="s")
    assert [s.action for s in cat.suggestions] == ["quarantine_chunks"]
    assert cat.suggestions[0].chunk_ids == ("o1", "o2")


def test_rescan_passes_the_declared_controls_to_the_check(monkeypatch):
    seen = {}

    def capture(check, connector, **kwargs):
        seen.update(kwargs)
        raise RuntimeError("stop")

    monkeypatch.setattr(rem, "_run", capture)
    finding = _finding("data_residency", collection=None)
    result = rem.rescan(finding, object(), controls={"residency_policy": {"a": 1}})
    assert seen["controls"] == {"residency_policy": {"a": 1}}
    assert result.outcome == "inconclusive"
