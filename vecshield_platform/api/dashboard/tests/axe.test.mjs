import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import axe from "axe-core";
import { JSDOM } from "jsdom";

// Accessibility audit in a real DOM implementation.
//
// What this covers: the structural rules — roles, names, labels, landmarks,
// heading order, list and table semantics, duplicate ids, ARIA validity.
//
// What it does NOT cover, and why: jsdom does no layout and no painting, so
// axe's colour-contrast and target-size rules cannot run here. Those are
// covered instead by tests/contrast.test.mjs (token pairs, both themes) and by
// CSS rules asserted in review. A browser-based audit would still add value
// for focus visibility and reflow; this is the part that runs on every commit.

const source = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

// Rules that need rendering. Disabled with a reason rather than silently.
const LAYOUT_DEPENDENT = {
  "color-contrast": "needs painting; covered by tests/contrast.test.mjs",
  "target-size": "needs layout; enforced in CSS",
  "scrollable-region-focusable": "needs layout",
};

const RESPONSES = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant", tenant_field: "tenant_id"}]},
  "/admin/policies": {policies: [{id: "p1", name: "Secrets", severity: "critical",
                                  when: {}, action: "purge", enabled: true}]},
  "/admin/policy-templates": {templates: []},
  "/admin/history": {jobs: [], stats: {total_findings: 2, by_severity: {high: 2}}},
  "/admin/history/trend?days=30": {trend: [], available: true},
  "/admin/history/audits": {audits: []},
  "/admin/estate": {stores: [{store_id: "prod", kind: "qdrant", last_assessed: null,
                              coverage: null, findings: {}, findings_total: 0,
                              history_available: true, probe: {probed: false}}],
                    probed: false, note: "note"},
  "/admin/findings": {findings: [{id: "f1", title: "PII", severity: "high",
                                  category: "data_classification", store: "prod",
                                  collection: "docs", suppressed: false,
                                  case: {state: "new", owner: null}}],
                      total: 1, limit: 50, offset: 0, has_more: false,
                      facets: {case_state: {new: 1}}},
  "/admin/jobs": {jobs: []},
  "/admin/allowlist": {rules: []},
  "/admin/suppressions": {suppressions: []},
  "/admin/detectors": {bulk_volume: {}, collection_sweep: {}, enumeration: {},
                       rate_baseline: {}, cooldown_s: 60},
  "/admin/alerting": {webhooks: [], min_severity: "high"},
  "/admin/dsar": {requests: []},
  "/compliance/criteria": {pack: {pack_version: "d1", criteria: 1, lifecycle: "draft",
                                  regulatory_review: null, note: "n"},
                           criteria: [{criterion_id: "C-1", framework: "HIPAA",
                                       paraphrase: "Access is limited.",
                                       sources: [{section: "45 CFR 164.312"}],
                                       manual_evidence: ["access_review_record"],
                                       limitations: [], applicability_questions: []}]},
  "/compliance/crypto-basis": {basis: [
    {framework: "HIPAA", relationship: "addressable", relationship_label: "Addressable",
     at_rest: "Explicit, but addressable", in_transit: "Explicit, but addressable",
     interpretation: "Encrypt if reasonable", applicability: "Covered entities",
     criteria: ["C-1"]}]},
  "/stores/prod/crypto-posture": {
    store_id: "prod", audit_id: "a1", assessed_at: "2026-09-20T10:00:00Z", pack_version: "d3",
    layers: [
      {layer: "transport", title: "Transport", rows: [
        {check: "transport_encryption", control: "VCR-01", label: "TLS on VecShield's connection",
         collection: null, outcome: "passed", crypto_state: "verified", reason: "TLSv1.3",
         details: {protocol: "TLSv1.3", encrypted: true}}]},
      {layer: "storage", title: "Storage encryption", rows: [
        {check: "at_rest_encryption", control: "VCR-11/13", label: "Encryption at rest",
         collection: null, outcome: "unsupported", crypto_state: "not_observable",
         reason: "Not exposed.", details: {}}]},
      {layer: "data", title: "Field and data-level protection", rows: [
        {check: "pan_representation", control: "VCR-06", label: "PAN storage representation",
         collection: "payments", outcome: "failed", crypto_state: "observed_exposure",
         reason: "Full PAN stored.", details: {counts: {full: 1}, examples: ["masked"]}}]},
    ],
    coverage: {collections_total: 2, at_rest: {verified_encrypted: 0, verified_unencrypted: 0, unknown: 2}},
    out_of_scope: [{property: "Infrastructure disk / volume encryption", state: "not_observable", reason: "r"}],
    statements: ["Embeddings are not treated as cryptographic protection."],
    drift: {previous_audit_id: "a0", compared: true, changes: [
      {check: "at_rest_encryption", label: "Encryption at rest", collection: null, change: "changed",
       before: {outcome: "passed", crypto_state: "verified"},
       after: {outcome: "unsupported", crypto_state: "not_observable"}}]},
    regulatory: [
      {framework: "HIPAA", relationship: "addressable", relationship_label: "Addressable",
       interpretation: "i", criteria: [{criterion_id: "C-1", technical_result: "not_run",
         technical_coverage: "unknown", fallback_required: ["encryption_at_rest_statement"]}]},
      {framework: "EU AI Act", relationship: "supporting", relationship_label: "Supporting evidence only",
       interpretation: "i", criteria: []}],
    note: "No crypto score."},
  "/stores/prod/crypto-gate": {
    store_id: "prod", audit_id: "a1", decision: "block", labels: ["pci"],
    settings: {requires_at_rest_encryption: false},
    rules: [
      {id: "full-pan-readable", description: "Full PAN readable.", decision: "block", status: "fired",
       reasons: ["payments: 1 full PAN"], cleared_by: [], evidence_that_clears: [],
       remediation: "Tokenise.", basis: "PCI DSS 3.5.1"},
      {id: "phi-at-rest-unverified", description: "PHI, at rest unverified.", decision: "request_evidence",
       status: "cleared", reasons: ["r"], cleared_by: [{criterion_id: "C-1", requirement: "encryption_at_rest_statement"}],
       evidence_that_clears: [{criterion_id: "C-1", requirement: "encryption_at_rest_statement"}],
       remediation: "r", basis: "b"},
      {id: "quiet", description: "q", decision: "warn", status: "not_triggered", reasons: [],
       cleared_by: [], evidence_that_clears: [], remediation: "", basis: ""}],
    evidence_needed: [], note: "Enforces nothing itself."},
  "/compliance/crypto-gate/rules": {decisions: ["block", "request_evidence", "warn", "pass"], rules: [
    {id: "full-pan-readable", description: "Full PAN readable.", decision: "block", when: "full PAN",
     evidence_that_clears: [], remediation: "Tokenise.", basis: "PCI DSS 3.5.1"}]},
  "/compliance/evidence": {artifacts: [], note: "n"},
  "/compliance/reviews": {reviews: []},
  "/compliance/exceptions": {exceptions: [], pending_approval: 0, active: 0, expired: 0, note: "n"},
  "/runtime/alerts": {alerts: []},
  "/runtime/alerts/stats": {total: 0},
  "/audit-log": {entries: [], verified: true},
  "/version": {version: "1", detection_version: "1", detectors: ["bulk_volume"]},
  "/healthz": {status: "ok"},
  "/readyz": {status: "ok", checks: {}},
  "/stores": {stores: []},
};

function respond(path) {
  const base = path.split("?")[0];
  const exact = RESPONSES[path] ?? RESPONSES[base];
  if (exact !== undefined) return exact;
  if (base.startsWith("/stores/")) return {findings: [], collections: [], schema: {}, stats: {}};
  if (base.startsWith("/admin/history/")) return {findings: [], jobs: [], audits: []};
  return {};
}

async function boot(hash = "#/overview") {
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="light"><head><style>${css}</style></head>` +
    `<body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});

  const {window} = dom;
  window.location.hash = hash;
  window.fetch = async path => ({
    ok: true, status: 200, headers: {get: () => "application/json"},
    json: async () => respond(path), text: async () => JSON.stringify(respond(path)),
  });
  window.eval(source);
  window.eval("buildShell()");
  await window.eval("route()");
  return dom;
}

async function auditDom(dom) {
  const results = await axe.run(dom.window.document.body, {
    rules: Object.fromEntries(Object.keys(LAYOUT_DEPENDENT).map(id => [id, {enabled: false}])),
    elementRef: false,
  });
  return results.violations.map(v =>
    `${v.id} (${v.impact}): ${v.help} — ${v.nodes.length} node(s), e.g. ${v.nodes[0]?.html?.slice(0, 120)}`);
}

const VIEWS = ["overview", "stores", "schema", "crypto", "assess", "history", "jobs", "findings",
               "frameworks", "criteria", "evidence", "exceptions", "dsar", "policies",
               "templates", "falsepositives", "runtime", "detectors", "alerting",
               "ingest", "audit", "status", "users", "docs"];

for (const view of VIEWS) {
  test(`${view} has no structural accessibility violations`, async () => {
    const dom = await boot(`#/${view}`);
    const violations = await auditDom(dom);
    dom.window.close();
    assert.deepEqual(violations, [], `\n  ${view}:\n  ${violations.join("\n  ")}\n`);
  });
}

test("an open dialog is accessible and named", async () => {
  const dom = await boot("#/overview");
  const {window} = dom;
  window.eval(`modal("Test dialog", h("div", {}, h("p", {}, "body")), () => {}, "Save")`);
  const violations = await auditDom(dom);
  const dialog = window.document.querySelector('[role="dialog"]');
  assert.ok(dialog, "the dialog is mounted");
  assert.equal(dialog.getAttribute("aria-modal"), "true");
  assert.ok(window.document.getElementById(dialog.getAttribute("aria-labelledby")),
            "aria-labelledby resolves");
  dom.window.close();
  assert.deepEqual(violations, [], `\n  dialog:\n  ${violations.join("\n  ")}\n`);
});

test("the layout-dependent rules are disabled deliberately, with a reason each", () => {
  for (const [rule, reason] of Object.entries(LAYOUT_DEPENDENT)) {
    assert.ok(reason.length > 10, `${rule} needs a stated reason for being skipped`);
  }
  // Guard against quietly widening the exemption list.
  assert.equal(Object.keys(LAYOUT_DEPENDENT).length, 3);
});

// ------------------------------------------------- density and responsive ---

test("every table cell carries its column name for the card layout", async () => {
  const dom = await boot("#/findings");
  const cells = [...dom.window.document.querySelectorAll(".table-wrap tbody td")];
  assert.ok(cells.length > 0, "the findings table rendered");
  const labelled = cells.filter(c => c.getAttribute("data-label"));
  assert.ok(labelled.length >= cells.length - 2,
            "all but the deliberately blank columns are labelled");
  assert.ok(labelled.some(c => c.getAttribute("data-label") === "Severity"));
  assert.ok(labelled.some(c => c.getAttribute("data-label") === "Case"));
  dom.window.close();
});

test("the theme control is reachable and named after a route change", async () => {
  const dom = await boot("#/stores");
  const button = dom.window.document.getElementById("theme-toggle");
  assert.match(button.getAttribute("aria-label"), /theme/i);
  const violations = await auditDom(dom);
  dom.window.close();
  assert.deepEqual(violations, []);
});
