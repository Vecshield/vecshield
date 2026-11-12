import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// Compliance, Operations, Estate and System on the shared patterns (phase 12
// of the console overhaul):
//
// - a screen's scope (the store) sits in its page header; its filters are a
//   labelled search toolbar over the list they narrow;
// - records that swap in place are an ARIA tab list, every tab tabbable;
// - long explanations and settings fold away, closed, under a summary that
//   still says what they hold;
// - a screen has at most one primary action, in its header;
// - identifiers a reader sees (job kinds, rule ids, policy actions) are named
//   in words, with the id kept beside them for configuration.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

const ISO = "2026-09-20T10:00:00+00:00";

const PACK = {
  pack: {pack_version: "d1", criteria: 1, lifecycle: "draft", frameworks: ["GDPR"]},
  criteria: [{criterion_id: "GDPR-A", framework: "GDPR", title: "Erasure reaches embeddings",
              paraphrase: "An erasure request reaches personal data held in embeddings.",
              sources: [{id: "s1", section: "Art. 17", kind: "regulation"}],
              technical_checks: [], manual_evidence: [], applicability_questions: []}],
};

const BASE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant", tenant_field: "tenant_id"}]},
  "/admin/policies": {policies: [{id: "p1", name: "PII in a collection", description: "Tag it.", enabled: true,
                                  severity: "high", action: "tag_pii_and_enforce_erasure_path",
                                  scope_store: "prod"}]},
  "/admin/policy-templates": {templates: []},
  "/version": {approvals: {separation_of_duties: "required"}, detectors: ["bulk_volume", "custom_rule"],
               version: "0.0.1", detection_version: "0.0.1"},
  "/readyz": {status: "ready", checks: {registry: "ok"}},
  "/admin/detection": {status: "ready"},
  "/healthz": {status: "ok", stores: 1},
  "/compliance/criteria": PACK,
  "/compliance/evidence": {artifacts: [
    {id: "ev-1", title: "Erasure procedure", state: "available", usable: true, scope: "prod", content_hash: "ab"},
    {id: "ev-0", title: "Old procedure", state: "superseded", usable: false, scope: "prod"}]},
  "/compliance/reviews": {reviews: [{id: "rev-1", artifact_id: "ev-1", criterion_id: "GDPR-A",
                                     requirement: "erasure_procedure", state: "submitted", accepted: false}]},
  "/compliance/exceptions": {exceptions: [
    {id: "x1", criterion_id: "GDPR-A", scope: "prod", status: "pending_approval", requested_by: "dpo@example.test",
     expires_at: ISO, rationale: "Legal hold."}], pending_approval: 1, active: 0, expired: 0},
  "/runtime/alerts/stats": {total: 1, by_severity: {high: 1}},
  "/runtime/alerts": {alerts: [{severity: "high", rule: "bulk_volume", principal: "svc", collection: "docs",
                                message: "150 queries in 60s"}]},
  "/stores/prod/schema": {kind: "qdrant", collection_count: 1, total_vectors: 20, metadata_fields: [],
                          capabilities: ["query"],
                          collections: [{name: "docs", count: 20, metadata_key_count: 0, metadata_fields: []}]},
  "/admin/findings": {findings: []},
};

async function boot(hash, extra = {}) {
  const data = {...BASE, ...extra};
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="light"><head><style>${css}</style></head>` +
    `<body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  window.fetch = async (path) => {
    const value = data[path] ?? data[path.split("?")[0]] ?? {};
    return {ok: true, status: 200, headers: {get: () => "application/json"},
            json: async () => value, text: async () => JSON.stringify(value)};
  };
  window.eval(shell);
  window.eval("buildShell()");
  await window.eval("route()");
  await new Promise(r => setTimeout(r, 30));
  return {dom, window, doc: window.document, run: code => window.eval(code)};
}

const words = node => node.textContent.replace(/\s+/g, " ").trim();
const buttonsIn = (root, text) => [...root.querySelectorAll("button")].filter(b => words(b) === text);

// ------------------------------------------------------------- Compliance ---

test("criteria: the store is the header's scope, and the explainer is folded into About", async () => {
  const {dom, doc} = await boot("#/criteria");
  const head = doc.querySelector("#content .page-head");
  assert.ok(head.querySelector('.page-head-actions select[aria-label="Store"]'), "the store picker is in the header");
  const tools = doc.querySelector(".crit-tools");
  assert.equal(tools.getAttribute("role"), "search");
  assert.equal(tools.querySelector('[aria-label="Store"]'), null, "the toolbar keeps only the filters");
  assert.ok(tools.querySelector('[aria-label="Framework"]') && tools.querySelector('[aria-label="Status"]'));
  const about = doc.querySelector("details.about");
  assert.equal(about.open, false);
  assert.ok(about.querySelector(".crit-explain"), "how a criterion is judged sits inside About");
  assert.match(words(about), /How a criterion is judged/);
  assert.equal(doc.querySelectorAll("#content .crit-explain").length, 1, "and nowhere else");
  dom.window.close();
});

test("evidence: documents, reviews and what to supply are tabs, every one tabbable", async () => {
  const {dom, window, doc} = await boot("#/evidence");
  const list = doc.querySelector('#content [role="tablist"]');
  assert.ok(list.classList.contains("ev-tabs"));
  const tabs = [...list.querySelectorAll('[role="tab"]')];
  assert.deepEqual(tabs.map(words), ["Documents (2)", "Reviews (1)", "What to supply"]);
  assert.ok(tabs.every(t => !t.hasAttribute("tabindex")), "a page's tabs stay in the Tab order");
  assert.equal(doc.querySelector('#content [aria-pressed]'), null, "no longer a toggle group");
  const panel = doc.getElementById(tabs[0].getAttribute("aria-controls"));
  assert.equal(panel.getAttribute("role"), "tabpanel");
  assert.equal(panel.getAttribute("aria-labelledby"), tabs[0].id);
  const shown = () => [...panel.querySelectorAll(".ev-panel")].filter(p => !p.hidden).map(p => p.dataset.tab);
  assert.deepEqual(shown(), ["artifacts"]);
  tabs[1].click();
  assert.deepEqual(shown(), ["reviews"]);
  assert.equal(tabs[1].getAttribute("aria-selected"), "true");
  assert.match(window.location.hash, /tab=reviews/);
  list.dispatchEvent(new window.KeyboardEvent("keydown", {key: "ArrowRight", bubbles: true}));
  assert.deepEqual(shown(), ["supply"]);
  dom.window.close();
});

test("evidence: a replaced document's state chip is whole, and may wrap rather than clip", async () => {
  const {dom, doc} = await boot("#/evidence");
  const row = doc.querySelector('.ev-row[data-artifact="ev-0"]');
  assert.match(words(row.querySelector(".ev-row-state")), /Replaced by a newer version/);
  assert.match(css, /\.evidence-page \.ev-row-state \.badge \{ max-width: 100%; white-space: normal; \}/);
  dom.window.close();
});

test("exceptions: the approval form row spans the card and takes no column name", async () => {
  const {dom, doc} = await boot("#/exceptions");
  const table = doc.querySelector("table.exc-table");
  assert.ok(table.closest(".table-wrap"), "the shared table frame");
  const row = table.querySelector('tr[data-exception="x1"]');
  assert.deepEqual([...row.children].slice(0, 2).map(td => td.dataset.label), ["Criterion", "Store"]);
  const form = table.querySelector("tr.exc-approve-row td");
  assert.equal(form.getAttribute("colspan"), "6");
  assert.equal(form.hasAttribute("data-label"), false);
  dom.window.close();
});

test("policies: filters are a search toolbar, and an action reads in words with its id kept", async () => {
  const {dom, doc} = await boot("#/policies");
  const tools = doc.querySelector('#content [role="search"][aria-label="Filter policies"]');
  assert.ok(tools && tools.querySelector(".result-count[role=status]"));
  const cell = doc.querySelector("table.policies-table tbody tr").children[4];
  assert.match(words(cell), /^Tag pii and enforce erasure path/);
  assert.equal(cell.querySelector(".mono").textContent, "tag_pii_and_enforce_erasure_path");
  dom.window.close();
});

test("templates: filters are a search toolbar, not a panel of their own", async () => {
  const {dom, doc} = await boot("#/templates");
  assert.ok(doc.querySelector('#content [role="search"][aria-label="Filter templates"]'));
  assert.ok(![...doc.querySelectorAll("#content .panel-heading")].some(n => words(n) === "Template filters"));
  dom.window.close();
});

// ------------------------------------------------------------- Operations ---

test("runtime: Send test event is the header's one primary, and filters are a search toolbar", async () => {
  const {dom, doc} = await boot("#/runtime");
  const primaries = [...doc.querySelectorAll("#content .btn.primary")];
  assert.equal(primaries.length, 1);
  assert.equal(words(primaries[0]), "Send test event");
  assert.ok(primaries[0].closest(".page-head"));
  const tools = doc.querySelector('#content [role="search"][aria-label="Filter alerts"]');
  assert.ok(tools.querySelector('select[aria-label="Severity"]'));
  assert.match(words(tools), /1 alert shown/);
  const rule = doc.querySelector("#content tbody tr").children[1];
  assert.match(words(rule), /^Bulk querying bulk_volume$/, "the detector's name, with its id");
  dom.window.close();
});

test("runtime: alerts that cannot be read are an error with a retry, not an empty list", async () => {
  const {dom, window, doc} = await boot("#/runtime");
  window.fetch = async () => { throw new Error("offline"); };
  buttonsIn(doc.getElementById("content"), "Refresh")[0].click();
  await new Promise(r => setTimeout(r, 30));
  assert.ok(doc.querySelector("#content .state-error"));
  assert.ok(doc.querySelector('#content [role="search"]'), "the filters stay, so the reader can retry");
  assert.doesNotMatch(words(doc.getElementById("content")), /No alerts have been recorded/);
  dom.window.close();
});

test("ingest: settings fold away under their current values; the caveat sits with the result", async () => {
  const {dom, window, doc} = await boot("#/ingest");
  const fold = doc.querySelector("details.ingest-settings-fold");
  assert.equal(fold.open, false);
  assert.match(words(fold.querySelector("summary")), /Settings · Blocks at High or above · soft caller/);
  assert.ok(fold.querySelector("#ingest-severity"), "the fields are inside it");
  const head = doc.querySelector("#content .page-head");
  assert.equal(head.nextElementSibling.classList.contains("note"), false, "no caveat between header and tabs");
  assert.match(words(doc.querySelector(".ingest-result-panel")), /do not write to a vector store/);
  doc.getElementById("ingest-tab-redact").click();
  assert.match(words(fold.querySelector("summary")), /Shows the redacted text/);
  doc.getElementById("ingest-tab-boundaries").click();
  const zone = doc.getElementById("ingest-zone");
  zone.value = "0";
  zone.dispatchEvent(new window.Event("input", {bubbles: true}));
  doc.querySelector("form.ingest-input").dispatchEvent(new window.Event("submit", {cancelable: true}));
  assert.equal(fold.open, true, "a problem in the folded settings opens them");
  dom.window.close();
});

// ----------------------------------------------------------------- Estate ---

test("schema: the store is the header's scope; capabilities are a line, not a stretched tile", async () => {
  const {dom, doc} = await boot("#/schema?store=prod");
  assert.ok(doc.querySelector("#content .page-head-actions select"));
  assert.equal(doc.querySelectorAll("#content .page-head .btn.primary").length, 0, "refresh is not primary");
  assert.match(words(doc.querySelector(".schema-caps")), /Capabilities query/);
  assert.ok(![...doc.querySelectorAll(".metric-k")].some(k => words(k) === "Capabilities"));
  dom.window.close();
});

test("a store's collections open their own page", async () => {
  const {dom, window, doc} = await boot("#/stores?store=prod");
  const link = [...doc.querySelectorAll("#content tbody td.mono button")].find(b => words(b) === "docs");
  link.click();
  assert.equal(window.location.hash, "#/schema?store=prod&collection=docs");
  dom.window.close();
});

// ----------------------------------------------------------------- System ---

test("status: runtime detectors by name, with the id one hover away", async () => {
  const {dom, doc} = await boot("#/status");
  const tags = [...doc.querySelectorAll("#content .tag")].filter(t => /Bulk|custom/.test(words(t)));
  assert.deepEqual(tags.map(words), ["Bulk querying", "custom_rule"]);
  assert.equal(tags[0].getAttribute("title"), "bulk_volume");
  dom.window.close();
});

// ---------------------------------------------------------------- Helpers ---

test("a job kind the console has no name for is still read in words", async () => {
  const {dom, run} = await boot("#/status");
  assert.equal(run(`runLabel({kind: "scan_classification", resource: "prod"})`), "Classification scan — prod");
  assert.equal(run(`runLabel({kind: "erasure_plan", resource: "prod"})`), "Erasure plan — prod");
  assert.equal(run(`runLabel({kind: "brand_new_kind", resource: "prod"})`), "Brand new kind — prod");
  dom.window.close();
});

test("a table cell that spans columns takes no column name", async () => {
  const {dom, run} = await boot("#/status");
  const wrap = run(`table(["A", "B"], [h("tr", {}, h("td", {}, "1"), h("td", {}, "2")),
                                     h("tr", {}, h("td", {colspan: "2"}, "form"))])`);
  const cells = [...wrap.querySelectorAll("tbody td")];
  assert.deepEqual(cells.map(td => td.getAttribute("data-label")), ["A", "B", null]);
  const region = run(`table(["A"], [], {wrapClass: "scroller", wrapAttrs: {role: "region", tabindex: "0",
                                                                         "aria-label": "Wide"}})`);
  assert.equal(region.className, "scroller");
  assert.equal(region.getAttribute("role"), "region");
  assert.equal(region.getAttribute("tabindex"), "0");
  dom.window.close();
});
