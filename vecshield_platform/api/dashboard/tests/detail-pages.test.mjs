import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// Records as a level of their own (phase 8 of the console overhaul). A store,
// a saved audit, a scan, a personal data request, a plan, a fix and a store's
// questions each open at a query address under their screen. On one of them:
//
// - the chrome shows a breadcrumb trail, area › screen › record, whose last
//   step is the only aria-current="page" in it;
// - the page header has one link back to the list, above an h1 naming the
//   record;
// - the window title and the route's announcement name the record.
//
// On a list the trail is dropped: the area tabs already say where you are.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

const ISO = "2026-09-20T10:00:00+00:00";

const BASE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant", tenant_field: "tenant_id"},
                             {store_id: "cold", kind: "chroma"}]},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
  "/version": {approvals: {separation_of_duties: "required"}},
  "/healthz": {status: "ok", stores: 2},
  "/admin/history/audits": {audits: [], available: true},
  "/admin/history": {jobs: [], available: true},
  "/admin/history/audits/a1": {id: "a1", store_id: "prod", status: "succeeded", started_at: ISO, finished_at: ISO,
                               summary: {}, coverage: {status: "complete", complete: true}, jobs: [],
                               violations: [], check_outcomes: []},
  "/admin/history/s1": {id: "s1", store: "prod", kind: "audit", created_at: ISO, findings: []},
  "/admin/dsar": {dsars: []},
  "/admin/dsar/r1": {id: "r1", subject: "alice@example.com", status: "scanned", total_chunks_found: 0,
                     requested_at: ISO, stores: []},
  "/actions/plans/p1/diff": {status: 404, detail: "plan not found"},
  "/admin/findings/f1/remediation": {
    finding: {id: "f1", title: "PII in docs", severity: "high", collection: "docs"},
    store_id: "prod", store_registered: true, kind: "sensitive_data", kind_label: "Sensitive data",
    case: {state: "new"}, executable: [], guided: [], withheld: [], plans: [], rescans: [],
    safe_mode: {safe_mode: false, note: "Writes are permitted."}},
  "/stores/prod/schema": {kind: "qdrant", collection_count: 1, total_vectors: 20, metadata_fields: [],
                          collections: [{name: "docs", count: 20, metadata_key_count: 0, metadata_fields: []}]},
  "/admin/findings": {findings: []},
  "/compliance/criteria": {pack: {pack_version: "d1", criteria: 0, lifecycle: "draft", frameworks: []},
                           criteria: []},
};

async function boot(hash) {
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="light"><head><style>${css}</style></head>` +
    `<body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  window.fetch = async (path, opts = {}) => {
    const base = path.split("?")[0];
    const value = BASE[path] ?? BASE[base] ?? {};
    if (typeof value?.status === "number") {
      return {ok: false, status: value.status, statusText: "Error",
              headers: {get: () => "application/json"}, json: async () => ({detail: value.detail})};
    }
    return {ok: true, status: 200, headers: {get: () => "application/json"},
            json: async () => value, text: async () => JSON.stringify(value)};
  };
  window.eval(shell);
  window.eval("buildShell()");
  await window.eval("route()");
  await new Promise(r => setTimeout(r, 30));
  return {dom, window, doc: window.document};
}

const words = node => node.textContent.replace(/\s+/g, " ").trim();

// [address, screen label, breadcrumb, h1, back label, legacy back class, where back goes]
const RECORDS = [
  ["#/stores?store=prod", "Stores", "prod", "prod", "All stores", "store-back", "#/stores"],
  ["#/history?audit=a1&store=prod", "History", "Audit a1", "Audit a1", "All saved audits", "archive-back",
   "#/history?store=prod"],
  ["#/history?scan=s1&list=scans", "History", "Scan s1", "Scan s1", "All scans", "archive-back",
   "#/history?list=scans"],
  ["#/dsar?request=r1", "Personal data requests", "Request r1", "alice@example.com", "All requests", "archive-back",
   "#/dsar"],
  ["#/actions?plan=p1", "Actions", "Plan p1", "Plan p1", "Work queue", "remediation-back", "#/actions"],
  ["#/actions?fix=f1", "Actions", "Fix", "PII in docs", "Work queue", "remediation-back", "#/actions"],
  ["#/criteria?answers=1&store=prod&framework=HIPAA", "Criteria", "Questions", "Questions for prod",
   "Back to criteria", "remediation-back", "#/criteria?store=prod&framework=HIPAA"],
  // A collection is a record of its store (phase 12): named for itself, with
  // the way back to the store's collections above it.
  ["#/schema?store=prod&collection=docs", "Schema", "docs", "docs", "All collections in prod",
   "collection-back", "#/schema?store=prod"],
];

for (const [hash, screen, crumb, title, backLabel, legacy, parent] of RECORDS) {
  test(`${hash} is a record: a trail, a way back, and its own name`, async () => {
    const {dom, window, doc} = await boot(hash);
    const chrome = doc.getElementById("view-chrome");
    const trail = chrome.querySelector('nav.breadcrumbs[aria-label="Breadcrumb"]');
    assert.ok(trail, "the chrome shows the trail on a record");
    const steps = [...trail.querySelectorAll("li")].map(words);
    assert.equal(steps.length, 3);
    assert.deepEqual(steps.slice(1), [screen, crumb]);
    const current = chrome.querySelectorAll('[aria-current="page"]');
    assert.equal(current.length, 1, "one step of the chrome is the page");
    assert.equal(words(current[0]), crumb, "and it is the record");
    const tab = chrome.querySelector(".tab-active");
    if (tab) assert.equal(tab.getAttribute("aria-current"), "true", "the tab is the section, not the page");
    assert.equal(chrome.querySelector(".subviews"), null, "a screen's view switch is left to its list");

    const headings = doc.querySelectorAll("h1");
    assert.equal(headings.length, 1);
    const h1 = headings[0];
    assert.equal(h1.id, "page-title");
    assert.ok(h1.closest("#content .page-head"));
    assert.match(words(h1), new RegExp(title));
    assert.equal(doc.activeElement, h1, "the route lands focus on the record's name");
    assert.ok(doc.querySelectorAll(".page-head .btn.primary").length <= 1);

    const back = doc.querySelectorAll("#content .page-back");
    assert.equal(back.length, 1, "one way back");
    assert.equal(back[0].tagName, "BUTTON");
    assert.ok(back[0].classList.contains("link") && back[0].classList.contains(legacy));
    assert.equal(words(back[0]), backLabel);
    assert.ok(back[0].querySelector("svg.icon"), "the arrow is an icon, not text");
    assert.equal(back[0].nextElementSibling, h1, "the way back sits directly above the name");

    assert.equal(doc.title, `${crumb} — ${screen} — VecShield`);
    assert.equal(doc.getElementById("live-region").textContent, `${crumb} ready`);

    back[0].click();
    assert.equal(window.location.hash, parent);
    dom.window.close();
  });

  test(`${hash}: the trail's screen step goes back to the same list`, async () => {
    const {dom, window, doc} = await boot(hash);
    const steps = doc.querySelectorAll("#view-chrome .breadcrumbs li button");
    assert.equal(steps.length, 2, "area and screen are links; the record is not");
    steps[1].click();
    assert.equal(window.location.hash, parent);
    dom.window.close();
  });
}

test("a fix and a plan carry no queue switch; the lists do", async () => {
  for (const hash of ["#/actions?plan=p1", "#/actions?fix=f1"]) {
    const {dom, doc} = await boot(hash);
    const labels = [...doc.querySelectorAll("#content button")].map(words);
    assert.ok(!labels.includes("Approval queue"), `${hash}: the switch belongs to the lists`);
    dom.window.close();
  }
  const {dom, doc} = await boot("#/actions?queue=approval&plan=p1");
  assert.equal(doc.querySelector("#view-chrome .breadcrumbs"), null, "the approval queue outranks a plan");
  assert.equal(words(doc.getElementById("page-title")), "Actions");
  assert.ok([...doc.querySelectorAll("#content button")].some(b => words(b) === "Approval queue"));
  dom.window.close();
});

test("a list has no trail: its tab says where you are", async () => {
  for (const [hash, label] of [["#/findings", "Findings"], ["#/history", "History"], ["#/stores", "Stores"],
                               ["#/dsar", "Personal data requests"], ["#/overview", "Overview"]]) {
    const {dom, doc} = await boot(hash);
    const chrome = doc.getElementById("view-chrome");
    assert.equal(chrome.querySelector(".breadcrumbs"), null, `${hash} shows no breadcrumb row`);
    const tab = chrome.querySelector(".tab-active");
    if (tab) assert.equal(tab.getAttribute("aria-current"), "page", `${hash}: the tab is the page`);
    assert.equal(doc.title, `${label} — VecShield`);
    assert.equal(doc.getElementById("live-region").textContent, `${label} ready`);
    assert.equal(doc.querySelector("#content .page-back"), null, "a list has no way back");
    dom.window.close();
  }
});

test("changing the store on a collection leaves the collection, trail and all", async () => {
  const {dom, window, doc} = await boot("#/schema?store=prod&collection=docs");
  assert.match(words(doc.querySelector("#view-chrome .breadcrumbs")), /docs/);
  const select = doc.querySelector("#content select");
  select.value = "cold";
  select.dispatchEvent(new window.Event("change", {bubbles: true}));
  await new Promise(r => setTimeout(r, 30));
  assert.equal(window.location.hash, "#/schema?store=cold");
  assert.equal(doc.querySelector("#view-chrome .breadcrumbs"), null);
  dom.window.close();
});
