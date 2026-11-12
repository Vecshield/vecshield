import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import axe from "axe-core";
import { JSDOM } from "jsdom";

// The Assessments area: choosing a run, getting from a finished run to its
// results, the Archive's list and its saved-audit page, and the DPIA draft.
// Each test boots the shipped console in a real DOM against a stubbed API.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

const BASE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"}, {store_id: "cold", kind: "chroma"}]},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
  "/version": {},
  "/healthz": {status: "ok", stores: 2},
  "/stores/prod/schema": {collections: [{name: "docs", count: 12}, {name: "big", count: 900}]},
};

async function boot(hash, responses = {}) {
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="light"><head><style>${css}</style></head>` +
    `<body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  const calls = [];
  const all = {...BASE, ...responses};
  window.fetch = async (path, opts = {}) => {
    calls.push({path, method: opts.method || "GET", body: opts.body ? JSON.parse(opts.body) : undefined});
    const key = `${opts.method || "GET"} ${path.split("?")[0]}`;
    let value = all[key] ?? all[path] ?? all[path.split("?")[0]] ?? {};
    if (typeof value === "function") value = value(path, opts);
    if (typeof value?.status === "number") {
      return {ok: false, status: value.status, statusText: "Error",
              headers: {get: () => "application/json"}, json: async () => ({detail: value.detail})};
    }
    return {ok: true, status: value?.job_id ? 202 : 200, headers: {get: () => "application/json"},
            json: async () => value, text: async () => JSON.stringify(value)};
  };
  window.eval(shell);
  window.eval("buildShell()");
  await window.eval("route()");
  await settle();
  return {dom, window, doc: window.document, calls, content: window.document.getElementById("content")};
}

const settle = (ms = 40) => new Promise(r => setTimeout(r, ms));
const text = node => node.textContent.replace(/\s+/g, " ");
const button = (root, label) => [...root.querySelectorAll("button")]
  .find(b => b.textContent.replace(/\s+/g, " ").trim() === label);

// ------------------------------------------------------------ the Run page ---

test("the Run page offers four modes as one choice, each saying what it reads, writes and leaves", async () => {
  const {dom, window, content} = await boot("#/assess?store=prod");
  const radios = [...content.querySelectorAll("input[name=run-mode]")];
  assert.deepEqual(radios.map(r => r.value), ["audit", "posture", "integrity", "dpia"]);
  assert.equal(radios.filter(r => r.checked).length, 1);
  assert.equal(radios[0].checked, true, "the full audit is the default");
  for (const card of content.querySelectorAll(".run-mode")) {
    assert.ok(card.querySelector("input[type=radio]"), "each mode is a real radio inside its label");
  }
  assert.match(text(content.querySelector(".run-mode-facts")), /Reads.*Writes.*Leaves you with/);
  assert.equal(content.querySelectorAll(".btn.primary").length, 1, "one primary action");
  assert.match(button(content, "Run full audit") ? "ok" : "", /ok/);

  radios[3].checked = true;
  radios[3].dispatchEvent(new window.Event("change", {bubbles: true}));
  assert.ok(button(content, "Generate DPIA draft"), "the button names what it will do");
  assert.match(text(content.querySelector(".run-mode-facts")), /not a legal determination/);
  assert.equal(content.querySelector(".run-probes").hidden, true, "active checks belong to the audit only");
  assert.match(window.location.hash, /mode=dpia/, "the chosen mode travels in the link");
  dom.window.close();
});

test("the target states its scope, and a chunk cap below a collection's size is called partial", async () => {
  const {dom, window, content} = await boot("#/assess?store=prod");
  await settle();
  assert.match(text(content.querySelector(".run-scope")), /prod: 2 collections, 912 chunks/);
  const cap = content.querySelector("#run-cap");
  cap.value = "100";
  cap.dispatchEvent(new window.Event("change", {bubbles: true}));
  assert.match(text(content.querySelector(".run-scope")), /1 collection holds more chunks than the cap \(big\)/);
  assert.match(text(content.querySelector(".run-scope")), /inconclusive rather than clean/);
  assert.match(text(content.querySelector("#run-summary")), /at most 100 chunks per collection/);
  dom.window.close();
});

test("an integrity scan picks its collection from the store's schema", async () => {
  const {dom, window, content, calls} = await boot("#/assess?store=prod&mode=integrity");
  await settle();
  const select = content.querySelector("#run-collection");
  assert.deepEqual([...select.options].map(o => o.value), ["", "docs", "big"]);
  button(content, "Run integrity scan").click();
  await settle();
  assert.match(text(content), /Choose a collection for the integrity scan/);
  assert.equal(calls.filter(c => c.path.includes("/scan/integrity")).length, 0, "nothing ran without one");
  select.value = "docs";
  select.dispatchEvent(new window.Event("change", {bubbles: true}));
  assert.match(text(content.querySelector("#run-summary")), /collection docs/);
  dom.window.close();
});

test("a finished audit hands over to its results with one primary button", async () => {
  const {dom, window, content} = await boot("#/assess?store=prod&job=j1", {
    "/admin/jobs/j1": {id: "j1", kind: "audit", status: "succeeded", resource: "prod",
                       result: {id: "audit-9", status: "partial", summary: {critical: 1, high: 0},
                                coverage: {status: "partial", complete: false, checks_complete: 3, checks_expected: 4}}},
  });
  await settle(80);
  const result = content.querySelector(".run-result");
  assert.ok(result, "the run shows a compact result, not the whole report");
  assert.match(text(result), /Audit saved as audit-9/);
  assert.match(text(result), /3 of 4 checks complete/);
  assert.match(text(result), /zero findings is inconclusive, not clean/);
  const view = button(result, "View audit results");
  assert.ok(view.classList.contains("primary"));
  assert.ok(!content.querySelector(".run-go-btn").classList.contains("primary"),
    "the Run button steps back once there is a result to read");
  view.click();
  assert.equal(window.location.hash, "#/history?audit=audit-9&store=prod");
  dom.window.close();
});

test("a DPIA draft reads as the four Article 35 parts, not as an empty findings table", async () => {
  const draft = {store: "prod", high_risk: true, residual_risk: "unknown", assessment_complete: false,
    dpo_action_required: true, data_categories: ["Personal data (identities, contact details)"],
    processing_description: "Embedding and retrieval in 'prod'.", necessity: "Personal data is present.",
    risks: [{severity: "high", category: "data_classification", title: "PII in docs", collection: "docs",
             to_rights: "Confidentiality of personal data."}],
    safeguards: [{control: "Tenant isolation", status: "not assessed — review required", assessed_by: "tenant_isolation",
                  reason: "No tenant field.", open_findings: 0, remediation: ""},
                 {control: "Patch management", status: "GAP", assessed_by: "cve", reason: "", open_findings: 2,
                  remediation: "Upgrade."}],
    unassessed_safeguards: ["Tenant isolation"], coverage: {status: "partial"}};
  const {dom, content} = await boot("#/assess?store=prod&mode=dpia&job=p1", {
    "/admin/jobs/p1": {id: "p1", kind: "pia", status: "succeeded", resource: "prod", result: draft},
  });
  await settle(80);
  const view = content.querySelector(".dpia-view");
  assert.ok(view);
  const t = text(view);
  assert.doesNotMatch(t, /No findings/);
  assert.match(t, /high-risk indicators observed|high risk: DPIA required/i);
  assert.match(t, /residual risk unknown/);
  assert.match(t, /does not establish Tenant isolation/);
  assert.match(t, /not a legal determination/);
  assert.match(t, /\(a\).*\(b\).*\(c\).*\(d\)/);
  assert.match(t, /Tenant isolation\s*not assessed/);
  assert.match(t, /Patch management\s*gap/);
  assert.ok(button(view, "Download DPIA document"), "the printable document is of this run");
  dom.window.close();
});

// ---------------------------------------------------------------- Archive ---

const AUDITS = [
  {id: "audit-old", store_id: "prod", status: "completed", started_at: "2026-01-01T10:00:00+00:00",
   max_severity: "low", summary: {low: 1}, coverage: {status: "complete", complete: true, checks_complete: 4, checks_expected: 4}},
  {id: "audit-new", store_id: "prod", status: "partial", started_at: new Date().toISOString(),
   max_severity: "critical", summary: {critical: 2, high: 1}, coverage: {status: "partial", complete: false, checks_complete: 3, checks_expected: 4}},
  {id: "audit-mid", store_id: "cold", status: "partial", started_at: new Date(Date.now() - 3 * 86400000).toISOString(),
   max_severity: "info", summary: {}, coverage: {status: "partial", complete: false}},
];

test("saved audits are a dense, filterable, sortable table", async () => {
  const {dom, window, content} = await boot("#/history", {
    "/admin/history/audits": {audits: AUDITS, has_more: false, available: true},
    "/admin/history": {jobs: [], available: true},
  });
  const rows = () => [...content.querySelectorAll("#archive-audits tbody tr")].map(text);
  assert.equal(rows().length, 3);
  assert.match(rows()[0], /audit-new/, "newest first");
  assert.match(rows()[1], /audit-mid/);
  assert.match(rows()[1], /none observed · inconclusive/, "zero under partial coverage is not clean");

  const coverage = content.querySelector('select[aria-label="Coverage"]');
  coverage.value = "complete";
  coverage.dispatchEvent(new window.Event("change", {bubbles: true}));
  assert.deepEqual(rows().map(r => r.match(/audit-(old|new|mid)/)[0]), ["audit-old"]);
  assert.match(text(content.querySelector(".archive-filters")), /1 of 3 loaded/);
  assert.match(window.location.hash, /coverage=complete/, "filters travel in the link");

  coverage.value = "";
  coverage.dispatchEvent(new window.Event("change", {bubbles: true}));
  const when = content.querySelector('select[aria-label="Started"]');
  when.value = "7";
  when.dispatchEvent(new window.Event("change", {bubbles: true}));
  assert.deepEqual(rows().map(r => r.match(/audit-(old|new|mid)/)[0]), ["audit-new", "audit-mid"]);

  when.value = "";
  when.dispatchEvent(new window.Event("change", {bubbles: true}));
  const sort = content.querySelector('select[aria-label="Sort"]');
  sort.value = "old";
  sort.dispatchEvent(new window.Event("change", {bubbles: true}));
  assert.match(rows()[0], /audit-old/);

  const sev = content.querySelector('select[aria-label="Worst finding at least"]');
  sev.value = "high";
  sev.dispatchEvent(new window.Event("change", {bubbles: true}));
  assert.deepEqual(rows().map(r => r.match(/audit-(old|new|mid)/)[0]), ["audit-new"]);
  dom.window.close();
});

test("the Archive shows one list at a time, and a failure in either stays visible", async () => {
  const {dom, content} = await boot("#/history", {
    "/admin/history/audits": {status: 403, detail: "forbidden"},
    "/admin/history": {jobs: [{id: "scan-1", store: "file:///data/stores/prod", kind: "chroma", finding_count: 0}], available: true},
  });
  assert.match(text(content.querySelector("#archive-audits")), /Saved audits unavailable: Access restricted/);
  assert.equal(content.querySelector("#archive-scans").hidden, true);
  button(content, "Individual scans (1)").click();
  assert.equal(content.querySelector("#archive-scans").hidden, false);
  assert.equal(content.querySelector("#archive-audits").hidden, true);
  assert.match(text(content.querySelector("#archive-scans")), /scan-1/);
  dom.window.close();
});

test("a saved audit opens as its own page, not a dialog, with a way back", async () => {
  const snapshot = {id: "audit-new", store_id: "prod", status: "partial", started_at: "2026-09-20T10:00:00+00:00",
    finished_at: "2026-09-20T10:01:05+00:00", summary: {critical: 2},
    coverage: {status: "partial", complete: false, checks_complete: 3, checks_expected: 4},
    check_outcomes: [{check: "integrity", collection: "docs", outcome: "inconclusive", reason: "Capped", coverage: {status: "partial"}}],
    jobs: [{findings: [{id: "f1", severity: "critical", title: "Secret in docs", collection: "docs", category: "data_classification"}]}],
    violations: [{severity: "critical", policy_id: "pol-1", action: "escalate", collection: "docs"}]};
  const {dom, window, doc, content} = await boot("#/history", {
    "/admin/history/audits": {audits: AUDITS, has_more: false, available: true},
    "/admin/history": {jobs: [], available: true},
    "/admin/history/audits/audit-new": snapshot,
  });
  button(content.querySelector("#archive-audits tbody"), "Open").click();
  assert.equal(window.location.hash, "#/history?audit=audit-new");
  await window.eval("route()");
  await settle();
  const page = doc.getElementById("content");
  assert.equal(doc.querySelector('[role="dialog"]'), null, "no popup");
  assert.equal(page.querySelectorAll("h1").length, 1);
  // The page is named by the audit: its id, which already says "audit", is
  // the h1 (phase 8), rather than "Audit audit-new" in a second heading.
  assert.equal(text(doc.getElementById("page-title")).trim(), "audit-new");
  assert.match(text(doc.querySelector("#view-chrome .breadcrumbs")), /History.*audit-new/);
  assert.match(text(page), /took 1m 5s/);
  assert.match(text(page), /3 of 4 checks complete.*zero findings is inconclusive/);
  assert.ok(button(page, "Download saved report"));
  assert.ok(page.querySelector(".next-steps"), "the next steps are on the page");

  const tabs = [...page.querySelectorAll(".archive-tabs button")].map(b => b.textContent.replace(/\s+/g, " ").trim());
  assert.deepEqual(tabs, ["Summary", "Coverage 1", "Findings 1", "Policy violations 1", "Snapshot data"]);
  button(page.querySelector(".archive-tabs"), "Findings 1").click();
  assert.match(text(page.querySelector(".archive-tab-body")), /Secret in docs/);
  assert.match(window.location.hash, /tab=findings/, "the open section is in the link");
  button(page.querySelector(".archive-tabs"), "Coverage 1").click();
  assert.match(text(page.querySelector(".archive-tab-body")), /inconclusive/);

  button(page, "All saved audits").click();
  assert.equal(window.location.hash, "#/history");
  dom.window.close();
});

test("a missing saved audit says so on its page, with a retry", async () => {
  const {dom, content} = await boot("#/history?audit=gone", {
    "/admin/history/audits/gone": {status: 404, detail: "audit snapshot not found"},
  });
  assert.match(text(content), /audit snapshot not found/);
  assert.ok(button(content, "Retry"));
  assert.ok(button(content, "All saved audits"));
  dom.window.close();
});

// ------------------------------------------------------------------- Runs ---

test("a finished run on the Runs page links to its results", async () => {
  const {dom, window, content} = await boot("#/jobs", {
    "/admin/jobs": {jobs: [
      {id: "j1", kind: "audit", status: "succeeded", resource: "prod", result: {id: "audit-9"}},
      {id: "j2", kind: "pia", status: "succeeded", resource: "prod", result: {store: "prod"}},
      {id: "j3", kind: "audit", status: "failed", resource: "prod", error: "boom"},
    ]},
  });
  assert.ok(text(content).includes("Full audit — prod"), "kinds read as a person names them");
  button(content, "View audit results").click();
  assert.equal(window.location.hash, "#/history?audit=audit-9&store=prod");
  button(content, "Open DPIA draft").click();
  assert.equal(window.location.hash, "#/assess?job=j2&store=prod&mode=dpia");
  assert.equal([...content.querySelectorAll("button")].filter(b => /View audit results/.test(b.textContent)).length, 1,
    "a failed run offers no results");
  dom.window.close();
});

// -------------------------------------------------------- accessibility ---

async function axeViolations(dom) {
  // Contrast and target size need painting; tests/contrast.test.mjs covers them.
  const results = await axe.run(dom.window.document.body, {
    rules: {"color-contrast": {enabled: false}, "target-size": {enabled: false},
            "scrollable-region-focusable": {enabled: false}},
    elementRef: false,
  });
  return results.violations.map(v => `${v.id}: ${v.help} — ${v.nodes[0]?.html?.slice(0, 120)}`);
}

const PAGES = {
  "the Run page with a store": ["#/assess?store=prod", {}],
  "the Archive list": ["#/history", {"/admin/history/audits": {audits: AUDITS, available: true},
                                     "/admin/history": {jobs: [], available: true}}],
  "a saved audit page": ["#/history?audit=audit-new", {"/admin/history/audits/audit-new": {
    id: "audit-new", store_id: "prod", summary: {}, coverage: {status: "partial"}, jobs: [], violations: []}}],
  "a privacy request page": ["#/dsar?request=r1", {"/admin/dsar/r1": {
    id: "r1", subject: "alice@example.com", status: "scanned", total_chunks_found: 1,
    stores: [{store_id: "prod", chunks_found: 1, coverage_complete: true,
              impact: {matches: [{chunk_id: "c1", collection: "docs", matched_on: "text", preview: "…"}]}}]}}],
};

for (const [name, [hash, responses]] of Object.entries(PAGES)) {
  test(`${name} has no structural accessibility violations`, async () => {
    const {dom} = await boot(hash, responses);
    await settle();
    const violations = await axeViolations(dom);
    dom.window.close();
    assert.deepEqual(violations, []);
  });
}

// ------------------------------------------------- phase 10: one of each ---

test("New assessment shows its steps once: no lifecycle bar, one stage line, one primary button", async () => {
  const {dom, content} = await boot("#/assess?store=prod");
  assert.equal(content.querySelector(".stepper"), null, "the numbered steps are the only step indicator");
  assert.equal(content.querySelector('[aria-label="Assessment lifecycle"]'), null);
  const notes = content.querySelectorAll(".run-stage-note");
  assert.equal(notes.length, 1);
  assert.equal(notes[0].getAttribute("role"), "status", "a change of stage is announced");
  assert.match(text(notes[0]), /Check the scope, then run\./);
  const bar = content.querySelector(".run-go");
  assert.equal(notes[0].nextElementSibling, bar, "the stage line sits directly above the Run bar");
  assert.ok(bar.querySelector("#run-summary") && bar.querySelector(".run-go-btn"),
    "the bar holds the summary and the Run button");
  assert.deepEqual([...content.querySelectorAll(".btn.primary")].map(b => text(b).trim()), ["Run full audit"]);
  dom.window.close();
});

test("a finished audit leaves exactly one primary button: the way to its results", async () => {
  const {dom, content} = await boot("#/assess?store=prod&job=j1", {
    "/admin/jobs/j1": {id: "j1", kind: "audit", status: "succeeded", resource: "prod",
                       result: {id: "audit-9", status: "partial", summary: {},
                                coverage: {status: "partial", complete: false}}},
  });
  await settle(80);
  const primaries = [...content.querySelectorAll(".btn.primary")].map(b => text(b).trim());
  assert.deepEqual(primaries, ["View audit results"]);
  assert.ok(content.querySelector(".run-go .run-go-open"), "the bar still offers the way to the saved audit");
  assert.match(text(content.querySelector(".run-stage-note")), /Review the results/);
  dom.window.close();
});

test("Runs keeps live runs as cards and lists finished ones in one table, a failure's reason in its row", async () => {
  const {dom, window, content} = await boot("#/jobs", {
    "/admin/jobs": {jobs: [
      {id: "j0", kind: "audit", status: "running", resource: "cold", started_at: new Date().toISOString()},
      {id: "j1", kind: "audit", status: "succeeded", resource: "prod", actor: "ana",
       started_at: "2026-09-17T10:00:00+00:00", finished_at: "2026-09-17T10:01:00+00:00", result: {id: "audit-9"}},
      {id: "j3", kind: "audit", status: "failed", resource: "prod", error: "connection refused"},
    ]},
  });
  const cards = content.querySelectorAll(".run-card");
  assert.equal(cards.length, 1, "only the running job is a live card");
  assert.match(text(cards[0]), /Full audit — cold/);
  const rows = [...content.querySelectorAll(".runs-table tbody tr")];
  assert.equal(rows.length, 2, "both finished jobs are rows of one table");
  const headers = [...content.querySelectorAll(".runs-table th")].map(th => text(th).trim());
  assert.deepEqual(headers.slice(0, 5), ["Run", "Status", "Started", "Elapsed", "Started by"]);
  const [done, failed] = rows;
  assert.match(text(done), /Full audit — prod.*Completed.*1m 0s.*ana/);
  assert.ok(done.querySelector("time[datetime]"), "the start is a <time>, not a raw ISO string");
  assert.doesNotMatch(text(done), /2026-09-17T10/);
  const reason = failed.querySelector(".run-row-error");
  assert.ok(reason, "the failure's reason is in the row");
  assert.match(text(reason), /connection refused/);
  assert.equal(reason.closest("button, details"), null, "and visible, not behind a control");
  assert.equal([...failed.querySelectorAll("button")].filter(b => /results|draft/i.test(text(b))).length, 0,
    "a failed run offers no result");
  failed.querySelector(".row-more").click();
  assert.deepEqual([...failed.querySelectorAll("[role=menuitem]")].map(b => text(b).trim()), ["Full record"]);
  button(done, "View audit results").click();
  assert.equal(window.location.hash, "#/history?audit=audit-9&store=prod");
  dom.window.close();
});

const SNAPSHOT = {id: "audit-new", store_id: "prod", status: "partial", started_at: "2026-09-20T10:00:00+00:00",
  summary: {critical: 1}, coverage: {status: "partial", complete: false},
  check_outcomes: [{check: "integrity", collection: "docs", outcome: "inconclusive", coverage: {status: "partial"}}],
  jobs: [{findings: [{id: "f1", severity: "critical", title: "Secret in docs", collection: "docs"}]}], violations: []};

test("a saved audit's sections are an ARIA tab list on the page, all tabbable, the open one in the link", async () => {
  const {dom, window, content} = await boot("#/history?audit=audit-new&tab=findings",
    {"/admin/history/audits/audit-new": SNAPSHOT});
  const bar = content.querySelector(".archive-tabs");
  assert.equal(bar.getAttribute("role"), "tablist");
  assert.equal(bar.getAttribute("aria-label"), "Audit sections");
  const tabs = [...bar.querySelectorAll("button")];
  assert.ok(tabs.every(t => t.getAttribute("role") === "tab"));
  assert.ok(tabs.every(t => !t.hasAttribute("tabindex")), "a page tab list keeps every tab in the Tab order");
  const selected = tabs.filter(t => t.getAttribute("aria-selected") === "true");
  assert.deepEqual(selected.map(t => text(t).trim()), ["Findings 1"], "tab= opens its section");
  const panel = content.querySelector("[role=tabpanel]");
  assert.ok(panel.classList.contains("archive-tab-body"));
  assert.equal(panel.getAttribute("aria-labelledby"), selected[0].id, "the panel is labelled by its tab");
  assert.ok(tabs.every(t => t.getAttribute("aria-controls") === panel.id));
  assert.match(text(panel), /Secret in docs/);

  selected[0].dispatchEvent(new window.KeyboardEvent("keydown", {key: "ArrowRight", bubbles: true}));
  assert.equal(text(bar.querySelector("[aria-selected=true]")).trim(), "Policy violations 0");
  assert.match(window.location.hash, /tab=violations/);
  button(bar, "Summary").click();
  assert.doesNotMatch(window.location.hash, /tab=/, "the default section is not in the link");
  assert.equal(panel.getAttribute("aria-labelledby"), "audit-tab-summary");
  dom.window.close();
});

test("an audit, a scan and a privacy request share one record head", async () => {
  const pages = [
    ["#/history?audit=audit-new", {"/admin/history/audits/audit-new": SNAPSHOT}, /Download saved report/],
    ["#/history?scan=scan-1", {"/admin/history/scan-1": {id: "scan-1", store: "prod", kind: "posture",
      created_at: "2026-09-20T10:00:00+00:00", findings: [], coverage: {status: "complete", complete: true}}},
     /Standalone or legacy scan/],
    ["#/dsar?request=r1", {"/admin/dsar/r1": {id: "r1", subject: "alice@example.com", status: "scanned",
      total_chunks_found: 0, requested_at: "2026-09-20T10:00:00+00:00", stores: []}}, /Stores searched/],
  ];
  for (const [hash, responses, action] of pages) {
    const {dom, content} = await boot(hash, responses);
    await settle();
    const heads = content.querySelectorAll(".archive-head");
    assert.equal(heads.length, 1, `${hash}: one record head`);
    const head = heads[0];
    assert.ok(head.querySelector(".archive-head-row > .archive-head-text > .archive-head-meta time[datetime]"),
      `${hash}: its facts in one row, with the time`);
    assert.match(text(head.querySelector(".archive-head-row")), action, `${hash}: its action beside them`);
    assert.ok(head.querySelector(".note"), `${hash}: the notes that qualify it`);
    dom.window.close();
  }
});

test("History's lists filter from one toolbar each, a search landmark with a name", async () => {
  const {dom, content} = await boot("#/history", {
    "/admin/history/audits": {audits: AUDITS, has_more: false, available: true},
    "/admin/history": {jobs: [{id: "scan-1", store: "prod", kind: "posture", finding_count: 0}], available: true},
  });
  const bars = [...content.querySelectorAll(".toolbar[role=search]")];
  assert.deepEqual(bars.map(b => b.getAttribute("aria-label")), ["Filter saved audits", "Filter scans"]);
  assert.ok(bars.every(b => b.classList.contains("archive-filters")));
  assert.ok(bars[0].querySelector('select[aria-label="Sort"]'));
  dom.window.close();
});
