import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// Batch 3 of docs/console_ux_roadmap.md: workflows that end inside the
// console. Each test boots the shipped console in a real DOM against a stubbed
// API and follows one journey.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

export const BASE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant", tenant_field: "tenant_id",
                              conn: {url: "https://q.example", api_key_env: "QDRANT_KEY"}},
                             {store_id: "cold", kind: "chroma", conn: {path: "/data/cold"}}]},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
  "/version": {approvals: {separation_of_duties: "required"}},
  "/healthz": {status: "ok", stores: 2},
};

export async function boot(hash, responses = {}, {session = {}} = {}) {
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="light"><head><style>${css}</style></head>` +
    `<body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  for (const [k, v] of Object.entries(session)) window.sessionStorage.setItem(k, v);
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
    return {ok: true, status: 200, headers: {get: () => "application/json"},
            json: async () => value, text: async () => JSON.stringify(value)};
  };
  window.eval(shell);
  window.eval("buildShell()");
  await window.eval("route()");
  await settle();
  return {dom, window, doc: window.document, calls, run: code => window.eval(code)};
}

export const settle = () => new Promise(r => setTimeout(r, 30));
const button = (root, text) => [...root.querySelectorAll("button")]
  .find(b => b.textContent.replace(/\s+/g, " ").trim() === text);

// -------------------------------------------------- 2. store carries over ---

test("area tabs carry the chosen store to store-scoped screens", async () => {
  const {dom, doc, window} = await boot("#/crypto?store=prod", {
    "/stores/prod/crypto-posture": {status: 409, detail: "no saved audit"},
  });
  button(doc.querySelector(".tabs"), "Schema").click();
  assert.equal(window.location.hash, "#/schema?store=prod");
  dom.window.close();
});

test("a screen with no store asks for one instead of picking the first", async () => {
  const {dom, doc, calls} = await boot("#/schema");
  const select = doc.querySelector("#content select");
  assert.equal(select.value, "", "nothing is chosen for the reader");
  assert.match(doc.getElementById("content").textContent, /Choose a store above/);
  assert.equal(calls.filter(c => c.path.startsWith("/stores/")).length, 0, "no store was read");
  dom.window.close();
});

test("the last-used store is offered, and labelled as such", async () => {
  const {dom, doc} = await boot("#/schema", {}, {session: {vecshield_store: "cold"}});
  assert.equal(doc.querySelector("#content select").value, "cold");
  assert.match(doc.getElementById("content").textContent, /Showing cold, the store you last used/);
  dom.window.close();
});

test("a remembered store that no longer exists is not used", async () => {
  const {dom, doc} = await boot("#/crypto", {}, {session: {vecshield_store: "gone"}});
  assert.equal(doc.querySelector("#content select").value, "");
  assert.doesNotMatch(doc.getElementById("content").textContent, /last used/);
  dom.window.close();
});

// ------------------------------------------------- 3. results lead somewhere ---

test("an audit result ends with its next steps, each carrying the store and audit", async () => {
  const {dom, window, run} = await boot("#/overview");
  const node = run(`auditSummary({id: "audit-1", store_id: "prod", status: "succeeded", summary: {}, jobs: []})`);
  const nav = node.querySelector('nav[aria-label="Next steps"]');
  assert.ok(nav, "the result ends with next steps");
  assert.equal(node.lastElementChild, nav, "they close the result");
  const targets = {};
  for (const b of nav.querySelectorAll("button")) {
    b.click();
    targets[b.textContent.trim()] = window.location.hash;
  }
  assert.deepEqual(targets, {
    "Findings for this store": "#/findings?store=prod",
    "Crypto posture": "#/crypto?store=prod&audit=audit-1",
    "Criteria": "#/criteria?store=prod&audit=audit-1",
    "Release gate": "#/crypto?store=prod&audit=audit-1&section=gate",
  });
  dom.window.close();
});

// -------------------------------------------- 4. the New assessment page ---

test("the New assessment page points to History instead of repeating it, with one primary action", async () => {
  const {dom, doc, window, calls} = await boot("#/assess?store=prod", {
    "/stores/prod/schema": {collections: [{name: "docs", count: 3}]},
  });
  const content = doc.getElementById("content");
  assert.equal(calls.filter(c => c.path.startsWith("/admin/history")).length, 0,
    "History is not fetched here");
  assert.equal(content.querySelector("table"), null, "no saved-audits table on the New assessment page");
  assert.equal(content.querySelectorAll(".btn.primary").length, 1, "one primary action");
  button(content, "Open history for prod").click();
  assert.equal(window.location.hash, "#/history?store=prod");
  dom.window.close();
});

// --------------------------------------------------------- 5. findings ---

const FINDINGS = {
  "/admin/findings": {findings: [{id: "f1", title: "PII in docs", severity: "high",
                                  category: "data_classification",
                                  store: "file:///var/lib/vecshield/stores/prod", collection: "docs",
                                  suppressed: false, case: {state: "new"}}],
                      total: 1, limit: 50, offset: 0, has_more: false, facets: {case_state: {new: 1}}},
  "/admin/findings/f1": {finding: {id: "f1", title: "PII in docs", severity: "high",
                                   description: "Emails in chunk text.", category: "data_classification",
                                   store: "prod", collection: "docs", case: {state: "new"}, evidence: {}},
                         case_events: [], same_fingerprint: []},
};

test("findings: the list comes first, under a compact filter toolbar", async () => {
  const {dom, doc} = await boot("#/findings", FINDINGS);
  const content = doc.getElementById("content");
  const headings = [...content.querySelectorAll(".panel-heading")].map(h => h.textContent);
  assert.equal(headings[0], "Findings", "the list is the first panel");
  assert.ok(content.querySelector(".toolbar[role=search]"), "filters are a toolbar, not a panel");
  for (const folded of ["Group by cause", "Where the labels sit"]) {
    const d = [...content.querySelectorAll("details.panel-fold")].find(x => x.textContent.includes(folded));
    assert.ok(d && !d.open, `${folded} is folded away below the list`);
  }
  assert.match(content.querySelector(".location").textContent, /prod/);
  dom.window.close();
});

const TWO = {
  "/admin/findings": {findings: [
    {id: "f1", title: "PII in docs", severity: "high", category: "data_classification",
     store: "prod", collection: "docs", suppressed: false, case: {state: "new"}},
    {id: "f2", title: "Secret in runbooks", severity: "medium", category: "data_classification",
     store: "prod", collection: "runbooks", suppressed: false, case: {state: "triaged", owner: "ana"}}],
    total: 2, limit: 50, offset: 0, has_more: false,
    facets: {severity: {high: 1, medium: 1}, case_state: {new: 1, triaged: 1}}},
  "/admin/findings/f1": {finding: {id: "f1", title: "PII in docs", severity: "high", store: "prod",
                                   collection: "docs", case: {state: "new"}, evidence: {}},
                         case_events: [], same_fingerprint: []},
  "/admin/findings/f2": {finding: {id: "f2", title: "Secret in runbooks", severity: "medium", store: "prod",
                                   collection: "runbooks", case: {state: "triaged", owner: "ana"}, evidence: {}},
                         case_events: [], same_fingerprint: []},
  "/admin/estate": {stores: [{store_id: "prod", last_assessed: "2026-09-20T00:00:00Z",
                              coverage: {status: "partial"}}]},
};

test("an open finding is in the address, steps to the next row, and leaves the address on close", async () => {
  const {dom, doc, window} = await boot("#/findings", TWO);
  const content = doc.getElementById("content");
  button(content, "PII in docs").click();
  await settle();
  assert.match(window.location.hash, /finding=f1/, "the open panel can be copied as a link");
  const dialog = () => doc.querySelector('[role="dialog"]');
  assert.match(dialog().querySelector(".fd-stepper").textContent, /1 of 2/);
  dialog().querySelector('[aria-label="Next finding: Secret in runbooks"]').click();
  await settle();
  assert.equal(doc.getElementById(dialog().getAttribute("aria-labelledby")).textContent, "Secret in runbooks");
  assert.match(window.location.hash, /finding=f2/);
  assert.equal(doc.querySelectorAll(".modal-backdrop").length, 1, "stepping replaces the panel, it does not stack");
  dialog().querySelector('[aria-label="Close"]').click();
  await settle();
  assert.doesNotMatch(window.location.hash, /finding=/);
  dom.window.close();
});

test("the finding tabs are a keyboard tab list", async () => {
  const {dom, doc, window, run} = await boot("#/findings", TWO);
  await run(`openFinding("f1")`);
  await settle();
  const list = doc.querySelector('[role="tablist"]');
  const tabs = () => [...list.querySelectorAll('[role="tab"]')];
  assert.deepEqual(tabs().map(t => t.getAttribute("tabindex")), ["0", "-1", "-1", "-1", "-1"]);
  list.dispatchEvent(new window.KeyboardEvent("keydown", {key: "ArrowRight", bubbles: true}));
  await settle();
  assert.equal(doc.activeElement.textContent, "Chunks (0)");
  assert.equal(doc.getElementById("finding-tabpanel").getAttribute("aria-labelledby"), "finding-tab-chunks");
  list.dispatchEvent(new window.KeyboardEvent("keydown", {key: "End", bubbles: true}));
  await settle();
  assert.equal(doc.activeElement.textContent, "History");
  dom.window.close();
});

test("summary chips filter, and each active filter is a chip that removes itself", async () => {
  const {dom, doc, window, calls} = await boot("#/findings", TWO);
  const content = doc.getElementById("content");
  const chip = [...content.querySelectorAll(".fsum-chip")].find(b => /medium/.test(b.textContent));
  chip.click();
  await settle();
  assert.match(window.location.hash, /severity=medium/);
  const last = () => new URLSearchParams(calls.filter(c => c.path.startsWith("/admin/findings?")).at(-1).path.split("?")[1]);
  assert.ok(calls.some(c => /[?&]severity=medium/.test(c.path)));
  const remove = content.querySelector('.filter-chip[aria-label="Remove filter Severity: medium"]');
  assert.ok(remove, "the active filter is shown and removable");
  remove.click();
  await settle();
  assert.equal(last().get("severity"), null);
  assert.ok(content.querySelector(".active-filters").hidden, "no filters, no chip row");
  // Sorting is by column header, and the direction is in the address.
  const header = [...content.querySelectorAll("th .th-sort")].find(b => b.textContent.startsWith("Recorded"));
  header.click();
  await settle();
  assert.equal(last().get("sort"), "created_at");
  assert.equal(content.querySelector('th[aria-sort="descending"]').textContent.startsWith("Recorded"), true);
  dom.window.close();
});

test("select all picks every row on the page for a bulk case change", async () => {
  const {dom, doc} = await boot("#/findings", TWO);
  const content = doc.getElementById("content");
  const all = content.querySelector('input[aria-label="Select every finding on this page"]');
  all.click();
  const bar = content.querySelector(".bulk-bar");
  assert.equal(bar.hidden, false);
  assert.match(bar.textContent, /2 selected on this page/);
  assert.equal([...content.querySelectorAll("tbody input[type=checkbox]")].every(b => b.checked), true);
  dom.window.close();
});

async function exportFrom(hash, responses, label) {
  const booted = await boot(hash, responses);
  const {window, doc} = booted;
  const blobs = [];
  window.URL.createObjectURL = blob => { blobs.push(blob); return "blob:export"; };
  window.URL.revokeObjectURL = () => {};
  const toggle = button(doc.getElementById("content"), "Export");
  assert.ok(toggle, "the findings toolbar offers an export");
  toggle.click();
  button(doc, label).click();
  await settle();
  return {...booted, blobs};
}

test("export takes the list's filters without its page size", async () => {
  const {dom, doc, calls, blobs} = await exportFrom("#/findings?severity=high&store=prod",
    {...TWO, "/admin/findings/export": "id,title\nf1,PII in docs\n"}, "CSV (spreadsheet)");
  const call = calls.find(c => c.path.startsWith("/admin/findings/export?"));
  assert.ok(call, "the export route was asked");
  const q = new URLSearchParams(call.path.split("?")[1]);
  assert.equal(q.get("format"), "csv");
  assert.equal(q.get("severity"), "high");
  assert.equal(q.get("store"), "prod");
  assert.equal(q.get("scope"), "latest", "the scope on screen");
  assert.equal(q.get("limit"), null, "no page size");
  assert.equal(q.get("offset"), null);
  assert.equal(blobs.length, 1, "one file was handed to the browser");
  assert.equal(blobs[0].type, "text/csv");
  assert.match([...doc.querySelectorAll(".toast")].map(t => t.textContent).join(" "),
               /vecshield-findings-\d{8}\.csv downloaded/);
  dom.window.close();
});

test("an export past the cap says it is partial", async () => {
  const many = {...TWO, "/admin/findings": {...TWO["/admin/findings"], total: 60000, has_more: true},
                "/admin/findings/export": {findings: [], total: 60000, exported: 50000, truncated: true}};
  const {dom, doc, blobs} = await exportFrom("#/findings", many, "JSON");
  assert.equal(blobs[0].type, "application/json");
  assert.match([...doc.querySelectorAll(".toast.warn")].map(t => t.textContent).join(" "),
               /Export is partial: 50,000 of 60,000 findings/);
  dom.window.close();
});

test("a finding opens in a side panel titled by what was found, with a real primary action", async () => {
  const {dom, doc, run} = await boot("#/findings", FINDINGS);
  await run(`openFinding("f1")`);
  await settle();
  const dialog = doc.querySelector('[role="dialog"]');
  assert.ok(dialog.classList.contains("modal-drawer"), "a side panel, not a centred box");
  assert.equal(doc.getElementById(dialog.getAttribute("aria-labelledby")).textContent, "PII in docs");
  assert.match(dialog.querySelector(".modal-meta").textContent, /f1/);
  const foot = [...dialog.querySelectorAll(".modal-foot button")].map(b => b.textContent.trim());
  assert.ok(!foot.includes("Close"), "Close is the X, not the main button");
  assert.ok(dialog.querySelector(".modal-foot .btn.primary").textContent.includes("Change case"));
  dom.window.close();
});

// ------------------------------------------------------- 6. row actions ---

const ESTATE = {
  "/admin/estate": {stores: [{store_id: "prod", kind: "qdrant", last_assessed: null, coverage: null,
                              findings: {}, findings_total: 0, history_available: true,
                              probe: {probed: true, reachable: true, capabilities: [], content_enumerable: true}}],
                    probed: true, note: ""},
};

test("a row shows one action; the rest, Delete last, are in an accessible menu", async () => {
  const {dom, doc, window} = await boot("#/stores", ESTATE);
  const cell = doc.querySelector("#content tbody tr td:last-child");
  const visible = [...cell.querySelectorAll("button")].filter(b => !b.closest(".menu-pop"));
  assert.deepEqual(visible.map(b => b.textContent.trim() || b.getAttribute("aria-label")),
                   ["Open", "More actions"]);
  const toggle = cell.querySelector(".row-more");
  const menu = cell.querySelector('[role="menu"]');
  assert.equal(menu.hidden, true);
  assert.equal(toggle.getAttribute("aria-haspopup"), "menu");
  toggle.click();
  assert.equal(menu.hidden, false);
  assert.equal(toggle.getAttribute("aria-expanded"), "true");
  const items = [...menu.querySelectorAll('[role="menuitem"]')];
  assert.deepEqual(items.map(i => i.textContent.trim()),
                   ["Assess", "Test connection", "Edit connection", "Delete store"]);
  assert.ok(items.at(-1).classList.contains("menu-danger"), "Delete is last and set apart");
  assert.equal(doc.activeElement, items[0], "focus moves into the menu");
  menu.dispatchEvent(new window.KeyboardEvent("keydown", {key: "ArrowDown", bubbles: true}));
  assert.equal(doc.activeElement, items[1]);
  menu.dispatchEvent(new window.KeyboardEvent("keydown", {key: "Escape", bubbles: true}));
  assert.equal(menu.hidden, true);
  assert.equal(doc.activeElement, toggle, "Escape returns focus to the toggle");
  dom.window.close();
});

test("an expired exception offers no Revoke", async () => {
  const {dom, doc} = await boot("#/exceptions", {
    "/compliance/exceptions": {exceptions: [
      {id: "e1", criterion_id: "HIPAA-1", scope: "prod", status: "expired", rationale: "r",
       requested_by: "a", approved_by: "b", expires_at: "2026-01-01T00:00:00+00:00"},
      {id: "e2", criterion_id: "HIPAA-2", scope: "prod", status: "active", rationale: "r",
       requested_by: "a", approved_by: "b", expires_at: "2027-01-01T00:00:00+00:00"}],
      pending_approval: 0, active: 1, expired: 1, note: "n"},
  });
  const rows = [...doc.querySelectorAll("#content tbody tr[data-exception]")];
  const items = row => [...row.querySelectorAll('[role="menuitem"]')].map(b => b.textContent.trim());
  assert.deepEqual(items(rows[0]), [], "expired: nothing to revoke");
  assert.deepEqual(items(rows[1]), ["Revoke"]);
  dom.window.close();
});

// --------------------------------------------------------- 7. edit a store ---

const PG = {store_id: "pg", kind: "pgvector", tenant_field: "tenant_id", description: "d",
            conn: {dsn: "***", user: "app", sslrootcert: "/etc/ca.pem"}};

async function openEdit(testResponse) {
  const ctx = await boot("#/stores", {
    ...ESTATE,
    "GET /admin/stores/pg": PG,
    "PUT /admin/stores/pg": {...PG},
    "POST /admin/stores/test-connection": testResponse,
  });
  await ctx.run(`editStore("pg")`);
  await settle();
  return {...ctx, dialog: ctx.doc.querySelector('[role="dialog"]')};
}

const submitForm = (window, dialog) =>
  dialog.querySelector("form").dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));

test("Test connection tries the form's values before saving, masked secrets as ***", async () => {
  const {dom, window, calls, dialog} = await openEdit({ok: true, endpoint: "pg.internal",
    collections: [{name: "docs", count: 12, dimension: 384}]});
  const dsn = dialog.querySelector('input[data-key="dsn"]');
  assert.equal(dsn.value, "", "a masked secret is never shown");
  assert.match(dsn.placeholder, /Stored value kept/);
  const user = dialog.querySelector('input[data-key="user"]');
  user.value = "reader";
  user.dispatchEvent(new window.Event("input", {bubbles: true}));
  button(dialog, "Test connection").click();
  await settle();
  const test = calls.find(c => c.path === "/admin/stores/test-connection");
  assert.deepEqual(test.body, {kind: "pgvector", store_id: "pg",
    conn: {dsn: "***", user: "reader", sslrootcert: "/etc/ca.pem"}},
    "the masked DSN goes as ***, with the store id; the unshown key is kept");
  assert.equal(calls.filter(c => c.method === "PUT").length, 0, "testing saves nothing");
  assert.match(dialog.textContent, /connect to pg\.internal: 1 collection found\. Nothing was saved/);
  assert.match(dialog.textContent, /docs/);
  submitForm(window, dialog);
  await settle();
  const put = calls.find(c => c.method === "PUT");
  assert.deepEqual(put.body.conn, {dsn: "***", user: "reader", sslrootcert: "/etc/ca.pem"});
  assert.equal(dom.window.document.querySelector('[role="alertdialog"]'), null, "a passed test needs no warning");
  assert.doesNotMatch(dom.window.document.body.textContent, /Restore the previous connection/);
  dom.window.close();
});

test("after a failed test, Save asks first, and Cancel saves nothing", async () => {
  const {dom, doc, window, calls, dialog} = await openEdit({ok: false, category: "auth",
    error_type: "OperationalError", reason: "The connection could not be opened with these settings. Nothing was saved."});
  button(dialog, "Test connection").click();
  await settle();
  assert.match(dialog.textContent, /did not connect \(auth\): The connection could not be opened/);
  assert.match(dialog.textContent, /OperationalError/);
  submitForm(window, dialog);
  await settle();
  const warning = doc.querySelector('[role="alertdialog"]');
  assert.ok(warning, "saving over a failed test is confirmed");
  assert.match(warning.textContent, /Save anyway\?/);
  assert.match(warning.textContent, /failed \(auth\)/);
  button(warning, "Cancel").click();
  await settle();
  assert.equal(calls.filter(c => c.method === "PUT").length, 0, "cancel saves nothing");
  submitForm(window, dialog);
  await settle();
  const again = doc.querySelector('[role="alertdialog"]');
  again.querySelector("form").dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  assert.equal(calls.filter(c => c.method === "PUT").length, 1, "Save anyway saves");
  dom.window.close();
});

test("changing a field after a failed test clears the warning; saving is never forced through a test", async () => {
  const {dom, doc, window, calls, dialog} = await openEdit({ok: false, category: "network", reason: "r"});
  button(dialog, "Test connection").click();
  await settle();
  const user = dialog.querySelector('input[data-key="user"]');
  user.value = "other";
  user.dispatchEvent(new window.Event("input", {bubbles: true}));
  submitForm(window, dialog);
  await settle();
  assert.equal(doc.querySelector('[role="alertdialog"]'), null, "the failed test was of other values");
  assert.equal(calls.filter(c => c.method === "PUT").length, 1);
  dom.window.close();
});

test("Add store tests its values before saving, with no store id", async () => {
  const {dom, doc, calls, run} = await boot("#/stores", {...ESTATE,
    "POST /admin/stores/test-connection": {ok: true, endpoint: "q", collections: []}});
  run("storeModal()");
  const dialog = doc.querySelector('[role="dialog"]');
  dialog.querySelector('input[data-key="path"]').value = "/data/new";
  button(dialog, "Test connection").click();
  await settle();
  const test = calls.find(c => c.path === "/admin/stores/test-connection");
  assert.deepEqual(test.body, {kind: "chroma", conn: {path: "/data/new"}});
  assert.equal(calls.filter(c => c.path === "/admin/stores" && c.method === "POST").length, 0);
  dom.window.close();
});

test("deleting a store reports what was retired with it", async () => {
  const {dom, doc, window, run} = await boot("#/stores", {
    ...ESTATE,
    "DELETE /admin/stores/prod": {removed: "prod", retired: {reviewer_decisions: 3, applicability_answers: 2}},
  });
  const pending = run(`deleteStore("prod")`);
  await settle();
  const dialog = doc.querySelector('[role="alertdialog"]');
  assert.match(dialog.textContent, /kept as history/);
  const input = dialog.querySelector("input");
  input.value = "prod";
  input.dispatchEvent(new window.Event("input", {bubbles: true}));
  dialog.querySelector("form").dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await pending;
  assert.match(doc.body.textContent, /3 reviewer decisions and 2 applicability answers were retired/);
  dom.window.close();
});

// ------------------------------------------------------------ 8. compliance ---

const PACK = {pack: {pack_version: "d3", criteria: 1, regulatory_review: null, frameworks: ["HIPAA"]},
              criteria: [{criterion_id: "HIPAA-1", framework: "HIPAA", paraphrase: "Access is limited.",
                          sources: [], manual_evidence: ["access_review_record"]}]};
const ASSESS = {criterion_id: "HIPAA-1", framework: "HIPAA", status: "evidence_needed",
  applicability: {handles_ephi: "requires_confirmation"}, applicability_status: "requires_confirmation",
  technical_result: "passed", technical_coverage: "complete", evidence_sufficiency: "missing",
  missing_evidence: ["access_review_record"], observations: [], gaps: [], limitations: [], reviewer: null,
  decision_source: null, what_if_ignored: false,
  stored_decision: {id: "dec-1", reviewer: "dana", conclusion: "satisfied", rationale: "Reviewed Q3.",
                    decided_at: "2026-09-20T10:00:00+00:00", audit_id: "audit-9", applied: false,
                    not_applied_reason: "made_against_later_audit",
                    not_applied_note: "This decision was made against an audit that finished after the one being evaluated.",
                    carried_forward: false}};
const CRITERIA = {
  "/compliance/criteria": PACK,
  "POST /stores/prod/criteria": {audit_id: "audit-1", assessments: [ASSESS], summary: {by_status: {}},
                                 coverage: {}, inputs: {notes: ["1 stored reviewer decision(s) were made against a later audit than this one."]}},
  "POST /stores/prod/criteria/HIPAA-1/decision": {decision: {reviewer: "sam"}, note: "n"},
  "GET /stores/prod/applicability": {store_id: "prod", answers: {handles_ephi: {answer: "yes", answered_by: "lee",
                                                                              answered_at: "2026-09-21T10:00:00+00:00"}}},
  "POST /stores/prod/applicability": {store_id: "prod", answers: {}},
  "GET /compliance/evidence": {artifacts: [{id: "ev-1", title: "Q3 access review", scope: "prod", usable: true},
                                           {id: "ev-2", title: "Old policy", scope: "prod", usable: false}]},
  "POST /compliance/reviews": {id: "rev-1", state: "submitted"},
  "POST /compliance/exceptions": {id: "ex-1"},
};

async function openCriteria() {
  const ctx = await boot("#/criteria?store=prod", CRITERIA);
  await settle();
  return ctx;
}

test("a stored decision that does not apply is shown and explained, not dropped", async () => {
  const {dom, doc} = await openCriteria();
  const card = doc.querySelector(".criterion");
  assert.match(card.textContent, /Reviewer's decisionNot applied/);
  assert.match(card.textContent, /dana recorded “Met for this store”/);
  assert.match(card.textContent, /made against an audit that finished after/);
  assert.match(doc.getElementById("content").textContent, /made against a later audit than this one/);
  dom.window.close();
});

test("a reviewer decision is recorded from the criterion, with a required rationale", async () => {
  const {dom, doc, window, calls} = await openCriteria();
  const opener = button(doc.querySelector(".criterion"), "Record a new decision");
  opener.click();
  // Inline, not a dialog (C-4): the form opens under the button that opened it.
  assert.equal(doc.querySelector('[role="dialog"]'), null);
  assert.equal(opener.getAttribute("aria-expanded"), "true");
  const form = doc.querySelector(".criterion .inline-form");
  assert.ok(form, "the decision form opens in the criterion");
  assert.match(form.textContent, /Not met: there is a gap/);
  assert.match(form.textContent, /gap stays open until it is fixed or an exception covers it/, "each choice says what it means");
  form.querySelector('input[type=radio][value="gap"]').checked = true;
  form.dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  assert.equal(calls.filter(c => c.path.endsWith("/decision")).length, 0, "no rationale, no decision");
  const textarea = form.querySelector("textarea");
  assert.equal(textarea.getAttribute("aria-invalid"), "true");
  const errId = textarea.getAttribute("aria-describedby").split(" ").find(id => id.endsWith("-err"));
  assert.match(doc.getElementById(errId).textContent, /Add a reason/, "the error is tied to its field");
  textarea.value = "Access review missed two service accounts.";
  form.dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  const post = calls.find(c => c.path.endsWith("/decision"));
  assert.equal(post.path, "/stores/prod/criteria/HIPAA-1/decision");
  assert.deepEqual(post.body, {conclusion: "gap", rationale: "Access review missed two service accounts.",
                               period: "", audit_id: "audit-1"});
  assert.ok(!("reviewer" in post.body), "the reviewer is the caller, never a field");
  // After the save the criterion reopens with a saved note in a status region.
  assert.match(window.location.hash, /criterion=HIPAA-1/);
  const flash = doc.querySelector(".criterion .crit-flash");
  assert.match(flash.textContent, /Decision saved for sam/);
  assert.equal(flash.getAttribute("role"), "status");
  dom.window.close();
});

test("cancelling an inline form closes it and returns focus to its button", async () => {
  const {dom, doc, window, calls} = await openCriteria();
  const opener = button(doc.querySelector(".criterion"), "Record a new decision");
  opener.click();
  const form = doc.querySelector(".criterion .inline-form");
  assert.equal(doc.activeElement, form.querySelector("input[type=radio]"), "focus moves into the form");
  button(form, "Cancel").click();
  assert.equal(doc.querySelector(".criterion .inline-form"), null);
  assert.equal(opener.getAttribute("aria-expanded"), "false");
  assert.equal(doc.activeElement, opener);
  // Opening another form closes the first: one at a time.
  opener.click();
  button(doc.querySelector(".criterion"), "Answer 1 question").click();
  assert.equal(doc.querySelectorAll(".criterion .inline-form").length, 1);
  assert.equal(opener.getAttribute("aria-expanded"), "false");
  assert.equal(calls.filter(c => c.method === "POST" && !c.path.endsWith("/criteria")).length, 0);
  dom.window.close();
});

test("applicability answers are stored for the store, showing who answered and when", async () => {
  const {dom, doc, window, calls} = await openCriteria();
  button(doc.querySelector(".criterion"), "Answer 1 question").click();
  await settle();
  assert.equal(doc.querySelector('[role="dialog"]'), null, "inline, not a dialog");
  const form = doc.querySelector(".criterion .inline-form");
  assert.match(form.textContent, /Answered “Yes” by lee/);
  assert.match(form.textContent, /Not sure yet/, "unanswered reads Not sure yet, never no");
  form.querySelector('input[type=radio][value="no"]').checked = true;
  form.dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  const post = calls.find(c => c.method === "POST" && c.path === "/stores/prod/applicability");
  assert.deepEqual(post.body, {answers: {handles_ephi: "no"}});
  assert.doesNotMatch(window.location.hash, /applies=/, "answers are not kept in the URL");
  dom.window.close();
});

test("evidence is attached from the criterion by picking an artifact", async () => {
  const {dom, doc, window, calls} = await openCriteria();
  button(doc.querySelector(".criterion"), "Add document (1)").click();
  await settle();
  assert.equal(doc.querySelector('[role="dialog"]'), null, "inline, not a dialog");
  const form = doc.querySelector(".criterion .inline-form");
  const [, artifact] = form.querySelectorAll("select");
  assert.deepEqual([...artifact.options].map(o => o.value), ["", "ev-1"], "only usable artifacts are offered");
  artifact.value = "ev-1";
  form.dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  const post = calls.find(c => c.method === "POST" && c.path === "/compliance/reviews");
  assert.deepEqual(post.body, {artifact_id: "ev-1", criterion_id: "HIPAA-1",
                               requirement: "access_review_record", scope: "prod", period: ""});
  dom.window.close();
});

test("a new document is added and sent for review without leaving the criterion", async () => {
  const {dom, doc, window, calls} = await boot("#/criteria?store=prod", {...CRITERIA,
    "POST /compliance/evidence": {id: "ev-9", state: "collected", usable: false}});
  await settle();
  button(doc.querySelector(".criterion"), "Add document (1)").click();
  await settle();
  const form = doc.querySelector(".criterion .inline-form");
  form.querySelector('input[type=radio][value="new"]').checked = true;
  form.querySelector('input[type=radio][value="new"]').dispatchEvent(new window.Event("change"));
  const branch = form.querySelector('[data-branch="new"]');
  assert.ok(!branch.hidden, "the new-document fields show");
  const [title, hash] = branch.querySelectorAll("input");
  hash.value = "not-a-hash";
  form.dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  assert.equal(calls.filter(c => c.method === "POST" && c.path === "/compliance/evidence").length, 0);
  assert.equal(title.getAttribute("aria-invalid"), "true", "the title is required");
  title.value = "Q3 access review";
  hash.value = "a".repeat(64);
  form.dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  const created = calls.find(c => c.method === "POST" && c.path === "/compliance/evidence");
  assert.deepEqual(created.body, {title: "Q3 access review", scope: "prod", content_hash: "a".repeat(64),
                                  period_start: null, period_end: null, supersedes: null, note: ""});
  const review = calls.find(c => c.method === "POST" && c.path === "/compliance/reviews");
  assert.equal(review.body.artifact_id, "ev-9", "the new document is the one sent for review");
  assert.equal(window.location.hash.split("?")[0], "#/criteria", "no detour to the Evidence screen");
  assert.match(doc.querySelector(".criterion .crit-flash").textContent, /counts only after its integrity is confirmed/);
  dom.window.close();
});

test("an exception is requested from the criterion with both pick lists filled in", async () => {
  const {dom, doc, window, calls} = await openCriteria();
  button(doc.querySelector(".criterion"), "Request exception").click();
  await settle();
  const dialog = doc.querySelector('[role="dialog"]');
  const [criterion, scope] = dialog.querySelectorAll("select");
  assert.equal(criterion.value, "HIPAA-1");
  assert.equal(scope.value, "prod");
  assert.equal(dialog.querySelector("input[placeholder*='HIPAA']"), null, "no typed criterion id");
  dialog.querySelector("textarea").value = "Compensating control in place.";
  dialog.querySelector("input[type=date]").value = "2026-12-31";
  dialog.querySelector("form").dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  const post = calls.find(c => c.method === "POST" && c.path === "/compliance/exceptions");
  assert.equal(post.body.criterion_id, "HIPAA-1");
  assert.equal(post.body.scope, "prod");
  dom.window.close();
});

test("no copy says reviews or answers are not stored", () => {
  assert.doesNotMatch(shell, /not yet stored by the backend|recorded for this view only|nothing is persisted server-side/);
});

// ---------------------------------------------------------- 9. remediation ---

const SUGGEST = {
  "/admin/findings/f1": {finding: {id: "f1", title: "PII in docs", severity: "high",
                                   store: "file:///x/stores/prod", collection: "docs"}},
  "POST /stores/prod/actions/suggest": {note: "n", suggestions: [
    {id: "s1", finding_id: "f1", title: "Tag f1 chunks", rationale: "r", collection: "docs", chunk_ids: ["c1"],
     reaches_all_observed: true, reversible: true, undo: "untag", calibrated: true, rests_on: []},
    {id: "s2", finding_id: "f2", title: "Tag f2 chunks", rationale: "r", collection: "docs", chunk_ids: ["c2"],
     reaches_all_observed: true, reversible: true, undo: "untag", calibrated: true, rests_on: []}],
    withheld: []},
  "/stores/prod/actions/plans": {plans: []},
  "/actions/safe-mode": {safe_mode: true, note: "n", actions: []},
};

test("opening Actions from a finding goes to that finding's fix, with a way back to both", async () => {
  const {dom, doc, window} = await boot("#/actions?finding=f1", {
    ...SUGGEST,
    "/admin/findings/f1/remediation": {
      finding: {id: "f1", title: "PII in docs", severity: "high", collection: "docs"},
      store_id: "prod", store_registered: true, kind: "sensitive_data", kind_label: "Sensitive data",
      rescan_supported: true, case: {state: "new"},
      executable: [{id: "s1", action: "tag_exclude", title: "Tag f1 chunks", finding_id: "f1",
                    collection: "docs", chunk_ids: ["c1"], reaches_all_observed: true, reversible: true,
                    undo: "untag", calibrated: true, rests_on: [], supported: true, needs_params: []}],
      guided: [], withheld: [], plans: [], rescans: [],
      safe_mode: {safe_mode: false, note: "Writes are permitted."}},
  });
  await settle();
  const content = doc.getElementById("content");
  assert.match(content.querySelector(".remediation-title").textContent, /PII in docs/);
  assert.match(content.textContent, /Tag f1 chunks/);
  assert.doesNotMatch(content.textContent, /Tag f2 chunks/, "only this finding's fixes");
  // The recommended fix is chosen, and the radio group is keyboard reachable.
  const picked = content.querySelector('input[type="radio"]:checked');
  assert.ok(picked, "a fix is preselected");
  assert.equal(content.querySelector(".remediation-options legend").textContent, "Fixes for this finding");
  button(content, "Open the finding").click();
  assert.equal(window.location.hash, "#/findings?finding=f1");
  dom.window.close();
});

test("bulk staging makes one plan per store from the recommended fixes only", async () => {
  const {dom, doc, calls} = await boot("#/actions?store=prod", {
    "POST /stores/prod/actions/suggest": {note: "n", suggestions: [
      {id: "s1", finding_id: "f1", title: "Tag f1 chunks", collection: "docs", chunk_ids: ["c1"],
       reaches_all_observed: true, reversible: true, undo: "untag", calibrated: true, rests_on: []},
      {id: "s1b", finding_id: "f1", title: "Quarantine f1", collection: "docs", chunk_ids: ["c1"],
       reaches_all_observed: true, reversible: true, undo: "restore", calibrated: true, rests_on: []},
      {id: "s2", finding_id: "f2", title: "Tag f2 chunks", collection: "docs", chunk_ids: ["c2"],
       reaches_all_observed: true, reversible: true, undo: "untag", calibrated: true, rests_on: []},
      {id: "s3", finding_id: "f3", title: "Assign f3", collection: "docs", selector_text: "untagged",
       reversible: true, needs_params: ["tenant_value"], rests_on: []}],
      withheld: [], findings: {f1: {title: "One"}, f2: {title: "Two"}, f3: {title: "Three"}}},
    "/stores/prod/actions/plans": (path, opts) => opts.method === "POST" ? {id: "plan-b", operations: []} : {plans: []},
    "/actions/safe-mode": {safe_mode: false, note: "Writes are permitted.", actions: []},
  });
  const content = doc.getElementById("content");
  const boxes = [...content.querySelectorAll('input[type="checkbox"][aria-label^="Select "]')];
  assert.equal(boxes.length, 2, "a fix that needs a value is not bulk-stageable");
  for (const box of boxes) { box.checked = true; box.dispatchEvent(new dom.window.Event("change")); }
  button(content, "Stage selected (2)").click();
  await settle();
  const posts = calls.filter(c => c.method === "POST" && c.path === "/stores/prod/actions/plans");
  assert.equal(posts.length, 1);
  assert.deepEqual(posts[0].body.suggestions.map(s => s.id), ["s1", "s2"]);
  dom.window.close();
});

test("bulk staging does not call a plan with a blocked operation ready to approve", async () => {
  const {dom, doc} = await boot("#/actions?store=prod", {
    "POST /stores/prod/actions/suggest": {note: "n", suggestions: [
      {id: "s1", finding_id: "f1", title: "Tag f1 chunks", collection: "docs", chunk_ids: ["c1"],
       reaches_all_observed: true, reversible: true, undo: "untag", calibrated: true, rests_on: []}],
      withheld: [], findings: {f1: {title: "One"}}},
    "/stores/prod/actions/plans": (path, opts) => opts.method === "POST"
      ? {id: "plan-b", operations: [{runnable: false,
                                     support_reason: "The connector does not declare 'metadata_write'."}]}
      : {plans: []},
    "/actions/safe-mode": {safe_mode: false, note: "Writes are permitted.", actions: []},
  });
  const content = doc.getElementById("content");
  const box = content.querySelector('input[type="checkbox"][aria-label^="Select "]');
  box.checked = true;
  box.dispatchEvent(new dom.window.Event("change"));
  button(content, "Stage selected (1)").click();
  await settle();
  const banner = doc.getElementById("content").querySelector(".actions-page-staged");
  assert.ok(banner, "the staged plan is reported");
  assert.match(banner.textContent, /cannot run/);
  assert.match(banner.textContent, /metadata_write/);
  assert.doesNotMatch(banner.textContent, /Approve it next/);
  dom.window.close();
});

test("the approval queue separates what you can approve from what needs a second person", async () => {
  const plan = (id, you, extra = {}) => ({plan_id: id, store: "prod", staged_by: "ana",
    staged_at: "2026-09-20T10:00:00+00:00", operations: 2, executable: 2, irreversible: false,
    awaiting: "approval", you, ...extra});
  const {dom, doc, calls} = await boot("#/actions?queue=approval", {
    "/actions/queue": {actor: "sam", plans: [
      plan("plan-a", {may_approve: true, needs_second_person: false, reason: null}),
      plan("plan-b", {may_approve: false, needs_second_person: true, self_proposed: true,
                      reason: "A second person must authorize this plan; the author cannot."},
           {irreversible: true, irreversible_operations: 1})],
      counts: {awaiting_approval: 2}, note: "Approving never executes a plan."},
  });
  const content = doc.getElementById("content");
  const headings = [...content.querySelectorAll(".panel-heading")].map(h => h.textContent);
  assert.deepEqual(headings, ["You can approve (1)", "Needs a second person (1)"]);
  const panels = [...content.querySelectorAll(".panel")];
  assert.match(panels[0].textContent, /plan-a/);
  assert.match(panels[1].textContent, /plan-b/);
  assert.match(panels[1].textContent, /A second person must authorize/);
  assert.match(panels[1].textContent, /1 irreversible/);
  assert.equal(content.querySelector('[aria-pressed="true"]').textContent, "Approval queue");
  assert.ok(!calls.some(c => c.method === "POST"), "looking at the queue approves nothing");
  dom.window.close();
});

// ------------------------------------------------------ 10. privacy requests ---

test("a privacy request picks its stores from the registry, none ticked meaning all", async () => {
  const {dom, doc, window, calls, run} = await boot("#/dsar", {"/admin/dsar": {dsars: []},
                                                               "POST /admin/dsar": {id: "r1"}});
  run("dsarModal()");
  const dialog = doc.querySelector('[role="dialog"]');
  assert.equal(dialog.querySelector("input[placeholder*='comma']"), null, "no comma-separated ids");
  const boxes = [...dialog.querySelectorAll("input[type=checkbox]")];
  assert.deepEqual(boxes.map(b => b.value), ["prod", "cold"]);
  assert.match(dialog.textContent, /every registered store is scanned/);
  boxes[1].checked = true;
  boxes[1].dispatchEvent(new window.Event("change", {bubbles: true}));
  assert.match(dialog.textContent, /1 of 2 stores will be scanned/);
  dialog.querySelector("input:not([type=checkbox])").value = "alice@example.com";
  dialog.querySelector("form").dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  const post = calls.find(c => c.method === "POST" && c.path === "/admin/dsar");
  assert.deepEqual(post.body.store_ids, ["cold"]);
  dom.window.close();
});

test("an erased request opens as its own page, with its evidence and each store's receipts", async () => {
  const {dom, doc, calls} = await boot("#/dsar?request=r1", {
    "/admin/dsar": {dsars: []},
    "/admin/dsar/r1": {id: "r1", subject: "alice@example.com", status: "executed", total_chunks_found: 1,
                       total_chunks_deleted: 1, requested_at: "2026-09-20T10:00:00+00:00",
                       stores: [{store_id: "prod", chunks_found: 1, chunks_deleted: 1, verified: true,
                                 coverage_complete: true,
                                 impact: {matches: []}, execution: {verification: {methods: ["enumeration"]}}}]},
    "/admin/dsar/r1/evidence": {dsar_id: "r1", stores: []},
    "/stores/prod/erasure/receipts": {store_id: "prod", count: 1, chain_verified: true,
      receipts: [{seq: 4, timestamp: 1789701184.7, actor: "dpo", dsar_id: "r1", chunks_deleted: 1}]},
  });
  const content = doc.getElementById("content");
  assert.equal(doc.querySelector('[role="dialog"]'), null, "no dialog: the request is a page");
  assert.match(content.textContent, /alice@example\.com/);
  assert.match(content.textContent, /erased and verified/);
  assert.ok(button(content, "All requests"), "a way back to the list");
  assert.ok(button(content, "Download erasure evidence"));
  assert.equal([...content.querySelectorAll("button")].filter(b => /erasure/i.test(b.textContent) &&
    /Execute|Retry/.test(b.textContent)).length, 0, "an erased request offers no second erasure");
  button(content, "Erasure receipts").click();
  await settle();
  const top = [...doc.querySelectorAll(".modal-backdrop")].find(b => !b.hidden);
  assert.match(top.textContent, /Erasure receipts — prod/);
  assert.match(top.textContent, /hash chain verifies/);
  assert.match(top.textContent, /chunks deleted\s*1/);
  assert.ok(calls.some(c => c.path === "/stores/prod/erasure/receipts"));
  dom.window.close();
});

test("a request that matched nothing says so, and offers nothing to erase", async () => {
  const {dom, doc} = await boot("#/dsar", {
    "/admin/dsar": {dsars: [
      {id: "r1", subject: "nobody@example.com", status: "scanned", requested_at: "2026-09-20T10:00:00+00:00",
       total_chunks_found: 0, total_chunks_deleted: 0, stores_with_errors: 0, stores_scanned: 2},
      {id: "r2", subject: "partial@example.com", status: "scanned", requested_at: "2026-09-20T10:00:00+00:00",
       total_chunks_found: 0, total_chunks_deleted: 0, stores_with_errors: 1, stores_scanned: 2},
      {id: "r3", subject: "found@example.com", status: "scanned", requested_at: "2026-09-20T10:00:00+00:00",
       total_chunks_found: 2, total_chunks_deleted: 0, stores_with_errors: 0, stores_scanned: 2}]},
  });
  const rows = [...doc.querySelectorAll("#content tbody tr")].map(r => r.textContent.replace(/\s+/g, " "));
  assert.match(rows[0], /nobody@example\.com.*no match in searched scope/);
  assert.doesNotMatch(rows[0], /matches found/, "zero matches is not 'matches found'");
  assert.match(rows[1], /partial@example\.com.*search incomplete.*1 incomplete/);
  assert.match(rows[2], /found@example\.com.*matches found, nothing erased/);
  // Needs action counts what still needs someone: the incomplete search and
  // the matched one, not the request that found nothing.
  assert.match(doc.querySelector(".page-facts").textContent, /Needs action\s*2/);
  assert.match(doc.getElementById("content").textContent, /does not reach backups/);
  dom.window.close();

  const detail = await boot("#/dsar?request=r1", {
    "/admin/dsar/r1": {id: "r1", subject: "nobody@example.com", status: "scanned", total_chunks_found: 0,
                       requested_at: "2026-09-20T10:00:00+00:00",
                       stores: [{store_id: "prod", chunks_found: 0, coverage_complete: true, impact: {matches: []}}]},
  });
  const text = detail.doc.getElementById("content").textContent;
  assert.match(text, /nothing to delete there/);
  assert.equal([...detail.doc.querySelectorAll("#content button")].filter(b => /Delete this person's data/.test(b.textContent)).length, 0);
  detail.dom.window.close();
});

test("opening a request lands on the request's page", async () => {
  const {dom, window, doc, calls, run} = await boot("#/dsar", {"/admin/dsar": {dsars: []},
    "POST /admin/dsar": {id: "r9", status: "scanned"}});
  run("dsarModal()");
  const dialog = doc.querySelector('[role="dialog"]');
  dialog.querySelector("input:not([type=checkbox])").value = "alice@example.com";
  dialog.querySelector("form").dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  assert.ok(calls.some(c => c.method === "POST" && c.path === "/admin/dsar"));
  assert.equal(window.location.hash, "#/dsar?request=r9");
  dom.window.close();
});

// ------------------------------------------------------------ 11. alerting ---

const ALERTING = {
  "/admin/alerting": {enabled: true, console: true, min_severity: "high", webhooks: [
    {url: "https://hooks.slack.com/…", style: "slack"},
    {url: "https://events.pagerduty.com/…", style: "pagerduty", routing_key: "***"}]},
  "PUT /admin/alerting": {enabled: true, webhooks: []},
};

test("webhooks are edited as rows, and masked values go back exactly as they came", async () => {
  const {dom, doc, calls} = await boot("#/alerting", ALERTING);
  const content = doc.getElementById("content");
  assert.equal(content.querySelector("textarea"), null, "no JSON text box");
  const rows = content.querySelectorAll(".webhook-row");
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /shown masked/);
  content.querySelector('select[aria-label="Minimum severity"]').value = "critical";
  button(content, "Save alerting").click();
  await settle();
  const put = calls.find(c => c.method === "PUT");
  assert.equal(put.body.min_severity, "critical");
  assert.deepEqual(put.body.webhooks, [
    {url: "https://hooks.slack.com/…", style: "slack"},
    {url: "https://events.pagerduty.com/…", style: "pagerduty", routing_key: "***"}],
    "untouched masked rows round-trip unchanged, for the server to resolve");
  dom.window.close();
});

test("invalid webhook input is refused in the page, with a reason", async () => {
  const {dom, doc, calls} = await boot("#/alerting", ALERTING);
  const content = doc.getElementById("content");
  button(content, "Add webhook").click();
  const last = [...content.querySelectorAll(".webhook-row")].at(-1);
  last.querySelector("input").value = "not a url";
  button(content, "Save alerting").click();
  await settle();
  assert.equal(calls.filter(c => c.method === "PUT").length, 0, "nothing is sent");
  const alert = content.querySelector('[role="alert"]');
  assert.match(alert.textContent, /Webhook 3: "not a url" is not an http\(s\) URL/);
  const style = last.querySelector("select");
  style.value = "pagerduty";
  style.dispatchEvent(new dom.window.Event("change", {bubbles: true}));
  last.querySelector("input").value = "https://events.pagerduty.com/v2/enqueue";
  button(content, "Save alerting").click();
  await settle();
  assert.match(content.querySelector('[role="alert"]').textContent, /PagerDuty needs a routing key/);
  dom.window.close();
});

// ------------------------------------------------------ 12. navigation ---

test("Frameworks is a view within Criteria, and its tab stays Criteria", async () => {
  const {dom, doc, window} = await boot("#/frameworks", {"/compliance/criteria": PACK});
  const chrome = doc.getElementById("view-chrome");
  const tabs = [...chrome.querySelectorAll(".tab")].map(t => t.textContent);
  assert.ok(!tabs.includes("Frameworks") && !tabs.includes("Templates"), "no tab of their own");
  assert.equal(chrome.querySelector('.tab[aria-current="page"]').textContent, "Criteria");
  const views = chrome.querySelector(".subviews");
  assert.deepEqual([...views.querySelectorAll("button")].map(b => b.textContent), ["Criteria", "Frameworks"]);
  assert.equal(views.querySelector('[aria-pressed="true"]').textContent, "Frameworks");
  button(views, "Criteria").click();
  assert.equal(window.location.hash, "#/criteria");
  dom.window.close();
});

test("System screens are quiet links at the sidebar's foot, and Docs is the help icon", async () => {
  const {dom, doc, window} = await boot("#/status");
  const system = doc.getElementById("nav-system");
  assert.deepEqual([...system.querySelectorAll("button")].map(b => b.textContent.trim()),
                   ["Audit log", "Alerting", "Status"]);
  assert.equal(system.querySelector('[aria-current="page"]').textContent.trim(), "Status");
  assert.ok(![...doc.querySelectorAll("#nav .nav-btn")].some(b => /Docs|Audit log/.test(b.textContent)));
  doc.getElementById("help-btn").click();
  assert.equal(window.location.hash, "#/docs");
  dom.window.close();
});

test("old links to moved screens still open them", async () => {
  // #/new-assessment and #/runs (2026-10-06) name the screens by their labels;
  // #/archive is the History tab's old name.
  for (const [hash, title] of [["#/runs", "Runs"], ["#/jobs", "Runs"], ["#/new-assessment", "New assessment"],
                               ["#/archive", "History"], ["#/false-positives", "False positives"],
                               ["#/audit-log", "Audit log"], ["#/policy-templates", "Templates"]]) {
    const {dom, doc} = await boot(hash, {"/admin/jobs": {jobs: []}, "/audit-log": {entries: [], verified: true},
                                         "/admin/allowlist": {allowlist: []}, "/admin/suppressions": {suppressions: []},
                                         "/admin/history/audits": {audits: [], available: true},
                                         "/admin/history": {jobs: [], available: true}});
    if (title) assert.equal(doc.getElementById("page-title").textContent, title, hash);
    dom.window.close();
  }
});

// -------------------------------------------------- History: one switch ---
// History used to stack the chrome's "Archive | Runs" switch above its own
// "Saved audits | Individual scans". Both screens now carry one switch with
// all three, and the chrome adds none.

const HISTORY = {
  "/admin/history/audits": {audits: [], available: true},
  "/admin/history": {jobs: [{id: "scan-1", store: "file:///data/stores/prod", kind: "chroma", finding_count: 0}],
                     available: true},
  "/admin/jobs": {jobs: []},
};
const switches = doc => [...doc.querySelectorAll("#view-chrome .segmented, #content .segmented")];
const options = group => [...group.querySelectorAll("button")].map(b => b.textContent.trim());
const pressed = group => [...group.querySelectorAll('[aria-pressed="true"]')].map(b => b.textContent.trim());

test("History shows one switch: its two lists and Runs", async () => {
  const {dom, doc, window} = await boot("#/history?store=prod", HISTORY);
  assert.equal(doc.querySelector("#view-chrome .subviews"), null, "no chrome switch above the page's");
  const groups = switches(doc);
  assert.equal(groups.length, 1, "one row of choices, not two");
  const [group] = groups;
  assert.equal(group.getAttribute("aria-label"), "History views");
  assert.deepEqual(options(group), ["Saved audits", "Individual scans (1)", "Runs"]);
  assert.deepEqual(pressed(group), ["Saved audits"]);
  const content = doc.getElementById("content");
  button(group, "Individual scans (1)").click();
  assert.deepEqual(pressed(group), ["Individual scans (1)"], "the lists swap in place");
  assert.equal(content.querySelector("#archive-scans").hidden, false);
  assert.equal(content.querySelector("#archive-audits").hidden, true);
  assert.match(window.location.hash, /^#\/history\?.*list=scans/);
  button(group, "Runs").click();
  assert.equal(window.location.hash, "#/jobs");
  dom.window.close();
});

test("the scans list opens with its option pressed", async () => {
  const {dom, doc} = await boot("#/history?list=scans", HISTORY);
  const [group] = switches(doc);
  assert.deepEqual(pressed(group), ["Individual scans (1)"]);
  assert.equal(doc.querySelector("#archive-scans").hidden, false);
  dom.window.close();
});

test("Runs carries the same switch, with Runs pressed, and its lists open History", async () => {
  const {dom, doc, window} = await boot("#/jobs?store=prod", HISTORY);
  assert.equal(doc.querySelector('#view-chrome .tab[aria-current="page"]').textContent, "History");
  assert.equal(doc.querySelector("#view-chrome .subviews"), null, "no chrome switch above the page's");
  const groups = switches(doc);
  assert.equal(groups.length, 1);
  const [group] = groups;
  // The scan count is not fetched on Runs, so it is left out rather than guessed.
  assert.deepEqual(options(group), ["Saved audits", "Individual scans", "Runs"]);
  assert.deepEqual(pressed(group), ["Runs"]);
  button(group, "Individual scans").click();
  assert.equal(window.location.hash, "#/history?store=prod&list=scans");
  button(group, "Saved audits").click();
  assert.equal(window.location.hash, "#/history?store=prod");
  dom.window.close();
});

// ------------------------------------------------- findings: open now / all ---

test("findings default to open now from the latest audits, and the switch shows every run", async () => {
  const {dom, doc, window, calls} = await boot("#/findings?severity=high&store=prod", {
    "/admin/findings": (path) => {
      const all = new URLSearchParams(path.split("?")[1]).get("scope") === "all";
      return {findings: [], total: all ? 240 : 69, limit: 50, offset: 0, has_more: false, facets: {},
              scope: all ? "all" : "latest",
              ...(all ? {} : {stores_assessed: 4, stores_never_assessed: 1,
                              note: "Distinct findings from each store's latest audit."})};
    },
  });
  const first = new URLSearchParams(calls.find(c => c.path.startsWith("/admin/findings?")).path.split("?")[1]);
  assert.equal(first.get("scope"), "latest", "an old deep link with filters reads as open now");
  assert.equal(first.get("suppressed"), "false", "counted as Home counts them");
  assert.equal(first.get("severity"), "high", "the severity Home counted, not that and above");
  assert.equal(first.get("min_severity"), null);
  const toolbar = doc.querySelector(".toolbar");
  assert.match(toolbar.textContent, /69 open in the latest audits · 1 store never assessed/);
  assert.equal(toolbar.querySelector('[aria-pressed="true"]').textContent, "Open now (latest audits)");
  assert.doesNotMatch(window.location.hash, /scope=/, "latest is the default, so it is not written");
  button(toolbar, "All recorded (every run)").click();
  await settle();
  const last = new URLSearchParams(calls.filter(c => c.path.startsWith("/admin/findings?")).at(-1).path.split("?")[1]);
  assert.equal(last.get("scope"), "all");
  assert.equal(last.get("suppressed"), null, "every run, suppressed included");
  assert.match(toolbar.textContent, /recorded across every run/);
  assert.match(window.location.hash, /scope=all/);
  dom.window.close();
});

test("rendered copy says 1 store and 2 stores, never store(s)", () => {
  const code = shell.replace(/\/\/.*$/gm, "");
  const templates = code.match(/`[^`]*`/g) || [];
  const strings = code.match(/"[^"\n]*"/g) || [];
  const offenders = [...templates, ...strings].filter(t => /[a-z]\((?:s|es|ies)\)/.test(t) && !/https?\(s\)|http\(s\)/.test(t));
  assert.deepEqual(offenders, []);
});
