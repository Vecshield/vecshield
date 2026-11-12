import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// Role-aware controls: the console offers each principal only what the server
// will let them do, says why a control is unavailable, and shows a refusal
// the server still returns in its own words. Also: signing out is claimed only
// after the server confirms it.

// The probe is a direct eval inside the console's own script, so a test can
// read and set its module-level state (`const state`, `let findingsCoverage`).
const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n") + "\nwindow.__probe = code => eval(code);\n";

const EXPAND = {admin: ["admin", "compliance", "operator", "viewer"], compliance: ["compliance", "viewer"],
                operator: ["operator", "viewer"], viewer: ["viewer"]};
const user = (username, role) => ({username, roles: [role], effective_roles: EXPAND[role],
                                   must_change_password: false, source: "session"});
const VIEWER = user("val", "viewer");
const OPERATOR = user("otto", "operator");
const COMPLIANCE = user("cora", "compliance");
const ADMIN = user("kim", "admin");
const session = u => ({login_enabled: true, authenticated: true, user: u, password_policy: {min_length: 12}});

const DSAR = (extra = {}) => ({
  id: "dsar-1", subject: "ann@example.com", status: "scanned", requested_at: "2026-09-20T10:00:00Z",
  created_by: "ana", total_chunks_found: 2, total_chunks_deleted: 0,
  stores: [{store_id: "prod", chunks_found: 2, coverage_complete: true,
            impact: {matches: [{chunk_id: "c1", collection: "docs", matched_on: "text"},
                               {chunk_id: "c2", collection: "docs", matched_on: "text"}]}}],
  ...extra,
});

const BASE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant", tenant_field: "tenant_id"}]},
  "/admin/policies": {policies: [{id: "p1", name: "No PII", enabled: true, severity: "high", action: "alert"}]},
  "/admin/policy-templates": {templates: []},
  "/version": {approvals: {separation_of_duties: "required"}},
  "/healthz": {status: "ok", stores: 1},
  "/admin/history": {jobs: [], stats: {total_findings: 0, by_severity: {}}},
  "/admin/estate": {stores: [
    {store_id: "prod", kind: "qdrant", tenant_field: "tenant_id", last_assessed: "2026-09-20T10:00:00Z",
     coverage: {status: "complete"}, findings: {}, findings_total: 0,
     probe: {probed: true, reachable: true, capabilities: [], content_enumerable: true, collections: 1, chunks: 3}}]},
  "/stores/prod/schema": {collections: [{name: "docs", count: 3}]},
  "/admin/dsar": {dsars: [DSAR()]},
  "/admin/dsar/dsar-1": DSAR(),
  "POST /stores/prod/actions/suggest": {note: "n", suggestions: [
    {id: "s1", finding_id: "f1", title: "Tag f1 chunks", collection: "docs", chunk_ids: ["c1"],
     reaches_all_observed: true, reversible: true, undo: "untag", calibrated: true, rests_on: []}],
    withheld: [], findings: {f1: {title: "One", severity: "high"}}},
  "/stores/prod/actions/plans": {plans: []},
  "/actions/safe-mode": {safe_mode: false, note: "Writes are permitted.", actions: []},
  "/actions/queue": {plans: []},
};

async function boot(hash, u, responses = {}) {
  const dom = new JSDOM(`<!doctype html><html lang="en"><body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  const calls = [];
  const all = {"/auth/session": session(u), ...BASE, ...responses};
  window.fetch = async (path, opts = {}) => {
    const method = opts.method || "GET";
    calls.push({path, method, body: opts.body ? JSON.parse(opts.body) : undefined});
    const base = path.split("?")[0];
    let value = all[`${method} ${base}`] ?? all[path] ?? all[base] ?? {};
    if (typeof value === "function") value = value(path, opts);
    if (typeof value?.status === "number") {
      return {ok: false, status: value.status, statusText: "Error",
              headers: {get: () => "application/json"}, json: async () => ({detail: value.detail})};
    }
    return {ok: true, status: 200, headers: {get: () => "application/json"},
            json: async () => value, text: async () => JSON.stringify(value)};
  };
  window.eval(shell);
  await window.eval("boot()");
  await settle();
  return {dom, window, doc: window.document, calls, run: code => window.__probe(code)};
}

const settle = async (n = 4) => { for (let i = 0; i < n; i++) await new Promise(r => setTimeout(r, 20)); };
const text = node => node.textContent.replace(/\s+/g, " ").trim();
const buttons = (root, pattern) => [...root.querySelectorAll("button")].filter(b => pattern.test(text(b)));
const menuItems = root => [...root.querySelectorAll(".menu-pop [role='menuitem']")].map(text);
const content = doc => doc.getElementById("content");

// What each role is offered on the screens that write.
async function offered(u) {
  const estate = await boot("#/stores", u);
  const estateMenu = menuItems(content(estate.doc));
  const addStore = buttons(content(estate.doc), /^Add store$/).length > 0;
  estate.dom.window.close();

  const overview = await boot("#/overview", u, {"/admin/home": {stores: {total: 1}}});
  const runShortcut = buttons(content(overview.doc), /^Run an assessment$/).length > 0;
  overview.dom.window.close();

  const assess = await boot("#/assess?store=prod", u);
  const go = content(assess.doc).querySelector(".run-go-btn");
  const run = {enabled: !go.disabled, why: text(content(assess.doc).querySelector(".run-go"))};
  assess.dom.window.close();

  const dsar = await boot("#/dsar", u);
  const newRequest = buttons(content(dsar.doc), /New request/)[0];
  const dsarList = {enabled: !newRequest.disabled, why: text(newRequest.parentElement)};
  dsar.dom.window.close();

  const request = await boot("#/dsar?request=dsar-1", u);
  const erase = buttons(content(request.doc), /Delete this person's data/)[0];
  const execute = {enabled: Boolean(erase && !erase.disabled), why: text(content(request.doc).querySelector(".privacy-erase"))};
  request.dom.window.close();

  const actions = await boot("#/actions?store=prod", u);
  const stage = buttons(content(actions.doc), /Stage selected/).length > 0;
  const picks = content(actions.doc).querySelectorAll('input[type="checkbox"][aria-label^="Select "]').length;
  actions.dom.window.close();

  return {estateMenu, addStore, runShortcut, run, dsarList, execute, stage, picks};
}

test("a viewer is offered no assessment, privacy-request, staging or store-admin control", async () => {
  const o = await offered(VIEWER);
  assert.deepEqual(o.estateMenu, ["Test connection"], "no Assess, Edit or Delete in the row menu");
  assert.equal(o.addStore, false);
  assert.equal(o.runShortcut, false, "the Overview does not offer a run");
  assert.equal(o.run.enabled, false, "Run is disabled");
  assert.match(o.run.why, /Needs the operator role\./, "and says why");
  assert.equal(o.dsarList.enabled, false);
  assert.match(o.dsarList.why, /Needs the compliance role\./);
  assert.equal(o.execute.enabled, false);
  assert.match(o.execute.why, /Needs the compliance role\./);
  assert.equal(o.stage, false, "no bulk staging");
  assert.equal(o.picks, 0, "nothing to select for staging");
});

test("an operator may assess but not open or execute a privacy request, or stage", async () => {
  const o = await offered(OPERATOR);
  assert.deepEqual(o.estateMenu, ["Assess", "Test connection"]);
  assert.equal(o.addStore, false);
  assert.equal(o.runShortcut, true);
  assert.equal(o.run.enabled, true);
  assert.doesNotMatch(o.run.why, /Needs the/);
  assert.equal(o.dsarList.enabled, false);
  assert.equal(o.execute.enabled, false);
  assert.match(o.execute.why, /Needs the compliance role\./);
  assert.equal(o.stage, false);
});

test("compliance may open and execute privacy requests and stage fixes, but not assess", async () => {
  const o = await offered(COMPLIANCE);
  assert.deepEqual(o.estateMenu, ["Test connection"], "compliance does not imply operator");
  assert.equal(o.runShortcut, false);
  assert.equal(o.run.enabled, false);
  assert.match(o.run.why, /Needs the operator role\./);
  assert.equal(o.dsarList.enabled, true);
  assert.equal(o.execute.enabled, true, "someone else opened this request");
  assert.equal(o.stage, true);
  assert.equal(o.picks, 1);
});

test("an admin is offered every control", async () => {
  const o = await offered(ADMIN);
  assert.deepEqual(o.estateMenu, ["Assess", "Test connection", "Edit connection", "Delete store"]);
  assert.equal(o.addStore, true);
  assert.equal(o.runShortcut, true);
  assert.equal(o.run.enabled, true);
  assert.equal(o.dsarList.enabled, true);
  assert.equal(o.execute.enabled, true);
  assert.equal(o.stage, true);
});

test("a viewer keeps every read view, and policy admin is read-only", async () => {
  const {dom, doc} = await boot("#/policies", VIEWER);
  const main = content(doc);
  assert.match(text(main), /No PII/, "the policy is listed");
  assert.equal(buttons(main, /New policy/).length, 0);
  const toggle = main.querySelector('input[aria-label="Enable policy No PII"]');
  assert.equal(toggle.disabled, true);
  assert.equal(toggle.title, "Needs the admin role.");
  assert.deepEqual(menuItems(main), [], "no Delete policy");
  dom.window.close();
});

// ------------------------------------------------ DSAR self-execution ---

test("whoever opened a request is told another compliance user must execute it", async () => {
  const {dom, doc} = await boot("#/dsar?request=dsar-1", COMPLIANCE,
                                {"/admin/dsar/dsar-1": DSAR({created_by: "cora"})});
  const erase = buttons(content(doc), /Delete this person's data/)[0];
  assert.equal(erase.disabled, true);
  assert.match(text(content(doc).querySelector(".privacy-erase")),
               /You opened this request, so another compliance user must delete its data\./);
  dom.window.close();
});

test("an admin, or a deployment with separation of duties off, may execute their own request", async () => {
  for (const [u, sod] of [[{...ADMIN, username: "cora"}, "required"], [COMPLIANCE, "off"]]) {
    const {dom, doc} = await boot("#/dsar?request=dsar-1", u, {
      "/admin/dsar/dsar-1": DSAR({created_by: "cora"}),
      "/version": {approvals: {separation_of_duties: sod}},
    });
    const erase = buttons(content(doc), /Delete this person's data/)[0];
    assert.equal(erase.disabled, false, `${u.roles[0]} with separation ${sod}`);
    assert.doesNotMatch(text(content(doc)), /another compliance user/);
    dom.window.close();
  }
});

// ------------------------------------------------------ refusals inline ---

test("a 403 the server still returns is shown beside the control, in the server's words", async () => {
  const {dom, window, doc} = await boot("#/dsar?request=dsar-1", COMPLIANCE, {
    "POST /admin/dsar/dsar-1/execute": {status: 403, detail: "the person who opened this request cannot also execute it"},
  });
  buttons(content(doc), /Delete this person's data/)[0].click();
  await settle();
  const typed = doc.querySelector(".modal-confirm input");
  typed.value = "ann@example.com";
  typed.dispatchEvent(new window.Event("input", {bubbles: true}));
  buttons(doc.querySelector(".modal-confirm"), /^Erase chunks$/)[0].click();
  await settle();
  const erase = content(doc).querySelector(".privacy-erase").parentElement;
  assert.match(text(erase), /Deletion did not run: The person who opened this request cannot also execute it\./);
  assert.doesNotMatch(text(erase), /Check your credentials/);
  dom.window.close();
});

test("a role refusal on a run reads as the role it needs", async () => {
  const {dom, doc} = await boot("#/assess?store=prod", null, {
    "/auth/session": {login_enabled: false, authenticated: false, user: null, password_policy: {min_length: 12}},
    "POST /stores/prod/audit": {status: 403, detail: "requires role: operator"},
  });
  const go = content(doc).querySelector(".run-go-btn");
  assert.equal(go.disabled, false, "an unknown principal is not second-guessed");
  go.click();
  await settle();
  assert.match(text(content(doc)), /could not start.*Needs the operator role\./);
  assert.equal(doc.defaultView.eval("unavailableReason(Object.assign(new Error('requires role: compliance'), " +
                                    "{status: 403, detail: 'requires role: compliance'}))"),
               "Access restricted. Needs the compliance role.");
  dom.window.close();
});

// --------------------------------------------------------------- sign-out ---

test("a failed sign-out does not claim success, keeps the session, drops cached data and offers Retry", async () => {
  let logout = () => { throw new Error("offline"); };
  const {dom, doc, calls, run} = await boot("#/overview", ADMIN, {"POST /auth/logout": () => logout()});
  run("sessionStorage.setItem('vecshield_store', 'prod')");
  run("findingsCoverage = {prod: {}}; state.approvals = {separation_of_duties: 'off'}");
  assert.ok(run("state.stores.length") > 0);
  doc.getElementById("account-btn").click();
  buttons(doc, /^Sign out$/)[0].click();
  await settle();
  assert.ok(calls.some(c => c.path === "/auth/logout" && c.method === "POST"));
  assert.doesNotMatch(doc.body.textContent, /You signed out/);
  assert.match(doc.body.textContent, /Could not reach the server; your session may still be active\./);
  assert.equal(run("state.auth.user && state.auth.user.username"), "kim", "not treated as signed out");
  assert.equal(run("state.stores.length"), 0, "cached data is dropped");
  assert.equal(run("findingsCoverage"), null);
  assert.equal(run("state.approvals"), undefined);
  assert.equal(run("sessionStorage.getItem('vecshield_store')"), null);
  assert.equal(doc.getElementById("content"), null, "nothing read before stays on screen");

  logout = () => ({ok: true});
  buttons(doc, /^Retry sign-out$/)[0].click();
  await settle();
  assert.match(doc.body.textContent, /You signed out\./);
  assert.equal(run("state.auth.user"), null);
  dom.window.close();
});

test("a sign-out the server answers with an error is not success either", async () => {
  const {dom, doc} = await boot("#/overview", ADMIN, {"POST /auth/logout": {status: 500, detail: "database locked"}});
  doc.getElementById("account-btn").click();
  buttons(doc, /^Sign out$/)[0].click();
  await settle();
  assert.doesNotMatch(doc.body.textContent, /You signed out/);
  assert.match(doc.body.textContent, /your session may still be active/);
  assert.match(doc.body.textContent, /500: Database locked\./);
  buttons(doc, /^Back to the console$/)[0].click();
  await settle();
  assert.ok(doc.getElementById("content"), "the console comes back");
  dom.window.close();
});

test("signing out, and a session ending, forget every cached value", async () => {
  const {dom, doc, run} = await boot("#/overview", ADMIN, {"POST /auth/logout": {ok: true}});
  run("sessionStorage.setItem('vecshield_store', 'prod')");
  run("findingsCoverage = {prod: {}}; findingsCoverageReady = Promise.resolve({}); state.approvals = {}");
  run("forgetSession()");
  assert.equal(run("findingsCoverage"), null);
  assert.equal(run("findingsCoverageReady"), null);
  assert.equal(run("state.approvals"), undefined);
  assert.equal(run("sessionStorage.getItem('vecshield_store')"), null);
  dom.window.close();
});
