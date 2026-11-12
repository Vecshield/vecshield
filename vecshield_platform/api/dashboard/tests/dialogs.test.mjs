import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// Confirmation and the dialog stack, in a real DOM.
//
// The console once confirmed an erasure with `window.confirm?.()` and treated
// "no dialog available" as a yes. These tests pin the replacement: one in-page
// confirmation that refuses to act when it cannot be shown, that needs the
// store id or subject typed for an irreversible action, and dialogs that close
// when the page changes and step back rather than vanish when nested.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

const FINDING = {
  id: "f1", title: "PII detected in collection 'docs'", severity: "high",
  category: "data_classification", store: "prod", collection: "docs", fingerprint: "fp-1",
  case: {state: "new"}, created_at: "2026-09-20T10:00:00+00:00",
  evidence: {examples: [{chunk_id: "c1", label: "pii", detectors: ["email"], spans: []}]},
};

const BASE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"}]},
  "/admin/policies": {policies: [{id: "p1", name: "Secrets", severity: "critical", when: {},
                                  action: "purge", enabled: true, scope_store: "prod"}]},
  "/admin/policy-templates": {templates: []},
  "/version": {}, "/healthz": {status: "ok", stores: 1},
  "/admin/findings/f1": {finding: FINDING, case_events: [], same_fingerprint: []},
  "/stores/prod/collections/docs/chunks/c1": {surfaces: [{name: "text", text: "hello", spans: []}],
                                              live_spans: 0, recorded_spans: 0, metadata: {},
                                              fetched_at: "2026-09-20T10:00:00+00:00"},
  "/admin/dsar/r1": {id: "r1", subject: "alice@example.com", status: "scanned",
                     total_chunks_found: 2, requested_at: "2026-09-20T10:00:00+00:00",
                     stores: [{store_id: "prod", chunks_found: 2, impact: {matches: []}}]},
  "/compliance/exceptions": {exceptions: [
    {id: "e1", criterion_id: "HIPAA-1", scope: "prod", status: "active", rationale: "r",
     requested_by: "a", approved_by: "b", expires_at: "2027-01-01T00:00:00+00:00"}],
    pending_approval: 0, active: 1, expired: 0, note: "n"},
};

async function boot(hash = "#/overview", responses = {}) {
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="light"><head><style>${css}</style></head>` +
    `<body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  const calls = [];
  const all = {...BASE, ...responses};
  window.fetch = async (path, opts = {}) => {
    calls.push({path, method: opts.method || "GET"});
    const value = all[path.split("?")[0]] ?? {};
    return {ok: true, status: 200, headers: {get: () => "application/json"},
            json: async () => value, text: async () => JSON.stringify(value)};
  };
  window.eval(shell);
  window.eval("buildShell()");
  await window.eval("loadCore()");
  return {dom, window, doc: window.document, calls,
          run: code => window.eval(code), settle: () => new Promise(r => setTimeout(r, 20))};
}

const confirmDialog = doc => doc.querySelector('[role="alertdialog"]');
const backdrops = doc => [...doc.querySelectorAll(".modal-backdrop")];
const visibleBackdrops = doc => backdrops(doc).filter(b => !b.hidden);

function type(window, input, value) {
  input.value = value;
  input.dispatchEvent(new window.Event("input", {bubbles: true}));
}

function submit(window, form) {
  form.dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
}

// ------------------------------------------------------------ no fallback ---

test("no window.confirm, alert, or prompt remains in the shipped console", () => {
  const code = shell.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
  assert.doesNotMatch(code, /window\.(confirm|alert|prompt)\b/);
  assert.doesNotMatch(code, /(^|[^\w.$])(confirm|alert|prompt)\s*\(/m,
    "a bare confirm()/alert()/prompt() call is a browser dialog, which can be unavailable");
});

// ------------------------------------------------------- confirm component ---

test("the confirmation is a labelled alertdialog that traps focus and cancels on Escape", async () => {
  const {window, doc, run, dom} = await boot();
  const answer = run(`confirmAction({title: "Delete policy?", message: "It goes.", confirmLabel: "Delete"})`);
  const dialog = confirmDialog(doc);
  assert.ok(dialog, "the confirmation is in the page");
  assert.equal(dialog.getAttribute("aria-modal"), "true");
  assert.match(doc.getElementById(dialog.getAttribute("aria-labelledby")).textContent, /Delete policy\?/);
  assert.match(doc.getElementById(dialog.getAttribute("aria-describedby")).textContent, /It goes\./);
  assert.ok(dialog.contains(doc.activeElement), "focus moves into it");

  dialog.closest(".modal-backdrop").dispatchEvent(
    new window.KeyboardEvent("keydown", {key: "Escape", bubbles: true, cancelable: true}));
  assert.equal(await answer, false, "Escape is a no");
  assert.equal(confirmDialog(doc), null, "and the dialog is gone");
  dom.window.close();
});

test("a confirmation that cannot be shown refuses, and the action never runs", async () => {
  const {window, doc, calls, run, dom} = await boot();
  // Simulate a page where the dialog cannot be mounted.
  const append = doc.body.append.bind(doc.body);
  doc.body.append = node => {
    if (node?.classList?.contains("modal-backdrop")) throw new Error("blocked");
    return append(node);
  };
  assert.equal(await run(`confirmAction({title: "t", message: "m"})`), false);
  assert.match(doc.body.textContent, /confirmation could not be shown, so nothing was done/);

  await run(`deleteStore("prod")`);
  await run(`decideException("e1", "revoke", {criterion_id: "HIPAA-1", scope: "prod"})`);
  assert.equal(calls.filter(c => c.method === "DELETE" || c.method === "POST").length, 0,
    "no delete or revoke was sent without a confirmation");
  dom.window.close();
});

test("deleting a store names its scoped policies and needs the store id typed", async () => {
  const {window, doc, calls, run, settle, dom} = await boot("#/stores");
  const pending = run(`deleteStore("prod")`);
  await settle();
  const dialog = confirmDialog(doc);
  assert.ok(dialog);
  assert.match(dialog.textContent, /1 policy scoped to this store/);
  assert.match(dialog.textContent, /Secrets/, "the scoped policy is named");

  const input = dialog.querySelector("input");
  const ok = [...dialog.querySelectorAll("button")].find(b => b.textContent === "Delete store");
  assert.equal(ok.disabled, true, "nothing typed, nothing to press");
  type(window, input, "pro");
  assert.equal(ok.disabled, true, "a partial id is not the id");
  submit(window, dialog.querySelector("form"));
  await settle();
  assert.ok(confirmDialog(doc), "submitting with the wrong text keeps it open");
  assert.equal(calls.filter(c => c.method === "DELETE").length, 0);

  type(window, input, "prod");
  assert.equal(ok.disabled, false);
  submit(window, dialog.querySelector("form"));
  await pending;
  assert.deepEqual(calls.filter(c => c.method === "DELETE").map(c => c.path), ["/admin/stores/prod"]);
  dom.window.close();
});

test("erasure needs the subject typed, and cancelling erases nothing", async () => {
  const {window, doc, calls, settle, dom} = await boot("#/dsar");
  // The request is a page now; render it where the route would.
  doc.getElementById("content").replaceChildren(await window.eval(`privacyRequestView("r1")`));
  const erase = () => [...doc.querySelectorAll("button")].find(b => /Delete this person's data/.test(b.textContent));
  erase().click();
  await settle();
  let dialog = confirmDialog(doc);
  assert.ok(dialog, "erasure asks first");
  assert.match(dialog.textContent, /cannot be undone/);
  assert.match(dialog.textContent, /alice@example\.com/);
  const cancel = [...dialog.querySelectorAll("button")].find(b => b.textContent === "Cancel");
  cancel.click();
  await settle();
  assert.equal(calls.filter(c => /\/execute$/.test(c.path)).length, 0, "cancel erases nothing");
  assert.ok(erase(), "the request it was opened from is still on screen");

  erase().click();
  await settle();
  dialog = confirmDialog(doc);
  type(window, dialog.querySelector("input"), "alice@example.com");
  submit(window, dialog.querySelector("form"));
  await settle();
  assert.deepEqual(calls.filter(c => /\/execute$/.test(c.path)).map(c => c.method), ["POST"]);
  dom.window.close();
});

test("deleting a policy and revoking an exception both ask first", async () => {
  const {window, doc, calls, run, settle, dom} = await boot("#/policies");
  const policy = run(`deletePolicy({id: "p1", name: "Secrets", when: {}})`);
  await settle();
  assert.match(confirmDialog(doc).textContent, /Delete policy "Secrets"\?/);
  [...confirmDialog(doc).querySelectorAll("button")].find(b => b.textContent === "Cancel").click();
  await policy;
  assert.equal(calls.filter(c => c.method === "DELETE").length, 0);

  const revoke = run(`decideException("e1", "revoke", {criterion_id: "HIPAA-1", scope: "prod"})`);
  await settle();
  const dialog = confirmDialog(doc);
  assert.match(dialog.textContent, /gap it covered is open again/);
  submit(window, dialog.querySelector("form"));
  await revoke;
  assert.deepEqual(calls.filter(c => c.method === "POST").map(c => c.path),
                   ["/compliance/exceptions/e1/revoke"]);
  dom.window.close();
});

// ------------------------------------------------------------ dialog stack ---

test("navigating away closes every open dialog", async () => {
  const {window, doc, run, dom} = await boot("#/overview");
  await run("route()");
  await run(`openFinding("f1")`);
  assert.equal(backdrops(doc).length, 1);
  window.location.hash = "#/stores";
  await run(`route({type: "hashchange"})`);
  assert.equal(backdrops(doc).length, 0, "the finding does not float over the next page");
  dom.window.close();
});

test("a chunk opened from a finding offers Back to the finding", async () => {
  const {window, doc, run, settle, dom} = await boot("#/findings");
  await run(`openFinding("f1")`);
  await run(`openChunk({store: "prod", collection: "docs", chunkId: "c1", finding: ${JSON.stringify(FINDING)}})`);
  await settle();
  assert.equal(backdrops(doc).length, 2, "the finding stays mounted beneath");
  assert.equal(visibleBackdrops(doc).length, 1, "only the chunk is shown");
  const back = doc.querySelector(".modal-back");
  assert.ok(back, "the nested detail has a Back button");
  assert.equal(back.getAttribute("aria-label"), "Back to PII detected in collection 'docs'");

  back.click();
  assert.equal(backdrops(doc).length, 1);
  const top = visibleBackdrops(doc)[0];
  assert.match(top.textContent, /PII detected in collection 'docs'/, "the finding is back, as it was");
  assert.equal(doc.querySelector(".modal-back"), null, "the finding itself has nothing to go back to");
  dom.window.close();
});

test("Escape steps back one level, not out of the whole stack", async () => {
  const {window, doc, run, settle, dom} = await boot("#/findings");
  await run(`openFinding("f1")`);
  await run(`openChunk({store: "prod", collection: "docs", chunkId: "c1"})`);
  await settle();
  visibleBackdrops(doc)[0].dispatchEvent(
    new window.KeyboardEvent("keydown", {key: "Escape", bubbles: true, cancelable: true}));
  assert.equal(backdrops(doc).length, 1);
  assert.match(visibleBackdrops(doc)[0].textContent, /PII detected in collection 'docs'/);
  dom.window.close();
});

test("an ordinary dialog still replaces whatever was open", async () => {
  const {doc, run, dom} = await boot();
  run(`modal("First", document.createElement("div"), null, "Close")`);
  run(`modal("Second", document.createElement("div"), null, "Close")`);
  assert.equal(backdrops(doc).length, 1);
  assert.match(backdrops(doc)[0].textContent, /Second/);
  dom.window.close();
});
