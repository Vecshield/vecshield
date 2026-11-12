// Crypto coverage statement, the estate matrix, the overview's failure
// states and the Run page's way to a finished audit. Harness copied from
// crypto.test.mjs (it is not exported there).
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// Crypto posture: the Estate → Crypto screen and the crypto rows inside the
// Frameworks, Criteria and Policies screens. Every assertion is about keeping
// states honest: "not observable" must never read as a failure, layers are
// never merged, and coverage is counts, never a percentage.
const source = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");

class Element {
  constructor(tagName, text = "") {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.attrs = {};
    this.dataset = {};
    this.events = {};
    this._text = text;
    this._classes = new Set();
    this.disabled = false;
    this.hidden = false;
    this.value = "";
  }
  append(...children) {
    for (const raw of children) {
      const c = typeof raw === "string" ? new Element("text", raw) : raw;
      if (c) { c.parent = this; this.children.push(c); }
    }
  }
  replaceChildren(...children) { this._text = ""; this.children = []; this.append(...children); }
  setAttribute(key, value) { this.attrs[key] = String(value); }
  getAttribute(key) { return key in this.attrs ? this.attrs[key] : null; }
  removeAttribute(key) { delete this.attrs[key]; }
  addEventListener(key, fn) { this.events[key] = fn; }
  remove() {}
  click() { return this.events.click?.(); }
  focus() {}
  querySelector() { return null; }
  get className() { return [...this._classes].join(" "); }
  set className(v) { this._classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get classList() {
    const set = this._classes;
    return {add: (...n) => n.forEach(x => set.add(x)), remove: (...n) => n.forEach(x => set.delete(x)),
            contains: n => set.has(n), toggle: (n, f) => { const on = f === undefined ? !set.has(n) : Boolean(f); on ? set.add(n) : set.delete(n); return on; }};
  }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(" "); }
  set textContent(v) { this._text = v; this.children = []; }
}

function find(node, predicate) {
  if (predicate(node)) return node;
  for (const child of node.children || []) {
    const found = find(child, predicate);
    if (found) return found;
  }
  return null;
}

function findAll(node, predicate, acc = []) {
  if (predicate(node)) acc.push(node);
  for (const child of node.children || []) findAll(child, predicate, acc);
  return acc;
}

const hasClass = name => node => node.classList?.contains?.(name);

function app(responses = {}, hash = "") {
  const calls = [];
  const doc = {
    body: new Element("body"), documentElement: new Element("html"), activeElement: null,
    getElementById: () => new Element("div"),
    querySelector: () => null, querySelectorAll: () => [],
    addEventListener() {},
    createElement: tag => new Element(tag),
    createElementNS: (_, tag) => new Element(tag),
    createTextNode: text => new Element("text", text),
  };
  const context = vm.createContext({
    Node: Element, FormData, Blob, Intl, URLSearchParams, document: doc,
    URL: {createObjectURL: () => "blob:x", revokeObjectURL() {}},
    setTimeout: fn => fn(), location: {hash},
    sessionStorage: {getItem: () => null, setItem() {}},
    localStorage: {getItem: () => null, setItem() {}},
    window: {addEventListener() {}},
    async fetch(path, opts = {}) {
      calls.push({path, opts});
      const value = typeof responses === "function" ? responses(path, opts) : responses[path];
      if (value === undefined) throw new Error(`Unexpected request: ${path}`);
      if (typeof value.status === "number") {
        return {ok: false, status: value.status, statusText: "Error", json: async () => ({detail: value.detail})};
      }
      return {ok: true, headers: {get: () => "application/json"}, json: async () => value};
    },
  });
  vm.runInContext(source, context);
  return {context, calls};
}

const CORE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "chroma"}, {store_id: "cold", kind: "chroma"}]},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
};

const layer = (id, title, headline, text, counts, rows) => ({layer: id, title, headline, text,
  counts, rows, basis: "observed", collections_with_exposure: headline === "exposure" ? ["docs"] : []});

const STATEMENT = {
  layers: [
    layer("transport", "Transport", "unknown", "Transport: 1 could not be established, 1 verified",
          {unknown: 1, verified: 1}, 2),
    layer("storage", "At rest", "not_observable", "At rest: not observable for Chroma", {not_observable: 1}, 1),
    layer("data", "Field and data", "exposure", "Field and data: 1 exposure observed, 2 not applicable",
          {exposure: 1, not_applicable: 2}, 3),
    layer("retrieval", "Retrieval", "not_checked", "Retrieval: not checked (opt-in probe not requested)",
          {not_checked: 1}, 1),
  ],
  totals: {}, by_basis: {observed: 4, declared: 0, unknown: 2, not_checked: 1}, rows: 7,
  outside_connector: ["Cloud KMS / Key Vault configuration"],
  text: "Transport: 1 could not be established, 1 verified · At rest: not observable for Chroma",
  note: "Counts are rows.",
};

const MODEL = {store_id: "prod", audit_id: "audit-7", assessed_at: "2026-09-20T10:00:00Z",
  layers: [], coverage: {collections_total: 1, at_rest: {unknown: 1}, statement: STATEMENT},
  out_of_scope: [], statements: [], drift: {compared: false}, regulatory: []};

test("the coverage statement shows each layer's headline, never a mixed layer as verified", () => {
  const {context} = app(CORE);
  const node = context.cryptoCoveragePanel(MODEL, () => {});
  const cards = findAll(node, hasClass("crypto-cov-card")).filter(c => c.dataset.layer);
  assert.deepEqual(cards.map(c => c.dataset.layer), ["transport", "storage", "data", "retrieval"]);
  const transport = cards[0];
  assert.equal(transport.dataset.bucket, "unknown", "one verified row does not make the layer verified");
  assert.match(transport.textContent, /Not established/);
  assert.doesNotMatch(find(transport, hasClass("crypto-cov-chip")).textContent, /Verified/);
  assert.match(cards[1].textContent, /Not observable for Chroma/);
  assert.match(cards[3].textContent, /opt-in probe not requested/);
  // What the connector cannot see is not drawn as a fifth layer (removed at the user's request).
  assert.doesNotMatch(node.textContent, /Cloud KMS|outside the connector/i);
  assert.match(node.textContent, /Not checked\s+1/);
  assert.doesNotMatch(node.textContent, /%/);
});

test("a card opens its layer", () => {
  const {context} = app(CORE);
  const opened = [];
  const node = context.cryptoCoveragePanel(MODEL, id => opened.push(id));
  const tiles = findAll(node, hasClass("crypto-cov-card"));
  tiles[2].click();
  tiles[4].click();
  assert.deepEqual(opened, ["data", "all"], "the last tile shows every layer");
});

test("a server without the statement says so instead of guessing", () => {
  const {context} = app(CORE);
  const node = context.cryptoCoveragePanel({...MODEL, coverage: {}}, () => {});
  assert.match(node.textContent, /does not summarise crypto coverage/);
  assert.equal(findAll(node, hasClass("crypto-cov-card")).length, 0);
});

test("the estate matrix says never assessed, and picking a store opens it", () => {
  const {context} = app(CORE);
  const picked = [];
  const node = context.cryptoEstateMatrix({stores: [
    {store_id: "prod", kind: "chroma", state: "assessed", statement: STATEMENT, gate: {decision: "block"}},
    {store_id: "cold", kind: "chroma", state: "never_assessed"},
  ]}, "", id => picked.push(id));
  const rows = findAll(node, hasClass("crypto-estate-row"));
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /Exposure observed/);
  assert.match(rows[0].textContent, /Block/);
  assert.match(rows[1].textContent, /Never assessed/);
  assert.match(rows[1].textContent, /not a clean result/);
  find(rows[0], n => n.tagName === "BUTTON").click();
  assert.deepEqual(picked, ["prod"]);
});

test("identical rows across collections are one line; store-scope rows never merge", () => {
  const {context} = app(CORE);
  const row = (collection, reason = "No PAN in any form was found.") => ({check: "pan_representation",
    collection, outcome: "passed", crypto_state: "not_applicable", reason, details: {}});
  const groups = context.cryptoGroupRows([row("a"), row("b"), row("c", "2 full PANs."),
    {check: "at_rest_encryption", collection: null, outcome: "unsupported", crypto_state: "not_observable"},
    {check: "at_rest_encryption", collection: null, outcome: "unsupported", crypto_state: "not_observable"}]);
  assert.deepEqual(Array.from(groups, g => g.members.length), [2, 1, 1, 1]);
});

test("a route the server lacks is named as an older server, with a retry", async () => {
  const {context} = app({...CORE, "/admin/home": {status: 404, detail: "Not Found"},
    "/runtime/alerts/stats": {total: 0}, "/admin/history/trend?days=30": {trend: [], available: true},
    "/admin/estate": {stores: []}});
  const node = await context.renderOverview();
  const text = node.textContent;
  assert.match(text, /This server does not serve \/admin\/home/);
  assert.match(text, /older checkout than this console/);
  assert.match(text, /not a list of nothing to do/);
  assert.doesNotMatch(text, /Nothing needs you/);
  assert.ok(findAll(node, n => n.tagName === "BUTTON").some(b => /Retry/.test(b.textContent)));
});

test("a finished run knows where its saved result is", () => {
  const {context} = app(CORE);
  const audit = context.runOpenTarget({kind: "audit", status: "succeeded", resource: "prod", result: {id: "audit-9"}});
  assert.equal(audit.label, "View audit results");
  audit.go();
  assert.equal(context.location.hash, "#/history?audit=audit-9&store=prod");
  assert.equal(context.runOpenTarget({kind: "audit", status: "failed", resource: "prod"}), null);
  assert.equal(context.runOpenTarget({kind: "audit", status: "succeeded", result: {}}), null,
    "an audit that was not saved has no page to open");
});
