// Renders every registered view against stubbed API responses, reporting the
// ones that throw. Shared by the parity gate.
import { readFile } from "node:fs/promises";
import vm from "node:vm";

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
    this.checked = false;
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

// Deliberately generous: a screen must render against a well-formed but empty
// backend. Screens that need richer data are covered by their own tests.
const RESPONSES = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant", tenant_field: "tenant_id"}]},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
  "/admin/history": {jobs: [], stats: {total_findings: 0, by_severity: {}}},
  "/admin/history/audits": {audits: []},
  "/admin/jobs": {jobs: []},
  "/admin/allowlist": {rules: []},
  "/admin/suppressions": {suppressions: []},
  "/admin/detectors": {bulk_volume: {}, collection_sweep: {}, enumeration: {}, rate_baseline: {}, cooldown_s: 60},
  "/admin/alerting": {webhooks: [], min_severity: "high"},
  "/admin/dsar": {requests: []},
  "/runtime/alerts": {alerts: []},
  "/runtime/alerts/stats": {total: 0},
  "/audit-log": {entries: [], verified: true},
  "/version": {version: "1.0", detection_version: "1.0",
               detectors: ["bulk_volume", "enumeration"]},
  "/healthz": {status: "ok"},
  "/readyz": {status: "ok", checks: {}},
  "/stores": {stores: []},
};

function match(path) {
  const base = path.split("?")[0];
  if (RESPONSES[base] !== undefined) return RESPONSES[base];
  if (base.startsWith("/stores/")) return {findings: [], collections: [], schema: {}, stats: {}};
  if (base.startsWith("/admin/history/")) return {findings: [], jobs: []};
  return {};
}

export async function renderAll() {
  const failures = [];
  const context = vm.createContext({
    Node: Element, FormData, Blob, Intl, URLSearchParams,
    URL: {createObjectURL: () => "blob:x", revokeObjectURL() {}},
    setTimeout: fn => fn(), location: {hash: "#/overview"},
    sessionStorage: {getItem: () => null, setItem() {}},
    localStorage: {getItem: () => null, setItem() {}},
    window: {addEventListener() {}},
    document: {
      body: new Element("body"),
      documentElement: new Element("html"),
      activeElement: null,
      getElementById: () => new Element("div"),
      querySelector: () => null,
      querySelectorAll: () => [],
      addEventListener() {},
      createElement: tag => new Element(tag),
      createElementNS: (_, tag) => new Element(tag),
      createTextNode: text => new Element("text", text),
    },
    async fetch(path) {
      return {ok: true, headers: {get: () => "application/json"}, json: async () => match(path)};
    },
  });
  vm.runInContext(source, context);
  const ids = vm.runInContext("Object.keys(views)", context);
  for (const id of ids) {
    context.location.hash = `#/${id}`;
    try {
      const node = await vm.runInContext(`views[${JSON.stringify(id)}][3]()`, context);
      if (!node || !node.tagName) failures.push(`${id}: rendered nothing`);
    } catch (e) {
      failures.push(`${id}: ${e.message}`);
    }
  }
  return failures;
}
