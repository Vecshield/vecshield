import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// Exercise the shipped script with a small DOM fixture. This is deliberately
// not a browser, layout, CSP, accessibility, or connector integration test.
const source = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");

// A deliberately small stand-in for the DOM. It carries enough of the real
// contract — attributes, classes, focus, and an active element — to exercise
// focus management and dialog semantics, and nothing more.
let activeDocument = null;

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
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ""; this.children = children; }
  setAttribute(key, value) { this.attrs[key] = String(value); }
  getAttribute(key) { return key in this.attrs ? this.attrs[key] : null; }
  removeAttribute(key) { delete this.attrs[key]; }
  addEventListener(key, fn) { this.events[key] = fn; }
  remove() { this.removed = true; if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); }
  click() { this.clicked = true; return this.events.click?.(); }
  focus() { this.focused = true; if (activeDocument) activeDocument.activeElement = this; }
  get className() { return [...this._classes].join(" "); }
  set className(value) { this._classes = new Set(String(value).split(/\s+/).filter(Boolean)); }
  get classList() {
    const set = this._classes;
    return {
      add: (...names) => names.forEach(n => set.add(n)),
      remove: (...names) => names.forEach(n => set.delete(n)),
      contains: name => set.has(name),
      toggle: (name, force) => {
        const on = force === undefined ? !set.has(name) : Boolean(force);
        on ? set.add(name) : set.delete(name);
        return on;
      },
    };
  }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(" "); }
  set textContent(value) { this._text = value; this.children = []; }
}

function walk(node, visit) {
  for (const child of node.children || []) {
    child.parent = node;
    const found = visit(child) ? child : walk(child, visit);
    if (found) return found;
  }
  return null;
}

function fixture(responses = {}) {
  const calls = [];
  const body = new Element("body");
  const doc = {
    body,
    activeElement: null,
    events: {},
    // Resolve ids against what was actually built, falling back to a detached
    // node for shell elements a unit test never mounts.
    getElementById: id => walk(body, el => el.attrs.id === id) || new Element("div"),
    querySelector: () => null,
    addEventListener(key, fn) { this.events[key] = fn; },
    createElement: tag => new Element(tag),
    createElementNS: (_, tag) => new Element(tag),
    createTextNode: text => new Element("text", text),
  };
  activeDocument = doc;
  const context = vm.createContext({
    Node: Element, FormData, Blob, Intl, URLSearchParams,
    // Views read their state out of the hash, so the harness needs one.
    location: {hash: ""},
    localStorage: {getItem: () => null, setItem() {}},
    URL: {createObjectURL: () => "blob:report", revokeObjectURL() {}},
    setTimeout() {},
    sessionStorage: {getItem: () => null},
    document: doc,
    async fetch(path, opts = {}) {
      calls.push({path, opts});
      const value = typeof responses === "function" ? responses(path, opts) : responses[path];
      if (value instanceof Error) throw value;
      if (value === undefined) throw new Error(`Unexpected request: ${path}`);
      if (value.status) return {ok: false, status: value.status, statusText: "Error", json: async () => ({detail: value.detail})};
      return {ok: true, headers: {get: () => typeof value === "string" ? "text/html" : "application/json"}, json: async () => value, text: async () => value};
    },
  });
  vm.runInContext(source, context);
  return {context, calls, body, doc};
}

const EMPTY_HOME = {
  history_available: true, needs_you: [],
  checked: ["plans_awaiting_approval", "stores_never_assessed"], unavailable: [],
  open_findings: {by_severity: {critical: 0, high: 0, medium: 0, low: 0, info: 0}, total: 0,
                  stores: 0, stores_assessed: 1, stores_never_assessed: 0, suppressed: 0, note: ""},
  stores: {total: 1, assessed: 1, never_assessed: 0, partial_coverage: 0}, note: "",
};

function coreResponses(extra = {}) {
  return {
    "/admin/stores": {stores: []}, "/admin/policy-templates": {templates: []},
    "/admin/policies": {policies: []}, "/version": {},
    "/admin/home": EMPTY_HOME,
    "/admin/estate": {stores: [], probed: false, note: ""},
    "/admin/history/trend?days=30": {trend: [], available: true},
    "/admin/history/audits?limit=200": {audits: []},
    "/runtime/alerts/stats": {total: 0}, ...extra,
  };
}

function findNode(node, predicate) {
  if (predicate(node)) return node;
  for (const child of node.children) {
    const found = findNode(child, predicate);
    if (found) return found;
  }
}

for (const status of [401, 403, 500]) {
  test(`overview preserves an unreadable inbox (${status})`, async () => {
    const {context} = fixture(coreResponses({"/admin/home": {status, detail: "History unavailable"}}));
    const output = (await context.renderOverview()).textContent;
    assert.match(output, /not a list of nothing to do/);
    assert.doesNotMatch(output, /Nothing needs you/, "an unread inbox is not an empty one");
    assert.doesNotMatch(output, /Critical open\s+0/);
    assert.match(output, /Runtime alerts\s+0/);
    assert.match(output, /Stores\s+Unknown/, "store counts that could not be read say so");
    if (status !== 500) assert.match(output, /Access restricted/);
  });
}

test("disabled history and failed runtime alerts are not empty data", async () => {
  const {context} = fixture(coreResponses({
    "/admin/home": {history_available: false, needs_you: [], checked: [], unavailable: [],
                    open_findings: null, stores: {total: 1, assessed: null, never_assessed: null},
                    note: "Counts only. No scan history is configured, so nothing else can be counted."},
    "/runtime/alerts/stats": new Error("offline"),
  }));
  const output = (await context.renderOverview()).textContent;
  assert.match(output, /No scan history is configured/);
  assert.match(output, /Open findings are unavailable/);
  assert.match(output, /Runtime alerts\s+Unknown/);
  assert.doesNotMatch(output, /Nothing needs you/);
  assert.doesNotMatch(output, /Critical open\s+0/);
});

test("an empty inbox and zero open findings are real, with the coverage caveat beside them", async () => {
  const {context} = fixture(coreResponses());
  const output = (await context.renderOverview()).textContent;
  assert.match(output, /Nothing needs you right now/);
  assert.match(output, /Checked: plans awaiting approval, stores never assessed/);
  assert.match(output, /Critical open\s+0/);
  assert.match(output, /Zero findings does not establish complete assessment coverage/);
  assert.doesNotMatch(output, /%/);
  assert.equal(context.observedNumber(undefined), "Unknown");
  assert.equal(context.observedNumber(null), "Unknown");
  assert.equal(context.observedNumber(0), "0");
});

test("an inbox that does not say what it checked is not read as empty", async () => {
  const {context} = fixture(coreResponses({"/admin/home": {history_available: true}}));
  const output = (await context.renderOverview()).textContent;
  assert.match(output, /The inbox came back incomplete/);
  assert.doesNotMatch(output, /Nothing needs you/);
});

test("unavailable policy configuration is not presented as nothing to do", async () => {
  const {context} = fixture(coreResponses({"/admin/policies": {status: 403, detail: "forbidden"}}));
  assert.match((await context.renderOverview()).textContent, /Policies could not be read/);
});

test("jobs with identical timestamps preserve independent identities", () => {
  const {context} = fixture();
  const jobs = [
    {id: "legacy-a", created_at: "2026-09-17T00:00:00Z"},
    {id: "legacy-b", created_at: "2026-09-17T00:00:00Z"},
    {id: "child", audit_id: "audit-1", created_at: "2026-09-17T00:00:00Z"},
  ];
  const rows = context.archiveRows(jobs);
  assert.equal(rows.length, 3);
  assert.equal(rows[0].id, "legacy-a");
  assert.equal(rows[1].id, "legacy-b");
  assert.equal(rows[2].audit_id, "audit-1");
});

test("zero findings with missing or partial coverage remains inconclusive", () => {
  const {context} = fixture();
  assert.match(context.resultCoverage({}).textContent, /Coverage: unknown.*zero findings is inconclusive/);
  const result = context.auditSummary({id: "a1", status: "partial", summary: {}, jobs: [],
    coverage: {status: "partial", complete: false},
    check_outcomes: [{check: "integrity", outcome: "unsupported", reason: "Content cannot be enumerated", coverage: {status: "unavailable"}}],
  }).textContent;
  assert.match(result, /Audit ID: a1/);
  assert.match(result, /Coverage: partial/);
  assert.match(result, /unsupported\s+unavailable\s+Content cannot be enumerated/);
  assert.match(result, /zero findings is inconclusive/);
});

test("job coverage uses nested stats and requires an explicit complete flag", () => {
  const {context} = fixture();
  assert.match(context.resultCoverage({stats: {coverage: {status: "complete", complete: true}}}).textContent,
    /Complete for the declared assessment scope/);
  assert.match(context.resultCoverage({coverage: {status: "complete"}}).textContent,
    /zero findings is inconclusive/);
});

test("saved report downloads request the exact audit snapshot without starting a scan", async () => {
  const path = "/stores/store%2Fa/report?audit_id=audit%20one";
  const {context, calls, body} = fixture({[path]: "<!doctype html><title>Saved audit</title>"});
  await context.downloadAuditReport("store/a", "audit one");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, path);
  assert.equal(calls[0].opts.method, undefined);
  const link = body.children[0];
  assert.equal(link.attrs.download, "vecshield-audit-audit_one.html");
  assert.equal(link.clicked, true);
});

test("saved audits paginate by parent ID and preserve store filtering", async () => {
  const {context, calls} = fixture({
    "/admin/history/audits?limit=50&offset=0&store_id=one": {
      audits: [{id: "a1", store_id: "one", status: "partial", coverage: {status: "partial"}}], has_more: true, next_offset: 50,
    },
    "/admin/history/audits?limit=50&offset=50&store_id=one": {
      audits: [{id: "a2", store_id: "one", status: "completed", coverage: {status: "complete"}}], has_more: false,
    },
  });
  const panel = await context.savedAuditsPanel("one");
  assert.match(panel.textContent, /one\s+partial.*a1/s);
  assert.match(panel.textContent, /1 of 1 loaded · more to load/);
  const more = findNode(panel, node => node.tagName === "BUTTON" && node.textContent === "Load more audits");
  await more.click();
  assert.match(panel.textContent, /one\s+partial.*a1/s);
  assert.match(panel.textContent, /one\s+complete.*a2/s);
  assert.match(panel.textContent, /2 of 2 loaded/);
  assert.equal(more.hidden, true);
  assert.equal(calls.length, 2);
});

test("history permission errors remain visible alongside accessible legacy jobs", async () => {
  const {context} = fixture({
    "/admin/history/audits?limit=50&offset=0": {status: 403, detail: "forbidden"},
    "/admin/history?limit=500": {jobs: [{id: "legacy-a", finding_count: 0}]},
  });
  const output = (await context.scanArchivePanel()).textContent;
  assert.match(output, /Saved audits unavailable: Access restricted/);
  assert.match(output, /legacy-a/);
  assert.match(output, /legacy jobs have no known parent/);
});

test("a template card shows its citation and that applicability is unconfirmed", () => {
  const {context} = fixture();
  const card = context.templateCard({
    id: "hipaa-phi", name: "PHI in a collection (§164.312)", severity: "high",
    regulation: "HIPAA", description: "Content matching health-data patterns.",
    applicability: {covered_entity_or_business_associate: "requires_confirmation"},
    attribution: {framework: "HIPAA", source_text: "45 CFR 164.312",
                  reviewed: false, unresolved: [], sources: []},
  });
  assert.match(card.textContent, /45 CFR 164\.312/);
  assert.match(card.textContent, /Draft mapping · not reviewed by a lawyer/);
  assert.match(card.textContent, /Not sure yet whether it applies \(covered entity or business associate\)/);
  assert.match(card.textContent, /not a legal conclusion/);
});

test("a template with no unconfirmed applicability carries no warning", () => {
  const {context} = fixture();
  const card = context.templateCard({
    id: "sec-secrets", name: "Secrets never embedded", severity: "critical",
    regulation: "General", applicability: {},
    attribution: {source_text: "VecShield vector-store security baseline",
                  reviewed: false, unresolved: [], sources: []},
  });
  assert.doesNotMatch(card.textContent, /Applicability unconfirmed/);
});

test("an unresolved source reference is shown instead of a silent citation", () => {
  const {context} = fixture();
  const card = context.templateCard({
    id: "broken", name: "Broken", severity: "low", regulation: "GDPR",
    applicability: {},
    attribution: {source_text: "Art. 32", reviewed: false,
                  unresolved: ["not-a-source"], sources: []},
  });
  assert.match(card.textContent, /source not confirmed: not-a-source/);
});

test("the evidence block separates what a rule detects from what it cannot establish", () => {
  const {context} = fixture();
  const block = context.evidenceBlock({evidence: {
    detects: "Digit sequences passing a card-number check.",
    does_not_establish: "That the value is a live PAN.",
    confidence: "pattern_match", requires_reviewer_decision: true,
    limitations: ["Only the inspected scope is covered."],
  }});
  assert.match(block.textContent, /Digit sequences passing a card-number check/);
  assert.match(block.textContent, /That the value is a live PAN/);
  assert.match(block.textContent, /Reviewer decision Required/);
  assert.match(block.textContent, /Only the inspected scope is covered/);
});

test("a licensed source is linked by locator and never claims a retrieval", () => {
  const {context} = fixture();
  const block = context.sourceBlock({attribution: {sources: [{
    id: "pci-dss-req-3", section: "Requirement 3", issuer: "PCI Security Standards Council",
    title: "PCI DSS Requirement 3", edition: "v4.0.1", lifecycle: "draft",
    url: "https://www.pcisecuritystandards.org/document_library/",
    redistributable: false, verified: false,
  }]}});
  assert.match(block.textContent, /Requirement 3/);
  assert.match(block.textContent, /Licensed standard: linked by locator, text not reproduced/);
  assert.match(block.textContent, /Provision text not retrieved by this build/);
  assert.doesNotMatch(block.textContent, /regulatory_reviewed/);
});

test("a template with no source record says so rather than showing nothing", () => {
  const {context} = fixture();
  assert.match(context.sourceBlock({attribution: {sources: []}}).textContent,
               /No maintained source record/);
});
