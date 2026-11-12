import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// From an observation to the chunk behind it and the rule that says it
// matters. Every assertion here is about what the console claims: masked by
// default, revealed only with a reason, and a trace that names its own joins.

const source = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");

class Element {
  constructor(tagName, text = "") {
    this.tagName = tagName.toUpperCase(); this.children = []; this.attrs = {}; this.dataset = {};
    this.events = {}; this._text = text; this._classes = new Set(); this.disabled = false;
    this.hidden = false; this.value = "";
  }
  append(...children) { for (const raw of children) { const c = typeof raw === "string" ? new Element("text", raw) : raw; if (c) { c.parent = this; this.children.push(c); } } }
  replaceChildren(...children) { this._text = ""; this.children = []; this.append(...children); }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(k, fn) { this.events[k] = fn; }
  remove() {}
  click() { return this.events.click?.(); }
  focus() {}
  querySelector(sel) { return find(this, n => sel.startsWith("#") ? n.attrs.id === sel.slice(1) : n._classes.has(sel.slice(1))); }
  get className() { return [...this._classes].join(" "); }
  set className(v) { this._classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get classList() { const set = this._classes; return {add: (...n) => n.forEach(x => set.add(x)), remove: (...n) => n.forEach(x => set.delete(x)), contains: n => set.has(n)}; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(" "); }
  set textContent(v) { this._text = v; this.children = []; }
}
function find(node, predicate) {
  if (predicate(node)) return node;
  for (const child of node.children || []) { const f = find(child, predicate); if (f) return f; }
  return null;
}
function findAll(node, predicate, acc = []) {
  if (predicate(node)) acc.push(node);
  for (const child of node.children || []) findAll(child, predicate, acc);
  return acc;
}

function app(responses = {}, hash = "") {
  const calls = [];
  const body = new Element("body");
  const doc = {
    body, documentElement: new Element("html"), activeElement: null,
    getElementById: id => find(body, n => n.attrs.id === id) || new Element("div"),
    querySelector: sel => body.querySelector(sel), querySelectorAll: () => [],
    addEventListener() {}, createElement: tag => new Element(tag),
    createElementNS: (_, tag) => new Element(tag), createTextNode: t => new Element("text", t),
  };
  const context = vm.createContext({
    Node: Element, FormData, Blob, Intl, URLSearchParams, document: doc,
    URL: {createObjectURL: () => "blob:x", revokeObjectURL() {}},
    // Zero-delay callbacks run now; the 60 s re-mask must not fire mid-test.
    setTimeout: (fn, ms) => { if (!ms) fn(); return 1; }, clearTimeout() {}, location: {hash},
    sessionStorage: {getItem: () => null, setItem() {}},
    localStorage: {getItem: () => null, setItem() {}},
    window: {addEventListener() {}, confirm: () => true},
    async fetch(path, opts = {}) {
      calls.push({path, opts});
      const value = typeof responses === "function" ? responses(path, opts) : responses[path.split("?")[0]] ?? responses[path];
      if (value === undefined) throw new Error(`Unexpected request: ${path}`);
      if (typeof value.status === "number") return {ok: false, status: value.status, statusText: "Error", json: async () => ({detail: value.detail})};
      return {ok: true, headers: {get: () => "application/json"}, json: async () => value};
    },
  });
  vm.runInContext(source, context);
  // `state` is a top-level const, not a global property: reach it through eval.
  const evaluate = code => vm.runInContext(code, context);
  return {context, calls, doc, evaluate};
}

const FINDING = {
  id: "f1", title: "PII detected in collection 'docs'", severity: "high", category: "data_classification",
  store: "file:///tmp/stores/prod", collection: "docs", fingerprint: "fp-1", case: {state: "new"},
  evidence: {
    label_counts: {pii: 2},
    examples: [{chunk_id: "c1", label: "pii", detectors: ["email"],
                spans: [{detector: "email", label: "pii", start: 8, end: 28, preview: "p.****st", surface: "text"}],
                explanations: [{detector: "email", start: 8, end: 28, matched_preview: "p.****st",
                                confidence: "uncertain", counter_signals: []}]},
               {probe_id: "c9", leaked_id: "c7", probe_tenant: "acme", leaked_tenant: "globex"}],
    explanations: [{detector: "email", start: 8, end: 28, matched_preview: "p.****st", confidence: "uncertain", counter_signals: []}],
  },
};

const CORE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "chroma"}]},
  "/admin/policies": {policies: [
    {id: "p1", name: "PII in a collection", template_id: "t1", enabled: true, severity: "high",
     action: "tag", when: {category: "data_classification", requires_label: "pii"}, scope_store: "prod"},
    {id: "p2", name: "Other store only", template_id: "t1", enabled: true, severity: "high",
     action: "tag", when: {category: "data_classification"}, scope_store: "elsewhere"},
  ]},
  "/admin/policy-templates": {templates: [
    {id: "t1", name: "PII in a collection", regulation: "GDPR", when: {category: "data_classification", requires_label: "pii"},
     attribution: {source_text: "Art. 5; Art. 17", sources: [{section: "Art. 17", url: "https://example.test/gdpr"}]}},
    {id: "t2", name: "Any high", regulation: "SOC 2", when: {min_severity: "high"}, attribution: {}},
  ]},
  "/compliance/criteria": {pack: {pack_version: "d1", criteria: 2, frameworks: ["GDPR", "SOC 2"]}, criteria: [
    {criterion_id: "GDPR-ERASURE-01", framework: "GDPR", paraphrase: "Erasure reaches embeddings.",
     technical_checks: ["data_classification"], applicability_questions: ["a", "b"]},
    {criterion_id: "SOC2-CC7.2-ANOMALY-01", framework: "SOC 2", paraphrase: "Anomalies are detected.",
     technical_checks: ["rag_integrity"]},
  ]},
};

const CHUNK_MASKED = {
  store: "prod", collection: "docs", chunk_id: "c1", level: "masked", fetched_at: "2026-09-18T20:00:00+00:00",
  surfaces: [{name: "text", text: "Contact p.****************st today.",
              spans: [{start: 8, end: 28, detector: "email", label: "pii", preview: "p.****st",
                       confidence: "uncertain", confidence_reason: "No measured precision.",
                       counter_signals: [{code: "reserved_domain", detail: "Reserved domain"}],
                       disputed: true, revealed: false}]},
             {name: "metadata.tenant", text: "acme", spans: []}],
  metadata: {tenant: "acme"}, drift: false, recorded_spans: 1, live_spans: 1,
  labels: ["pii"], detectors: ["email"], note: "masked", related_findings: [{id: "f1", title: "PII", severity: "high"}],
};

test("the store id is resolved from the name a connector reports", () => {
  const {context, evaluate} = app(CORE);
  evaluate('state.stores = [{store_id: "prod"}, {store_id: "other"}]');
  assert.equal(context.storeIdFor("prod"), "prod");
  assert.equal(context.storeIdFor("file:///tmp/stores/prod"), "prod");
  assert.equal(context.storeIdFor("something-unregistered"), "something-unregistered");
});

test("a finding's examples yield the chunks a reader can open, leaked ones included", () => {
  const {context} = app(CORE);
  const refs = context.chunkRefs(FINDING);
  assert.deepEqual([...refs.map(r => r.chunkId)], ["c1", "c7"]);
  assert.match(refs[1].role, /leaked to acme/);
});

test("the obligation trace goes finding → policy → template → criterion and scopes by store", async () => {
  const {context, evaluate} = app(CORE);
  await context.loadCore();
  const pack = await context.loadPack();
  const trace = context.obligationTrace(FINDING, {policies: evaluate("state.policies"), templates: evaluate("state.templates"), pack});
  assert.deepEqual([...trace.policies.map(p => p.id)], ["p1"], "the policy scoped to another store does not fire");
  assert.deepEqual([...trace.templates.map(t => t.id)], ["t1"]);
  assert.deepEqual([...trace.criteria.map(c => c.criterion_id)], ["GDPR-ERASURE-01"],
    "joined by framework and the finding's check, so the SOC 2 criterion is out");
  assert.deepEqual([...trace.dormant.map(t => t.id)], ["t2"], "a template that would match but has no policy is named as dormant");
  const view = await context.obligationView(FINDING);
  assert.match(view.textContent, /PII in a collection/);
  assert.match(view.textContent, /Art\. 17/);
  assert.match(view.textContent, /GDPR-ERASURE-01/);
  assert.match(view.textContent, /joined by framework and check name/, "the heuristic join says so");
});

test("the chunk drawer asks for the masked view, marks each match, and needs a reason to reveal", async () => {
  const requests = [];
  const {context, evaluate} = app((path) => {
    requests.push(path);
    if (path.startsWith("/stores/prod/collections/docs/chunks/c1")) {
      return path.includes("reveal=raw") ? {...CHUNK_MASKED, level: "raw", note: "raw"} : CHUNK_MASKED;
    }
    return CORE[path.split("?")[0]];
  });
  evaluate('state.stores = [{store_id: "prod"}]');
  const {body} = await context.openChunk({store: "file:///tmp/stores/prod", collection: "docs", chunkId: "c1", finding: FINDING});
  assert.ok(requests.some(p => p.includes("reveal=masked") && p.includes("finding_id=f1")), "masked first, compared to the finding");
  const marks = findAll(body, n => n.tagName === "MARK");
  assert.equal(marks.length, 1);
  assert.match(marks[0].textContent, /pii · email/, "the tag names label and detector");
  assert.match(body.textContent, /Values are masked/);
  assert.match(body.textContent, /Reserved domain/, "counter-signals sit beside the highlight");
  assert.doesNotMatch(body.textContent, /Metadata\.tenant/i, "a metadata surface with no match is not its own block");
  // Revealing without a reason is refused before any request is made.
  const reveal = find(body, n => n.tagName === "BUTTON" && /Reveal values/.test(n.textContent));
  const before = requests.length;
  reveal.click();
  assert.equal(requests.length, before, "no request without a reason");
  const input = find(body, n => n.tagName === "INPUT");
  input.value = "DSAR review";
  await reveal.click();
  await new Promise(r => setImmediate(r));
  assert.ok(requests.some(p => p.includes("reveal=raw") && p.includes("reason=DSAR+review")));
  assert.match(body.textContent, /Values shown/);
});

test("a chunk that is gone is reported as such, not as an empty chunk", async () => {
  const {context, evaluate} = app((path) => {
    if (path.startsWith("/stores/prod/collections/docs/chunks/")) return {status: 404, detail: "chunk 'c1' is not in 'docs' now. It may have been deleted since the assessment that recorded it."};
    return CORE[path.split("?")[0]];
  });
  evaluate('state.stores = [{store_id: "prod"}]');
  const {body} = await context.openChunk({store: "prod", collection: "docs", chunkId: "c1"});
  assert.match(body.textContent, /may have been deleted/);
  assert.match(body.textContent, /still records what was seen/);
});

test("the finding detail has the five tabs and its chunk tab opens each recorded chunk", async () => {
  const {context, evaluate} = app({
    ...CORE,
    "/admin/findings/f1": {finding: FINDING, case_events: [{at: "2026-09-18T00:00:00Z", actor: "sarah", from_state: "new", to_state: "triaged"}],
                           same_fingerprint: [{id: "f0", job_id: "scan-0", severity: "high", case: {state: "closed"}}]},
  });
  evaluate('state.stores = [{store_id: "prod"}]');
  const {body, show} = await context.openFinding("f1");
  const tabs = findAll(body, n => n.attrs.role === "tab").map(t => t.textContent.trim());
  assert.deepEqual(tabs, ["Summary", "Chunks (2)", "Why", "Obligations", "History"]);
  assert.match(body.textContent, /fp-1/);
  await show("chunks");
  assert.match(body.textContent, /c1/);
  assert.match(body.textContent, /leaked to acme/);
  await show("history");
  assert.match(body.textContent, /sarah/);
  assert.match(body.textContent, /f0/, "the same observation in another run is listed");
});

test("the label matrix counts labelled chunks per collection and never a score", () => {
  const {context, evaluate} = app(CORE);
  evaluate('state.stores = [{store_id: "prod"}]');
  const other = {...FINDING, id: "f2", collection: "other", evidence: {label_counts: {secret: 1}}};
  const matrix = context.labelMatrix([FINDING, other]);
  const text = matrix.textContent;
  assert.match(text, /prod \/ docs/);
  assert.match(text, /prod \/ other/);
  assert.doesNotMatch(text, /\d+%/);
  const cells = findAll(matrix, n => n._classes.has("cell-btn")).map(c => c.textContent);
  assert.deepEqual(cells.sort(), ["1", "2"]);
});

test("live sampling is labelled as not an assessment and pages through the collection", async () => {
  const pages = [
    {chunks: [{chunk_id: "a", labels: ["pii"], detectors: ["email"], matches: 1, preview: "x p.**st", disputed: false}],
     next_offset: 1, exhausted: false, sensitive: 1, note: "Not an assessment."},
    {chunks: [], next_offset: 1, exhausted: true, sensitive: 0, note: "Not an assessment."},
  ];
  const {context} = app((path) => path.includes("/sample") ? pages.shift() : CORE[path.split("?")[0]]);
  const panel = context.liveSamplePanel("prod", "docs", {limit: 1});
  assert.match(panel.textContent, /not an assessment/i);
  const button = find(panel, n => n.tagName === "BUTTON");
  await button.click();
  await new Promise(r => setImmediate(r));
  assert.match(panel.textContent, /1 chunk sampled so far/);
  await button.click();
  await new Promise(r => setImmediate(r));
  assert.match(panel.textContent, /end of collection/);
  assert.equal(button.disabled, true);
});
