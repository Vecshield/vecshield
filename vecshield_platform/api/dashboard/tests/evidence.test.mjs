import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// Phase 4: the surfaces that report what was checked, what was found, and what
// was never measured. Every assertion here is about honesty, not layout.
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

function app(responses = {}, hash = "") {
  const calls = [];
  const body = new Element("body");
  const doc = {
    body, documentElement: new Element("html"), activeElement: null, events: {},
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
      if (value instanceof Error) throw value;
      if (value === undefined) throw new Error(`Unexpected request: ${path}`);
      if (typeof value.status === "number") {
        return {ok: false, status: value.status, statusText: "Error", json: async () => ({detail: value.detail})};
      }
      return {ok: true, headers: {get: () => "application/json"}, json: async () => value};
    },
  });
  vm.runInContext(source, context);
  return {context, calls, doc};
}

// -------------------------------------------------------------- trend chart ---

test("a day with no run draws no bar and is named as unmeasured", () => {
  const {context} = app();
  const today = new Date().toISOString().slice(0, 10);
  const chart = context.trendChart([{day: today, store: "prod", max_severity: "high", findings: 4}],
                                   {days: 7});
  assert.match(chart.textContent, /1 of 7 days recorded a run/);
  assert.match(chart.textContent, /Days with no run are hatched, not zero/);
  // Six unmeasured days, each stated as its own row in the data table.
  const unmeasured = findAll(chart, n => n.tagName === "TR" && /no run/.test(n.textContent));
  assert.equal(unmeasured.length, 6);
  assert.ok(unmeasured.every(row => /not measured/.test(row.textContent)));
});

test("the trend chart is named for assistive technology and offers its data", () => {
  const {context} = app();
  const chart = context.trendChart([], {days: 30});
  const svg = find(chart, n => n.tagName === "SVG");
  assert.equal(svg.attrs.role, "img");
  assert.match(svg.attrs["aria-label"], /Findings recorded per day over the last 30 days/);
  assert.ok(find(chart, n => n.tagName === "TITLE"), "an SVG title element");
  assert.ok(find(chart, n => n.tagName === "TABLE"), "a data table alternative");
  assert.match(chart.textContent, /0 of 30 days recorded a run/);
});

test("findings from several stores on one day are summed, not overwritten", () => {
  const {context} = app();
  const day = new Date().toISOString().slice(0, 10);
  const chart = context.trendChart([
    {day, store: "a", max_severity: "low", findings: 2},
    {day, store: "b", max_severity: "critical", findings: 3},
  ], {days: 1});
  assert.match(chart.textContent, /5/, "2 + 3 findings");
  assert.match(chart.textContent, /CRITICAL/, "the day takes its highest severity");
});

// ----------------------------------------------------------- coverage chart ---

test("the unmeasured segment is always stated, even when it is everything", () => {
  const {context} = app();
  const chart = context.coverageChart({
    status: "unknown", complete: false, checks_expected: 4, checks_complete: 0,
    outcomes: {passed: 0, failed: 0, inconclusive: 0, skipped: 3, unsupported: 1, error: 0},
  });
  assert.match(chart.textContent, /0 complete/);
  assert.match(chart.textContent, /4 unmeasured of 4 checks/);
  assert.match(chart.textContent, /never measured/i);
});

test("partial coverage is distinguished from complete coverage", () => {
  const {context} = app();
  const chart = context.coverageChart({
    status: "partial", complete: false, checks_expected: 5, checks_complete: 2,
    outcomes: {passed: 2, failed: 0, inconclusive: 2, skipped: 1, unsupported: 0, error: 0},
  });
  assert.match(chart.textContent, /2 complete · 2 partial · 1 unmeasured of 5 checks/);
  assert.match(chart.textContent, /absence of a finding proves nothing/);
});

// ------------------------------------------------------------------ heatmap ---

test("a collection nobody inspected is hatched, not drawn as clean", () => {
  const {context} = app();
  const chart = context.heatmapChart(
    [{collection: "docs", severity: "high"}],
    {inspected: ["docs"], scope: ["docs", "archive"]});
  assert.match(chart.textContent, /Hatched rows were never inspected/);
  const rows = findAll(chart, n => n.tagName === "TR");
  const archive = rows.find(r => /archive/.test(r.textContent));
  assert.ok(archive, "the uninspected collection still gets a row");
  assert.match(archive.textContent, /not inspected/);
  const docs = rows.find(r => /docs/.test(r.textContent));
  assert.match(docs.textContent, /yes/);
});

test("store-scope findings are counted, not hatched as never inspected", () => {
  const {context} = app();
  const chart = context.heatmapChart(
    [{severity: "critical"}, {severity: "critical"}, {collection: "docs", severity: "high"}],
    {inspected: ["docs"], scope: ["docs"]});
  const rows = findAll(chart, n => n.tagName === "TR");
  const store = rows.find(r => /\(store\)/.test(r.textContent));
  assert.ok(store, "findings without a collection get the store row");
  assert.match(store.textContent, /2/);
  assert.match(store.textContent, /yes/);
  assert.doesNotMatch(store.textContent, /not inspected/);
});

test("an empty heatmap says nothing was inspected rather than drawing nothing", () => {
  const {context} = app();
  assert.match(context.heatmapChart([], {}).textContent, /No collections were inspected/);
});

// ------------------------------------------------------------------ overview ---

const OVERVIEW = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"}, {store_id: "cold", kind: "chroma"}]},
  "/admin/policies": {policies: [{id: "p1"}]},
  "/admin/policy-templates": {templates: []},
  "/version": {},
  "/runtime/alerts/stats": {total: 2},
  "/admin/home": {
    history_available: true,
    needs_you: [
      {kind: "crypto_gate_blocks", title: "Stores the crypto gate would block", count: 1,
       target: {view: "crypto", params: {store: "prod"}}, stores: ["prod"]},
      {kind: "stores_never_assessed", title: "Stores never assessed", count: 1,
       target: {view: "assess", params: {store: "cold"}}, stores: ["cold"]},
    ],
    checked: ["crypto_gate_blocks", "stores_never_assessed", "exceptions_expired"],
    unavailable: [],
    open_findings: {by_severity: {critical: 1, high: 2, medium: 0, low: 0, info: 0}, total: 3,
                    stores: 1, stores_assessed: 1, stores_never_assessed: 1, suppressed: 2, note: ""},
    stores: {total: 2, assessed: 1, never_assessed: 1, partial_coverage: 1}, note: "",
  },
  "/admin/history/trend?days=30": {trend: [], available: true},
  "/admin/estate": {stores: [
    {store_id: "prod", kind: "qdrant", last_assessed: new Date().toISOString(),
     coverage: {status: "partial", complete: false}, findings: {high: 2},
     findings_total: 2, history_available: true, probe: {probed: false}},
    {store_id: "cold", kind: "chroma", last_assessed: null, coverage: null,
     findings: {}, findings_total: 0, history_available: true, probe: {probed: false}},
  ], probed: false, note: ""},
};

test("the overview leads with what needs you, not what exists", async () => {
  const {context} = app(OVERVIEW);
  const node = await context.renderOverview();
  const out = node.textContent;
  assert.match(out, /Needs you/);
  assert.ok(out.indexOf("Needs you") < out.indexOf("Open findings"), "the inbox comes first");
  // Each item is a count, what it is, and a way to get there.
  const rows = findAll(node, n => n.className === "inbox-row");
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /1\s*Stores the crypto gate would block\s*prod/);
  const open = find(rows[0], n => n.tagName === "BUTTON");
  open.click();
  assert.equal(context.location.hash, "#/crypto?store=prod", "Open goes to the target, with its store");
  assert.match(out, /Also checked, nothing waiting: expired exceptions/);
});

test("open findings are distinct, from the latest audit, not run totals", async () => {
  const {context} = app(OVERVIEW);
  const out = (await context.renderOverview()).textContent;
  assert.match(out, /Critical open\s+1/);
  assert.match(out, /High open\s+2/);
  assert.match(out, /Distinct findings from each store\'s latest audit\. 1 store never assessed, which is not zero\./);
  // The long explanation is folded away; the caveat that changes the numbers is not.
  assert.match(out, /About these numbers\s+Counted from the latest audit of 1 store; 1 store never assessed, which is not zero; 2 suppressed, counted apart/);
  assert.match(out, /Zero findings does not establish complete assessment coverage/);
  assert.doesNotMatch(out, /Recorded findings by severity/, "run-inflated totals are gone from the overview");
});

test("a store never assessed reads as never, never as zero findings", async () => {
  const {context} = app(OVERVIEW);
  const out = (await context.renderOverview()).textContent;
  assert.match(out, /Estate posture/);
  assert.match(out, /Never assessed/);
  assert.match(out, /Coverage of that run/);
});

test("with nothing assessed the open-finding cards are blank, not a reassuring zero", async () => {
  const home = OVERVIEW["/admin/home"];
  const {context} = app({...OVERVIEW, "/admin/home": {...home,
    open_findings: {...home.open_findings, stores_assessed: 0,
                    by_severity: {critical: 0, high: 0, medium: 0, low: 0, info: 0}}}});
  const out = (await context.renderOverview()).textContent;
  assert.match(out, /Critical open\s+—\s+Nothing assessed yet/);
  assert.doesNotMatch(out, /Critical open\s+0/);
});

test("an unreadable estate is said out loud rather than shown as an empty estate", async () => {
  const {context} = app({...OVERVIEW, "/admin/estate": {status: 403, detail: "forbidden"}});
  const out = (await context.renderOverview()).textContent;
  assert.match(out, /estate summary could not be read/);
  assert.doesNotMatch(out, /No stores are registered/);
});

test("an unreadable policy set is surfaced rather than counted as none", async () => {
  const {context} = app({...OVERVIEW, "/admin/policies": {status: 403, detail: "forbidden"}});
  const out = (await context.renderOverview()).textContent;
  assert.match(out, /Policies could not be read/);
});

test("the trend uses per-severity counts when the server sends them, with its note", async () => {
  const today = new Date().toISOString().slice(0, 10);
  const {context} = app({...OVERVIEW, "/admin/history/trend?days=30": {available: true,
    note: "Findings recorded per store per day, counted across every run that day.",
    trend: [{day: today, store: "prod", max_severity: "critical", findings: 5,
             by_severity: {critical: 1, high: 3, medium: 1, low: 0, info: 0}}]}});
  const node = await context.renderOverview();
  assert.match(node.textContent, /counted across every run that day/);
  const fills = findAll(node, n => String(n.attrs?.class || "").startsWith("bar sev-fill"))
    .map(n => n.attrs.class);
  assert.deepEqual(fills.sort(), ["bar sev-fill-critical", "bar sev-fill-high", "bar sev-fill-medium"]);
  assert.match(node.textContent, /Each bar is split by severity/);
});

test("an unavailable trend is said out loud, not drawn as a flat line", async () => {
  const {context} = app({...OVERVIEW,
    "/admin/history/trend?days=30": {trend: [], available: false, message: "history disabled"}});
  const out = (await context.renderOverview()).textContent;
  assert.match(out, /Trend history is unavailable|history disabled/);
});

// ------------------------------------------------------------------ criteria ---

const PACK = {
  pack: {pack_version: "draft-1", criteria: 2, regulatory_review: null},
  criteria: [
    {criterion_id: "HIPAA-1", framework: "HIPAA", paraphrase: "Access is limited.",
     sources: [{section: "45 CFR 164.312(a)(1)"}], manual_evidence: ["access_review_record"]},
    {criterion_id: "GDPR-1", framework: "GDPR", paraphrase: "Erasure reaches embeddings.",
     sources: [{section: "Art. 17"}], manual_evidence: ["erasure_procedure"]},
  ],
};

const ASSESSMENT = {
  criterion_id: "HIPAA-1", framework: "HIPAA", status: "not_assessed",
  applicability: {covered_entity: "requires_confirmation", handles_ephi: "yes"},
  applicability_status: "requires_confirmation",
  technical_result: "not_run", technical_coverage: "unknown",
  evidence_sufficiency: "missing", missing_evidence: ["access_review_record"],
  observations: [], gaps: ["Required evidence is missing: access_review_record"],
  limitations: ["A probe samples."], reviewer: null,
  rationale: "Applicability is unconfirmed; this criterion has neither been satisfied nor breached.",
};

test("a criterion shows its four inputs as four separate fields", () => {
  const {context} = app();
  const card = context.criterionCard(ASSESSMENT, {store: "prod", redraw: () => {}});
  const labels = findAll(card, n => n.className === "metric-k").map(n => n.textContent.trim());
  assert.deepEqual(labels, ["Applies?", "Check result", "Evidence status", "Reviewer's decision"]);
  assert.match(card.textContent, /Not sure yet/, "unanswered is never 'no'");
  assert.match(card.textContent, /Not run/);
  assert.match(card.textContent, /coverage unknown/);
  assert.match(card.textContent, /No decision recorded/);
});

test("a criterion never renders a single merged verdict badge", () => {
  const {context} = app();
  const card = context.criterionCard({...ASSESSMENT, status: "satisfied_for_scope",
    reviewer: {reviewer: "dpo@example.test"}}, {store: "prod", redraw: () => {}});
  // The status is present, but so are all four inputs that produced it.
  assert.match(card.textContent, /Met for this store \(reviewer\)/);
  assert.equal(findAll(card, n => n.className === "metric-k").length, 4);
  assert.match(card.textContent, /dpo@example\.test/);
});

test("unanswered applicability offers the question, not a default answer", () => {
  const {context} = app();
  const card = context.criterionCard(ASSESSMENT, {store: "prod", redraw: () => {}});
  const button = find(card, n => n.tagName === "BUTTON" && /^\s*Answer \d+ question/.test(n.textContent));
  assert.ok(button, "the unanswered question is actionable");
  assert.match(button.textContent, /Answer 1 question\b/, "one question outstanding, not two");
});

test("observations open as check outcomes, and their absence is stated", () => {
  const {context, doc} = app();
  context.observationsModal(ASSESSMENT);
  assert.match(doc.body.textContent, /recorded nothing for this criterion's checks/);
  assert.match(doc.body.textContent, /Not run/);
});

test("the criteria screen refuses to evaluate without a saved audit", async () => {
  const {context} = app({
    "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"}]},
    "/admin/policies": {policies: []}, "/admin/policy-templates": {templates: []},
    "/compliance/criteria": PACK,
    "/stores/prod/criteria": {status: 409, detail: "no saved audit snapshot"},
  }, "#/criteria?store=prod");
  const out = (await context.renderCriteria()).textContent;
  assert.match(out, /No saved assessment for this store/);
  assert.match(out, /Run an assessment first/);
  assert.doesNotMatch(out, /frozen/);
});

test("the criteria screen states the pack has had no regulatory review", async () => {
  const {context} = app({
    "/admin/stores": {stores: []}, "/admin/policies": {policies: []},
    "/admin/policy-templates": {templates: []}, "/compliance/criteria": PACK,
  }, "#/criteria");
  const out = (await context.renderCriteria()).textContent;
  assert.match(out, /Draft mapping · not reviewed by a lawyer/);
  assert.match(out, /It does not mean your store meets the law/);
  assert.match(out, /45 CFR 164\.312\(a\)\(1\)/, "sources are shown before any store is chosen");
});

test("criterion counts are never totalled into a compliance score", async () => {
  const {context} = app({
    "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"}]},
    "/admin/policies": {policies: []}, "/admin/policy-templates": {templates: []},
    "/compliance/criteria": PACK,
    "/stores/prod/criteria": {
      audit_id: "a1", pack: PACK.pack,
      coverage: {status: "partial", checks_expected: 2, checks_complete: 1,
                 outcomes: {passed: 1, inconclusive: 1}},
      summary: {by_status: {not_assessed: 1, satisfied_for_scope: 1}, criteria: 2,
                note: "Status counts describe this run and its evidence. They are not a compliance score."},
      assessments: [ASSESSMENT],
    },
  }, "#/criteria?store=prod");
  const out = (await context.renderCriteria()).textContent;
  assert.match(out, /not a compliance score/);
  assert.doesNotMatch(out, /\d+%/, "no percentage that would read as a score");
  assert.match(out, /Using assessment a1/);
});

// ------------------------------------------------------ findings as cases ---

const FINDING = {
  id: "f-1", title: "PII detected", severity: "high", category: "data_classification",
  store: "prod", collection: "docs", suppressed: false,
  case: {state: "new", owner: null, reason: "", updated_at: null},
};

function findingsApp(extra = {}, hash = "#/findings") {
  return app({
    "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"}]},
    "/admin/policies": {policies: []}, "/admin/policy-templates": {templates: []},
    "/admin/estate": {stores: [{store_id: "prod", last_assessed: "2026-09-20T00:00:00Z",
                                coverage: {status: "partial"}}]},
    ...extra,
  }, hash);
}

test("the findings count states the true total, not the page size", async () => {
  const {context} = findingsApp({
    "/admin/findings?scope=latest&suppressed=false&sort=severity&direction=desc&limit=50&offset=0": {
      findings: [FINDING], total: 4207, limit: 50, offset: 0,
      has_more: true, next_offset: 50, facets: {case_state: {new: 4207}},
    },
  });
  const out = (await context.renderFindings()).textContent;
  assert.match(out, /4,?207 open in the latest audits/);
  assert.match(out, /Showing 1–1 of 4,?207/);
});

test("filters are sent to the server rather than applied to a capped fetch", async () => {
  const empty = {findings: [], total: 0, limit: 50, offset: 0, has_more: false, facets: {}};
  const {context, calls} = findingsApp({
    "/admin/findings?scope=latest&suppressed=false&search=ssn&min_severity=high&category=cve&sort=store&direction=asc&limit=50&offset=0": empty,
    "/admin/findings?scope=latest&suppressed=false&search=ssn&category=cve&sort=store&direction=asc&limit=1&offset=0": empty,
  }, "#/findings?q=ssn&min_severity=high&category=cve&sort=store&dir=asc");
  await context.renderFindings();
  const request = calls.find(c => c.path.startsWith("/admin/findings"));
  assert.match(request.path, /search=ssn/);
  assert.match(request.path, /min_severity=high/);
  assert.match(request.path, /category=cve/);
  assert.match(request.path, /sort=store&direction=asc/);
});

test("a severity from Home is that severity, as Home counted it, not that and above", async () => {
  // Home's "High open: 21" links to #/findings?severity=high. Read as a
  // minimum, the list showed high and critical together and a different count.
  const {context, calls} = findingsApp({
    "/admin/findings?scope=latest&suppressed=false&severity=high&sort=severity&direction=desc&limit=50&offset=0": {
      findings: [FINDING], total: 21, limit: 50, offset: 0, has_more: false,
      facets: {severity: {high: 21}, case_state: {new: 21}},
    },
    "/admin/findings?scope=latest&suppressed=false&sort=severity&direction=desc&limit=1&offset=0": {
      findings: [FINDING], total: 33, limit: 1, offset: 0, has_more: true,
      facets: {severity: {critical: 12, high: 21}, case_state: {new: 33}},
    },
  }, "#/findings?severity=high");
  const out = (await context.renderFindings()).textContent;
  const first = calls.find(c => c.path.startsWith("/admin/findings?")).path;
  assert.match(first, /[?&]severity=high/);
  assert.doesNotMatch(first, /min_severity/);
  assert.match(out, /21 open in the latest audits/);
  // The severity strip counts under every filter but its own, so critical
  // still reads 12 while high is picked.
  assert.match(out, /12\s+critical/);
  assert.match(out, /Severity:\s+high/, "the active filter is a removable chip");
});

test("the triage default is worst first, and every row says how sure and what is disputed", async () => {
  const disputed = {...FINDING, id: "f-2", evidence: {explanations: [
    {detector: "aws_access_key", confidence: "possible", counter_signals: [{code: "published_example"}]},
    {detector: "email", confidence: "uncertain", counter_signals: []}]}};
  const posture = {...FINDING, id: "f-3", category: "cve", evidence: {}};
  const {context, calls} = findingsApp({
    [`${"/admin/findings?scope=latest&suppressed=false&sort=severity&direction=desc&limit=50&offset=0"}`]: {
      findings: [disputed, posture], total: 2, limit: 50, offset: 0, has_more: false,
      facets: {severity: {high: 2}, case_state: {new: 2}},
    },
  });
  const out = (await context.renderFindings()).textContent;
  assert.match(calls.find(c => c.path.startsWith("/admin/findings?")).path, /sort=severity&direction=desc/);
  assert.match(out, /possible–uncertain/, "mixed confidence reads as its range, not its best class");
  assert.match(out, /1 disputed/);
  assert.match(out, /n\/a/, "a CVE has no detector confidence, and says so");
  assert.match(out, /Latest audits: 1 partial/, "coverage of the audits behind the list stays in view");
  assert.match(out, /not a clean result/);
});

test("a finding shows its severity and its case as two separate facts", () => {
  const {context} = findingsApp();
  const table = context.findingsCaseTable(
    {findings: [{...FINDING, case: {state: "risk_accepted", owner: "bob"}}],
     total: 1, limit: 50, facets: {case_state: {risk_accepted: 1}}},
    {selection: new Set(), reload: () => {}, offset: 0});
  assert.match(table.textContent, /HIGH/, "the observed severity");
  assert.match(table.textContent, /risk accepted/, "the decision");
  assert.match(table.textContent, /bob/);
  assert.match(table.textContent, /accepted, not fixed/);
});

test("a false positive is labelled a claim rather than a fix", () => {
  const {context} = findingsApp();
  const [path, claims] = context.caseStrip({new: 1, false_positive: 3}, {onPick: () => {}});
  assert.match(path.textContent, /new/);
  assert.match(claims.textContent, /3\s+false positive/);
  assert.match(claims.textContent, /none of them is a fix/);
  const chip = find(claims, n => n.tagName === "BUTTON");
  assert.match(chip.attrs.title, /a claim, not a fix/);
});

test("case counts that could not be read say so rather than showing zero", () => {
  const {context} = findingsApp();
  const [strip] = context.caseStrip(null, {onPick: () => {}});
  assert.match(strip.textContent, /Counts unavailable/);
  assert.match(context.severityStrip(null, {onPick: () => {}}).textContent, /Counts unavailable/);
});

test("a claim asks for its reason before the server has to refuse it", async () => {
  const {context, doc} = findingsApp({
    "/admin/findings/f-1/case": {state: "new", owner: null, events: [],
                                 allowed_transitions: ["assigned", "false_positive", "risk_accepted"]},
  });
  await context.caseModal(FINDING, () => {});
  const select = find(doc.body, n => n.tagName === "SELECT");
  const reason = find(doc.body, n => n.tagName === "TEXTAREA");
  const owner = find(doc.body, n => n.tagName === "INPUT" && n.attrs.placeholder === "owner@example.com");
  select.value = "risk_accepted";
  select.events.change();
  assert.equal(reason.required, true);
  assert.match(doc.body.textContent, /accepting a risk does not fix it/);
  select.value = "assigned";
  select.events.change();
  assert.equal(reason.required, false);
  assert.equal(owner.required, true);
  assert.match(doc.body.textContent, /Assigning needs an owner/);
});

test("an empty result offers the action that would fill it", () => {
  const {context} = findingsApp();
  const out = context.findingsCaseTable({findings: [], total: 0, limit: 50, facets: {}},
                                        {selection: new Set(), reload: () => {}, offset: 0});
  assert.match(out.textContent, /No findings match these filters/);
  assert.ok(find(out, n => n.tagName === "BUTTON" && /Run an assessment/.test(n.textContent)));
});

test("history being unavailable is said out loud, not shown as no findings", async () => {
  const {context} = findingsApp({
    "/admin/findings?scope=latest&suppressed=false&sort=severity&direction=desc&limit=50&offset=0": {status: 409, detail: "findings require scan history"},
  });
  const out = (await context.renderFindings()).textContent;
  assert.match(out, /findings require scan history/);
  assert.doesNotMatch(out, /No findings match/);
});

test("the case dialog says suppression is not a case state", async () => {
  const {context, doc} = findingsApp({
    "/admin/findings/f-1/case": {
      state: "new", owner: null, events: [], allowed_transitions: ["triaged", "assigned"],
      is_open: true,
    },
  });
  await context.caseModal(FINDING, () => {});
  const text = doc.body.textContent;
  assert.match(text, /Suppression hides a finding/);
  assert.match(text, /never means the work was done/);
  assert.match(text, /No case changes recorded yet/);
});

test("the case dialog offers only the transitions the backend allows", async () => {
  const {context, doc} = findingsApp({
    "/admin/findings/f-1/case": {
      state: "verified", owner: "bob", events: [
        {at: "2026-09-17", actor: "bob", from_state: "awaiting_verification",
         to_state: "verified", reason: "confirmed by job j1"},
      ],
      allowed_transitions: ["closed", "reopened"], is_open: false,
    },
  });
  await context.caseModal(FINDING, () => {});
  const options = findAll(doc.body, n => n.tagName === "OPTION").map(o => o.textContent.trim());
  assert.ok(options.includes("closed") && options.includes("reopened"));
  assert.ok(!options.includes("in progress"), "an illegal move is not even offered");
  assert.match(doc.body.textContent, /confirmed by job j1/, "the trail is shown");
});

test("a partial bulk change reports which findings refused it", async () => {
  const {context, doc} = findingsApp({
    "/admin/findings/cases": {
      applied: 1, refused: 1, ok: false, cases: [],
      refusals: [{finding_id: "f-2", reason: "cannot move a case from verified to assigned",
                  status: 409}],
    },
  });
  context.bulkCaseModal(["f-1", "f-2"], () => {});
  assert.match(doc.body.textContent, /applies to 2 finding/);
  assert.match(doc.body.textContent, /not silently skipped/);

  const form = find(doc.body, n => n.tagName === "FORM");
  await form.events.submit({preventDefault() {}});
  assert.match(doc.body.textContent, /1 applied, 1 refused/);
  assert.match(doc.body.textContent, /cannot move a case from verified to assigned/);
});

// -------------------------------------------------------------- the estate ---

const ESTATE = {
  note: "Capabilities and reachability are only known after opening a connector.",
  probed: false,
  stores: [
    {store_id: "prod", kind: "qdrant", tenant_field: "tenant_id",
     last_assessed: new Date().toISOString(), last_audit_id: "a1",
     coverage: {status: "partial"}, findings: {high: 2, low: 1}, findings_total: 3,
     cases: {new: 3}, history_available: true,
     probe: {probed: false, reachable: null, capabilities: null, content_enumerable: null}},
    {store_id: "cold", kind: "chroma", tenant_field: null,
     last_assessed: null, coverage: null, findings: {}, findings_total: 0,
     cases: {}, history_available: true,
     probe: {probed: false, reachable: null, capabilities: null, content_enumerable: null}},
  ],
};

function estateApp(summary = ESTATE, hash = "#/stores") {
  return app({
    "/admin/stores": {stores: summary.stores.map(s => ({store_id: s.store_id, kind: s.kind}))},
    "/admin/policies": {policies: []}, "/admin/policy-templates": {templates: []},
    "/admin/estate": summary, "/admin/estate?probe=true": {...summary, probed: true},
  }, hash);
}

test("an unprobed capability reads as unknown, never as absent", () => {
  const {context} = estateApp();
  const cell = context.capabilityCell({probed: false});
  assert.equal(cell.textContent.trim(), "unknown");
  assert.doesNotMatch(cell.textContent, /inventory only/);
});

test("an inventory-only store says what cannot be inspected inside it", () => {
  const {context} = estateApp();
  const cell = context.capabilityCell({probed: true, reachable: true, capabilities: [],
                                       content_enumerable: false});
  assert.match(cell.textContent, /inventory only/);
  assert.match(cell.textContent, /cannot see inside this store/);
});

test("a readable store lists the capabilities that bound what its results mean", () => {
  const {context} = estateApp();
  const cell = context.capabilityCell({probed: true, reachable: true,
                                       capabilities: ["delete", "query"],
                                       content_enumerable: true});
  assert.match(cell.textContent, /content readable/);
  assert.match(cell.textContent, /delete/);
  assert.match(cell.textContent, /query/);
});

test("an unreachable store reports why, and does not claim zero capabilities", () => {
  const {context} = estateApp();
  const health = context.storeHealth({probed: true, reachable: false, error: "connection refused"});
  assert.match(health.textContent, /unreachable/);
  assert.match(health.textContent, /connection refused/);
  const cell = context.capabilityCell({probed: true, reachable: false});
  assert.match(cell.textContent, /unknown — unreachable/);
});

test("the estate distinguishes never assessed from assessed with nothing found", () => {
  const {context} = estateApp();
  const rendered = context.estateTable(ESTATE).textContent;
  assert.match(rendered, /Never assessed/);
  assert.match(rendered, /partial/, "the coverage of the run that did happen");
  assert.match(rendered, /HIGH/, "the worst recorded severity for the assessed store");
  assert.match(rendered, /not assessed/, "the never-assessed store claims no findings");
});

test("an estate row offers assess, open, test, and delete", () => {
  const {context} = estateApp();
  const labels = findAll(context.estateTable(ESTATE), n => n.tagName === "BUTTON")
    .map(b => b.textContent.trim());
  for (const wanted of ["Open", "Assess", "Test", "Delete"]) {
    assert.ok(labels.some(l => l.includes(wanted)), `${wanted} is reachable from the row`);
  }
});

test("an empty console explains how to get a first assessment", async () => {
  const {context} = app({
    "/admin/stores": {stores: []}, "/admin/policies": {policies: []},
    "/admin/policy-templates": {templates: []},
  }, "#/stores");
  const out = (await context.renderStores()).textContent;
  assert.match(out, /Nothing is connected yet/);
  assert.match(out, /Connect a store/);
  assert.match(out, /Run a baseline assessment/);
  assert.match(out, /zero findings over partial coverage is not a clean result/);
  assert.doesNotMatch(out, /No records/, "an empty table is not the answer here");
});

test("the estate is read in one call, with every store probed", async () => {
  const {context, calls} = estateApp();
  const out = await context.renderStores();
  const estateCalls = calls.filter(c => c.path.startsWith("/admin/estate"));
  assert.equal(estateCalls.length, 1, "one call for the whole estate");
  assert.equal(estateCalls[0].path, "/admin/estate?probe=true", "probing is the default");
  assert.match(out.textContent, /Each store is opened when this page loads/);
  const labels = findAll(out, n => n.tagName === "BUTTON").map(b => b.textContent);
  assert.ok(!labels.some(l => /Probe capabilities|Hide capability probe/.test(l)),
            "there is no probe button to press");
});

// -------------------------------------------------- compliance centre (P7) ---

const PACK_FULL = {
  pack: {pack_version: "draft-1", criteria: 2, lifecycle: "draft",
         regulatory_review: null, note: "Not reviewed by a qualified practitioner."},
  criteria: [
    {criterion_id: "HIPAA-1", framework: "HIPAA", paraphrase: "Access is limited.",
     sources: [{section: "45 CFR 164.312(a)(1)"}], manual_evidence: ["access_review_record"]},
    {criterion_id: "GDPR-1", framework: "GDPR", paraphrase: "Erasure reaches embeddings.",
     sources: [{section: "Art. 17"}], manual_evidence: []},
  ],
};

function complianceApp(extra = {}, hash = "") {
  return app({
    "/admin/stores": {stores: []}, "/admin/policies": {policies: []},
    "/admin/policy-templates": {templates: []}, "/compliance/criteria": PACK_FULL,
    ...extra,
  }, hash);
}

test("frameworks report counts and sources, never a compliance percentage", async () => {
  const {context} = complianceApp();
  const out = (await context.renderFrameworks()).textContent;
  assert.match(out, /HIPAA/);
  assert.match(out, /GDPR/);
  assert.match(out, /45 CFR 164\.312\(a\)\(1\)/);
  assert.match(out, /Draft mapping · not reviewed by a lawyer/);
  assert.doesNotMatch(out, /\d+%/, "a percentage would read as a score");
});

test("a criterion with no manual evidence says so rather than showing a blank", async () => {
  const {context} = complianceApp();
  const out = (await context.renderFrameworks()).textContent;
  assert.match(out, /None: the automatic checks cover it/);
});

test("an artifact's state is separate from what it was judged to evidence", () => {
  const {context} = complianceApp();
  const cell = context.evidenceJudgement(
    [{criterion_id: "HIPAA-1", state: "accepted", accepted: true}],
    {usable: true});
  assert.match(cell.textContent, /Accepted/);
  assert.match(cell.textContent, /HIPAA-1/);
});

test("evidence accepted against an artifact that is no longer usable reads as stale", () => {
  const {context} = complianceApp();
  const cell = context.evidenceJudgement(
    [{criterion_id: "HIPAA-1", state: "accepted", accepted: true}],
    {usable: false});
  assert.match(cell.textContent, /Accepted, no longer counts/);
});

test("an unreviewed artifact claims nothing", () => {
  const {context} = complianceApp();
  assert.match(context.evidenceJudgement([], {usable: true}).textContent,
               /not reviewed against anything/);
});

test("an artifact that is not usable says so beside its state", () => {
  const {context} = complianceApp();
  const cell = context.artifactState({state: "superseded", usable: false});
  assert.match(cell.textContent, /Replaced by a newer version/);
  assert.match(cell.textContent, /does not count as evidence yet/);
});

test("the evidence screen shows artifacts and their reviews as two records", async () => {
  const {context} = complianceApp({
    "/compliance/evidence": {note: "An artifact's state says whether the file is fit to look at.",
      artifacts: [{id: "ev-1", title: "Q3 access review", state: "available", usable: true,
                   integrity: "hashed", content_hash: "abc123def456789012", scope: "prod",
                   period_start: "2026-07-01", period_end: "2026-09-30"}]},
    "/compliance/reviews": {reviews: [
      {id: "rev-1", artifact_id: "ev-1", criterion_id: "HIPAA-1",
       requirement: "access_review_record", state: "accepted", accepted: true,
       reviewer: "sarah", reason: ""}]},
  });
  const out = (await context.renderEvidence()).textContent;
  assert.match(out, /Q3 access review/);
  assert.match(out, /2026-07-01 → 2026-09-30/);
  assert.match(out, /access_review_record/);
  assert.match(out, /sarah/);
});

test("an artifact with no period says it evidences no particular window", async () => {
  const {context} = complianceApp({
    "/compliance/evidence": {note: "", artifacts: [
      {id: "ev-2", title: "Policy doc", state: "available", usable: true,
       integrity: "not hashed", scope: "", period_start: null, period_end: null}]},
    "/compliance/reviews": {reviews: []},
  });
  const out = (await context.renderEvidence()).textContent;
  assert.match(out, /no period stated — it evidences no particular window/);
  assert.match(out, /unscoped/);
});

test("exceptions are counted as pending, active, and expired, and never as closures", async () => {
  const {context} = complianceApp({
    "/compliance/exceptions": {
      pending_approval: 1, active: 2, expired: 3,
      note: "An exception records that a gap is tolerated. It does not close the gap.",
      exceptions: [
        {id: "e1", criterion_id: "HIPAA-1", scope: "prod", status: "active", active: true,
         expires_at: new Date(Date.now() + 86400000).toISOString(),
         rationale: "Compensating control.", approved_by: "sarah", requested_by: "bob"},
        {id: "e2", criterion_id: "GDPR-1", scope: "prod", status: "pending_approval",
         active: false, expires_at: new Date(Date.now() + 86400000).toISOString(),
         rationale: "Under review.", approved_by: null, requested_by: "bob"},
      ]},
  });
  const out = (await context.renderExceptions()).textContent;
  assert.match(out, /Waiting for approval 1/);
  assert.match(out, /Active 2/);
  assert.match(out, /Expired 3/);
  assert.match(out, /accepted for now; still a gap/);
  assert.match(out, /does not close the gap/);
});

test("only a pending exception offers approval, and a revoked one offers nothing", async () => {
  const {context} = complianceApp({
    "/compliance/exceptions": {
      pending_approval: 0, active: 0, expired: 0, note: "",
      exceptions: [
        {id: "e3", criterion_id: "HIPAA-1", scope: "prod", status: "revoked", active: false,
         expires_at: null, rationale: "No longer needed.", requested_by: "bob"},
      ]},
  });
  const rendered = await context.renderExceptions();
  const labels = findAll(rendered, n => n.tagName === "BUTTON").map(b => b.textContent.trim());
  assert.ok(!labels.includes("Approve"), "a revoked exception cannot be approved");
  assert.ok(!labels.includes("Revoke"), "nor revoked twice");
});

test("the exception request dialog states that it does not close the gap", () => {
  const {context, doc} = complianceApp();
  context.requestExceptionModal();
  assert.match(doc.body.textContent, /does not close the gap/);
  assert.match(doc.body.textContent, /A second person must authorize it; the author cannot/);
});

test("where an admin may self-approve, the dialog says so and the row shows it", async () => {
  const {context, doc} = complianceApp({
    "/version": {version: "1", detection_version: "1",
                 approvals: {separation_of_duties: "admin_may_self_approve",
                             self_approval: "admins, except for irreversible operations"}},
    "/compliance/exceptions": {
      pending_approval: 0, active: 1, expired: 0, note: "",
      exceptions: [{id: "e1", criterion_id: "HIPAA-1", scope: "prod", status: "active",
                    active: true, expires_at: new Date(Date.now() + 86400000).toISOString(),
                    rationale: "Compensating control.", approved_by: "admin",
                    requested_by: "admin", self_approved: true}]},
  });
  const out = await context.renderExceptions();
  assert.match(out.textContent, /self-approved/, "a self-approval is never silent");
  context.requestExceptionModal();
  assert.match(doc.body.textContent, /An admin may approve it even if they proposed it/);
  assert.doesNotMatch(doc.body.textContent, /A second person must authorize it/);
});

test("registering an artifact says that judging it is a separate step", () => {
  const {context, doc} = complianceApp();
  context.registerEvidenceModal();
  assert.match(doc.body.textContent, /Whether it evidences an obligation is a separate review/);
});

test("evidence without history is unavailable, not empty", async () => {
  const {context} = complianceApp({
    "/compliance/evidence": {status: 409, detail: "evidence requires scan history"},
    "/compliance/reviews": {reviews: []},
  });
  const out = (await context.renderEvidence()).textContent;
  assert.match(out, /evidence requires scan history/);
  assert.doesNotMatch(out, /No evidence has been registered/);
});

test("privacy requests now live under compliance", () => {
  const {context} = complianceApp();
  const area = context.areaOf("dsar");
  assert.equal(area[0], "Compliance");
  assert.ok(!context.areaOf("runtime")[3].includes("dsar"));
});

test("a criterion's position exports with its evidence, exceptions, and caveats", () => {
  const {context} = complianceApp();
  const position = context.exportCriterionPosition({
    criterion_id: "HIPAA-1", framework: "HIPAA", pack_version: "draft-1",
    status: "gap_identified", rationale: "A check failed.",
    applicability_status: "confirmed", applicability: {handles_ephi: "yes"},
    technical_result: "failed", technical_coverage: "complete",
    observations: [{check: "tenant_isolation", outcome: "failed"}],
    evidence_sufficiency: "accepted", missing_evidence: [],
    evidence_reviews: [{id: "rev-1", accepted: true}],
    exceptions: [{id: "exc-1", status: "active"}],
    reviewer: null, gaps: ["A technical check observed a failure."],
    limitations: ["A probe samples."],
  }, {store: "prod", auditId: "a1"});

  assert.equal(position.criterion_id, "HIPAA-1");
  assert.equal(position.audit_id, "a1");
  assert.equal(position.technical.result, "failed");
  assert.equal(position.evidence.reviews.length, 1);
  assert.equal(position.exceptions.length, 1);
  assert.ok(position.caveats.some(c => /not been reviewed by a lawyer/.test(c)));
  assert.ok(position.caveats.some(c => /They are not a score/.test(c)));
  assert.ok(position.caveats.some(c => /Only a named reviewer can mark a criterion as met for this store/.test(c)));
  assert.ok(position.caveats.every(c => !/[a-z]+_[a-z]+/.test(c)), "no raw identifiers in the caveats");
  assert.ok(position.caveats.some(c => /does not close the gap/.test(c)));
});

// ------------------------------------------------------ UI bug regressions ---
// Each of these was found by driving the console against a live demo server.

test("a state chip shows the state, not the colour it borrows", () => {
  const {context} = app();
  // badge() prints its argument, so passing a tone printed "UNKNOWN" beside a
  // case whose state was "new".
  const chip = context.caseBadge("new");
  assert.match(chip.textContent, /new/);
  assert.doesNotMatch(chip.textContent, /UNKNOWN/);

  const accepted = context.caseBadge("risk_accepted");
  assert.match(accepted.textContent, /risk accepted/);
  assert.doesNotMatch(accepted.textContent, /MEDIUM/);
});

test("a run card names its state rather than its tone", () => {
  const {context} = app();
  const card = context.runCard({id: "j1", status: "interrupted", kind: "audit"}, {label: "Audit"});
  assert.match(card.textContent, /Interrupted/);
  assert.doesNotMatch(card.textContent, /MEDIUM/);
});

test("timestamps render for both shapes the backend emits", () => {
  const {context} = app();
  // Shown as a relative age plus the reader's local date and time; the exact
  // ISO instant is kept for hover and machines, never printed raw.
  const local = millis => new Intl.DateTimeFormat(undefined, {dateStyle: "medium", timeStyle: "short"})
    .format(new Date(millis));
  // ISO, as history and jobs emit.
  const iso = context.formatWhen("2026-09-17T10:30:00+00:00");
  assert.ok(iso.textContent.includes(local(Date.parse("2026-09-17T10:30:00Z"))));
  assert.equal(iso.attrs.title, "2026-09-17T10:30:00.000Z");
  assert.equal(iso.attrs.datetime, "2026-09-17T10:30:00.000Z");
  assert.doesNotMatch(iso.textContent, /\d{4}-\d\d-\d\dT\d\d:/, "no raw ISO string in the text");
  // Epoch seconds, as the hash-chained audit log emits.
  const epoch = context.formatWhen(1789701184.738249);
  assert.ok(epoch.textContent.includes(local(1789701184738)));
  assert.match(epoch.attrs.title, /^2026-09-18T03:13/);
  assert.doesNotMatch(epoch.textContent, /1789701184/,
                      "a raw epoch float must never reach a table cell");
  // Milliseconds, in case a caller passes them.
  assert.match(context.formatWhen(1789701184738).attrs.title, /^2026-09-18T03:13/);
  // Unparseable input is shown as-is rather than as a wrong date.
  assert.match(context.formatWhen("not a date").textContent, /not a date/);
  assert.match(context.formatWhen(null).textContent, /-/);
});

test("relative ages understand epoch stamps too", () => {
  const {context} = app();
  assert.equal(context.relativeDay(Date.now() / 1000), "today");
  assert.equal(context.relativeDay(new Date(Date.now() - 86400000).toISOString()), "yesterday");
  assert.equal(context.relativeDay("nonsense"), "nonsense");
});

test("relative ages read forward as well as back", () => {
  // An exception expiring in sixty days used to read "today".
  const {context} = app();
  // Half a day of cushion: relativeDay reads the clock again, and exactly
  // sixty days less the milliseconds in between floors to fifty-nine.
  assert.equal(context.relativeDay(new Date(Date.now() + 60 * 86400000 + 12 * 3600000).toISOString()), "in 60 days");
  assert.equal(context.relativeDay(new Date(Date.now() + 86400000 + 60000).toISOString()), "tomorrow");
});

test("the frameworks screen spells out what each criterion needs", async () => {
  const {context} = complianceApp({
    "/compliance/criteria": {
      pack: PACK_FULL.pack,
      criteria: [{
        criterion_id: "HIPAA-1", framework: "HIPAA", paraphrase: "Access is limited.",
        sources: [{section: "45 CFR 164.312(a)(1)", issuer: "HHS", kind: "rule", status: "in_force",
                   url: "https://example.test/hipaa"}],
        technical_checks: ["tenant_isolation"], manual_evidence: ["access_review_record"],
        applicability_questions: ["system_handles_ephi"],
        limitations: ["A probe samples."], interpretation_notes: "One access path.",
      }],
      // The words for identifiers are served with the pack, not kept in the console.
      evidence_types: {access_review_record: {label: "Access review record",
        what: "A dated record that access was checked.", examples: ["A quarterly access review export"],
        reviewer_checks: "Dated in the period."}},
      applicability_questions: {system_handles_ephi: {
        question: "Does this system handle electronic protected health information?", help: "h"}},
    },
  });
  const out = (await context.renderFrameworks()).textContent;
  assert.match(out, /Tenant isolation/, "checks are named, not left as identifiers");
  assert.match(out, /queried under every other tenant's filter/, "the check says how it verifies");
  assert.match(out, /Access review record/, "evidence is named from the vocabulary");
  assert.match(out, /A dated record that access was checked\./, "and explained");
  assert.match(out, /handle electronic protected health information\?/, "applicability is a question");
  assert.match(out, /A probe samples\./);
  assert.match(out, /One access path\./);
  assert.match(out, /HHS/, "the issuer comes from the source record");
  assert.match(out, /1 checked automatically/);
  assert.doesNotMatch(out, /\d+%/, "still no percentage anywhere");
});

test("a framework the profiles do not know still renders from its sources", async () => {
  const {context} = complianceApp({
    "/compliance/criteria": {
      pack: PACK_FULL.pack,
      criteria: [{criterion_id: "X-1", framework: "Some New Act", paraphrase: "Do the thing.",
                  sources: [{section: "s. 4", issuer: "Somebody"}]}],
    },
  });
  const out = (await context.renderFrameworks()).textContent;
  assert.match(out, /Some New Act/);
  assert.match(out, /Somebody/);
  assert.match(out, /Nothing: documents only/);
});

test("the audit log reads the field the API actually returns", async () => {
  const {context} = app({
    "/audit-log": {verified: true, entries: [
      {seq: 1, timestamp: 1789701184.738249, actor: "admin", action: "full_audit",
       target: "support-kb", details: {violations: 12}},
    ]},
  });
  const out = (await context.renderAudit()).textContent;
  // The API calls it `target`; reading `resource` showed "-" on every row.
  assert.match(out, /support-kb/);
  assert.match(out, /full_audit/);
  assert.ok(out.includes(new Intl.DateTimeFormat(undefined, {dateStyle: "medium", timeStyle: "short"})
    .format(new Date(1789701184738))), "the entry's time, in local time");
  // Details are a key/value list, not a JSON dump.
  assert.match(out, /violations\s+12/);
  assert.doesNotMatch(out, /"violations"/);
  assert.match(out, /hash chain verifies/);
});

test("a broken audit chain is reported as an alert, not a quiet table", async () => {
  const {context} = app({
    "/audit-log": {verified: false, reason: "entry 4 does not match its predecessor",
                   entries: [{seq: 1, timestamp: 1789701184, actor: "a", action: "x",
                              target: "t", details: {}}]},
  });
  const rendered = await context.renderAudit();
  assert.match(rendered.textContent, /does not match its predecessor/);
  assert.ok(find(rendered, n => n.attrs?.role === "alert"));
});

test("the runs screen surfaces an interrupted run instead of burying it in JSON", async () => {
  const {context} = app({
    "/admin/jobs?limit=100": {jobs: [
      {id: "j-1", kind: "audit", status: "succeeded", actor: "demo", resource: "prod",
       created_at: "2026-09-17T10:00:00+00:00", started_at: "2026-09-17T10:00:00+00:00",
       finished_at: "2026-09-17T10:01:00+00:00"},
      {id: "j-2", kind: "scan_integrity", status: "interrupted", actor: "demo",
       resource: "prod/docs", created_at: "2026-09-17T09:00:00+00:00",
       error: "worker restarted before this job finished; the work was not resumed"},
    ]},
  });
  const out = (await context.renderJobs()).textContent;
  assert.match(out, /worker restarted before this job finished/,
               "the reason is on the card, not hidden behind a Details button");
  assert.match(out, /1 run was interrupted by a restart and recorded nothing/);
  assert.match(out, /Interrupted 1/);
  assert.doesNotMatch(out, /2026-09-17T09:00:00/, "no raw ISO strings in the card");
});

test("an empty runs screen offers the action that would fill it", async () => {
  const {context} = app({"/admin/jobs?limit=100": {jobs: []}});
  const rendered = await context.renderJobs();
  assert.match(rendered.textContent, /No background work has run yet/);
  assert.ok(find(rendered, n => n.tagName === "BUTTON" && /Run an assessment/.test(n.textContent)));
});

// Found by driving every control and dialog against a live server.

test("copying falls back instead of throwing where the clipboard is unavailable", async () => {
  const {context, doc} = app();
  // navigator.clipboard is undefined outside a secure context — which includes
  // any console served over plain HTTP, as a self-hosted one often is.
  await context.copyText("{\"rule\": 1}", "Template JSON");
  assert.match(doc.body.textContent, /not served over HTTPS/);
  assert.match(doc.body.textContent, /\{"rule": 1\}/, "the text is shown so it can be copied");
});

test("a download that cannot start shows its content rather than failing silently", () => {
  const {context, doc} = app();
  // Stand in for a sandboxed frame, a blocked download, or a browser without
  // Blob URL support: the page cannot start the transfer.
  context.URL.createObjectURL = () => { throw new Error("downloads are blocked"); };
  const ok = context.downloadText("report-body", "report.html", "text/html", "Report — a1");
  assert.equal(ok, false);
  assert.match(doc.body.textContent, /would not start the download/);
  assert.match(doc.body.textContent, /downloads are blocked/, "and says why");
  assert.match(doc.body.textContent, /report-body/);
  assert.ok(find(doc.body, n => n.tagName === "BUTTON" && /Copy/.test(n.textContent)));
});

test("metadata fields are unknown when nothing was sampled, never zero", () => {
  const {context} = app();
  // The schema API reports metadata_complete; ignoring it turns "we did not
  // look" into "there is nothing there".
  const unsampled = context.metadataFieldCount({
    name: "docs", count: 10, metadata_fields: [], metadata_complete: false, sample_size: 0});
  assert.match(unsampled.textContent, /not sampled/);
  assert.ok(unsampled.className.includes("sev-unknown"));

  const sampled = context.metadataFieldCount({
    name: "docs", count: 10, metadata_complete: true, sample_size: 10,
    metadata_fields: [{path: "tenant_id"}, {path: "source"}]});
  assert.equal(sampled.textContent ?? sampled, "2");

  // A collection that really was sampled and has none still reads zero.
  const genuinelyNone = context.metadataFieldCount({
    name: "docs", count: 10, metadata_complete: true, sample_size: 10, metadata_fields: []});
  assert.equal(genuinelyNone.textContent ?? genuinelyNone, "0");
});

test("a validation failure reads as words, not [object Object]", async () => {
  // FastAPI returns a list of error objects for a 422. Passing that to Error()
  // is what made every form in the console say "[object Object]".
  const {context} = app();
  assert.equal(
    context.describeDetail([
      {type: "string_too_short", loc: ["body", "scope"],
       msg: "String should have at least 1 character"},
      {type: "missing", loc: ["body", "expires_at"], msg: "Field required"},
    ]),
    "scope: String should have at least 1 character; expires_at: Field required");

  // The part of the request an error arrived in is noise; the field is not.
  assert.equal(context.describeDetail([{loc: ["query", "limit"], msg: "Input should be less than 500"}]),
               "limit: Input should be less than 500");
  // A plain string detail is untouched.
  assert.equal(context.describeDetail("no saved audit snapshot"), "no saved audit snapshot");
  // Duplicates from repeated fields collapse.
  assert.equal(context.describeDetail([{loc: ["body", "a"], msg: "x"}, {loc: ["body", "a"], msg: "x"}]),
               "a: x");
  // Nothing at all leaves the caller's fallback in place.
  assert.equal(context.describeDetail(undefined), "");
  assert.equal(context.describeDetail(null), "");
  // An unexpected shape is shown rather than swallowed.
  assert.match(context.describeDetail({msg: "boom"}), /boom/);
  assert.match(context.describeDetail([{unexpected: true}]), /unexpected/);
});

test("a rejected request surfaces the readable message", async () => {
  const {context} = app({
    "/admin/stores": {stores: []}, "/admin/policies": {policies: []},
    "/admin/policy-templates": {templates: []},
    "/admin/findings?scope=latest&suppressed=false&sort=severity&direction=desc&limit=50&offset=0": {
      status: 422, detail: [{loc: ["query", "sort"], msg: "cannot sort findings by that"}],
    },
  }, "#/findings");
  const out = (await context.renderFindings()).textContent;
  assert.match(out, /sort: cannot sort findings by that/);
  assert.doesNotMatch(out, /\[object Object\]/);
});

test("an unreadable allow-list is unavailable, never 'No records'", async () => {
  // Found on a locked-down console: both lists rendered "No records." for data
  // nobody was allowed to read.
  const {context} = app({
    "/admin/allowlist": {status: 401, detail: "invalid or missing token"},
    "/admin/suppressions": {status: 401, detail: "invalid or missing token"},
  });
  const out = (await context.renderFalsePositives()).textContent;
  assert.match(out, /Access restricted/);
  assert.match(out, /not a list of none/);
  assert.doesNotMatch(out, /No records/,
    "an unreadable list must not render as an empty one");
});

test("one readable list and one unreadable list are reported separately", async () => {
  const {context} = app({
    "/admin/allowlist": {allowlist: [{reason: "Known test key", rule: "r1", source: "builtin"}]},
    "/admin/suppressions": {status: 403, detail: "forbidden"},
  });
  const out = (await context.renderFalsePositives()).textContent;
  assert.match(out, /Known test key/, "the readable list is shown");
  assert.match(out, /Suppressions could not be read/);
});

test("genuinely empty lists still read as empty", async () => {
  const {context} = app({
    "/admin/allowlist": {allowlist: []}, "/admin/suppressions": {suppressions: []},
  });
  const out = (await context.renderFalsePositives()).textContent;
  assert.match(out, /No records/);
  assert.doesNotMatch(out, /could not be read/);
});

// ------------------------------------------------- v2.1: explaining findings ---

const EXPLAINED = {
  id: "f1", title: "SECRET detected", severity: "critical",
  category: "data_classification", store: "prod", collection: "runbooks",
  suppressed: false, case: {state: "new", owner: null},
  evidence: {explanations: [{
    detector: "aws_access_key", label: "secret", matched_preview: "AK••••••••••••••••LE",
    confidence: "uncertain",
    confidence_reason: "No measured precision for aws_access_key.",
    counter_signals: [{code: "published_example",
                       detail: "AWS publishes this access key id in its documentation"}],
    disputed: true,
  }]},
};

test("a finding says what matched, how sure, and what argues against it", () => {
  const {context} = app();
  const view = context.explanationView(EXPLAINED);
  assert.match(view.textContent, /aws_access_key/);
  assert.match(view.textContent, /AK••••••••••••••••LE/);
  assert.match(view.textContent, /uncertain/);
  assert.match(view.textContent, /What argues against this/);
  assert.match(view.textContent, /AWS publishes this access key id in its documentation/);
});

test("an explanation never shows the raw value it matched", () => {
  const {context} = app();
  const view = context.explanationView(EXPLAINED);
  assert.doesNotMatch(view.textContent, /AKIAIOSFODNN7EXAMPLE/);
});

test("a match with nothing against it says so rather than staying blank", () => {
  const {context} = app();
  const view = context.explanationView({evidence: {explanations: [{
    detector: "aws_access_key", matched_preview: "AK••••••••••••••••99",
    confidence: "uncertain", confidence_reason: "No measured precision.",
    counter_signals: [], disputed: false,
  }]}});
  assert.match(view.textContent, /Nothing recorded argues against this match/);
});

test("a detector that does not explain itself admits it", () => {
  const {context} = app();
  assert.match(context.explanationView({evidence: {}}).textContent,
               /does not yet explain itself/);
});

test("findings group into causes, with disputed ones counted", () => {
  const {context} = app();
  const summary = context.causeSummary([
    EXPLAINED,
    {...EXPLAINED, id: "f2", collection: "docs",
     evidence: {explanations: [{detector: "aws_access_key", counter_signals: []}]}},
    {id: "f3", severity: "high", collection: "docs", category: "rag_integrity",
     evidence: {explanations: [{detector: "prompt_injection", counter_signals: []}]}},
  ]);
  assert.match(summary.textContent, /2 causes across 3 findings/);
  assert.match(summary.textContent, /aws_access_key/);
  assert.match(summary.textContent, /prompt_injection/);
  assert.match(summary.textContent, /1 with counter-signals/);
  assert.match(summary.textContent, /docs, runbooks/);
});

test("a finding with no explanation still groups under something", () => {
  const {context} = app();
  const summary = context.causeSummary([
    {id: "f1", severity: "medium", category: "configuration_posture", evidence: {}},
  ]);
  assert.match(summary.textContent, /configuration_posture/);
  assert.match(summary.textContent, /store scope/);
});

test("the case dialog leads with why the detector fired", async () => {
  const {context, doc} = app({
    "/admin/findings/f1/case": {state: "new", owner: null, events: [],
                                allowed_transitions: ["triaged"], is_open: true},
  });
  await context.caseModal(EXPLAINED, () => {});
  const text = doc.body.textContent;
  assert.match(text, /Why this fired/);
  assert.match(text, /AWS publishes this access key id/);
});
