import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// Phase 2: no long action blocks the interface, and every view is linkable.
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
  }
  append(...children) {
    for (const raw of children) {
      const c = typeof raw === "string" ? new Element("text", raw) : raw;
      c.parent = this;
      this.children.push(c);
    }
  }
  replaceChildren(...children) { this._text = ""; this.children = []; this.append(...children); }
  setAttribute(key, value) { this.attrs[key] = String(value); }
  getAttribute(key) { return key in this.attrs ? this.attrs[key] : null; }
  removeAttribute(key) { delete this.attrs[key]; }
  addEventListener(key, fn) { this.events[key] = fn; }
  remove() { this.removed = true; }
  click() { return this.events.click?.(); }
  focus() {}
  get className() { return [...this._classes].join(" "); }
  set className(value) { this._classes = new Set(String(value).split(/\s+/).filter(Boolean)); }
  get classList() {
    const set = this._classes;
    return {
      add: (...n) => n.forEach(x => set.add(x)),
      remove: (...n) => n.forEach(x => set.delete(x)),
      contains: n => set.has(n),
      toggle: (n, f) => { const on = f === undefined ? !set.has(n) : Boolean(f); on ? set.add(n) : set.delete(n); return on; },
    };
  }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(" "); }
  set textContent(value) { this._text = value; this.children = []; }
}

function find(node, predicate) {
  if (predicate(node)) return node;
  for (const child of node.children || []) {
    const found = find(child, predicate);
    if (found) return found;
  }
  return null;
}

function app(responses = {}, hash = "") {
  const calls = [];
  const body = new Element("body");
  const liveRegion = new Element("div");
  liveRegion.setAttribute("id", "live-region");
  const doc = {
    body,
    documentElement: new Element("html"),
    activeElement: null,
    events: {},
    getElementById: id => (id === "live-region" ? liveRegion : new Element("div")),
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener(key, fn) { this.events[key] = fn; },
    createElement: tag => new Element(tag),
    createElementNS: (_, tag) => new Element(tag),
    createTextNode: text => new Element("text", text),
  };
  const context = vm.createContext({
    Node: Element, FormData, Blob, Intl, URLSearchParams, document: doc,
    URL: {createObjectURL: () => "blob:x", revokeObjectURL() {}},
    setTimeout: fn => fn(),
    sessionStorage: {getItem: () => null, setItem() {}},
    localStorage: {getItem: () => null, setItem() {}},
    location: {hash},
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
  return {context, calls, doc, liveRegion};
}

// ------------------------------------------------------------- URL state ----

test("the hash carries the view and its state", () => {
  const {context} = app({}, "#/assess?store=prod&job=a1f2");
  assert.equal(context.currentView(), "assess");
  assert.equal(context.param("store"), "prod");
  assert.equal(context.param("job"), "a1f2");
  assert.equal(context.param("missing", "fallback"), "fallback");
});

test("an unknown view falls back to the overview without losing the app", () => {
  const {context} = app({}, "#/not-a-view?store=prod");
  assert.equal(context.currentView(), "overview");
});

test("setting a param preserves the others and the view", () => {
  const {context} = app({}, "#/assess?store=prod&max=500");
  context.setParams({job: "j-1"});
  const [view, query] = context.location?.hash?.split("?") ?? [];
  assert.ok(true);
  const parsed = new URLSearchParams(query);
  assert.equal(view, "#/assess");
  assert.equal(parsed.get("store"), "prod");
  assert.equal(parsed.get("max"), "500");
  assert.equal(parsed.get("job"), "j-1");
});

test("an empty value clears its param instead of writing a blank one", () => {
  const {context} = app({}, "#/templates?q=pci&framework=PCI-DSS");
  context.setParams({q: ""});
  assert.equal(context.location.hash.includes("q="), false);
  assert.equal(context.location.hash.includes("framework=PCI-DSS"), true);
});

test("a param write we made ourselves does not re-render the view", async () => {
  const responses = {
    "/admin/stores": {stores: []}, "/admin/policy-templates": {templates: []},
    "/admin/policies": {policies: []}, "/version": {}, "/healthz": {status: "ok"},
  };
  const {context, calls} = app(responses, "#/templates");
  await context.route();
  const afterFirstRender = calls.length;
  assert.ok(afterFirstRender > 0, "the view fetched its data");

  // The browser answers our own hash write with a hashchange event.
  const hashchange = {type: "hashchange"};
  context.setParams({q: "pci"});
  await context.route(hashchange);
  assert.equal(calls.length, afterFirstRender,
               "writing our own filter state must not tear the page down and refetch");

  context.location.hash = "#/templates?q=hipaa";
  await context.route(hashchange);
  const afterNavigation = calls.length;
  assert.ok(afterNavigation > afterFirstRender, "a hash change from elsewhere still routes");

  // Code that changed something and asks for a redraw gets one. Skipping it
  // (the old behaviour) left a list stale after adding to it.
  await context.route();
  assert.ok(calls.length > afterNavigation, "an explicit route() redraws the same page");
});

test("goTo builds a linkable address with its state", () => {
  const {context} = app({}, "#/overview");
  context.goTo("assess", {store: "prod", collection: "", max: null});
  assert.equal(context.location.hash, "#/assess?store=prod");
});

// --------------------------------------------------------- background runs ---

test("long work is submitted to the queue, not held open", async () => {
  const {context, calls} = app({
    "/stores/prod/audit?background=true": {job_id: "j-9", status: "queued", kind: "audit"},
  });
  const jobId = await context.startBackgroundRun("/stores/prod/audit", {body: {include_integrity: true}});
  assert.equal(jobId, "j-9");
  assert.equal(calls[0].path, "/stores/prod/audit?background=true");
  assert.equal(calls[0].opts.method, "POST");
});

test("an existing query string keeps its parameters when backgrounded", async () => {
  const {context, calls} = app({
    "/stores/prod/scan/integrity?collection=docs&background=true": {job_id: "j-3"},
  });
  await context.startBackgroundRun("/stores/prod/scan/integrity?collection=docs");
  assert.match(calls[0].path, /collection=docs&background=true$/);
});

test("a server that ignores the background flag is reported, not assumed", async () => {
  const {context} = app({"/stores/prod/audit?background=true": {findings: []}});
  await assert.rejects(() => context.startBackgroundRun("/stores/prod/audit"),
                       /did not accept this as a background run/);
});

test("a queued run says the work continues on the server and cannot be cancelled", () => {
  const {context} = app();
  const card = context.runCard({id: "j-1", status: "running", kind: "audit",
                                started_at: new Date().toISOString()}, {label: "Full audit", scope: "prod"});
  assert.match(card.textContent, /Full audit/);
  assert.match(card.textContent, /Running/);
  assert.match(card.textContent, /continues on the server/);
  assert.match(card.textContent, /cannot be cancelled/);
  // There is no cancel endpoint, so there must be no cancel control.
  assert.equal(find(card, n => n.tagName === "BUTTON" && /cancel/i.test(n.textContent)), null);
});

test("an interrupted run says its results were not recorded", () => {
  const {context} = app();
  const card = context.runCard({
    id: "j-2", status: "interrupted", kind: "audit",
    error: "worker restarted before this job finished; the work was not resumed",
  }, {label: "Full audit"});
  assert.match(card.className, /run-interrupted/);
  assert.match(card.textContent, /worker restarted/);
  assert.equal(find(card, n => n.attrs?.role === "alert") !== null, true);
});

test("a failed run surfaces its error assertively", () => {
  const {context} = app();
  const card = context.runCard({id: "j-3", status: "failed", error: "connector unreachable"},
                               {label: "Posture"});
  assert.match(card.textContent, /connector unreachable/);
  assert.equal(find(card, n => n.attrs?.role === "alert") !== null, true);
});

test("elapsed time is measured, and absent timestamps stay unknown", () => {
  const {context} = app();
  assert.equal(context.runElapsed({}), "-");
  assert.equal(context.runElapsed({started_at: "2026-09-17T10:00:00+00:00",
                                   finished_at: "2026-09-17T10:00:42+00:00"}), "42s");
  assert.equal(context.runElapsed({started_at: "2026-09-17T10:00:00+00:00",
                                   finished_at: "2026-09-17T10:02:05+00:00"}), "2m 5s");
  assert.equal(context.runElapsed({started_at: "2026-09-17T10:00:00+00:00",
                                   finished_at: "2026-09-17T11:00:30+00:00"}), "1h 0m", "an hour reads as hours");
  assert.equal(context.runElapsed({started_at: "not a date"}), "-");
});

test("watching a run polls to a terminal state and renders the result", async () => {
  const states = [
    {id: "j-7", status: "running", kind: "audit", started_at: "2026-09-17T10:00:00+00:00"},
    {id: "j-7", status: "succeeded", kind: "audit", started_at: "2026-09-17T10:00:00+00:00",
     finished_at: "2026-09-17T10:00:09+00:00", result: {findings: [], max_severity: "info"}},
  ];
  let call = 0;
  const {context} = app(path => {
    if (path === "/admin/jobs/j-7") return states[Math.min(call++, states.length - 1)];
    return undefined;
  });
  const container = new Element("div");
  const job = await context.watchRun("j-7", container, {
    label: "Full audit", scope: "prod", wait: () => {},
    renderResult: result => new Element("div", `result:${result.max_severity}`),
  });
  assert.equal(job.status, "succeeded");
  assert.equal(call, 2, "polls until the job reaches a terminal state");
  assert.match(container.textContent, /Completed/);
  assert.match(container.textContent, /result:info/);
});

test("a result renderer that throws does not lose the run card", async () => {
  const {context} = app({
    "/admin/jobs/j-8": {id: "j-8", status: "succeeded", kind: "audit", result: {}},
  });
  const container = new Element("div");
  await context.watchRun("j-8", container, {
    label: "Full audit", wait: () => {},
    renderResult: () => { throw new Error("could not render findings"); },
  });
  assert.match(container.textContent, /Completed/);
  assert.match(container.textContent, /could not render findings/);
});

test("losing the API mid-run reports the failure instead of polling forever", async () => {
  const {context} = app({"/admin/jobs/j-4": new Error("offline")});
  const container = new Element("div");
  const job = await context.watchRun("j-4", container, {label: "Audit", wait: () => {}});
  assert.equal(job.status, "queued", "the last known job state is preserved");
  assert.match(container.textContent, /Failed/);
  assert.match(container.textContent, /API is unreachable/);
});

function progressJob(status, phases, extra = {}) {
  return {id: "j-p", status, kind: "audit", progress: {phases}, ...extra};
}

test("a running checklist names the current phase and the chunk count", () => {
  const {context} = app();
  const card = context.runCard(progressJob("running", [
    {id: "classifying", label: "Classifying stored text", state: "done"},
    {id: "integrity", label: "Checking integrity", state: "current",
     detail: "orders, 2 of 5", chunks_read: 4200, chunks_bound: 10000},
    {id: "configuration", label: "Checking configuration", state: "pending"},
  ]), {label: "Full audit", scope: "prod"});
  const list = find(card, n => n.attrs?.["aria-label"] === "Assessment progress");
  assert.ok(list);
  assert.match(card.textContent, /Checking integrity/);
  assert.match(card.textContent, /orders, 2 of 5/);
  assert.match(card.textContent, /4,200 of 10,000 chunks read/);
  const current = find(card, n => n.attrs?.["aria-current"] === "step");
  assert.ok(current);
  assert.match(current.className, /is-current/);
  assert.equal(find(current, n => n.className.includes("run-progress-bar")) !== null, true);
  assert.equal(find(card, n => (n.className || "").includes("step-done")), null);
});

test("a finished row is a neutral marker, not a green check", () => {
  const {context} = app();
  const card = context.runCard(progressJob("succeeded", [
    {id: "configuration", label: "Checking configuration", state: "done"},
  ]), {label: "Posture"});
  const list = find(card, n => n.attrs?.["aria-label"] === "Assessment progress");
  assert.ok(list);
  assert.match(card.textContent, /finished/);
  assert.equal(find(list, n => (n.className || "").includes("step-done")), null);
  assert.equal(find(list, n => (n.className || "").includes("sev-ok")), null);
  assert.equal(find(list, n => n.className.includes("run-progress-mark")) !== null, true);
});

test("success keeps the checklist above the result", async () => {
  const {context} = app({
    "/admin/jobs/j-p": progressJob("succeeded", [
      {id: "configuration", label: "Checking configuration", state: "done"},
    ], {result: {findings: [], max_severity: "info"}}),
  });
  const container = new Element("div");
  await context.watchRun("j-p", container, {
    label: "Posture", wait: () => {},
    renderResult: () => new Element("div", "posture-result"),
  });
  assert.match(container.textContent, /Checking configuration/);
  assert.match(container.textContent, /finished/);
  assert.match(container.textContent, /posture-result/);
  assert.match(container.textContent, /Completed/);
});

test("failure keeps the in-progress row and the error", () => {
  const {context} = app();
  const card = context.runCard(progressJob("failed", [
    {id: "classifying", label: "Classifying stored text", state: "done"},
    {id: "integrity", label: "Checking integrity", state: "current", detail: "orders, 1 of 2"},
  ], {error: "connector unreachable"}), {label: "Full audit"});
  const current = find(card, n => n.attrs?.["aria-current"] === "step");
  assert.ok(current);
  assert.match(current.className, /is-current/);
  assert.equal(find(current, n => (n.className || "").includes("is-stopped")) !== null, true);
  assert.match(card.textContent, /connector unreachable/);
  assert.equal(find(card, n => n.attrs?.role === "alert") !== null, true);
});

test("a chunk-only poll does not update the live region", async () => {
  const states = [
    progressJob("running", [
      {id: "classifying", label: "Classifying stored text", state: "current", chunks_read: 100},
    ]),
    progressJob("running", [
      {id: "classifying", label: "Classifying stored text", state: "current", chunks_read: 400},
    ]),
    progressJob("succeeded", [
      {id: "classifying", label: "Classifying stored text", state: "done", chunks_read: 400},
    ], {result: {}}),
  ];
  let call = 0;
  const announced = [];
  const {context} = app(path => {
    if (path === "/admin/jobs/j-p") return states[Math.min(call++, states.length - 1)];
    return undefined;
  });
  context.announce = message => announced.push(message);
  const container = new Element("div");
  await context.watchRun("j-p", container, {label: "Full audit", wait: () => {}});
  assert.deepEqual(announced, ["Full audit: Classifying stored text", "Full audit Completed"]);
  assert.match(container.textContent, /400 chunks read/);
});

// ------------------------------------------------------------- lifecycle ----

test("the stepper marks one current stage and the ones already passed", () => {
  const {context} = app();
  const stepper = context.lifecycleStepper("run", {note: "Tracking a run."});
  assert.equal(stepper.attrs["aria-label"], "Assessment lifecycle");
  const steps = find(stepper, n => n.tagName === "OL").children;
  assert.equal(steps.filter(s => s.className.includes("step-current")).length, 1);
  assert.equal(steps.filter(s => s.className.includes("step-done")).length, 2, "scope and validate");
  assert.match(stepper.textContent, /Tracking a run\./);
  assert.match(stepper.textContent, /\(current stage\)/, "the current stage is named, not just coloured");
});

test("an unknown stage highlights nothing rather than guessing", () => {
  const {context} = app();
  const steps = find(context.lifecycleStepper("nonsense"), n => n.tagName === "OL").children;
  assert.equal(steps.filter(s => s.className.includes("step-current")).length, 0);
  assert.equal(steps.filter(s => s.className.includes("step-done")).length, 0);
});

// ------------------------------------------------- information architecture ---

function shell(hash = "#/overview", responses = {}) {
  const harness = app({
    "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"},
                               {store_id: "docs", kind: "chroma"}]},
    "/admin/policy-templates": {templates: []}, "/admin/policies": {policies: []},
    "/version": {}, "/healthz": {status: "ok"},
    "/admin/history": {jobs: [], stats: {total_findings: 0, by_severity: {}}},
    "/runtime/alerts/stats": {total: 0}, ...responses,
  }, hash);
  return harness;
}

test("the sidebar offers six areas, with System at its foot and Docs as a help icon", () => {
  const {context} = shell();
  const nav = new Element("div");
  const system = new Element("div");
  context.document.getElementById = id => (id === "nav-system" ? system : nav);
  context.buildNav();
  assert.deepEqual(nav.children.map(b => b.dataset.area),
                   ["Overview", "Estate", "Assessments", "Findings", "Compliance", "Operations"]);
  assert.deepEqual(system.children.map(b => b.dataset.view), ["audit", "alerting", "status"],
                   "audit log, alerting and status are quiet links at the foot");
  assert.ok(!nav.children.some(b => b.dataset.area === "Docs"), "Docs is the help icon, not an area");
});

test("an area with several screens shows tabs; one with a single screen does not", () => {
  const {context} = shell();
  const tabs = context.areaTabs("assess");
  assert.equal(tabs.attrs["aria-label"], "Assessments sections");
  const labels = tabs.children.map(t => t.textContent.trim());
  // 2026-10-06: "Run" and "Archive" became "New assessment" and "History".
  assert.deepEqual(labels, ["New assessment", "History"], "Runs is a view within History");
  const active = tabs.children.filter(t => t.attrs["aria-current"] === "page");
  assert.equal(active.length, 1);
  assert.equal(active[0].textContent.trim(), "New assessment");

  const findings = context.areaTabs("findings");
  assert.deepEqual(findings.children.map(t => t.textContent.trim()),
                   ["Findings", "Actions", "False positives"],
                   "what could be done about a finding, and what is known benign, sit beside it");
  // A view within a screen keeps its parent's tab current.
  const runs = context.areaTabs("jobs");
  assert.equal(runs.children.filter(t => t.attrs["aria-current"] === "page")[0].textContent.trim(), "History");

  assert.equal(context.areaTabs("overview"), "", "a one-screen area needs no tabs");
});

test("breadcrumbs name the area and the screen inside it", () => {
  const {context} = shell();
  const crumbs = context.breadcrumbs("schema");
  assert.equal(crumbs.attrs["aria-label"], "Breadcrumb");
  assert.match(crumbs.textContent, /Estate/);
  assert.match(crumbs.textContent, /Schema/);
  const current = find(crumbs, n => n.attrs?.["aria-current"] === "page");
  assert.ok(current, "the current screen is marked, not just styled");
});

// A record (one saved audit, one store) is a level below its screen. Its
// address keeps the query form; DETAIL_PARAMS makes it a step you can see and
// climb out of.
test("on a record, the breadcrumb is area, screen, record, and the screen step goes back to its list", () => {
  const {context} = shell("#/history?audit=a1&store=prod");
  const crumbs = context.breadcrumbs("history", "audit=a1&store=prod");
  assert.equal(crumbs.attrs["aria-label"], "Breadcrumb");
  const items = crumbs.children[0].children;
  assert.equal(items.length, 3, "Assessments › History › Audit a1");
  assert.deepEqual(items.map(li => li.textContent.trim()), ["Assessments", "History", "Audit a1"]);
  const marked = items.filter(li => find(li, n => n.attrs?.["aria-current"] === "page"));
  assert.equal(marked.length, 1, "one step is the page");
  assert.equal(marked[0], items[2], "and it is the record");
  assert.equal(items[2].children[0].tagName, "SPAN", "the record is where you are, not a link");
  items[1].children[0].click();
  assert.equal(context.location.hash, "#/history?store=prod", "the store is carried back to the list");
  items[0].children[0].click();
  assert.equal(context.location.hash, "#/assess", "the area step goes to the area's first screen");
});

test("detailOf reads each record param, and a list has none", () => {
  const {context} = shell();
  const label = (view, query) => context.detailOf(view, query)?.label ?? null;
  assert.equal(label("stores", "store=prod"), "prod");
  assert.equal(label("schema", "store=prod&collection=docs"), "docs");
  assert.deepEqual({...context.detailOf("schema", "store=prod&collection=docs").parent}, {store: "prod"});
  assert.equal(label("history", "scan=s1"), "Scan s1");
  // An id that already says what it is is not prefixed twice.
  assert.equal(label("history", "audit=audit-8d47"), "audit-8d47");
  assert.equal(label("actions", "plan=plan-3f0c"), "plan-3f0c");
  assert.equal(label("dsar", "request=dsar-12ab"), "Request dsar-12ab", "a dsar- id still reads as a request");
  assert.deepEqual({...context.detailOf("history", "scan=s1").parent}, {list: "scans"});
  assert.equal(label("actions", "plan=p1"), "Plan p1");
  assert.equal(label("actions", "fix=f1"), "Fix");
  assert.equal(label("actions", "finding=f1"), "Fix");
  assert.equal(label("actions", "queue=approval&plan=p1"), null, "the approval queue outranks a plan");
  assert.equal(label("criteria", "answers=1&store=prod"), "Questions");
  assert.equal(label("dsar", "request=r1"), "Request r1");
  assert.equal(label("findings", "finding=f1"), null, "a finding opens a drawer over the list, not a page");
  for (const view of ["stores", "history", "actions", "criteria", "dsar", "overview"]) {
    assert.equal(context.detailOf(view, ""), null, `${view} with no record param is a list`);
  }
});

test("every screen resolves to exactly one area", () => {
  const {context} = shell();
  for (const id of ["overview", "stores", "schema", "assess", "history", "jobs",
                    "findings", "actions", "policies", "templates", "falsepositives", "runtime",
                    "detectors", "alerting", "ingest", "dsar", "audit", "status"]) {
    const area = context.areaOf(id);
    assert.ok(area, `${id} belongs to no area`);
    assert.ok(area[3].includes(id));
  }
});

test("the palette offers areas, screens, and the stores that are registered", async () => {
  const {context} = shell();
  await context.loadCore();
  const entries = context.paletteEntries();
  const groups = new Set(entries.map(e => e.group));
  assert.deepEqual([...groups].sort(), ["Areas", "Screens", "Stores"]);
  assert.ok(entries.some(e => e.label === "Estate"));
  assert.ok(entries.some(e => e.label === "Compliance: Templates"));
  assert.ok(entries.some(e => e.label === "prod"));
  assert.ok(entries.some(e => e.label === "Assess prod"));
  for (const entry of entries) assert.equal(typeof entry.run, "function");
});

test("a palette entry navigates with the state it implies", async () => {
  const {context} = shell();
  await context.loadCore();
  const assess = context.paletteEntries().find(e => e.label === "Assess prod");
  assess.run();
  assert.equal(context.location.hash, "#/assess?store=prod");
});

test("the palette filters as you type and reports its denominator", () => {
  const {context} = shell();
  const {input, list, count} = context.openPalette();
  const total = context.paletteEntries().length;
  assert.ok(list.children.length > 0);
  assert.equal(count.textContent, `${total} of ${total}`);

  input.value = "compliance";
  input.events.input();
  assert.ok(list.children.length < total, "the list narrows");
  assert.match(count.textContent, new RegExp(`^${list.children.length} of ${total}$`),
               "the count states what it filtered from");
  assert.ok(list.children.some(c => /Compliance/.test(c.textContent)));
});

test("the palette keyboard model moves a selection and opens it", () => {
  const {context} = shell();
  const {input, list} = context.openPalette();
  const selected = () => list.children.findIndex(c => c.attrs["aria-selected"] === "true");
  assert.equal(selected(), 0);

  input.events.keydown({key: "ArrowDown", preventDefault() {}});
  assert.equal(selected(), 1);
  input.events.keydown({key: "ArrowUp", preventDefault() {}});
  assert.equal(selected(), 0);

  input.value = "estate";
  input.events.input();
  input.events.keydown({key: "Enter", preventDefault() {}});
  assert.equal(context.location.hash, "#/stores");
});

test("a name that contains the query outranks a description that merely resembles it", () => {
  const {context} = shell();
  const ranked = context.rankPaletteEntries([
    {label: "Overview", hint: "What changed, and what needs you", group: "Areas"},
    {label: "Compliance: Frameworks", hint: "Every regulation", group: "Screens"},
    {label: "Frameworks: GDPR", hint: "GDPR obligations", group: "Screens"},
  ], "gdpr");
  assert.equal(ranked[0].label, "Frameworks: GDPR");
  assert.ok(!ranked.some(e => e.label === "Overview"),
    "a subsequence in a description is not a match");
});

test("the palette says so when nothing matches", () => {
  const {context} = shell();
  const {input, list} = context.openPalette();
  input.value = "zzzzzz-no-such-thing";
  input.events.input();
  assert.match(list.textContent, /Nothing matches that/);
});

test("old links resolve to their screen, keeping bookmarks alive", () => {
  const {context} = shell("#/policy-templates?framework=HIPAA");
  assert.equal(context.currentView(), "templates");
  assert.equal(context.param("framework"), "HIPAA");
});
