import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// The Actions screen. Every assertion here is about a claim the screen must
// not make: that a plan covers a finding, that a refusal did not happen, that a
// blocked operation would run, or that an unreadable backend means nothing was
// proposed.
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

function app(responses = {}, hash = "#/actions?store=prod") {
  const doc = {
    body: new Element("body"), documentElement: new Element("html"),
    activeElement: null, events: {},
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
      const base = path.replace(/^https?:\/\/[^/]+/, "");
      const value = typeof responses === "function" ? responses(base, opts) : responses[base];
      if (value === undefined) throw new Error(`Unexpected request: ${base}`);
      if (typeof value.status === "number") {
        return {ok: false, status: value.status, statusText: "Error",
                json: async () => ({detail: value.detail})};
      }
      return {ok: true, headers: {get: () => "application/json"}, json: async () => value};
    },
  });
  vm.runInContext(source, context);
  return {context, doc};
}

const CORE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "chroma"}]},
  "/version": {version: "1.0", detection_version: "1.0", detectors: []},
  "/healthz": {status: "ok"},
};

function suggestion(overrides = {}) {
  return {
    id: "s1", action: "tag_exclude", title: "Tag chunks for exclusion from retrieval",
    risk: "low", reversible: true, undo: "Remove the tag.", gate: "approval",
    finding_id: "f1", store: "prod", collection: "runbooks",
    chunk_ids: ["c1", "c2", "c3", "c4", "c5"], rests_on: ["aws_access_key"],
    calibrated: false, rationale: "SECRET was matched by aws_access_key.",
    observed_chunks: 300, named_chunks: 5, reaches_all_observed: false,
    ...overrides,
  };
}


test("a plan that reaches five of three hundred chunks says both numbers", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [suggestion()], withheld: [], note: ""},
    "/stores/prod/actions/plans": {plans: []},
  });
  const view = await context.renderActions();
  // "5 chunks" alone would read as the whole problem. The point of the screen
  // is that acting on this does not resolve the finding.
  assert.match(view.textContent, /5 of\s+300/);
  assert.match(view.textContent, /retained only a sample/);
});


test("a suggestion covering everything observed does not cry partial", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {
      suggestions: [suggestion({chunk_ids: ["c1"], observed_chunks: 1, named_chunks: 1,
                                reaches_all_observed: true})],
      withheld: [], note: ""},
    "/stores/prod/actions/plans": {plans: []},
  });
  const view = await context.renderActions();
  assert.doesNotMatch(view.textContent, /retained only a sample/);
});


test("refusals are shown with their reasons, not swallowed", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {
      suggestions: [suggestion()],
      withheld: [{action: "delete_chunks", title: "Delete chunks", finding_id: "f1",
                  reason: "The benchmark has not established a precision for aws_access_key."}],
      note: ""},
    "/stores/prod/actions/plans": {plans: []},
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /Withheld \(1\)/);
  assert.match(view.textContent, /has not established a precision/);
});


test("an unmeasured detector is marked as such on the proposal it motivates", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [suggestion()], withheld: [], note: ""},
    "/stores/prod/actions/plans": {plans: []},
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /unmeasured/);
});


test("an irreversible action is labelled as one, next to its undo", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {
      suggestions: [suggestion({action: "delete_chunks", title: "Delete chunks",
                                reversible: false, calibrated: true,
                                undo: "It cannot be undone."})],
      withheld: [], note: ""},
    "/stores/prod/actions/plans": {plans: []},
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /cannot be undone/);
});


test("a backend that cannot answer is not rendered as 'nothing proposed'", async () => {
  // The archetypal bug this product exists to prevent: an error path that
  // renders as an empty, reassuring result.
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {status: 503, detail: "no scan history is configured"},
    "/stores/prod/actions/plans": {plans: []},
  });
  const view = await context.renderActions();
  assert.doesNotMatch(view.textContent, /Nothing is proposed/);
  assert.match(view.textContent, /no scan history is configured/);
});


test("an empty result says nothing was proposed and points at the refusals", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [], withheld: [], note: ""},
    "/stores/prod/actions/plans": {plans: []},
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /Nothing is proposed/);
});


test("plans that cannot be listed are unavailable, not an empty list", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [], withheld: [], note: ""},
    "/stores/prod/actions/plans": {status: 503, detail: "no scan history"},
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /could not be read/);
  assert.doesNotMatch(view.textContent, /No plans have been staged/);
});


test("the diff leads with what a reviewer would skim past", async () => {
  const {context} = app({
    ...CORE,
    "/actions/plans/plan-1/diff": {
      id: "plan-1", plan_hash: "abc", store: "prod",
      blast_radius: {operations: 2, executable: 1, chunks_targeted: 1,
                     chunks_observed_by_findings: 300, reaches_all_observed: false,
                     irreversible_chunks: 1},
      review: {warnings: ["1 chunk(s) would be permanently deleted."],
               executes: false, execution_note: "Nothing here writes to the store."},
      operations: [
        {title: "Delete chunks", supported: true, resolved: 1, missing: 0, unchecked: 0,
         undo: "It cannot be undone.", support_reason: "",
         sample: [{chunk_id: "c1", preview: "rotate AKIA..."}]},
        {title: "Tag chunks", supported: false, resolved: 0, missing: 0, unchecked: 5,
         undo: "Remove the tag.",
         support_reason: "The connector does not declare 'metadata_write'.", sample: []},
      ],
    },
  });
  const shown = await context.planReview("plan-1");
  const text = shown.textContent;
  assert.match(text, /Before you read the operations/);
  assert.match(text, /permanently deleted/);
  assert.match(text, /of\s+300/);                      // reach, not just what it touches
  assert.match(text, /does not declare 'metadata_write'/);  // why the blocked one is blocked
  assert.match(text, /Nothing here writes to the store/);
});


test("a plan that no longer matches its hash is refused, not rendered", async () => {
  const {context} = app({
    ...CORE,
    "/actions/plans/plan-1/diff": {status: 409, detail: "does not match its recorded hash"},
  });
  const shown = await context.planReview("plan-1");
  assert.match(shown.textContent, /does not match its recorded hash/);
  assert.doesNotMatch(shown.textContent, /Before you read the operations/);
});


test("whether this deployment can write at all is said on the screen", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [suggestion()], withheld: [], note: ""},
    "/stores/prod/actions/plans": {plans: []},
    "/actions/safe-mode": {safe_mode: true, variable: "VECSHIELD_SAFE_MODE",
                           executable_actions: ["tag_exclude"],
                           note: "Writes are blocked. Suggesting, staging, reviewing "
                                 + "and approving all work; set VECSHIELD_SAFE_MODE=0 "
                                 + "to permit execution."},
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /Writes are blocked/);
});


test("a deployment whose write setting cannot be read does not claim it can write",
     async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [], withheld: [], note: ""},
    "/stores/prod/actions/plans": {plans: []},
    "/actions/safe-mode": {status: 503, detail: "unavailable"},
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /could not be read/);
  assert.doesNotMatch(view.textContent, /Writes are permitted/);
});


function planWith(operations, extra = {}) {
  return {
    id: "plan-1", plan_hash: "abc", store: "prod",
    blast_radius: {operations: operations.length, executable: 1, chunks_targeted: 1,
                   chunks_observed_by_findings: 300, reaches_all_observed: false,
                   irreversible_chunks: 0},
    review: {warnings: [], executes: false, execution_note: "Nothing writes yet."},
    operations, ...extra,
  };
}

const TAG_OP = {title: "Tag chunks", action: "tag_exclude", supported: true,
                runnable: true, reversible: true, resolved: 1, missing: 0,
                unchecked: 0, undo: "Remove the tag.", support_reason: "", sample: []};


test("approving asks for a reason rather than offering a bare button", async () => {
  const sent = [];
  const {context} = app((path) => {
    if (path === "/actions/plans/plan-1/diff") return planWith([TAG_OP]);
    if (path === "/actions/plans/plan-1/executions") return {approvals: [], executions: []};
    return CORE[path];
  });
  const shown = await context.planReview("plan-1");
  assert.match(shown.textContent, /A second person must authorize this plan; the author cannot/);
  assert.match(shown.textContent, /re-staging needs a fresh one/);
  assert.equal(sent.length, 0, "opening the dialog must not approve anything");
});


test("a plan nobody has approved says so, and shows no execute control", async () => {
  const {context} = app((path) => {
    if (path === "/actions/plans/plan-1/diff") return planWith([TAG_OP]);
    if (path === "/actions/plans/plan-1/executions") return {approvals: [], executions: []};
    return CORE[path];
  });
  const shown = await context.planReview("plan-1");
  assert.match(shown.textContent, /Nobody has approved this plan/);
  assert.doesNotMatch(shown.textContent, /Execute/);
});


test("an approved plan shows who approved it and why, next to the execute control",
     async () => {
  const {context} = app((path) => {
    if (path === "/actions/plans/plan-1/diff") return planWith([TAG_OP]);
    if (path === "/actions/plans/plan-1/executions") {
      return {approvals: [{id: "appr-1", approver: "dana",
                           approved_at: "2026-09-18T10:00:00Z",
                           reason: "Checked the diff; the key is live."}],
              executions: []};
    }
    return CORE[path];
  });
  const shown = await context.planReview("plan-1");
  assert.match(shown.textContent, /dana/);
  assert.match(shown.textContent, /the key is live/);
  assert.match(shown.textContent, /Execute/);
});


test("a halted execution is not rendered as a run that worked", async () => {
  const {context} = app((path) => {
    if (path === "/actions/plans/plan-1/diff") return planWith([TAG_OP]);
    if (path === "/actions/plans/plan-1/executions") {
      return {approvals: [],
              executions: [{id: "e1", started_at: "2026-09-18T10:00:00Z",
                            executed_by: "dana", halted: 1}]};
    }
    return CORE[path];
  });
  const shown = await context.planReview("plan-1");
  assert.match(shown.textContent, /HALTED|halted/i);
});


test("an action that is built but gated shut is not shown as available", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [], withheld: [], note: ""},
    "/stores/prod/actions/plans": {plans: []},
    "/actions/safe-mode": {
      safe_mode: true, variable: "VECSHIELD_SAFE_MODE", note: "Writes are blocked.",
      executable_actions: ["tag_exclude", "delete_chunks"],
      actions: [
        {action: "tag_exclude", title: "Tag chunks", reversible: true,
         implemented: true, reachable: true, blocked_by: null},
        {action: "delete_chunks", title: "Delete chunks", reversible: false,
         implemented: true, reachable: false,
         blocked_by: "No detector is measured at 'likely'; the strongest measured "
                     + "class is 'possible'. Growing the benchmark corpus is what "
                     + "changes this."},
      ],
    },
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /Delete chunks/);
  assert.match(view.textContent, /irreversible/);
  assert.match(view.textContent, /No detector is measured at 'likely'/);
  assert.match(view.textContent, /Growing the benchmark corpus/);
});


test("nothing is pre-selected for staging, and the button waits for a choice", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [suggestion()], withheld: [], note: ""},
    "/stores/prod/actions/plans": {plans: []},
    "/actions/safe-mode": {safe_mode: true, note: "Writes are blocked.", actions: []},
  });
  const view = await context.renderActions();
  const boxes = [];
  (function walk(n) { if (n.tagName === "INPUT" && n.attrs.type === "checkbox"
                          && /^Select /.test(n.attrs["aria-label"] || "")) boxes.push(n);
                      (n.children || []).forEach(walk); })(view);
  assert.equal(boxes.length, 1);
  assert.equal(boxes[0].checked, false);
  let button = null;
  (function walk(n) { if (n.tagName === "BUTTON" && /Stage selected/.test(n.textContent)) button = n;
                      (n.children || []).forEach(walk); })(view);
  assert.ok(button, "a stage control exists");
  assert.equal(button.disabled, true, "nothing chosen, nothing to stage");
});


test("staging sends exactly the chosen proposals", async () => {
  const sent = [];
  const {context} = app((path, opts) => {
    if (path === "/stores/prod/actions/suggest") {
      return {suggestions: [suggestion(), suggestion({id: "s2", finding_id: "f2",
                                                     action: "quarantine_collection",
                                                     title: "Quarantine"})],
              withheld: [], note: ""};
    }
    if (path === "/stores/prod/actions/plans" && opts?.method === "POST") {
      sent.push(JSON.parse(opts.body));
      return {id: "plan-1", plan_hash: "abc"};
    }
    if (path === "/stores/prod/actions/plans") return {plans: []};
    if (path === "/actions/safe-mode") return {safe_mode: true, note: "", actions: []};
    return CORE[path];
  });
  const view = await context.renderActions();
  const boxes = [];
  (function walk(n) { if (n.tagName === "INPUT" && n.attrs.type === "checkbox"
                          && /^Select /.test(n.attrs["aria-label"] || "")) boxes.push(n);
                      (n.children || []).forEach(walk); })(view);
  boxes[1].events.change({target: {checked: true}});
  let button = null;
  (function walk(n) { if (n.tagName === "BUTTON" && /Stage selected/.test(n.textContent)) button = n;
                      (n.children || []).forEach(walk); })(view);
  assert.equal(button.disabled, false);
  await button.events.click();
  assert.equal(sent.length, 1);
  assert.deepEqual(sent[0].suggestions.map(s => s.id), ["s2"]);
});


test("a redaction shows the exact replacement the reviewer is approving", async () => {
  const {context} = app((path) => {
    if (path === "/actions/plans/plan-1/diff") {
      return planWith([{
        title: "Redact the matched spans in the stored text", action: "redact_text",
        supported: true, runnable: true, reversible: true, resolved: 1, missing: 0,
        unchecked: 0, undo: "Restore from the retained original.",
        caveat: "The vector is not changed and still encodes the original text.",
        support_reason: "",
        sample: [{chunk_id: "c1", preview: "rotate AKIA5TQ2NHBGVCXZ9WQ1 before Friday",
                  redacted_preview: "rotate [REDACTED:secret] before Friday"}],
      }]);
    }
    if (path === "/actions/plans/plan-1/executions") return {approvals: [], executions: []};
    return CORE[path];
  });
  const shown = await context.planReview("plan-1");
  assert.match(shown.textContent, /\[REDACTED:secret\]/);
  assert.match(shown.textContent, /vector is not changed/);
});


test("an executed plan offers no approve control and says why", async () => {
  const {context} = app((path) => {
    if (path === "/actions/plans/plan-1/diff") return planWith([TAG_OP], {state: "executed"});
    if (path === "/actions/plans/plan-1/executions") {
      return {approvals: [{id: "a1", approver: "dana", approved_at: "2026-09-18T10:00:00Z",
                           reason: "Checked."}],
              executions: [{id: "e1", started_at: "2026-09-18T10:05:00Z",
                            executed_by: "dana", halted: 0}]};
    }
    return CORE[path];
  });
  const shown = await context.planReview("plan-1");
  assert.match(shown.textContent, /is executed and cannot be approved again/);
  const buttons = [];
  (function walk(n) { if (n.tagName === "BUTTON") buttons.push(n.textContent.trim());
                      (n.children || []).forEach(walk); })(shown);
  assert.ok(!buttons.includes("Approve"));
  assert.ok(!buttons.includes("Execute"), "an approval on an executed plan is spent");
});


test("a chunk a gated action cannot reach is listed with the detector that held it back",
     async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {
      suggestions: [suggestion({action: "redact_text", title: "Redact the matched spans",
                                chunk_ids: ["c1"], observed_chunks: 2, named_chunks: 2,
                                reaches_all_observed: false, calibrated: true,
                                excluded: [{chunk_id: "c2",
                                            reason: "slack_token is 'uncertain'"}]})],
      withheld: [], note: ""},
    "/stores/prod/actions/plans": {plans: []},
    "/actions/safe-mode": {safe_mode: true, note: "", actions: []},
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /1 of\s+2/);
  assert.match(view.textContent, /held back/);
  assert.match(view.textContent, /c2\s*:\s*slack_token is 'uncertain'/);
});


test("disputed chunks are excluded unless the reviewer ticks the box", async () => {
  const sent = [];
  const {context} = app((path, opts) => {
    if (path === "/stores/prod/actions/suggest") {
      sent.push(JSON.parse(opts.body)); return {suggestions: [], withheld: [], note: ""};
    }
    if (path === "/stores/prod/actions/plans") return {plans: []};
    if (path === "/actions/safe-mode") return {safe_mode: true, note: "", actions: []};
    return CORE[path];
  });
  const view = await context.renderActions();
  assert.deepEqual(sent[0], {include_disputed: false, include_resolved: false});
  let box = null;
  (function walk(n) { if (n.tagName === "INPUT" && n.attrs.id === "include-disputed") box = n;
                      (n.children || []).forEach(walk); })(view);
  assert.ok(box && box.checked === false, "off by default");
  assert.match(view.textContent, /Include disputed-only chunks/);
  assert.match(box.parent.children[1].attrs.title, /every match is disputed/);
});




// ---- Fix a finding: #/actions?fix=<id> ----------------------------------

function remediationView(overrides = {}) {
  return {
    finding: {id: "f9", title: "Chunks without a tenant value in 'tickets'", severity: "medium",
              collection: "tickets"},
    store_id: "prod", store_registered: true, store_kind: "chroma",
    kind: "tenant_untagged", kind_label: "Chunks with no tenant value",
    check: "tenant_isolation", rescan_supported: true,
    case: {state: "new"}, resolution: null, newer_record: null,
    executable: [{
      id: "s-assign", action: "assign_tenant", mode: "executable",
      title: "Assign a tenant to chunks that have none", risk: "medium", reversible: true,
      undo: "Remove the tenant field.", effect: "Writes the tenant field.",
      caveat: "Every targeted chunk receives the same tenant.",
      verification: "Each chunk is read back.", finding_id: "f9", store: "prod",
      collection: "tickets", chunk_ids: [], selector: {match: "missing_field", field: "tenant_id"},
      selector_text: "every chunk with no 'tenant_id' value", params: {tenant_field: "tenant_id"},
      needs_params: ["tenant_value"], param_hints: {tenant_value: ["acme", "globex"]},
      basis: "condition", reaches_all_observed: true,
      rescan_expect: "clears", rescan_text: "Removes what the check observes: a re-scan should stop observing the finding.",
      supported: true, support_reason: "The connector declares 'metadata_write'.", scope: "chunks",
    }, {
      id: "s-move", action: "quarantine_chunks", mode: "executable",
      title: "Move chunks to a quarantine collection", risk: "medium", reversible: true,
      undo: "Copy back.", effect: "Moves them.", verification: "Read back.",
      finding_id: "f9", store: "prod", collection: "tickets", chunk_ids: [],
      selector_text: "every chunk with no 'tenant_id' value", basis: "condition",
      needs_params: [], reaches_all_observed: true, scope: "chunks",
      supported: false, support_reason: "The connector does not declare 'delete'.",
    }],
    withheld: [{action: "delete_chunks", title: "Delete chunks", finding_id: "f9",
                reason: "No detector is measured at 'likely'."}],
    guided: [{
      id: "f9:reject-untagged", mode: "guided", finding_id: "f9",
      title: "Make ingestion reject chunks without 'tenant_id'", summary: "2 chunks carry none.",
      steps: ["In the ingestion job, refuse chunks with no tenant_id.",
              "Mark this done here, then run the re-scan: VecShield re-runs the check."],
      owner: "ingestion pipeline owner", risk: "low", reversible: true, undo: "Remove the check.",
      settings: [{where: "chunk metadata", key: "tenant_id", value: "<owner>", note: ""}],
      verify: "A re-scan counts the chunks with no tenant value.", check: "tenant_isolation",
      rescan_supported: true, not_executable_because: "The ingestion pipeline is the customer's code.",
      attested: null, last_rescan: null,
    }],
    plans: [],
    rescans: [],
    safe_mode: {safe_mode: true, variable: "VECSHIELD_SAFE_MODE",
                how_to_enable: "Set VECSHIELD_SAFE_MODE=0 in the server's environment and restart it.",
                note: "Writes are blocked on this deployment."},
    separation_of_duties: {separation_of_duties: "required"},
    note: "Executable steps run through staging.",
    ...overrides,
  };
}

function findAll(node, pred, out = []) {
  if (pred(node)) out.push(node);
  (node.children || []).forEach(c => findAll(c, pred, out));
  return out;
}
const buttons = (root, re) => findAll(root, n => n.tagName === "BUTTON" && re.test(n.textContent));
const radios = root => findAll(root, n => n.tagName === "INPUT" && n.attrs.type === "radio");

function fixApp(handler, hash = "#/actions?fix=f9") {
  return app((path, opts) => {
    const hit = handler(path, opts);
    if (hit !== undefined) return hit;
    return CORE[path] || {approvals: {separation_of_duties: "required"}};
  }, hash);
}

test("the fix page picks the recommended fix and says what it changes, briefly", async () => {
  const {context} = fixApp(path => path === "/admin/findings/f9/remediation" ? remediationView() : undefined);
  const page = await context.remediationPage("f9");
  const text = page.textContent;
  // The first fix this store can perform is chosen for the reader.
  const options = radios(page);
  assert.equal(options.length, 3, "two executable fixes and one guided one");
  assert.equal(options[0].checked, true);
  assert.match(text, /recommended/);
  assert.match(text, /VecShield does it/);
  assert.match(text, /you do it/);
  // What changes, whether it can be undone, how it is checked, and what a
  // re-scan should then show: four short facts, not paragraphs.
  assert.match(text, /What changes/);
  assert.match(text, /every chunk with no 'tenant_id' value/i);
  assert.match(text, /Reversible\?\s*Yes/);
  assert.match(text, /Verified by/);
  assert.match(text, /Reaches/);
  assert.match(text, /a re-scan should stop observing the finding/);
  assert.match(text, /Does not/);
  // Safe mode is said up front, with the setting that changes it.
  assert.match(text, /Writes are blocked on this deployment/);
  assert.match(text, /VECSHIELD_SAFE_MODE=0/);
  // Refusals stay on the page, compact, with their reason.
  assert.match(text, /Withheld \(1\)/);
  assert.match(text, /No detector is measured at 'likely'/);
});

test("a fix this store cannot perform can be read but not staged", async () => {
  const {context} = fixApp(path => path === "/admin/findings/f9/remediation" ? remediationView() : undefined);
  const page = await context.remediationPage("f9");
  radios(page)[1].events.change();
  assert.match(page.textContent, /does not declare 'delete'/);
  const stage = buttons(page, /Stage this fix/);
  assert.equal(stage.length, 1);
  assert.equal(stage[0].disabled, true);
});

test("a fix whose store support was never checked says so rather than reading as certain", async () => {
  const base = remediationView();
  const executable = base.executable.map((s, i) => i === 0
    ? {...s, supported: null, support_reason: "The store could not be opened: unreachable."} : s);
  const {context} = fixApp(path => path === "/admin/findings/f9/remediation"
    ? remediationView({executable}) : undefined);
  const page = await context.remediationPage("f9");
  assert.match(page.textContent, /support not checked/, "the unchecked store is marked on the option");
  // Only the one option was left unchecked; a store known to support the fix,
  // or known not to, gets no such chip.
  assert.equal(page.textContent.match(/support not checked/g).length, 1);
});

test("a guided fix says why a person does it, and that marking it done is a claim", async () => {
  const {context} = fixApp(path => path === "/admin/findings/f9/remediation" ? remediationView() : undefined);
  const page = await context.remediationPage("f9");
  radios(page)[2].events.change();
  const text = page.textContent;
  assert.match(text, /The ingestion pipeline is the customer's code/);
  assert.match(text, /records a claim; only the re-scan verifies it/);
  assert.doesNotMatch(text, /Mark this done here/, "the buttons say it; the list does not repeat it");
});

test("staging sends the tenant the person typed, offers recorded values, and never guesses one", async () => {
  const sent = [];
  let reads = 0;
  const {context} = fixApp((path, opts) => {
    if (path === "/admin/findings/f9/remediation") { reads += 1; return remediationView(); }
    if (path === "/stores/prod/actions/plans" && opts?.method === "POST") {
      sent.push(JSON.parse(opts.body));
      return {id: "plan-7", operations: [{runnable: true}]};
    }
    return undefined;
  });
  const page = await context.remediationPage("f9");
  const input = findAll(page, n => n.tagName === "INPUT" && /Tenant to assign/.test(n.attrs["aria-label"] || ""))[0];
  assert.ok(input, "the value the action needs is asked for");
  assert.equal(input.value, "", "not pre-filled");
  assert.ok(findAll(page, n => n.tagName === "DATALIST").length, "recorded tenants are offered");
  const button = buttons(page, /Stage this fix/)[0];
  await button.events.click();
  assert.equal(sent.length, 0, "nothing is staged without the tenant");
  input.value = "acme";
  await button.events.click();
  assert.equal(sent.length, 1);
  assert.equal(sent[0].suggestions[0].params.tenant_value, "acme");
  assert.equal(sent[0].suggestions[0].params.tenant_field, "tenant_id");
  assert.equal(reads, 2, "the page redraws in place to show the staged plan");
});

function withPlan(stage, extra = {}) {
  return remediationView({plans: [{id: "plan-3", state: stage === "approved" ? "staged" : "executed",
    staged_by: "admin", staged_at: "2026-09-18T10:00:00Z", you: {may_approve: true, would_be_self_approval: true},
    summary: {stage, findings: ["f9"],
              operations: [{action: "assign_tenant", title: "Assign a tenant to chunks that have none",
                            params: {tenant_value: "acme", tenant_field: "tenant_id"}, runnable: true, reversible: true}],
              approvals: stage === "staged" ? [] : [{id: "appr-1", approver: "admin", approved_at: "2026-09-18T10:01:00Z",
                                                     self_approved: true, reason: "acme owns them"}],
              executions: [], ...extra}}]});
}

test("a staged plan asks for a reason to approve, and says a self-approval is recorded as one", async () => {
  const approvals = [];
  const {context} = fixApp((path, opts) => {
    if (path === "/admin/findings/f9/remediation") return withPlan("staged");
    if (path === "/actions/plans/plan-3/diff") {
      return {id: "plan-3", store: "prod", blast_radius: {operations: 1, executable: 1, chunks_targeted: 3,
              reaches_all_observed: true}, review: {warnings: ["3 chunk(s) would be assigned to tenant 'acme'."],
              execution_note: "Reviewing this diff writes nothing to the store."}, operations: []};
    }
    if (path === "/actions/plans/plan-3/approve") { approvals.push(JSON.parse(opts.body)); return {id: "appr-1", self_approved: true}; }
    return undefined;
  });
  const page = await context.remediationPage("f9");
  const text = page.textContent;
  assert.match(text, /Before you approve/);
  assert.match(text, /assigned to tenant 'acme'/);
  assert.match(text, /recorded as self-approved/);
  const approve = buttons(page, /^\s*Approve\s*$/)[0] || buttons(page, /Approve/)[0];
  await approve.events.click();
  assert.equal(approvals.length, 0, "a bare approval is not sent");
  findAll(page, n => n.tagName === "INPUT" && n.attrs["aria-label"] === "Reason for approving")[0].value = "acme owns them";
  await buttons(page, /Approve/)[0].events.click();
  assert.deepEqual(approvals, [{reason: "acme owns them", typed_store_id: ""}]);
});

test("an approved plan is run from the page, and safe mode is said beside the control", async () => {
  const {context} = fixApp(path => {
    if (path === "/admin/findings/f9/remediation") return withPlan("approved");
    if (path === "/actions/plans/plan-3/diff") return {id: "plan-3", store: "prod", blast_radius: {}, review: {}, operations: []};
    return undefined;
  });
  const page = await context.remediationPage("f9");
  const run = buttons(page, /Run it/)[0];
  assert.ok(run);
  assert.equal(run.disabled, true, "safe mode is on in this fixture");
  assert.match(page.textContent, /Safe mode is on\. Set VECSHIELD_SAFE_MODE=0/);
  assert.match(page.textContent, /self-approved/);
});

test("after a run the next step is the re-scan, and a read-back is not called a fix", async () => {
  const {context} = fixApp(path => path === "/admin/findings/f9/remediation"
    ? withPlan("verified", {verification: {outcome: "confirmed", expected: 2, observed: 2,
                                           caveats: ["This confirms the tenant value is on each chunk."]}})
    : undefined);
  const page = await context.remediationPage("f9");
  const text = page.textContent;
  assert.match(text, /read-back: confirmed/);
  assert.match(text, /2 of\s+2 observed/);
  assert.match(text, /This confirms the tenant value is on each chunk/);
  assert.match(text, /Next: re-scan to confirm/);
  assert.match(text, /a re-scan should stop observing the finding/);
  assert.ok(buttons(page, /Re-scan now/).length);
  assert.doesNotMatch(text, /Resolved:/);
  assert.match(text, /Try a different fix/, "the other fixes fold away while this one is in flight");
});

test("a finding a re-scan no longer observes says so, and names the run", async () => {
  const {context} = fixApp(path => path === "/admin/findings/f9/remediation"
    ? remediationView({case: {state: "verified"},
        resolution: {by: "rescan", state: "resolved", job_id: "iso-1", at: "2026-09-18T10:05:00Z", claim: undefined},
        rescans: [{at: 1789000000, actor: "admin", outcome: "resolved", job_id: "iso-1",
                   reason: "The re-run completed over the finding's scope and did not observe it."}]})
    : undefined);
  const page = await context.remediationPage("f9");
  assert.match(page.textContent, /Resolved: re-scan iso-1/);
  assert.match(page.textContent, /no longer observed/);
  assert.ok(buttons(page, /Open that run/).length);
});

test("a guided step marked done and re-scanned records a claim, then the re-scan's answer", async () => {
  const sent = [];
  const {context} = fixApp((path, opts) => {
    if (path === "/admin/findings/f9/remediation") return remediationView();
    if (path === "/admin/findings/f9/remediation/attest") {
      sent.push(["attest", JSON.parse(opts.body)]);
      return {note: "Recorded as a claim. Run the re-scan to verify it."};
    }
    if (path === "/admin/findings/f9/remediation/verify") {
      sent.push(["verify", JSON.parse(opts.body)]);
      return {outcome: "still_present", case: {state: "in_progress"}};
    }
    return undefined;
  });
  const page = await context.remediationPage("f9");
  radios(page)[2].events.change();
  await buttons(page, /Mark done and re-scan/)[0].events.click();
  assert.deepEqual(sent, [["attest", {guided_id: "f9:reject-untagged", note: ""}],
                          ["verify", {guided_id: "f9:reject-untagged"}]]);
});

test("a remediation view that cannot be read is an error, not an empty fix list", async () => {
  const {context} = fixApp(path => path === "/admin/findings/f9/remediation" ? {status: 500, detail: "boom"} : undefined);
  const page = await context.remediationPage("f9");
  assert.match(page.textContent, /boom/);
  assert.doesNotMatch(page.textContent, /VecShield does it/);
});

test("the finding drawer's Fix this goes to the fix page instead of opening a panel over it", () => {
  const {context} = app({...CORE});
  context.openRemediation({id: "f9", title: "x"});
  assert.equal(context.location.hash, "#/actions?fix=f9");
});

// ---- The work queue --------------------------------------------------------

test("the queue shows a finding's plan and its read-back, even with no proposals left", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [], withheld: [], note: "",
                                     findings: {f9: {title: "Chunks without a tenant value"}}},
    "/stores/prod/actions/plans": {plans: [{id: "plan-3", state: "executed", staged_by: "kim",
      staged_at: "2026-09-18T10:00:00Z", plan_hash: "abc",
      summary: {stage: "verified", findings: ["f9"],
                operations: [{title: "Assign a tenant", collection: "tickets",
                              params: {tenant_value: "acme"}}],
                verification: {outcome: "confirmed", expected: 2, observed: 2}}}]},
    "/actions/safe-mode": {safe_mode: true, note: "Writes are blocked.", actions: []},
  });
  const view = await context.renderActions();
  const text = view.textContent;
  assert.match(text, /Assign a tenant · tickets → acme/);
  assert.match(text, /Chunks without a tenant value/);
  assert.match(text, /read-back confirmed: 2 of\s+2/);
  // Executed, not verified: the finding is open until a re-scan says otherwise.
  assert.match(text, /In progress \(1\)/);
  const row = findAll(view, n => n.className.includes("actions-page-row"))[0];
  assert.match(row.textContent, /executed/);
  assert.doesNotMatch(row.textContent, /verified/);
});

test("resolved findings are set aside and counted, never silently dropped", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [suggestion()], withheld: [], note: "",
      findings_resolved: 1,
      resolved: {f2: {title: "Old", resolution: {by: "rescan", job_id: "iso-1"}}}},
    "/stores/prod/actions/plans": {plans: []},
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /Show resolved \(1\)/);
  assert.doesNotMatch(view.textContent, /Old/);
});

test("the state filter narrows the queue in place and keeps the address", async () => {
  const {context} = app({
    ...CORE,
    "/stores/prod/actions/suggest": {suggestions: [suggestion(), suggestion({id: "s2", finding_id: "f2"})],
      withheld: [], note: "", findings: {f1: {title: "First finding"}, f2: {title: "Second finding"}}},
    "/stores/prod/actions/plans": {plans: [{id: "plan-9", state: "staged", staged_at: "2026-09-18T10:00:00Z",
      summary: {stage: "staged", findings: ["f2"], operations: [{title: "Tag"}]}}]},
  });
  const view = await context.renderActions();
  assert.match(view.textContent, /First finding/);
  assert.match(view.textContent, /Second finding/);
  const select = findAll(view, n => n.tagName === "SELECT" && n.attrs["aria-label"] === "Progress")[0];
  select.value = "proposed";
  select.onchange();
  assert.match(view.textContent, /First finding/);
  assert.doesNotMatch(view.textContent, /Second finding/);
  assert.match(context.location.hash, /state=proposed/);
});

test("a fix a re-scan still observes says so, and opens the other fixes again", async () => {
  const view = withPlan("verified", {verification: {outcome: "confirmed", expected: 5, observed: 5},
                                     executions: [{id: "e1", started_at: "2026-09-18T10:02:00Z"}]});
  view.executable[0].rescan_expect = "contains";
  view.rescans = [{at: Date.parse("2026-09-18T10:03:00Z") / 1000, actor: "admin", outcome: "still_present",
                   job_id: "scan-2", reason: "The re-run observed the same finding."}];
  view.case = {state: "in_progress"};
  const {context} = fixApp(path => path === "/admin/findings/f9/remediation" ? view : undefined);
  const page = await context.remediationPage("f9");
  const text = page.textContent;
  assert.match(text, /Re-scan scan-2 still observes the finding, as expected/);
  assert.doesNotMatch(text, /Next: re-scan to confirm/);
  assert.match(text, /Choose a fix/, "the choice is open again, not folded");
  assert.ok(buttons(page, /Record a case decision/).length);
  const picked = radios(page).findIndex(r => r.checked);
  assert.equal(picked, 2, "the fix that was just tried is not offered again first");
});

test("a guided claim a re-scan contradicted is not left reading as pending", async () => {
  const view = remediationView();
  view.guided[0].attested = {actor: "admin", at: 1789000000, note: ""};
  view.rescans = [{at: 1789000100, actor: "admin", outcome: "still_present", job_id: "p-1"}];
  const {context} = fixApp(path => path === "/admin/findings/f9/remediation" ? view : undefined);
  const page = await context.remediationPage("f9");
  radios(page)[2].events.change();
  assert.match(page.textContent, /the claim did not hold/);
});

test("a plan names the findings it fixes as links, not as object text", async () => {
  const {context} = app((path) => {
    if (path === "/actions/plans/plan-1/diff") return planWith([{...TAG_OP, finding_id: "f1"}, {...TAG_OP, finding_id: "f2"}]);
    if (path === "/actions/plans/plan-1/executions") return {approvals: [], executions: []};
    return CORE[path];
  });
  const shown = await context.planReview("plan-1");
  assert.match(shown.textContent, /Fixes\s+f1\s*,\s*f2/);
  assert.doesNotMatch(shown.textContent, /object/);
});
