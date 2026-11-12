import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// Findings, Actions and False positives (phase 11 of the console overhaul).
//
// - The Findings severity chips are severitySummary's strip variant: they
//   filter, keep aria-pressed, and a severity the server's facet leaves out is
//   a measured zero (disabled), never "Unknown".
// - What to do with ticked rows floats: the Findings bulk bar and the work
//   queue's stage bar stick to the bottom of the window, inside panels that
//   clip rather than scroll.
// - The work queue and the approval queue are tables with the same columns
//   in every section, and only Stage selected is a primary button.
// - A finding's case path and a plan's progress are one sequence look.
// - Evidence chips truncate to a phone-width card instead of widening it.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

const BASE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"}]},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
  "/version": {approvals: {separation_of_duties: "required"}},
  "/healthz": {status: "ok", stores: 1},
};

async function boot(hash, responses = {}) {
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="light"><head><style>${css}</style></head>` +
    `<body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
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

const settle = () => new Promise(r => setTimeout(r, 30));
const text = node => node.textContent.replace(/\s+/g, " ").trim();
const button = (root, label) => [...root.querySelectorAll("button")].find(b => text(b) === label);

// Every rule in the sheet, with the @media condition it sits under (or "").
function cssRules() {
  const rules = [];
  const media = [];
  for (const m of css.matchAll(/@media([^{]+)\{/g)) {
    let depth = 1;
    let i = m.index + m[0].length;
    while (depth && i < css.length) depth += css[i] === "{" ? 1 : css[i] === "}" ? -1 : 0, i++;
    media.push({start: m.index, end: i, query: m[1].trim()});
  }
  const bare = css.replace(/\/\*[\s\S]*?\*\//g, c => " ".repeat(c.length));
  for (const m of bare.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selector = m[1].trim();
    if (selector.startsWith("@")) continue;
    const at = media.find(x => m.index > x.start && m.index < x.end);
    rules.push({selectors: selector.split(",").map(s => s.trim()), body: m[2], media: at ? at.query : ""});
  }
  return rules;
}
const RULES = cssRules();
const rulesFor = (selector, media = "") =>
  RULES.filter(r => r.selectors.includes(selector) && r.media === media).map(r => r.body).join("\n");

// ---------------------------------------------------------------- Findings ---

const FINDINGS = {
  "/admin/findings": {findings: [
    {id: "f1", title: "PII in docs", severity: "high", category: "data_classification",
     store: "prod", collection: "docs", suppressed: false, case: {state: "new"}},
    {id: "f2", title: "Secret in runbooks", severity: "medium", category: "data_classification",
     store: "prod", collection: "runbooks", suppressed: false, case: {state: "triaged", owner: "ana"}}],
    total: 2, limit: 50, offset: 0, has_more: false,
    // A facet is a GROUP BY: critical, low and info matched no row.
    facets: {severity: {high: 1, medium: 1}, case_state: {new: 1, triaged: 1}}},
  "/admin/findings/f1": {finding: {id: "f1", title: "PII in docs", severity: "high", store: "prod",
                                   collection: "docs", case: {state: "new"}, evidence: {}},
                         case_events: [], same_fingerprint: []},
  "/admin/estate": {stores: [{store_id: "prod", last_assessed: "2026-09-20T00:00:00Z",
                              coverage: {status: "complete"}}]},
};

test("the Findings severity chips are the summary strip: they filter and keep aria-pressed", async () => {
  const {dom, doc, window} = await boot("#/findings", FINDINGS);
  const content = doc.getElementById("content");
  const group = content.querySelector('.fsum-group[role="group"][aria-label="Filter by severity"]');
  assert.ok(group, "the strip is a labelled toggle group");
  const chips = [...group.querySelectorAll("button.fsum-chip")];
  assert.deepEqual(chips.map(c => c.className.match(/sev-(\w+)/)[1]),
                   ["critical", "high", "medium", "low", "info"], "every severity, in order");
  assert.ok(chips.every(c => c.getAttribute("aria-pressed") === "false"));
  assert.ok(chips.every(c => c.querySelector("svg") && c.querySelector(".fsum-n") && c.querySelector(".fsum-k")),
            "each chip carries a glyph and a name as well as its count");
  // A severity the facet leaves out matched nothing: a measured zero, not unknown.
  const critical = group.querySelector(".fsum-chip.sev-critical");
  assert.equal(text(critical.querySelector(".fsum-n")), "0");
  assert.ok(critical.disabled, "a measured zero cannot narrow the list");
  assert.doesNotMatch(text(group), /Unknown/);

  group.querySelector(".fsum-chip.sev-medium").click();
  await settle();
  assert.match(window.location.hash, /severity=medium/);
  const medium = content.querySelector('.fsum-group[aria-label="Filter by severity"] .fsum-chip.sev-medium');
  assert.equal(medium.getAttribute("aria-pressed"), "true", "the picked chip is pressed");
  assert.ok(medium.classList.contains("is-on"));
  assert.match(medium.title, /Showing only medium; select again to clear/);
  // The Findings page has no tab list of its own: the first is the drawer's.
  assert.equal(content.querySelector('[role="tablist"]'), null);
  dom.window.close();
});

test("an unreadable severity facet says so, and never reads as zero", async () => {
  const {dom, run} = await boot("#/findings", FINDINGS);
  const strip = run(`severityStrip(null, {onPick: () => {}})`);
  assert.match(strip.textContent, /Counts unavailable/);
  assert.equal(strip.querySelectorAll(".fsum-chip").length, 0);
  dom.window.close();
});

test("ticked findings get a floating bar after the table, with a live count", async () => {
  const {dom, doc} = await boot("#/findings", FINDINGS);
  const content = doc.getElementById("content");
  const bar = content.querySelector(".bulk-bar");
  assert.ok(bar.hidden, "nothing ticked, no bar");
  assert.equal(bar.getAttribute("role"), "group");
  assert.equal(bar.getAttribute("aria-label"), "Selected findings");
  // It follows the table inside the list panel, so it can stick along it.
  const wrap = content.querySelector(".findings-panel .table-wrap");
  assert.equal(wrap.parentElement, bar.parentElement, "the bar is the table's sibling");
  assert.ok(wrap.compareDocumentPosition(bar) & dom.window.Node.DOCUMENT_POSITION_FOLLOWING);

  const box = content.querySelector('tbody input[type="checkbox"]');
  box.click();
  assert.equal(bar.hidden, false);
  const count = bar.querySelector('[role="status"]');
  assert.equal(text(count), "1 selected on this page");
  assert.ok(button(bar, "Change case").classList.contains("primary"), "one primary action in the bar");
  button(bar, "Clear selection").click();
  assert.ok(content.querySelector(".bulk-bar").hidden, "clearing hides it again");
  dom.window.close();
});

test("the bulk and stage bars stick to the window inside panels that clip", () => {
  const bulk = rulesFor(".bulk-bar");
  assert.match(bulk, /position:\s*sticky/);
  assert.match(bulk, /bottom:\s*var\(--space-\d\)/);
  assert.match(bulk, /z-index:\s*var\(--z-sticky\)/);
  const stage = rulesFor(".actions-page-bulk.is-active");
  assert.match(stage, /position:\s*sticky/);
  assert.match(stage, /z-index:\s*var\(--z-sticky\)/);
  // overflow: hidden makes a scroll container, and a sticky child would stick
  // to the panel instead of the window.
  assert.match(rulesFor(".findings-panel"), /overflow:\s*clip/);
  assert.match(rulesFor(".actions-page .panel"), /overflow:\s*clip/);
});

test("the finding title clamps with its whole text on hover, and long chips truncate", async () => {
  const {dom, doc} = await boot("#/findings", FINDINGS);
  const title = doc.querySelector("#content .f-title");
  assert.equal(title.title, "PII in docs");
  assert.match(rulesFor(".ftable .f-title"), /-webkit-line-clamp:\s*2/);
  assert.match(rulesFor(".ftable .f-line .tag"), /text-overflow:\s*ellipsis/);
  dom.window.close();
});

test("on a phone the summary chips wrap under their group's name instead of scrolling", () => {
  const phone = "(max-width: 900px)";
  assert.doesNotMatch(rulesFor(".fsum-group", phone), /overflow-x|nowrap/);
  assert.doesNotMatch(rulesFor(".fsum-group .fsum-label", phone), /display:\s*none/,
                      "Claims: None recorded means nothing without its name");
});

test("evidence chips truncate to a phone-width card and keep the whole value in their title", async () => {
  const {dom, run} = await boot("#/findings", FINDINGS);
  const chip = run(`evidenceChip({key: "explanations[0].matched_preview", value: "x".repeat(200)})`);
  assert.match(chip.title, /^explanations\[0\]\.matched_preview: x+\.\.\.$/);
  assert.ok(chip.querySelector(".chip-value"));
  // The view's one track has no automatic minimum, and below 900px neither
  // the view nor a chip holds a minimum width of its own.
  assert.match(rulesFor(".evidence-view"), /grid-template-columns:\s*minmax\(0,\s*1fr\)/);
  const phone = "(max-width: 900px)";
  assert.match(rulesFor(".evidence-view", phone), /min-width:\s*0/);
  assert.match(rulesFor(".evidence-chip", phone), /min-width:\s*0/);
  assert.match(rulesFor(".chip-value"), /text-overflow:\s*ellipsis/);
  dom.window.close();
});

test("evidence chips summarize top-level fields, never every nested leaf", async () => {
  const {dom, run} = await boot("#/findings", FINDINGS);
  // The shape of a data_classification finding: lists of nested records and
  // a count map, which used to flatten into hundreds of chips.
  const view = run(`evidenceView({
    scanned: 13, sensitive: 7,
    explanations: Array.from({length: 18}, () => ({confidence: "uncertain", detectors: ["a", "b"]})),
    detector_counts: {date_of_birth: 5, medical_record_context: 6, "presidio:PERSON": 5},
    examples: Array.from({length: 5}, (_, i) => ({chunk_id: i, detectors: ["date_of_birth"]})),
    tenants: ["clinical"], sensitivity: {score: 0.9, level: "high"},
    fingerprint: "fp-1", suppressed: false})`);
  const chipText = chip => `${text(chip.querySelector(".chip-key"))} ${text(chip.querySelector(".chip-value"))}`;
  const chips = [...view.querySelectorAll(".evidence-chip")].map(chipText);
  assert.deepEqual(chips, [
    "scanned 13", "sensitive 7", "explanations 18 items",
    "detector counts medical record context 6 · date of birth 5 · presidio:PERSON 5",
    "examples 5 items", "tenants clinical", "sensitivity 2 fields"]);
  // The fingerprint has its own column, and "not suppressed" says nothing.
  assert.ok(!chips.some(chip => /fingerprint|suppressed/.test(chip)));
  assert.equal(view.querySelector(".evidence-tags > .tag"), null);

  const wide = run(`evidenceView(Object.fromEntries(
    Array.from({length: 11}, (_, i) => ["field_" + i, i + 1])))`);
  assert.equal(wide.querySelectorAll(".evidence-chip").length, 8);
  assert.equal(text(wide.querySelector(".evidence-tags > .tag")), "+3 more fields");
  // A suppressed finding still says so, and the full record stays one click away.
  const muted = run(`evidenceView({suppressed: true})`);
  assert.deepEqual([...muted.querySelectorAll(".evidence-chip")].map(chipText), ["suppressed true"]);
  assert.ok(muted.querySelector("details.evidence-data"));
  dom.window.close();
});

// ------------------------------------------------------------------ phones ---
// Below 900px each finding is a card and the header row is hidden, with the
// select-all box and the sort buttons in it. A bar of its own carries both.

test("on a phone Findings still sorts, in either direction, from a bar of its own", async () => {
  const {dom, doc, window, calls} = await boot("#/findings", FINDINGS);
  const bar = doc.querySelector("#content .findings-panel .ftable-phone-bar");
  assert.ok(bar, "the bar sits in the list's panel");
  assert.ok(bar.compareDocumentPosition(doc.querySelector("#content .ftable")) &
            dom.window.Node.DOCUMENT_POSITION_FOLLOWING, "above the cards");
  const sort = bar.querySelector("select");
  assert.equal(sort.getAttribute("aria-label"), "Sort findings by");
  assert.equal(sort.value, "severity desc", "the triage order, worst first, is the default");
  const values = [...sort.options].map(o => o.value);
  for (const key of ["severity", "created_at", "case_updated_at", "store"]) {
    assert.ok(values.includes(`${key} asc`) && values.includes(`${key} desc`), `${key}, either way round`);
  }
  sort.value = "created_at asc";
  sort.dispatchEvent(new window.Event("change"));
  await settle();
  assert.match(window.location.hash, /sort=created_at/);
  assert.match(window.location.hash, /dir=asc/);
  const asked = new URLSearchParams(calls.filter(c => c.path.startsWith("/admin/findings?")).at(-1).path.split("?")[1]);
  assert.equal(asked.get("sort"), "created_at", "the server sorts, as it does for a header click");
  assert.equal(asked.get("direction"), "asc");
  assert.equal(doc.querySelector("#content .ftable-phone-bar select").value, "created_at asc",
               "the redrawn list keeps the order it was asked for");
  // A header click still flips the column it is on.
  const recorded = [...doc.querySelectorAll("#content th .th-sort")].find(b => b.textContent.startsWith("Recorded"));
  recorded.click();
  await settle();
  assert.match(window.location.hash, /sort=created_at/);
  assert.doesNotMatch(window.location.hash, /dir=asc/, "and back to newest first");
  dom.window.close();
});

test("on a phone the select-all box in the bar and the header's are one selection", async () => {
  const {dom, doc} = await boot("#/findings", FINDINGS);
  const content = doc.getElementById("content");
  const phoneAll = content.querySelector(".ftable-phone-bar input[type=checkbox]");
  assert.equal(text(phoneAll.closest("label")), "Select all on this page");
  phoneAll.click();
  const rows = [...content.querySelectorAll('tbody input[type="checkbox"]')];
  assert.ok(rows.length === 2 && rows.every(box => box.checked), "every finding on the page is ticked");
  assert.ok(content.querySelector('thead input[type="checkbox"]').checked, "and the header's box says so");
  assert.equal(text(content.querySelector(".bulk-bar [role=status]")), "2 selected on this page");
  rows[0].click();
  const after = content.querySelector(".ftable-phone-bar input[type=checkbox]");
  assert.equal(after.checked, false);
  assert.equal(after.indeterminate, true, "one of two is neither all nor none");
  // Shown below 900px only: on a wide screen the header row does this.
  assert.match(rulesFor(".ftable-phone-bar"), /display:\s*none/);
  assert.match(rulesFor(".ftable-phone-bar", "(max-width: 900px)"), /display:\s*flex/);
  dom.window.close();
});

test("the run results' findings cards name their columns", async () => {
  const {dom, run} = await boot("#/findings", FINDINGS);
  const view = run(`findingsTable([{id: "f9", title: "PII", severity: "high", store: "prod",
                                    collection: "docs", category: "data_classification", evidence: {}}])`);
  const cells = [...view.querySelectorAll("tbody td")];
  assert.deepEqual(cells.map(c => c.getAttribute("data-label")),
                   ["Severity", "Finding", "Scope", "Evidence", "Fingerprint"]);
  dom.window.close();
});

// ---------------------------------------------------------- sequence pills ---

test("a case path and a plan's progress are one sequence look", async () => {
  const done = RULES.find(r => r.selectors.includes(".fd-life-steps li.is-done::before")
    && r.selectors.includes(".remediation-steps li.is-done::before"));
  assert.ok(done && /content:\s*"\\2713"/.test(done.body), "done steps are ticked on both");
  const failed = RULES.find(r => r.selectors.includes(".fd-life-steps li.is-failed::before")
    && r.selectors.includes(".remediation-steps li.is-failed::before"));
  assert.ok(failed && /content:\s*"\\2715"/.test(failed.body), "failed steps are crossed on both");
  assert.doesNotMatch(css, /counter\(fd-step\)/, "neither path numbers its steps");

  const {dom, run} = await boot("#/findings", FINDINGS);
  const path = run(`caseLifecycle("assigned")`);
  const list = path.querySelector("ol.fd-life-steps");
  assert.equal(list.getAttribute("aria-label"), "Case path");
  const items = [...list.querySelectorAll("li")];
  assert.deepEqual(items.slice(0, 3).map(li => li.className), ["is-done", "is-done", "is-current"]);
  assert.equal(items[2].querySelector(".sr-only").textContent, "current: ", "the state is read out");
  dom.window.close();
});

// ---------------------------------------------------------------- Actions ---

const QUEUE = {
  "POST /stores/prod/actions/suggest": {note: "n", suggestions: [
    {id: "s1", finding_id: "f1", title: "Tag f1 chunks", collection: "docs", chunk_ids: ["c1"],
     reaches_all_observed: true, reversible: true, undo: "untag", calibrated: true, rests_on: []},
    {id: "s2", finding_id: "f2", title: "Tag f2 chunks", collection: "docs", chunk_ids: ["c2"],
     reaches_all_observed: true, reversible: true, undo: "untag", calibrated: true, rests_on: []}],
    withheld: [], findings: {f1: {title: "One", severity: "high"}, f2: {title: "Two", severity: "low"}}},
  "/stores/prod/actions/plans": {plans: [{id: "plan-9", state: "staged", staged_at: "2026-09-18T10:00:00Z",
    summary: {stage: "staged", findings: ["f2"], operations: [{title: "Tag"}]}}]},
  "/actions/safe-mode": {safe_mode: false, note: "Writes are permitted.", actions: []},
};

test("the work queue is one table per section with the same columns, and quiet row buttons", async () => {
  const {dom, doc} = await boot("#/actions?store=prod", QUEUE);
  const content = doc.getElementById("content");
  assert.equal(text(content.querySelector('[aria-pressed="true"]')), "Work queue", "the queue switch leads");
  const filters = content.querySelector('.toolbar[role="search"][aria-label="Filter the work queue"]');
  assert.ok(filters, "the filters are the shared toolbar");
  const tables = [...content.querySelectorAll("table.work-table")];
  assert.equal(tables.length, 2, "In progress and To do");
  for (const table of tables) {
    assert.deepEqual([...table.querySelectorAll("thead th")].map(text),
                     ["Select", "Finding", "Fix to try first", "Progress", "Open"]);
    assert.equal(table.querySelector("thead th").querySelector(".sr-only")?.textContent, "Select");
  }
  const rows = [...content.querySelectorAll("tr.actions-page-row")];
  assert.equal(rows.length, 2);
  assert.ok(rows.every(r => r.querySelector("td.actions-page-finding") && r.querySelector("td.actions-page-open")));
  assert.equal(content.querySelectorAll("tbody .btn.primary").length, 0, "no row shouts");
  assert.match(rulesFor(".work-table"), /table-layout:\s*fixed/, "sections line up");
  dom.window.close();
});

test("ticking a fix floats the stage bar, which sits beside the To do table", async () => {
  const {dom, doc} = await boot("#/actions?store=prod", QUEUE);
  const content = doc.getElementById("content");
  const bar = content.querySelector(".actions-page-bulk");
  assert.equal(bar.getAttribute("role"), "group");
  assert.ok(!bar.classList.contains("is-active"));
  // A sibling of the To do table, so it can stick anywhere along it.
  const todo = [...content.querySelectorAll(".work-table-wrap")].at(-1);
  assert.equal(todo.parentElement, bar.parentElement, "the bar is the To do table's sibling");
  const box = content.querySelector('input[type="checkbox"][aria-label^="Select "]');
  box.checked = true;
  box.dispatchEvent(new dom.window.Event("change"));
  assert.ok(bar.classList.contains("is-active"), "a selection makes it float");
  assert.ok(button(bar, "Stage selected (1)").classList.contains("primary"));
  box.checked = false;
  box.dispatchEvent(new dom.window.Event("change"));
  assert.ok(!bar.classList.contains("is-active"), "an empty selection lets it settle");
  dom.window.close();
});

test("the approval queue opens like the work queue and lines its tables up", async () => {
  const plan = (id, you) => ({plan_id: id, store: "prod", staged_by: "ana",
    staged_at: "2026-09-20T10:00:00+00:00", operations: 2, executable: 2, irreversible: false, you});
  const {dom, doc} = await boot("#/actions?queue=approval", {
    "/actions/queue": {plans: [plan("plan-a", {may_approve: true}),
                               plan("plan-b", {may_approve: false, needs_second_person: true})],
                       note: "Approving never executes a plan."},
  });
  const content = doc.getElementById("content");
  assert.equal(text(content.querySelector('[aria-pressed="true"]')), "Approval queue");
  const notes = content.querySelector(".actions-page-deploy");
  assert.match(text(notes), /Approving never executes a plan/);
  assert.match(text(notes), /A second person must authorize a plan/);
  const tables = [...content.querySelectorAll("table.approval-table")];
  assert.equal(tables.length, 2);
  assert.equal(tables[0].querySelector("thead th:last-child .sr-only").textContent, "Open");
  assert.match(rulesFor(".approval-table"), /table-layout:\s*fixed/);
  dom.window.close();
});

// --------------------------------------------------------- False positives ---

test("false-positive lists count themselves, and a suppression near its end says so", async () => {
  const soon = new Date(Date.now() + 2 * 86400000).toISOString();
  const later = new Date(Date.now() + 60 * 86400000).toISOString();
  const {dom, doc} = await boot("#/falsepositives", {
    "/admin/allowlist": {allowlist: [{reason: "Known test key", rule: "r1", source: "builtin"}]},
    "/admin/suppressions": {suppressions: [
      {fingerprint: "fp-1", reason: "Tracked in JIRA-1", owner: "ana", expires_at: soon},
      {fingerprint: "fp-2", reason: "Vendor sample", owner: "", expires_at: later}]},
  });
  const content = doc.getElementById("content");
  assert.deepEqual([...content.querySelectorAll(".panel-heading")].map(text),
                   ["Allow-list (1)", "Suppressions (2)"]);
  assert.match(text(content.querySelector(".fp-table .tag")), /^built-in$/);
  const rows = [...content.querySelectorAll(".panel:last-of-type tbody tr")];
  assert.match(text(rows[0]), /lapses soon/);
  assert.doesNotMatch(text(rows[1]), /lapses soon|lapsed/);
  assert.match(text(rows[1]), /unassigned/, "no owner is said, not left blank");
  assert.equal(rows[0].querySelector(".fp-print").title, "fp-1");
  dom.window.close();
});

test("an unreadable false-positive list has no count in its heading", async () => {
  const {dom, doc} = await boot("#/falsepositives", {
    "/admin/allowlist": {status: 403, detail: "forbidden"},
    "/admin/suppressions": {suppressions: []},
  });
  const headings = [...doc.querySelectorAll("#content .panel-heading")].map(text);
  assert.deepEqual(headings, ["Allow-list", "Suppressions (0)"]);
  dom.window.close();
});
