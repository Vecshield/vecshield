import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// The Overview's order and the one severity summary every screen shares. A
// count nobody reported is "Unknown", never 0, in every variant; the estate
// posture shows the stores that most need a look first and links to the rest.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");

function load(responses = {}) {
  const dom = new JSDOM(`<!doctype html><html lang="en"><body><div id="root"></div></body></html>`,
    {url: "https://console.test/#/overview", pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  window.eval(shell);
  window.fetch = async path => {
    const value = responses[path];
    if (value === undefined) throw new Error(`Unexpected request: ${path}`);
    if (typeof value.status === "number") {
      return {ok: false, status: value.status, statusText: "Error", json: async () => ({detail: value.detail})};
    }
    return {ok: true, headers: {get: () => "application/json"}, json: async () => value};
  };
  return {dom, window, doc: window.document, run: code => window.eval(code)};
}

const text = node => node.textContent.replace(/\s+/g, " ").trim();
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

// ---------------------------------------------------------- severitySummary ---

test("a missing count is Unknown, never 0, in every variant", () => {
  const {dom, run} = load();
  for (const counts of ["null", "undefined", "{}", "{critical: null, high: undefined, medium: 'x'}"]) {
    const list = run(`severitySummary(${counts}, {variant: "list"})`);
    const values = [...list.querySelectorAll(".sev-summary-n")].map(n => n.textContent);
    assert.deepEqual(values, Array(5).fill("Unknown"), `list of ${counts}`);
    assert.ok([...list.querySelectorAll(".sev-summary-n")].every(n => n.classList.contains("is-unknown")));

    const columns = run(`severitySummary(${counts}, {variant: "list", columns: true, total: undefined})`);
    assert.deepEqual([...columns.querySelectorAll(".sev-summary-n")].map(n => n.textContent),
      Array(6).fill("Unknown"), `columns with a total of ${counts}`);

    const inline = run(`severitySummary(${counts}, {variant: "inline"})`);
    assert.doesNotMatch(text(inline), /\b0\b/, `inline of ${counts}`);
  }
  // A strip with no counts at all says so; one missing a severity shows Unknown.
  const none = run(`severitySummary(null, {variant: "strip"})`);
  assert.equal(none.querySelector(".fsum-label").textContent, "Severity");
  assert.equal(none.querySelector(".sub").textContent, "Counts unavailable");
  const strip = run(`severitySummary({critical: 2}, {variant: "strip"})`);
  const n = [...strip.querySelectorAll(".fsum-n")].map(x => x.textContent);
  assert.deepEqual(n, ["2", "Unknown", "Unknown", "Unknown", "Unknown"]);
  assert.ok([...strip.querySelectorAll("button")].every(b => !b.disabled),
    "an unknown count is not a disabled zero");
  // An inline summary with no object at all is unknown, not "none observed".
  assert.equal(text(run(`severitySummary(undefined, {variant: "inline"})`)), "Unknown");
  // Zero is still zero when it was reported.
  const zero = run(`severitySummary({critical: 0, high: 0, medium: 0, low: 0, info: 0}, {variant: "list"})`);
  assert.deepEqual([...zero.querySelectorAll(".sev-summary-n")].map(x => x.textContent), Array(5).fill("0"));
  dom.window.close();
});

test("each severity carries its glyph and its name, in severity order", () => {
  const {dom, run} = load();
  const list = run(`severitySummary({critical: 1, high: 2, medium: 3, low: 4, info: 5}, {variant: "list"})`);
  const rows = [...list.querySelectorAll(".sev-summary-row")];
  assert.deepEqual(rows.map(text), ["Critical 1", "High 2", "Medium 3", "Low 4", "Info 5"]);
  for (const [i, row] of rows.entries()) {
    const glyph = row.querySelector(`.sev-summary-icon.sev-${SEVERITIES[i]}`);
    assert.ok(glyph?.querySelector("svg"), `${SEVERITIES[i]} has its icon`);
  }
  dom.window.close();
});

test("linked rows go to the findings list filtered by their severity", () => {
  const {dom, window, run} = load();
  const list = run(`severitySummary({critical: 1, high: 0, medium: 0, low: 0, info: 0}, {
    variant: "list", label: s => severityName(s) + " open", link: s => ["findings", {severity: s}]})`);
  const buttons = [...list.querySelectorAll("button.sev-summary-row")];
  assert.equal(buttons.length, 5);
  assert.ok(buttons.every(b => b.getAttribute("type") === "button" && !b.hasAttribute("aria-pressed")));
  for (const [i, button] of buttons.entries()) {
    button.click();
    assert.equal(window.location.hash, `#/findings?severity=${SEVERITIES[i]}`);
  }
  // A blank summary links nowhere and says why once, visibly, and per row to
  // a screen reader.
  const empty = run(`severitySummary({critical: 0}, {variant: "list", link: s => ["findings", {severity: s}],
    label: s => severityName(s) + " open", empty: "Nothing assessed yet"})`);
  assert.equal(empty.querySelectorAll("button").length, 0);
  assert.match(text(empty), /Critical open — Nothing assessed yet/);
  assert.equal(empty.querySelector(".sev-summary-note").getAttribute("aria-hidden"), "true");
  const unread = run(`severitySummary(null, {variant: "list", unavailable: "Could not be read"})`);
  assert.deepEqual([...unread.querySelectorAll(".sev-summary-n")].map(x => x.textContent), Array(5).fill("Unavailable"));
  dom.window.close();
});

test("the inline variant is the compact row the history tables have always shown", () => {
  const {dom, run} = load();
  const some = run(`severitySummary({critical: 2, high: 0, low: 1}, {variant: "inline"})`);
  assert.equal(some.className, "sev-counts");
  assert.deepEqual([...some.querySelectorAll(".sev-count")].map(n => n.className),
    ["sev-count sev-critical", "sev-count sev-low"]);
  assert.deepEqual([...some.querySelectorAll(".sev-count-n")].map(n => n.textContent), ["2", "1"]);
  assert.equal(some.querySelector(".sev-count").getAttribute("title"), "2 critical");
  assert.equal(text(run(`severitySummary({}, {variant: "inline", complete: true})`)), "none observed");
  assert.equal(text(run(`severitySummary({}, {variant: "inline"})`)), "none observed · inconclusive");
  assert.equal(run(`severityCounts({high: 3})`).outerHTML,
    run(`severitySummary({high: 3}, {variant: "inline"})`).outerHTML, "severityCounts is the inline variant");
  dom.window.close();
});

test("the strip variant reproduces the Findings severity filter markup", () => {
  const {dom, window, run} = load();
  window.picks = [];
  const counts = `{critical: 3, high: 0, medium: 12, low: 0, info: 1}`;
  for (const [exact, min] of [["", ""], ["medium", ""], ["", "high"], ["low", ""]]) {
    const before = run(`severityStrip(${counts}, {exact: "${exact}", min: "${min}", onPick: s => picks.push(s)})`);
    const after = run(`severitySummary(${counts}, {variant: "strip", onPick: s => picks.push(s),
      active: s => "${exact}" === s || Boolean("${min}" && severityMeets(s, "${min}")),
      title: (s, on) => "${exact}" === s ? "Showing only " + s + "; select again to clear" : "Show only " + s})`);
    assert.equal(after.outerHTML, before.outerHTML, `exact=${exact} min=${min}`);
    const chips = [...after.querySelectorAll("button.fsum-chip")];
    assert.ok(chips.every(c => c.querySelector("svg") && c.querySelector(".fsum-n") && c.querySelector(".fsum-k")));
    assert.ok(chips.every(c => ["true", "false"].includes(c.getAttribute("aria-pressed"))));
  }
  const strip = run(`severitySummary(${counts}, {variant: "strip", onPick: s => picks.push(s)})`);
  strip.querySelector(".fsum-chip.sev-medium").click();
  assert.deepEqual([...window.picks], ["medium"]);
  assert.ok(strip.querySelector(".fsum-chip.sev-high").disabled, "a reported zero is disabled");
  dom.window.close();
});

// ------------------------------------------------------------------ overview ---

const day = n => new Date(Date.now() - n * 86400000).toISOString();

function overviewResponses(stores) {
  return {
    "/admin/stores": {stores: stores.map(s => ({store_id: s.store_id, kind: s.kind}))},
    "/admin/policy-templates": {templates: []}, "/admin/policies": {policies: []}, "/version": {},
    "/admin/home": {
      history_available: true, needs_you: [], checked: ["plans_awaiting_approval"], unavailable: [],
      open_findings: {by_severity: {critical: 1, high: 0, medium: 0, low: 0, info: 0}, total: 1,
                      stores_assessed: 1, stores_never_assessed: 0, suppressed: 0, note: ""},
      stores: {total: stores.length, assessed: stores.length, never_assessed: 0}, note: "",
    },
    "/runtime/alerts/stats": {total: 0},
    "/admin/history/trend?days=30": {trend: [], available: true},
    "/admin/estate": {stores, probed: false, note: ""},
  };
}

const store = (id, ago, status = "complete") => ({
  store_id: id, kind: "chroma", last_assessed: ago == null ? null : day(ago),
  coverage: ago == null ? null : {status, complete: status === "complete"},
  findings: {}, findings_total: 0, history_available: true, probe: {probed: false},
});

test("the overview reads in one order: header, facts, needs you beside open findings, estate, trend", async () => {
  const {dom, run} = load(overviewResponses([store("a", 1)]));
  const page = await run("renderOverview()");
  const order = [...page.children].map(n => n.className || n.tagName);
  assert.equal(order[0].includes("page-header") || page.children[0].querySelector("h1") != null, true);
  assert.ok(page.children[1].querySelector("dl.page-facts"), "facts follow the header");
  const lead = page.children[2];
  assert.equal(lead.className, "overview-lead");
  assert.deepEqual([...lead.querySelectorAll("h2")].map(text), ["Needs you", "Open findings"]);
  assert.equal(text(page.children[3].querySelector("h2")), "Estate posture");
  assert.equal(text(page.children[4].querySelector("h2")), "Findings recorded over time");
  assert.equal([...page.querySelectorAll(".btn.primary")].map(text).join("|"), "Run an assessment");
  // Open findings is the severity list, its rows linking to the findings list.
  const rows = [...lead.querySelectorAll(".sev-summary button.sev-summary-row")];
  assert.deepEqual(rows.map(text), ["Critical open 1", "High open 0", "Medium open 0", "Low open 0", "Info open 0"]);
  dom.window.close();
});

test("estate posture shows eight stores, the ones needing a look first, and links to all", async () => {
  const stores = [
    store("fresh-complete", 1), store("old-complete", 30), store("partial-new", 2, "partial"),
    store("never-1", null), store("partial-old", 20, "partial"), store("mid-complete", 10),
    store("never-2", null), store("unknown-cov", 5, "unknown"), store("newest-complete", 0),
    store("older-complete", 15),
  ];
  const {dom, window, run} = load(overviewResponses(stores));
  const page = await run("renderOverview()");
  const estate = [...page.querySelectorAll("section.panel")].find(p => /Estate posture/.test(text(p.querySelector("h2"))));
  const ids = [...estate.querySelectorAll("tbody tr")].map(tr => tr.querySelector("td .mono").textContent);
  assert.deepEqual(ids, ["never-1", "never-2", "partial-old", "unknown-cov", "partial-new",
                         "old-complete", "older-complete", "mid-complete"]);
  // Kind sits under the store id, not in a column of its own.
  assert.deepEqual([...estate.querySelectorAll("thead th")].map(text).slice(0, 3),
    ["Store", "Last assessed", "Coverage of that run"]);
  assert.equal(text(estate.querySelector("tbody td .sub")), "chroma");
  assert.match(text(estate.querySelector("tbody tr")), /Never assessed/);
  const all = [...estate.querySelectorAll(".panel-title button")].find(b => /All 10 stores/.test(text(b)));
  assert.ok(all, "more than eight stores links to all of them");
  all.click();
  assert.equal(window.location.hash, "#/stores");
  dom.window.close();
});

test("an estate of eight or fewer has no link to the rest", async () => {
  const {dom, run} = load(overviewResponses([store("a", 1), store("b", null)]));
  const page = await run("renderOverview()");
  assert.doesNotMatch(text(page), /All \d+ stores/);
  dom.window.close();
});

test("Stores and the Overview share the last-assessed and coverage cells", () => {
  const {dom, run} = load();
  const never = run(`lastAssessedCell({store_id: "x", last_assessed: null})`);
  assert.equal(text(never), "Never assessed");
  assert.ok(never.querySelector("svg"), "the never-assessed chip has its icon");
  assert.equal(text(run(`coverageCell({store_id: "x", last_assessed: null})`)), "no coverage recorded");
  assert.equal(text(run(`coverageCell({store_id: "x", last_assessed: "${day(1)}", coverage: {status: "partial"}})`)), "partial");
  const table = run(`estateTable({stores: [
    {store_id: "x", kind: "chroma", last_assessed: "${day(1)}", coverage: {status: "partial"}, probe: {}, findings: {}},
    {store_id: "y", kind: "chroma", last_assessed: null, probe: {}, findings: {}}]})`);
  // Stores keeps its stacked cell: the day, then the coverage chip under it.
  const [assessed, never2] = [...table.querySelectorAll("tbody tr")].map(tr => tr.children[3]);
  const lines = [...assessed.firstElementChild.children];
  assert.deepEqual(lines.map(text), ["yesterday", "partial"]);
  assert.equal(lines[1].className, "sub");
  assert.equal(text(never2), "Never assessed");
  assert.ok(never2.querySelector(".badge svg"));
  dom.window.close();
});
