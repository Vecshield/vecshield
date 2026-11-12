import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// The console's shared building blocks: tab lists, sortable tables, toggle
// groups, step paths and fact lists. Screens are built from these, so their
// keyboard model and ARIA are checked once here, in a real DOM, rather than
// screen by screen.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");

function load() {
  const dom = new JSDOM(`<!doctype html><html lang="en"><body><div id="root"></div></body></html>`,
    {url: "https://console.test/#/overview", pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  window.eval(shell);
  return {dom, window, doc: window.document, run: code => window.eval(code)};
}

const key = (window, target, name) =>
  target.dispatchEvent(new window.KeyboardEvent("keydown", {key: name, bubbles: true}));

// ------------------------------------------------------------------ tabList ---

test("a page tab list has the ARIA pattern and keeps every tab in the Tab order", () => {
  const {dom, window, doc, run} = load();
  window.picked = [];
  const {bar, panel} = run(`tabList({id: "demo", label: "Sections", current: "b",
    tabs: [["a", "Alpha"], ["b", "Beta", 3], ["c", "Gamma"]],
    onSelect: key => picked.push(key)})`);
  doc.body.append(bar, panel);
  const tabs = [...bar.querySelectorAll('[role="tab"]')];

  assert.equal(bar.getAttribute("role"), "tablist");
  assert.equal(bar.getAttribute("aria-label"), "Sections");
  assert.deepEqual(tabs.map(t => t.textContent), ["Alpha", "Beta (3)", "Gamma"]);
  assert.deepEqual(tabs.map(t => t.id), ["demo-tab-a", "demo-tab-b", "demo-tab-c"]);
  assert.deepEqual(tabs.map(t => t.getAttribute("aria-selected")), ["false", "true", "false"]);
  assert.ok(tabs.every(t => t.getAttribute("aria-controls") === "demo-tabpanel"));
  assert.ok(tabs.every(t => t.getAttribute("tabindex") !== "-1"), "no page tab leaves the Tab order");
  assert.equal(panel.getAttribute("role"), "tabpanel");
  assert.equal(panel.id, "demo-tabpanel");
  assert.equal(panel.getAttribute("aria-labelledby"), "demo-tab-b");
  assert.equal(panel.getAttribute("tabindex"), null, "a page panel is not a focus stop");

  key(window, tabs[1], "ArrowRight");
  assert.equal(doc.activeElement, tabs[2]);
  assert.deepEqual(tabs.map(t => t.getAttribute("aria-selected")), ["false", "false", "true"]);
  assert.equal(tabs[2].className, "tab tab-active");
  assert.equal(panel.getAttribute("aria-labelledby"), "demo-tab-c");

  key(window, tabs[2], "ArrowRight");
  assert.equal(doc.activeElement, tabs[0], "Right from the last tab wraps to the first");
  key(window, tabs[0], "ArrowLeft");
  assert.equal(doc.activeElement, tabs[2], "Left from the first tab wraps to the last");
  key(window, tabs[2], "Home");
  assert.equal(doc.activeElement, tabs[0]);
  key(window, tabs[0], "End");
  assert.equal(doc.activeElement, tabs[2]);
  key(window, tabs[2], "Enter");
  assert.deepEqual([...window.picked], ["c", "a", "c", "a", "c"], "only movement keys pick a tab");

  tabs[1].click();
  assert.equal(window.picked.at(-1), "b");
  assert.equal(panel.getAttribute("aria-labelledby"), "demo-tab-b");
  assert.ok(tabs.every(t => t.getAttribute("tabindex") !== "-1"));
  dom.window.close();
});

test("a dialog tab list roves: only the selected tab is tabbable", () => {
  const {dom, window, doc, run} = load();
  const existing = doc.createElement("div");
  existing.className = "detail-body";
  window.existing = existing;
  const tabs = run(`tabList({id: "dlg", roving: true, panel: existing, current: "one",
    tabs: [["one", "One"], ["two", "Two"], ["three", "Three"]]})`);
  doc.body.append(tabs.bar, tabs.panel);
  const buttons = [...tabs.bar.querySelectorAll('[role="tab"]')];

  assert.equal(tabs.panel, existing, "an existing element becomes the panel");
  assert.equal(existing.getAttribute("role"), "tabpanel");
  assert.equal(existing.id, "dlg-tabpanel");
  assert.equal(existing.getAttribute("tabindex"), "0");
  assert.deepEqual(buttons.map(b => b.getAttribute("tabindex")), ["0", "-1", "-1"]);

  key(window, tabs.bar, "End");
  assert.deepEqual(buttons.map(b => b.getAttribute("tabindex")), ["-1", "-1", "0"]);
  assert.equal(doc.activeElement, buttons[2]);
  assert.equal(existing.getAttribute("aria-labelledby"), "dlg-tab-three");

  // select() redraws without reporting a pick, so a caller can drive it.
  tabs.select("two");
  assert.deepEqual(buttons.map(b => b.getAttribute("tabindex")), ["-1", "0", "-1"]);
  assert.equal(tabs.current(), "two");
  dom.window.close();
});

// ---------------------------------------------------------------- dataTable ---

test("a sortable data table marks the sorted column and asks for the other direction", () => {
  const {dom, window, doc, run} = load();
  window.sorts = [];
  // Arrays from the page's realm, copied so they compare as plain arrays.
  const lastSort = () => [...window.sorts.at(-1)];
  const table = run(`dataTable(["Name", {label: "Severity", sortKey: "severity", defaultDir: "desc"},
                                {label: "Store", sortKey: "store"}, {sr: "Open"}],
    {tableClass: "ftable", sort: {key: "severity", dir: "desc", onSort: (key, dir) => sorts.push([key, dir])}})`);
  doc.body.append(table.node);
  const sortOf = () => [...table.node.querySelectorAll("th")].map(th => th.getAttribute("aria-sort"));

  assert.equal(table.node.className, "table-wrap");
  assert.equal(table.node.querySelector("table").className, "ftable");
  assert.deepEqual(sortOf(), [null, "descending", "none", null], "unsortable columns carry no aria-sort");
  const severity = () => table.node.querySelectorAll("th")[1].querySelector("button.th-sort");
  assert.equal(severity().title, "Sort by severity");

  severity().click();
  assert.deepEqual(lastSort(), ["severity", "asc"], "the sorted column flips");
  assert.deepEqual(sortOf(), [null, "ascending", "none", null]);

  table.node.querySelectorAll("th")[2].querySelector("button").click();
  assert.deepEqual(lastSort(), ["store", "asc"], "a new column starts at its default");
  assert.deepEqual(sortOf(), [null, "none", "ascending", null]);
  severity().click();
  assert.deepEqual(lastSort(), ["severity", "desc"], "the severity column defaults to worst first");
  assert.deepEqual({...table.sortState()}, {key: "severity", dir: "desc"});
  dom.window.close();
});

test("setRows stamps each cell with its column and shows the empty row", () => {
  const {dom, doc, run} = load();
  const table = run(`dataTable(["Started", "Store", {sr: "Open"}], {wrapClass: "table-wrap archive-table",
                                                                   empty: "No saved audits yet."})`);
  doc.body.append(table.node);
  const body = table.node.querySelector("tbody");
  assert.equal(body.children.length, 0, "the body starts empty until the first draw");

  table.setRows(run(`[h("tr", {}, h("td", {}, "today"), h("td", {}, "prod"), h("td", {}, "Open"))]`));
  assert.deepEqual([...body.querySelectorAll("td")].map(td => td.dataset.label), ["Started", "Store", "Open"]);

  table.setRows([]);
  const cell = body.querySelector("td");
  assert.equal(cell.getAttribute("colspan"), "3");
  assert.equal(cell.querySelector(".empty").textContent, "No saved audits yet.");

  table.setRows([], {empty: "No loaded audit matches these filters."});
  assert.equal(body.querySelector(".empty").textContent, "No loaded audit matches these filters.");
  assert.equal(body.children.length, 1);
  dom.window.close();
});

test("a static table keeps its header shapes and reports the sort it asks for", () => {
  const {dom, window, run} = load();
  window.asked = [];
  const node = run(`table([{label: "Recorded", sortKey: "created_at", defaultDir: "desc"}, "", {sr: "Select"},
                           {label: "Picked", srLabel: "Select all", className: "c-select"}], [],
    {sort: {key: "", dir: "desc", onSort: (key, dir) => asked.push([key, dir])}})`);
  const heads = [...node.querySelectorAll("th")];
  assert.equal(heads[0].getAttribute("aria-sort"), "none");
  assert.equal(heads[1].querySelector(".sr-only").textContent, "Actions");
  assert.equal(heads[2].querySelector(".sr-only").textContent, "Select");
  assert.equal(heads[3].className, "c-select");
  assert.equal(heads[3].textContent, "Picked");
  assert.equal(node.querySelector("td").getAttribute("colspan"), "4");
  assert.equal(node.querySelector(".empty").textContent, "No records.");
  heads[0].querySelector("button").click();
  assert.deepEqual(window.asked.map(a => [...a]), [["created_at", "desc"]]);
  dom.window.close();
});

// ---------------------------------------------------------------- segmented ---

test("a toggle group presses one option and moves the press when picked", () => {
  const {dom, window, doc, run} = load();
  window.picks = [];
  const group = run(`segmented({label: "Archive lists", className: "archive-switch", value: "audits",
    dataKey: "list", controls: id => "archive-" + id,
    options: [["audits", "Saved audits"], ["scans", "Individual scans"]], onPick: id => picks.push(id)})`);
  doc.body.append(group);
  const buttons = [...group.querySelectorAll("button")];
  const pressed = () => buttons.map(b => b.getAttribute("aria-pressed"));

  assert.equal(group.className, "segmented archive-switch");
  assert.equal(group.getAttribute("role"), "group");
  assert.equal(group.getAttribute("aria-label"), "Archive lists");
  assert.deepEqual(pressed(), ["true", "false"]);
  assert.deepEqual(buttons.map(b => b.className), ["seg seg-on", "seg"]);
  assert.deepEqual(buttons.map(b => b.dataset.list), ["audits", "scans"]);
  assert.deepEqual(buttons.map(b => b.getAttribute("aria-controls")), ["archive-audits", "archive-scans"]);

  buttons[1].click();
  assert.deepEqual(pressed(), ["false", "true"]);
  assert.deepEqual(buttons.map(b => b.className), ["seg", "seg seg-on"]);
  assert.deepEqual([...window.picks], ["scans"]);
  dom.window.close();
});

test("a toggle group that navigates leaves the press to the next screen", () => {
  const {dom, window, run} = load();
  window.went = [];
  const group = run(`segmented({label: "Show", value: "work", navigates: true,
    options: [["work", "Work queue"], ["approval", "Approval queue"]], onPick: id => went.push(id)})`);
  const buttons = [...group.querySelectorAll("button")];
  assert.equal(group.className, "segmented");
  buttons[1].click();
  assert.deepEqual([...window.went], ["approval"]);
  assert.deepEqual(buttons.map(b => b.getAttribute("aria-pressed")), ["true", "false"]);
  dom.window.close();
});

// ----------------------------------------------------------------- stepList ---

test("a step list marks done, current and failed steps in text as well as class", () => {
  const {dom, run} = load();
  const list = run(`stepList(["Stage", "Approve", "Run", "Re-scan"], 2, {className: "remediation-steps",
                                                                         label: "Progress", srPrefix: true})`);
  const items = [...list.querySelectorAll("li")];
  assert.equal(list.tagName, "OL");
  assert.equal(list.getAttribute("aria-label"), "Progress");
  assert.deepEqual(items.map(li => li.className), ["is-done", "is-done", "is-current", ""]);
  assert.deepEqual(items.map(li => li.getAttribute("aria-current")), [null, null, "step", null]);
  assert.deepEqual(items.map(li => li.querySelector(".sr-only").textContent),
                   ["done: ", "done: ", "current: ", "to do: "]);

  const failed = run(`stepList(["Stage", "Approve", "Run"], 1, {failed: true, srPrefix: true})`);
  const failedItems = [...failed.querySelectorAll("li")];
  assert.equal(failedItems[1].className, "is-failed", "a failure is drawn at its step, never as done");
  assert.equal(failedItems[1].getAttribute("aria-current"), "step");
  assert.equal(failedItems[1].querySelector(".sr-only").textContent, "failed: ");

  const wrapped = run(`stepList(["Scope", "Run"], 0, {label: "Lifecycle", ariaCurrent: false,
    itemClass: state => "step step-" + state, wrap: {tag: "nav", className: "stepper", after: "Note"}})`);
  assert.equal(wrapped.tagName, "NAV");
  assert.equal(wrapped.getAttribute("aria-label"), "Lifecycle");
  assert.equal(wrapped.querySelector("ol").getAttribute("aria-label"), null, "the label sits on the wrapper");
  assert.deepEqual([...wrapped.querySelectorAll("li")].map(li => li.className), ["step step-current", "step step-todo"]);
  assert.equal(wrapped.querySelector("[aria-current]"), null);
  dom.window.close();
});

// ----------------------------------------------------------------- factList ---

test("a fact list renders label and value pairs in either shape", () => {
  const {dom, run} = load();
  const tiles = run(`factList([["Stores", "3"], ["Needs action", "1", "matched, not verified"], null],
    {className: "page-facts", itemClass: "page-fact", valueClass: "page-fact-v", noteClass: "page-fact-n"})`);
  assert.equal(tiles.tagName, "DL");
  assert.equal(tiles.className, "page-facts");
  const facts = [...tiles.children];
  assert.deepEqual(facts.map(f => f.className), ["page-fact", "page-fact"], "a falsy item is dropped");
  assert.deepEqual(facts.map(f => f.querySelector("dt").textContent), ["Stores", "Needs action"]);
  assert.deepEqual(facts.map(f => f.querySelector(".page-fact-v").textContent), ["3", "1"]);
  assert.equal(facts[0].querySelector(".page-fact-n"), null);
  assert.equal(facts[1].querySelector(".page-fact-n").textContent, "matched, not verified");

  const kv = run(`factList([["What changes", "Deletes chunks"], ["Reaches", ""], {label: "Does not", value: "Re-scan"}],
                           {className: "kv", skipEmpty: true})`);
  assert.deepEqual([...kv.children].map(n => n.tagName), ["DT", "DD", "DT", "DD"], "dt and dd sit in the list");
  assert.deepEqual([...kv.querySelectorAll("dt")].map(n => n.textContent), ["What changes", "Does not"]);
  assert.deepEqual([...kv.querySelectorAll("dd")].map(n => n.textContent), ["Deletes chunks", "Re-scan"]);
  dom.window.close();
});

// ----------------------------------------------------------------- toneChip ---

test("a tone chip labels an unknown state as it came, in the unknown tone", () => {
  const {dom, run} = load();
  const known = run(`toneChip({passed: "ok", not_run: {tone: "unknown", text: "Not run"}}, "passed")`);
  assert.equal(known.className, "badge sev-ok");
  assert.equal(known.textContent, "passed");
  const mapped = run(`toneChip({not_run: {tone: "unknown", text: "Not run"}}, "not_run")`);
  assert.equal(mapped.textContent, "Not run");
  const unknown = run(`toneChip({passed: "ok"}, "half_done")`);
  assert.equal(unknown.className, "badge sev-unknown");
  assert.equal(unknown.textContent, "half done");
  dom.window.close();
});
