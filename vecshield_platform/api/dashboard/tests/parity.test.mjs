import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// The parity gate. `fixtures/console-parity-checklist.md` names a destination
// for every workflow the shipped console has. This resolves each one against
// the console's own area and tab registry, so a checklist row that points
// nowhere fails the build instead of quietly becoming a lost workflow.

const source = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const checklist = await readFile(
  new URL("./fixtures/console-parity-checklist.md", import.meta.url), "utf8");

function registry() {
  const context = vm.createContext({
    document: {
      createElement: () => ({setAttribute() {}, addEventListener() {}, append() {}, dataset: {}}),
      createElementNS: () => ({setAttribute() {}, addEventListener() {}, append() {}, dataset: {}}),
      createTextNode: () => ({}),
      getElementById: () => null,
      addEventListener() {},
    },
    Node: function Node() {}, URLSearchParams, Intl,
    location: {hash: ""}, sessionStorage: {getItem: () => null},
    localStorage: {getItem: () => null}, setTimeout() {}, fetch: async () => ({ok: true}),
  });
  vm.runInContext(source, context);
  // `const` declarations are script-scoped, so read them by evaluating names.
  return {
    areas: vm.runInContext("AREAS", context),
    views: vm.runInContext("Object.entries(views).map(([id, v]) => [id, v[0], v[2]])", context),
    legacy: vm.runInContext("LEGACY_VIEWS", context),
    resolveView: id => vm.runInContext(`resolveView(${JSON.stringify(id)})`, context),
    subviews: vm.runInContext("SUBVIEW_PARENT", context),
  };
}

const {areas, views, legacy, resolveView, subviews} = registry();

// Rows read: "- [ ] Description — *Area → Tab*"
function rows() {
  return [...checklist.matchAll(/^- \[([ x-])\] (.+?) — \*([^*]+)\*/gm)].map(m => ({
    verified: m[1] === "x",
    dropped: m[1] === "-",
    description: m[2].trim(),
    destination: m[3].trim(),
  }));
}

function destinations() {
  const map = new Map();
  // The shell is on every screen rather than being one, so its rows are proved
  // by the a11y and workflow suites (focus, announcements, deep links, theme)
  // rather than by resolving to an area.
  map.set("shell", "shell");
  for (const [areaName, , , members] of areas) {
    map.set(areaName.toLowerCase(), members[0]);
    for (const id of members) {
      const [label] = views.find(([viewId]) => viewId === id);
      map.set(`${areaName} → ${label}`.toLowerCase(), id);
    }
  }
  return map;
}

test("the checklist has rows and every one names a destination", () => {
  const parsed = rows();
  assert.ok(parsed.length >= 60, `expected the full inventory, parsed ${parsed.length}`);
  for (const row of parsed) {
    assert.ok(row.destination.length > 0, `${row.description} names no destination`);
  }
});

test("every destination the checklist names exists in the console", () => {
  const known = destinations();
  const missing = [];
  for (const row of rows()) {
    if (row.dropped) continue;
    const key = row.destination.toLowerCase();
    // "Area → Tab → Action" resolves to its tab; the action lives on that screen.
    const parts = key.split("→").map(s => s.trim());
    const candidates = [key, parts.slice(0, 2).join(" → "), parts[0]];
    if (!candidates.some(c => known.has(c))) missing.push(`${row.description} → ${row.destination}`);
  }
  assert.deepEqual(missing, [], `\n  unreachable destinations:\n  ${missing.join("\n  ")}\n`);
});

test("every area has at least one screen and every screen belongs to an area", () => {
  const owned = new Set(areas.flatMap(([, , , members]) => members));
  for (const [areaName, glyph, blurb, members] of areas) {
    assert.ok(members.length >= 1, `${areaName} owns no screens`);
    assert.ok(glyph && blurb, `${areaName} needs an icon and a description`);
  }
  for (const [id] of views) {
    assert.ok(owned.has(id), `view "${id}" is not reachable from any area`);
  }
});

test("the sixteen original destinations all survived the re-parenting", () => {
  const original = ["overview", "stores", "schema", "assess", "ingest", "policies",
                    "templates", "falsepositives", "runtime", "detectors", "alerting",
                    "dsar", "jobs", "history", "audit", "status"];
  const present = new Set(views.map(([id]) => id));
  for (const id of original) {
    assert.ok(present.has(id), `"${id}" was lost in the re-parenting`);
  }
  // The six task areas the re-parenting produced must all still be there. The
  // count is not pinned: Docs was added later and is not a task area.
  const names = areas.map(([name]) => name);
  for (const name of ["Overview", "Estate", "Assessments", "Findings", "Compliance",
                      "Operations"]) {
    assert.ok(names.includes(name), `the ${name} area was lost`);
  }
});

test("links people already hold still resolve", () => {
  for (const [oldId, newId] of Object.entries(legacy)) {
    assert.equal(resolveView(oldId), newId, `#/${oldId} must still resolve`);
  }
  for (const [id] of views) {
    assert.equal(resolveView(id), id, `#/${id} must resolve to itself`);
  }
  assert.equal(resolveView("nonsense"), "overview", "an unknown link lands somewhere usable");
});

test("no checklist row is checked without a destination that exists", () => {
  // Guards against the failure mode this document exists to prevent: marking a
  // workflow as preserved because the code moved, not because it was verified.
  const known = destinations();
  for (const row of rows().filter(r => r.verified)) {
    const parts = row.destination.toLowerCase().split("→").map(s => s.trim());
    const candidates = [row.destination.toLowerCase(), parts.slice(0, 2).join(" → "), parts[0]];
    assert.ok(candidates.some(c => known.has(c)),
              `"${row.description}" is checked but points at "${row.destination}"`);
  }
});

// Rendering every screen is the part that actually proves re-parenting did not
// break anything: a view that throws on render is a lost workflow, however
// tidily it is filed in the navigation.

import { renderAll } from "./render-harness.mjs";

test("every screen in every area still renders", async () => {
  const failures = await renderAll();
  assert.deepEqual(failures, [], `\n  screens that failed to render:\n  ${failures.join("\n  ")}\n`);
});

test("the consolidated navigation keeps every screen reachable where the plan put it", () => {
  // Batch 3: Frameworks is a view within Criteria, Templates within Policies,
  // Runs within Archive; False positives sits under Findings; Audit log,
  // Alerting and Status are the System group; Docs is the help icon.
  assert.deepEqual({...subviews}, {frameworks: "criteria", templates: "policies", jobs: "history"});
  const areaOf = id => areas.find(([, , , members]) => members.includes(id));
  for (const [child, parent] of Object.entries(subviews)) {
    assert.equal(areaOf(child)[0], areaOf(parent)[0], `${child} lives in its parent's area`);
  }
  assert.equal(areaOf("falsepositives")[0], "Findings");
  const system = areas.find(([name]) => name === "System");
  // Users joins them; it is listed only for an admin when sign-in is on.
  assert.deepEqual([...system[3]], ["audit", "alerting", "status", "users"]);
  assert.equal(system[4], "system");
  assert.equal(areas.find(([name]) => name === "Docs")[4], "help");
  const main = Array.from(areas.filter(a => a[4] === "main"), ([name]) => name);
  assert.deepEqual(main, ["Overview", "Estate", "Assessments", "Findings", "Compliance", "Operations"],
                   "area names stay");
  // Every id still resolves to itself, so deep links and bookmarks survive.
  for (const id of ["frameworks", "templates", "jobs", "falsepositives", "audit", "alerting", "status", "docs"]) {
    assert.equal(resolveView(id), id);
  }
});
