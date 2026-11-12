import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// Every screen, rendered in a real DOM, checked for the structure Batch 1 of
// docs/console_ux_roadmap.md settled on:
//
// - a screen names itself once: one h1, in its own header, and no second copy
//   of the title and subtitle in the top bar;
// - its header has at most one primary action;
// - every status chip is an icon and a label;
// - notes are not live regions;
// - no raw ISO timestamp is printed where a reader reads it.
//
// jsdom does no layout, so what this cannot check (wrapping, overflow, the
// 56px phone bar) is pinned by tests/layout.test.mjs and the screenshot pass.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

const ISO = "2026-09-20T10:15:30.123456+00:00";

const RESPONSES = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant", tenant_field: "tenant_id"}]},
  "/admin/home": {history_available: true, checked: ["stores_partial_coverage"], unavailable: [],
                  needs_you: [{kind: "stores_partial_coverage", count: 1, stores: ["prod"],
                               title: "Stores whose latest audit did not cover its whole scope",
                               target: {view: "history", params: {store: "prod"}},
                               by_status: {partial: 1}}],
                  open_findings: {by_severity: {critical: 0, high: 2, medium: 0, low: 0, info: 0},
                                  total: 2, stores: 1, stores_assessed: 1, stores_never_assessed: 0,
                                  suppressed: 0, note: "n"},
                  stores: {total: 1, assessed: 1, never_assessed: 0, partial_coverage: 1}, note: "n"},
  "/admin/policies": {policies: [{id: "p1", name: "Secrets", severity: "critical",
                                  when: {}, action: "purge", enabled: true}]},
  "/admin/policy-templates": {templates: []},
  "/admin/history": {jobs: [{id: "j1", store: "prod", kind: "audit", max_severity: "high",
                             finding_count: 2, created_at: ISO, stats: {coverage: {status: "partial"}}}],
                     stats: {total_findings: 2, by_severity: {high: 2}}},
  "/admin/history/trend": {trend: [], available: true},
  "/admin/history/audits": {audits: [{id: "a1", store_id: "prod", status: "succeeded",
                                      coverage: {status: "partial"}, started_at: ISO}],
                            has_more: false},
  "/admin/estate": {stores: [{store_id: "prod", kind: "qdrant", last_assessed: ISO,
                              coverage: {status: "partial"}, findings: {high: 2}, findings_total: 2,
                              history_available: true, probe: {probed: false}}],
                    probed: false, note: "note"},
  "/admin/findings": {findings: [{id: "f1", title: "PII", severity: "high",
                                  category: "data_classification",
                                  store: "file:///var/lib/vecshield/stores/prod", collection: "docs",
                                  suppressed: false, case: {state: "new", owner: null}}],
                      total: 1, limit: 50, offset: 0, has_more: false,
                      facets: {case_state: {new: 1}}},
  "/admin/jobs": {jobs: [{id: "j1", kind: "audit", status: "succeeded", actor: "a",
                          resource: "prod", created_at: ISO, started_at: ISO, finished_at: ISO}]},
  "/admin/allowlist": {allowlist: []},
  "/admin/suppressions": {suppressions: []},
  "/admin/detectors": {bulk_volume: {enabled: true, threshold: 5}, cooldown_s: 60},
  "/admin/alerting": {webhooks: [], min_severity: "high", enabled: true, console: true},
  "/admin/dsar": {dsars: [{id: "r1", subject: "alice@example.com", status: "awaiting_verification",
                           requested_at: ISO, total_chunks_found: 3}]},
  "/compliance/criteria": {pack: {pack_version: "d1", criteria: 1, lifecycle: "draft",
                                  regulatory_review: null, note: "n", frameworks: ["HIPAA"]},
                           criteria: [{criterion_id: "C-1", framework: "HIPAA",
                                       paraphrase: "Access is limited.",
                                       sources: [{section: "45 CFR 164.312"}],
                                       technical_checks: ["cve"],
                                       manual_evidence: ["access_review_record"],
                                       limitations: [], applicability_questions: []}]},
  "/compliance/evidence": {artifacts: [], note: "n"},
  "/compliance/reviews": {reviews: []},
  "/compliance/exceptions": {exceptions: [], pending_approval: 0, active: 0, expired: 0, note: "n"},
  "/runtime/alerts": {alerts: []},
  "/runtime/alerts/stats": {total: 0},
  "/audit-log": {entries: [{ts: 1789701184.7, actor: "admin", action: "full_audit",
                            target: "prod", details: {violations: 12, finished_at: ISO}}],
                 verified: true},
  "/version": {version: "1", detection_version: "1", detectors: ["bulk_volume"],
               auth_enabled: true, admin_enabled: true},
  "/healthz": {status: "ok", stores: 1},
  "/readyz": {status: "ready", checks: {registry: "ok", history: "ok", alert_store: "ok"}},
  "/stores": {stores: []},
};

function respond(path) {
  const base = path.split("?")[0];
  if (RESPONSES[base] !== undefined) return RESPONSES[base];
  if (base.startsWith("/stores/")) return {findings: [], collections: [], schema: {}, stats: {}};
  if (base.startsWith("/admin/history/")) return {findings: [], jobs: [], audits: []};
  return {};
}

async function boot(hash) {
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="light"><head><style>${css}</style></head>` +
    `<body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  dom.window.location.hash = hash;
  dom.window.fetch = async path => ({
    ok: true, status: 200, headers: {get: () => "application/json"},
    json: async () => respond(path), text: async () => JSON.stringify(respond(path)),
  });
  dom.window.eval(shell);
  dom.window.eval("buildShell()");
  await dom.window.eval("route()");
  await new Promise(r => setTimeout(r, 30));
  return dom;
}

const VIEWS = ["overview", "stores", "schema", "crypto", "assess", "history", "jobs", "findings",
               "actions", "frameworks", "criteria", "evidence", "exceptions", "dsar", "policies",
               "templates", "falsepositives", "runtime", "detectors", "alerting",
               "ingest", "audit", "status", "docs", "settings"];

const titles = new JSDOM("", {url: "https://console.test/", runScripts: "outside-only"});
// `views` is a script-level const, so it is read in the same evaluation.
const TITLE = JSON.parse(titles.window.eval(
  `${shell}\n;JSON.stringify(Object.fromEntries(Object.entries(views).map(([k, v]) => [k, v[0]])))`));
titles.window.close();

for (const view of VIEWS) {
  test(`${view} names itself once, in its own header`, async () => {
    const dom = await boot(`#/${view}`);
    const doc = dom.window.document;
    const headings = [...doc.querySelectorAll("h1")];
    assert.equal(headings.length, 1, `one h1, found ${headings.length}`);
    assert.equal(headings[0].textContent.trim(), TITLE[view], "named from the view registry");
    assert.ok(headings[0].closest("#content .page-head"), "the heading is in the page header");
    assert.equal(headings[0].id, "page-title");
    assert.equal(doc.activeElement, headings[0], "the route lands focus on it");

    const bar = doc.getElementById("top");
    assert.equal(bar.querySelector("h1, h2, .subtitle"), null, "the top bar carries no second title");
    assert.ok(!bar.textContent.includes(TITLE[view]), "the top bar does not repeat the page's title");

    const primaries = doc.querySelectorAll(".page-head .btn.primary");
    assert.ok(primaries.length <= 1, `at most one primary action in the header, found ${primaries.length}`);
    // The old intro strip is gone; what it held is in a closed disclosure.
    assert.equal(doc.querySelector(".intro"), null);
    const about = doc.querySelector("details.about");
    if (about) {
      assert.equal(about.open, false, "About this screen starts closed");
      assert.match(about.querySelector("summary").textContent, /About this screen/);
    }
    dom.window.close();
  });

  test(`${view}: statuses are chips with an icon and a label, and notes are not live regions`, async () => {
    const dom = await boot(`#/${view}`);
    const doc = dom.window.document;
    for (const chip of doc.querySelectorAll("#content .badge")) {
      assert.ok(chip.querySelector("svg"), `chip "${chip.textContent.trim()}" has an icon`);
      assert.ok(chip.textContent.trim().length > 0, "and a label");
    }
    for (const note of doc.querySelectorAll("#content .note")) {
      assert.equal(note.getAttribute("role"), null,
        `static note "${note.textContent.trim().slice(0, 40)}" must not be a live region`);
    }
    // Count facts under the header carry no percentage (compliance screens
    // above all): counts only.
    for (const fact of doc.querySelectorAll(".page-facts .page-fact-v")) {
      assert.doesNotMatch(fact.textContent, /%/);
    }
    dom.window.close();
  });
}

// Everything a reader reads, minus the raw-record disclosures that exist to
// show the machine form.
function readableText(root) {
  const clone = root.cloneNode(true);
  for (const raw of clone.querySelectorAll("details.evidence-data, pre, [title]")) {
    if (raw.matches("details.evidence-data, pre")) raw.remove();
  }
  return clone.textContent;
}

for (const view of ["assess", "history", "dsar", "jobs", "audit", "overview", "stores"]) {
  test(`${view} prints no raw ISO timestamp`, async () => {
    const dom = await boot(`#/${view}`);
    const content = dom.window.document.getElementById("content");
    const text = readableText(content);
    assert.doesNotMatch(text, /\d{4}-\d\d-\d\dT\d\d:\d\d/, "times read as relative and local");
    // The exact instant is still there for anyone who hovers.
    const times = [...content.querySelectorAll("time[datetime]")];
    if (["history", "dsar", "jobs"].includes(view)) {
      assert.ok(times.length > 0, "a <time> carries the exact instant");
      assert.match(times[0].getAttribute("title"), /^\d{4}-\d\d-\d\dT/);
    }
    dom.window.close();
  });
}

test("a finding's location reads as the store id, with the full URI on hover", async () => {
  const dom = await boot("#/findings");
  const location = dom.window.document.querySelector("#content .location");
  assert.ok(location);
  assert.match(location.textContent, /prod/);
  assert.doesNotMatch(location.textContent, /file:\/\//);
  assert.match(location.getAttribute("title"), /file:\/\/\/var\/lib\/vecshield\/stores\/prod \/ docs/);
  dom.window.close();
});

test("the frameworks matrix never prints a check's id under a label that is the id", async () => {
  const dom = await boot("#/frameworks");
  const rows = [...dom.window.document.querySelectorAll(".matrix tbody th")];
  assert.ok(rows.length > 0);
  for (const row of rows) {
    const parts = [...row.children].map(n => n.textContent.trim().toLowerCase());
    assert.ok(new Set(parts).size === parts.length, `repeated label: ${parts.join(" / ")}`);
  }
  assert.match(rows.map(r => r.textContent).join(" "), /Known CVEs/);
  dom.window.close();
});

test("the audit log shows details as a key/value list, not JSON", async () => {
  const dom = await boot("#/audit");
  const content = dom.window.document.getElementById("content");
  assert.equal(content.querySelector("table pre"), null, "no JSON block in a row");
  assert.ok(content.querySelector("table dl.kv-compact"));
  dom.window.close();
});

test("status reads its readiness checks as chips, with the raw record folded away", async () => {
  const dom = await boot("#/status");
  const content = dom.window.document.getElementById("content");
  const chips = [...content.querySelectorAll(".badge")].map(b => b.textContent.trim());
  assert.ok(chips.includes("ready"));
  assert.ok(chips.filter(c => c === "ok").length >= 3);
  const raw = content.querySelector("details.evidence-data pre");
  assert.ok(raw && !raw.closest("details").open, "the JSON is behind a closed Raw record");
  dom.window.close();
});

test("the findings chart colours each store's segment by severity, not the whole day red", async () => {
  const dom = await boot("#/overview");
  const {window} = dom;
  const today = new Date().toISOString().slice(0, 10);
  const chart = window.eval(`trendChart(${JSON.stringify([
    {day: today, store: "a", max_severity: "critical", findings: 3},
    {day: today, store: "b", max_severity: "low", findings: 5},
  ])}, {days: 3})`);
  const fills = [...chart.querySelectorAll("rect.bar")].map(r => r.getAttribute("class"));
  assert.ok(fills.some(c => c.includes("sev-fill-critical")));
  assert.ok(fills.some(c => c.includes("sev-fill-low")), "the low store is not painted critical");
  assert.match(chart.textContent, /coloured by the worst severity that store recorded/);
  dom.window.close();
});
