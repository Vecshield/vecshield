import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

/**
 * The keyboard walkthrough gate.
 *
 * What this checks: that on every view, every interactive control is reachable
 * in document order, carries an accessible name, and that no control removes
 * itself from the tab sequence or jumps the queue with a positive tabindex.
 * Dialogs are separately covered in tests/a11y.test.mjs.
 *
 * What it cannot check, and why: jsdom does no layout, so it cannot verify that
 * focus is *visible*, that a focused control is scrolled into view, or that CSS
 * has not visually reordered the DOM. Those need a real browser. This is the
 * part that can run on every commit; it is not the whole walkthrough.
 */

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

const RESPONSES = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant", tenant_field: "tenant_id"}]},
  "/admin/policies": {policies: [{id: "p1", name: "Secrets", severity: "critical",
                                  when: {}, action: "purge", enabled: true}]},
  "/admin/policy-templates": {templates: []},
  "/admin/history": {jobs: [], stats: {total_findings: 2, by_severity: {high: 2}}},
  "/admin/history/trend": {trend: [], available: true},
  "/admin/history/audits": {audits: []},
  "/admin/estate": {stores: [{store_id: "prod", kind: "qdrant", last_assessed: null,
                              coverage: null, findings: {}, findings_total: 0,
                              history_available: true, probe: {probed: false}}],
                    probed: false, note: "note"},
  "/admin/findings": {findings: [{id: "f1", title: "PII", severity: "high",
                                  category: "data_classification", store: "prod",
                                  collection: "docs", suppressed: false,
                                  case: {state: "new", owner: null}}],
                      total: 1, limit: 50, offset: 0, has_more: false,
                      facets: {case_state: {new: 1}}},
  "/admin/jobs": {jobs: [{id: "j1", kind: "audit", status: "succeeded", actor: "a",
                          resource: "prod", created_at: "2026-09-17T10:00:00+00:00"}]},
  "/admin/allowlist": {rules: []},
  "/admin/suppressions": {suppressions: []},
  "/admin/detectors": {bulk_volume: {}, collection_sweep: {}, enumeration: {},
                       rate_baseline: {}, cooldown_s: 60},
  "/admin/alerting": {webhooks: [], min_severity: "high"},
  "/admin/dsar": {requests: []},
  "/compliance/criteria": {pack: {pack_version: "d1", criteria: 1, lifecycle: "draft",
                                  regulatory_review: null, note: "n"},
                           criteria: [{criterion_id: "C-1", framework: "HIPAA",
                                       paraphrase: "Access is limited.",
                                       sources: [{section: "45 CFR 164.312"}],
                                       manual_evidence: ["access_review_record"],
                                       limitations: [], applicability_questions: []}]},
  "/compliance/evidence": {artifacts: [], note: "n"},
  "/compliance/reviews": {reviews: []},
  "/compliance/exceptions": {exceptions: [], pending_approval: 0, active: 0, expired: 0, note: "n"},
  "/runtime/alerts": {alerts: []},
  "/runtime/alerts/stats": {total: 0},
  "/audit-log": {entries: [], verified: true},
  "/version": {version: "1", detection_version: "1", detectors: ["bulk_volume"]},
  "/healthz": {status: "ok"},
  "/readyz": {status: "ok", checks: {}},
  "/stores": {stores: []},
};

function respond(path) {
  const base = path.split("?")[0];
  if (RESPONSES[base] !== undefined) return RESPONSES[base];
  if (base.startsWith("/stores/")) return {findings: [], collections: [], schema: {}, stats: {}};
  if (base.startsWith("/admin/history/")) return {findings: [], jobs: [], audits: []};
  return {};
}

const FOCUSABLE = 'a[href], button, input, select, textarea, summary, [tabindex]';

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
  return dom;
}

// Contents name a button or a link. They do not name a form control: a
// <select>'s textContent is its options, and treating that as a name is how an
// unnamed filter dropdown slips through a check like this one.
const NAMED_BY_CONTENTS = new Set(["BUTTON", "A", "SUMMARY", "TH", "LABEL"]);

/** An element's accessible name, by the routes this console actually uses. */
function accessibleName(el, doc) {
  const labelledBy = el.getAttribute("aria-labelledby");
  if (labelledBy) {
    const target = doc.getElementById(labelledBy);
    if (target?.textContent.trim()) return target.textContent.trim();
  }
  const aria = el.getAttribute("aria-label");
  if (aria?.trim()) return aria.trim();

  const id = el.getAttribute("id");
  if (id) {
    // Matched by attribute rather than by selector, so no id needs escaping.
    const label = [...doc.querySelectorAll("label[for]")]
      .find(l => l.getAttribute("for") === id);
    if (label?.textContent.trim()) return label.textContent.trim();
  }
  const wrapping = el.closest("label");
  if (wrapping && wrapping !== el && wrapping.textContent.trim()) {
    return wrapping.textContent.trim();
  }

  const title = el.getAttribute("title");
  if (title?.trim()) return title.trim();
  if (NAMED_BY_CONTENTS.has(el.tagName) && el.textContent.trim()) {
    return el.textContent.trim();
  }
  // An input may be named by its placeholder as a last resort; a select may not.
  const placeholder = el.getAttribute("placeholder");
  if (el.tagName === "INPUT" && placeholder?.trim()) return placeholder.trim();
  return "";
}

const VIEWS = ["overview", "stores", "schema", "assess", "history", "jobs", "findings",
               "frameworks", "criteria", "evidence", "exceptions", "dsar", "policies",
               "templates", "falsepositives", "runtime", "detectors", "alerting",
               "ingest", "audit", "status", "docs"];

for (const view of VIEWS) {
  test(`${view} is fully operable by keyboard`, async () => {
    const dom = await boot(`#/${view}`);
    const doc = dom.window.document;
    const controls = [...doc.querySelectorAll(FOCUSABLE)];

    const unnamed = [];
    const jumpsQueue = [];
    const unreachable = [];

    for (const el of controls) {
      const tabindex = el.getAttribute("tabindex");
      // A positive tabindex jumps ahead of document order and breaks the
      // sequence for everyone else on the page.
      if (tabindex && Number(tabindex) > 0) {
        jumpsQueue.push(`${el.tagName}[tabindex=${tabindex}]`);
      }
      // -1 is legitimate for a focus target like the page heading, but not for
      // something the reader is meant to operate.
      if (tabindex === "-1" && ["BUTTON", "A", "INPUT", "SELECT", "TEXTAREA"].includes(el.tagName)) {
        unreachable.push(`${el.tagName} "${el.textContent.trim().slice(0, 30)}"`);
      }
      if (el.hasAttribute("disabled")) continue;
      // A tabindex="-1" element is a focus target, not a tab stop — the page
      // heading route changes focus to, for instance. It is not something the
      // reader operates, so it needs no name of its own.
      if (tabindex === "-1") continue;
      if (!accessibleName(el, doc)) {
        unnamed.push(`${el.tagName}${el.className ? "." + el.className.split(" ")[0] : ""}` +
                     ` ${el.outerHTML.slice(0, 90)}`);
      }
    }

    dom.window.close();
    assert.deepEqual(jumpsQueue, [], `positive tabindex breaks the sequence: ${jumpsQueue}`);
    assert.deepEqual(unreachable, [], `removed from the tab order: ${unreachable}`);
    assert.deepEqual(unnamed, [],
      `\n  ${view}: controls a screen reader cannot name:\n  ${unnamed.join("\n  ")}\n`);
    assert.ok(controls.length > 0, "the view has something to operate");
  });
}

test("the page heading is a focus target, not a tab stop", async () => {
  const dom = await boot("#/overview");
  const heading = dom.window.document.getElementById("page-title");
  assert.equal(heading.getAttribute("tabindex"), "-1",
    "route changes move focus here without adding a stop to the sequence");
  dom.window.close();
});

test("every view's first control is reachable without passing through the content", async () => {
  // Navigation comes before content in the document, so a keyboard user reaches
  // the nav without tabbing through the page body first.
  const dom = await boot("#/findings");
  const doc = dom.window.document;
  const controls = [...doc.querySelectorAll(FOCUSABLE)];
  const firstNav = controls.findIndex(el => el.classList.contains("nav-btn"));
  const firstContent = controls.findIndex(el => el.closest("#content"));
  assert.ok(firstNav > -1 && firstContent > -1);
  assert.ok(firstNav < firstContent, "navigation precedes content in the tab sequence");
  dom.window.close();
});

test("the first stop in the tab order skips to the page, and is a button", async () => {
  // An anchor to #content would be read by the hash router as a view id.
  const dom = await boot("#/findings");
  const doc = dom.window.document;
  const first = [...doc.querySelectorAll(FOCUSABLE)][0];
  assert.equal(first.tagName, "BUTTON");
  assert.ok(first.classList.contains("skip-link"));
  assert.equal(first.textContent.trim(), "Skip to content");
  assert.equal(first.parentElement, doc.querySelector(".app"));
  assert.equal(first, doc.querySelector(".app").firstElementChild, "the shell's first child");
  doc.querySelector(".nav-btn").focus();
  first.click();
  assert.equal(doc.activeElement, doc.getElementById("page-title"));
  dom.window.close();
});

test("the drawer's backdrop is hidden until the drawer opens, and the close button is named", async () => {
  const dom = await boot("#/overview");
  const doc = dom.window.document;
  const backdrop = doc.getElementById("side-backdrop");
  assert.ok(backdrop.hidden);
  assert.equal(backdrop.parentElement, doc.getElementById("side").parentElement);
  const close = doc.querySelector("#side .side-close");
  assert.equal(close.tagName, "BUTTON");
  assert.equal(close.getAttribute("aria-label"), "Close navigation");
  doc.getElementById("menu-btn").click();
  assert.equal(backdrop.hidden, false);
  assert.ok(doc.querySelector("main.main").hasAttribute("inert"));
  backdrop.click();
  assert.ok(backdrop.hidden);
  assert.equal(doc.querySelector("main.main").hasAttribute("inert"), false);
  dom.window.close();
});
