import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// The Detectors and Ingest screens.
// Each test boots the shipped console in a real DOM against a stubbed API and
// follows one journey: tune a rule and save it deliberately, or load an
// example, run a check, and read what the result does and does not establish.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

const SETTINGS = {
  cooldown_s: 300.0,
  bulk_volume: {enabled: true, threshold: 500, window_s: 600.0, severity: "high"},
  collection_sweep: {enabled: true, fraction: 0.8, window_s: 600.0, severity: "high"},
  enumeration: {enabled: true, sim_threshold: 0.97, run_length: 10, max_gap_s: 30.0, severity: "medium"},
  rate_baseline: {enabled: true, window_s: 60.0, spike_factor: 5.0, warmup_samples: 3,
                  min_rate: 10.0, alpha: 0.3, severity: "medium"},
};

const DEGRADED = {classifier: "regex", status: "degraded", nlp_loaded: false, regex_detector_count: 130,
                  reason: "NLP model 'en_core_web_hftrf' is not installed"};

const BASE = {
  "/admin/stores": {stores: []},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
  "/version": {},
  "/healthz": {status: "ok", stores: 0},
  "/admin/detectors": SETTINGS,
};

async function boot(hash, responses = {}, {signIn = false} = {}) {
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
    let value = all[key] ?? all[path.split("?")[0]] ?? {};
    if (typeof value === "function") value = await value(path, opts);
    if (typeof value?.status === "number") {
      return {ok: false, status: value.status, statusText: "Error",
              headers: {get: () => "application/json"}, json: async () => ({detail: value.detail})};
    }
    return {ok: true, status: 200, headers: {get: () => "application/json"},
            json: async () => value, text: async () => JSON.stringify(value)};
  };
  window.eval(shell);
  window.addEventListener("hashchange", window.eval("route"));
  if (signIn) {
    // The real start, which asks /auth/session and records the role.
    await window.eval("startConsole()");
  } else {
    window.eval("buildShell()");
    await window.eval("route()");
  }
  await settle();
  return {dom, window, doc: window.document, calls, run: code => window.eval(code)};
}

const settle = () => new Promise(r => setTimeout(r, 30));
const text = node => node.textContent.replace(/\s+/g, " ").trim();
const button = (root, label) => [...root.querySelectorAll("button")].find(b => text(b) === label);
// The run button shares its task's name with the tab; this is the one that runs.
const runButton = doc => doc.querySelector(".ingest-run button");
const posts = calls => calls.filter(c => c.method !== "GET");
function type(window, input, value) {
  input.value = value;
  input.dispatchEvent(new window.Event("input", {bubbles: true}));
}
// Reader-facing text, without the raw response disclosure.
function readable(root) {
  const clone = root.cloneNode(true);
  for (const raw of clone.querySelectorAll("details.evidence-data")) raw.remove();
  return text(clone);
}

// ------------------------------------------------------------ Detectors ---

test("detectors are four named choices, and the selected one explains its rule", async () => {
  const {dom, doc} = await boot("#/detectors");
  const content = doc.getElementById("content");
  const names = [...content.querySelectorAll(".detector-choice .strong")].map(text);
  assert.deepEqual(names, ["Bulk querying", "Collection harvesting", "Repeated similar queries", "Query-rate spikes"]);
  const detail = readable(content.querySelector(".detector-detail"));
  assert.match(detail, /Alert at High when one principal sends 500 queries within 10 minutes/);
  assert.match(detail, /counts queries, not the records they returned/);
  assert.match(detail, /not a recommended threshold/);
  assert.match(detail, /Enabled in configuration/);
  assert.doesNotMatch(readable(content), /bulk_volume|window_s|sim_threshold/, "no configuration keys as labels");
  assert.equal(content.querySelector("#det-bulk_volume-severity, #det-severity").tagName, "SELECT", "severity is a choice");
  dom.window.close();
});

test("the harvesting prerequisite is stated, not implied by the toggle", async () => {
  const {dom, doc} = await boot("#/detectors?detector=collection_sweep");
  const detail = readable(doc.querySelector(".detector-detail"));
  assert.match(detail, /no source for collection sizes, so with it this detector never alerts, even when enabled/);
  assert.equal(doc.getElementById("det-collection_sweep-fraction").value, "80", "a fraction reads as a percentage");
  dom.window.close();
});

test("an edit survives switching detectors, and untouched values round-trip exactly", async () => {
  const {dom, doc, window, calls} = await boot("#/detectors", {
    "PUT /admin/detectors": (_, opts) => JSON.parse(opts.body),
  });
  type(window, doc.getElementById("det-bulk_volume-threshold"), "750");
  assert.match(text(doc.querySelector(".save-status")), /1 unsaved change/);
  [...doc.querySelectorAll(".detector-choice")][1].click();
  await settle();
  [...doc.querySelectorAll(".detector-choice")][0].click();
  await settle();
  assert.equal(doc.getElementById("det-bulk_volume-threshold").value, "750", "the draft is kept");
  button(doc, "Save changes").click();
  await settle();
  const put = posts(calls).find(c => c.path === "/admin/detectors");
  assert.equal(put.method, "PUT");
  const expected = structuredClone(SETTINGS);
  expected.bulk_volume.threshold = 750;
  assert.deepEqual(put.body, expected, "only the edited value changed; 0.8 and 0.3 are sent as they came");
  assert.match(text(doc.querySelector(".save-status")), /No unsaved changes/);
  dom.window.close();
});

test("invalid values are refused inline and block saving", async () => {
  const {dom, doc, window, calls} = await boot("#/detectors");
  const input = doc.getElementById("det-bulk_volume-threshold");
  type(window, input, "0");
  assert.equal(input.getAttribute("aria-invalid"), "true");
  assert.match(text(doc.getElementById("det-bulk_volume-threshold-error")), /1 or more/);
  type(window, input, "12.5");
  assert.match(text(doc.getElementById("det-bulk_volume-threshold-error")), /whole number/);
  assert.equal(button(doc, "Save changes").disabled, true);
  assert.match(text(doc.querySelector(".save-status")), /Fix 1 invalid value/);
  assert.equal(posts(calls).length, 0);
  dom.window.close();
});

test("discard restores the saved values", async () => {
  const {dom, doc, window} = await boot("#/detectors");
  type(window, doc.getElementById("det-bulk_volume-threshold"), "900");
  button(doc, "Discard changes").click();
  await settle();
  assert.equal(doc.getElementById("det-bulk_volume-threshold").value, "500");
  assert.equal(button(doc, "Save changes").disabled, true);
  dom.window.close();
});

test("an invalid-only edit can be discarded and is protected on same-page navigation", async () => {
  const {dom, doc, window} = await boot("#/detectors");
  type(window, doc.getElementById("det-bulk_volume-threshold"), "bad");
  assert.equal(button(doc, "Discard changes").disabled, false);
  window.location.hash = "#/detectors?detector=enumeration";
  await settle(); await settle();
  assert.equal(window.location.hash, "#/detectors");
  button(doc.querySelector(".modal"), "Stay and keep editing").click();
  button(doc, "Discard changes").click();
  assert.equal(doc.getElementById("det-bulk_volume-threshold").value, "500");
  assert.equal(button(doc, "Discard changes").disabled, true);
  dom.window.close();
});

test("controls stay disabled during a save, including after changing the selected detector", async () => {
  let finish;
  const response = new Promise(resolve => { finish = resolve; });
  const {dom, doc, window} = await boot("#/detectors", {"PUT /admin/detectors": () => response});
  type(window, doc.getElementById("det-bulk_volume-threshold"), "750");
  button(doc, "Save changes").click();
  await settle();
  assert.equal(doc.getElementById("det-bulk_volume-threshold").disabled, true);
  [...doc.querySelectorAll(".detector-choice")][1].click();
  assert.equal(doc.getElementById("det-collection_sweep-fraction").disabled, true);
  assert.equal(doc.getElementById("det-enabled").disabled, true);
  finish({...SETTINGS, bulk_volume: {...SETTINGS.bulk_volume, threshold: 750}});
  await settle();
  assert.equal(doc.getElementById("det-collection_sweep-fraction").disabled, false);
  assert.equal(button(doc, "Save changes").disabled, true);
  dom.window.close();
});

test("a refused save keeps the draft and names the field", async () => {
  const {dom, doc, window} = await boot("#/detectors", {
    "PUT /admin/detectors": {status: 422, detail: "bulk_volume.window_s must be a finite number"},
  });
  type(window, doc.getElementById("det-bulk_volume-threshold"), "650");
  button(doc, "Save changes").click();
  await settle();
  assert.equal(doc.getElementById("det-bulk_volume-threshold").value, "650", "the draft survives");
  assert.match(text(doc.querySelector(".save-bar")), /Not saved: .*Your changes are still here/);
  assert.equal(doc.getElementById("det-bulk_volume-window_s").getAttribute("aria-invalid"), "true");
  dom.window.close();
});

test("leaving with unsaved edits asks first, and staying keeps them", async () => {
  const {dom, doc, window} = await boot("#/detectors");
  type(window, doc.getElementById("det-bulk_volume-threshold"), "650");
  window.location.hash = "#/runtime";
  await settle(); await settle();
  assert.equal(window.location.hash, "#/detectors", "the address is put back");
  assert.match(text(doc.querySelector(".modal")), /Discard unsaved changes\?/);
  button(doc.querySelector(".modal"), "Stay and keep editing").click();
  await settle();
  assert.equal(doc.getElementById("det-bulk_volume-threshold").value, "650");
  window.location.hash = "#/runtime";
  await settle(); await settle();
  button(doc.querySelector(".modal"), "Discard changes and leave").click();
  await settle(); await settle();
  assert.equal(window.location.hash, "#/runtime");
  dom.window.close();
});

test("a signed-in non-admin reads the settings but cannot edit them", async () => {
  const viewer = {username: "v", roles: ["viewer"], effective_roles: ["viewer"]};
  const {dom, doc} = await boot("#/detectors", {
    "/auth/session": {login_enabled: true, authenticated: true, user: viewer, password_policy: {min_length: 12}},
  }, {signIn: true});
  await settle();
  assert.match(readable(doc.getElementById("content")), /Administrator access is required to edit/);
  assert.equal(doc.getElementById("det-bulk_volume-threshold").disabled, true);
  assert.equal(doc.querySelector(".save-bar").hidden, true);
  dom.window.close();
});

test("unreadable detector settings are an error with a retry, not a form of defaults", async () => {
  const {dom, doc} = await boot("#/detectors", {"/admin/detectors": {status: 503, detail: "config unavailable"}});
  assert.equal(doc.querySelector(".detector-field"), null);
  assert.ok(button(doc.getElementById("content"), "Retry"));
  dom.window.close();
});

// --------------------------------------------------------------- Ingest ---

const GATE_EMAIL = {
  total: 1, blocked: 1, allowed: 0, pii_density: 1, blocked_chunk_ids: ["chunk-1"],
  findings: [{id: "f1", title: "PII blocked at ingest", severity: "high", category: "ingest_gate",
              description: "Chunk 'chunk-1' contains PII (email) and was blocked before embedding.",
              evidence: {chunk_id: "chunk-1", label: "pii", detectors: ["email"],
                         spans: [{detector: "email", label: "pii", preview: "jo*******om"}]}}],
  detection: DEGRADED,
};

test("loading an example fills the editor and runs nothing", async () => {
  const {dom, doc, window, calls} = await boot("#/ingest");
  const before = calls.length;
  const card = [...doc.querySelectorAll(".example-card")].find(c => /Support reply/.test(text(c)));
  card.click();
  await settle();
  assert.equal(calls.length, before, "no request");
  assert.match(doc.getElementById("ingest-chunk-1").value, /jordan\.lee@example\.com/);
  assert.equal(doc.querySelector(".ingest-picker").open, false, "the picker folds away");
  assert.match(window.location.hash, /example=support-email/);
  assert.doesNotMatch(window.location.hash, /jordan/, "content never enters the address");
  assert.match(readable(doc.querySelector(".ingest-result")), /Nothing has run yet/);
  dom.window.close();
});

test("categories filter the examples, not the engine", async () => {
  const {dom, doc} = await boot("#/ingest");
  const all = doc.querySelectorAll(".example-card").length;
  assert.ok(all >= 10, `a library of examples (${all})`);
  button(doc.querySelector('[aria-label="Example category"]'), "Payments").click();
  await settle();
  const cards = [...doc.querySelectorAll(".example-card")];
  assert.ok(cards.length > 0 && cards.length < all);
  assert.ok(cards.every(c => /Payments/.test(text(c.querySelector(".example-cat")))));
  dom.window.close();
});

test("replacing edited content asks first", async () => {
  const {dom, doc, window} = await boot("#/ingest");
  type(window, doc.getElementById("ingest-chunk-1"), "my own draft");
  doc.querySelector(".example-card").click();
  await settle();
  assert.match(text(doc.querySelector(".modal")), /Replace your content\?/);
  button(doc.querySelector(".modal"), "Keep my content").click();
  await settle();
  assert.equal(doc.getElementById("ingest-chunk-1").value, "my own draft");
  dom.window.close();
});

test("a gate check reads as a preview with its coverage, per chunk", async () => {
  const {dom, doc, window, calls} = await boot("#/ingest", {"POST /ingest/gate": GATE_EMAIL});
  type(window, doc.getElementById("ingest-chunk-1"), "reply to jordan.lee@example.com");
  runButton(doc).click();
  await settle();
  const post = posts(calls).find(c => c.path === "/ingest/gate");
  assert.deepEqual(post.body.chunks.map(c => [c.id, c.text]), [["chunk-1", "reply to jordan.lee@example.com"]]);
  assert.equal(post.body.block_severity, "high");
  const result = readable(doc.querySelector(".ingest-result"));
  assert.match(result, /Would block 1 of 1 chunk at High or above/);
  assert.match(result, /would block/);
  assert.match(result, /jo\*+om/, "the masked value, not the raw one");
  assert.match(result, /Coverage degraded: .*not a complete check/);
  assert.doesNotMatch(result, /blocked before embedding|PII density|all chunks passed/i);
  dom.window.close();
});

test("a result goes stale when its input changes, and survives a task switch", async () => {
  const {dom, doc, window} = await boot("#/ingest", {"POST /ingest/gate": GATE_EMAIL});
  type(window, doc.getElementById("ingest-chunk-1"), "reply to jordan.lee@example.com");
  runButton(doc).click();
  await settle();
  type(window, doc.getElementById("ingest-chunk-1"), "reply to someone else");
  assert.match(readable(doc.querySelector(".ingest-result")), /changed after this result/);
  doc.getElementById("ingest-tab-redact").click();
  await settle();
  assert.equal(doc.getElementById("ingest-chunk-1").value, "reply to someone else", "input is kept");
  assert.match(window.location.hash, /task=redact/);
  assert.ok(doc.getElementById("ingest-preview"), "only redaction settings are shown");
  assert.equal(doc.getElementById("ingest-severity"), null);
  dom.window.close();
});

test("boundary checks need two chunks, and an over-long chunk is refused, never cut", async () => {
  const {dom, doc, window, calls} = await boot("#/ingest?task=boundaries");
  type(window, doc.getElementById("ingest-chunk-1"), "only one chunk");
  runButton(doc).click();
  await settle();
  assert.match(text(doc.querySelector(".ingest-problems")), /at least two consecutive chunks/);
  const long = "x".repeat(5003);
  type(window, doc.getElementById("ingest-chunk-1"), long);
  runButton(doc).click();
  await settle();
  assert.match(text(doc.querySelector(".ingest-problems")), /3 characters over the 5,000-character limit/);
  assert.equal(doc.getElementById("ingest-chunk-1").value.length, 5003, "nothing truncated");
  assert.equal(posts(calls).length, 0);
  dom.window.close();
});

test("a failed check keeps the input and offers a retry, with no zero result", async () => {
  const {dom, doc, window} = await boot("#/ingest", {
    "POST /ingest/gate": {status: 503, detail: "detection unavailable: NLP model required"},
  });
  type(window, doc.getElementById("ingest-chunk-1"), "anything");
  runButton(doc).click();
  await settle();
  const result = doc.querySelector(".ingest-result");
  assert.match(text(result), /did not run: detection unavailable/);
  assert.ok(button(result, "Retry"));
  assert.doesNotMatch(text(result), /No blocking findings/);
  assert.equal(doc.getElementById("ingest-chunk-1").value, "anything");
  dom.window.close();
});

test("a run cannot be submitted twice while it is in flight", async () => {
  let release;
  const pending = new Promise(r => { release = r; });
  const {dom, doc, window, calls} = await boot("#/ingest", {
    "POST /ingest/gate": () => pending.then(() => GATE_EMAIL),
  });
  type(window, doc.getElementById("ingest-chunk-1"), "reply to jordan.lee@example.com");
  const run = runButton(doc);
  run.click();
  run.click();
  await settle();
  assert.equal(run.disabled, true);
  release();
  await settle();
  assert.equal(posts(calls).filter(c => c.path === "/ingest/gate").length, 1);
  assert.equal(run.disabled, false);
  dom.window.close();
});

test("counts-only redaction says so, and an absent coverage record is unknown", async () => {
  const {dom, doc, window} = await boot("#/ingest?task=redact", {"POST /ingest/redact": {spans_redacted: 2}});
  type(window, doc.getElementById("ingest-chunk-1"), "a@example.com b@example.com");
  doc.getElementById("ingest-preview").click();
  runButton(doc).click();
  await settle();
  const result = readable(doc.querySelector(".ingest-result"));
  assert.match(result, /2 matches replaced/);
  assert.match(result, /Counts only/);
  assert.match(result, /not verified anonymisation/);
  assert.match(result, /which detectors ran, so what this result covers is unknown/);
  dom.window.close();
});

test("no finding reads as no finding at this threshold, not as safe", async () => {
  const {dom, doc, window} = await boot("#/ingest", {
    "POST /ingest/gate": {total: 1, blocked: 0, allowed: 1, blocked_chunk_ids: [], findings: [],
                          detection: {status: "disabled", nlp_loaded: false, regex_detector_count: 130}},
  });
  type(window, doc.getElementById("ingest-chunk-1"), "Your refund has been processed.");
  runButton(doc).click();
  await settle();
  const result = readable(doc.querySelector(".ingest-result"));
  assert.match(result, /No blocking findings at this threshold/);
  assert.match(result, /not every kind of sensitive content/);
  assert.doesNotMatch(result, /\bsafe\b|all chunks passed/i);
  dom.window.close();
});
