import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// Criteria and evidence read as words, not identifiers. Each test boots the
// shipped console in a real DOM against a stubbed API.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");

const BASE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"}]},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
  "/version": {approvals: {separation_of_duties: "required"}},
  "/healthz": {status: "ok", stores: 1},
};

async function boot(hash, responses = {}) {
  const dom = new JSDOM(`<!doctype html><html lang="en"><body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  const calls = [];
  const all = {...BASE, ...responses};
  window.fetch = async (path, opts = {}) => {
    calls.push({path, method: opts.method || "GET", body: opts.body ? JSON.parse(opts.body) : undefined});
    const key = `${opts.method || "GET"} ${path.split("?")[0]}`;
    const value = all[key] ?? all[path] ?? all[path.split("?")[0]] ?? {};
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
  return {dom, window, doc: window.document, calls};
}

const settle = () => new Promise(r => setTimeout(r, 30));
const button = (root, text) => [...root.querySelectorAll("button")]
  .find(b => b.textContent.replace(/\s+/g, " ").trim() === text);
const submit = (window, dialog) =>
  dialog.querySelector("form").dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));

const PACK = {
  pack: {pack_version: "d3", criteria: 1, regulatory_review: null, frameworks: ["GDPR"]},
  criteria: [{criterion_id: "GDPR-ERASURE-01", framework: "GDPR",
              title: "Erasure requests reach embeddings, and the result can be verified",
              paraphrase: "An erasure request reaches personal data held in embeddings, and the outcome is verifiable.",
              sources: [{citation: "Art. 17", section: "Art. 17"}],
              technical_checks: ["erasure_verification"],
              manual_evidence: ["erasure_procedure", "backup_retention_statement"],
              fallback_evidence: [], applicability_questions: ["processes_personal_data_of_eu_subjects"],
              limitations: ["Deletion from the live index is not deletion from backups."]}],
  evidence_types: {
    erasure_procedure: {label: "Erasure procedure", what: "The documented steps an erasure request follows.",
                        examples: ["A data-subject request procedure with a step for deleting embeddings"],
                        reviewer_checks: "It reaches the vector store explicitly."},
    backup_retention_statement: {label: "Backup retention statement", what: "How long backups keep data.",
                                 examples: ["The snapshot retention setting"], reviewer_checks: "A concrete period."},
  },
  applicability_questions: {processes_personal_data_of_eu_subjects: {
    question: "Does the store hold personal data of people in the EU?", help: "GDPR applies."}},
  reviewer_checklist: ["Right document: it is the kind of artifact the requirement asks for."],
  specification_notes: {}, terms: {embeddings: "The vectors a model computes from text."},
};

const ASSESSMENT = {
  criterion_id: "GDPR-ERASURE-01", framework: "GDPR", status: "evidence_needed",
  applicability: {processes_personal_data_of_eu_subjects: "yes"}, applicability_status: "confirmed",
  technical_result: "passed", technical_coverage: "complete", evidence_sufficiency: "rejected",
  missing_evidence: ["erasure_procedure", "backup_retention_statement"],
  observations: [], gaps: ["Required evidence is missing or rejected: erasure_procedure"],
  limitations: [], reviewer: null, rationale: "Applicable, but the required manual evidence is not accepted.",
  exceptions: [{id: "e1", status: "expired", expires_at: "2026-01-01T00:00:00+00:00", rationale: "Interim."}],
  evidence_reviews: [
    {id: "rev-1", artifact_id: "ev-ropa", requirement: "erasure_procedure", state: "rejected", accepted: false,
     reviewer: "dpo@example.test", reason: "Does not list the vector store."},
    {id: "rev-2", artifact_id: "ev-baa", requirement: "baa", state: "accepted", accepted: true,
     reviewer: "dpo@example.test", reason: "Executed."}],
};

const CRITERIA = {
  "/compliance/criteria": PACK,
  "POST /stores/prod/criteria": {audit_id: "audit-1", assessments: [ASSESSMENT],
                                 summary: {by_status: {evidence_needed: 1}, note: "Not a compliance score."},
                                 coverage: {}, inputs: {notes: []}},
};

test("a criterion row leads with its title and what it asks; the id is small", async () => {
  const {dom, doc} = await boot("#/criteria?store=prod", CRITERIA);
  const row = doc.querySelector('.crit-row[data-criterion="GDPR-ERASURE-01"]');
  assert.equal(row.querySelector(".crit-row-title").textContent,
               "Erasure requests reach embeddings, and the result can be verified");
  assert.match(row.querySelector(".crit-row-asks").textContent, /reaches personal data held in embeddings/);
  assert.equal(row.querySelector(".crit-row-id").textContent, "GDPR-ERASURE-01");
  assert.match(row.querySelector(".crit-row-cite").textContent, /GDPR\s*Art\. 17/);
  assert.match(row.querySelector(".crit-row-next").textContent, /Replace rejected: Erasure procedure/);
  dom.window.close();
});

test("a row opens in place, into the address, and closes out of it", async () => {
  const {dom, doc, window} = await boot("#/criteria?store=prod", CRITERIA);
  const head = doc.querySelector(".crit-row-head");
  const detail = doc.getElementById(head.getAttribute("aria-controls"));
  assert.equal(head.getAttribute("aria-expanded"), "false");
  assert.ok(detail.hidden);
  head.click();
  assert.equal(head.getAttribute("aria-expanded"), "true");
  assert.ok(!detail.hidden);
  assert.match(window.location.hash, /criterion=GDPR-ERASURE-01/);
  head.click();
  assert.doesNotMatch(window.location.hash, /criterion=/);
  dom.window.close();
});

test("a deep link opens that criterion", async () => {
  const {dom, doc} = await boot("#/criteria?store=prod&criterion=GDPR-ERASURE-01", CRITERIA);
  assert.equal(doc.querySelector(".crit-row-head").getAttribute("aria-expanded"), "true");
  dom.window.close();
});

test("the detail says how it is judged and what evidence would satisfy it, with reasons", async () => {
  const {dom, doc} = await boot("#/criteria?store=prod", CRITERIA);
  const text = doc.querySelector(".crit-detail").textContent;
  assert.match(text, /How it is judged/);
  assert.match(text, /Does the store hold personal data of people in the EU\?/, "questions are sentences");
  assert.match(text, /For example: A data-subject request procedure with a step for deleting embeddings/);
  assert.match(text, /Rejected by dpo@example\.test.*Does not list the vector store/s, "the reason is shown");
  assert.match(text, /counts toward nothing here/, "a review under another requirement does not count");
  assert.match(text, /Exception expired\s*Ended .*open again/s, "an expired exception is visible");
  assert.match(text, /Rejected/, "the state is never softened");
  assert.match(text, /embeddings\s*The vectors a model computes/, "terms are explained");
  dom.window.close();
});

test("status chips filter the list and never add up to a score", async () => {
  const {dom, doc, window} = await boot("#/criteria?store=prod", CRITERIA);
  const chips = [...doc.querySelectorAll(".crit-chip")];
  assert.equal(chips.length, 6, "every status is shown, zero included");
  assert.doesNotMatch(doc.getElementById("content").textContent, /\d+%/);
  chips.find(c => c.dataset.status === "satisfied_for_scope").click();
  assert.match(window.location.hash, /status=satisfied_for_scope/);
  assert.match(doc.querySelector(".crit-rows").textContent, /No criterion matches these filters/);
  dom.window.close();
});

test("without a store, criteria still explain themselves and say nothing is evaluated", async () => {
  const {dom, doc, calls} = await boot("#/criteria", {"/compliance/criteria": PACK});
  const row = doc.querySelector(".crit-row");
  assert.match(row.textContent, /not evaluated/);
  assert.match(row.textContent, /Choose a store to see where it stands/);
  assert.match(doc.querySelector(".crit-detail").textContent, /Erasure procedure/);
  assert.equal(calls.filter(c => c.path.endsWith("/criteria") && c.method === "POST").length, 0);
  dom.window.close();
});

// ------------------------------------------------------------------ evidence ---

const EVIDENCE = {
  "/compliance/criteria": PACK,
  "/compliance/evidence": {note: "n", artifacts: [
    {id: "ev-ropa", title: "Record of processing activities", state: "available", usable: true,
     content_hash: "a".repeat(64), scope: "prod", period_start: "2026-01-01", period_end: "2026-12-31"},
    {id: "ev-new", title: "Access policy v4", state: "collected", usable: false, content_hash: "b".repeat(64),
     scope: "prod"}],
    lifecycle: {artifact_states: {
      available: {meaning: "Fit to be reviewed as evidence for a criterion.", next: ["superseded", "revoked"]},
      collected: {meaning: "Registered, not yet checked.", next: ["integrity_checked", "revoked"]}},
      review_states: {rejected: {meaning: "m", next: ["under_review", "submitted"]},
                      submitted: {meaning: "m", next: ["accepted", "rejected", "needs_clarification"]}}}},
  "/compliance/reviews": {reviews: [
    {id: "rev-1", artifact_id: "ev-ropa", criterion_id: "GDPR-ERASURE-01", requirement: "erasure_procedure",
     state: "submitted", accepted: false, reviewer: "", reason: "", scope: "prod", period: "2026"}]},
  "POST /compliance/reviews/rev-1": {id: "rev-1", state: "rejected"},
  "POST /compliance/evidence": {id: "ev-9"},
  "POST /compliance/evidence/ev-new/state": {id: "ev-new", state: "integrity_checked"},
};

test("the evidence screen explains artifact against review, and superseded, up front", async () => {
  const {dom, doc} = await boot("#/evidence", EVIDENCE);
  const explain = doc.querySelector(".ev-explain").textContent;
  assert.match(explain, /Document/);
  assert.match(explain, /Review/);
  assert.match(explain, /accepted as the vendor contract for one criterion\s+and rejected/);
  assert.match(explain, /Replaced/);
  assert.match(explain, /What a reviewer checks/);
  dom.window.close();
});

test("an artifact opens in place with its lifecycle moves in words", async () => {
  const {dom, doc, window, calls} = await boot("#/evidence", EVIDENCE);
  const row = doc.querySelector('.ev-row[data-artifact="ev-new"]');
  row.querySelector(".ev-row-head").click();
  assert.match(window.location.hash, /artifact=ev-new/);
  assert.match(row.textContent, /Registered, not yet checked/);
  button(row, "Confirm integrity").click();
  const dialog = doc.querySelector('[role="dialog"]');
  assert.match(dialog.textContent, /compared the file's SHA-256/);
  submit(window, dialog);
  await settle();
  const post = calls.find(c => c.path === "/compliance/evidence/ev-new/state");
  assert.deepEqual(post.body, {to_state: "integrity_checked", reason: ""});
  dom.window.close();
});

test("a review decision shows what to check and refuses to record without a reason", async () => {
  const {dom, doc, window, calls} = await boot("#/evidence?tab=reviews", EVIDENCE);
  button(doc.querySelector('.ev-panel[data-tab="reviews"]'), "Decide").click();
  const dialog = doc.querySelector('[role="dialog"]');
  assert.match(dialog.textContent, /Check before deciding/);
  assert.match(dialog.textContent, /It reaches the vector store explicitly/, "the requirement's own check");
  assert.match(dialog.textContent, /Erasure requests reach embeddings/, "the criterion by its title");
  const [decision] = dialog.querySelectorAll("select");
  decision.value = "rejected";
  submit(window, dialog);
  await settle();
  assert.equal(calls.filter(c => c.path === "/compliance/reviews/rev-1").length, 0);
  assert.match(dialog.querySelector(".field-error:not([hidden])").textContent, /Say why/);
  dialog.querySelector("textarea").value = "Does not list the vector store as a processing location.";
  submit(window, dialog);
  await settle();
  const post = calls.find(c => c.path === "/compliance/reviews/rev-1");
  assert.deepEqual(post.body, {to_state: "rejected",
                               reason: "Does not list the vector store as a processing location."});
  dom.window.close();
});

test("registering validates the hash and the period beside the fields", async () => {
  const {dom, doc, window, calls} = await boot("#/evidence", EVIDENCE);
  button(doc.querySelector(".page-head"), "Add document").click();
  await settle();
  const dialog = doc.querySelector('[role="dialog"]');
  assert.match(dialog.textContent, /Whether it evidences an obligation is a separate review/);
  const inputs = dialog.querySelectorAll("input");
  inputs[0].value = "Signed BAA with Acme Vector Cloud, 2026";
  const hash = [...inputs].find(i => /hex/.test(i.getAttribute("placeholder") || ""));
  hash.value = "not-a-hash";
  submit(window, dialog);
  await settle();
  assert.equal(calls.filter(c => c.method === "POST" && c.path === "/compliance/evidence").length, 0);
  assert.equal(hash.getAttribute("aria-invalid"), "true");
  assert.match(dialog.textContent, /64 hexadecimal characters/);
  hash.value = "c".repeat(64);
  submit(window, dialog);
  await settle();
  const post = calls.find(c => c.method === "POST" && c.path === "/compliance/evidence");
  assert.equal(post.body.content_hash, "c".repeat(64));
  assert.equal(post.body.supersedes, null);
  dom.window.close();
});

test("the isolation check says whether it was exhaustive or sampled, with its counts", async () => {
  const obs = (method, extra = {}) => ({check: "tenant_isolation", collection: "docs", outcome: "passed",
    coverage: {status: method === "sampled" ? "partial" : "complete", method, cross_tenant_queries: 1240,
               bleeds: 0, ...extra}});
  const withObs = {...CRITERIA, "POST /stores/prod/criteria": {...CRITERIA["POST /stores/prod/criteria"],
    assessments: [{...ASSESSMENT, observations: [obs("exhaustive"), {...obs("sampled"), collection: "big"}]}]}};
  const {dom, doc} = await boot("#/criteria?store=prod", withObs);
  const text = doc.querySelector(".crit-detail").textContent;
  assert.match(text, /Isolation \(docs\): exhaustive 1,?240 cross-tenant queries · 0 bleeds/);
  assert.match(text, /Isolation \(big\): sampled, partial/, "sampling is never shown as complete");
  dom.window.close();
});
