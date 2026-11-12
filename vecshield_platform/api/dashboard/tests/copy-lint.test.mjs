import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// Copy lint for the Compliance screens (enterprise-readiness plan §4B.2,
// phases C-1 and C-2). It reads the copy tables statically, then renders every
// compliance view in a real DOM against stubbed data that covers every status
// the server can send, and fails on:
//
//   - words that claim a legal verdict: compliant, non-compliant, certify /
//     certified / certification, guarantee ("certificate", as in TLS, is not);
//   - percentages anywhere in a compliance view;
//   - raw snake_case identifiers in readable text (code, pre, kbd and .mono
//     are for identifiers and are skipped);
//   - "frozen", "what-if" and "execute" in readable copy;
//   - a green (sev-ok) chip labelled satisfied or met.
//
// It also reports a reading-level score for the primary copy. That one is
// advisory (decision D-C7): it is logged, never failed on.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");

const BANNED = /\bcompliant\b|non-compliant|certif(?!icate)|guarantee/i;
const PERCENT = /\d\s*%/;
const SNAKE = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/;
const JARGON = /\bfrozen\b|what-if|\bexecut/i;
const GREEN_MET = /satisf|\bmet\b/i;

// ------------------------------------------------------------------ stubs ---

const NOW = Date.now();
const future = days => new Date(NOW + days * 86400000).toISOString();
const past = days => new Date(NOW - days * 86400000).toISOString();

const PACK = {
  pack: {pack_version: "draft-4", criteria: 8, lifecycle: "draft", regulatory_review: null,
         frameworks: ["GDPR", "HIPAA"],
         note: "Authored alongside the detection rules. Criteria cover only obligations a vector-store assessment can observe."},
  criteria: [
    {criterion_id: "HIPAA-A", framework: "HIPAA", title: "Only the right people can read the store",
     paraphrase: "Access to ePHI in the store is limited to those who need it.", specification: "addressable",
     sources: [{id: "s1", section: "45 CFR 164.312(a)(1)", issuer: "HHS", kind: "regulation", status: "in_force",
                lifecycle: "draft"}],
     technical_checks: ["tenant_isolation"], manual_evidence: ["access_review_record"],
     fallback_evidence: ["encryption_at_rest_statement"], applicability_questions: ["handles_ephi"],
     limitations: ["A probe samples."]},
    {criterion_id: "HIPAA-B", framework: "HIPAA", title: "Disposal of ePHI on retired media",
     paraphrase: "Retired media holding ePHI is disposed of.", specification: "required",
     sources: [{id: "s2", section: "45 CFR 164.310(d)(2)", kind: "rule", status: "in_force"}],
     technical_checks: [], manual_evidence: ["disposal_procedure"], applicability_questions: ["handles_ephi", "covered_entity"]},
    {criterion_id: "GDPR-A", framework: "GDPR", title: "Erasure reaches embeddings",
     paraphrase: "An erasure request reaches personal data held in embeddings.",
     sources: [{id: "s3", section: "Art. 17", kind: "regulation", status: "in_force", legal_status: "in_force"}],
     technical_checks: ["erasure_verification"], manual_evidence: ["erasure_procedure"],
     applicability_questions: ["processes_eu_personal_data"]},
    {criterion_id: "GDPR-B", framework: "GDPR", title: "Security of processing", specification: "risk_based",
     paraphrase: "Appropriate security for personal data in the store.",
     sources: [{id: "s4", section: "Art. 32", kind: "regulation", status: "future_effective",
                legal_status: "future_effective"}],
     technical_checks: ["transport_encryption"], manual_evidence: [], applicability_questions: []},
  ],
  evidence_types: {
    access_review_record: {label: "Access review record", what: "A dated record that access was checked.",
                           examples: ["A quarterly access review"], reviewer_checks: "It names this store."},
    encryption_at_rest_statement: {label: "Encryption at rest statement", what: "How data at rest is encrypted.",
                                   examples: [], reviewer_checks: ""},
    disposal_procedure: {label: "Disposal procedure", what: "How retired media is wiped.", examples: [], reviewer_checks: ""},
    erasure_procedure: {label: "Erasure procedure", what: "The steps an erasure request follows.", examples: [], reviewer_checks: ""},
  },
  applicability_questions: {
    handles_ephi: {question: "Does the store hold electronic protected health information?", help: "HIPAA applies to ePHI."},
    covered_entity: {question: "Are you a covered entity or a business associate?", help: ""},
    processes_eu_personal_data: {question: "Does the store hold personal data of people in the EU?", help: ""},
  },
  reviewer_checklist: ["Right document: it is the kind of document the criterion needs."],
  specification_notes: {addressable: "An addressable safeguard may be replaced by a documented alternative."},
  terms: {},
};

const obs = (check, outcome, status, extra = {}) =>
  ({check, collection: "docs", outcome, coverage: {status, ...extra}, reason: ""});

const base = {framework: "HIPAA", observations: [], gaps: [], limitations: [], reviewer: null,
              evidence_reviews: [], exceptions: [], missing_evidence: [], applicability: {},
              technical_coverage: "complete"};

// Every criterion status, technical result, coverage, evidence status,
// applicability status, exception status and review state at least once.
const ASSESSMENTS = [
  {...base, criterion_id: "HIPAA-A", status: "not_assessed", applicability_status: "requires_confirmation",
   applicability: {handles_ephi: "requires_confirmation"}, technical_result: "not_run", technical_coverage: "not_observable",
   evidence_sufficiency: "missing", missing_evidence: ["access_review_record", "encryption_at_rest_statement"],
   fallback_required: ["encryption_at_rest_statement"], addressable_determination: "missing",
   observations: [obs("tenant_isolation", "not_run", "unknown"), obs("tenant_isolation", "skipped", "not_observable")],
   rationale: "Not every question is answered yet."},
  {...base, criterion_id: "HIPAA-B", status: "not_assessed", applicability_status: "excluded",
   applicability: {handles_ephi: "no", covered_entity: "yes"}, technical_result: "not_run",
   technical_coverage: "not_applicable", evidence_sufficiency: "not_required"},
  {...base, criterion_id: "GDPR-A", framework: "GDPR", status: "evidence_needed", applicability_status: "confirmed",
   applicability: {processes_eu_personal_data: "yes"}, technical_result: "passed", evidence_sufficiency: "rejected",
   missing_evidence: ["erasure_procedure"],
   observations: [obs("erasure_verification", "passed", "complete")],
   evidence_reviews: [{id: "r1", artifact_id: "ev-1", requirement: "erasure_procedure", state: "rejected",
                       accepted: false, reviewer: "dana", reason: "Does not name the store."},
                      {id: "r9", artifact_id: "ev-2", requirement: "disposal_procedure", state: "needs_clarification",
                       accepted: false, reviewer: "dana", reason: "Which store?"}],
   exceptions: [{id: "x1", status: "expired", expires_at: past(3), rationale: "Interim."},
                {id: "x2", status: "revoked", expires_at: future(3), rationale: "Withdrawn."}]},
  {...base, criterion_id: "GDPR-B", framework: "GDPR", status: "under_review", applicability_status: "confirmed",
   technical_result: "inconclusive", technical_coverage: "partial", evidence_sufficiency: "submitted",
   risk_determination: "submitted",
   observations: [obs("transport_encryption", "inconclusive", "partial")],
   exceptions: [{id: "x3", status: "pending_approval", expires_at: future(20), rationale: "Fix in flight."}]},
];

// The same criteria again under the other four outcomes, as extra rows.
const MORE = [
  {...base, criterion_id: "HIPAA-C", status: "satisfied_for_scope", applicability_status: "confirmed",
   technical_result: "passed", evidence_sufficiency: "accepted",
   reviewer: {reviewer: "dana", conclusion: "satisfied", decided_at: past(1)},
   stored_decision: {reviewer: "dana", conclusion: "satisfied", decided_at: past(1), audit_id: "audit-1",
                     applied: true, rationale: "Reviewed the Q3 access review.", carried_forward: true},
   evidence_reviews: [{id: "r2", artifact_id: "ev-3", requirement: "access_review_record", state: "accepted",
                       accepted: true, reviewer: "dana", reason: "Signed and in date."}]},
  {...base, criterion_id: "HIPAA-D", status: "gap_identified", applicability_status: "confirmed",
   technical_result: "failed", technical_coverage: "does_not_arise", evidence_sufficiency: "not_required",
   observations: [obs("tenant_isolation", "failed", "complete", {method: "sampled", cross_tenant_queries: 40, bleeds: 2}),
                  obs("tenant_isolation", "unsupported", "unknown")],
   exceptions: [{id: "x4", status: "active", expires_at: future(10), rationale: "Compensating control."}]},
  {...base, criterion_id: "HIPAA-E", status: "gap_identified", applicability_status: "confirmed",
   technical_result: "passed", evidence_sufficiency: "accepted",
   reviewer: {reviewer: "sam", conclusion: "gap", decided_at: past(2)}, decision_source: "what_if",
   what_if_ignored: true,
   stored_decision: {reviewer: "lee", conclusion: "not_applicable", decided_at: past(9), audit_id: "audit-0",
                     applied: false, not_applied_reason: "made_against_later_audit"}},
  {...base, criterion_id: "HIPAA-F", status: "not_applicable", applicability_status: "excluded",
   technical_result: "not_run", evidence_sufficiency: "not_required",
   reviewer: {reviewer: "sam", conclusion: "not_applicable", decided_at: past(2)}},
];

const PACK_ALL = {...PACK, criteria: [...PACK.criteria,
  ...["HIPAA-C", "HIPAA-D", "HIPAA-E", "HIPAA-F"].map(id => ({...PACK.criteria[0], criterion_id: id,
    title: `Only the right people can read the store (${id.slice(-1)})`}))]};

const ARTIFACT_STATES = ["collected", "integrity_checked", "available", "quarantined", "superseded", "expired", "revoked"];
const REVIEW_STATES = ["requested", "submitted", "under_review", "accepted", "rejected", "needs_clarification"];

const LIFECYCLE = {
  artifact_states: Object.fromEntries(ARTIFACT_STATES.map(s => [s, {meaning: "What this state means.",
    next: s === "revoked" ? [] : ["revoked", "quarantined"], usable: s === "available"}])),
  review_states: Object.fromEntries(REVIEW_STATES.map(s => [s, {meaning: "m", next: ["accepted", "rejected", "needs_clarification"]}])),
};

const RESPONSES = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"}]},
  "/admin/policies": {policies: [
    {id: "p1", name: "PHI in embeddings", description: "Flags ePHI.", enabled: true, action: "tag_phi",
     severity: "high", template_id: "hipaa-phi", scope_store: "prod", when: {min_severity: "high"}}]},
  "/admin/policy-templates": {templates: [
    {id: "hipaa-phi", name: "PHI in embeddings", description: "Flags ePHI.", regulation: "HIPAA",
     severity: "high", action: "tag_phi", default_scope: "collection", when: {min_severity: "high"},
     applicability: {handles_ephi: "requires_confirmation"},
     attribution: {source_text: "45 CFR 164.312", reviewed: false,
                   sources: [{id: "s1", section: "45 CFR 164.312", lifecycle: "draft", redistributable: true}]},
     evidence: {detects: "ePHI in chunk text.", does_not_establish: "That access was authorised.",
                confidence: "possible", requires_reviewer_decision: true, limitations: []}}]},
  "/version": {approvals: {separation_of_duties: "required"}},
  "/healthz": {status: "ok", stores: 1},
  "/compliance/criteria": PACK_ALL,
  "/compliance/hipaa": {pack: {not_covered: [{topic: "Workforce training", section: "45 CFR 164.308(a)(5)",
                                              reason: "Training lives in an HR system."}]}},
  "/compliance/crypto-basis": {basis: []},
  "POST /stores/prod/criteria": {audit_id: "audit-1", assessments: [...ASSESSMENTS, ...MORE],
    summary: {note: "Status counts describe this assessment and its documents. They are not a score."},
    coverage: {status: "partial", checks_expected: 2, checks_complete: 1}, inputs: {notes: []}},
  "GET /stores/prod/applicability": {store_id: "prod",
    answers: {handles_ephi: {answer: "yes", answered_by: "lee", answered_at: past(1)},
              covered_entity: {answer: "no", answered_by: "lee", answered_at: past(1)}},
    questions: [{question: "covered_entity", criteria: ["HIPAA-B"], answer: "no", answered: true},
                {question: "handles_ephi", criteria: ["HIPAA-A", "HIPAA-B"], answer: "yes", answered: true},
                {question: "processes_eu_personal_data", criteria: ["GDPR-A"], answer: "requires_confirmation",
                 answered: false}]},
  "/compliance/evidence": {artifacts: ARTIFACT_STATES.map((s, i) => ({id: `ev-${i + 1}`, title: `Document ${i + 1}`,
    state: s, usable: s === "available", content_hash: s === "collected" ? null : "a".repeat(64), scope: "prod",
    period_start: "2026-07-01", period_end: "2026-09-30"})), lifecycle: LIFECYCLE},
  "/compliance/reviews": {reviews: REVIEW_STATES.map((s, i) => ({id: `r${i + 1}`, artifact_id: `ev-${i + 1}`,
    criterion_id: "GDPR-A", requirement: "erasure_procedure", state: s, accepted: s === "accepted",
    reviewer: "dana", reason: "A reason.", scope: "prod", period: "2026-Q3"}))},
  "/compliance/exceptions": {pending_approval: 1, active: 1, expired: 1,
    note: "An exception accepts a gap for now. It does not close the gap.",
    exceptions: [
      {id: "x1", criterion_id: "HIPAA-A", scope: "prod", status: "pending_approval", expires_at: future(20),
       rationale: "Fix in flight.", requested_by: "bob"},
      {id: "x2", criterion_id: "HIPAA-D", scope: "prod", status: "active", expires_at: future(10),
       rationale: "Compensating control.", requested_by: "bob", approved_by: "dana",
       approval_reason: "Segmentation covers it until the fix lands."},
      {id: "x3", criterion_id: "GDPR-A", scope: "prod", status: "expired", expires_at: past(3),
       rationale: "Interim.", requested_by: "bob", approved_by: "dana"},
      {id: "x4", criterion_id: "GDPR-B", scope: "prod", status: "revoked", expires_at: future(3),
       rationale: "Withdrawn.", requested_by: "bob", approved_by: "dana", revoked_at: past(1)}]},
  "/admin/dsar": {dsars: ["pending", "scanned", "executed", "awaiting_verification", "partial_error"].map((s, i) => ({
    id: `d${i}`, subject: `person${i}@example.com`, status: s, requested_at: past(i + 1),
    total_chunks_found: i ? 2 : 0, total_chunks_deleted: s === "executed" ? 2 : 0, stores_scanned: 1,
    stores_with_errors: s === "partial_error" ? 1 : 0, created_by: "bob"}))},
  "/admin/dsar/d1": {id: "d1", subject: "person1@example.com", status: "scanned", total_chunks_found: 2,
    requested_at: past(2), created_by: "bob",
    stores: [{store_id: "prod", chunks_found: 2, coverage_complete: true,
              impact: {matches: [{collection: "docs", chunk_id: "c1"}, {collection: "docs", chunk_id: "c2"}]}}]},
};

async function render(hash) {
  const dom = new JSDOM(`<!doctype html><html lang="en"><body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  window.fetch = async (path, opts = {}) => {
    const key = `${opts.method || "GET"} ${path.split("?")[0]}`;
    const value = RESPONSES[key] ?? RESPONSES[path] ?? RESPONSES[path.split("?")[0]] ?? {};
    return {ok: true, status: 200, headers: {get: () => "application/json"},
            json: async () => value, text: async () => JSON.stringify(value)};
  };
  window.eval(shell);
  window.eval("buildShell()");
  await window.eval("route()");
  await settle();
  return {dom, window, doc: window.document};
}

const settle = () => new Promise(r => setTimeout(r, 30));

// Readable text: every text node except inside code, pre, kbd and .mono,
// which are for identifiers. Hidden text counts: it is one click away.
function readable(root) {
  const out = [];
  const skip = el => ["CODE", "PRE", "KBD", "SCRIPT", "STYLE"].includes(el.tagName) ||
    el.classList?.contains("mono") || el.classList?.contains("sr-skip-lint");
  const walk = node => {
    for (const child of node.childNodes) {
      if (child.nodeType === 3) {
        const text = child.textContent.replace(/\s+/g, " ").trim();
        if (text) out.push(text);
      } else if (child.nodeType === 1 && !skip(child)) {
        walk(child);
      }
    }
  };
  walk(root);
  return out;
}

function lint(lines, where) {
  const problems = [];
  for (const line of lines) {
    if (BANNED.test(line)) problems.push(`${where}: verdict word in “${line}”`);
    if (PERCENT.test(line)) problems.push(`${where}: percentage in “${line}”`);
    if (SNAKE.test(line)) problems.push(`${where}: raw identifier “${line.match(SNAKE)[0]}” in “${line}”`);
    if (JARGON.test(line)) problems.push(`${where}: specialist word in “${line}”`);
  }
  return problems;
}

function greenMet(root, where) {
  return [...root.querySelectorAll(".badge.sev-ok")]
    .filter(chip => GREEN_MET.test(chip.textContent))
    .map(chip => `${where}: green chip “${chip.textContent.trim()}” reads as compliance`);
}

// Opens every inline form on every criterion, so their copy is linted too.
async function openInlineForms(doc) {
  for (const card of doc.querySelectorAll(".crit-row")) {
    for (const opener of card.querySelectorAll("button[data-form]")) {
      opener.click();
      await settle();
      const form = card.querySelector(".inline-form");
      if (form) card.dataset.lintForms = `${card.dataset.lintForms || ""}\n${readable(form).join("\n")}`;
    }
  }
}

// ------------------------------------------------------------ copy tables ---

function strings(value, out = []) {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) value.forEach(v => strings(v, out));
  else if (value && typeof value === "object") Object.values(value).forEach(v => strings(v, out));
  return out;
}

test("the compliance copy tables use no verdict words, percentages, identifiers or jargon", async () => {
  const {dom, window} = await render("#/docs");
  const copy = window.eval("COMPLIANCE_COPY");
  const terms = window.eval("COMPLIANCE_TERMS");
  const all = [...strings(copy), ...strings(terms)];
  assert.ok(all.length > 150, `expected the full table, read ${all.length} strings`);
  // Template slots ({name}) are not identifiers.
  const problems = lint(all.map(s => s.replace(/\{\w+\}/g, "X")), "COMPLIANCE_COPY");
  assert.deepEqual(problems, []);
  dom.window.close();
});

test("no label table pairs a green tone with satisfied or met", async () => {
  const {dom, window} = await render("#/docs");
  const labels = window.eval("COMPLIANCE_COPY.labels");
  const bad = [];
  for (const [group, entries] of Object.entries(labels)) {
    for (const [key, meta] of Object.entries(entries)) {
      if (meta.tone === "ok" && GREEN_MET.test(`${meta.text} ${meta.chip || ""}`)) bad.push(`${group}.${key}`);
    }
  }
  assert.deepEqual(bad, []);
  // D-C1 and D-C2: the reviewer's "met" is neutral, named as the reviewer's.
  const met = labels.criterionStatus.satisfied_for_scope;
  assert.equal(met.text, "Met for this store (reviewer)");
  assert.equal(met.tone, "info");
  assert.equal(met.glyph, "check");
  dom.window.close();
});

test("every glossary term is defined exactly once", async () => {
  const {dom, window} = await render("#/docs");
  const terms = window.eval("COMPLIANCE_TERMS");
  const names = Object.values(terms).map(([name]) => name.toLowerCase());
  assert.equal(new Set(names).size, names.length, "a term is defined twice");
  for (const expected of ["framework", "obligation", "criterion", "control", "template", "policy", "applies?",
                          "check result", "evidence status", "reviewer's decision", "document", "exception",
                          "suppression"]) {
    assert.ok(names.includes(expected), `${expected} is missing from the glossary`);
  }
  dom.window.close();
});

// --------------------------------------------------------- rendered views ---

const VIEWS = [
  ["#/criteria?store=prod", "criteria with a store"],
  ["#/criteria", "criteria without a store"],
  ["#/criteria?answers=1&store=prod", "questionnaire"],
  ["#/frameworks", "frameworks"],
  ["#/evidence", "evidence"],
  ["#/exceptions", "exceptions"],
  ["#/dsar", "personal data requests"],
  ["#/dsar?request=d1", "one personal data request"],
  ["#/policies", "policies"],
  ["#/templates", "templates"],
];

for (const [hash, name] of VIEWS) {
  test(`copy lint: ${name} (${hash})`, async () => {
    const {dom, doc} = await render(hash);
    const content = doc.getElementById("content");
    if (hash.startsWith("#/criteria?store")) await openInlineForms(doc);
    const lines = readable(content);
    const extra = [...content.querySelectorAll("[data-lint-forms]")]
      .flatMap(n => n.dataset.lintForms.split("\n")).filter(Boolean);
    assert.ok(lines.length > 20, `${name} rendered almost nothing: ${lines.slice(0, 5).join(" | ")}`);
    const problems = [...lint([...lines, ...extra], name), ...greenMet(content, name)];
    assert.deepEqual(problems, []);
    dom.window.close();
  });
}

test("the criteria stub covers every status the server sends", async () => {
  const {dom, doc} = await render("#/criteria?store=prod");
  const statuses = new Set([...doc.querySelectorAll(".crit-row")].map(r => r.dataset.status).filter(Boolean));
  for (const status of ["not_assessed", "evidence_needed", "under_review", "satisfied_for_scope",
                        "gap_identified", "not_applicable"]) {
    assert.ok(statuses.has(status), `no row with status ${status}`);
  }
  const text = doc.getElementById("content").textContent;
  for (const label of ["Waiting for approval", "Exception active", "Exception expired", "Exception revoked",
                       "Checks passed", "Checks failed", "Inconclusive", "Not run", "Not sure yet",
                       "Excluded by an answer", "Waiting for review", "More information needed"]) {
    assert.match(text, new RegExp(label, "i"), `${label} is not rendered`);
  }
  dom.window.close();
});

// ------------------------------------------------------ reading level (D-C7) ---

function syllables(word) {
  const w = word.toLowerCase().replace(/[^a-z]/g, "");
  if (!w) return 0;
  if (w.length <= 3) return 1;
  const groups = w.replace(/(?:[^laeiouy]es|ed|[^laeiouy]e)$/, "").replace(/^y/, "").match(/[aeiouy]{1,2}/g);
  return Math.max(1, groups ? groups.length : 1);
}

// Flesch-Kincaid grade level over a body of sentences.
function gradeLevel(sentencesList) {
  const words = sentencesList.flatMap(s => s.split(/\s+/).filter(w => /[a-z]/i.test(w)));
  if (!words.length) return 0;
  const syl = words.reduce((sum, w) => sum + syllables(w), 0);
  return 0.39 * (words.length / sentencesList.length) + 11.8 * (syl / words.length) - 15.59;
}

test("reading level of the primary compliance copy (advisory, not blocking)", async t => {
  const {dom, window} = await render("#/docs");
  const copy = window.eval("COMPLIANCE_COPY");
  const primary = strings({criteria: copy.criteria, forms: copy.forms, questionnaire: copy.questionnaire,
                           exceptions: copy.exceptions, dsar: copy.dsar, mapping: copy.mapping})
    .map(s => s.replace(/\{\w+\}/g, "it"))
    .flatMap(s => s.split(/(?<=[.?!])\s+/))
    .filter(s => s.split(/\s+/).length >= 4);
  const grade = gradeLevel(primary);
  const long = primary.filter(s => s.split(/\s+/).length > 20);
  // D-C7: reported, never failed on. Target US grade 8–9 and at most 20 words
  // a sentence for primary copy.
  t.diagnostic(`reading level: grade ${grade.toFixed(1)} over ${primary.length} sentences ` +
               `(target 8–9); ${long.length} longer than 20 words`);
  for (const sentence of long) t.diagnostic(`long: ${sentence}`);
  assert.ok(Number.isFinite(grade));
  dom.window.close();
});
