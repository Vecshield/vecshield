import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// Crypto posture: the Estate → Crypto screen and the crypto rows inside the
// Frameworks, Criteria and Policies screens. Every assertion is about keeping
// states honest: "not observable" must never read as a failure, layers are
// never merged, and coverage is counts, never a percentage.
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

function find(node, predicate) {
  if (predicate(node)) return node;
  for (const child of node.children || []) {
    const found = find(child, predicate);
    if (found) return found;
  }
  return null;
}

function findAll(node, predicate, acc = []) {
  if (predicate(node)) acc.push(node);
  for (const child of node.children || []) findAll(child, predicate, acc);
  return acc;
}

const hasClass = name => node => node.classList?.contains?.(name);

function app(responses = {}, hash = "") {
  const calls = [];
  const doc = {
    body: new Element("body"), documentElement: new Element("html"), activeElement: null,
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
      calls.push({path, opts});
      const value = typeof responses === "function" ? responses(path, opts) : responses[path];
      if (value === undefined) throw new Error(`Unexpected request: ${path}`);
      if (typeof value.status === "number") {
        return {ok: false, status: value.status, statusText: "Error", json: async () => ({detail: value.detail})};
      }
      return {ok: true, headers: {get: () => "application/json"}, json: async () => value};
    },
  });
  vm.runInContext(source, context);
  return {context, calls};
}

const CORE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "mongodb"}]},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
};

// A read model in the shape crypto/view.py builds, with the layers shuffled and
// the retrieval layer missing, to prove the screen imposes its own order and
// never drops a layer.
const MODEL = {
  store_id: "prod", audit_id: "audit-7", assessed_at: "2026-09-20T10:00:00Z",
  pack_version: "vecshield-vector-store-draft-3",
  layers: [
    {layer: "data", title: "Field and data-level protection", rows: [
      {check: "field_encryption", control: "VCR-10", label: "Field-level encryption",
       collection: "patients", outcome: "unsupported", crypto_state: "not_observable",
       reason: "The connector cannot read field encryption settings.", details: {supported: false, fields: []}},
      {check: "pan_representation", control: "VCR-06", label: "PAN storage representation",
       collection: "payments", outcome: "failed", crypto_state: "observed_exposure",
       reason: "2 full PANs are stored readable.",
       details: {counts: {full: 2, truncated: 5, tokenized: 3, hash_candidate: 0, opaque: 0},
                 records_with_pan: 10, examples: ["4111 **** **** 1111"]}},
      {check: "data_representation", control: "VCR-03/04/05/08/09", label: "Sensitive data representation",
       collection: "patients", outcome: "passed", crypto_state: "protected_representation",
       reason: "Every sensitive value is masked or tokenised.",
       details: {sensitive_values: 12, protected_values: 12, plaintext_values: 0,
                 protected_fraction: 1, inversion_risk: 0.12,
                 fields: [{path: "ssn", surface: "metadata", classes: {tokenized: 12}}],
                 statement: "Embeddings are not treated as cryptographic protection."}},
    ]},
    {layer: "transport", title: "Transport", rows: [
      {check: "transport_encryption", control: "VCR-01", label: "TLS on VecShield's connection",
       collection: null, outcome: "passed", crypto_state: "verified",
       reason: "The live session reports TLSv1.3.", details: {scheme: "mongodb+srv", protocol: "TLSv1.3", encrypted: true}},
      {check: "transport_tls_enforcement", control: "VCR-02", label: "Plaintext connections refused",
       collection: null, outcome: "skipped", crypto_state: "not_verified",
       reason: "Not included in this run: the active probe is off.", details: {}},
    ]},
    {layer: "storage", title: "Storage encryption", rows: [
      {check: "at_rest_encryption", control: "VCR-11/13", label: "Database-native encryption at rest",
       collection: null, outcome: "inconclusive", crypto_state: "not_verified",
       reason: "38 collections report encryption; 4 are not observable.",
       details: {source: "serverStatus.encryptionAtRest", scope: "collection",
                 collections: {total: 42, verified_encrypted: 38, verified_unencrypted: 0, unknown: 4}}},
    ]},
  ],
  coverage: {collections_total: 42,
             at_rest: {verified_encrypted: 38, verified_unencrypted: 0, unknown: 4},
             checks: {at_rest_encryption: {inconclusive: 1}}},
  out_of_scope: [
    {property: "Infrastructure disk / volume encryption", state: "not_observable",
     reason: "Volume encryption sits below the database interface."},
    {property: "Cloud KMS / Key Vault configuration", state: "outside_connector_scope",
     reason: "Key management services are cloud control-plane resources."},
  ],
  statements: ["Embeddings are not treated as cryptographic protection.",
               "Not observable is not a failure: supply manual evidence where a criterion asks for it."],
  drift: {previous_audit_id: "audit-6", compared: true, changes: [
    {check: "at_rest_encryption", label: "Database-native encryption at rest", collection: null,
     change: "changed", before: {outcome: "passed", crypto_state: "verified"},
     after: {outcome: "failed", crypto_state: "observed_exposure"}},
    {check: "pan_representation", label: "PAN storage representation", collection: "payments",
     change: "new", before: null, after: {outcome: "failed", crypto_state: "observed_exposure"}},
  ]},
  regulatory: [
    {framework: "HIPAA", relationship: "addressable", relationship_label: "Addressable",
     at_rest: "Explicit, but currently addressable", in_transit: "Explicit, but currently addressable",
     interpretation: "Encrypt if reasonable/appropriate; otherwise document alternative",
     applicability: "Covered entities", source_ids: ["hipaa-164-312-a-2-iv"],
     criteria: [{criterion_id: "HIPAA-164-312-A2IV-ENCRYPTION-01", technical_result: "inconclusive",
                 technical_coverage: "partial", fallback_required: ["encryption_at_rest_statement"],
                 checks: ["at_rest_encryption"]}]},
    {framework: "PCI-DSS", relationship: "direct_if_pan", relationship_label: "Direct where PAN is present",
     at_rest: "Stored PAN must be unreadable", in_transit: "Strong cryptography required",
     interpretation: "Very strong if PAN is in vector DB", applicability: "Account data",
     criteria: [{criterion_id: "PCI-DSS-3-STORAGE-01", technical_result: "failed",
                 technical_coverage: "complete", fallback_required: [], checks: ["pan_representation"]}]},
    {framework: "EU AI Act", relationship: "supporting", relationship_label: "Supporting evidence only",
     at_rest: "No explicit at-rest encryption requirement",
     in_transit: "No explicit transit-encryption requirement",
     interpretation: "Supporting cybersecurity/privacy control only; don't claim direct mandate",
     applicability: "High-risk AI systems (Art. 15 cybersecurity), as context", criteria: []},
  ],
  note: "No crypto score. Counts describe what the connector could observe.",
};

function cryptoApp(model = MODEL, hash = "#/crypto?store=prod") {
  return app({...CORE, "/stores/prod/crypto-posture": model}, hash);
}

// ----------------------------------------------------------- the screen ---

test("the Crypto screen is registered in the Estate area", () => {
  const {context} = app();
  const area = vm.runInContext("areaOf('crypto')", context);
  assert.equal(area[0], "Estate");
  assert.equal(vm.runInContext("views.crypto[0]", context), "Crypto");
});

test("layers render in order, and a layer the model omits is still shown", async () => {
  const {context} = cryptoApp();
  const node = await context.renderCrypto();
  const layers = findAll(node, n => n.dataset?.layer).map(n => n.dataset.layer);
  assert.deepEqual(layers, ["transport", "storage", "data", "retrieval"]);
  const retrieval = find(node, n => n.dataset?.layer === "retrieval");
  assert.match(retrieval.textContent, /holds no rows for this layer/);
  assert.match(retrieval.textContent, /not verified/);
});

test("not observable is visibly and textually distinct from a failure", () => {
  const {context} = app();
  const unseen = context.cryptoChip("not_observable", "unsupported");
  const failed = context.cryptoChip("observed_exposure", "failed");
  assert.match(unseen.textContent, /Not observable/);
  assert.match(failed.textContent, /Observed exposure/);
  assert.ok(unseen.classList.contains("crypto-not-observable"));
  assert.ok(unseen.classList.contains("sev-info"), "a neutral tone");
  for (const warning of ["sev-critical", "sev-high", "sev-medium"]) {
    assert.ok(!unseen.classList.contains(warning), `not observable must not carry ${warning}`);
  }
  assert.ok(failed.classList.contains("sev-critical"));
  assert.notEqual(unseen.className, failed.className);
  // A glyph accompanies every chip, so the state is never colour alone.
  assert.ok(find(unseen, n => n.tagName === "SVG"));
});

test("an exposure that depends on risk is not drawn as a failure", () => {
  const {context} = app();
  const review = context.cryptoChip("observed_exposure", "inconclusive");
  assert.ok(review.classList.contains("sev-high"));
  assert.ok(!review.classList.contains("sev-critical"));
});

test("a skipped or missing check reads as not run, whatever state it records", () => {
  const {context} = app();
  assert.match(context.cryptoChip("not_verified", "skipped").textContent, /Not run/);
  assert.match(context.cryptoChip("not_verified", "not_run").textContent, /Not run/);
  assert.ok(context.cryptoChip("not_verified", "not_run").classList.contains("crypto-not-run"));
});

test("rows carry label, control id, collection, state and reason", async () => {
  const {context} = cryptoApp();
  const node = await context.renderCrypto();
  const row = find(node, n => n.tagName === "TR" && n.dataset?.check === "field_encryption");
  assert.match(row.textContent, /Field-level encryption/);
  assert.match(row.textContent, /VCR-10/);
  assert.match(row.textContent, /patients/);
  assert.match(row.textContent, /Not observable/);
  assert.match(row.textContent, /cannot read field encryption settings/);
  const store = find(node, n => n.tagName === "TR" && n.dataset?.check === "transport_encryption");
  assert.match(store.textContent, /Store scope/);
});

test("coverage is counts, and nothing on the screen is a percentage", async () => {
  const {context} = cryptoApp();
  const text = (await context.renderCrypto()).textContent;
  assert.match(text, /38 verified encrypted · 0 verified unencrypted · 4 unknown/);
  assert.match(text, /No crypto score/);
  assert.doesNotMatch(text, /%/, "a percentage would read as a score");
});

test("details are counts and names, never masked values", async () => {
  const {context} = cryptoApp();
  const node = await context.renderCrypto();
  const pan = find(node, n => n.tagName === "TR" && n.dataset?.check === "pan_representation");
  assert.match(pan.textContent, /full 2/);
  assert.match(pan.textContent, /records with pan/);
  assert.doesNotMatch(pan.textContent, /4111|\*\*\*\*/, "masked previews stay out of the table");
  const rep = find(node, n => n.tagName === "TR" && n.dataset?.check === "data_representation");
  assert.doesNotMatch(rep.textContent, /protected fraction/);
  assert.match(rep.textContent, /ssn/);
});

test("the statements, including embeddings, are shown", async () => {
  const {context} = cryptoApp();
  const text = (await context.renderCrypto()).textContent;
  assert.match(text, /Embeddings are not treated as cryptographic protection\./);
});

test("the page no longer lists what lies outside the connector", async () => {
  // Removed at the user's request (2026-09-25). The read model still carries
  // out_of_scope for API clients; the screen makes no claim about it.
  const {context} = cryptoApp();
  const text = (await context.renderCrypto()).textContent;
  assert.doesNotMatch(text, /Infrastructure disk|Cloud KMS|outside (?:what )?the connector/i);
});

test("drift names the change, and a first observation is not read as a fix", async () => {
  const {context} = cryptoApp();
  const node = await context.renderCrypto();
  const items = findAll(node, hasClass("crypto-drift-item")).map(n => n.textContent);
  assert.ok(items.some(t => /Database-native encryption at rest\s+changed from verified to observed exposure/.test(t)));
  assert.ok(items.some(t => /PAN storage representation \(payments\)\s+first observed as observed exposure/.test(t)));
});

test("with no earlier audit, drift says nothing was compared", async () => {
  const {context} = cryptoApp({...MODEL, drift: {previous_audit_id: null, compared: false, changes: []}});
  const text = (await context.renderCrypto()).textContent;
  assert.match(text, /No earlier saved audit to compare against/);
});

test("each framework is one row with its relationship, and the EU AI Act is supporting only", async () => {
  const {context} = cryptoApp();
  const node = await context.renderCrypto();
  const rows = findAll(node, hasClass("crypto-reg-row"));
  assert.deepEqual(rows.map(r => r.dataset.framework), ["HIPAA", "PCI-DSS", "EU AI Act"]);
  const hipaa = rows[0].textContent;
  assert.match(hipaa, /Addressable/);
  assert.match(hipaa, /HIPAA-164-312-A2IV-ENCRYPTION-01/);
  assert.match(hipaa, /Inconclusive/);
  assert.match(find(rows[0], hasClass("crypto-fallback")).textContent, /encryption at rest statement/i);
  assert.match(rows[1].textContent, /Direct where PAN is present/);
  const ai = rows[2];
  assert.match(ai.textContent, /Supporting evidence only/);
  assert.match(ai.textContent, /no encryption mandate/);
  assert.ok(!find(ai, hasClass("crypto-reg-criteria")), "no criterion is claimed for it");
  assert.doesNotMatch(ai.textContent, /Passed|Failed|Inconclusive/);
});

test("a criterion links to the Criteria screen for this store", async () => {
  const {context} = cryptoApp();
  const node = await context.renderCrypto();
  const link = find(node, n => n.tagName === "BUTTON" && n.textContent === "PCI-DSS-3-STORAGE-01");
  link.click();
  assert.equal(context.location.hash, "#/criteria?store=prod&framework=PCI-DSS");
});

test("a store with no saved audit is told to run one from New assessment", async () => {
  const {context} = app({...CORE,
    "/stores/prod/crypto-posture": {status: 409, detail: "no saved audit snapshot"}}, "#/crypto?store=prod");
  const node = await context.renderCrypto();
  assert.match(node.textContent, /No saved audit for this store/);
  assert.match(node.textContent, /run an audit from New assessment/);
  assert.doesNotMatch(node.textContent, /Request failed|error/i);
  find(node, n => n.tagName === "BUTTON" && /Run an audit/.test(n.textContent)).click();
  assert.equal(context.location.hash, "#/assess?store=prod");
});

test("a named saved audit is requested, not the latest", async () => {
  const {context, calls} = cryptoApp(MODEL, "#/crypto?store=prod&audit=audit-6");
  await context.renderCrypto();
  assert.ok(calls.some(c => c.path === "/stores/prod/crypto-posture?audit_id=audit-6"));
});

// ------------------------------------------------------------ frameworks ---

const PACK = {
  pack: {pack_version: "vecshield-vector-store-draft-3", criteria: 2, lifecycle: "draft",
         regulatory_review: null, note: "Draft.",
         frameworks: ["HIPAA", "EU AI Act"]},
  criteria: [
    {criterion_id: "HIPAA-164-312-A2IV-ENCRYPTION-01", framework: "HIPAA",
     paraphrase: "ePHI in the store is encrypted at rest, or an alternative is documented.",
     sources: [{section: "45 CFR 164.312(a)(2)(iv)"}], technical_checks: ["at_rest_encryption"],
     manual_evidence: [], fallback_evidence: ["encryption_at_rest_statement"],
     applicability_questions: []},
    {criterion_id: "AIACT-ART10-DATA-GOV-01", framework: "EU AI Act",
     paraphrase: "Data used by the retrieval corpus is governed.",
     sources: [{section: "Art. 10"}], technical_checks: ["rag_integrity"],
     manual_evidence: ["data_governance_record"], applicability_questions: []},
  ],
};

const BASIS = {basis: [
  {framework: "HIPAA", relationship: "addressable", relationship_label: "Addressable",
   at_rest: "Explicit, but currently addressable", in_transit: "Explicit, but currently addressable",
   interpretation: "Encrypt if reasonable/appropriate; otherwise document alternative",
   applicability: "Covered entities and business associates handling ePHI",
   criteria: ["HIPAA-164-312-A2IV-ENCRYPTION-01"]},
  {framework: "EU AI Act", relationship: "supporting", relationship_label: "Supporting evidence only",
   at_rest: "No explicit at-rest encryption requirement",
   in_transit: "No explicit transit-encryption requirement",
   interpretation: "Supporting cybersecurity/privacy control only; don't claim direct mandate",
   applicability: "High-risk AI systems (Art. 15 cybersecurity), as context", criteria: []},
]};

function frameworksApp(basis = BASIS) {
  return app(path => {
    if (CORE[path]) return CORE[path];
    if (path === "/compliance/criteria") return PACK;
    if (path === "/compliance/hipaa") return {status: 404, detail: "no"};
    if (path === "/compliance/crypto-basis") return basis;
    return undefined;
  }, "#/frameworks");
}

test("each framework carries a cryptographic protection block, with no percentage", async () => {
  const {context} = frameworksApp();
  const node = await context.renderFrameworks();
  const blocks = findAll(node, hasClass("fw-crypto"));
  assert.deepEqual(blocks.map(b => b.dataset.framework).sort(), ["EU AI Act", "HIPAA"]);
  const hipaa = blocks.find(b => b.dataset.framework === "HIPAA").textContent;
  assert.match(hipaa, /Cryptographic protection/);
  assert.match(hipaa, /Addressable/);
  assert.match(hipaa, /At rest\s+Explicit, but currently addressable/);
  assert.match(hipaa, /In transit\s+Explicit, but currently addressable/);
  assert.match(hipaa, /Encrypt if reasonable\/appropriate/);
  assert.match(hipaa, /Open the Crypto view/);
  const ai = blocks.find(b => b.dataset.framework === "EU AI Act").textContent;
  assert.match(ai, /Supporting evidence only — no encryption mandate/);
  assert.doesNotMatch(node.textContent, /\d+%/, "a percentage would read as a score");
  // The card at a glance names the relationship too.
  const cards = findAll(node, hasClass("fw-crypto-line")).map(n => n.textContent);
  assert.ok(cards.some(t => /Addressable/.test(t)));
});

test("the crypto block links to the Crypto screen", async () => {
  const {context} = frameworksApp();
  const node = await context.renderFrameworks();
  const block = find(node, n => n.dataset?.framework === "HIPAA" && hasClass("fw-crypto")(n));
  find(block, n => n.tagName === "BUTTON" && /Open the Crypto view/.test(n.textContent)).click();
  assert.equal(context.location.hash, "#/crypto");
});

test("fallback evidence is listed as conditional beside the obligation", async () => {
  const {context} = frameworksApp();
  const text = (await context.renderFrameworks()).textContent;
  assert.match(text, /encryption at rest statement \(conditional\)/);
});

test("frameworks still render when the basis is not served", async () => {
  const {context} = frameworksApp({status: 404, detail: "Not Found"});
  const node = await context.renderFrameworks();
  assert.equal(findAll(node, hasClass("fw-crypto")).length, 0);
  assert.match(node.textContent, /HIPAA/);
});

// -------------------------------------------------------------- criteria ---

function obs(check, state, outcome, collection = null, reason = "") {
  return {check, store: "prod", collection, outcome, reason,
          coverage: {status: "partial", complete: false, crypto_state: state}};
}

const CRITERIA_RESULT = {
  audit_id: "audit-7", coverage: {status: "partial"},
  summary: {by_status: {evidence_needed: 2, gap_identified: 1}, note: "Counts, not a score."},
  assessments: [
    {criterion_id: "HIPAA-164-312-A2IV-ENCRYPTION-01", framework: "HIPAA", status: "evidence_needed",
     applicability: {}, applicability_status: "confirmed", technical_result: "not_run",
     technical_coverage: "unknown", evidence_sufficiency: "missing",
     observations: [obs("at_rest_encryption", "not_observable", "unsupported", null,
                        "The store exposes no encryption-at-rest setting.")],
     missing_evidence: ["encryption_at_rest_statement"], gaps: [], limitations: [],
     specification: "addressable", addressable_determination: "missing", risk_determination: null,
     fallback_required: ["encryption_at_rest_statement"]},
    {criterion_id: "GDPR-32-1A-ENCRYPTION-01", framework: "GDPR", status: "gap_identified",
     applicability: {}, applicability_status: "confirmed", technical_result: "failed",
     technical_coverage: "partial", evidence_sufficiency: "missing",
     observations: [obs("data_representation", "observed_exposure", "failed", "patients",
                        "A field mixes protected and plaintext values.")],
     missing_evidence: [], gaps: [], limitations: [], specification: "risk_based",
     addressable_determination: null, risk_determination: "missing", fallback_required: []},
    {criterion_id: "PCI-DSS-3-STORAGE-01", framework: "PCI-DSS", status: "gap_identified",
     applicability: {}, applicability_status: "confirmed", technical_result: "failed",
     technical_coverage: "complete", evidence_sufficiency: "missing",
     observations: [obs("pan_representation", "observed_exposure", "failed", "payments",
                        "2 full PANs are stored readable."),
                    {check: "data_classification", store: "prod", collection: "payments",
                     outcome: "passed", reason: "", coverage: {status: "complete", complete: true}}],
     missing_evidence: [], gaps: [], limitations: [], fallback_required: [],
     addressable_determination: null, risk_determination: null},
  ],
};

function criteriaApp() {
  return app(path => {
    if (CORE[path]) return CORE[path];
    if (path === "/compliance/criteria") return PACK;
    if (path === "/stores/prod/criteria") return CRITERIA_RESULT;
    return undefined;
  }, "#/criteria?store=prod");
}

// A criterion row leads with its plain title; its id is data, not the heading.
function card(node, id) {
  return find(node, n => n.tagName === "ARTICLE" && hasClass("criterion")(n) &&
                         n.dataset?.criterion === id);
}

test("a criterion's crypto observations keep not observable apart from failed", async () => {
  const {context} = criteriaApp();
  const node = await context.renderCriteria();
  const hipaa = card(node, "HIPAA-164-312-A2IV-ENCRYPTION-01");
  const chip = find(hipaa, hasClass("crypto-chip"));
  assert.equal(chip.dataset.state, "not_observable");
  assert.match(chip.textContent, /Not observable/);
  const gdpr = card(node, "GDPR-32-1A-ENCRYPTION-01");
  const failed = find(gdpr, hasClass("crypto-chip"));
  assert.equal(failed.dataset.state, "observed_exposure");
  assert.notEqual(chip.className, failed.className);
});

test("fallback evidence says why it is required", async () => {
  const {context} = criteriaApp();
  const node = await context.renderCriteria();
  const hipaa = card(node, "HIPAA-164-312-A2IV-ENCRYPTION-01").textContent;
  assert.match(hipaa, /Needed because the store does not show this: encryption at rest statement/);
});

test("addressable and risk-based determinations are shown when they apply", async () => {
  const {context} = criteriaApp();
  const node = await context.renderCriteria();
  // Not observable is not absent: the determination waits on the fallback.
  assert.match(card(node, "HIPAA-164-312-A2IV-ENCRYPTION-01").textContent,
               /Addressable determination\s+Only if absent/);
  const gdpr = card(node, "GDPR-32-1A-ENCRYPTION-01").textContent;
  assert.match(gdpr, /Risk determination\s+Missing/);
  assert.doesNotMatch(gdpr, /Addressable determination/);
  assert.doesNotMatch(card(node, "PCI-DSS-3-STORAGE-01").textContent, /determination/);
});

test("PCI storage shows storage encryption and PAN protection as two rows", async () => {
  const {context} = criteriaApp();
  const node = await context.renderCriteria();
  const pci = card(node, "PCI-DSS-3-STORAGE-01");
  const rows = findAll(pci, hasClass("crypto-obs-item"));
  assert.equal(rows.length, 2, "never merged into one");
  assert.match(rows[0].textContent, /^Storage encryption/);
  // The storage observation comes from a sibling criterion in this evaluation.
  assert.match(rows[0].textContent, /Not observable/);
  assert.match(rows[1].textContent, /^PAN data-level protection/);
  assert.match(rows[1].textContent, /Observed exposure/);
  assert.match(pci.textContent, /never satisfies it/);
});

test("the observations dialog shows each crypto state", () => {
  const {context} = criteriaApp();
  context.observationsModal(CRITERIA_RESULT.assessments[0]);
  const dialog = context.document.body.children.at(-1);
  assert.match(dialog.textContent, /Crypto state/);
  assert.match(dialog.textContent, /Not observable/);
});

// ------------------------------------------------------ policies, labels ---

test("the built-in crypto policies are listed with the state that triggers them", async () => {
  const {context} = app({...CORE}, "#/policies");
  const text = (await context.renderPolicies()).textContent;
  for (const id of ["at-rest-encryption-not-disabled", "tls-enforced",
                    "pan-rendered-unreadable", "protection-applied-consistently"]) {
    assert.match(text, new RegExp(id));
  }
  assert.match(text, /Never fires on/);
  assert.match(text, /no policy fires on it/);
});

test("crypto categories have readable names, and a rule may name several", () => {
  const {context} = app();
  for (const [id, label] of [["transport_tls_enforcement", "TLS enforcement"],
                             ["at_rest_encryption", "Encryption at rest"],
                             ["field_encryption", "Field-level encryption"],
                             ["data_representation", "Sensitive data representation"],
                             ["pan_representation", "PAN representation"],
                             ["retrieval_exposure", "Retrieval exposure"],
                             ["direct_identifier_exposure", "Direct identifier exposure"]]) {
    assert.equal(context.categoryLabel(id), label);
  }
  const rule = {category: ["data_classification", "pan_representation"], requires_label: "pci"};
  assert.match(context.ruleSummary(rule), /category Data classification or PAN representation/);
  assert.ok(context.findingMatchesRule({category: "pan_representation",
                                        evidence: {label_counts: {pci: 1}}}, rule));
  assert.ok(!context.findingMatchesRule({category: "isolation",
                                         evidence: {label_counts: {pci: 1}}}, rule));
});

test("every crypto check has a glossary entry", () => {
  const {context} = app();
  for (const check of ["transport_encryption", "transport_tls_enforcement", "at_rest_encryption",
                       "field_encryption", "data_representation", "pan_representation",
                       "retrieval_exposure", "direct_identifier_exposure"]) {
    assert.notEqual(context.checkLabel(check), check.replace(/_/g, " "), `${check} has a name`);
  }
});

test("the docs describe the Crypto screen", async () => {
  const {context} = app();
  const text = (await context.renderDocs()).textContent;
  assert.match(text, /Cryptographic posture/);
  assert.match(text, /Not observable means the store's interface cannot answer/);
  assert.doesNotMatch(text, /\d+%/);
});

// ------------------------------------------------------- follow-up work ---

test("the header strip states the absence of a score affirmatively", async () => {
  const {context} = cryptoApp();
  const text = (await context.renderCrypto()).textContent;
  assert.match(text, /Counts only\s+no crypto score/);
  assert.doesNotMatch(text, /Score\s+None/);
});

test("PCI storage encryption comes from the audit's crypto context when filtered to PCI", async () => {
  const pciOnly = {
    ...CRITERIA_RESULT,
    assessments: [CRITERIA_RESULT.assessments[2]],
    crypto_context: [obs("at_rest_encryption", "verified", "passed", null,
                         "The database reports encryption at rest for every collection.")],
  };
  const {context} = app(path => {
    if (CORE[path]) return CORE[path];
    if (path === "/compliance/criteria") return PACK;
    if (path === "/stores/prod/criteria") return pciOnly;
    return undefined;
  }, "#/criteria?store=prod&framework=PCI-DSS");
  const node = await context.renderCriteria();
  const rows = findAll(card(node, "PCI-DSS-3-STORAGE-01"), hasClass("crypto-obs-item"));
  assert.equal(rows.length, 2);
  assert.match(rows[0].textContent, /^Storage encryption/);
  assert.match(rows[0].textContent, /Verified/);
  assert.doesNotMatch(rows[0].textContent, /Not run/);
  assert.match(rows[1].textContent, /Observed exposure/);
});

test("without crypto context or a sibling observation, PCI storage says it was not run", async () => {
  const {context} = app(path => {
    if (CORE[path]) return CORE[path];
    if (path === "/compliance/criteria") return PACK;
    if (path === "/stores/prod/criteria") {
      return {...CRITERIA_RESULT, assessments: [CRITERIA_RESULT.assessments[2]]};
    }
    return undefined;
  }, "#/criteria?store=prod&framework=PCI-DSS");
  const node = await context.renderCriteria();
  const rows = findAll(card(node, "PCI-DSS-3-STORAGE-01"), hasClass("crypto-obs-item"));
  assert.match(rows[0].textContent, /Not run/);
});

function assessApp() {
  return app((path, opts) => {
    if (CORE[path]) return CORE[path];
    if (path.startsWith("/stores/prod/schema")) return {collections: []};
    if (path.startsWith("/admin/history")) return {jobs: [], audits: []};
    // No job id: the run is refused, which keeps the harness from polling.
    if (path.startsWith("/stores/prod/")) return {};
    return undefined;
  }, "#/assess?store=prod");
}

async function submitted(context) {
  const node = await context.renderAssess();
  // One Run button, whose words follow the chosen mode.
  const click = () => find(node, n => n.tagName === "BUTTON" && n.classList.contains("run-go-btn")).click();
  const choose = mode => {
    const radio = find(node, n => n.tagName === "INPUT" && n.attrs.name === "run-mode" && n.attrs.value === mode);
    radio.checked = true;
    radio.events.change();
  };
  return {node, click, choose};
}

test("the active probes are off by default and sent only when switched on, only for the audit", async () => {
  const {context, calls} = assessApp();
  const {node, click, choose} = await submitted(context);
  const legend = find(node, n => n.tagName === "LEGEND" && /Active checks/.test(n.textContent));
  assert.ok(legend, "the active checks are their own labelled step");
  assert.match(legend.textContent, /optional, off by default/);
  assert.match(node.textContent, /TLS enforcement probe\s+— attempts a credential-free plaintext connection/);
  assert.match(node.textContent, /Retrieval exposure probe\s+— replays stored vectors as queries/);
  // Each says what it sends, and what being off means.
  assert.match(node.textContent, /One extra connection attempt/);
  assert.match(node.textContent, /adds query load/);
  assert.match(node.textContent, /Off: recorded as skipped/);
  const tls = find(node, n => n.tagName === "INPUT" && n.attrs.id === "probe-tls");
  const retrieval = find(node, n => n.tagName === "INPUT" && n.attrs.id === "probe-retrieval");
  assert.ok(!tls.checked && !retrieval.checked, "unchecked by default");
  const summary = () => find(node, n => n.attrs?.id === "run-summary").textContent;
  assert.match(summary(), /no active checks \(recorded as skipped\)/);

  const audits = () => calls.filter(c => c.path.startsWith("/stores/prod/audit"))
    .map(c => JSON.parse(c.opts.body));
  await click();
  assert.deepEqual(audits().at(-1), {include_integrity: true});

  tls.checked = true;
  tls.events.change();
  assert.match(summary(), /active checks: TLS enforcement probe/, "the summary says what will be sent");
  await click();
  assert.deepEqual(audits().at(-1), {include_integrity: true, tls_probe: true});

  retrieval.checked = true;
  await click();
  assert.deepEqual(audits().at(-1), {include_integrity: true, tls_probe: true, retrieval_probe: true});

  // Posture is not the audit: it never carries the probes, and hides them.
  choose("posture");
  const section = find(node, n => n.tagName === "FIELDSET" && n.classList.contains("run-probes"));
  assert.equal(section.hidden, true, "the probes are not offered for posture");
  await click();
  const posture = calls.filter(c => c.path.startsWith("/stores/prod/posture")).at(-1);
  assert.ok(posture, "posture was requested");
  assert.ok(!posture.opts.body, "and sent no probe fields");

  // The DPIA carries the chunk cap and nothing active.
  choose("dpia");
  await click();
  const dpia = calls.filter(c => c.path.startsWith("/stores/prod/pia")).at(-1);
  assert.deepEqual(JSON.parse(dpia.opts.body), {});
});

test("the evidence register marks fallback artifacts as conditional", async () => {
  const {context} = app({
    ...CORE, "/compliance/criteria": {
      ...PACK, criteria: [...PACK.criteria, {
        criterion_id: "HIPAA-164-312-A1-ACCESS-CONTROL-01", framework: "HIPAA",
        paraphrase: "Access is limited.", manual_evidence: ["access_review_record"],
        fallback_evidence: [], technical_checks: []}]},
    "/compliance/evidence": {artifacts: [], note: "n"},
    "/compliance/reviews": {reviews: [
      {criterion_id: "HIPAA-164-312-A2IV-ENCRYPTION-01", requirement: "encryption_at_rest_statement",
       artifact_id: "art-1", state: "accepted", accepted: true, reviewer: "r", reason: "ok"}]},
  }, "#/evidence");
  const node = await context.renderEvidence();
  const conditional = findAll(node, n => n.tagName === "TR" && n.dataset?.kind === "conditional");
  const required = findAll(node, n => n.tagName === "TR" && n.dataset?.kind === "required");
  assert.equal(conditional.length, 1);
  assert.match(conditional[0].textContent, /encryption at rest statement/);
  assert.match(conditional[0].textContent, /Conditional — needed only when the store cannot show this property/);
  assert.ok(required.some(r => /access review record/.test(r.textContent) && /Always required/.test(r.textContent)));
  assert.ok(required.every(r => !/Conditional/.test(r.textContent)));
  const review = find(node, n => n.tagName === "TR" && /art-1/.test(n.textContent));
  assert.match(review.textContent, /conditional/);
});

test("the criterion's inline add-document form labels fallback items as conditional", () => {
  const {context} = criteriaApp();
  const form = context.attachForm(CRITERIA_RESULT.assessments[0], {store: "prod", close() {}, done() {}});
  assert.equal(form.tagName, "FORM", "an inline form, not a dialog");
  assert.match(form.textContent,
    /encryption at rest statement \(only because the store can't show this\)/);
});

test("checks first observed after an upgrade are folded apart from real changes", async () => {
  const {context} = cryptoApp();
  const node = await context.renderCrypto();
  const folded = find(node, hasClass("crypto-drift-first"));
  assert.match(folded.textContent, /1 check first observed in this audit/);
  assert.match(folded.textContent, /PAN storage representation \(payments\)\s+first observed/);
  assert.doesNotMatch(folded.textContent, /changed from/);
});

test("a criterion reduced to not run because the store cannot answer says so", async () => {
  const {context} = criteriaApp();
  const node = await context.renderCriteria();
  assert.match(card(node, "HIPAA-164-312-A2IV-ENCRYPTION-01").textContent,
               /Not Run\s+not observable through this store|not run\s+not observable through this store/i);
  const {context: crypto} = cryptoApp({...MODEL, layers: MODEL.layers.map(l => l.layer !== "storage" ? l : {
    ...l, rows: [{...l.rows[0], outcome: "unsupported", crypto_state: "not_observable"}]}),
    regulatory: [{...MODEL.regulatory[0], criteria: [{...MODEL.regulatory[0].criteria[0], technical_result: "not_run"}]}]});
  const text = (await crypto.renderCrypto()).textContent;
  assert.match(text, /the check ran; the store does not expose this property/);
});

test("technical coverage words a property the store cannot show, or that does not arise", () => {
  const {context} = app();
  const text = c => vm.runInContext(`technicalCoverageText(${JSON.stringify(c)})`, context);
  assert.equal(text("not_observable"), "not observable through this store");
  assert.match(text("does_not_arise"), /doesn't come up for this store; documents decide it/);
  assert.doesNotMatch(text("does_not_arise"), /pass/i);
  // Manual-evidence-only criteria already use not_applicable; they are not
  // about a property that does not arise.
  assert.match(text("not_applicable"), /No automatic check covers this; documents do/);
  assert.equal(text("partial"), "coverage partial");
  assert.equal(text(undefined), "coverage unknown");
});

// ------------------------------------------- not supported by the database ---

const QDRANT_SUPPORT = {
  support: "not_supported", database: "Qdrant", capability_limit: true,
  evidence_to_supply: ["Hosting provider's volume-encryption configuration for the Qdrant nodes",
                       "Qdrant Cloud cluster encryption statement"],
  documented_default: {text: "Qdrant Cloud encrypts data at rest on its managed storage.",
                       source_url: "https://qdrant.tech/documentation/cloud/security/"},
  sources: ["https://qdrant.tech/documentation/cloud/security/",
            "https://qdrant.tech/documentation/guides/security/"],
};

const QDRANT_MODEL = {
  ...MODEL,
  layers: MODEL.layers.map(layer => {
    if (layer.layer === "storage") {
      return {...layer, rows: [{
        check: "at_rest_encryption", control: "VCR-11/13", label: "Database-native encryption at rest",
        collection: null, outcome: "unsupported", crypto_state: "not_observable",
        reason: "Qdrant exposes no encryption-at-rest state through its API.",
        details: {...QDRANT_SUPPORT, source: null, collections: {total: 3, verified_encrypted: 0,
                  verified_unencrypted: 0, unknown: 3}}}]};
    }
    if (layer.layer === "data") {
      return {...layer, rows: [{
        check: "field_encryption", control: "VCR-10", label: "Field-level encryption",
        collection: null, outcome: "unsupported", crypto_state: "not_observable",
        reason: "Qdrant has no field-level encryption to introspect.",
        details: {capability_limit: true, database: "Qdrant", supported: false}}]};
    }
    return layer;
  }),
  coverage: {collections_total: 3, at_rest: {verified_encrypted: 0, verified_unencrypted: 0, unknown: 3}},
};

test("not supported names the database, and differs from not observable", () => {
  const {context} = app();
  const unsupported = context.recordChip({outcome: "unsupported", crypto_state: "not_observable",
                                          details: QDRANT_SUPPORT});
  const unobserved = context.recordChip({outcome: "unsupported", crypto_state: "not_observable",
                                         details: {support: "supported", database: "PostgreSQL (Amazon RDS)"}});
  assert.match(unsupported.textContent, /Not supported by Qdrant/);
  assert.match(unobserved.textContent, /Not observable/);
  assert.doesNotMatch(unobserved.textContent, /Not supported/);
  assert.equal(unsupported.dataset.state, "not_supported");
  assert.ok(unsupported.classList.contains("crypto-not-supported"));
  assert.ok(unsupported.classList.contains("sev-info"), "a neutral tone");
  for (const warning of ["sev-critical", "sev-high", "sev-medium"]) {
    assert.ok(!unsupported.classList.contains(warning), `not supported must not carry ${warning}`);
  }
  // A capability limit on an unsupported outcome reads the same way.
  const field = context.recordChip({outcome: "unsupported", crypto_state: "not_observable",
                                    coverage: {capability_limit: true, database: "Qdrant"}});
  assert.match(field.textContent, /Not supported by Qdrant/);
});

test("the storage row lists evidence to supply and labels the vendor default as documentation", async () => {
  const {context} = cryptoApp(QDRANT_MODEL);
  const node = await context.renderCrypto();
  const row = find(node, n => n.tagName === "TR" && n.dataset?.check === "at_rest_encryption");
  const text = row.textContent;
  assert.match(text, /Not supported by Qdrant/);
  assert.match(text, /Qdrant exposes no encryption-at-rest state/);
  assert.match(text, /Evidence you can supply instead/);
  assert.match(text, /Hosting provider's volume-encryption configuration/);
  assert.match(text, /Qdrant Cloud cluster encryption statement/);
  assert.match(text, /documented, not verified here\s+Vendor documentation: Qdrant Cloud encrypts data at rest/);
  const links = findAll(row, n => n.tagName === "A");
  assert.ok(links.some(a => a.textContent === "qdrant.tech" &&
                            a.attrs.href === "https://qdrant.tech/documentation/cloud/security/"),
            "the documentation link is labelled with its domain");
  assert.equal(links.filter(a => a.attrs.rel === "noopener noreferrer").length, links.length);
  const sources = find(row, hasClass("crypto-sources"));
  assert.equal(sources.tagName, "DETAILS", "sources are collapsible");
  assert.match(sources.textContent, /Sources \(2\)/);
  // The documented default never makes the row read as verified.
  assert.doesNotMatch(text, /Verified/);
  // The generic details do not repeat the support fields.
  assert.doesNotMatch(find(row, hasClass("crypto-details"))?.textContent || "", /evidence to supply|documented default/);
});

test("the coverage line says the database does not support it, with counts and no percentage", async () => {
  const {context} = cryptoApp(QDRANT_MODEL);
  const node = await context.renderCrypto();
  const text = node.textContent;
  assert.match(text, /0 verified encrypted · 0 verified unencrypted · 3 not supported by the database/);
  assert.doesNotMatch(text, /%/);
  const field = find(node, n => n.tagName === "TR" && n.dataset?.check === "field_encryption");
  assert.match(field.textContent, /Not supported by Qdrant/);
});

test("criteria name the database that cannot report the property", async () => {
  const obsNs = {...obs("at_rest_encryption", "not_observable", "unsupported", null,
                        "Qdrant exposes no encryption-at-rest state through its API."),
                 coverage: {status: "complete", complete: true, crypto_state: "not_observable",
                            ...QDRANT_SUPPORT}};
  const result = {
    ...CRITERIA_RESULT,
    assessments: [
      {...CRITERIA_RESULT.assessments[0], technical_coverage: "not_observable",
       technical_checks: ["at_rest_encryption"], observations: [obsNs]},
      CRITERIA_RESULT.assessments[2],
    ],
    crypto_context: [obsNs],
  };
  const {context} = app(path => {
    if (CORE[path]) return CORE[path];
    if (path === "/compliance/criteria") return PACK;
    if (path === "/stores/prod/criteria") return result;
    return undefined;
  }, "#/criteria?store=prod");
  const node = await context.renderCriteria();
  const hipaa = card(node, "HIPAA-164-312-A2IV-ENCRYPTION-01").textContent;
  assert.match(hipaa, /not supported by Qdrant/);
  assert.doesNotMatch(hipaa, /not observable through this store/);
  assert.match(hipaa, /Evidence you can supply instead/);
  const pci = findAll(card(node, "PCI-DSS-3-STORAGE-01"), hasClass("crypto-obs-item"));
  assert.match(pci[0].textContent, /^Storage encryption.*Not supported by Qdrant/s);
  assert.match(pci[0].textContent, /documented, not verified here/);
  assert.match(pci[1].textContent, /PAN data-level protection/);
  assert.doesNotMatch(node.textContent, /\d+%/);
});

test("the docs explain not supported, not observable and not applicable", async () => {
  const {context} = app();
  const text = (await context.renderDocs()).textContent;
  assert.match(text, /Not supported means the database has no interface that reports the property/);
  assert.match(text, /Not applicable means the property does not arise/);
});

// ---------------------------------------------------------- release gate ---

const GATE_BLOCK = {
  store_id: "prod", audit_id: "audit-7", assessed_at: "2026-09-20T10:00:00Z",
  decision: "block", labels: ["pci", "phi"], settings: {requires_at_rest_encryption: false},
  rules: [
    {id: "full-pan-readable", description: "A full, readable PAN is stored.", decision: "block",
     status: "fired", reasons: ["payments: 2 full PANs readable"], cleared_by: [],
     evidence_that_clears: [], remediation: "Tokenise or truncate PAN before embedding.",
     basis: "PCI DSS 3.5.1"},
    {id: "phi-at-rest-unverified", description: "PHI where encryption at rest cannot be verified.",
     decision: "request_evidence", status: "cleared", reasons: ["at-rest encryption not supported by Qdrant"],
     cleared_by: [{criterion_id: "HIPAA-164-312-A2IV-ENCRYPTION-01", requirement: "encryption_at_rest_statement"}],
     evidence_that_clears: [{criterion_id: "HIPAA-164-312-A2IV-ENCRYPTION-01", requirement: "encryption_at_rest_statement"}],
     remediation: "Supply the statement.", basis: "45 CFR 164.312(a)(2)(iv)"},
    {id: "at-rest-reported-off", description: "The database reports encryption at rest off.",
     decision: "block", status: "not_triggered", reasons: [], cleared_by: [], evidence_that_clears: [],
     remediation: "Turn encryption at rest on.", basis: "Policy"},
  ],
  evidence_needed: [],
  note: "The gate decides from one saved audit and accepted evidence; it enforces nothing itself.",
};

function gateApp(gate = GATE_BLOCK, extra = {}) {
  const {context, calls} = app(path => {
    if (CORE[path]) return CORE[path];
    const base = path.split("?")[0];
    if (base === "/stores/prod/crypto-posture") return MODEL;
    if (base === "/stores/prod/crypto-gate") {
      return typeof gate === "function" ? gate(path) : gate;
    }
    return extra[path];
  }, "#/crypto?store=prod");
  return {context, calls};
}

test("a blocking gate renders critical, with its reasons, remediation and basis", async () => {
  const {context} = gateApp();
  const node = await context.renderCrypto();
  const panelNode = find(node, hasClass("gate-panel"));
  assert.ok(panelNode, "the gate panel is on the Crypto view");
  const chip = find(panelNode, n => hasClass("gate-chip")(n) && n.dataset.decision === "block");
  assert.ok(chip.classList.contains("sev-critical"));
  assert.match(chip.textContent, /Block/);
  const fired = find(panelNode, n => n.dataset?.rule === "full-pan-readable");
  assert.match(fired.textContent, /payments: 2 full PANs readable/);
  assert.match(fired.textContent, /Remediation:\s+Tokenise or truncate PAN/);
  assert.match(fired.textContent, /Basis:\s+PCI DSS 3\.5\.1/);
  assert.match(fired.textContent, /No document clears this: it rests on what the audit observed/);
  assert.match(panelNode.textContent, /Data in scope: pci, phi/);
  assert.match(panelNode.textContent, /vecshield-platform crypto-gate --store prod/);
  assert.match(panelNode.textContent, /exits 2 on block, 1 when evidence is needed/);
  assert.match(panelNode.textContent, /enforces nothing itself/);
  assert.doesNotMatch(node.textContent, /%/);
});

test("a cleared rule names the evidence that cleared it", async () => {
  const {context} = gateApp();
  const node = await context.renderCrypto();
  const cleared = find(node, n => n.dataset?.rule === "phi-at-rest-unverified");
  assert.equal(cleared.dataset.status, "cleared");
  assert.match(cleared.textContent,
               /Cleared by encryption at rest statement \(HIPAA-164-312-A2IV-ENCRYPTION-01\)/);
  const quiet = find(node, n => n.tagName === "DETAILS" && /1 rule not triggered/.test(n.textContent));
  assert.ok(quiet, "rules that did not fire are folded away");
});

test("evidence that would clear a fired rule links to the Evidence register", async () => {
  const gate = {...GATE_BLOCK, decision: "request_evidence",
    rules: [{...GATE_BLOCK.rules[1], status: "fired", cleared_by: []}],
    evidence_needed: [{criterion_id: "HIPAA-164-312-A2IV-ENCRYPTION-01", requirement: "encryption_at_rest_statement"}]};
  const {context} = gateApp(gate);
  const node = await context.renderCrypto();
  const chip = find(node, hasClass("gate-chip"));
  assert.ok(chip.classList.contains("sev-medium"));
  assert.match(chip.textContent, /Evidence needed/);
  const rule = find(node, n => n.dataset?.rule === "phi-at-rest-unverified");
  assert.match(rule.textContent, /Evidence that would clear it\s+encryption at rest statement \(HIPAA-164-312-A2IV-ENCRYPTION-01\)/);
  find(rule, n => n.tagName === "BUTTON" && /Evidence register/.test(n.textContent)).click();
  assert.equal(context.location.hash, "#/evidence");
});

test("a gate with no rule held never calls the store compliant", async () => {
  const {context} = gateApp({...GATE_BLOCK, decision: "pass",
    rules: GATE_BLOCK.rules.map(r => ({...r, status: "not_triggered"}))});
  const node = await context.renderCrypto();
  const panelNode = find(node, hasClass("gate-panel"));
  assert.match(panelNode.textContent, /No gate rule held in this audit/);
  assert.doesNotMatch(panelNode.textContent, /compliant|\bPass\b/i);
  assert.ok(find(panelNode, hasClass("gate-chip")).classList.contains("sev-ok"));
});

test("the at-rest policy toggle re-queries the gate, and is not persisted", async () => {
  const {context, calls} = gateApp(path => ({...GATE_BLOCK,
    settings: {requires_at_rest_encryption: path.includes("requires_at_rest_encryption=true")}}));
  const node = await context.renderCrypto();
  const gateCalls = () => calls.filter(c => c.path.startsWith("/stores/prod/crypto-gate"));
  assert.equal(gateCalls().length, 1);
  assert.doesNotMatch(gateCalls()[0].path, /requires_at_rest_encryption/);
  const toggle = find(node, n => n.tagName === "INPUT" && n.attrs.id === "gate-requires-at-rest");
  assert.ok(!toggle.checked, "off by default");
  toggle.checked = true;
  await toggle.events.change();
  assert.equal(gateCalls().length, 2);
  assert.match(gateCalls()[1].path, /requires_at_rest_encryption=true/);
  assert.doesNotMatch(context.location.hash, /requires/, "the setting is not written to the link");
  const again = find(node, n => n.tagName === "INPUT" && n.attrs.id === "gate-requires-at-rest");
  assert.ok(again.checked, "the re-rendered toggle keeps its state");
  assert.match(node.textContent, /--requires-at-rest-encryption/);
});

test("the gate says so when there is no saved audit to evaluate", async () => {
  const {context} = gateApp({status: 409, detail: "no saved audit snapshot"});
  const node = await context.renderCrypto();
  const panelNode = find(node, hasClass("gate-panel"));
  assert.match(panelNode.textContent, /No saved audit to evaluate; run an audit from New assessment first/);
});

test("the Policies view lists the gate rules from the server, beside the finding policies", async () => {
  const {context, calls} = app({...CORE, "/compliance/crypto-gate/rules": {
    decisions: ["block", "request_evidence", "warn", "pass"],
    rules: [
      {id: "full-pan-readable", description: "A full, readable PAN is stored.", decision: "block",
       when: "pan_representation finds full PAN", evidence_that_clears: [],
       remediation: "Tokenise PAN.", basis: "PCI DSS 3.5.1"},
      {id: "phi-at-rest-unverified", description: "PHI where at-rest cannot be verified.",
       decision: "request_evidence", when: "PHI present and at_rest_encryption not verified",
       evidence_that_clears: [{criterion_id: "HIPAA-164-312-A2IV-ENCRYPTION-01",
                               requirement: "encryption_at_rest_statement"}],
       remediation: "Supply the statement.", basis: "45 CFR 164.312(a)(2)(iv)"},
    ]}}, "#/policies");
  const node = await context.renderPolicies();
  assert.ok(calls.some(c => c.path === "/compliance/crypto-gate/rules"));
  const pan = find(node, n => n.tagName === "TR" && n.dataset?.rule === "full-pan-readable");
  assert.match(pan.textContent, /Block/);
  assert.match(pan.textContent, /pan_representation finds full PAN/);
  assert.match(pan.textContent, /Nothing — no document clears what the audit observed/);
  const phi = find(node, n => n.tagName === "TR" && n.dataset?.rule === "phi-at-rest-unverified");
  assert.match(phi.textContent, /Evidence needed/);
  assert.match(phi.textContent, /encryption at rest statement \(HIPAA-164-312-A2IV-ENCRYPTION-01\)/);
  assert.match(phi.textContent, /45 CFR 164\.312/);
  for (const id of ["at-rest-encryption-not-disabled", "tls-enforced",
                    "pan-rendered-unreadable", "protection-applied-consistently"]) {
    assert.match(node.textContent, new RegExp(id));
  }
  assert.doesNotMatch(node.textContent, /\d+%/);
});

test("the docs describe the release gate and its exit codes", async () => {
  const {context} = app();
  const text = (await context.renderDocs()).textContent;
  assert.match(text, /release gate/);
  assert.match(text, /exits 2 on block, 1 when evidence is needed/);
});

test("a gate rule's structured trigger is put into words", () => {
  const {context} = app();
  assert.equal(context.gateWhenText({labels_any: ["phi"], check: "at_rest_encryption", not_states: ["verified"]}),
               "Database-native encryption at rest: anything but verified, with phi data present");
  assert.equal(context.gateWhenText({check: "pan_representation", outcomes: ["failed"]}),
               "PAN storage representation: outcome failed");
  assert.match(context.gateWhenText({setting: "requires_at_rest_encryption", check: "at_rest_encryption",
                                     not_states: ["verified"]}),
               /when the "requires at rest encryption" setting is on/);
});

// -------------------------------------------- certificate check, reason notes ---

test("TLS certificate verification has a readable category, glossary entry and policy", async () => {
  const {context} = app({...CORE}, "#/policies");
  assert.equal(context.categoryLabel("tls_certificate_verification"), "TLS certificate verification");
  assert.equal(context.checkLabel("tls_certificate_verification"), "TLS certificate verification");
  const text = (await context.renderPolicies()).textContent;
  assert.match(text, /verify-tls-certificates\s+TLS is used without verifying the server certificate/);
  assert.match(text, /MEDIUM/);
});

test("a reason's caveat note is shown beside the reason, not hidden in details", async () => {
  const note = "Readable to an authenticated client says nothing about disk encryption.";
  const model = {...MODEL, layers: MODEL.layers.map(layer => layer.layer !== "data" ? layer : {
    ...layer, rows: layer.rows.map(row => row.check !== "data_representation" ? row : {
      ...row, reason: "6 sensitive values are stored as plaintext.",
      details: {...row.details, note}})})};
  const {context} = cryptoApp(model);
  const node = await context.renderCrypto();
  const row = find(node, n => n.tagName === "TR" && n.dataset?.check === "data_representation");
  const shown = find(row, hasClass("crypto-note"));
  assert.ok(shown, "the note renders");
  assert.match(shown.textContent, /says nothing about disk encryption/);
  assert.doesNotMatch(find(row, hasClass("crypto-details"))?.textContent || "", /disk encryption/,
                      "and is not repeated in the details list");
  // The same caveat on a criterion's observation.
  const {context: crit} = criteriaApp();
  const item = crit.cryptoObservationItem("Sensitive data representation",
    {check: "data_representation", collection: "patients", outcome: "inconclusive",
     reason: "6 sensitive values are stored as plaintext.",
     coverage: {crypto_state: "observed_exposure", note}});
  assert.match(item.textContent, /says nothing about disk encryption/);
});
