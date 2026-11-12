import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import axe from "axe-core";
import { JSDOM } from "jsdom";

// Sign-in, the forced password change, the account menu, the Users screen,
// the routed store page and the NLP install hint. Each test boots the shipped
// console through its real boot(), which asks /auth/session first.

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

const ADMIN = {username: "kim", roles: ["admin"], effective_roles: ["admin", "compliance", "operator", "viewer"],
               must_change_password: false, source: "session"};
const VIEWER = {username: "val", roles: ["viewer"], effective_roles: ["viewer"],
                must_change_password: false, source: "session"};
const signedIn = user => ({login_enabled: true, authenticated: true, user, password_policy: {min_length: 12}});
const SIGNED_OUT = {login_enabled: true, authenticated: false, user: null, password_policy: {min_length: 12}};
const OPEN = {login_enabled: false, authenticated: true, user: null, password_policy: {min_length: 12}};

const BASE = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant", tenant_field: "tenant_id"},
                             {store_id: "cold", kind: "chroma"}]},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
  "/version": {approvals: {separation_of_duties: "required"}},
  "/healthz": {status: "ok", stores: 2},
  "/admin/history": {jobs: [], stats: {total_findings: 0, by_severity: {}}},
  "/admin/estate": {stores: [
    {store_id: "prod", kind: "qdrant", tenant_field: "tenant_id", last_assessed: "2026-09-20T10:00:00Z",
     coverage: {status: "complete"}, findings: {high: 2}, findings_total: 2,
     probe: {probed: true, reachable: true, capabilities: ["query"], content_enumerable: true, collections: 2, chunks: 30}},
    {store_id: "cold", kind: "chroma", probe: {probed: true, reachable: true, capabilities: [], content_enumerable: true}}]},
  "/stores/prod/schema": {collections: [{name: "docs", count: 20}, {name: "faq", count: 10}]},
  "/auth/users": {users: [
    {username: "kim", roles: ["admin"], disabled: false, must_change_password: false,
     created_at: "2026-09-01T00:00:00Z", created_by: "bootstrap", last_login_at: "2026-09-28T08:00:00Z"},
    {username: "val", roles: ["viewer", "operator"], disabled: false, must_change_password: true,
     created_at: "2026-09-02T00:00:00Z", created_by: "kim", last_login_at: null},
    {username: "old", roles: ["compliance"], disabled: true, must_change_password: false,
     created_at: "2026-09-03T00:00:00Z", created_by: "kim", last_login_at: "2026-09-10T08:00:00Z"}]},
};

async function boot(hash, responses = {}, {theme = "light"} = {}) {
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="${theme}"><head><style>${css}</style></head>` +
    `<body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  const calls = [];
  const all = {...BASE, ...responses};
  window.fetch = async (path, opts = {}) => {
    const method = opts.method || "GET";
    calls.push({path, method, headers: opts.headers || {}, credentials: opts.credentials,
                body: opts.body ? JSON.parse(opts.body) : undefined});
    const base = path.split("?")[0];
    let value = all[`${method} ${base}`] ?? all[path] ?? all[base] ?? {};
    if (typeof value === "function") value = value(path, opts);
    if (typeof value?.status === "number") {
      return {ok: false, status: value.status, statusText: "Error",
              headers: {get: () => "application/json"}, json: async () => ({detail: value.detail})};
    }
    return {ok: true, status: 200, headers: {get: () => "application/json"},
            json: async () => value, text: async () => JSON.stringify(value)};
  };
  window.eval(shell);
  await window.eval("boot()");
  await settle();
  return {dom, window, doc: window.document, calls, run: code => window.eval(code)};
}

const settle = async (n = 3) => { for (let i = 0; i < n; i++) await new Promise(r => setTimeout(r, 20)); };
const text = node => node.textContent.replace(/\s+/g, " ").trim();
const button = (root, label) => [...root.querySelectorAll("button")].find(b => text(b) === label);
const inputNamed = (doc, labelText) => [...doc.querySelectorAll("label.field")]
  .find(l => l.querySelector("span")?.textContent.trim() === labelText)?.querySelector("input");

function type(window, input, value) {
  input.value = value;
  input.dispatchEvent(new window.Event("input", {bubbles: true}));
}

function submit(window, form) {
  form.dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
}

// The same structural audit as tests/axe.test.mjs, with the same rules left
// out for the same reason: jsdom does no layout or painting.
async function axeViolations(dom) {
  const results = await axe.run(dom.window.document.body, {
    rules: {"color-contrast": {enabled: false}, "target-size": {enabled: false},
            "scrollable-region-focusable": {enabled: false}},
    elementRef: false,
  });
  return results.violations.map(v => `${v.id}: ${v.help} (${v.nodes[0]?.html?.slice(0, 100)})`);
}

// --------------------------------------------------------------- sign-in ---

for (const theme of ["light", "dark"]) {
  test(`an unauthenticated visit shows the sign-in screen, not the console (${theme})`, async () => {
    const {dom, doc, calls} = await boot("#/stores", {"/auth/session": SIGNED_OUT}, {theme});
    assert.equal(calls[0].path, "/auth/session", "the session is asked for first");
    assert.equal(doc.getElementById("content"), null, "no console behind it");
    assert.equal(calls.filter(c => c.path !== "/auth/session").length, 0, "no data was requested");
    assert.equal(doc.getElementById("auth-title").textContent, "Sign in");
    assert.ok(doc.querySelector(".auth-brand img[src$='vecshield-mark.svg']"), "the mark leads the card");
    const user = inputNamed(doc, "Username");
    const pass = inputNamed(doc, "Password");
    assert.equal(user.getAttribute("autocomplete"), "username");
    assert.equal(pass.type, "password");
    assert.equal(pass.getAttribute("autocomplete"), "current-password");
    assert.equal(doc.activeElement, user, "focus starts in the username");
    assert.doesNotMatch(doc.body.textContent, /admin\s*\/\s*admin|default password/i, "no credential hint");
    assert.ok(doc.getElementById("theme-toggle"), "the theme can be changed before signing in");
    assert.deepEqual(await axeViolations(dom), []);
    dom.window.close();
  });
}

test("signing in posts the credentials and returns to the page that was asked for", async () => {
  let session = SIGNED_OUT;
  const {dom, window, doc, calls} = await boot("#/stores?store=prod", {
    "/auth/session": () => session,
    "POST /auth/login": () => { session = signedIn(ADMIN); return {user: ADMIN}; },
  });
  type(window, inputNamed(doc, "Username"), "kim");
  type(window, inputNamed(doc, "Password"), "correct horse battery");
  submit(window, doc.querySelector("form.auth-form"));
  await settle(5);
  const login = calls.find(c => c.path === "/auth/login");
  assert.deepEqual(login.body, {username: "kim", password: "correct horse battery"});
  assert.equal(window.location.hash, "#/stores?store=prod", "the hash was kept");
  assert.equal(doc.getElementById("page-title").textContent, "prod", "the store page it asked for");
  assert.equal(doc.querySelector(".token"), null, "no bearer token field when sign-in is on");
  const account = doc.getElementById("account-btn");
  assert.equal(text(account), "Account: kim, admin", "name and role, read as two words");
  assert.equal(account.getAttribute("aria-haspopup"), "menu");
  for (const call of calls) {
    assert.equal(call.headers["X-VecShield-CSRF"], "1", `${call.path} carries the CSRF header`);
    assert.equal(call.credentials, "same-origin", `${call.path} sends same-origin credentials`);
  }
  dom.window.close();
});

test("a wrong password is said inline, the password is cleared and refocused", async () => {
  const {dom, window, doc} = await boot("#/overview", {
    "/auth/session": SIGNED_OUT,
    "POST /auth/login": {status: 401, detail: "invalid username or password"},
  });
  type(window, inputNamed(doc, "Username"), "kim");
  type(window, inputNamed(doc, "Password"), "nope");
  submit(window, doc.querySelector("form.auth-form"));
  await settle();
  const error = doc.querySelector(".auth-error");
  assert.equal(error.getAttribute("role"), "alert");
  assert.equal(text(error), "Invalid username or password.");
  assert.equal(inputNamed(doc, "Password").value, "");
  assert.equal(doc.activeElement, inputNamed(doc, "Password"));
  assert.equal(doc.getElementById("content"), null, "still signed out");
  dom.window.close();
});

test("a lockout is reported with the server's reason", async () => {
  const {dom, window, doc} = await boot("#/overview", {
    "/auth/session": SIGNED_OUT,
    "POST /auth/login": {status: 429, detail: "too many failed attempts; try again in 5 minutes"},
  });
  type(window, inputNamed(doc, "Username"), "kim");
  type(window, inputNamed(doc, "Password"), "whatever");
  submit(window, doc.querySelector("form.auth-form"));
  await settle();
  assert.match(text(doc.querySelector(".auth-error")), /Too many failed attempts; try again in 5 minutes\./);
  dom.window.close();
});

// ------------------------------------------------------- password change ---

test("a temporary password leads to the change-password screen before the console", async () => {
  let session = {...signedIn({...VIEWER, must_change_password: true}), password_policy: {min_length: 14}};
  const {dom, window, doc, calls} = await boot("#/findings", {
    "/auth/session": () => session,
    "POST /auth/password": () => { session = signedIn(VIEWER); return {user: VIEWER}; },
    "/admin/history/findings": {findings: []},
  });
  assert.equal(doc.getElementById("auth-title").textContent, "Choose a new password");
  assert.match(doc.body.textContent, /At least 14 characters\./, "the policy's minimum is stated");
  assert.equal(doc.getElementById("content"), null);
  const current = inputNamed(doc, "Current password");
  const next = [...doc.querySelectorAll("input[name='new-password']")][0];
  const confirm = inputNamed(doc, "Confirm new password");
  assert.equal(doc.activeElement, current);
  assert.equal(next.getAttribute("aria-describedby"), "password-rule");
  const form = doc.querySelector("form.auth-form");

  type(window, current, "temporary-password");
  type(window, next, "short");
  submit(window, form);
  assert.equal(text(doc.querySelector(".auth-error")), "Use at least 14 characters.");
  assert.equal(calls.filter(c => c.path === "/auth/password").length, 0, "nothing sent");

  type(window, next, "a much longer passphrase");
  type(window, confirm, "a different passphrase");
  submit(window, form);
  assert.equal(text(doc.querySelector(".auth-error")), "The new passwords do not match.");
  assert.equal(doc.activeElement, confirm);

  type(window, confirm, "a much longer passphrase");
  submit(window, form);
  await settle(5);
  assert.deepEqual(calls.find(c => c.path === "/auth/password").body,
                   {current_password: "temporary-password", new_password: "a much longer passphrase"});
  assert.ok(doc.getElementById("content"), "the console follows");
  assert.equal(window.location.hash, "#/findings");
  dom.window.close();
});

test("the server's policy refusal is shown inline", async () => {
  const {dom, window, doc} = await boot("#/overview", {
    "/auth/session": signedIn({...VIEWER, must_change_password: true}),
    "POST /auth/password": {status: 400, detail: "that password is too common; choose another"},
  });
  type(window, inputNamed(doc, "Current password"), "temporary-password");
  type(window, doc.querySelector("input[name='new-password']"), "password1234");
  type(window, inputNamed(doc, "Confirm new password"), "password1234");
  submit(window, doc.querySelector("form.auth-form"));
  await settle();
  assert.equal(text(doc.querySelector(".auth-error")), "That password is too common; choose another.");
  dom.window.close();
});

test("a 403 'password change required' from any request opens the change-password screen", async () => {
  const {dom, doc} = await boot("#/stores", {
    "/auth/session": signedIn(VIEWER),
    "/admin/estate": {status: 403, detail: "password change required"},
  });
  await settle();
  assert.equal(doc.getElementById("auth-title")?.textContent, "Choose a new password");
  assert.equal(doc.getElementById("content"), null);
  assert.ok(button(doc, "Sign out"), "the wrong person can leave");
  dom.window.close();
});

// -------------------------------------------------------- session expiry ---

test("a 401 mid-session returns to sign-in and then to the same page", async () => {
  let expired = false;
  let session = signedIn(ADMIN);
  const {dom, window, doc, run} = await boot("#/overview", {
    "/auth/session": () => session,
    "/admin/estate": () => (expired ? {status: 401, detail: "session expired"} : BASE["/admin/estate"]),
    "POST /auth/login": () => { expired = false; session = signedIn(ADMIN); return {user: ADMIN}; },
  });
  assert.ok(doc.getElementById("content"));
  expired = true;
  window.location.hash = "#/stores";
  await settle(5);
  assert.equal(doc.getElementById("auth-title")?.textContent, "Sign in");
  assert.match(doc.body.textContent, /Your session ended/);
  assert.equal(window.location.hash, "#/stores", "the hash is where the reader will return");
  assert.equal(run("paletteEntries().filter(e => e.group === 'Stores').length"), 0,
               "data read in the old session is dropped");
  type(window, inputNamed(doc, "Username"), "kim");
  type(window, inputNamed(doc, "Password"), "correct horse battery");
  submit(window, doc.querySelector("form.auth-form"));
  await settle(5);
  assert.equal(doc.getElementById("page-title").textContent, "Stores");
  dom.window.close();
});

test("signing out ends the session and says so", async () => {
  const {dom, doc, calls, run} = await boot("#/overview", {"/auth/session": signedIn(ADMIN),
                                                           "POST /auth/logout": {ok: true}});
  doc.getElementById("account-btn").click();
  const items = [...doc.querySelectorAll(".menu-pop [role='menuitem']")].map(text);
  assert.deepEqual(items, ["Settings", "Sign out"]);
  button(doc, "Sign out").click();
  await settle();
  assert.ok(calls.some(c => c.path === "/auth/logout" && c.method === "POST"));
  assert.match(doc.body.textContent, /You signed out\./);
  assert.equal(run("isAdmin()"), false, "the signed-out user is forgotten");
  dom.window.close();
});

test("with sign-in off the console keeps the bearer token field and has no account menu", async () => {
  const {dom, doc} = await boot("#/overview", {"/auth/session": OPEN});
  assert.ok(doc.querySelector("input.token"));
  assert.equal(doc.getElementById("account-btn"), null);
  assert.ok(![...doc.querySelectorAll("#nav-system button")].some(b => /Users/.test(b.textContent)));
  dom.window.close();
});

test("a server without /auth/session is treated as a token deployment", async () => {
  const {dom, doc} = await boot("#/overview", {"/auth/session": {status: 404, detail: "Not Found"}});
  assert.ok(doc.getElementById("content"));
  assert.ok(doc.querySelector("input.token"));
  dom.window.close();
});

// ----------------------------------------------------------------- users ---

test("Users is offered to an admin only, and only when sign-in is on", async () => {
  const admin = await boot("#/overview", {"/auth/session": signedIn(ADMIN)});
  const names = [...admin.doc.querySelectorAll("#nav-system button")].map(text);
  assert.deepEqual(names, ["Audit log", "Alerting", "Status", "Users"]);
  assert.equal(admin.run(`paletteEntries().some(e => e.label === "System: Users")`), true);
  admin.dom.window.close();

  const viewer = await boot("#/users", {"/auth/session": signedIn(VIEWER)});
  assert.ok(![...viewer.doc.querySelectorAll("#nav-system button")].some(b => /Users/.test(b.textContent)));
  assert.equal(viewer.run(`paletteEntries().some(e => e.label === "System: Users")`), false);
  assert.match(viewer.doc.getElementById("content").textContent, /Only an admin can manage users/);
  assert.ok(!viewer.calls.some(c => c.path === "/auth/users"), "a viewer's console does not ask");
  viewer.dom.window.close();
});

test("the Users table shows roles as chips, status, last sign-in and who created each account", async () => {
  const {dom, doc} = await boot("#/users", {"/auth/session": signedIn(ADMIN)});
  const rows = [...doc.querySelectorAll("#content tbody tr")];
  assert.equal(rows.length, 3);
  const cells = rows.map(r => [...r.children].map(td => text(td)));
  assert.match(cells[0][0], /^kim \(you\)$/);
  assert.deepEqual([...rows[1].querySelectorAll(".role-chips .tag")].map(text), ["operator", "viewer"],
                   "most privileged first");
  assert.match(cells[0][2], /active/);
  assert.match(cells[1][2], /must change password/);
  assert.match(cells[2][2], /disabled/);
  assert.equal(cells[1][3], "never");
  assert.equal(cells[1][4], "kim");
  assert.equal(rows[0].children[1].getAttribute("data-label"), "Roles", "cards keep their labels");
  assert.deepEqual(await axeViolations(dom), []);
  dom.window.close();
});

test("adding a user sends a temporary password and the chosen roles", async () => {
  const {dom, window, doc, calls} = await boot("#/users", {
    "/auth/session": signedIn(ADMIN),
    "POST /auth/users": {user: {username: "new"}},
  });
  button(doc, "Add user").click();
  const panel = doc.getElementById("add-user-panel");
  assert.ok(panel, "the form is inline, not a dialog");
  assert.equal(doc.querySelector("[role='dialog']"), null);
  assert.match(panel.textContent, /choose their own password the first time they sign in/);
  type(window, inputNamed(doc, "Username"), "new");
  type(window, inputNamed(doc, "Temporary password"), "short");
  submit(window, panel.querySelector("form"));
  assert.match(text(panel.querySelector(".auth-error")), /at least 12 characters/);
  type(window, inputNamed(doc, "Temporary password"), "a temporary passphrase");
  panel.querySelector("input[value='operator']").checked = true;
  submit(window, panel.querySelector("form"));
  await settle();
  assert.deepEqual(calls.find(c => c.path === "/auth/users" && c.method === "POST").body,
                   {username: "new", password: "a temporary passphrase", roles: ["viewer", "operator"]});
  assert.equal(doc.getElementById("add-user-panel"), null, "the panel closes");
  assert.match(doc.querySelector(".users-notice").textContent, /new was added/);
  dom.window.close();
});

test("roles are edited inline and a server refusal is shown with its reason", async () => {
  const {dom, window, doc, calls} = await boot("#/users", {
    "/auth/session": signedIn(ADMIN),
    "PATCH /auth/users/kim": {status: 409, detail: "cannot remove the last admin"},
  });
  const kimRow = doc.querySelector("#content tbody tr");
  button(kimRow, "Edit roles").click();
  const edit = doc.querySelector(".user-edit-row");
  assert.ok(edit, "the editor opens under the row");
  assert.equal(edit.firstElementChild.getAttribute("data-label"), null);
  edit.querySelector("input[value='admin']").checked = false;
  edit.querySelector("input[value='viewer']").checked = true;
  submit(window, edit.querySelector("form"));
  await settle();
  assert.deepEqual(calls.find(c => c.method === "PATCH").body, {roles: ["viewer"]});
  assert.equal(text(doc.querySelector(".user-edit-row .auth-error")), "Cannot remove the last admin.");
  dom.window.close();
});

test("disabling asks first, and a guard's refusal is reported", async () => {
  const {dom, doc, calls} = await boot("#/users", {
    "/auth/session": signedIn(ADMIN),
    "PATCH /auth/users/kim": {status: 409, detail: "you cannot disable your own account"},
  });
  const kimRow = doc.querySelector("#content tbody tr");
  kimRow.querySelector(".row-more").click();
  button(kimRow, "Disable").click();
  const dialog = doc.querySelector("[role='alertdialog']");
  assert.match(dialog.textContent, /Disable kim\?/);
  assert.equal(calls.filter(c => c.method === "PATCH").length, 0, "nothing before confirming");
  dialog.querySelector("form").dispatchEvent(new dom.window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  assert.deepEqual(calls.find(c => c.method === "PATCH").body, {disabled: true});
  assert.match(doc.querySelector(".users-notice").textContent, /You cannot disable your own account\./);
  dom.window.close();
});

test("resetting a password is an inline form that says what happens next", async () => {
  const {dom, window, doc, calls} = await boot("#/users", {
    "/auth/session": signedIn(ADMIN),
    "POST /auth/users/val/password": {user: {username: "val"}},
  });
  const valRow = doc.querySelectorAll("#content tbody tr")[1];
  valRow.querySelector(".row-more").click();
  button(valRow, "Reset password").click();
  const edit = doc.querySelector(".user-edit-row");
  assert.match(edit.textContent, /choose a new one at next sign-in/);
  type(window, edit.querySelector("input[type='password']"), "another temporary one");
  submit(window, edit.querySelector("form"));
  await settle();
  assert.deepEqual(calls.find(c => c.path === "/auth/users/val/password").body,
                   {new_password: "another temporary one"});
  assert.match(doc.querySelector(".users-notice").textContent, /Password for val reset/);
  dom.window.close();
});

// ------------------------------------------------------------ store page ---

test("Open on a store routes to its own page, with the detail at the top and focused", async () => {
  const {dom, window, doc} = await boot("#/stores", {"/auth/session": OPEN});
  const prodRow = [...doc.querySelectorAll("#content tbody tr")].find(r => r.textContent.includes("prod"));
  button(prodRow, "Open").click();
  await settle(5);
  assert.equal(window.location.hash, "#/stores?store=prod");
  const content = doc.getElementById("content");
  // The back link's arrow is an icon now (one shape for every record's way
  // back), so its text is the label alone.
  const back = content.querySelector(".store-back");
  assert.equal(back.textContent.trim(), "All stores");
  assert.ok(back.classList.contains("page-back") && back.querySelector("svg.icon"), "the shared back link, with its icon");
  const title = doc.getElementById("page-title");
  assert.equal(title.textContent, "prod");
  assert.equal(doc.activeElement, title, "focus moves to the store's heading");
  assert.ok(!content.textContent.includes("Can inspect"), "the estate table is replaced, not stacked above");
  for (const label of ["Full schema", "Findings for this store", "Crypto posture", "Edit connection"]) {
    assert.ok(button(content, label), `${label} is kept`);
  }
  assert.deepEqual([...content.querySelectorAll("tbody td.mono")].map(td => td.textContent), ["docs", "faq"]);
  button(content, "Findings for this store").click();
  assert.equal(window.location.hash, "#/findings?store=prod");
  dom.window.close();
});

test("a store deep link loads directly, and All stores goes back", async () => {
  const {dom, window, doc, calls} = await boot("#/stores?store=prod", {"/auth/session": OPEN});
  assert.equal(doc.getElementById("page-title").textContent, "prod");
  assert.ok(!calls.some(c => c.path === "/admin/estate?probe=true"), "one store's page does not probe them all");
  assert.match(doc.querySelector(".store-facts").textContent, /tenant_id/);
  doc.querySelector(".store-back").click();
  assert.equal(window.location.hash, "#/stores");
  dom.window.close();
});

test("a deep link to a store that is not registered says so", async () => {
  const {dom, doc} = await boot("#/stores?store=gone", {"/auth/session": OPEN});
  assert.equal(doc.getElementById("page-title").textContent, "gone");
  assert.match(doc.getElementById("content").textContent, /No store with this id is registered/);
  dom.window.close();
});

const COMPARED = {
  store_id: "prod", compared: true, before_audit_id: "audit-a", after_audit_id: "audit-b",
  before_at: "2026-09-20T10:00:00Z", after_at: "2026-09-27T10:00:00Z", persistent: 4,
  new: [{fingerprint: "fp1", id: "f-new", title: "PII detected in collection 'faq'", severity: "high",
         category: "data_classification", collection: "faq"}],
  new_total: 1,
  resolved: [{fingerprint: "fp2", id: "f-old", title: "Prompt-injection content in 'docs'", severity: "medium",
              category: "rag_integrity", collection: "docs"}],
  resolved_total: 1,
  not_retested: [{fingerprint: "fp3", id: "f-iso", title: "Tenant isolation gap", severity: "high",
                  category: "isolation", collection: "docs"}],
  not_retested_total: 1,
};
const INVENTORY_CHANGES = {store_id: "prod", events: [
  {kind: "collection_added", severity: "info", summary: "Collection 'docs_backup' is new."},
  {kind: "possible_shadow_copy", severity: "high",
   summary: "'docs_backup' looks like a copy of 'docs', holding pii."}],
  note: "Aliases are compared only when both inventories observed them."};

test("the store page says what changed since the previous audit", async () => {
  const {dom, window, doc} = await boot("#/stores?store=prod", {
    "/auth/session": OPEN, "/stores/prod/changes": COMPARED, "/stores/prod/inventory/changes": INVENTORY_CHANGES});
  const box = doc.querySelector(".store-changes");
  assert.ok(box, "the panel renders");
  const panelText = text(box);
  for (const chip of ["1 new", "1 resolved", "1 not re-tested, not resolved", "4 still present"]) {
    assert.ok(panelText.includes(chip), `${chip} is counted`);
  }
  assert.match(panelText, /New \(1\).*PII detected in collection 'faq'/);
  assert.match(panelText, /Not re-tested \(1\).*Tenant isolation gap/);
  const events = [...box.querySelectorAll(".change-group:last-child li")].map(text);
  assert.match(events[0], /looks like a copy/, "the shadow copy leads the inventory changes");
  button(box, "PII detected in collection 'faq'").click();
  assert.match(window.location.hash, /^#\/findings\?/);
  assert.match(window.location.hash, /finding=f-new/);
  dom.window.close();
});

test("a store with one saved audit has nothing to compare, which is not no changes", async () => {
  const {dom, doc} = await boot("#/stores?store=prod", {
    "/auth/session": OPEN,
    "/stores/prod/changes": {store_id: "prod", compared: false, after_audit_id: "audit-b",
                             reason: "this store has one saved audit; the next audit will be compared with it"},
    "/stores/prod/inventory/changes": {status: 404, detail: "no saved audit"}});
  const content = doc.getElementById("content");
  assert.match(content.textContent, /Since the last audit/);
  assert.match(content.textContent, /This store has one saved audit; the next audit will be compared with it\./);
  assert.ok(!content.querySelector(".store-changes"), "no counts without a comparison");
  assert.doesNotMatch(content.textContent, /No finding appeared/);
  dom.window.close();
});

test("a failed comparison is an error with a retry, not an empty panel", async () => {
  const {dom, doc} = await boot("#/stores?store=prod", {
    "/auth/session": OPEN, "/stores/prod/changes": {status: 500, detail: "history unavailable"}});
  const content = doc.getElementById("content");
  const state = [...content.querySelectorAll(".panel")].find(p => p.textContent.includes("Since the last audit"))
    .querySelector(".state-error");
  assert.ok(state, "an error state");
  assert.ok(button(state, "Retry"));
  dom.window.close();
});

// ------------------------------------------------------------ NLP status ---

test("degraded NLP detection shows the install command as a copyable line", async () => {
  const {dom, doc} = await boot("#/status", {
    "/auth/session": OPEN,
    "/readyz": {status: "ready", checks: {}},
    "/admin/detection": {status: "degraded", mode: "auto", requested_model: "en_core_web_hftrf",
                         reason: "NLP model 'en_core_web_hftrf' is not installed; install it with " +
                                 "`vecshield-platform nlp install en_core_web_hftrf`",
                         install_command: "vecshield-platform nlp install en_core_web_hftrf"},
  });
  const line = doc.querySelector(".install-line");
  assert.ok(line);
  assert.equal(line.querySelector("code").textContent, "vecshield-platform nlp install en_core_web_hftrf");
  assert.ok(button(line, "Copy"));
  const content = doc.getElementById("content").textContent;
  assert.match(content, /NLP model 'en_core_web_hftrf' is not installed\./);
  assert.equal(content.split("nlp install en_core_web_hftrf").length - 1, 1, "the command appears once");
  dom.window.close();
});

test("without an install command, nothing new is shown", async () => {
  const {dom, doc} = await boot("#/status", {
    "/auth/session": OPEN,
    "/readyz": {status: "ready", checks: {}},
    "/admin/detection": {status: "degraded", requested_model: "en_core_web_lg", reason: "model missing"},
  });
  assert.equal(doc.querySelector(".install-line"), null);
  dom.window.close();
});
