import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import axe from "axe-core";
import { JSDOM } from "jsdom";

// The reader's own Settings: profile, password and sessions for a local
// account, an honest "managed elsewhere" for every other sign-in method, and
// the two browser preferences (theme, time zone). Each test boots the shipped
// console through its real boot().

const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");
const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");

const KIM = {username: "kim", roles: ["operator"], effective_roles: ["operator", "viewer"],
             must_change_password: false, source: "session"};
const signedIn = user => ({login_enabled: true, authenticated: true, user, password_policy: {min_length: 12}});
const OPEN = {login_enabled: false, authenticated: true,
              user: {username: "admin", roles: ["admin"], effective_roles: ["admin"], source: "open"},
              password_policy: {min_length: 12}};
const JWT = {login_enabled: true, authenticated: true,
             user: {username: "svc-ci", roles: ["viewer"], effective_roles: ["viewer"], source: "jwt"},
             password_policy: {min_length: 12}};

const FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0";
const SAFARI_IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
const SESSIONS = {
  current: "aaaaaaaaaaaaaaaa",
  sessions: [
    {id: "aaaaaaaaaaaaaaaa", created_at: "2026-10-07T08:00:00Z", last_seen_at: "2026-10-07T09:00:00Z",
     expires_at: "2026-10-07T20:00:00Z", user_agent: FIREFOX},
    {id: "bbbbbbbbbbbbbbbb", created_at: "2026-10-06T08:00:00Z", last_seen_at: "2026-10-07T07:00:00Z",
     expires_at: "2026-10-07T19:00:00Z", user_agent: SAFARI_IOS},
  ],
};

const BASE = {
  "/admin/stores": {stores: []},
  "/version": {approvals: {separation_of_duties: "required"}},
  "/healthz": {status: "ok", stores: 0},
  "/auth/sessions": SESSIONS,
};

async function boot(hash, responses = {}, {stored = {}, systemDark = false} = {}) {
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="light"><head><style>${css}</style></head>` +
    `<body><div id="root"></div></body></html>`,
    {url: `https://console.test/${hash}`, pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  for (const [key, value] of Object.entries(stored)) window.localStorage.setItem(key, value);
  window.matchMedia = query => ({matches: query.includes("dark") && systemDark, media: query,
                                 addEventListener() {}, removeEventListener() {}});
  const calls = [];
  const all = {...BASE, ...responses};
  window.fetch = async (path, opts = {}) => {
    const method = opts.method || "GET";
    calls.push({path, method, body: opts.body ? JSON.parse(opts.body) : undefined});
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

const settle = async (n = 4) => { for (let i = 0; i < n; i++) await new Promise(r => setTimeout(r, 20)); };
const text = node => node.textContent.replace(/\s+/g, " ").trim();
const button = (root, label) => [...root.querySelectorAll("button")].find(b => text(b) === label);
const panelNamed = (doc, title) => [...doc.querySelectorAll("#content .panel")]
  .find(p => p.querySelector("h2")?.textContent.trim() === title);
// A Profile fact's value, by its label.
const fact = (doc, label) => {
  const dt = [...panelNamed(doc, "Profile").querySelectorAll("dt")].find(d => text(d) === label);
  return dt ? text(dt.nextElementSibling) : undefined;
};
const inputNamed = (doc, labelText) => [...doc.querySelectorAll("label.field")]
  .find(l => l.querySelector("span")?.textContent.trim() === labelText)?.querySelector("input");

function type(window, input, value) {
  input.value = value;
  input.dispatchEvent(new window.Event("input", {bubbles: true}));
}

function submit(window, form) {
  form.dispatchEvent(new window.Event("submit", {bubbles: true, cancelable: true}));
}

// --------------------------------------------------------------- reaching ---

test("the account menu offers Settings and Sign out, and Settings opens the page", async () => {
  const {dom, doc, window} = await boot("#/overview", {"/auth/session": signedIn(KIM)});
  doc.getElementById("account-btn").click();
  const items = [...doc.querySelectorAll(".menu-pop [role='menuitem']")].map(text);
  assert.deepEqual(items, ["Settings", "Sign out"]);
  button(doc, "Settings").click();
  await settle();
  assert.equal(window.location.hash, "#/settings");
  assert.equal(doc.getElementById("page-title").textContent, "Settings");
  assert.equal(doc.querySelector("#nav [data-view='settings'], #nav-system [data-view='settings']"), null,
               "a personal page, not a sidebar destination");
  dom.window.close();
});

test("the palette's Change password lands on Settings with the current password focused", async () => {
  const {dom, doc, window, run} = await boot("#/overview", {"/auth/session": signedIn(KIM)});
  const entry = run("paletteEntries().find(e => e.label === 'Change password')");
  assert.ok(entry, "offered in the palette");
  entry.run();
  await settle();
  assert.equal(window.location.hash, "#/settings?focus=password");
  assert.equal(doc.activeElement, inputNamed(doc, "Current password"));
  dom.window.close();
});

test("with sign-in off there is no account menu, but a Settings button reaches the page", async () => {
  const {dom, doc, window} = await boot("#/overview", {"/auth/session": OPEN});
  assert.equal(doc.getElementById("account-btn"), null);
  doc.getElementById("settings-btn").click();
  await settle();
  assert.equal(window.location.hash, "#/settings");
  dom.window.close();
});

// ---------------------------------------------------------------- profile ---

test("a local account sees its profile, password form and sessions", async () => {
  const {dom, doc, calls} = await boot("#/settings", {"/auth/session": signedIn(KIM)});
  assert.equal(fact(doc, "Username"), "kim");
  assert.equal(fact(doc, "Roles"), "operator Includes viewer.");
  assert.equal(fact(doc, "Sign-in method"), "Local account");
  assert.ok(fact(doc, "Signed in since"), "filled from the current session");
  assert.doesNotMatch(fact(doc, "Signed in since"), /Reading|Unknown/);
  assert.ok(calls.some(c => c.path === "/auth/sessions" && c.method === "GET"));

  const security = panelNamed(doc, "Security");
  assert.ok(inputNamed(doc, "Current password"));
  const rows = [...security.querySelectorAll("tbody tr")];
  assert.equal(rows.length, 2);
  assert.match(text(rows[0]), /Firefox on Windows/);
  assert.match(text(rows[0]), /this session/i);
  assert.match(text(rows[1]), /Safari on iOS/);
  assert.equal(rows[1].querySelector("[title]").getAttribute("title"), SAFARI_IOS,
               "the full user agent is one hover away");
  assert.equal(button(security, "Sign out other sessions").disabled, false);
  dom.window.close();
});

for (const [name, session, pattern] of [
  ["a JWT caller", JWT, /identity provider manages your password/],
  ["an open deployment", OPEN, /Sign-in is off on this server/],
]) {
  test(`${name} is told where sign-in is managed, and no session call is made`, async () => {
    const {dom, doc, calls} = await boot("#/settings", {"/auth/session": session});
    const security = text(panelNamed(doc, "Security"));
    assert.match(security, pattern);
    assert.equal(inputNamed(doc, "Current password"), undefined);
    assert.equal(calls.filter(c => c.path.startsWith("/auth/sessions")).length, 0);
    assert.ok(panelNamed(doc, "Preferences"), "preferences still apply");
    dom.window.close();
  });
}

// --------------------------------------------------------------- sessions ---

test("signing out another session revokes it by id and redraws the list", async () => {
  let listing = SESSIONS;
  const {dom, doc, calls} = await boot("#/settings", {
    "/auth/session": signedIn(KIM),
    "/auth/sessions": () => listing,
    "DELETE /auth/sessions/bbbbbbbbbbbbbbbb": () => {
      listing = {...SESSIONS, sessions: SESSIONS.sessions.slice(0, 1)};
      return {ok: true, current: false};
    },
  });
  const security = panelNamed(doc, "Security");
  const other = security.querySelectorAll("tbody tr")[1];
  button(other, "Sign out").click();
  await settle();
  assert.ok(calls.some(c => c.method === "DELETE" && c.path === "/auth/sessions/bbbbbbbbbbbbbbbb"));
  assert.match(text(security), /The Safari on iOS session was signed out\./);
  assert.equal(security.querySelectorAll("tbody tr").length, 1);
  assert.equal(button(security, "Sign out other sessions").disabled, true, "nothing else to sign out");
  dom.window.close();
});

test("signing out every other session asks first, then reports the count", async () => {
  const {dom, doc, calls} = await boot("#/settings", {
    "/auth/session": signedIn(KIM),
    "POST /auth/sessions/revoke-others": {revoked: 1},
  });
  button(panelNamed(doc, "Security"), "Sign out other sessions").click();
  const dialog = doc.querySelector("[role='alertdialog']");
  assert.match(dialog.textContent, /Sign out other sessions\?/);
  assert.equal(calls.filter(c => c.path === "/auth/sessions/revoke-others").length, 0, "nothing before confirming");
  dialog.querySelector("form").dispatchEvent(new dom.window.Event("submit", {bubbles: true, cancelable: true}));
  await settle();
  assert.ok(calls.some(c => c.method === "POST" && c.path === "/auth/sessions/revoke-others"));
  assert.match(text(panelNamed(doc, "Security")), /1 other session signed out\./);
  dom.window.close();
});

test("the current session's Sign out is the ordinary sign-out", async () => {
  const {dom, doc, calls} = await boot("#/settings", {"/auth/session": signedIn(KIM),
                                                      "POST /auth/logout": {ok: true}});
  const mine = panelNamed(doc, "Security").querySelectorAll("tbody tr")[0];
  button(mine, "Sign out").click();
  await settle();
  assert.ok(calls.some(c => c.path === "/auth/logout" && c.method === "POST"));
  assert.match(doc.body.textContent, /You signed out\./);
  dom.window.close();
});

test("a session list that cannot be read says so and offers Retry", async () => {
  const {dom, doc} = await boot("#/settings", {"/auth/session": signedIn(KIM),
                                               "/auth/sessions": {status: 500, detail: "boom"}});
  const security = panelNamed(doc, "Security");
  assert.ok(security.querySelector(".state-error"));
  assert.ok(button(security, "Retry"));
  assert.equal(fact(doc, "Signed in since"), "Unknown");
  dom.window.close();
});

// --------------------------------------------------------------- password ---

test("changing the password in Settings stays on the page and refreshes the sessions", async () => {
  const {dom, window, doc, calls} = await boot("#/settings", {
    "/auth/session": signedIn(KIM),
    "POST /auth/password": {user: KIM},
  });
  type(window, inputNamed(doc, "Current password"), "the old passphrase");
  type(window, inputNamed(doc, "New password"), "a much longer passphrase");
  type(window, inputNamed(doc, "Confirm new password"), "a much longer passphrase");
  const before = calls.filter(c => c.path === "/auth/sessions").length;
  submit(window, doc.querySelector("form.settings-password"));
  await settle();
  assert.deepEqual(calls.find(c => c.path === "/auth/password").body,
                   {current_password: "the old passphrase", new_password: "a much longer passphrase"});
  assert.equal(doc.getElementById("page-title").textContent, "Settings");
  assert.match(text(panelNamed(doc, "Security")), /Password changed\. Your other sessions were signed out\./);
  assert.equal(inputNamed(doc, "Current password").value, "", "the form is cleared");
  assert.ok(calls.filter(c => c.path === "/auth/sessions").length > before);
  dom.window.close();
});

test("a wrong current password is reported on that field", async () => {
  const {dom, window, doc} = await boot("#/settings", {
    "/auth/session": signedIn(KIM),
    "POST /auth/password": {status: 401, detail: "current password is incorrect"},
  });
  type(window, inputNamed(doc, "Current password"), "not my passphrase");
  type(window, inputNamed(doc, "New password"), "a much longer passphrase");
  type(window, inputNamed(doc, "Confirm new password"), "a much longer passphrase");
  submit(window, doc.querySelector("form.settings-password"));
  await settle();
  assert.match(doc.querySelector(".settings-password .auth-error").textContent, /Current password is incorrect\./);
  assert.equal(inputNamed(doc, "Current password").getAttribute("aria-invalid"), "true");
  assert.equal(doc.getElementById("page-title").textContent, "Settings", "still signed in, still here");
  dom.window.close();
});

// ------------------------------------------------------------ preferences ---

test("the theme choice is three-way and System drops the stored override", async () => {
  const {dom, doc, window} = await boot("#/settings", {"/auth/session": signedIn(KIM)},
                                        {stored: {vecshield_theme: "dark"}, systemDark: false});
  const pressed = () => doc.querySelector(".theme-choice [aria-pressed='true']").dataset.choice;
  assert.equal(pressed(), "dark");
  assert.equal(doc.documentElement.dataset.theme, "dark");
  button(doc.querySelector(".theme-choice"), "System").click();
  assert.equal(window.localStorage.getItem("vecshield_theme"), null);
  assert.equal(doc.documentElement.dataset.theme, "light", "follows the system again");
  button(doc.querySelector(".theme-choice"), "Light").click();
  assert.equal(window.localStorage.getItem("vecshield_theme"), "light",
               "an explicit Light is kept even when it matches the system");
  doc.getElementById("theme-toggle").click();
  assert.equal(pressed(), "dark", "the header toggle and Settings agree");
  dom.window.close();
});

test("choosing UTC changes displayed times only, and is kept in this browser", async () => {
  const {dom, doc, window, run} = await boot("#/settings", {"/auth/session": signedIn(KIM)});
  const when = "2026-10-07T08:00:00Z";
  button(doc.querySelector(".time-choice"), "UTC").click();
  assert.equal(window.localStorage.getItem("vecshield_time"), "utc");
  assert.match(run(`localTime("${when}")`), /UTC$/);
  assert.match(run(`localTime("${when}")`), /8:00/);
  assert.match(text(panelNamed(doc, "Preferences")), /Now: .* UTC/);
  const node = run(`formatWhen("${when}")`);
  assert.equal(node.getAttribute("title"), "2026-10-07T08:00:00.000Z", "the hover ISO instant is unchanged");
  doc.querySelector(".time-choice [data-zone='local']").click();
  assert.equal(window.localStorage.getItem("vecshield_time"), null);
  assert.doesNotMatch(run(`localTime("${when}")`), /UTC$/);
  dom.window.close();
});

test("a stored UTC choice applies from the first paint of the console", async () => {
  const {dom, run} = await boot("#/overview", {"/auth/session": signedIn(KIM)}, {stored: {vecshield_time: "utc"}});
  assert.match(run(`localTime("2026-10-07T08:00:00Z")`), /UTC$/);
  dom.window.close();
});

// --------------------------------------------------------- accessibility ---

test("Settings has no structural accessibility violations", async () => {
  const {dom} = await boot("#/settings", {"/auth/session": signedIn(KIM)});
  const results = await axe.run(dom.window.document.body, {
    rules: {"color-contrast": {enabled: false}, "target-size": {enabled: false},
            "scrollable-region-focusable": {enabled: false}},
    elementRef: false,
  });
  const violations = results.violations.map(v => `${v.id}: ${v.help} (${v.nodes[0]?.html?.slice(0, 100)})`);
  assert.deepEqual(violations, []);
  dom.window.close();
});
