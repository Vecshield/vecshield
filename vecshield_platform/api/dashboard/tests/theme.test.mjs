import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

// The console follows the system theme unless someone chooses otherwise, and
// never paints the wrong one first. theme.js runs synchronously in <head>
// before the stylesheet (the CSP forbids inline script); the console keeps the
// theme current afterwards.

const themeJs = await readFile(new URL("../dist/assets/theme.js", import.meta.url), "utf8");
const html = await readFile(new URL("../dist/index.html", import.meta.url), "utf8");
const shell = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");

const KEY = "vecshield_theme";
const SIGNED_OUT = {login_enabled: true, authenticated: false, user: null, password_policy: {min_length: 12}};
const OPEN = {login_enabled: false, authenticated: true, user: null, password_policy: {min_length: 12}};
const RESPONSES = {
  "/admin/stores": {stores: [{store_id: "prod", kind: "qdrant"}]},
  "/admin/policies": {policies: []},
  "/admin/policy-templates": {templates: []},
  "/version": {approvals: {separation_of_duties: "required"}},
  "/healthz": {status: "ok", stores: 1},
  "/admin/history": {jobs: [], stats: {total_findings: 0, by_severity: {}}},
  "/admin/estate": {stores: []},
};

// A stand-in for the system colour-scheme query whose answer can change, as
// it does when the OS switches to dark at sunset.
function fakeSystem(dark) {
  const listeners = [];
  const scheme = {
    media: "(prefers-color-scheme: dark)",
    get matches() { return dark; },
    addEventListener: (type, fn) => { if (type === "change") listeners.push(fn); },
    removeEventListener() {},
  };
  const other = {matches: false, addEventListener() {}, removeEventListener() {}};
  return {
    matchMedia: query => (query.includes("prefers-color-scheme") ? scheme : other),
    listeners,
    change(next) { dark = next; for (const fn of listeners) fn({matches: next, media: scheme.media}); },
  };
}

function page({theme = "light", stored, system, blockStorage = false} = {}) {
  const dom = new JSDOM(
    `<!doctype html><html lang="en" data-theme="${theme}"><head></head><body><div id="root"></div></body></html>`,
    {url: "https://console.test/#/stores", pretendToBeVisual: true, runScripts: "outside-only"});
  const {window} = dom;
  if (stored !== undefined) window.localStorage.setItem(KEY, stored);
  if (blockStorage) {
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      get() { throw new window.DOMException("The operation is insecure.", "SecurityError"); },
    });
  }
  if (system) window.matchMedia = system.matchMedia;
  return {dom, window, doc: window.document};
}

const themeOf = doc => doc.documentElement.getAttribute("data-theme");

async function bootConsole(options = {}, session = SIGNED_OUT) {
  const env = page(options);
  const {window} = env;
  window.fetch = async path => {
    const base = path.split("?")[0];
    const value = base === "/auth/session" ? session : (RESPONSES[base] ?? {});
    return {ok: true, status: 200, headers: {get: () => "application/json"},
            json: async () => value, text: async () => JSON.stringify(value)};
  };
  window.eval(shell);
  await window.eval("boot()");
  for (let i = 0; i < 3; i++) await new Promise(r => setTimeout(r, 20));
  const toggle = () => env.doc.getElementById("theme-toggle");
  return {...env, toggle, stored: () => window.localStorage.getItem(KEY)};
}

// ------------------------------------------------------------- theme.js ---

test("theme.js applies a stored choice over the system preference", () => {
  for (const [stored, dark, expected] of [["dark", false, "dark"], ["light", true, "light"]]) {
    const {window, doc} = page({stored, system: fakeSystem(dark)});
    window.eval(themeJs);
    assert.equal(themeOf(doc), expected, `stored ${stored}, system ${dark ? "dark" : "light"}`);
    window.close();
  }
});

test("theme.js follows the system when nothing is stored", () => {
  for (const dark of [true, false]) {
    const {window, doc} = page({theme: dark ? "light" : "dark", system: fakeSystem(dark)});
    window.eval(themeJs);
    assert.equal(themeOf(doc), dark ? "dark" : "light");
    window.close();
  }
});

test("theme.js ignores a stored value that is not a theme", () => {
  const {window, doc} = page({stored: "blue", system: fakeSystem(true)});
  window.eval(themeJs);
  assert.equal(themeOf(doc), "dark");
  window.close();
});

test("theme.js falls back to light where the system cannot be asked", () => {
  const {window, doc} = page({theme: "dark"});
  assert.equal(window.matchMedia, undefined, "jsdom has no matchMedia");
  window.eval(themeJs);
  assert.equal(themeOf(doc), "light");
  window.close();
});

test("theme.js survives storage that throws", () => {
  const {window, doc} = page({system: fakeSystem(true), blockStorage: true});
  assert.throws(() => window.localStorage, /insecure/);
  window.eval(themeJs);
  assert.equal(themeOf(doc), "dark", "the system preference still applies");
  window.close();
});

test("theme.js leaves no globals behind", () => {
  const {window} = page({system: fakeSystem(false)});
  const before = new Set(Object.getOwnPropertyNames(window));
  window.eval(themeJs);
  const added = Object.getOwnPropertyNames(window).filter(name => !before.has(name));
  assert.deepEqual(added, []);
  window.close();
});

test("theme.js is small, self-contained and evaluates no strings", () => {
  assert.ok(themeJs.length < 1024, `theme.js is ${themeJs.length}B; it blocks first paint`);
  assert.match(themeJs, /^\s*(\/\/[^\n]*\n\s*)*\(function \(\) \{/, "an IIFE");
  assert.doesNotMatch(themeJs, /\beval\s*\(|new Function|\bFunction\s*\(|setTimeout\s*\(\s*["'`]|setInterval|document\.write|innerHTML|\bimport\b|\bexport\b/);
  assert.doesNotMatch(themeJs, /\.style\b|cssText/, "no inline style under style-src 'self'");
});

// ----------------------------------------------------------- index.html ---

test("index.html loads theme.js synchronously in <head>, before the stylesheet", () => {
  const head = html.slice(html.indexOf("<head>"), html.indexOf("</head>"));
  const tag = head.match(/<script\b[^>]*src="\/static\/assets\/theme\.js"[^>]*><\/script>/);
  assert.ok(tag, "theme.js is loaded in <head>");
  assert.doesNotMatch(tag[0], /\b(defer|async|type=)/, "a classic, blocking script");
  const at = head.indexOf(tag[0]);
  assert.ok(at < head.indexOf('rel="stylesheet"'), "before the stylesheet");
  assert.ok(at < head.indexOf('rel="preload"'), "before the font preload");
  assert.match(html, /<html lang="en" data-theme="light">/, "light stays the no-script default");
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/, "no inline script under script-src 'self'");
});

// ------------------------------------------------------------- console ---

test("boot leaves the page's theme alone when nothing is stored", async () => {
  const {window, doc} = await bootConsole({theme: "dark", system: fakeSystem(false)});
  assert.equal(themeOf(doc), "dark", "theme.js already chose; boot does not second-guess it");
  window.close();
});

test("boot re-applies a stored choice", async () => {
  const {window, doc, toggle} = await bootConsole({theme: "dark", stored: "light", system: fakeSystem(true)});
  assert.equal(themeOf(doc), "light");
  assert.equal(toggle().getAttribute("aria-label"), "Switch to dark theme");
  window.close();
});

test("boot survives storage that throws", async () => {
  const {window, doc, toggle} = await bootConsole({theme: "dark", system: fakeSystem(true), blockStorage: true});
  assert.equal(themeOf(doc), "dark");
  assert.ok(doc.getElementById("auth-title"), "the sign-in screen still renders");
  toggle().click();
  assert.equal(themeOf(doc), "light", "the toggle still works for this page");
  window.close();
});

test("toggling away from the system stores the choice; toggling back follows the system again", async () => {
  for (const dark of [false, true]) {
    const system = dark ? "dark" : "light";
    const other = dark ? "light" : "dark";
    const {window, doc, toggle, stored} = await bootConsole({theme: system, system: fakeSystem(dark)});
    assert.equal(toggle().getAttribute("aria-label"), `Switch to ${other} theme`);
    toggle().click();
    assert.equal(themeOf(doc), other);
    assert.equal(stored(), other, "an override is remembered");
    assert.equal(toggle().getAttribute("aria-label"), `Switch to ${system} theme`);
    toggle().click();
    assert.equal(themeOf(doc), system);
    assert.equal(stored(), null, "matching the system drops the override");
    window.close();
  }
});

test("without a system preference, every toggle is stored", async () => {
  const {window, doc, toggle, stored} = await bootConsole({theme: "light"});
  toggle().click();
  assert.equal(themeOf(doc), "dark");
  assert.equal(stored(), "dark");
  toggle().click();
  assert.equal(stored(), "light");
  window.close();
});

test("a system change applies live only while nothing is stored", async () => {
  const system = fakeSystem(false);
  const {window, doc, toggle} = await bootConsole({theme: "light", system}, OPEN);
  assert.ok(doc.getElementById("content"), "the console shell is up");
  assert.equal(system.listeners.length, 1, "one listener, registered once");
  system.change(true);
  assert.equal(themeOf(doc), "dark");
  assert.equal(toggle().getAttribute("aria-label"), "Switch to light theme", "the control follows");
  system.change(false);
  assert.equal(themeOf(doc), "light");

  toggle().click(); // an explicit dark override
  assert.equal(window.localStorage.getItem(KEY), "dark");
  system.change(true);
  system.change(false);
  assert.equal(themeOf(doc), "dark", "an override outlasts system changes");
  window.close();
});
