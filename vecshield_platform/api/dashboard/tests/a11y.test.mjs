import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

// Keyboard and screen-reader behaviour, exercised against the shipped script.
// This is not a substitute for a real browser audit; it is the part of that
// audit that can run on every commit with no dependencies.
const source = (await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8"))
  .replace(/\nboot\(\);\s*$/, "\n");

let activeDocument = null;

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
  }
  append(...children) {
    for (const raw of children) {
      const c = typeof raw === "string" ? new Element("text", raw) : raw;
      c.parent = this;
      this.children.push(c);
    }
  }
  replaceChildren(...children) { this._text = ""; this.children = []; this.append(...children); }
  setAttribute(key, value) { this.attrs[key] = String(value); }
  getAttribute(key) { return key in this.attrs ? this.attrs[key] : null; }
  removeAttribute(key) { delete this.attrs[key]; }
  addEventListener(key, fn) { this.events[key] = fn; }
  remove() { this.removed = true; if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); }
  click() { return this.events.click?.(); }
  focus() { if (activeDocument) activeDocument.activeElement = this; }
  get className() { return [...this._classes].join(" "); }
  set className(value) { this._classes = new Set(String(value).split(/\s+/).filter(Boolean)); }
  get classList() {
    const set = this._classes;
    return {
      add: (...n) => n.forEach(x => set.add(x)),
      remove: (...n) => n.forEach(x => set.delete(x)),
      contains: n => set.has(n),
      toggle: (n, force) => {
        const on = force === undefined ? !set.has(n) : Boolean(force);
        on ? set.add(n) : set.delete(n);
        return on;
      },
    };
  }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(" "); }
  set textContent(value) { this._text = value; this.children = []; }
}

function find(node, predicate) {
  if (predicate(node)) return node;
  for (const child of node.children || []) {
    const found = find(child, predicate);
    if (found) return found;
  }
  return null;
}

function app(responses = {}, hash = "") {
  const body = new Element("body");
  const rootNode = new Element("div");
  rootNode.setAttribute("id", "root");
  body.append(rootNode);
  const doc = {
    body,
    documentElement: new Element("html"),
    activeElement: null,
    events: {},
    getElementById: id => find(body, el => el.attrs?.id === id) || new Element("div"),
    querySelector: () => null,
    querySelectorAll: selector => {
      const want = selector.replace(/^\./, "");
      const out = [];
      (function collect(node) {
        for (const child of node.children || []) {
          if (child._classes?.has(want)) out.push(child);
          collect(child);
        }
      })(body);
      return out;
    },
    addEventListener(key, fn) { this.events[key] = fn; },
    createElement: tag => new Element(tag),
    createElementNS: (_, tag) => new Element(tag),
    createTextNode: text => new Element("text", text),
  };
  activeDocument = doc;
  const context = vm.createContext({
    Node: Element, FormData, Blob, Intl, URLSearchParams, document: doc,
    URL: {createObjectURL: () => "blob:x", revokeObjectURL() {}},
    setTimeout() {},
    sessionStorage: {getItem: () => null, setItem() {}},
    localStorage: {getItem: () => null, setItem() {}},
    location: {hash},
    window: {addEventListener() {}},
    async fetch(path) {
      const value = responses[path];
      if (value === undefined) throw new Error(`Unexpected request: ${path}`);
      // A numeric `status` means an HTTP failure; a job's status: "running" is
      // data. Without this the fixture returned every error as a success.
      if (typeof value.status === "number") {
        return {ok: false, status: value.status, statusText: "Error",
                headers: {get: () => "application/json"},
                json: async () => ({detail: value.detail})};
      }
      return {ok: true, status: 200, headers: {get: () => "application/json"},
              json: async () => value};
    },
  });
  vm.runInContext(source, context);
  return {context, doc, body};
}

function press(node, key, extra = {}) {
  let defaultPrevented = false;
  node.events.keydown({key, preventDefault: () => { defaultPrevented = true; }, ...extra});
  return defaultPrevented;
}

// ---------------------------------------------------------------- dialogs ---

test("opening a dialog moves focus into it and closing returns it", () => {
  const {context, doc} = app();
  const opener = new Element("button");
  opener.focus();
  assert.equal(doc.activeElement, opener);

  context.modal("Edit store", new Element("div"), () => {}, "Save");
  assert.notEqual(doc.activeElement, opener, "focus must enter the dialog");
  assert.ok(doc.activeElement.tagName === "BUTTON" || doc.activeElement.tagName === "INPUT");

  context.closeModal();
  assert.equal(doc.activeElement, opener, "focus must return to whatever opened it");
});

test("Escape closes a dialog", () => {
  const {context, doc, body} = app();
  const backdrop = context.modal("Details", new Element("div"), null, "Close");
  assert.ok(find(body, n => n.attrs?.id === "modal-backdrop"), "dialog is mounted");
  assert.equal(press(backdrop, "Escape"), true, "Escape is handled, not passed through");
  assert.equal(find(body, n => n.attrs?.id === "modal-backdrop"), null, "dialog is dismissed");
  // Closing twice is harmless: the dialog is already gone.
  context.closeModal();
});

test("Tab cycles within the dialog instead of escaping to the page", () => {
  const {context, doc} = app();
  const field = new Element("input");
  const backdrop = context.modal("Add policy", field, () => {}, "Create");
  const focusable = context.focusableWithin(backdrop.children[0]);
  assert.ok(focusable.length >= 3, "close, field, cancel, submit");

  const last = focusable[focusable.length - 1];
  last.focus();
  assert.equal(press(backdrop, "Tab"), true);
  assert.equal(doc.activeElement, focusable[0], "wraps forward to the first control");

  assert.equal(press(backdrop, "Tab", {shiftKey: true}), true);
  assert.equal(doc.activeElement, last, "wraps backward to the last control");
});

test("a dialog names itself for assistive technology", () => {
  const {context} = app();
  const backdrop = context.modal("Delete store", new Element("div"), () => {}, "Delete");
  const dialog = backdrop.children[0];
  assert.equal(dialog.attrs.role, "dialog");
  assert.equal(dialog.attrs["aria-modal"], "true");
  const labelledBy = dialog.attrs["aria-labelledby"];
  const heading = find(dialog, n => n.attrs?.id === labelledBy);
  assert.ok(heading, "aria-labelledby must resolve to a real element");
  assert.match(heading.textContent, /Delete store/);
});

test("a submitting dialog is a real form, so Enter submits it", async () => {
  const {context} = app();
  let submitted = 0;
  const backdrop = context.modal("Add store", new Element("div"), () => { submitted += 1; }, "Create");
  const form = find(backdrop, n => n.tagName === "FORM");
  assert.ok(form, "a dialog that saves must be a form");

  let preventedDefault = false;
  await form.events.submit({preventDefault: () => { preventedDefault = true; }});
  assert.equal(submitted, 1, "submitting the form runs the action");
  assert.equal(preventedDefault, true, "the form must not navigate");

  const submit = find(form, n => n.attrs?.type === "submit");
  assert.ok(submit, "the primary action must be a submit button");
});

test("a read-only dialog has no form and no cancel", () => {
  const {context} = app();
  const backdrop = context.modal("Job details", new Element("div"), null, "Close");
  assert.equal(find(backdrop, n => n.tagName === "FORM"), null);
  assert.equal(find(backdrop, n => n.textContent.trim() === "Cancel"), null);
});

test("opening a second dialog does not leave the first mounted", () => {
  const {context, body} = app();
  context.modal("First", new Element("div"), null, "Close");
  context.modal("Second", new Element("div"), null, "Close");
  const mounted = body.children.filter(n => n.attrs?.id === "modal-backdrop" && !n.removed);
  assert.equal(mounted.length, 1);
  assert.match(mounted[0].textContent, /Second/);
});

// ------------------------------------------------------------- focus walk ---

test("focusableWithin skips disabled, hidden, and tabindex -1 nodes", () => {
  const {context} = app();
  const box = new Element("div");
  const ok = new Element("button");
  const off = new Element("button"); off.disabled = true;
  const gone = new Element("input"); gone.hidden = true;
  const skipped = new Element("h1"); skipped.setAttribute("tabindex", "-1");
  const custom = new Element("div"); custom.setAttribute("tabindex", "0");
  box.append(ok, off, gone, skipped, custom);
  const found = context.focusableWithin(box);
  assert.equal(found.length, 2);
  assert.equal(found[0], ok);
  assert.equal(found[1], custom);
});

// ------------------------------------------------------------------ shell ---

test("the navigation drawer reports and restores its own state", () => {
  const {context, doc} = app();
  context.buildShell();
  const button = doc.getElementById("menu-btn");
  const side = doc.getElementById("side");

  assert.equal(button.attrs["aria-expanded"], "false");
  assert.equal(button.attrs["aria-controls"], "side");

  button.click();
  assert.equal(button.attrs["aria-expanded"], "true");
  assert.ok(side.classList.contains("open"));
  assert.notEqual(doc.activeElement, button, "focus moves into the drawer");

  doc.events.keydown({key: "Escape"});
  assert.equal(button.attrs["aria-expanded"], "false");
  assert.equal(side.classList.contains("open"), false);
  assert.equal(doc.activeElement, button, "focus returns to the trigger");
});

test("the shell carries a polite live region and a focusable heading", () => {
  const {context, doc} = app();
  context.buildShell();
  const region = doc.getElementById("live-region");
  assert.equal(region.attrs.role, "status");
  assert.equal(region.attrs["aria-live"], "polite");
  assert.ok(region.className.includes("sr-only"));

  // The heading belongs to the page header, not the shell's bar, so a screen
  // names itself once; it is still a focus target, never a tab stop.
  const header = context.pageHeader("overview");
  const heading = find(header, n => n.attrs?.id === "page-title");
  assert.equal(heading.tagName, "H1");
  assert.equal(heading.attrs.tabindex, "-1");

  context.announce("Overview ready");
  assert.equal(doc.getElementById("live-region").textContent, "Overview ready");
});

test("a route change announces itself and lands focus on the heading", async () => {
  const {context, doc} = app({
    "/admin/stores": {stores: []}, "/admin/policy-templates": {templates: []},
    "/admin/policies": {policies: []}, "/version": {},
    "/admin/history": {jobs: [], stats: {total_findings: 0, by_severity: {}}},
    "/runtime/alerts/stats": {total: 0}, "/healthz": {status: "ok"},
  });
  context.buildShell();
  await context.route();
  assert.equal(doc.activeElement, doc.getElementById("page-title"));
  assert.match(doc.getElementById("live-region").textContent, /Overview ready/);
});

// ------------------------------------------------------------ data states ---

test("an error is announced assertively and offers a retry", () => {
  const {context} = app();
  let retried = 0;
  const node = context.errorState("History is unavailable.", () => { retried += 1; });
  assert.equal(node.attrs.role, "alert");
  assert.match(node.textContent, /History is unavailable\./);
  find(node, n => n.tagName === "BUTTON").click();
  assert.equal(retried, 1);
});

test("an error with no recovery offers no retry", () => {
  const {context} = app();
  const node = context.errorState("The audit failed.");
  assert.equal(find(node, n => n.tagName === "BUTTON"), null);
});

test("empty, unknown, and unavailable are three different states", () => {
  const {context} = app();
  const states = {
    empty: context.emptyState("No stores registered."),
    unknown: context.unknownState("Coverage unknown.", "This run recorded no outcomes."),
    unavailable: context.unavailableState("History is disabled.", "Enable it to record runs."),
    error: context.errorState("Request failed."),
  };
  const classes = Object.values(states).map(node => node.className);
  assert.equal(new Set(classes).size, 4, "each state has its own shape, not just a colour");
  for (const [name, node] of Object.entries(states)) {
    assert.ok(find(node, n => n.tagName === "SVG"), `${name} carries a glyph`);
  }
  assert.equal(states.error.attrs.role, "alert");
  assert.equal(states.empty.attrs.role, "status");
  assert.match(states.unknown.textContent, /This run recorded no outcomes/);
});

test("an empty state can carry the action that fills it", () => {
  const {context} = app();
  let clicked = 0;
  const node = context.emptyState("No stores registered.", {
    action: () => { clicked += 1; }, actionLabel: "Add a store",
  });
  const button = find(node, n => n.tagName === "BUTTON");
  assert.match(button.textContent, /Add a store/);
  button.click();
  assert.equal(clicked, 1);
});

test("loading keeps a text alternative for people who cannot see a skeleton", () => {
  const {context} = app();
  const node = context.loadingState("Loading findings");
  assert.equal(node.attrs.role, "status");
  assert.match(node.textContent, /Loading findings/);
  assert.ok(find(node, n => n.className.includes("sr-only")));
});

test("status lines carry a glyph as well as a colour", () => {
  const {context} = app();
  const line = context.statusLine("Coverage is partial.", "medium");
  assert.ok(find(line, n => n.tagName === "SVG"));
  assert.match(line.textContent, /Coverage is partial\./);
});

test("a static note is a compact line, not an announced empty-state block", () => {
  const {context} = app();
  const line = context.statusLine("Coverage is partial.", "medium");
  // Every caveat used to be a centred 90px .empty block with role=status, so
  // a screen reader announced each one on every page load.
  assert.equal(line.attrs.role, undefined, "a static note is not a live region");
  assert.ok(!line.className.includes("empty"), "it is not the empty-state shape");
  assert.ok(line.className.includes("note"));
  // The outcome of something the reader just did is still announced.
  assert.equal(context.statusLine("Choose a store first.", "medium", {live: true}).attrs.role, "status");
  assert.equal(context.statusLine("It failed.", "error", {live: true}).attrs.role, "alert");
  // An absent optional caveat takes no space.
  assert.ok(context.statusLine("", "info").attrs.hidden);
});

// ------------------------------------------------ route-level error paths ---
// These live here because this fixture resolves element ids against the body,
// so what route() renders into #content is actually reachable.

// The Estate rethrows when the store list cannot be read, so it exercises the
// route-level catch. (The Overview degrades in place instead, which is why it
// renders "Unavailable" cards rather than failing the route.)
test("a locked console points at the control that unlocks it", async () => {
  const {context, doc} = app({
    "/admin/stores": {status: 401, detail: "invalid or missing token"},
  }, "#/stores");
  context.buildShell();
  await context.route();
  const text = doc.body.textContent;
  assert.match(text, /Access restricted/);
  assert.match(text, /Enter a bearer token in the header, then retry/);
});

test("a failure that is not an auth problem does not suggest a token", async () => {
  const {context, doc} = app({
    "/admin/stores": {status: 500, detail: "database is on fire"},
  }, "#/stores");
  context.buildShell();
  await context.route();
  const text = doc.body.textContent;
  assert.match(text, /database is on fire/);
  assert.doesNotMatch(text, /bearer token/);
});

// ----------------------------------------------------- shell, Phase 3 ---
// The skip link, the phone drawer's backdrop and inert page, and the window
// title. jsdom and this fixture do no layout, so the slide itself and the
// focused skip link's position are checked in tests/layout.test.mjs and the
// screenshot pass.

const SHELL_ROUTE = {
  "/admin/stores": {stores: []}, "/admin/policy-templates": {templates: []},
  "/admin/policies": {policies: []}, "/version": {},
  "/admin/history": {jobs: [], stats: {total_findings: 0, by_severity: {}}},
  "/runtime/alerts/stats": {total: 0}, "/healthz": {status: "ok"},
};

test("the skip link is the first thing in the shell and lands on the page heading", async () => {
  const {context, doc, body} = app(SHELL_ROUTE);
  context.buildShell();
  await context.route();
  const shell = find(body, n => n._classes?.has("app"));
  const skip = shell.children[0];
  assert.equal(skip.tagName, "BUTTON", "a button: an anchor's #content would be read as a view id");
  assert.ok(skip.className.includes("skip-link"));
  assert.equal(skip.textContent.trim(), "Skip to content");
  assert.equal(skip.attrs.href, undefined);

  doc.getElementById("menu-btn").focus();
  skip.click();
  assert.equal(doc.activeElement, doc.getElementById("page-title"));
});

function drawerParts(doc) {
  return {
    button: doc.getElementById("menu-btn"),
    side: doc.getElementById("side"),
    backdrop: doc.getElementById("side-backdrop"),
    main: doc.getElementById("main"),
  };
}

function assertClosed({button, side, backdrop, main}, how) {
  assert.equal(side.classList.contains("open"), false, `${how}: the drawer closes`);
  assert.equal(button.attrs["aria-expanded"], "false", `${how}: the trigger says so`);
  assert.ok("hidden" in backdrop.attrs, `${how}: the backdrop is hidden again`);
  assert.equal(main.attrs.inert, undefined, `${how}: the page is never left inert`);
}

test("the open drawer shows a backdrop and makes the page behind it inert", () => {
  const {context, doc} = app();
  context.buildShell();
  const parts = drawerParts(doc);
  assert.equal(parts.backdrop.tagName, "DIV");
  assert.ok(parts.backdrop.className.includes("side-backdrop"));
  assert.equal(parts.backdrop.parent, parts.side.parent, "a sibling of the sidebar");
  assert.equal(parts.main.tagName, "MAIN");
  assertClosed(parts, "at rest");

  parts.button.click();
  assert.ok(parts.side.classList.contains("open"));
  assert.equal("hidden" in parts.backdrop.attrs, false, "the backdrop shows");
  assert.equal(parts.main.attrs.inert, "", "the page behind is inert");
});

test("every way of closing the drawer clears the inert page", async () => {
  const {context, doc} = app(SHELL_ROUTE);
  context.buildShell();
  const parts = drawerParts(doc);
  const close = find(parts.side, n => n._classes?.has("side-close"));
  assert.equal(close.tagName, "BUTTON");
  assert.equal(close.attrs["aria-label"], "Close navigation");

  const ways = {
    backdrop: () => parts.backdrop.click(),
    Escape: () => doc.events.keydown({key: "Escape"}),
    "close button": () => close.click(),
    "choosing a screen": () => find(parts.side, n => n._classes?.has("nav-btn")).click(),
  };
  for (const [how, act] of Object.entries(ways)) {
    parts.button.click();
    assert.ok(parts.side.classList.contains("open"), `${how}: opened first`);
    act();
    assertClosed(parts, how);
  }
  // Escape and the close button hand focus back to the trigger.
  parts.button.click();
  doc.events.keydown({key: "Escape"});
  assert.equal(doc.activeElement, parts.button);

  // A route change closes it too, and focus goes to the new page instead.
  parts.button.click();
  await context.route();
  assertClosed(parts, "a route change");
  assert.equal(doc.activeElement, doc.getElementById("page-title"));
});

// ------------------------------------------------------- phones and touch ---
// What a phone needs that a mouse never noticed. The layout itself is checked
// in tests/layout.test.mjs and by scripts/mobile-check.mjs in a real browser.

// A click's target, as the document listener sees it: inside a selector or not.
const tapOn = inside => ({target: {closest: selector => (inside(selector) ? {} : null)}});

test("a tap outside the More menu closes it, and a tap inside does not", () => {
  const {context, doc} = app();
  context.buildShell();
  const more = doc.getElementById("more-btn");
  const top = doc.getElementById("top");
  more.click();
  assert.ok(top.classList.contains("menu-open"));
  doc.events.click(tapOn(selector => selector.includes("#top-actions")));
  assert.ok(top.classList.contains("menu-open"), "a tap on a control inside it keeps it open");
  doc.events.click(tapOn(() => false));
  assert.equal(top.classList.contains("menu-open"), false, "a tap on the page closes it");
  assert.equal(more.attrs["aria-expanded"], "false", "and the button says so");
});

test("the page under the drawer or a dialog does not scroll", () => {
  const {context, doc} = app();
  context.buildShell();
  const locked = () => doc.documentElement.classList.contains("is-locked");
  assert.equal(locked(), false, "at rest");
  doc.getElementById("menu-btn").click();
  assert.ok(locked(), "the drawer is open");
  doc.events.keydown({key: "Escape"});
  assert.equal(locked(), false, "the drawer closed");
  context.modal("Details", new Element("div"), null, "Close");
  assert.ok(locked(), "a dialog is open");
  context.modal("Inner", new Element("div"), null, "Close", {stack: true});
  context.closeModal();
  assert.ok(locked(), "the dialog beneath a closed one is still open");
  context.closeModal();
  assert.equal(locked(), false, "every dialog closed");
});

test("a row menu near the foot of a phone screen opens upward and fits the room", () => {
  const {context} = app();
  context.window.innerWidth = 390;
  context.window.innerHeight = 740;
  const open = rect => {
    const row = context.rowActions(null, [{label: "Open", onclick() {}}, {label: "Delete", onclick() {}}]);
    const wrap = find(row, n => n._classes?.has("menu-wrap"));
    const [toggle, menu] = wrap.children;
    toggle.getBoundingClientRect = () => rect;
    // This fixture keeps the hidden attribute and the property apart.
    Object.assign(menu, {hidden: true, style: {}, scrollHeight: 150, offsetWidth: 190});
    toggle.click();
    return menu.style;
  };
  const low = open({top: 700, bottom: 728, right: 380});
  assert.equal(low.top, "auto");
  assert.equal(low.bottom, "44px", "4px above its toggle");
  assert.equal(low.maxHeight, "688px", "and no taller than the room above");
  const high = open({top: 100, bottom: 128, right: 380});
  assert.equal(high.top, "132px", "with room below, it opens below");
  assert.equal(high.bottom, "auto");
  assert.equal(high.maxHeight, "600px");
  // A toggle in a card's left half: the menu keeps 8px from the left edge.
  const left = open({top: 100, bottom: 128, right: 150});
  assert.equal(left.right, `${390 - 190 - 8}px`);
});

test("a tap shows a tip, and a tip inside a label does not tick its box", () => {
  const {context, doc} = app();
  const tip = context.tooltip("What this setting does.");
  let prevented = false;
  tip.events.click({preventDefault: () => { prevented = true; }});
  assert.equal(prevented, true, "the label does not see the tap");
  assert.equal(doc.activeElement, tip, "the glyph takes focus, which shows its text");
});

test("on a phone the trend chart is drawn for a phone", () => {
  const {context} = app();
  const svg = node => find(node, n => n.tagName === "SVG" && n.attrs.viewBox);
  assert.equal(svg(context.trendChart([])).attrs.viewBox, "0 0 1000 160", "wide by default");
  context.matchMedia = query => ({matches: query === "(max-width: 640px)"});
  assert.equal(svg(context.trendChart([])).attrs.viewBox, "0 0 340 180",
               "narrow enough that its labels are not shrunk to 4px");
});

test("the window title names the screen on every route", async () => {
  const {context, doc} = app(SHELL_ROUTE);
  context.buildShell();
  await context.route();
  assert.equal(doc.title, "Overview — VecShield");
  context.location.hash = "#/docs";
  await context.route();
  assert.equal(doc.title, "Docs — VecShield");
});

test("the palette offers recent places only before anything is typed", async () => {
  const {context} = app(SHELL_ROUTE);
  const store = new Map();
  context.sessionStorage = {
    getItem: key => (store.has(key) ? store.get(key) : null),
    setItem: (key, value) => store.set(key, String(value)),
    removeItem: key => store.delete(key),
  };
  context.buildShell();
  await context.route();
  context.location.hash = "#/docs";
  await context.route();

  const {input, list} = context.openPalette();
  const groups = () => list.children.map(c => c.dataset.group);
  const recent = list.children.filter(c => c.dataset.group === "Recent");
  assert.equal(recent.length, 1, "the page being shown is not offered as a recent place");
  assert.match(recent[0].textContent, /Overview/);
  assert.equal(groups()[0], "Recent", "recent places lead the list");
  // Recent rows repeat destinations, so the denominator does not count them.
  assert.ok(!context.paletteEntries().some(e => e.group === "Recent"));

  input.value = "overview";
  input.events.input();
  assert.ok(!groups().includes("Recent"), "a query searches destinations, not history");
  context.closeModal();

  // Sign-out forgets where the last person went.
  context.forgetCachedData();
  assert.equal(store.has("vecshield_recent"), false);
});

test("a recent list that cannot be read or written is no list, not an error", async () => {
  const {context} = app(SHELL_ROUTE);
  context.sessionStorage = {
    getItem() { throw new Error("blocked"); },
    setItem() { throw new Error("blocked"); },
    removeItem() { throw new Error("blocked"); },
  };
  context.buildShell();
  await context.route();
  const {list} = context.openPalette();
  assert.ok(list.children.length > 0);
  assert.ok(!list.children.some(c => c.dataset.group === "Recent"));
});
