import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

// Layout invariants that jsdom cannot check by measuring, because it does no
// layout — so they are checked by reading the rules instead. Each one is here
// because breaking it produced a visible defect.

const css = (await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8"))
  .replace(/\/\*[\s\S]*?\*\//g, "");

function rule(selector) {
  const at = css.indexOf(selector + " {");
  assert.ok(at > -1, `no rule for ${selector}`);
  return css.slice(at, css.indexOf("}", at));
}

test("the header bar is one row that cannot overflow", () => {
  // It used to hold a title plus five controls and wrapped to a second row at
  // 1440px and to four rows (about 190px) on a phone. It now holds no title,
  // stays on one row, and below 900px folds its controls into a menu.
  assert.match(rule(".top"), /flex-wrap:\s*nowrap/);
  assert.match(rule(".top > *"), /min-width:\s*0/, "every item can shrink");
  assert.match(rule(".top-actions"), /min-width:\s*0/);
  const narrow = css.slice(css.indexOf("@media (max-width: 900px)"));
  assert.match(narrow, /\.top \{[^}]*height:\s*56px/, "the phone bar is 56px, one row");
  assert.match(narrow, /\.top-actions \{[^}]*display:\s*none/, "the controls fold away");
  assert.match(narrow, /\.top\.menu-open \.top-actions \{[^}]*display:\s*flex/, "into the More menu");
});

test("the More menu is a real disclosure", async () => {
  const shell = await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8");
  const more = shell.slice(shell.indexOf('"more-btn"') - 200, shell.indexOf('"more-btn"') + 400);
  assert.match(more, /aria-expanded/);
  assert.match(more, /aria-controls": "top-actions"/);
  assert.match(more, /aria-label/);
});

test("no control in the header bar is rigidly sized", () => {
  const token = rule(".token");
  assert.doesNotMatch(token, /(^|[^-])width:\s*\d+px/,
    "a fixed width here is what pushed the bar over its container");
  assert.match(token, /min-width/);
  assert.match(rule(".health"), /min-width:\s*0/);
});

test("the current navigation area is marked by more than a fill colour", () => {
  const current = rule('.nav-btn[aria-current="page"]');
  assert.match(current, /border-left-color/, "an accent bar, not only a background");
  assert.match(current, /font-weight/);
});

test("palette rows cannot spill into each other", () => {
  const hint = rule(".palette-item .palette-hint");
  assert.match(hint, /overflow:\s*hidden/);
  assert.match(hint, /text-overflow:\s*ellipsis/);
  assert.match(rule(".palette-label"), /text-overflow:\s*ellipsis/);
});

test("palette rows are laid out by a flex column, never a grid", () => {
  // Chrome sizes a <button> grid item to its min-height rather than its
  // content, so a grid list clamped every row to 24px and the hints painted
  // over the row below. The button also must not be the grid container.
  const list = rule(".palette-list");
  assert.match(list, /display:\s*flex/);
  assert.match(list, /flex-direction:\s*column/);
  assert.doesNotMatch(rule(".palette-item"), /display:\s*grid/);
  assert.match(rule(".palette-row"), /display:\s*grid/, "the layout lives on the inner span");
});

test("the palette search field fills its dialog", () => {
  assert.match(rule(".palette .search-field"), /width:\s*100%/);
});

test("every long-text surface can shrink inside its row", () => {
  // A row of flex children with nothing able to shrink is the shape that
  // produced the header overlap; these are the other places it could recur.
  for (const selector of [".chip-value", ".palette-item .palette-hint"]) {
    assert.match(rule(selector), /overflow:\s*hidden|text-overflow/,
      `${selector} must be able to truncate`);
  }
});

// ------------------------------------------------------------ terminology ---
// One name per thing. The nav was renamed in Phase 3 and the in-page headings
// were not, so the console said "Run" in the tab and "Scans & Audits" on the
// page. These keep the two from drifting apart again.

const shell = await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8");

test("every screen takes its name from the view registry", () => {
  const headers = [...shell.matchAll(/pageHeader\("([^"]+)"/g)].map(m => m[1]);
  assert.ok(headers.length > 15, "every screen has a heading");
  const ids = [...shell.matchAll(/^  (\w+): \["/gm)].map(m => m[1]);
  for (const header of headers) {
    assert.ok(ids.includes(header),
      `"${header}" is a literal title; pass the view id so the name is defined once`);
  }
});

test("retired screen names are gone from the console", () => {
  // Each of these was a second name for a screen that already had one.
  for (const retired of ["Scans & Audits", "Scan History", "Policy Templates",
                         "Privacy Requests", "Runtime Alerts", "Detection Engine",
                         "Ingest Firewall", "Schema Explorer"]) {
    assert.ok(!shell.includes(`"${retired}"`),
      `"${retired}" is a second name for a screen that already has one`);
  }
});

test("one word per concept in what the reader is shown", () => {
  // The API's `job` is the reader's "run"; the console should not mix them in
  // visible text. (Endpoint paths and field names keep the API's word.)
  const visible = [...shell.matchAll(/"([^"\\]{12,120})"/g)].map(m => m[1])
    .filter(t => / /.test(t) && !t.startsWith("/") && !/^[a-z_]+$/.test(t));
  const mixed = visible.filter(t => /\bbackground job\b/i.test(t));
  assert.deepEqual(mixed, [],
    `these say "background job" where the console says "run": ${mixed.join(" | ")}`);
});

// ------------------------------------------------------ Batch 1 foundations ---

test("the type scale has five steps, and every font size uses one", () => {
  const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
  const steps = [...root.matchAll(/--text-([a-z0-9]+):/g)].map(m => m[1]);
  assert.deepEqual(steps, ["xs", "sm", "base", "lg", "xl"]);
  const literal = [...css.matchAll(/font-size:\s*([^;}]+)/g)].map(m => m[1].trim())
    .filter(v => !/^var\(--text-/.test(v) && v !== "inherit");
  assert.deepEqual(literal, [], "a literal font size invents a sixth step");
  const shorthand = [...css.matchAll(/\bfont:\s*([^;}]+)/g)].map(m => m[1].trim())
    .filter(v => /\d+(\.\d+)?px/.test(v));
  assert.deepEqual(shorthand, [], "font shorthands use the scale too");
});

test("text uses three weights, and every line height is a leading token", () => {
  // Eight weights and fifteen line heights had crept in, several a few units
  // apart. The variable font ships 400-600 only, so a 700 would be clamped
  // to 600 anyway and only look like a fourth weight in the source.
  // An @font-face weight is the range its file covers, not a weight in use.
  const rules = css.replace(/@font-face\s*\{[^}]*\}/g, "");
  const weights = [...rules.matchAll(/font-weight:\s*([^;}]+)/g)].map(m => m[1].trim())
    .filter(v => !/^(400|500|600|var\(--weight-(regular|medium|semibold)\)|inherit|normal)$/.test(v));
  assert.deepEqual(weights, [], "a weight outside 400 / 500 / 600");
  const shorthandWeights = [...css.matchAll(/\bfont:\s*(\d{3})\b/g)].map(m => m[1])
    .filter(v => !["400", "500", "600"].includes(v));
  assert.deepEqual(shorthandWeights, [], "a font shorthand with a weight outside the three");
  const leading = [...css.matchAll(/line-height:\s*([^;}]+)/g)].map(m => m[1].trim())
    .filter(v => !/^(var\(--leading-(tight|snug|normal|relaxed)\)|1|0|normal|inherit)$/.test(v));
  assert.deepEqual(leading, [], "a line height outside the leading tokens");
  const shorthandLeading = [...css.matchAll(/\bfont:\s*[^;}]*\/\s*([^\s;}]+)/g)].map(m => m[1])
    .filter(v => !/^(var\(--leading-(tight|snug|normal|relaxed)\)|1)$/.test(v));
  assert.deepEqual(shorthandLeading, [], "a font shorthand with its own line height");
  const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
  for (const token of ["--weight-regular: 400", "--weight-medium: 500", "--weight-semibold: 600",
                       "--leading-tight", "--leading-snug", "--leading-normal", "--leading-relaxed"]) {
    assert.ok(root.includes(token), `${token} is defined with the other tokens`);
  }
});

test("labels are sentence case; only the product line and nav heads are uppercase", () => {
  const upper = [];
  for (const m of css.matchAll(/([^{}]+)\{([^}]*text-transform:\s*uppercase[^}]*)\}/g)) {
    upper.push(m[1].trim());
  }
  assert.deepEqual(upper.sort(), [".auth-brand span", ".brand span", ".nav-head"]);
});

test("every monospaced face comes from the mono token", () => {
  const stacks = [...css.matchAll(/(?:font-family|font):\s*([^;}]+)/g)].map(m => m[1])
    .filter(v => /monospace|Menlo|Consolas/.test(v));
  assert.deepEqual(stacks, [], "a hand-written mono stack drifts from var(--font-mono)");
  assert.match(css, /--font-mono:[^;]*monospace;/);
});

test("three radii and three elevations are defined, and nothing static lifts on hover", () => {
  for (const token of ["--radius-sm", "--radius-md", "--radius-pill", "--elev-0", "--elev-1", "--elev-2"]) {
    assert.match(css, new RegExp(`${token}:`), `${token} is defined`);
  }
  assert.doesNotMatch(css, /\.panel:hover|\.card:hover|\.template-card:hover|\.fw-card:hover/,
    "a static panel with a hover state looks clickable");
});

test("on a phone, a table cell keeps everything it holds together in the value column", () => {
  const children = rule(".table-wrap td > *");
  assert.match(children, /grid-column:\s*2/, "every child goes in the value column, not under the label");
  assert.match(children, /justify-self:\s*start/, "and keeps its own width");
  const label = css.slice(css.indexOf(".table-wrap td::before {"));
  assert.match(label.slice(0, label.indexOf("}")), /grid-column:\s*1/);
});

test("a status chip is as wide as its words", () => {
  const chip = rule(".pill, .tag, .badge");
  assert.match(chip, /justify-self:\s*start/);
  assert.match(chip, /flex:\s*none/);
  assert.match(chip, /max-width:\s*100%/);
});

test("checkboxes and radios are not stretched by the text-input rule", () => {
  assert.doesNotMatch(css, /(^|\n)input, select, textarea \{/, "a bare input rule stretches checkboxes");
  assert.match(css, /input:where\(:not\(\[type="checkbox"\]\):not\(\[type="radio"\]\)\), select, textarea \{\s*width:\s*100%/,
    "and at element specificity, so a component's own padding still applies");
  assert.match(rule('input[type="checkbox"], input[type="radio"]'), /width:\s*16px/);
});

test("a note is a compact left-aligned line, not a centred empty-state block", () => {
  const at = css.search(/\n\.note \{/);
  const note = css.slice(at, css.indexOf("}", at));
  assert.match(note, /text-align:\s*left/);
  assert.match(note, /font-size:\s*var\(--text-sm\)/);
  assert.doesNotMatch(note, /justify-content:\s*center/);
  assert.doesNotMatch(note, /padding:\s*var\(--space-6\)|padding:\s*3\dpx/);
});

test("statuses use the chip, not a coloured tag", async () => {
  const shell = await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8");
  // A classifier label (pii, secret) is metadata tinted by its tone; every
  // other `tag sev-*` was a status drawn in a second style.
  const coloured = [...shell.matchAll(/class: [`"]tag sev-([^`"]*)[`"]/g)].map(m => m[0])
    .filter(t => !t.includes("${spanTone("));
  assert.deepEqual(coloured, []);
  assert.doesNotMatch(shell, /class: `tag \$\{(?!spanTone)/, "no tag takes a status tone");
});

test("the hidden attribute wins over every component's display", () => {
  // Menus, stacked dialogs and folded fields are hidden with the attribute; a
  // component rule setting display: grid would otherwise show them.
  assert.match(css, /\[hidden\] \{ display: none !important; \}/);
});

// ------------------------------------------------------- Phase 3: shell ---

test("every z-index is a stacking token, or a local 0, 1 or -1", () => {
  const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
  const defined = new Set([...root.matchAll(/(--z-[a-z]+):/g)].map(m => m[1]));
  for (const token of ["--z-sticky", "--z-dropdown", "--z-drawer", "--z-menu", "--z-modal",
                       "--z-toast", "--z-tooltip"]) {
    assert.ok(defined.has(token), `${token} is defined with the other tokens`);
  }
  const values = [...css.matchAll(/z-index:\s*([^;}]+)/g)].map(m => m[1].trim());
  assert.ok(values.length > 5);
  const raw = values.filter(v => {
    const ref = v.match(/^var\((--z-[a-z]+)\)$/);
    return ref ? !defined.has(ref[1]) : !["0", "1", "-1"].includes(v);
  });
  assert.deepEqual(raw, [], "a raw z-index drifts out of the stacking order");
});

test("four breakpoints: 1200, 900, 640 and 360px", () => {
  const widths = [...css.matchAll(/@media[^{]*\((max|min)-width:\s*(\d+)px\)/g)]
    .map(m => `${m[1]} ${m[2]}`);
  assert.ok(widths.length > 10);
  const allowed = new Set(["max 1200", "min 1201", "max 900", "min 901", "max 640", "max 360"]);
  assert.deepEqual([...new Set(widths.filter(w => !allowed.has(w)))], [],
    "a seventh width makes a layout that exists at one window size only");
});

test("the dark theme is expressed by its token block only", () => {
  const scoped = [...css.matchAll(/html\[data-theme/g)].map(m => m.index);
  assert.equal(scoped.length, 1, "a rule scoped to the dark theme outside its token block");
  assert.equal(scoped[0], css.indexOf('html[data-theme="dark"] {'));
  assert.ok(scoped[0] > css.indexOf(":root {"), "and it follows the light tokens");
});

test("the content column is centred and capped", () => {
  const column = rule(".view-chrome, .content");
  assert.match(column, /max-width:\s*var\(--content-max\)/);
  assert.match(column, /margin-inline:\s*auto/);
  assert.match(rule(".page-desc"), /max-width:\s*72ch/);
});

test("the phone sidebar slides in over a backdrop instead of popping in", () => {
  const narrow = css.slice(css.indexOf("@media (max-width: 900px)"));
  const side = narrow.slice(narrow.indexOf(".side {"), narrow.indexOf("}", narrow.indexOf(".side {")));
  assert.match(side, /transform:\s*translateX\(-100%\)/);
  assert.match(side, /visibility:\s*hidden/, "closed, nothing in it takes focus");
  assert.match(side, /z-index:\s*var\(--z-drawer\)/);
  assert.doesNotMatch(side, /display:\s*none/);
  const open = narrow.slice(narrow.indexOf(".side.open {"), narrow.indexOf("}", narrow.indexOf(".side.open {")));
  assert.match(open, /transform:\s*none/);
  assert.match(open, /visibility:\s*visible/);
  assert.match(rule(".side-backdrop"), /background:\s*var\(--overlay\)/);
  // Reduced motion collapses every transition, the slide included.
  const reduced = css.slice(css.indexOf("@media (prefers-reduced-motion: reduce)"));
  assert.match(reduced.slice(0, reduced.indexOf("}\n}")), /transition-duration:\s*\.01ms !important/);
});

test("the skip link is off screen until it has focus", () => {
  assert.match(rule(".skip-link"), /transform:\s*translateY\(/);
  assert.match(rule(".skip-link:focus"), /transform:\s*none/);
});

// ------------------------------- Phase 4: one surface, one chip, one state ---

// Every style rule as {selectors, body}, inside @media blocks too. @font-face
// and @keyframes are skipped. Selectors are split on commas, which is enough
// for membership checks (a :where() list splits too, harmlessly).
function styleRules() {
  const out = [];
  let start = 0;
  for (let i = 0; i < css.length; i += 1) {
    if (css[i] === "}") { start = i + 1; continue; }
    if (css[i] !== "{") continue;
    const prelude = css.slice(start, i).trim();
    if (/^@(media|supports)\b/.test(prelude)) { start = i + 1; continue; }
    let depth = 1;
    let end = i + 1;
    while (depth && end < css.length) {
      if (css[end] === "{") depth += 1;
      else if (css[end] === "}") depth -= 1;
      end += 1;
    }
    if (!prelude.startsWith("@")) {
      out.push({selectors: prelude.split(",").map(s => s.trim()), body: css.slice(i + 1, end - 1)});
    }
    i = end - 1;
    start = end;
  }
  return out;
}
const RULES = styleRules();

test("one selected state marks everything a reader picks", () => {
  const selected = RULES.filter(r => /background:\s*var\(--selected-bg\)/.test(r.body)
    && /box-shadow:\s*inset 0 0 0 1px var\(--selected-line\)/.test(r.body)
    && /border-color:\s*var\(--selected-line\)/.test(r.body));
  const covered = new Set(selected.flatMap(r => r.selectors));
  for (const selector of [".chip-on", '.chip[aria-pressed="true"]', ".fsum-chip.is-on", ".crit-chip.is-on",
                          ".seg-on", ".run-mode-on", ".detector-choice.is-selected", ".example-card.is-loaded",
                          ".palette-item.palette-active", ".crypto-cov-card.is-on",
                          ".fd-life-steps li.is-current", ".remediation-steps li.is-current",
                          ".remediation-option:has(input:checked)"]) {
    assert.ok(covered.has(selector), `${selector} takes the shared selected state`);
  }
  // And there is no second selected look: the accent ring and the 3px inset
  // bar each belonged to one of the three styles this replaced.
  assert.doesNotMatch(css, /inset 0 0 0 1px var\(--accent\)/);
  assert.doesNotMatch(css, /inset 3px 0 0 var\(--accent\)/);
  const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
  assert.match(root, /--selected-bg:\s*var\(--accent-soft\)/);
  assert.match(root, /--selected-line:\s*var\(--accent\)/);
});

test("one surface and one well own the paint of every container", () => {
  const surface = RULES.find(r => r.selectors.includes(".panel") && r.selectors.includes(".card")
    && /background:\s*var\(--surface\)/.test(r.body));
  assert.ok(surface, "panels and cards share the surface rule");
  assert.match(surface.body, /border:\s*1px solid var\(--border\)/);
  assert.match(surface.body, /border-radius:\s*var\(--radius-md\)/);
  assert.match(surface.body, /box-shadow:\s*var\(--elev-0\)/);
  for (const selector of [".template-card", ".fw-card", ".stepper", ".save-bar", ".run-mode", ".detector-choice"]) {
    assert.ok(surface.selectors.includes(selector), `${selector} is a surface`);
  }
  const well = RULES.find(r => r.selectors.includes(".fd-glance") && /background:\s*var\(--surface-2\)/.test(r.body));
  assert.ok(well, "the well is one rule");
  for (const selector of [".chunk-text", ".next-steps", ".reveal-bar", "pre"]) {
    assert.ok(well.selectors.includes(selector), `${selector} is a well`);
  }
});

test("static panels and cards are not raised", () => {
  const lifted = RULES.filter(r => /var\(--elev-[12]\)/.test(r.body))
    .flatMap(r => r.selectors)
    .filter(s => /\.(panel|card)(?![\w-])/.test(s.split(/\s+|>/).pop()));
  assert.deepEqual(lifted, [], "a panel or card with a shadow reads as something that floats");
});

test("the skeleton loader is the only gradient", () => {
  const gradients = RULES.filter(r => /gradient\(/.test(r.body)).flatMap(r => r.selectors);
  assert.deepEqual(gradients, [".skeleton-line"]);
});

test("column heads are a rule, not a band, and rows do not pretend to be clickable", () => {
  const head = RULES.find(r => r.selectors.length === 1 && r.selectors[0] === "th");
  assert.match(head.body, /background:\s*transparent/);
  assert.match(head.body, /font-weight:\s*var\(--weight-medium\)/);
  const hovered = RULES.flatMap(r => r.selectors).filter(s => /tr:hover/.test(s) && !s.startsWith(".matrix"));
  assert.deepEqual(hovered, [], "only a matrix tints the row under the pointer");
});

test("filter chips are one component at the small control height", () => {
  const chip = RULES.find(r => [".chip", ".fsum-chip", ".crit-chip", ".filter-chip"].every(s => r.selectors.includes(s))
    && /border-radius/.test(r.body));
  assert.ok(chip, "the four filter chips share one rule");
  assert.match(chip.body, /min-height:\s*var\(--control-h-sm\)/);
  assert.match(chip.body, /border-radius:\s*var\(--radius-pill\)/);
  assert.match(chip.body, /background:\s*var\(--surface\)/);
});

test("an empty field error takes no room, wherever the field is", () => {
  // A scoped error rule with display: block at the same specificity, placed
  // after :empty, used to leave a blank line under every valid field.
  const empty = css.indexOf(".field-error:empty {");
  assert.ok(empty > -1);
  let lastScoped = -1;
  for (const m of css.matchAll(/(\.field|\.choice-group) \.field-error/g)) lastScoped = m.index;
  assert.ok(lastScoped > -1 && lastScoped < empty, ":empty comes after every scoped error rule");
  assert.match(rule(".field .field-hint, .auth-hint, .choice-group .field-hint"), /color:\s*var\(--muted\)/,
    "the hint rule is qualified with .field, so the label's span rule does not restyle it");
});

// ------------------------------------------------ Phase 5: no edge stripes ---

test("state is carried by chips, icons and shape, never by an edge stripe", () => {
  // A coloured 3px edge was the console's habit for every kind of box, so it
  // stopped meaning anything. Two edges are left, and both are exact: the
  // sidebar's current-item bar, and the neutral rule beside a quote or a
  // timeline, which is structure rather than state.
  const NAV = s => s.startsWith(".nav-btn");
  const STRUCTURE = [".plain-legal-body", ".trace-step"];
  const width = value => {
    if (/\b(medium|thick)\b/.test(value)) return 3;
    const px = value.match(/(\d+(?:\.\d+)?)px/);
    return px ? Number(px[1]) : 0;
  };
  const offenders = [];
  for (const {selectors, body} of RULES) {
    for (const [, prop, value] of body.matchAll(/(border-(?:left|top)(?:-width)?)\s*:\s*([^;]+)/g)) {
      if (width(value) < 2) continue;
      if (selectors.every(NAV)) continue;
      if (selectors.every(s => STRUCTURE.includes(s)) && prop === "border-left"
          && /^2px solid var\(--border\)$/.test(value.trim())) continue;
      offenders.push(`${selectors.join(", ")} { ${prop}: ${value.trim()} }`);
    }
    // A tone on one edge is a stripe at any width.
    for (const [, prop] of body.matchAll(/(border-(?:left|top)-(?:color|style))\s*:/g)) {
      if (!selectors.every(NAV)) offenders.push(`${selectors.join(", ")} { ${prop} }`);
    }
    // An inset shadow offset to one side is a painted stripe. The shared
    // selected ring (inset 0 0 0 1px) and a match's underline (inset 0 -2px)
    // are not.
    for (const [shadow] of body.matchAll(/box-shadow\s*:[^;]*/g)) {
      if (/inset\s+-?[1-9]/.test(shadow) || /inset\s+0\s+[1-9]/.test(shadow)) {
        offenders.push(`${selectors.join(", ")} { ${shadow.trim()} }`);
      }
    }
  }
  assert.deepEqual(offenders, [], "an edge stripe is back; carry the state with a chip, icon, words or shape");
  // The two exceptions are still what they claim to be.
  assert.ok(RULES.some(r => r.selectors.includes(".nav-btn") && /border-left:\s*3px solid transparent/.test(r.body)));
  assert.match(rule('.nav-btn[aria-current="page"]'), /border-left-color:\s*var\(--side-indicator\)/);
  assert.match(rule(".trace-step"), /border-left:\s*2px solid var\(--border\)/);
});

test("crypto coverage buckets differ by dot shape as well as tone", () => {
  // The cards lost their coloured top edge; the dot before each title keeps
  // the solid, dashed and dotted shapes that edge used to carry.
  const dot = RULES.find(r => r.selectors.includes(".crypto-page .crypto-cov-card[data-bucket] .crypto-cov-title::before"));
  assert.ok(dot, "each bucketed card has a dot");
  assert.match(dot.body, /border-radius:\s*50%/);
  const shape = bucket => RULES.find(r => r.selectors.includes(
    `.crypto-page .crypto-cov-card[data-bucket="${bucket}"] .crypto-cov-title::before`))?.body || "";
  assert.match(shape("not_observable"), /border-style:\s*dashed/);
  assert.match(shape("not_checked"), /border-style:\s*dotted/);
  assert.match(shape("not_observable"), /background:\s*transparent/, "a ring, not a filled dot");
  assert.match(shape("not_checked"), /background:\s*transparent/);
});

// -------------------------------------------------------- phones and touch ---
// Read from the rules, as everything in this file is; scripts/mobile-check.mjs
// measures the same things in a real browser at phone and tablet widths.

// Every @media block with exactly this query, joined.
function media(query) {
  const head = `@media ${query} {`;
  const out = [];
  for (let at = css.indexOf(head); at > -1; at = css.indexOf(head, at + 1)) {
    let depth = 1;
    let i = at + head.length;
    while (depth && i < css.length) {
      if (css[i] === "{") depth += 1;
      else if (css[i] === "}") depth -= 1;
      i += 1;
    }
    out.push(css.slice(at + head.length, i - 1));
  }
  return out.join("\n");
}

test("on a touch screen every control is a 44px target and every field is set at 16px", () => {
  const touch = media("(pointer: coarse)");
  assert.match(touch, /:root \{[^}]*--control-h:\s*44px;[^}]*--control-h-sm:\s*44px/,
    "both control heights, so buttons, chips, segments and fields follow");
  assert.match(touch, /select, textarea, \.token \{[^}]*font-size:\s*var\(--text-lg\)/,
    "iOS zooms the page into a field set under 16px");
  assert.match(touch, /\.nav-btn, \.tab, \.menu-item, summary \{[^}]*min-height:\s*var\(--control-h\)/);
  // With a mouse nothing changes: the first token block keeps 36 and 28px.
  const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
  assert.match(root, /--control-h:\s*36px/);
  assert.match(root, /--control-h-sm:\s*28px/);
});

test("the phone layout is sized to the visible screen, not to 100vh", () => {
  // 100vh is the screen with the browser's toolbar hidden: on a phone it ran
  // the drawer's foot and a dialog's buttons under the toolbar.
  for (const selector of [".app", ".auth-page"]) {
    assert.match(rule(selector), /min-height:\s*100vh;[^}]*min-height:\s*100dvh/, `${selector}: dvh after its vh fallback`);
  }
  assert.match(rule(".modal"), /max-height:\s*min\(780px, 90dvh\)/);
  const narrow = css.slice(css.indexOf("@media (max-width: 900px)"));
  const side = narrow.slice(narrow.indexOf(".side {"), narrow.indexOf("}", narrow.indexOf(".side {")));
  assert.match(side, /height:\s*auto/, "the phone drawer is sized by its insets");
  assert.match(media("(max-width: 900px)"), /html\.is-locked \{[^}]*overflow:\s*hidden/,
    "the page behind the drawer or a dialog is held still");
});

test("on a phone a dialog is a sheet, the palette hangs from the top and a toast drops in under the bar", () => {
  const phone = media("(max-width: 640px)");
  assert.match(phone, /\.modal \{[^}]*width:\s*100%[^}]*max-height:\s*calc\(100dvh - var\(--space-5\)\)/);
  assert.match(phone, /\.modal-foot \{[^}]*flex-wrap:\s*wrap/, "its buttons wrap rather than overflow");
  assert.match(phone, /\.modal-drawer \{[^}]*max-height:\s*none/, "the detail drawer stays a full screen");
  assert.match(phone, /\.modal-palette \{[^}]*margin-top:\s*0/);
  assert.match(phone, /\.toast, \.toast\.run-notice \{[^}]*top:\s*calc\(var\(--top-h\)[^}]*bottom:\s*auto/,
    "a toast no longer covers the Run, bulk, save and stage bars");
});

test("nothing on a phone holds a line or a width that pushes it past the screen", () => {
  const cards = media("(max-width: 900px)");
  assert.match(cards, /\.table-wrap td, \.table-wrap td \.nowrap, \.table-wrap td\.mono[^{]*\{[^}]*white-space:\s*normal;[^}]*overflow-wrap:\s*anywhere/);
  assert.match(cards, /\.crypto-estate-table td\[data-label\]::before \{[^}]*content:\s*attr\(data-label\)/,
    "the crypto matrix is cards, like every other table");
  const fixed = [...css.matchAll(/repeat\((?:auto-fit|auto-fill), minmax\(\d+px/g)].map(m => m[0]);
  assert.deepEqual(fixed, [], "a fixed track minimum overflowed a 320px phone");
  assert.match(rule(".tip-pop"), /width:\s*min\(240px, calc\(100vw/);
  assert.match(media("(hover: none)"), /\.tip:focus \.tip-pop \{[^}]*position:\s*fixed/,
    "with no hover a tip is a card along the foot of the screen");
  assert.match(media("(max-width: 360px)"), /\.top-brand-name \{[^}]*clip-path:\s*inset\(50%\)/,
    "the smallest phones keep the mark and drop the name from the bar");
});

test("the screen's edges clear a notch and the home indicator", () => {
  // env() is 0 unless the page takes the whole screen (viewport-fit=cover).
  for (const selector of [".bulk-bar", ".actions-page-bulk.is-active", ".save-bar.is-active",
                          ".assess-view .run-go", ".modal-drawer .modal-foot"]) {
    assert.match(rule(selector), /padding-bottom:\s*max\([^;]*env\(safe-area-inset-bottom\)\)/, selector);
  }
  assert.match(rule(".bulk-bar"), /(^|[^-])bottom:\s*var\(--space-\d\)/, "the bar's own offset is unchanged");
  const narrow = css.slice(css.indexOf("@media (max-width: 900px)"));
  const side = narrow.slice(narrow.indexOf(".side {"), narrow.indexOf("}", narrow.indexOf(".side {")));
  assert.match(side, /padding-left:\s*max\(var\(--space-3\), env\(safe-area-inset-left\)\)/);
  assert.match(side, /padding-bottom:\s*max\(var\(--space-4\), env\(safe-area-inset-bottom\)\)/);
  assert.match(media("(max-width: 900px)"),
    /\.top, \.view-chrome, \.content \{[^}]*padding-left:\s*max\(var\(--space-4\), env\(safe-area-inset-left\)\)/);
});
