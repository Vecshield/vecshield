import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

// The console states risk, coverage, and uncertainty in text and colour. A token
// that falls under its contrast bar makes one of those statements unreadable for
// someone, so the bars are enforced here rather than reviewed by eye.
//
// Bars come from WCAG 2.2: 4.5:1 for body text, 3:1 for the boundary of a control
// whose only affordance is that boundary, and 3:1 for a focus indicator.

const css = (await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8"))
  .replace(/\/\*[\s\S]*?\*\//g, "");  // comments carry colons and would parse as tokens

function tokens(selector) {
  const block = css.slice(css.indexOf(selector) + selector.length);
  const body = block.slice(block.indexOf("{") + 1, block.indexOf("}"));
  const out = {};
  for (const line of body.split(";")) {
    const [name, value] = line.split(":").map(x => x && x.trim());
    if (name?.startsWith("--")) out[name] = value;
  }
  return out;
}

const base = tokens(":root");
const dark = {...base, ...tokens('html[data-theme="dark"]')};

function resolve(palette, value, seen = 0) {
  if (!value) return value;
  const ref = value.match(/^var\((--[\w-]+)\)$/);
  if (!ref) return value;
  assert.ok(seen < 10, `token reference loop at ${value}`);
  return resolve(palette, palette[ref[1]], seen + 1);
}

function luminance(hex) {
  const value = hex.trim();
  assert.match(value, /^#[0-9a-f]{6}$/i, `not a plain hex colour: ${hex}`);
  const channels = [1, 3, 5].map(i => parseInt(value.slice(i, i + 2), 16) / 255)
    .map(c => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

// Which surfaces each group of foreground tokens is allowed to sit on.
const CONTENT_SURFACES = ["--surface", "--surface-2", "--surface-3", "--bg"];
const CONTROL_SURFACES = ["--surface", "--surface-2"];

const MATRIX = [
  // [foreground tokens, surface tokens, minimum ratio, what it is]
  [["--text", "--muted", "--faint"], CONTENT_SURFACES, 4.5, "body text"],
  [["--critical", "--high", "--medium", "--low", "--info", "--ok", "--unknown"],
   CONTENT_SURFACES, 4.5, "status text"],
  [["--accent"], ["--surface", "--surface-2", "--bg", "--accent-soft"], 4.5, "accent text"],
  [["--accent-ink"], ["--accent", "--accent-hover"], 4.5, "text on a filled accent control, hovered too"],
  // The one selected state: its outline is the boundary that says "chosen"
  // without colour alone, and the item's own words sit on its tint.
  [["--selected-line"], ["--surface", "--surface-2", "--selected-bg"], 3, "selected-item outline"],
  [["--text", "--muted"], ["--selected-bg"], 4.5, "text on a selected item"],
  [["--side-text", "--side-head"], ["--side"], 4.5, "sidebar text"],
  [["--side-ink"], ["--side", "--side-active"], 4.5, "current and hovered sidebar text"],
  [["--side-indicator"], ["--side", "--side-active"], 3, "current-item bar in the sidebar"],
  [["--danger-ink"], ["--critical"], 4.5, "text on a filled danger control"],
  [["--border-strong"], CONTROL_SURFACES, 3, "control boundary"],
  [["--focus-ring"], CONTENT_SURFACES, 3, "focus indicator"],
];

for (const [themeName, palette] of [["light", base], ["dark", dark]]) {
  test(`${themeName} theme meets its contrast bars`, () => {
    const failures = [];
    for (const [foregrounds, surfaces, bar, what] of MATRIX) {
      for (const fg of foregrounds) {
        const fgValue = resolve(palette, palette[fg]);
        assert.ok(fgValue, `${themeName}: missing token ${fg}`);
        for (const surface of surfaces) {
          const bgValue = resolve(palette, palette[surface]);
          assert.ok(bgValue, `${themeName}: missing token ${surface}`);
          const measured = contrast(fgValue, bgValue);
          if (measured < bar) {
            failures.push(`${what}: ${fg} (${fgValue}) on ${surface} (${bgValue}) ` +
                          `= ${measured.toFixed(2)}:1, needs ${bar}:1`);
          }
        }
      }
    }
    assert.deepEqual(failures, [], `\n  ${failures.join("\n  ")}\n`);
  });
}

// Chips and notes put each status colour on its own soft background, in both
// themes. A tone that fails on its own tint is unreadable exactly where it is
// used most.
const TONES = ["critical", "high", "medium", "low", "info", "ok", "unknown"];

for (const [themeName, palette] of [["light", base], ["dark", dark]]) {
  test(`${themeName} theme: every status tone reads on its own soft background`, () => {
    const failures = [];
    for (const tone of TONES) {
      const fg = resolve(palette, palette[`--${tone}`]);
      const bg = resolve(palette, palette[`--${tone}-soft`]);
      assert.ok(bg, `${themeName}: --${tone}-soft is not defined`);
      const measured = contrast(fg, bg);
      if (measured < 4.5) failures.push(`--${tone} on --${tone}-soft = ${measured.toFixed(2)}:1`);
      // A soft background is a tint, not a second surface colour to read
      // body text on; it must still carry the muted text a note puts beside it.
      const muted = contrast(resolve(palette, palette["--muted"]), bg);
      if (measured >= 4.5 && tone === "info" && muted < 4.5) {
        failures.push(`--muted on --info-soft = ${muted.toFixed(2)}:1`);
      }
    }
    assert.deepEqual(failures, [], `\n  ${failures.join("\n  ")}\n`);
  });
}

test("the grey ramp darkens as its number rises", () => {
  // --slate-700 was lighter than --slate-600, so --info read fainter than
  // --muted. Each step must be darker than the one before it.
  const steps = ["25", "50", "100", "200", "400", "500", "600", "700", "900"];
  const values = steps.map(n => resolve(base, base[`--slate-${n}`]));
  for (let i = 1; i < values.length; i += 1) {
    assert.ok(luminance(values[i]) < luminance(values[i - 1]),
      `--slate-${steps[i]} (${values[i]}) must be darker than --slate-${steps[i - 1]} (${values[i - 1]})`);
  }
});

test("both themes define every token the matrix checks", () => {
  const needed = new Set(MATRIX.flatMap(([fg, bg]) => [...fg, ...bg]));
  for (const [themeName, palette] of [["light", base], ["dark", dark]]) {
    for (const name of needed) {
      assert.ok(palette[name], `${themeName} theme is missing ${name}`);
    }
  }
});

test("severity is never carried by colour alone", async () => {
  const js = await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8");
  const start = js.indexOf("function badge(");
  const badge = js.slice(start, js.indexOf("\n}", start));
  assert.match(badge, /icon\(/, "badge must render an icon next to its colour");
  assert.match(badge, /toUpperCase\(\)|label/, "badge must render a text label");
});

test("spacing tokens exist, and there is exactly one density", () => {
  for (const token of ["--row-y", "--row-x", "--panel-y", "--card-y"]) {
    assert.ok(base[token], `the stylesheet defines ${token}`);
  }
  // The compact toggle was removed; a leftover override would silently apply
  // to anyone whose browser still carries the old preference.
  assert.doesNotMatch(css, /data-density/, "no density variant remains");
});
