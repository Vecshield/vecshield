import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

// The brand is a contract, not decoration: the mark ships, the favicons point
// at it, and the palette is expressed as tokens rather than sprinkled hexes.

const css = await readFile(new URL("../dist/assets/dashboard.css", import.meta.url), "utf8");
const js = await readFile(new URL("../dist/assets/dashboard.js", import.meta.url), "utf8");
const html = await readFile(new URL("../dist/index.html", import.meta.url), "utf8");
const mark = await readFile(new URL("../dist/assets/vecshield-mark.svg", import.meta.url), "utf8");

test("the brand palette is defined once, as tokens", () => {
  for (const token of ["--brand-900", "--brand-700", "--brand-600", "--brand-500",
                       "--brand-400", "--brand-50"]) {
    assert.match(css, new RegExp(`${token}:\\s*#[0-9a-f]{6}`), `${token} is defined`);
  }
  // The accent, the sidebar and the focus ring reference the brand rather than
  // restating its hexes, so changing the brand changes all three.
  assert.match(css, /--accent: var\(--brand-600\)/);
  assert.match(css, /--side: var\(--brand-900\)/);
  assert.match(css, /--focus-ring: var\(--brand-600\)/);
  assert.doesNotMatch(css, /--teal-\d/, "the old teal palette is gone");
});

test("severity blue is not the brand blue", () => {
  // A blue 'low' badge beside a blue accent reads as a link, so low is cyan.
  const light = css.slice(css.indexOf(":root"), css.indexOf("html[data-theme=\"dark\"]"));
  assert.match(light, /--low: var\(--cyan-700\)/);
  assert.doesNotMatch(light, /--blue-600/);
});

test("the mark ships as SVG and keeps its two-tone split", () => {
  assert.match(mark, /viewBox="0 0 64 64"/);
  assert.match(mark, /#031e46/, "the navy half");
  assert.match(mark, /#1b7bfb/, "the blue half");
  assert.ok(mark.match(/<circle/g).length === 4, "four graph nodes");
  assert.ok(mark.length < 8000, `the mark is ${mark.length}B; it is a favicon, keep it small`);
});

test("the page points every icon slot at a real asset", () => {
  assert.match(html, /rel="icon"[^>]*vecshield-mark\.svg/);
  assert.match(html, /rel="icon"[^>]*vecshield-mark-192\.png/);
  assert.match(html, /rel="apple-touch-icon"[^>]*vecshield-app-icon-180\.png/);
  assert.match(html, /name="theme-color"[^>]*#031e46/, "dark chrome matches the sidebar");
  assert.match(html, /<title>VecShield Privacy &amp; Compliance Console<\/title>/);
});

test("the page takes the whole screen of a notched phone and keeps pinch zoom", () => {
  // viewport-fit=cover lets the stylesheet's env(safe-area-inset-*) padding
  // clear the notch; the zoom limits some sites add would stop a reader
  // enlarging the text.
  assert.match(html, /name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/);
  assert.doesNotMatch(html, /maximum-scale|user-scalable/);
});

test("the sidebar shows the mark itself, not a glyph in a tinted tile", () => {
  assert.match(js, /class: "logo", src: "\/static\/assets\/vecshield-mark\.svg"/);
  const logo = css.slice(css.indexOf(".logo {"), css.indexOf("}", css.indexOf(".logo {")));
  assert.doesNotMatch(logo, /background:/, "the mark carries its own colour");
});

test("the mark stays legible when it is small", () => {
  // Heavier nodes merge into one white shape at sidebar size, which is the
  // defect this geometry was tuned to avoid.
  const radius = [...mark.matchAll(/<circle[^>]*r="([\d.]+)"/g)].map(m => Number(m[1]));
  assert.ok(radius.every(r => r <= 3.6), `node radius ${radius} is too heavy for 32px`);
  assert.match(mark, /stroke-width="1\.8"/);
  // And the sidebar gives it room rather than the 34px a generic slot would.
  const logo = css.slice(css.indexOf(".logo {"), css.indexOf("}", css.indexOf(".logo {")));
  assert.match(logo, /width: 40px/);
});

test("the docs page leads with the lockup and describes the areas from the registry", async () => {
  assert.match(js, /src: "\/static\/assets\/vecshield-logo\.png"/, "the hero is the lockup");
  // The area cards are generated from AREAS, so this page cannot describe a
  // navigation that no longer exists.
  const block = js.slice(js.indexOf('if (block.kind === "areas")'));
  assert.match(block.slice(0, 600), /AREAS\.map/);
  assert.match(js, /docs: \["Docs"/, "docs is a registered view");
  for (const heading of ["What this is", "The lifecycle", "Approvals and safe mode",
                         "From a finding to the text behind it"]) {
    assert.ok(js.includes(heading), `the docs page covers "${heading}"`);
  }
});
