import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";

// The console's fonts are self-hosted: the Content Security Policy allows
// same-origin resources only, and a missing or oversized file shows up as a
// fallback face or a slow first paint rather than as an error. These checks
// keep the files, the stylesheet and the page pointing at one another.

const assets = new URL("../dist/assets/", import.meta.url);
const css = (await readFile(new URL("dashboard.css", assets), "utf8"))
  .replace(/\/\*[\s\S]*?\*\//g, "");
const html = await readFile(new URL("../dist/index.html", import.meta.url), "utf8");

const faces = [...css.matchAll(/@font-face\s*\{([^}]*)\}/g)].map(m => m[1]);
const urlFaces = faces.filter(body => /url\(/.test(body));
const urlOf = body => body.match(/url\(\s*["']?([^"')]+)["']?\s*\)/)[1];

// Budgets for the Latin subsets (assets/fonts/README.md).
const BUDGET = {
  "fonts/inter-latin-var.woff2": 85 * 1024,
  "fonts/jetbrains-mono-latin-var.woff2": 50 * 1024,
};
const LICENCE = {
  "Inter": "fonts/Inter-OFL.txt",
  "JetBrains Mono": "fonts/JetBrainsMono-OFL.txt",
};

test("every @font-face file exists under the assets folder", async () => {
  assert.ok(urlFaces.length >= 2, "Inter and JetBrains Mono are declared");
  for (const body of urlFaces) {
    const file = urlOf(body);
    assert.doesNotMatch(file, /^(\/|[a-z]+:)/i, `${file} is relative to the stylesheet`);
    const info = await stat(new URL(file, assets));
    assert.ok(info.isFile(), `${file} is a file`);
  }
});

test("each font file is a WOFF2 inside its size budget", async () => {
  const declared = urlFaces.map(urlOf).sort();
  assert.deepEqual(declared, Object.keys(BUDGET).sort(), "one budget per declared file");
  for (const [file, budget] of Object.entries(BUDGET)) {
    const bytes = await readFile(new URL(file, assets));
    assert.equal(bytes.subarray(0, 4).toString("latin1"), "wOF2", `${file} is WOFF2`);
    assert.ok(bytes.length <= budget,
      `${file} is ${(bytes.length / 1024).toFixed(1)} KB; the budget is ${budget / 1024} KB`);
  }
});

test("each font family ships with its OFL licence", async () => {
  for (const body of urlFaces) {
    const family = body.match(/font-family:\s*["']?([^"';]+)["']?/)[1];
    const licence = LICENCE[family];
    assert.ok(licence, `no licence file is recorded for ${family}`);
    const text = await readFile(new URL(licence, assets), "utf8");
    assert.match(text, /SIL OPEN FONT LICENSE/i, `${licence} is the OFL`);
  }
});

test("every downloaded face swaps in rather than hiding text", () => {
  for (const body of urlFaces) {
    assert.match(body, /font-display:\s*swap/, `${urlOf(body)} declares font-display: swap`);
    assert.match(body, /unicode-range:/, `${urlOf(body)} names the characters it covers`);
  }
});

test("the stylesheet loads nothing from another origin", () => {
  assert.doesNotMatch(css, /url\(\s*["']?(https?:)?\/\//i,
    "the CSP allows same-origin resources only");
});

test("the page preloads Inter from a file that exists, as CORS", async () => {
  const preload = html.match(/<link[^>]*rel="preload"[^>]*>/);
  assert.ok(preload, "Inter is preloaded");
  const tag = preload[0];
  assert.match(tag, /as="font"/);
  assert.match(tag, /type="font\/woff2"/);
  // Fonts are always fetched in CORS mode; a preload without crossorigin is
  // fetched twice.
  assert.match(tag, /\scrossorigin(\s|>|=)/);
  const href = tag.match(/href="\/static\/assets\/([^"]+)"/);
  assert.ok(href, "the preload points into /static/assets/");
  assert.ok((await stat(new URL(href[1], assets))).isFile(), `${href[1]} exists`);
  assert.ok(urlFaces.map(urlOf).includes(href[1]), "and is the file the stylesheet uses");
  assert.ok(html.indexOf(tag) < html.indexOf('rel="stylesheet"'), "before the stylesheet");
});
