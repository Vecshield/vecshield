<p align="center">
  <img src="../../../docs/brand/vecshield-logo-lockup.png"
       alt="VecShield Security Console — compliance and security for vector stores"
       width="520">
</p>

# VecShield Enterprise Dashboard

This folder is the dashboard frontend home. The production dashboard is served
same-origin by FastAPI from `vecshield_platform/api/dashboard/dist`.

## What ships

`dist/` is the console FastAPI serves: `dist/index.html`,
`dist/assets/dashboard.js` and `dist/assets/dashboard.css`. They are
hand-written plain JavaScript and CSS with no build step; edit them directly.
The shell avoids inline script and style tags so the API can serve it with a
strict Content Security Policy.

`dist/assets/theme.js` sets the theme before the stylesheet paints: a stored
choice (`localStorage.vecshield_theme`) wins, otherwise the operating system's
colour scheme. Because the CSP forbids inline script, it is a separate file
loaded synchronously in `<head>`. Toggling back to the system's theme clears
the stored choice, so the console follows the system again.

`dist/assets/fonts/` holds the console's two self-hosted fonts, Latin subsets
of Inter (text) and JetBrains Mono (identifiers and code), with their SIL OFL
licence texts and a README recording the upstream versions, checksums and the
exact subsetting commands. They are same-origin because the CSP allows nothing
else; `tests/fonts.test.mjs` checks their size budgets, licences,
`font-display: swap` and the Inter preload in `index.html`.

The in-console React preview (`?ui=react`, the Status-page toggle and
`dist/assets/areas.js`) has been removed. The React/TypeScript sources in
`src/`, `index.html` and the `vite*.config.ts` files are still on disk but
nothing in the shipped console loads them.

## Commands

```bash
cd vecshield_platform/api/dashboard
npm install
node --check dist/assets/dashboard.js
node --check dist/assets/theme.js
npm test
```

`npm test` runs the Node fixtures against `dist/`. `npm run lint` and
`npm run test:types` type-check `src/`; `npm run dev` and `npm run build`
serve or build that unused scaffold (the build goes to `dist-preview/`, which
is gitignored). Start the backend separately:

```bash
vecshield-platform serve \
  --config ./vecshield.json \
  --state-dir ./state \
  --host 127.0.0.1 \
  --port 8088
```

`npm test` runs Node regression fixtures for the packaged dashboard's
behaviour, the [workflow parity gate](tests/fixtures/console-parity-checklist.md)
(`tests/parity.test.mjs`), contrast, axe and keyboard checks. It does not
establish browser journey or visual parity; take screenshots for that.

## Styling contract

The comment at the top of `dist/assets/dashboard.css` is the contract list:
the order of the file's sections, the type scale (five steps, 11/13/14/16/24px),
the three weights, the leading tokens, the four breakpoints, the stacking
tokens, and every literal-string rule the tests read the stylesheet for. Read
it before editing the file, and update it when a contract changes. In short:

- Colours, sizes, weights, line heights and z-indexes come from tokens.
  Theme differences live only in the dark token block.
- No CSS nesting, `@layer` or `@container` (the tests parse the file with
  jsdom), no `style` attributes from the JavaScript (the CSP forbids them),
  and `dashboard.js` stays a classic script whose last line is `boot();`.
- No edge stripes. A state is carried by a chip, an icon, words or shape;
  the only coloured bar is the sidebar's current item.

## Component vocabulary

Reach for the shared piece before writing a new one.

- **Surface and well.** A surface (`--surface`, a border, the 10px radius) is
  a container: `.panel`, `.card` and the other boxes listed in the stylesheet's
  surface group. A well (`--surface-2`) is a recessed area inside one: a
  glance block, a code sample, next steps. Components set layout and padding
  only; the group rule sets the paint. Panels and cards have no shadow and no
  hover.
- **Chips, four kinds.** A status chip is a `.badge` with a severity or tone
  class, always an icon plus a label (`badge()`, `toneChip()`). A neutral
  `.tag` labels a kind or a mode. A filter chip (`.chip`, `.fsum-chip`,
  `.crit-chip`, `.filter-chip`) toggles a filter. The accent `.pill` is the
  fourth kind; nothing on the current screens uses it.
- **Selected versus current.** Something the reader picked (a chip, a mode, a
  card, a row) gets the one selected state: the accent tint, the accent edge
  and a 1px inner ring, from the last section of the stylesheet. Where the
  reader is (the current nav item, tab or breadcrumb step) is marked
  differently, by a bar or underline and weight 600.
- **Tabs, toggles and navigation.**
  - `tabList()` when the choice swaps a panel on the same page: Findings'
    drawer, Evidence, Ingest, the saved audit's sections. It is the ARIA
    tab pattern. On a page every tab stays in the Tab order; pass
    `roving: true` only inside a dialog.
  - `segmented()` when the choice is a mode or filter over the same content,
    or a switch between sibling views (Criteria · Frameworks, the History
    switch). It is a `role=group` of `aria-pressed` buttons, with
    `navigates: true` when picking one changes the route.
  - The area's nav tabs (`areaTabs()`) are navigation, not tabs: a `nav` of
    buttons marked with `aria-current`. Use them only for an area's screens.
- **Page structure.** `pageHeader()` names the page once, with at most one
  primary action and an optional store picker in its scope slot; a record's
  page passes `{back}` for its back link. `panel()` makes a section with an
  h2. `factList()` renders label and value pairs, `table()` and `dataTable()`
  the shared table frame (sortable headers, the empty row, card rows below
  900px), `toolbar()` a list's filter bar, `recordHead()` the head of a saved
  record, `stepList()` a sequence of steps, and `severitySummary()` every
  count by severity. A count that was not reported reads Unknown, never 0.

## Screenshot pass

`npm test` cannot see the rendered page. For a visible change, run the console
against seeded demo state (`demo/seed.py`) and take
screenshots of the screens it touches at 1440px in light and dark, at 1200
and 1024px, and on touch at 768, 390, 360 and 320px (the mobile check below
takes all of these). Check for horizontal overflow (the page's
`scrollWidth` equals its `clientWidth`), a one-row header at 1440px and one no
taller than 56px on a phone, one primary action per page header, readable
selected and hover states in dark mode, and visible focus when tabbing.

## Mobile check

`npm run check:mobile` renders every screen in the console's view registry
in headless Chrome. It also opens a few record pages and dialogs: the finding
drawer, the store form, the palette, the drawer, the More menu and a row menu.
It renders each at 320, 360, 390 and 768px with touch emulation, and at
1440px with a mouse as the control. It uses Chrome's DevTools protocol over
Node's built-in `WebSocket`, so it needs no dependency, only Chrome
(`CHROME_PATH`, or the usual install path) and a running server.

```bash
VECSHIELD_USER=admin VECSHIELD_PASSWORD=... npm run check:mobile -- --url http://127.0.0.1:8088
# or VECSHIELD_TOKEN=... for a bearer token; neither for an open local server
# --widths 360,390   --only findings   --theme dark   --no-shots   --verbose
```

It fails (exit code 1) when:

- a page scrolls sideways;
- a phone header is taller than 56px;
- a menu or dialog does not fit the screen.

It warns about:

- a control under 44px on touch;
- a text link, breadcrumb or info glyph under 24px (WCAG 2.2's minimum);
- a scroller inside the page that scrolls sideways. The warning names the
  element that sticks out furthest.

Screenshots and `report.json` go to `--out`, which defaults to the system
temp folder, outside the repository. The check only navigates and opens
menus and dialogs, then closes them. It never submits a form or presses an
action, though the server still records what any visit records. Credentials
come from the environment and are never printed, and a session the check
opens is signed out when it finishes.

What it cannot show is iOS itself: focus zoom, the toolbar and the notch.
Check those on a real iPhone or iPad.

## Audit history and reports

Saved audits use explicit parent IDs, scope, coverage, and check outcomes from
`/admin/history/audits`. Individual jobs retain their IDs; legacy jobs are not
grouped by timestamps. The audit list supports loading additional pages; the
individual-job list explicitly shows a bounded recent window.

The saved-audit report action downloads `/stores/{id}/report?audit_id={id}` with
the current credentials. This renders a persisted snapshot and does not start
another scan. Disabled history, permission errors, and unknown coverage remain
visible instead of being converted to zero findings.

## Security Notes

- API calls are same-origin in production.
- Bearer tokens are stored in `sessionStorage`, not persistent local storage.
- API response content is rendered as text/DOM nodes, not injected as raw HTML.
- Generated reports should be opened as downloads/blob documents or sandboxed
  documents, not inserted into the dashboard DOM.
- Connector secrets stay server-side; the admin API masks secret values.

## Detector Settings

Runtime detector settings are independent from compliance policy templates.
The dashboard reads and writes `/admin/detectors`, which persists:

- `cooldown_s`
- `bulk_volume`
- `collection_sweep`
- `enumeration`
- `rate_baseline`

Policy templates describe governance rules over findings. Detector settings tune
how runtime query events become alerts.

## Drill-down, reveal, and approvals

A finding opens into tabs (`#/findings?finding=<id>`): Summary, Chunks, Why,
Obligations, History. A chunk opens into a drawer that fetches it from the
store *now* (`GET /stores/{id}/collections/{col}/chunks/{chunk_id}`), marks
each match with its label and detector, and shows why the detector fired and
which policy, template citation, and criterion the finding touches. Values are
masked by default; "Reveal values" needs a reason, requires the compliance
role, is written to the audit log as `chunk_revealed`, and re-masks after 60 s.
Nothing fetched this way is stored.

Whether an admin may approve their own plan or exception comes from
`/version` → `approvals.separation_of_duties`; the console's copy follows it
and every self-approval is shown as one.

## Brand assets

The sidebar logo and the favicons come from `dist/assets/vecshield-mark.svg`
(hand-drawn, ~2KB, crisp at 16px) with `vecshield-mark-192.png` and
`vecshield-app-icon-180.png` as the raster fallbacks. The palette they belong
to is defined once, as `--brand-*` tokens in `dashboard.css`; the accent, the
sidebar and the focus ring all reference those tokens rather than restating
hexes. `tests/brand.test.mjs` fails if that wiring is broken and
`tests/contrast.test.mjs` fails if a colour drops below its WCAG bar.

Source artwork and the palette table: [`docs/brand/`](../../../docs/brand/README.md).
