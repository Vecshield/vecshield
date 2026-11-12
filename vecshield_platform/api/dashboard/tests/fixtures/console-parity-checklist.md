# Console parity checklist

**This document is a gate, not a description.** It is the baseline inventory of the shipped `dist/` console, enforced by `parity.test.mjs`.

Any re-parenting of the console's destinations, or a rewrite of its implementation, is a way to lose a workflow quietly. This checklist enumerates what the console can do today, so "nothing was lost" is something we can check rather than something we assert.

Rules:

- A row is checked only when the workflow is reachable **and completable** in the new location, not when the code was moved.
- A row that is deliberately dropped is struck through with a reason, never deleted.
- Deleting the vanilla implementation of an area requires every row for that area to be checked.
- The inventory is derived from the source, not from memory: 16 views, 12 dialog openers, 39 API paths.

## Legend

| Mark | Meaning |
|---|---|
| `[x]` | Reachable and completable in the new IA, verified |
| `[ ]` | Not yet verified in the new IA |
| `[-]` | Deliberately dropped, with the reason stated |

---

## Estate (was: Stores, Schema Explorer)

**Migration status:** vanilla only. The in-console React preview (`?ui=react`)
was removed on 2026-09-25; the React sources in `src/` are no longer loaded.

- [x] List registered stores with kind and tenant field — *Estate → Stores*
- [x] See whether a store is reachable, and why not when it is not — *Estate → Stores*
- [x] See what a connector can do, with unprobed capabilities marked unknown rather than absent — *Estate → Stores*
- [x] See last assessed age and that run's coverage per store — *Estate → Stores*
- [x] Open a store's collections without leaving the estate — *Estate → Stores* (2026-09-28: Open is a routed page, `#/stores?store=<id>`, that replaces the table with the store's facts, next steps and collections, focused and at the top; it used to render below the table, off screen. `tests/account.test.mjs`)
- [x] Jump from a store to its assessment or its findings — *Estate → Stores*
- [x] See what changed since a store's previous saved audit: new, resolved, and not re-tested findings, and inventory changes such as possible shadow copies; with fewer than two audits it says there is nothing to compare yet — *Estate → Stores* (2026-10-02: "Since the last audit" panel on `#/stores?store=<id>`, `GET /stores/{id}/changes` and `GET /stores/{id}/inventory/changes`. `tests/account.test.mjs`)
- [x] A console with nothing connected explains how to get a first assessment — *Estate → Stores*
- [ ] Add a store, choosing among 13 connector kinds with kind-specific fields — *Estate → Stores → Add store*
- [x] Edit an existing store's connection — *Estate → Stores → row → Edit* (Batch 3: row menu → Edit connection; masked secrets and unshown keys round-trip as `***`; Test connection tries the form's values before saving (`POST /admin/stores/test-connection`, nothing persisted); saving after a failed test asks "Save anyway?" first. Add store has the same test. `tests/batch3.test.mjs`)
- [x] Test a store connection and see the result inline — *Estate → Stores → row → Test* (Batch 3: row menu → Test connection, and inside Edit. `tests/batch3.test.mjs`)
- [x] Delete a store, with its scoped policies named in the confirmation — *Estate → Stores → row → Delete* (Batch 1: an in-page confirmation that names the scoped policies and needs the store id typed; it refuses if it cannot be shown. `tests/dialogs.test.mjs`)
- [x] Secret-reference fields (`*_env`) never echo their values — *Estate → Stores*
- [ ] Discover a store's schema: collections, vector counts, metadata fields — *Estate → Schema*
- [x] Set the metadata sample size and re-discover — *Estate → Schema*
- [ ] Per-collection metadata field coverage and example values — *Estate → Schema*
- [x] Schema discovery failure states its cause and offers a retry — *Estate → Schema*
- [x] Read a store's saved-audit crypto posture in layer order: transport, storage encryption, field/data level, retrieval — *Estate → Crypto*
- [x] See each crypto row's control id, collection, state, reason, and count-only details — *Estate → Crypto*
- [x] Tell "not observable" apart from an observed exposure, not verified, not applicable, and not run — *Estate → Crypto*
- [x] See at-rest coverage as counts (verified encrypted, verified unencrypted, unknown), never a percentage — *Estate → Crypto*
- [-] See what lies outside the connector's view (disk/volume encryption, cloud KMS) — *Estate → Crypto* (dropped 2026-09-25 at the user's request to cut prose; controls the connector cannot observe still show as "not observable" rows)
- [x] See crypto state changes since the previous saved audit — *Estate → Crypto*
- [x] See each framework's relationship to encryption and its criteria's technical results and fallback evidence — *Estate → Crypto*
- [x] A store with no saved audit is told to run one from Run — *Estate → Crypto*
- [x] See the release gate's decision for a store's saved audit, the rules that fired or were cleared, and the evidence that would clear them — *Estate → Crypto*
- [x] Re-evaluate the gate as if policy required encryption at rest, without saving the setting — *Estate → Crypto*

## Assessments (was: Scans & Audits, Scan History, Background Jobs)

**Migration status:** vanilla only. The in-console React preview (`?ui=react`)
was removed on 2026-09-25.

- [x] Choose a target store, or all stores — *Assessments → New assessment*
- [x] Choose an integrity collection and a max-chunks cap — *Assessments → New assessment*
- [x] Opt in to the TLS enforcement and retrieval exposure probes for a full audit, off by default — *Assessments → New assessment*
- [ ] Run a full audit — *Assessments → New assessment*
- [x] Every audit result ends with next steps: findings for the store, crypto posture, criteria, and the release gate — *Assessments → New assessment* (Batch 3; also on a saved audit. `tests/batch3.test.mjs`)
- [x] The New assessment page points to History for saved audits instead of repeating the table — *Assessments → New assessment* (Batch 3, `tests/batch3.test.mjs`; 2026-10-06: the header action reads "Open history for <store>")
- [ ] Run a posture check — *Assessments → New assessment*
- [ ] Run an integrity scan for one collection — *Assessments → New assessment*
- [ ] Generate a DPIA — *Assessments → New assessment*
- [ ] Run audit, posture, and DPIA across every registered store — *Assessments → New assessment*
- [x] See coverage and check outcomes for a result — *Assessments → New assessment*
- [x] Browse archived scans with search, kind, store, severity, and has-findings filters — *Assessments → History*
- [ ] Page through saved audits — *Assessments → History → Load more audits*
- [ ] Open a saved audit snapshot and its child jobs — *Assessments → History → Open audit*
- [ ] Open one archived job with its findings and evidence — *Assessments → History → Details*
- [ ] Download the saved report for an audit — *Assessments → History → Download saved report*
- [x] List background jobs with kind, status, actor, resource, created — *Assessments → History → Runs view* (2026-10-06: reached from History's one switch, Saved audits · Individual scans · Runs, which Runs also carries; `tests/batch3.test.mjs`)
- [ ] Open a background job's full record — *Assessments → History → Runs view → Details*
- [x] Legacy jobs with no parent audit remain visible and labelled — *Assessments → History*

## Findings (was: findings tables inside results and history)

- [x] Filter findings by search text, severity, category, collection, store, and label — *Findings*
- [x] Findings default to "Open now": distinct findings from each store's latest audit, suppressed ones left out as Home counts them; a switch shows "All recorded (every run)", kept in the URL as `scope=all` — *Findings* (`GET /admin/findings?scope=latest`, `tests/batch3.test.mjs`)
- [x] The findings list comes first under a compact filter toolbar; grouping by cause and the label heatmap are folded below it — *Findings* (Batch 3, `tests/batch3.test.mjs`)
- [x] A finding opens in a side panel titled by what was found, with Change case as its primary action and a readable location — *Findings* (Batch 3, `tests/batch3.test.mjs`)
- [x] Hide suppressed findings — *Findings*
- [x] See each finding's evidence as chips plus raw data — *Findings* (evidence chips remain on result panels; the Findings list shows title, category, and location)
- [x] See a finding's fingerprint — *Findings* (searchable; shown in the result panels)
- [x] Result count states the denominator it filtered from — *Findings* (Phase 5: now the true total from the database, not the fetched page)
- [x] Filter, sort, and page findings in the database rather than over a capped fetch — *Findings*
- [x] Export the findings list as filtered, as CSV or JSON, without evidence, saying when the export is partial — *Findings* (2026-10-02: toolbar Export, `GET /admin/findings/export`, audit-logged, capped at 50,000 rows. `tests/batch3.test.mjs`)
- [x] Assign an owner to a finding — *Findings*
- [x] Move a finding's case through its workflow — *Findings*
- [x] Read a case's history: who changed what, when, and why — *Findings*
- [x] Open a chunk from a finding and step Back to the same finding, as it was left — *Findings* (Batch 1 dialog stack, `tests/dialogs.test.mjs`)
- [x] Apply a case change to many findings, with per-finding outcomes — *Findings*
- [x] See case states counted, with resolution claims kept apart from verified work — *Findings*

### Actions (new in v2.4 — not a parity row; recorded so the area stays complete)

- [x] See what could be done about a store's findings — *Findings → Actions*
- [x] See what was refused, and the reason it was refused — *Findings → Actions*
- [x] See how much of a finding a proposal actually reaches — *Findings → Actions*
- [x] Review a staged plan's diff, warnings first — *Findings → Actions → Review*
- [x] Stage a plan from the console — *Findings → Actions → Stage selected*
- [x] See whether this deployment permits writes at all — *Findings → Actions*
- [x] Approve a plan, with a reason and a second person — *Findings → Actions → Review*
- [x] See who approved a plan and why — *Findings → Actions → Review*
- [x] Execute an approved plan and see its verification outcome — *Findings → Actions → Review*
- [x] Open Actions from a finding and keep it: named at the top, proposals narrowed to it, a way back — *Findings → Actions* (Batch 3, `tests/batch3.test.mjs`)
- [x] See every plan awaiting approval across stores, split into "you can approve" and "needs a second person" — *Findings → Actions → Approval queue* (Batch 3, `GET /actions/queue`, `tests/batch3.test.mjs`)

## Compliance (was: Policies, Policy Templates, False Positives)

- [x] List configured policies with scope and enabled state — *Compliance → Policies*
- [ ] Create a policy, from scratch or from a template — *Compliance → Policies → New policy*
- [ ] Edit and delete a policy — *Compliance → Policies* (Batch 1: delete now asks first, `tests/dialogs.test.mjs`; editing is still not offered, so the row stays open)
- [x] Scope a policy to a store and collection — *Compliance → Policies*
- [x] Browse policy templates with framework, category, severity, and label filters — *Compliance → Policies → Templates view*
- [ ] Inspect a template: rule, attribution, sources, applicability, evidential reach — *Compliance → Policies → Templates view → Inspect*
- [ ] See recent findings a template's rule would match — *Compliance → Policies → Templates view → Inspect*
- [ ] Customize a template into a scoped policy — *Compliance → Policies → Templates view → Customize*
- [x] Copy a template as JSON — *Compliance → Policies → Templates view → Copy JSON*
- [x] View the built-in allow-list — *Findings → False positives*
- [ ] View and manage time-boxed suppressions — *Findings → False positives*
- [x] Criterion pack: applicability, technical result, evidence, and reviewer decision as four separate fields — *Compliance → Criteria*
- [x] Answer a criterion's applicability questions — *Compliance → Criteria* (Batch 3: stored per store with who answered and when, no longer in the URL. `tests/batch3.test.mjs`)
- [x] Record a reviewer decision for a criterion, with a required rationale; a stored decision that does not apply to this audit is shown and explained — *Compliance → Criteria* (Batch 3, `tests/batch3.test.mjs`)
- [x] Request an exception from a criterion, with the criterion and store picked, not typed — *Compliance → Criteria* (Batch 3, `tests/batch3.test.mjs`)
- [x] Record evidence states for a criterion — *Compliance → Criteria* (Batch 3: now "Attach evidence": pick a registered artifact for a requirement, which opens a stored review. The what-if states that lived in the URL are gone. `tests/batch3.test.mjs`)
- [x] Open the check outcomes behind a criterion — *Compliance → Criteria*
- [x] Browse the pack by framework, with sources and required evidence — *Compliance → Criteria → Frameworks view*
- [x] Read what each framework says about encryption at rest and in transit, and its relationship label — *Compliance → Criteria → Frameworks view*
- [x] See a criterion's crypto observations as state chips, with fallback evidence explained — *Compliance → Criteria*
- [x] See PCI storage encryption and PAN data-level protection as two separate rows — *Compliance → Criteria*
- [x] See the built-in crypto posture policies and the state that triggers each — *Compliance → Policies*
- [x] See the crypto gate rules the server evaluates: decision, trigger, clearing evidence, and basis — *Compliance → Policies*
- [x] Register an evidence artifact with its scope, period, and hash — *Compliance → Evidence*
- [x] Move an artifact through its lifecycle, including supersession — *Compliance → Evidence*
- [x] See what each artifact was judged to evidence, per criterion — *Compliance → Evidence*
- [x] See which artifacts are always required and which are conditional fallback evidence — *Compliance → Evidence*
- [x] Request, approve, and revoke an exception — *Compliance → Exceptions* (Batch 1: revoking now asks first; it used to act on one click)
- [x] See exceptions counted as pending, active, and expired — *Compliance → Exceptions*
- [x] Export a criterion's position with its evidence, exceptions, and caveats — *Compliance → Criteria*

## Operations (was: Runtime Alerts, Detection Engine, Alerting, Audit Log, Status, Ingest Firewall)

- [x] List runtime alerts with principal, rule, and severity filters — *Operations → Runtime*
- [x] Refresh alerts — *Operations → Runtime*
- [ ] Send a test runtime event — *Operations → Runtime*
- [ ] Open one runtime event's detail — *Operations → Runtime*
- [x] Read and change detector settings: bulk volume, collection sweep, enumeration, rate baseline, cooldown — *Operations → Detectors* (2026-09-28, §17: four named rules with units and inline validation; untouched values round-trip exactly; discard, refused saves keep the draft, leaving with edits asks first, non-admins read only. `tests/detectors-ingest.test.mjs`)
- [x] Read and change alerting: webhooks and minimum severity — *System → Alerting* (Batch 3: a row per webhook instead of JSON; masked values round-trip unchanged; invalid input is refused with a reason. `tests/batch3.test.mjs`)
- [x] Screen chunks through the ingest firewall in gate mode — *Operations → Ingest* (2026-09-28, §17: the Check content tab; soft/hard is in the Settings disclosure (2026-10-06, Phase 12: Settings fold away under a summary of their current values); results read "would block", per chunk, with the run's detection coverage. `tests/detectors-ingest.test.mjs`)
- [x] Preview redaction — *Operations → Ingest* (2026-09-28, §17: its own tab; counts-only kept. `tests/detectors-ingest.test.mjs`)
- [x] Analyze chunk boundaries — *Operations → Ingest* (2026-09-28, §17: the Check chunk boundaries tab; needs two chunks and a whole-number window. `tests/detectors-ingest.test.mjs`)
- [x] Create a DSAR request — *Compliance → Privacy* (Batch 3: stores picked from the registry, none meaning all. `tests/batch3.test.mjs`)
- [x] Download a request's erasure evidence and read each store's erasure receipts, with the audit chain's state — *Compliance → Privacy* (Batch 3, `tests/batch3.test.mjs`)
- [x] List DSAR requests with status and coverage — *Compliance → Privacy* (Batch 1: status is a chip with a readable label, the request time is relative and local)
- [x] Execute an erasure only after typing the subject into an in-page confirmation, never on a missing or dismissed dialog — *Compliance → Privacy* (`tests/dialogs.test.mjs`)
- [ ] Open a DSAR record's full payload — *Compliance → Privacy*
- [x] Read the hash-chained audit log and its verification state — *System → Audit log* (Batch 1: each entry's details are a key/value list, not a JSON block)
- [x] Read readiness checks, versions, and runtime configuration — *System → Status* (Batch 1: checks are chips; the raw record is behind a closed disclosure)
- [x] See local NLP detection status and, when it is degraded, the command that installs the model — *System → Status* (2026-09-28: `install_command` from `GET /admin/detection` is a copyable line; absent, nothing is shown. `tests/account.test.mjs`)
- [x] Sign in, change a temporary password, and sign out; a session that ends returns to sign-in and then to the same page — *Shell* (2026-09-28: only when the server has sign-in on; token deployments keep the bearer token field. `tests/account.test.mjs`)
- [x] Manage console users: add with a temporary password, edit roles, reset a password, disable and enable — *System → Users* (2026-09-28: admin only, sign-in on only. `tests/account.test.mjs`)
- [x] See your own profile, change your password, list your live sessions and sign one or all others out — *Account → Settings* (2026-10-07: from the account menu; local accounts only, other sign-in methods are told where their credential is managed. `tests/settings.test.mjs`)
- [x] Choose the theme (System, Light, Dark) and whether times show in local time or UTC, saved in this browser — *Account → Settings* (2026-10-07: display only; exports and evidence keep their timestamps. `tests/settings.test.mjs`)
- [x] Offer each principal only the controls its roles allow, with the role a disabled control needs beside it, and a server refusal shown in the server's words next to the control — *Shell* (2026-09-29: from `/auth/session` `effective_roles`; admin implies every role, compliance does not imply operator; an unknown principal is not second-guessed. `tests/roles.test.mjs`)
- [x] Say "You signed out" only after the server confirms it; on failure drop cached data, keep the session, and offer Retry — *Shell* (2026-09-29, `tests/roles.test.mjs`)
- [x] Tell whoever opened a privacy request that another compliance user must execute its erasure, unless they are an admin or separation of duties is off — *Compliance → Privacy* (2026-09-29, `tests/roles.test.mjs`)

## Overview

**Migration status:** vanilla only. The in-console React preview (`?ui=react`)
and its comparison test `tests/react-areas.test.mjs` were removed on 2026-09-25.

- [x] Store, policy, findings, and runtime-alert signal — *Overview* (Phase 4: now an attention band; the community-version tile moved to *System → Status* and the sidebar footer. Batch 3: store and runtime-alert counts are header facts, findings are distinct open findings, and unreadable policies are a note in the inbox)
- [x] Unavailable history renders "Unavailable", never `0` — *Overview*
- [x] Coverage caveat stated next to severity totals — *Overview* (Batch 3: next to the open-finding counts)
- [-] Quick links into the primary tasks — *Overview* — **dropped in Phase 4.** The marketing callout they sat in was replaced by the attention band, whose cards navigate *with the filter already applied*, which is strictly more useful. The one genuinely needed shortcut for an empty install (connect a store) is the estate table's empty-state action. A guided first run is Phase 6.
- [x] Attention band: critical and high findings, stores never assessed, runs with incomplete coverage, runtime alerts, policy availability — *Overview* (Batch 3: replaced by the "Needs you" inbox from `GET /admin/home`, which carries never-assessed and partial stores among its items, and by distinct open findings from each store's latest audit. Nothing it said was dropped.)
- [x] "Needs you" inbox: each item a count, what it is, and a link to where it is dealt with; an empty inbox says what was checked; an unreadable one is not empty — *Overview* (Batch 3, `tests/batch3.test.mjs`)
- [x] Open findings are distinct fingerprints from each store's latest audit, never-assessed stores are not zero, suppressed are counted apart — *Overview* (Batch 3)
- [x] Findings recorded over time, with unmeasured days hatched — *Overview*
- [x] Estate posture: last assessed age and that run's coverage per store — *Overview*

## Shell (must survive every migration)

- [x] Theme toggle, persisted per browser — *Shell* (Batch 1: in the top bar at desktop widths; under More below 900px)
- [x] Bearer token entry, persisted for the session — *Shell* (Batch 1: under More below 900px)
- [x] API health indicator with authentication state — *Shell* (Batch 1: under More below 900px)
- [x] Version in the sidebar footer — *Shell*
- [x] Deep links to any view with its state — *Shell*
- [x] The chosen store carries across an area's tabs; no screen picks the first store, and a remembered one is labelled as such — *Shell* (Batch 3, `tests/batch3.test.mjs`)
- [x] Frameworks is a view within Criteria, Templates within Policies, Runs within History; False positives sits under Findings; Audit log, Alerting and Status are a System group at the sidebar's foot; Docs is a help icon. Every view id and alias still resolves — *Shell* (Batch 3, `tests/parity.test.mjs`, `tests/batch3.test.mjs`)
- [x] Old single-segment links (`#/schema`, `#/dsar`) still resolve — *Shell*
- [x] Keyboard operation of every action, including dialogs — *Shell*
- [x] Live-region announcements on route change — *Shell*
- [x] Each screen names itself once, in its own header; the route lands focus on that heading — *Shell* (Batch 1; the top bar no longer repeats the title and subtitle. `tests/page-structure.test.mjs`)
- [x] Each screen's explanation is kept, in a closed "About this screen" disclosure under its header — *Shell* (Batch 1; the intro strip's purpose, steps, non-count facts and links moved there, none deleted)
- [x] Dialogs close when the page changes; a detail opened from another detail offers Back — *Shell* (Batch 1, `tests/dialogs.test.mjs`)
- [x] Destructive actions ask in the page, never through `window.confirm`, and do nothing if the question cannot be shown — *Shell* (Batch 1, `tests/dialogs.test.mjs`)

---

## Verification log

Nothing is checked until it has been verified in the new location. Rows are
verified by `tests/parity.test.mjs`, which parses this file, resolves every
destination against the console's own area and tab registry, and renders each
one. A destination this file names that does not exist fails the build.

| Date | Change | Rows verified | By |
|---|---|---|---|
| 2026-10-08 | Phones and touch (`docs/console_ux_roadmap.md`, "Shipped (2026-10-08)"). On a touch screen, controls are 44px and fields 16px. Dialogs are sheets below 640px, and the page under an overlay is held still. Findings gains a phone bar for select all and sort. The crypto matrix becomes cards. Row menus open upward near the foot of the screen, and a tap opens a tooltip. Every workflow keeps its destination; no row was added, dropped or re-checked (`tests/layout.test.mjs`, `tests/a11y.test.mjs`, `tests/findings-actions.test.mjs`, `tests/parity.test.mjs`, and `npm run check:mobile` at 320, 360, 390, 768 and 1440px) | 124 of 148, 2 deliberately dropped | main session |
| 2026-10-06 | Console overhaul Phase 12: Compliance, Operations, Estate and System on the shared patterns. Criteria's store picker moved into the page header and its explainer into "About this screen"; Evidence's records are a tab list; Ingest's settings fold away (the Ingest gate row's wording edited); Runtime's "Send test event" is the header action and its filters a search toolbar; a collection opens as its own page, linked from its store. No row was added, dropped or re-checked (`tests/screens.test.mjs`, `tests/detail-pages.test.mjs`, `tests/parity.test.mjs`) | 124 of 148, 2 deliberately dropped | frontend-ux |
| 2026-10-06 | Console overhaul Phase 7 (`docs/console_ux_roadmap.md`, Batch 4): the Assessments tabs "Run" and "Archive" were renamed "New assessment" and "History" (view ids `assess`/`history` unchanged; `#/new-assessment` and `#/runs` added as aliases, `#/archive` kept). The 19 Assessments rows and the Shell navigation row had their destinations or wording edited to the new labels; no row was added, dropped or re-checked. History and Runs now share one switch (Saved audits · Individual scans · Runs) instead of two stacked ones (`tests/batch3.test.mjs`, `tests/workflow.test.mjs`, `tests/parity.test.mjs`) | 124 of 148, 2 deliberately dropped | frontend-ux |
| 2026-09-24 | Console UX Batch 3 (`docs/console_ux_roadmap.md`): "Needs you" inbox and distinct open findings, store carried across tabs, next steps after an audit, findings list first with a side-panel detail, row menus, store edit, reviewer decisions and stored applicability, attach evidence and request exceptions from a criterion, the finding kept in Actions, the approval queue, privacy-request stores and erasure evidence, the webhook editor, and navigation consolidated (`tests/batch3.test.mjs`, `tests/parity.test.mjs`, `tests/react-areas.test.mjs`) | 113 of 140, 1 deliberately dropped | frontend-ux |
| 2026-09-24 | Console UX Batch 0 (console) and Batch 1 (`docs/console_ux_roadmap.md`): in-page confirmation replacing `window.confirm` (store delete, policy delete, exception revoke, erasure), dialog stack with Back, one header per page, status chips, notes, readable times and records, one-row header (`tests/dialogs.test.mjs`, `tests/page-structure.test.mjs`, `tests/layout.test.mjs`) | 95 of 126, 1 deliberately dropped | frontend-ux |
| 2026-09-24 | Crypto posture: Estate → Crypto screen, crypto rows in Frameworks, Criteria and Policies , run-form probes, conditional fallback evidence, release gate (`tests/crypto.test.mjs`) | 88 of 120 |
| 2026-09-17 | Phase 3: sixteen destinations re-parented into six task areas | 37 of 69 |
| 2026-09-18 | Phase 9: Assessments (run screen) migrated behind the flag | 62 of 94 |
| 2026-09-18 | Phase 9: Estate migrated behind the same flag; rows verified against both | 62 of 94 |
| 2026-09-17 | Phase 9: Overview migrated behind a flag; rows verified against both implementations | 62 of 94 |
| 2026-09-17 | Phase 7: compliance centre (frameworks, evidence, exceptions, DSAR moved) | 62 of 94 |
| 2026-09-17 | Phase 6: estate depth, capability matrix, first-run path | 55 of 87 |
| 2026-09-17 | Phase 5: findings as cases (owner, state, history, bulk, server-side query) | 49 of 81 |
| 2026-09-17 | Phase 4: evidence surfaces (criteria, charts, attention band, pre-flight) | 43 of 75, 1 deliberately dropped | `tests/parity.test.mjs` — resolves every destination named here, renders all 17 screens, and asserts each original view id survived |

The 26 unchecked rows are actions that need a live connector or a
person to complete them (adding a store, running an audit, submitting a DSAR).
Their screens render and their destinations resolve; the actions themselves want
a manual pass or an integration test before anyone claims them.
