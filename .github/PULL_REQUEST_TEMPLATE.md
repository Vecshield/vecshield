<!-- Thanks for contributing. CONTRIBUTING.md has the setup and the gates. -->

## What this changes

<!-- And why. Link the issue if there is one. -->

## How you verified it

<!-- Name the checks you actually ran, with their results. `pytest -rs` prints
     the skip reasons; a run that went green because an optional SDK was
     missing is not evidence. -->

- [ ] `ruff check .`
- [ ] `pytest -rs` (and I read the skip report)
- [ ] `npm test` in `vecshield_platform/api/dashboard/` — *if the console changed*
- [ ] `benchmark run` + `compare` — *if a detector changed*

## Checklist

- [ ] A new or changed route has its authorization gate in
      `tests/test_route_authorization.py`.
- [ ] A check whose outcome changed, or a check added or renamed, is reflected
      in `tests/assessment_contract.py`.
- [ ] A new detector comes with labelled corpus cases, including a hard
      negative.
- [ ] Nothing reports unknown coverage as a pass, and no partial read is
      reported as clean.
- [ ] No secrets, real personal data or customer content in the diff, the
      fixtures, or the log output.
- [ ] An interface, security boundary or user-facing default that changed has
      an ADR in `docs/adr/`.
