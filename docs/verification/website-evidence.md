# Website evidence (REL-006, REL-007, REL-008)

This note is the single record of the hosted website check behind failure-matrix cases REL-006 (download
manifest match), REL-007 (website navigation) and REL-008 (website feature truth). Their entries in
`matrix-status.json` and `docs/completion-report.md` refer to it. Each case's entry still lists the tests
that check it and its own scope.

## The check

`.github/workflows/website-evidence.yml` does the following:
- checks out `ferrum-edge/ferrumedge` at the pinned commit `FERRUMEDGE_SHA` and fails unless HEAD is that commit;
- runs the website's own tests, `node --test --test-reporter=tap "tests/**/*.test.js"`, with Node 22.23.3 and
  `RUN_LIVE_ASSET_CHECKS` unset, so no live network asset checks run;
- uploads `website-evidence.json`, which records the website SHA, the command, the counts, the exit code and the result.

The result is `pass` only when the exit code is 0, at least one test passes, and none fails or is cancelled.

`release.yml` calls the workflow from its `website` job on every release run, whether a tag push or a dry run.
The job runs beside the build. **It does not gate the draft release**: a failure shows in the release run but
does not block it. The workflow also runs on manual dispatch and on pull requests and pushes to `main` that
change it, which is how a new pin is tried.

## Current pin

`1f89dfd94915aa419b80decf9666dc1bcc769df8`: ferrumedge `main` after ferrum-edge/ferrumedge#108. That commit ties
every Anvil capability claim on the site to evidence recorded from ferrum-anvil at `anvil-v0.1.5`.

| Run | Event | Anvil commit | Result |
|---|---|---|---|
| [41359301938](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41359301938) | workflow_dispatch, 2026-11-01 | `383aa911` (the pin change) | `pass`: 461 tests, 459 pass, 0 fail, 0 cancelled, 2 skipped |

The 2 skipped tests are the live highlight.js CDN checks in `tests/components.test.js`
(`skip: RUN_LIVE_ASSET_CHECKS !== '1'`), which do not concern Anvil.

## Previous pin

`e4fe8b9a1b1de6b8dfeb021111bea262828fe57c` (ferrumedge `main` after #105). 403 of 405 tests passed, with 0 failed
and the same 2 skipped, in these runs:
- workflow_dispatch run [41280626152](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41280626152) on
  `main` `f2beb1b8`;
- push run [41185707622](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41185707622) and
  workflow_dispatch run [41185714154](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41185714154) on
  `main` `21d8778`;
- the website job of release dry runs [41234488118](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41234488118)
  and [41192909519](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41192909519).

Between the two pins, the tests REL-006 and REL-007 cite are unchanged in substance:
- `tests/components.test.js` and `tests/fixtures/release-audit.json` did not change;
- in `tests/anvil.test.js`, the HTML matching now accepts attributes on `<title>`, `<td>` and `<meta>`;
- `tests/releases.test.js` changed only a Docker-registry line.

The new pin adds the capability-evidence tests (REL-008) and a test that no link nests inside another on any
page with a checked Anvil region.

## Scope

These limits apply to all three cases:
- **The pinned commit only.** The check covers the website at the pinned commit, which describes `anvil-v0.1.5`. It
  re-runs the website's tests against that commit and its recorded audit, not against the live site or the
  release being built, so it gives the same result whenever it runs. A later release's pages are covered once the
  pin moves to a website commit that describes that release.
- **Recorded, not re-fetched.** Release assets and digests are compared as recorded in the website's
  `tests/fixtures/release-audit.json`, and Anvil capabilities as recorded in
  `tests/fixtures/anvil-capabilities.json`. Neither is re-fetched on each run. The website repository's own CI
  re-verifies the capability fixture against a checkout of `anvil-v0.1.5`
  (`scripts/verify_anvil_capabilities.py --anvil`); this workflow does not run that step.
- **Stated limits elsewhere.** Each case's own limits are in its `matrix-status.json` entry. The residual limits
  of the REL-008 claim check are listed in ferrumedge's `README.md` ("Residual limits of a word-level check").
