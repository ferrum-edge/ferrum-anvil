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

`f8b206ace58ea0587ef19a817bb64cafda784ede`: ferrumedge `main` after ferrum-edge/ferrumedge#143. That commit moves
the site to the published `anvil-v0.1.8` and re-records the capability evidence from ferrum-anvil at that tag.

| Run | Event | Anvil commit | Result |
|---|---|---|---|
| [45012006101](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/45012006101) | workflow_dispatch, 2026-11-22 | `bfdb1196` (the pin change) | `pass`: 532 tests, 530 pass, 0 fail, 0 cancelled, 2 skipped |
| [45012375360](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/45012375360) | pull_request, 2026-11-22 | `dcd3d0ae` (the pull request's test merge of the pin change into `main`) | `pass`: 532 tests, 530 pass, 0 fail, 0 cancelled, 2 skipped |

The 2 skipped tests are the live highlight.js CDN checks in `tests/components.test.js`
(`skip: RUN_LIVE_ASSET_CHECKS !== '1'`), which do not concern Anvil.

Between `f3551a0` and this pin, the website's tests grew from 461 to 532. 66 of the new tests cover site work
unrelated to Anvil: the contact Worker (54), the shared components and page CSP (5), CSS (2) and accuracy guards in
`tests/releases.test.js` (5). The other five are new Anvil tests in `tests/anvil.test.js`: one from #112 (the Anvil
block inventory) and four from #115 (page walks and entity handling). For Anvil:
- `tests/fixtures/release-audit.json` re-records the Anvil entry from the published `anvil-v0.1.8`: 35 assets with
  GitHub's digests (checked 2026-11-22), the 33 `SHA256SUMS` lines and the `release-evidence.json` targets, and
  records the published advisory GHSA-7p29-5g2w-wwq4, which affects 0.1.8;
- `tests/fixtures/anvil-capabilities.json` is re-recorded from ferrum-anvil at `anvil-v0.1.8` (`164edccc`): the
  0.9.20 catalog is added (620 outcomes, 17 headers, nine public tokens including `loop_detected`), the lab is
  recorded as running Edge v0.9.20 only, the upgrade note is 0.1.8's, and a new `export.dataset-attachments`
  capability backs the copy saying both workspace bundle modes carry free text and stored dataset files as
  written; `tests/fixtures/anvil-vocabulary.json` is regenerated;
- `tests/anvil.test.js`, `tests/anvil-capabilities.test.js` and `tests/anvil-claims.js` changed in three other
  website PRs: constant regexes compiled once (#111), the Anvil page and block inventory derived from the claim
  check (#112), and entities read in `anvil.test.js` as the claim check reads them, with dot directories skipped in
  page walks (#115). In #143 the pinned values follow the release (version, date, supported versions, catalog count
  and the upgrade-guide anchor). The tests REL-006, REL-007 and REL-008 cite keep their names, and all ten Anvil and
  shared pages still carry `nav-container` and `footer-container` and load `components.js` at their depth.

At this pin, the claim check reads 832 claim elements in 17 regions (`node tests/anvil-claims.js --counts`, run on a
checkout of `f8b206a`).

## Previous pins

`f3551a0664aaec1ec23666d37cf9f962d6dca0a7` (ferrumedge `main` after #109), which described `anvil-v0.1.7`. 459 of
461 tests passed, with 0 failed and the same 2 skipped, in workflow_dispatch run
[41589535671](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41589535671) on `3a7f371e` (the pin change)
and pull_request run [41589538071](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41589538071), 2026-11-03.
At that pin the claim check read 824 claim elements in 17 regions.

`1f89dfd94915aa419b80decf9666dc1bcc769df8` (ferrumedge `main` after #108), which described `anvil-v0.1.5`. 459 of
461 tests passed, with 0 failed and the same 2 skipped, in workflow_dispatch run
[41359301938](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41359301938) on `383aa911` (the pin change),
2026-11-01.

`e4fe8b9a1b1de6b8dfeb021111bea262828fe57c` (ferrumedge `main` after #105). 403 of 405 tests passed, with 0 failed
and the same 2 skipped, in these runs:
- workflow_dispatch run [41280626152](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41280626152) on
  `main` `f2beb1b8`;
- push run [41185707622](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41185707622) and
  workflow_dispatch run [41185714154](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41185714154) on
  `main` `21d8778`;
- the website job of release dry runs [41234488118](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41234488118)
  and [41192909519](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/41192909519).

Between `e4fe8b9` and `1f89dfd`, the tests REL-006 and REL-007 cite were unchanged in substance:
- `tests/components.test.js` and `tests/fixtures/release-audit.json` did not change;
- in `tests/anvil.test.js`, the HTML matching now accepts attributes on `<title>`, `<td>` and `<meta>`. The same
  file's REL-008 assertions were also strengthened: the gRPC-Web load cell, the load guide's units and refusal
  tables, and the plan-time refusal pins;
- `tests/releases.test.js` changed only a Docker-registry line.

`1f89dfd` added the capability-evidence tests (REL-008) and a test that no link nests inside another on any
page with a checked Anvil region.

## Scope

These limits apply to all three cases:
- **The pinned commit only.** The check covers the website at the pinned commit, which describes `anvil-v0.1.8`. It
  re-runs the website's tests against that commit and its recorded audit, not against the live site or the
  release being built, so it gives the same result whenever it runs. A later release's pages are covered once the
  pin moves to a website commit that describes that release.
- **Recorded, not re-fetched.** Release assets and digests are compared as recorded in the website's
  `tests/fixtures/release-audit.json`, and Anvil capabilities as recorded in
  `tests/fixtures/anvil-capabilities.json`. Neither is re-fetched on each run. The website repository's own CI
  re-verifies the capability fixture against a checkout of `anvil-v0.1.8`
  (`scripts/verify_anvil_capabilities.py --anvil`); this workflow does not run that step.
- **Stated limits elsewhere.** Each case's own limits are in its `matrix-status.json` entry. The residual limits
  of the REL-008 claim check are listed in ferrumedge's `README.md` ("Residual limits of a word-level check").
