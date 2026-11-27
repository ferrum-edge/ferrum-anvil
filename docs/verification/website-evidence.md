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

`5acfcd4fdf1f415968104e276f859b04f346140d`: ferrumedge `main` after ferrum-edge/ferrumedge#148. The Anvil pages
still describe the published `anvil-v0.1.9`.

| Run | Event | Anvil commit | Result |
|---|---|---|---|
| [46023775311](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/46023775311) | pull_request, 2026-11-27 | `01e9259d` (the pull request's test merge of the pin change into `main`) | `pass`: 594 tests, 592 pass, 0 fail, 0 cancelled, 2 skipped |

The 2 skipped tests are the live highlight.js CDN checks in `tests/components.test.js`
(`skip: RUN_LIVE_ASSET_CHECKS !== '1'`, the only two skips in the suite), which do not concern Anvil.

Between `4e3caa5` and this pin the website merged #140, #145, #146, #147 and #148, and the test count rose from
532 to 594. For Anvil:
- #140 (benchmark pages rebuilt from CI, accuracy audit): `guides/anvil-getting-started` now builds the desktop UI
  (`npm ci && npm run build` in `apps/desktop`) before `cargo build --workspace`; shared pages, guides,
  `download.html` and `releases.html` were edited, and `tests/fixtures/anvil-vocabulary.json` gained one word;
- #145 (the deploy waits for the Pages artifact) changes no Anvil content; #146 adds a Ferrum Migration page and
  a Migration entry to the shared navigation;
- #147 (corrected licence and contracts facts; compatibility matrix, security and 404 pages): `anvil.html` links to
  the compatibility matrix (`releases#compatibility`), whose Anvil row reads Edge v0.9.20 and
  `contracts-edge-0.9.20` from `lab/gateway/RELEASE.lock` and `contracts/ferrum-contracts/PIN` at `anvil-v0.1.9`
  (a new `release.contracts` fact in `tests/fixtures/anvil-capabilities.json`). The claim check also reads the
  Anvil blocks on `why-ferrum.html`, `about.html`, `licensing.html` and `security.html` (`BLOCK_PAGES` in
  `tests/anvil-claims.js`), and `tests/anvil.test.js` accepts the organization's private vulnerability reporting
  link (`/security/advisories/new`);
- #148 adds the 1.0.0 candidates section (`releases.html#v1-candidates`), which deliberately has no Anvil row.

The Anvil entry of `tests/fixtures/release-audit.json` (assets, digests and `release-evidence.json` targets,
checked 2026-11-23) is unchanged. The tests REL-006, REL-007 and REL-008 cite keep their names, and all fourteen
Anvil and shared pages with Anvil content (the six Anvil pages and `index`, `guides/index`, `releases`,
`download`, `why-ferrum`, `about`, `licensing` and `security`) carry `nav-container` and `footer-container` and load
`components.js` at their depth.

At this pin, the claim check reads 845 claim elements in 21 regions (`node tests/anvil-claims.js --counts`, run on a
`git archive` extract of `5acfcd4`; the same command on `4e3caa5` reproduces the recorded 832 in 17).

## Previous pins

`4e3caa5d4b6e72c1d8d495e8606066a0df30f594` (ferrumedge `main` after #144), which moved the site to the published
`anvil-v0.1.9`. 530 of 532 tests passed, with 0 failed and the same 2 skipped, in workflow_dispatch run
[45098664403](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/45098664403) on `50624e69` (the pin change)
and pull_request run [45099361622](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/45099361622), 2026-11-23.
At that pin the claim check read 832 claim elements in 17 regions.

`f8b206ace58ea0587ef19a817bb64cafda784ede` (ferrumedge `main` after #143), which described `anvil-v0.1.8`. 530 of
532 tests passed, with 0 failed and the same 2 skipped, in workflow_dispatch run
[45012006101](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/45012006101) on `bfdb1196` (the pin change)
and pull_request run [45012375360](https://github.com/ferrum-edge/ferrum-anvil/actions/runs/45012375360), 2026-11-22.
At that pin the claim check read 832 claim elements in 17 regions.

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
- **The pinned commit only.** The check covers the website at the pinned commit, which describes `anvil-v0.1.9`. It
  re-runs the website's tests against that commit and its recorded audit, not against the live site or the
  release being built, so it gives the same result whenever it runs. A later release's pages are covered once the
  pin moves to a website commit that describes that release.
- **Recorded, not re-fetched.** Release assets and digests are compared as recorded in the website's
  `tests/fixtures/release-audit.json`, and Anvil capabilities as recorded in
  `tests/fixtures/anvil-capabilities.json`. Neither is re-fetched on each run. The website repository's own CI
  re-verifies the capability fixture against a checkout of `anvil-v0.1.9`
  (`scripts/verify_anvil_capabilities.py --anvil`); this workflow does not run that step.
- **Stated limits elsewhere.** Each case's own limits are in its `matrix-status.json` entry. The residual limits
  of the REL-008 claim check are listed in ferrumedge's `README.md` ("Residual limits of a word-level check").
