# ADR 0007: Failure lab against the real gateway

## Decision
- Scenarios run against the pinned Ferrum Edge release binary (v0.9.5;
  sha256 in `lab/gateway/RELEASE.lock`) in file mode, with generated PKI,
  loopback-only ports and controllable fixtures.
- Ground truth comes from fixture logs and the gateway's operator
  `error_class` log lines. It is used only by checks and never fed to the
  engine.
- Every scenario runs twice: with the destination declared as a trusted
  Ferrum gateway, and untrusted (where no gateway attribution may appear).
  Lookalikes and recovery requests are part of each scenario. Infeasible
  cases are recorded as `skipped` with a reason, never as passes.

## Consequences
- Coverage claims are grounded in real behaviour rather than injected enums.
  Cases that would need gateway-internal fault hooks are marked as such.
