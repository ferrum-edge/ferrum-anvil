# ADR 0007: Failure lab against the real gateway

## Decision
- Scenarios run against a pinned Ferrum Edge release binary in file mode
  (mesh mode for the mesh profile), with generated PKI, loopback-only ports
  and controllable fixtures. The default pin is `lab/gateway/RELEASE.lock`
  (v0.9.7, first v0.9.5); every supported release keeps its own lock in
  `lab/gateway/releases/` and is selected with `--release`.
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
