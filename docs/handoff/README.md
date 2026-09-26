# Ferrum Anvil implementation handoff

**Ferrum Anvil — Put your APIs to the test**  
Prepared September 25, 2026.

This package is a researched plan, not built software or an executed test report.

## Contents

- `FERRUM_ANVIL_BUILD_PLAN.md`: full product/architecture specification, existing Ferrum diagnostic findings, data/auth/security design, implementation packages, local verification, and website release gates.
- `FERRUM_ANVIL_FAILURE_MATRIX.json`: 182 planned scenarios in 10 categories, with stimuli, expected results, prohibited claims and remediation/recovery guidance. The implementing agent must turn them into fixtures/tests and expand source-path coverage.
- `FERRUM_ANVIL_AGENT_PROMPT.md`: instructions to give the implementing agent together with the other two files.

Start the agent with `FERRUM_ANVIL_AGENT_PROMPT.md`. Keep all three files available in its workspace. The master plan’s source references distinguish inspected existing behavior from proposed contracts and future implementation.

The reviewed gateway snapshot was `8ef06f2cece2847b552b7858c73fa9a1a265442f`. Reconcile current code and actual published releases before building. The website repository is `ferrum-edge/ferrumedge`; no repository was modified while preparing this package.
