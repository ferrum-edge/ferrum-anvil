---
name: sol-agents
description: Orchestrate GPT-6.1 Sol Codex CLI workers for Ferrum Anvil when the user asks Claude to delegate to Sol workers, with optional fast mode on explicit request. Do not use for ordinary single-agent work or when you are already a dispatched worker.
---

# GPT-6.1 Sol agents

Read [the canonical skill](../../../.agents/skills/sol-agents/SKILL.md) and act as its Claude
orchestrator. Use its shared launcher, references, isolation, and verification rules.

```bash
<ABS_REPO>/.agents/skills/sol-agents/scripts/dispatch-agent.sh \
  --worktree <ABS_WORKER_WORKTREE> \
  --prompt-file <ABS_PROMPT_FILE> \
  --effort <low|medium|high|xhigh|max|ultra>
```

Append `--fast` only for an explicit request such as "Sol high with fast mode". Use `--no-fast`
for "fast mode off", "without fast mode", or "standard mode". Omit both flags for standard
mode by default. Carry an explicit choice through continuations until the user changes it; never
pass both flags. The launcher pins `gpt-6.1-sol` with `service_tier="default"` and
`features.fast_mode=false`, or `service_tier="fast"` and `features.fast_mode=true` with `--fast`.
Keep the selected effort unchanged and report an unavailable tier.

For implementation, read [agent-brief.md](../../../.agents/skills/sol-agents/references/agent-brief.md).
For a continuation, also read [continuation-brief.md](../../../.agents/skills/sol-agents/references/continuation-brief.md).
