# Lab profile `mcp`: MCP through `mcp_gateway`

The `mcp` profile runs Anvil's MCP requests (docs/protocols.md §3.14) against the pinned Ferrum
Edge release with its `mcp_gateway` plugin in **aggregate-router** mode, in front of the fixture
MCP server `anvil_fixtures::mcp`. Each scenario is one MCP request, so one session: `initialize`,
`notifications/initialized`, the operation and `DELETE`.

```sh
cargo run -p anvil-lab -- run mcp --untrusted-pass
cargo run -p anvil-lab -- up mcp        # gateway on http://127.0.0.1:17180/mcp until Ctrl-C
```

| Listener | Port |
|---|---|
| Gateway HTTP (MCP endpoint `/mcp`) | 17180 |
| Gateway admin | 17190 |
| MCP server behind the gateway (JSON answers) | 17101 |
| The same server answering with event streams, addressed directly (control) | 17102 |

Configuration: `lab/gateway/mcp.conf`, `lab/gateway/mcp.yaml`. One upstream server (`fx`), so the
public tool names are `fx.<tool>`. The policy (`policy.tools`, keyed by public name):

| Tool | Policy | Listed | `tools/call` |
|---|---|---|---|
| `fx.echo`, `fx.add`, `fx.fail` | `allow` | yes | forwarded (arguments validated against `inputSchema`) |
| `fx.delete_all` | `deny` | yes (`hide_denied_tools` and `hide_denied_items` off) | `-32001` |
| `fx.internal_audit` | `hide_from_discovery` | no | `-32001` |
| `fx.session`, `fx.new_tool` | not configured: `default_action: deny`, `discovery.on_new_tool: hide_until_configured` (default) | no | `-32001` |

## Scenarios

The fixture's record of the calls that reached it is the ground truth that the gateway forwarded
or refused a call. With a trusted destination, each refusal must be explained by its catalog
outcome (capped at `likely`: plain HTTP, and a body a server could also send); the untrusted pass
must make no gateway attribution.

| ID | Request | Expected |
|---|---|---|
| CTRL-MCP-001 | `tools/call echo`, straight to the event-stream server | success; the JSON-RPC response read from the stream; the four exchanges seen; no `ferrum.*` finding |
| MCP-001 | `tools/list` | `fx.echo` and `fx.delete_all` listed, `fx.internal_audit` and `fx.new_tool` not; `fx.echo`'s `inputSchema` digest is the server's; no catalog outcome |
| MCP-002 | `tools/call fx.echo {"text": …}` | success; `$.result.structuredContent.text` checked; forwarded |
| MCP-003 | `tools/call fx.delete_all` | `-32001`, `plugin.mcp_gateway.tool_denied`; not forwarded |
| MCP-004 | `tools/call fx.internal_audit` | `-32001`, `plugin.mcp_gateway.tool_denied`; not forwarded |
| MCP-005 | `tools/call fx.echo {"text": 42}` | `-32602`, `plugin.mcp_gateway.invalid_params`; not forwarded |
| MCP-006 | `tools/call fx.nope` | `-32003`, `plugin.mcp_gateway.unknown_item`; not forwarded |
| MCP-007 | `tools/list` with `initialize` off | HTTP 400, `-32600`, `plugin.mcp_gateway.session_or_version_rejected` |
| MCP-008 | `tools/call fx.fail` | a result with `isError: true`: `app.mcp_tool_error`, an application failure, no catalog outcome; forwarded |

Anvil sends MCP requests as `Content-Type: application/json` with no `charset`, so v0.9.10's refusal
of a non-UTF-8 request charset (`-32600` before routing, GHSA-4f9m-cfqg-fhx9) changes no scenario
here; the profile configures no `ai_prompt_shield`.

Not covered yet: per-consumer tool grants and OpenAPI-generated tools. The pinned releases'
`mcp_gateway` has one tool policy for every caller (it binds a session to the principal that opened
it, but grants no tools per consumer) and no OpenAPI tool source; the profile gains scenarios when a
pinned release has them.
