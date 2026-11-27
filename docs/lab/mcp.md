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
| HTTP echo server, the backend of the OpenAPI bridge route `/echo` | 17103 |

Configuration: `lab/gateway/mcp.conf`, `lab/gateway/mcp.yaml`. One upstream server (`fx`), so the
public tool names are `fx.<tool>`. The policy (`policy.tools`, keyed by public name):

| Tool | Policy | Listed | `tools/call` |
|---|---|---|---|
| `fx.echo`, `fx.add`, `fx.fail` | `allow` | yes | forwarded (arguments validated against `inputSchema`) |
| `fx.delete_all` | `deny` | yes (`hide_denied_tools` off) | `-32001` |
| `fx.internal_audit` | `hide_from_discovery` | no | `-32001` |
| `fx.session`, `fx.new_tool` | not configured: `default_action: deny`, `discovery.on_new_tool: hide_until_configured` (default) | no | `-32001` |

Two more routes, each with its own `mcp_gateway` instance:

- **`/mcp-grants`: per-consumer tool grants.** `key_auth` (`X-Lab-Api-Key`, keys generated per lab
  start) maps the caller to a Consumer, and the instance (namespace `gx`, the same upstream server)
  allows `gx.echo` only with `allowed_groups: [mcp-readers]` and `denied_groups: [mcp-suspended]`.
  Consumers: `mcp-reader` (`mcp-readers`), `mcp-outsider` (`lab-other`) and `mcp-suspended` (both
  groups). The gateway filters `tools/list` per caller and refuses an ungranted call with `-32001`,
  the answer a denied tool gets.
- **`/echo`: the OpenAPI bridge on a literal-prefix route.** The instance (endpoint `/echo/mcp`)
  generates `br.echo` from one operation, `GET /echo/bridge`, which the gateway runs against the
  route's own backend, the echo server on 17103; no MCP server is involved.

At v0.9.21 `policy.hide_denied_tools` is the single setting: v0.9.21 removed
`discovery.hide_denied_items` (#7136; the key fails config load), so the profile no longer sets a
`discovery` block and `lab/gateway/lint-profiles.rb` refuses that key. (At the retired v0.9.20 a
denied tool was listed only when both were off, and `hide_denied_items` defaulted to on.)

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
| MCP-009 | as `mcp-reader` on `/mcp-grants`: `tools/list`, then `tools/call gx.echo` | `gx.echo` listed to the grantee; the call succeeds (`structuredContent.text` checked), no catalog outcome; forwarded |
| MCP-010 | as `mcp-outsider` (no allowed group): `tools/list`, then `tools/call gx.echo` | `gx.echo` not listed to it; `-32001`, `plugin.mcp_gateway.tool_denied`; not forwarded. Recovery: the grantee's call succeeds |
| MCP-011 | as `mcp-suspended` (an allowed and a denied group) | the denied group wins: not listed, `-32001`, `plugin.mcp_gateway.tool_denied`; not forwarded. Recovery: the grantee's call succeeds |
| MCP-012 | `tools/call br.echo` on `/echo/mcp` | the bridged `GET /echo/bridge` reached the route's backend exactly once and its JSON is the tool's `structuredContent` (`method` `GET`, `target` `/echo/bridge`); `isError` false; success with no catalog outcome; no MCP server called |

Anvil sends MCP requests as `Content-Type: application/json` with no `charset`, so v0.9.10's refusal
of a non-UTF-8 request charset (`-32600` before routing, GHSA-4f9m-cfqg-fhx9) changes no scenario
here; the profile configures no `ai_prompt_shield`.

Per-consumer grants and the OpenAPI bridge arrived in v0.9.9 (see
[the v0.9.9 delta](../audit/gateway-0.9.9-delta.md); a failed or refused bridged call is
`plugin.mcp_gateway.openapi_bridge_error_result`). Earlier releases (v0.9.5 to v0.9.8) had one tool
policy for every caller and no OpenAPI tool source.
