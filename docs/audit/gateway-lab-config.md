# Ferrum Edge v0.9.5 gateway lab configuration (Ferrum Anvil failure lab)

Status: researched from source and tests, not yet run. The configs have not been started against a
downloaded binary. Every behavior below is cited to the v0.9.5 source or to a v0.9.5 functional
test, unless it is marked **inferred** or **verify live**.

Configs: `lab/gateway/` (8 profiles, listed in section 4). Structural lint:
`ruby lab/gateway/lint-profiles.rb`, which passes on all profiles today.

## 0. Provenance and citation convention

| Item | Value |
|---|---|
| Gateway tag | `v0.9.5` = `20e76030a05dc49c3804e969516c94ab101110b9` (2026-09-13) |
| Release asset | `ferrum-edge-macos-aarch64` plus `ferrum-edge-macos-aarch64.sha256` (`.github/workflows/release.yml:135-138,296-304`) |
| Asset features | `cargo build --features cloud-secrets --release --target aarch64-apple-darwin` (`release.yml:250-253`). This means default `crypto-ring` plus the Vault/AWS/GCP/Azure secret backends. `acme`, `pkcs11` and `ebpf` are not built in (`Cargo.toml:356-436`). |
| Handoff research SHA | `8ef06f2c…` is **newer** than v0.9.5 (it is a v0.9.6 release-notes commit). Revalidate any matrix/build-plan claim sourced from it against v0.9.5 before asserting it in a test. |

All `path:line` citations are relative to the gateway repo at tag v0.9.5. Reproduce any of them with:

```sh
git -C /Volumes/JustusStorage/GitHub/ferrum-edge/ferrum-edge show v0.9.5:<path>
```

## 1. Running the binary in file mode

### 1.1 Obtain and verify (not done yet; needs explicit approval to download)

```sh
TAG=v0.9.5; BASE=https://github.com/ferrum-edge/ferrum-edge/releases/download/$TAG
curl -fsSLO $BASE/ferrum-edge-macos-aarch64 && curl -fsSLO $BASE/ferrum-edge-macos-aarch64.sha256
shasum -a 256 -c ferrum-edge-macos-aarch64.sha256 && chmod +x ferrum-edge-macos-aarch64
./ferrum-edge-macos-aarch64 version --json   # expect {"version":"0.9.5","target":"aarch64-apple-darwin"} (docs/cli.md:405-413)
```

The URL pattern comes from `docs/cli.md:14-26`. Record the sha256 alongside the source SHA
(build plan §15.1).

### 1.2 Commands

A subcommand is required (`src/cli.rs:19-39`). In `docs/cli.md`: `run` is at `:47-95`, `validate` at `:96-204`, `reload` at `:276-305`, `health` at `:306-390` and `version` at `:391-414`.

| Action | Command |
|---|---|
| Validate | `ferrum-edge validate -m file -s <run>/<p>.conf -c <run>/<p>.yaml` exits 0 and prints `Validation passed.`, or exits 1. It parses settings, instantiates every plugin, checks that TLS files exist and are valid, and checks port conflicts (`docs/cli.md:115-181`). It does **not** bind ports or reach backends. |
| Start | `cd <run>/<p> && ulimit -n 4096 && env <secrets> ferrum-edge run -m file -s <run>/<p>.conf -c <run>/<p>.yaml > gw.stdout 2> gw.stderr` |
| Readiness | Poll `GET http://127.0.0.1:<admin>/health` until it returns `200 {"status":"ok","ready":true}`. It returns 503 `"starting"` before that (`src/admin/mod.rs:2761-2800,3255-3319`; `docs/admin_api.md:217-261`). Or run `ferrum-edge health -s <p>.conf`, which exits 0 or 1 (`docs/cli.md:306-390`). |
| Liveness | `GET /live` returns 200 `{"status":"ok"}` (`src/admin/mod.rs:2756-2758`). There is no `/ready`. On the proxy port `/health` is just an ordinary route miss. |
| Reload | `kill -HUP <pid>`, or `ferrum-edge reload --pid <pid>`. Publish the new YAML with temp-file-plus-`rename`, never an in-place edit (`docs/configuration.md:423-429`). A rejected reload keeps the last good config and makes `/health` report `degraded` (`docs/admin_api.md:322`). There is no file watcher. |
| Stop | SIGTERM or SIGINT. A second signal skips the rest of the pre-drain and drain wait (`docs/graceful_shutdown.md:28-36`). Each lab conf sets `FERRUM_SHUTDOWN_DRAIN_SECONDS=2`, except `drain.conf`. |
| Version | `ferrum-edge version --json` |

**Isolation.** Always pass `-s` and `-c` explicitly and run from a clean per-profile working directory:
- With no `-s`, the CLI auto-discovers `./ferrum.conf`, then `./config/ferrum.conf`, then `/etc/ferrum/ferrum.conf`. With no `-c`, it auto-discovers `./resources.yaml` and `/etc/ferrum/config.yaml` (`docs/cli.md:458-490`; `src/cli.rs:189-238`).
- `FERRUM_CONF_PATH=""` does not disable discovery (`src/config/conf_file.rs:240-245`).
- `ferrum.conf` rejects unknown keys (`docs/configuration.md:5-10`). All keys in `lab/gateway/*.conf` were checked against `src/config/public_env_inventory.rs`.

**Precedence:** CLI flag > environment > `-s` conf file > defaults (`docs/cli.md:448-457`). The lab keeps non-secret settings in `<profile>.conf` and passes secrets only through the environment.

**Environment hygiene.** Start the process with `env -i PATH=… HOME=…` plus the lab variables. Stray `FERRUM_*` variables in the parent shell win over the conf file, and the functional harness scrubs them for the same reason (`tests/common/gateway_harness.rs:1327-1357`).

### 1.3 Environment and settings used by the lab

| Setting | Lab value | Source |
|---|---|---|
| `FERRUM_MODE` | `file` (or `cp`/`dp` for the cpdp profile). The `-m` flag overrides it. | `docs/configuration.md:50` |
| `FERRUM_FILE_CONFIG_PATH` | Supplied by `-c` | `docs/configuration.md:419-423` |
| `FERRUM_CONF_PATH` | Supplied by `-s` | `docs/configuration.md:49` |
| `FERRUM_LOG_LEVEL` | `info` (default `warn`) | `docs/configuration.md:52` |
| `FERRUM_PROXY_BIND_ADDRESS` | `127.0.0.1`. Default is `0.0.0.0`. Covers HTTP, HTTPS and HTTP/3. | `docs/configuration.md:111`; `src/config/env_config.rs:4258` |
| `FERRUM_PROXY_HTTP_PORT` / `FERRUM_PROXY_HTTPS_PORT` | Per the port plan. `0` disables. | `docs/configuration.md:107-108` |
| `FERRUM_ADMIN_BIND_ADDRESS` | `127.0.0.1` (already the default) | `docs/configuration.md:158` |
| `FERRUM_ADMIN_HTTP_PORT` / `FERRUM_ADMIN_HTTPS_PORT` | Per the plan / `0` | `docs/configuration.md:156-157` |
| `FERRUM_STREAM_PROXY_BIND_ADDRESS` | `127.0.0.1`. Default `0.0.0.0`, and independent of the proxy bind. | `docs/configuration.md:1020` |
| `FERRUM_CP_GRPC_LISTEN_ADDR` | `127.0.0.1:18795`. The default `0.0.0.0:50051` plaintext bind is refused. | `docs/configuration.md:446`; `env_config.rs:8440-8458` |
| `FERRUM_FRONTEND_TLS_CERT_PATH` / `FERRUM_FRONTEND_TLS_KEY_PATH` | tls and streams profiles. HTTPS starts only if both are set. | `docs/configuration.md:112-115`; `src/modes/startup_security.rs:351-356` |
| `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` | tls profile only. Makes a client certificate **mandatory** on HTTPS, HTTP/3 and TCP+TLS. There is no optional mode. | `docs/configuration.md:948`; `src/tls/mod.rs:1341-1366,1405-1412` |
| `FERRUM_ENABLE_HTTP3` | `true` in the streams profile. QUIC listens on UDP at `<bind>:<HTTPS port>`. | `docs/configuration.md:990`; `src/modes/file.rs:562-571,1537-1590` |
| `FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH` / `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | ECDSA P-256/P-384 only. A client CA makes DTLS client certificates mandatory. | `docs/configuration.md:1027-1032`; `src/dtls/mod.rs:3284-3290` |
| `FERRUM_POOL_WARMUP_ENABLED` | `false`, so no startup HEAD requests to fault fixtures | `docs/configuration.md:1120`; `src/proxy/mod.rs:11406-11417` |
| `FERRUM_ACCEPT_THREADS` | `1` | `docs/configuration.md:1099` |
| `FERRUM_ADMIN_JWT_SECRET` (env) | Optional in file mode; a random read-only secret is generated if unset. If set it must be at least 32 chars, or startup fails. **Required** in cp and dp modes. | `docs/configuration.md:170`; `src/modes/file.rs:1052-1073` |
| `FERRUM_METRICS_BEARER_TOKEN` (env) | Recommended. Unlocks authenticated `/health`, `/overload` and `/metrics` for the "authorized evidence" mode without minting JWTs. | `docs/configuration.md:161` |
| `FERRUM_BASIC_AUTH_HMAC_SECRET` (env) | auth profile only. At least 32 bytes; required for `basic_auth`. | `docs/configuration.md:1043`; `src/plugins/basic_auth.rs:95-101` |
| `FERRUM_CP_DP_GRPC_JWT_SECRET` (env) | cpdp profile. At least 32 chars, must differ from the admin secret, and must be identical on CP and DP. | `docs/configuration.md:448`; `env_config.rs:7581-7598` |
| `FERRUM_DP_CP_GRPC_URLS`, `FERRUM_DP_CONFIG_MAX_STALE_SECONDS`, `FERRUM_DP_CONFIG_STALE_ACTION` | cpdp profile. Loopback `http://` is allowed. | `docs/configuration.md:477-480`; `env_config.rs:895-926` |

Loopback backends need no egress opt-in. The default `FERRUM_BACKEND_ALLOW_IPS=both` with the dangerous-range baseline still allows loopback and RFC 1918 (`docs/configuration.md:1258-1260`).

### 1.4 Traffic the gateway sends to fixtures on its own

Fixture ground-truth logs must label these; they are not test requests.

1. **Backend capability probe.** This runs even with warmup off. It fires immediately after readiness (`src/modes/file.rs:884-895,1648-1657`), then every `FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS` (default 86400).
   - `backend_scheme: http` targets get an **h2c prior-knowledge** connection (`PRI * HTTP/2.0` preface) (`src/proxy/mod.rs:10676-10686,10784-10816`).
   - `https` targets get a **TLS ClientHello with ALPN h2** plus a **QUIC Initial** on UDP of the same port (`src/proxy/mod.rs:10687-10720`).
   - HTTP/1-only fixtures and TLS fixtures that offer only `http/1.1` ALPN are classified "unsupported" and keep traffic on the reqwest HTTP/1 path. All lab TLS fixtures must offer only `http/1.1`.
   - There is no switch to disable the initial probe from the binary.
2. **DNS warmup** of backend hostnames at startup. In the lab the only hostname is the UP-001 NXDOMAIN name, sent to the DNS fixture (`src/modes/file.rs:880-883`).
3. **Active health checks.** Only `ups-degraded` in the core profile sends them: `GET /lab-health` every 1 s (`src/health_check.rs:3249`).
4. **JWKS fetches** from `jwks_auth` against the auth JWKS fixture.

Lab procedure: start fixtures, then the gateway; wait for `ready:true`; wait about 2 s for probes to settle; reset fixture counters; then run the scenarios.

### 1.5 Operator-side evidence

- Each profile enables a global `stdout_logging` plugin. It writes one JSON transaction line per request to **stdout**, including `error_class` (19 values), `body_error_class`, `proxy_id` and status (`docs/error_classification.md:274-297`; `src/plugins/stdout_logging.rs:179-251`).
- Runtime tracing (for example the `https_to_plaintext_backend` WARN, the "All upstream targets unhealthy" WARN and the transformer-ceiling WARN) goes through the process log sinks. Capture both stdout and stderr (`docs/configuration.md:53`).
- These lines are **authorized detail evidence**. They must never be fed to a public-evidence-only diagnosis test (build plan §15.1).

## 2. Config schema essentials (file mode)

### 2.1 Document

- **Top level (`GatewayConfig`).** It has `deny_unknown_fields`. `version`, `proxies` and `plugin_configs` are **required**, even when empty; `consumers` and `upstreams` are optional (`src/config/types.rs:3197-3207`). `version` may be `"1"` or `1` (`src/config/file_loader.rs:180-230`).
- **Integrity seal.** Optional `resource_counts: {proxies, consumers, plugin_configs, upstreams}` is checked against the counts in the file (`docs/configuration.md:431-440`). Every lab profile uses it.
- **Format** is chosen by file extension only: `.json` is JSON, anything else is YAML (`docs/configuration.md:427`). The size cap is 64 MiB.
- **No variable substitution.** `load_config_from_file` does serde deserialization with no environment or `${…}` expansion (`src/config/file_loader.rs:135-230`), and `ferrum.conf` values are literal (`docs/configuration.md:1318-1323`). The lab therefore uses **`{{TOKEN}}` placeholders that the lab runner must render** into absolute values before `validate`/`run`:
  - `{{LAB_CERTS}}`: absolute certificate directory.
  - `{{LAB_RUN}}`: per-run scratch directory, used for the CP sqlite file.
  - `{{BASIC_AUTH_ALICE_HASH}}`: `hmac_sha256:<hex>` (section 2.6).

  The only interpolations that exist are plugin-specific: `${ENV}` in `ai_stream_router` and `${secret:NAME}` in `ai_transcript_audit`, neither used here.
- **Namespace.** Resources default to namespace `ferrum`, and the loader keeps only resources in `FERRUM_NAMESPACE` (`src/config/file_loader.rs:380-383`).

### 2.2 Proxy (`deny_unknown_fields`, `src/config/types.rs:2609-3015`)

**Routing**
- `id`, `name`, `hosts: []`, `listen_path` (prefix; `=` for exact, `~` for regex), `strip_listen_path` (default `true`), `backend_path`, `preserve_host_header`.
- Prefix matching is segment-bounded (`docs/routing.md:29-66,305`).
- Unmatched requests get 404 (section 5, GW-006).
- The routed path is canonicalized. Encoded `/`, dot segments and `%XX` of non-pchar bytes are rejected with **400 before routing or authentication** (`docs/routing.md:22`).

**Backend**
- `backend_scheme` is one of `http | https | tcp | tcps | udp | dtls` (`types.rs:2360-2368`).
- It **defaults to `https` when omitted** on HTTP-family proxies (`types.rs:7580-7590`), so always set it.
- There is **no `backend_protocol` field, and no `ws`, `grpc`, `h3` or `tcp_tls` value**. WebSocket and gRPC are detected per request (`docs/routing.md:9-12`).
- `backend_host` and `backend_port` are required unless `upstream_id` is set (`types.rs:7960-7965`). `dns_override` (a static IP) and `dns_cache_ttl_seconds` are also available.

**Timeouts** (milliseconds; defaults at `types.rs:5613-5623`, ranges at `types.rs:7974-7998`)

| Field | Default | Meaning |
|---|---|---|
| `backend_connect_timeout_ms` | 5000 | DNS + TCP + backend TLS handshake (`docs/configuration.md:1472-1476`) |
| `backend_read_timeout_ms` | 30000 | Header wait, idle gap between body frames, and total time to collect a buffered upload (`docs/configuration.md:1385-1399`) |
| `backend_write_timeout_ms` | 30000 | Idle upload progress, including send-queue drain on macOS through `SO_NWRITE` (`docs/configuration.md:1401-1454`) |

- There is **no separate HTTP "idle" field**: the read timeout acts as the body idle bound.
- `tcp_idle_timeout_seconds` (default from `FERRUM_TCP_IDLE_TIMEOUT_SECONDS`, 300) and `udp_idle_timeout_seconds` (default 60, range 1–3600) apply to stream proxies (`types.rs:2882-2911,8042-8059`).

**Other fields**
- `allowed_methods: [..]`: an unmatched method gets 405 before plugins run (`src/proxy/mod.rs:31059-31081`).
- `response_body_mode: stream|buffer` (`types.rs:2545-2557`).
- `circuit_breaker`, `retry`, `plugins: [{plugin_config_id}]`, `auth_mode: single|multi`.
- The `pool_*` overrides include `pool_enable_http2`. The lab sets it to `false` on HTTP/1 fixtures.

**Backend TLS** (direct backends only, no `upstream_id`; `types.rs:2679-2695`)
- `backend_tls_verify_server_cert` (default `true`), `backend_tls_server_ca_cert_path`, `backend_tls_client_cert_path`, `backend_tls_client_key_path`.
- Cert and key must be set together (`types.rs:8242-8258`). All four fields are **rejected on http, tcp and udp** (`types.rs:8151-8174`).
- A configured CA is the only trust anchor (`docs/backend_mtls.md:57-65`). Global equivalents are `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH`/`_KEY_PATH`; per-proxy settings win (`src/tls/backend.rs:925-947`).
- The global client cert is **not** used by `tcps` or `dtls` stream backends (`src/proxy/tcp_proxy.rs:1669-1678`; `src/proxy/udp_proxy.rs:1698-1703`).
- **There is no per-proxy SNI override.** The verified name is `backend_host` (`types.rs:1736-1746`). `backend_tls_sni` and `backend_tls_san_allow_list` exist only on upstreams (`types.rs:1905-1912`). The lab therefore uses `backend_host: localhost` plus `dns_override: "127.0.0.1"`, following `tests/functional/functional_mtls_test.rs:568-577`.

**Stream proxies**
- `listen_port` plus `backend_scheme` in `tcp|tcps|udp|dtls` (scheme required, `types.rs:8177-8182`). `listen_path` is **forbidden** (`types.rs:7890-7897`).
- `frontend_tls: true` terminates TLS on TCP or DTLS on UDP. It uses the `FERRUM_FRONTEND_TLS_*` or `FERRUM_DTLS_*` material; there are no per-proxy certificate fields (`types.rs:2870-2874`; `src/modes/file.rs:1017-1042`).
- A stream port must not equal any non-zero HTTP, HTTPS or admin port, even an unbound one (`src/modes/file.rs:521-560`; `types.rs:5584-5606`).
- TCP half-close is propagated in both directions (`src/proxy/tcp_proxy.rs:8454-8465,8491-8494`), capped by `FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS` (default 300).

### 2.3 Upstreams (`deny_unknown_fields` on `Upstream`; `types.rs:1826-1970`)

**Fields**
- `id`, `algorithm`: `round_robin | weighted_round_robin | least_connections | least_latency | consistent_hashing | random | passthrough` (`types.rs:462-471`).
- `targets: [{host, port, weight (default 1), tags, locality, path}]` (`types.rs:1204-1218`).
- `health_checks: {active, passive}`:
  - `active` (`types.rs:1448-1521`): `http_path` (default `/health`, probed with GET), `interval_seconds` (10), `timeout_ms` (5000), `healthy_threshold` (3), `unhealthy_threshold` (3), `healthy_status_codes` ([200, 302]), `use_tls`, `probe_type` (`http|tcp|udp|grpc`), `udp_probe_payload`, `grpc_service_name`.
  - `passive` (`types.rs:1527-1612`): `unhealthy_status_codes` ([500, 502, 503, 504]), `unhealthy_threshold`, `unhealthy_window_seconds`, `healthy_after_seconds`, `max_ejection_percent`, and more.
- Upstream TLS: `backend_tls_*`, `backend_tls_sni`, `backend_tls_san_allow_list`.

**Not settable in file mode**
- **`port_overrides` is rejected in file mode**: "populated by mesh DestinationRule…" (`types.rs:9548-9555`, fatal at `src/config/file_loader.rs:318-325`). That is the only carrier of `max_connections`, so there is no per-destination physical-connection cap in file mode (UP-018).
- Target tags in the `mesh.*` namespace are also rejected (`types.rs:9507-9512`).

**Silent-typo risk.** `UpstreamTarget`, `HealthCheckConfig`, `ActiveHealthCheck` and `PassiveHealthCheck` are **not** `deny_unknown_fields`, so typos there are silently ignored. `lint-profiles.rb` exists for this.

### 2.4 Circuit breaker and retries (both on the proxy; both lenient to unknown keys)

**Circuit breaker** (`types.rs:2225-2276`)
- Fields: `circuit_breaker: {failure_threshold 5, success_threshold 3, timeout_seconds 30 (alias cooldown_seconds), failure_status_codes [500,502,503,504], half_open_max_requests 1, trip_on_connection_errors true}`.
- It counts **consecutive** failures and is keyed per proxy and backend `host:port` (`src/circuit_breaker.rs:305-311,369-390`; `src/proxy/backend_dispatch.rs:865-879`).
- There is no breaker on upstreams. It is off unless the block is present.

**Retry** (`types.rs:2294-2341`)
- Fields: `retry: {max_retries 3, retryable_status_codes [], retryable_methods [GET,HEAD,OPTIONS,PUT,DELETE], backoff, retry_on_connect_failure true}`.
- **Retries are off unless a `retry` block is present** (`docs/retry.md:26`). The lab omits it everywhere so every request makes exactly one attempt.
- `backoff` is an externally tagged enum. In YAML it is written `backoff: !fixed {delay_ms: 100}` or `!exponential {base_ms: …, max_ms: …}` (`tests/scaffolding/mod.rs:152-160`); in JSON, `{"fixed":{"delay_ms":100}}`.
- A retry block also forces uploads to be buffered.

### 2.5 Size limits

| Knob | Scope | Over-limit result |
|---|---|---|
| `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` (10 MiB) | env, process-wide | 413 `{"error":"Request body exceeds maximum size"}`, no `X-Gateway-Error` (`docs/configuration.md:831`; `src/proxy/mod.rs:44659-44680`) |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` (10 MiB) | env | 502 `{"error":"Backend response body exceeds maximum size"}`, or a truncated stream (`docs/configuration.md:832`) |
| `request_size_limiting {max_bytes}` | per proxy (plugin) | 413 `{"error":"Request body too large","limit":N}` (`src/plugins/request_size_limiting.rs:130`; `src/plugins/utils/size_limit.rs:112-126`) |
| `response_size_limiting {max_bytes, require_buffered_check}` | per proxy (plugin) | 502 (see UP-014) |

- Route plugins publish their ceiling to the core, and the strictest active bound wins (`docs/configuration.md:882-903`).
- Buffering budgets: `FERRUM_RESPONSE_BUFFER_MAX_TOTAL_BYTES`, `FERRUM_RESPONSE_BUFFER_FALLBACK_MAX_BYTES` and `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` (64 KiB eager-buffer cutoff) (`docs/configuration.md:833-838`).

### 2.6 Consumers and credentials (`deny_unknown_fields`, `types.rs:3025-3048`)

- Consumer fields: `id`, `username` (required), `custom_id`, `acl_groups: [..]`, `credentials: {<type>: [ {..} ]}`.
- **Every credential value must be an array of objects** (`types.rs:8563-8596`), with at most `FERRUM_MAX_CREDENTIALS_PER_TYPE` (2) entries.

| Type key | Entry | Rules |
|---|---|---|
| `keyauth` | `{key}` | Non-empty; unique across consumers (`types.rs:8665-8674`) |
| `basicauth` | `{password_hash: "hmac_sha256:<64 lowercase hex>"}` | **Plaintext `password` is rejected in file mode** (`file_loader.rs:288-306`). The hash is `hex(HMAC-SHA256(key=FERRUM_BASIC_AUTH_HMAC_SECRET, msg=password))` (`types.rs:9009-9031`). Compute it with `printf %s "$PW" \| openssl dgst -sha256 -hmac "$SECRET"`. |
| `jwt` | `{secret}` | Exactly one field, at least 32 chars; HS256 only (`types.rs:8643-8664`; `src/plugins/jwt_auth.rs:82`) |
| `hmac_auth` | `{secret}` | Exactly one field, at least 32 non-whitespace chars (`types.rs:8617-8637`) |
| `mtls_auth` | `{identity}` | (unused here) |

### 2.7 plugin_configs (`deny_unknown_fields`, `types.rs:3053-3100`)

**Entry shape**
- `{id, plugin_name (required), scope (required: global | proxy | proxy_group), proxy_id, enabled (default true), config, priority_override, trigger}`.
- `config` defaults to `null`, which most plugins reject, so always write `config: {}` at minimum.

**Attachment rule (silent failure if broken)**
- A `scope: proxy` plugin runs only if its `proxy_id` matches **and** that proxy lists it under `plugins: [{plugin_config_id}]` (`src/plugin_cache.rs:2689-2705,4475-4486`). The v0.9.5 test comment says the same: "File-mode proxies only run the plugin configs they attach" (`tests/functional/functional_chunked_response_size_limits_test.rs:71-72`).
- Validation does not flag an unattached proxy-scoped plugin; it simply never runs. `lint-profiles.rb` flags it.
- A proxy may not reference a `global` plugin (`types.rs:5080-5160`).

**Key checking.** Plugins used in the lab reject unknown config keys through their `*_CONFIG_KEYS` constants. `validate` instantiates every plugin (`docs/cli.md:165`).

### 2.8 Public error contract (applies to every HTTP-family recipe)

**`X-Gateway-Error`**
- Always on, with no gate (`src/proxy/mod.rs:39444-39465`). The token depends only on `connection_error` and the final status (`src/retry.rs:281-291`):
  - `connection_error` (a pre-wire class) → `connection_failure`
  - status 504 → `backend_timeout`, **even when the backend itself returned 504**
  - any other status ≥ 500 → `backend_error`, **including a genuine application 500**
  - status < 500 → no header
- Values sent by backends or plugins are stripped first (`mod.rs:39449`).
- Gateway-authored reject tokens: `circuit_breaker_open`, `overload`, `config_stale`, `concurrency_limit` (`docs/error_classification.md:313-323`).
- Plugin rejections (401, 403, 400, 429, OPA 503) carry **no** token.

**Bodies**
- `ReadWriteTimeout` → 504 `{"error":"Backend timeout"}`.
- Other dispatch failures → 502 `{"error":"Backend unavailable"}`, except DNS: 502 `{"error":"Backend DNS resolution failed"}` (`src/proxy/mod.rs:42788-42815,43055-43076`).

**`X-Gateway-Upstream-Status: degraded`**
- Written only on all-unhealthy fallback (`mod.rs:39463-39465`).
- **Not stripped on HTTP/1 or HTTP/2 when a backend or plugin sends it** on a non-fallback response. Only the H3 path overwrites it, and only on fallback (`src/http3/server.rs:10318-10328`). A forged copy is therefore possible; see GW-019.

**Other headers**
- `Via` is added by default (`FERRUM_ADD_VIA_HEADER`, `docs/configuration.md:1051`).
- There is no core `X-Request-Id`; one would require the `correlation_id` plugin.

## 3. Port and resource plan

Rule: **profile N uses gateway ports 18N00–18N99 and fixture ports 19N00–19N99.** Fixture `19N00` is reserved for that profile's fixture control and ground-truth API. Everything binds `127.0.0.1`. Ports marked "(unbound)" must stay closed: they are fault stimuli.

| # | Profile (files) | Gateway listeners | Fixture ports |
|---|---|---|---|
| 0 | core (`core.conf`, `core.yaml`) | HTTP 18080; admin 18090 | 19000 control; 19001 echo; 19002 (unbound: refused); 19003 backlog-full never-accept; 19009 upload stall; 19010 header stall; 19011 body stall; 19012 RST mid-body; 19013 short Content-Length; 19014 oversize; 19020 close / garbage; 19021 500-toggle; 19022 app 403; 19023 app 500/504; 19024 degraded target; 19053 DNS NXDOMAIN (UDP+TCP) |
| 1 | auth (`auth.*`) | HTTP 18180; admin 18190 | 19100 control; 19101 echo (reflects request headers); 19102 JWKS (`/.well-known/jwks.json`) |
| 2 | policy (`policy.*`) | HTTP 18280; admin 18290 | 19200 control; 19201 echo; 19202 OPA mock; 19203 OPA stall; 19204 AI provider mock; 19205 slow (3 s); 19206 JSON `{}`; 19207 (unbound); 19208 forged-header echo; 19209 (unbound: OPA refused) |
| 3 | tls (`tls.*`) | HTTP 18380; **HTTPS 18343 (mTLS required)**; admin 18390; DTLS 18301/udp; TCP+TLS 18302 | 19300 control; 19301 TLS trusted; 19302 TLS untrusted; 19303 TLS wrong name; 19304 TLS 1.3 requires client cert; 19305 TLS 1.2 requires client cert; 19306 TLS stall; 19307 plain HTTP; 19308 TLS server (plaintext client); 19309 echo; 19310 UDP echo; 19311 TCP echo |
| 4 | streams (`streams.*`) | HTTP 18480 (h1 + h2c); HTTPS 18443/tcp + HTTP/3 18443/udp; admin 18490; streams 18401–18406 | 19400 control; 19401 WebSocket echo; 19402 gRPC (h2c); 19403 echo; 19404 TCP half-close echo; 19405 UDP echo; 19406 UDP silent; 19407 UDP lossy; 19409 (unbound: gRPC down) |
| 5 | admission (`admission.*`) | HTTP 18580; admin 18590 | 19500 control; 19501 sized responder; 19502 staller |
| 6 | drain (`drain.*`) | HTTP 18680; admin 18690 | 19600 control; 19601 echo; 19602 6 s staller |
| 7 | cpdp (`cpdp-*.conf`, `cpdp-seed-proxy.json`) | CP: admin 18790, gRPC 18795. DP: HTTP 18780, admin 18791. Orphan DP: HTTP 18770, admin 18771 (its CP URL 18799 is unbound) | 19700 control; 19701 echo |

All profiles can run at the same time. Profiles 5 and 6 each change process-wide behavior, so they are separate instances. Profile 6 is destroyed by its own test.

**Lab PKI** (generated per run, never committed, never added to any system trust store)
- ECDSA P-256 keys in unencrypted PKCS#8. DTLS requires ECDSA (`docs/configuration.md:1027`).
- `frontend-ca.pem` → `gateway-server.{pem,key}` with SAN `localhost` and `127.0.0.1`. Used for frontend TLS and DTLS.
- `client-ca.pem` → `client-good.{pem,key}`.
- `rogue-ca.pem` → `client-rogue.{pem,key}`.
- `backend-ca.pem` → `backend-good.{pem,key}` (SAN `localhost`, `127.0.0.1`) and `backend-wrongname.{pem,key}` (SAN `wrong-name.anvil-lab.invalid` only).
- Self-signed `backend-untrusted.{pem,key}`.
- `backend-client-ca.pem` → `gateway-backend-client.{pem,key}`. The mTLS fixtures require certificates from this CA.

## 4. Profiles produced

| Profile | Scenarios |
|---|---|
| `core` | UP-001..003, UP-009..014, UP-020, GW-001, GW-006..008, GW-016..018 |
| `auth` | AUTH-001, 003, 007, 018..022, 024, 025, GW-011 |
| `policy` | GW-004, 009, 010, 012..015, 019, 020 |
| `tls` | TLS-005/006/008, UP-004..008, UP-016, PROTO-022 (wrong client identity) |
| `streams` | PROTO-006, 012, 013, 014, 019..022 |
| `admission` | UP-015, GW-002 |
| `drain` | GW-003 |
| `cpdp` | GW-005 |

**Validation once the binary is downloaded.** For each profile:
1. Render the `{{…}}` tokens into `<run>/`.
2. Run `ruby lab/gateway/lint-profiles.rb <run>/*.yaml`.
3. Run `env -i … <secrets> ferrum-edge validate -m file -s <run>/<p>.conf -c <run>/<p>.yaml` and expect `Validation passed.`

The certificate files must already exist, because `validate` loads and expiry-checks the frontend and DTLS material. For cpdp, use `validate -m cp` / `-m dp` with the `-s` file only.

## 5. Scenario recipes

Row format: route (profile) → fixture behavior → expected client-visible result → operator `error_class` (access log) → evidence level.

Evidence levels:
- **T**: asserted by a v0.9.5 functional or integration test (cited).
- **S**: traced in source.
- **I**: inferred; **verify live**.

"Recovery" is the positive request to run after removing the fault.

### 5.1 Gateway-to-upstream (UP)

**UP-001 · DNS NXDOMAIN**
- Route: `GET :18080/up/dns` (core).
- Fixture: the DNS fixture on 19053 answers NXDOMAIN (`core.conf` `FERRUM_DNS_RESOLVER_ADDRESS`; nameserver parse `src/dns/mod.rs:3117-3143`).
- Client sees: **502** `{"error":"Backend DNS resolution failed"}`, `X-Gateway-Error: connection_failure`.
- Log: `dns_lookup_error`.
- Evidence: S (`src/proxy/mod.rs:43055-43076,43497-43524`). The functional test only asserts a 5xx (`tests/functional/functional_dns_cache_test.rs:132-203`).
- Notes: errors are cached for `FERRUM_DNS_ERROR_TTL` (set to 1 s), doubling on repeats. For recovery, point the fixture at `127.0.0.1` for that name and wait for the TTL.

**UP-002 · connect refused**
- Route: `/up/refused` (core). Nothing is bound on 19002.
- Client sees: **502** `{"error":"Backend unavailable"}`, `connection_failure`.
- Log: `connection_refused`.
- Evidence: T (`tests/functional/scripted_backend_tests.rs:97-136`; `src/retry.rs:1505-1550`).

**UP-003 · connect deadline**
- Route: `/up/connect-stall`, with `backend_connect_timeout_ms: 1000` (core).
- Fixture: listens on 19003 with a tiny backlog, pre-fills it and never calls `accept`. On macOS/BSD, SYNs beyond the queue are dropped (**I**: kernel behavior, not in the snapshot). Do not use 192.0.2.1: offline it fails fast as "unreachable" and is classified as refused (`tests/integration/connection_pool_tests.rs:776-834`).
- Client sees: **502** `Backend unavailable`, `connection_failure`.
- Log: `connection_timeout`.
- Evidence: S (`src/retry.rs:1514-1516`; `mod.rs:44533-44538`).
- Notes: keep the connect timeout below the read timeout, because the header deadline starts before the dial (`mod.rs:45246`).

**UP-004 · untrusted backend certificate**
- Route: `/up/tls-untrusted` via `:18380` (tls).
- Fixture: 19302 presents a self-signed certificate; the proxy trusts only `backend-ca`.
- Client sees: **502** `Backend unavailable`, `connection_failure`.
- Log: `tls_error`.
- Evidence: T (expired-certificate variant, `scripted_backend_tests.rs:420-496`; untrusted CA returns 502 at `functional_mtls_test.rs:619-682`).
- Recovery: `/up/tls-trusted` (19301) returns 200.

**UP-005 · backend certificate name mismatch**
- Route: `/up/tls-wrong-name` (tls).
- Fixture: 19303 presents a `backend-ca` certificate for `wrong-name.anvil-lab.invalid`; the verified name is `localhost`.
- Client sees: **502**, `connection_failure`.
- Log: `tls_error`.
- Evidence: S. The typed name cause appears only in the operator log.

**UP-006 · backend mTLS, gateway presents no identity**
- Routes and fixtures (tls):
  - `/up/mtls-missing`: 19304 (TLS 1.3, `http/1.1` only).
  - `/up/mtls-missing-tls12`: 19305 (TLS 1.2).
- TLS 1.3 result is deliberately ambiguous: **502** with either `connection_failure` (`connection_pool_error`) or `backend_error` (`connection_reset`).
- TLS 1.2 result: expected **502** `connection_failure` / `tls_error` (**I**: the rejection happens inside the handshake).
- Evidence: T for TLS 1.3 (`tests/integration/backend_mtls_tests.rs:541-673` accepts either; logic at `docs/error_classification.md:44-61`).
- Recovery: `/up/mtls-ok` presents `gateway-backend-client.pem` and gets 200 (T: `functional_mtls_test.rs:687-752`).

**UP-007 · backend TLS handshake stall**
- Route: `/up/tls-stall`, with a 1000 ms connect timeout (tls).
- Fixture: 19306 accepts TCP and never answers the ClientHello.
- Client sees: **502**, `connection_failure`.
- Log: `connection_timeout`. The connect budget covers the TLS handshake.
- Evidence: S (`docs/configuration.md:1472-1476`; `docs/upstream-reqwest-patches/001-per-request-connect-timeout/`).

**UP-008 · scheme mismatch**
- (a) `/up/scheme-https-to-plain` → plain HTTP fixture on 19307.
  - Client sees: **502**, `connection_failure`.
  - Log: `tls_error`, plus a WARN containing `error_reason=https_to_plaintext_backend`.
  - Evidence: T (`scripted_backend_tests.rs:1710-1759`; `docs/error_classification.md:59`).
- (b) `/up/scheme-http-to-tls` → TLS fixture on 19308.
  - Client sees: **502**, `backend_error`.
  - Log: `request_error` or `connection_closed`.
  - Evidence: I (`src/retry.rs:1557-1583`).

**UP-009 · backend stops reading an upload**
- Route: `POST /up/upload-stall` with an 8 MiB body; `backend_write_timeout_ms: 1000` (core).
- Fixture: 19009 reads the request head, never reads the body, and uses a small `SO_RCVBUF`.
- Client sees: **504** `{"error":"Backend timeout"}`, `backend_timeout`.
- Log: `read_write_timeout`.
- Evidence: T (`scripted_backend_tests.rs:1936-1994`; macOS `SO_NWRITE` at `src/socket_opts.rs:780-782`).
- Notes: the body must exceed the peer's receive buffer and stay under `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` (10 MiB).

**UP-010 · first-header stall**
- Route: `/up/header-stall`, read timeout 1000 ms (core).
- Fixture: 19010 reads the request and withholds response headers.
- Client sees: **504** `Backend timeout`, `backend_timeout`.
- Log: `read_write_timeout`.
- Evidence: T (`scripted_backend_tests.rs:221-284`).

**UP-011 · body idle stall**
- Route: `/up/body-stall/{small,large,chunked}` (core).
- Fixture: 19011 sends headers plus a first chunk, then stalls. `/small` uses Content-Length ≤ 64 KiB; `/large` uses Content-Length > 64 KiB.
- `/small` is eager-buffered: **504** `backend_timeout`.
- `/large` and `/chunked` stream: **200**, partial body, then abort after about 1 s idle. Log has `body_error_class=read_write_timeout`.
- Evidence: T for the streamed case (`scripted_backend_tests.rs:2075-2159`); S for the buffered case (`mod.rs:42757-42773,45441-45535`).

**UP-012 · RST mid-body**
- Route: `/up/reset/{small,large}` (core).
- Fixture: 19012 sends headers and a partial body, then RSTs (`SO_LINGER` 0).
- Small: **502** `{"error":"Backend response body read failed"}`, `backend_error`, log `connection_reset`.
- Large: **200**, then truncated.
- If the reset lands before headers: 502 `Backend unavailable`.
- Evidence: S (`mod.rs:42740-42756,42839-42861`). Timing-sensitive.

**UP-013 · short Content-Length then FIN**
- Route: `/up/short-body/{small,large}` (core).
- Fixture: 19013 declares a larger Content-Length than it sends, then FINs.
- Small: **502** `Backend response body read failed`, log `connection_closed`.
- Large: **200**, truncated body; log `body_error_class=connection_closed`.
- Evidence: T (`scripted_backend_tests.rs:352-408`).

**UP-014 · oversized response**
- Routes: `/up/oversize/{cl,chunked}` (route ceiling 65 536 bytes) and `/up/oversize-buffered/chunked` (core).
- Fixture: 19014 sends 1 MiB with Content-Length (`cl`) or chunked (`chunked`).
- `cl`: **502**, `backend_error`, log `response_body_too_large`. The body is either the plugin's `{"error":"Response body too large","limit":65536}` or the core's `Backend response body exceeds maximum size`; do not assert the exact body.
- Streamed `chunked`: **200**, then the body errors. Over H2: a stream reset.
- Buffered `chunked`: **502** `Backend response body exceeds maximum size`.
- Evidence: T (`tests/functional/functional_chunked_response_size_limits_test.rs:140-197,391-461`; `functional_response_body_limits_test.rs:26-60,220-234`). Never retried (`src/retry.rs:1856-1870`).

**UP-015 · gateway retained-buffer exhaustion**
- Route: `/up/buffer-capacity/big` (admission; buffered; budgets 64 KiB).
- Fixture: 19501 sends 256 KiB with Content-Length.
- Client sees: **503** `{"error":"Response buffering capacity exceeded"}`, **`X-Gateway-Error: backend_error`**. This is the documented trap: the public token blames the backend.
- Log: `gateway_buffer_capacity`.
- Evidence: S (`src/proxy/response_buffer_budget.rs:469-491,803-830`; `docs/error_classification.md:24,345`). No functional test.
- Recovery: `/up/buffer-capacity/small` (32 KiB) returns 200.

**UP-016 · pool cancellation (pre-dispatch)**
- Covered only through the UP-006 TLS 1.3 route, when hyper reports `is_canceled`: 502, `connection_failure`, log `connection_pool_error`.
- The outcome is nondeterministic; record which class occurred. The other natural path (HTTP client construction failure → 502 `{"error":"Bad Gateway"}`) needs TLS material to break after startup; that is unverified (`mod.rs:44463-44481`).
- **Partially feasible.**

**UP-017 · ephemeral-port exhaustion**
- **Not feasible live.**
- The class is only assigned for EADDRNOTAVAIL during connect (`src/retry.rs:500-513,1505-1513`). The release build has no lab hook; features are crypto, secrets, acme, pkcs11 and fuzzing only (`Cargo.toml:356-436`; `src/lib.rs:82-88`). Reaching it would mean exhausting the host's ephemeral port range.
- Keep this as an Anvil-side typed unit/hook test, labeled hook-based (build plan §15.4).

**UP-018 · backend connection ceiling**
- **Not feasible in v0.9.5 file mode.**
- The only cap is `Upstream.port_overrides[port].max_connections` (`types.rs:664-697`), which file mode rejects (`types.rs:9548-9555`; `file_loader.rs:318-325`). DestinationRules are applied only in mesh mode (`src/modes/mesh/mod.rs:1490-1494,1602`), and there is no env equivalent.
- For reference: on the H1 path, a hit would be 503 `{"error":"Backend connection limit exceeded"}`, class `dispatch_policy_rejected` (`mod.rs:45754-45782`).
- Would need the mesh-mode lab.

**UP-019 · trust withdrawn**
- **Not feasible in file mode.**
- It is emitted only by the gateway-to-mesh HBONE and mesh-mTLS pools (`src/proxy/mesh_trust_registry.rs:1-20`; `docs/error_classification.md:32`). Those need `mesh.*` target tags, which file mode rejects (`types.rs:9507-9512`).

**UP-020 · generic post-dispatch failure**
- Route: `/up/post-dispatch/garbage` (core).
- Fixture: 19020 reads the request and writes a malformed status line.
- Client sees: **502** `Backend unavailable`, `backend_error`.
- Log: `request_error`.
- Evidence: S (`src/retry.rs:1583`).
- Companion: `/up/post-dispatch/close` (reads the request, then FINs) gives 502 and log `connection_closed`.

### 5.2 Gateway admission, policy, ownership (GW)

**GW-001 · open circuit breaker**
- Route: `/gw/breaker` (core; threshold 3, open 5 s).
- Fixture: 19021 returns 500 while its toggle is on.
- Three requests each return the backend 500 with `backend_error`. The fourth returns **503** `{"error":"Service temporarily unavailable (circuit breaker open)"}`, `X-Gateway-Error: circuit_breaker_open`, and the fixture sees no hit. There is no `Retry-After`.
- Evidence: T (`tests/functional/functional_circuit_breaker_retry_test.rs:147-232`; `src/proxy/mod.rs:33104-33122`).
- Recovery: turn the toggle off, wait 5 s, and the half-open probe returns 200.

**GW-002 · overload refusal**
- Route: `/gw/occupant` (admission; `FERRUM_MAX_REQUESTS=1`; monitor ticks every 100 ms).
- Hold `/gw/occupant` in flight (fixture 19502 holds the response), wait at least 300 ms, then send `/gw/probe`.
- Client sees: **503** `{"error":"Service overloaded"}`, `X-Gateway-Error: overload`. This happens before routing. Admin `/overload` shows `{"level":"critical"}`.
- Evidence: S (`src/proxy/mod.rs:29960-29985`; `src/overload.rs:1236-1265`; `docs/overload_manager.md:96-158`).
- Only `FERRUM_MAX_REQUESTS` produces an HTTP 503. The connection, FD and event-loop tiers RST the connection instead (`mod.rs:21456-21486`).
- Run `ulimit -n 4096` first.

**GW-003 · drain refusal**
- Routes: `/gw/fast` and `/gw/slow` (drain; pre-drain 3 s, drain 10 s).
- After SIGTERM:
  - (a) `/health` returns **503** `{"status":"draining","ready":false}` while `/gw/fast` still returns 200 (pre-drain).
  - (b) After 3 s, a new TCP connect is **refused**.
  - (c) A `/gw/slow` request started before the listener closed completes with `Connection: close`.
- A 503 `overload` / `Service overloaded` for new streams on existing connections is possible but **racy**. Idle HTTP/1 connections are closed and HTTP/2 connections get GOAWAY (`mod.rs:14118-14126`). Do not make it a required assertion.
- Evidence: S (`docs/graceful_shutdown.md:9-26`; `src/admin/mod.rs:2941,3286-3297`; `src/overload.rs:1565-1588`; `mod.rs:39498-39510`).

**GW-004 · adaptive concurrency limit**
- Route: `/gw/concurrency` (policy; `min_limit`, `initial_limit` and `max_limit` all 1).
- Fixture: 19205 holds each response about 3 s. Send two concurrent requests.
- The second gets **503** `{"error":"Upstream concurrency limit reached"}`, `X-Gateway-Error: concurrency_limit`, `x-adaptive-concurrency-limit: 1`, `x-adaptive-concurrency-inflight: 1`.
- Evidence: S (`src/plugins/adaptive_concurrency.rs:24-29,96-134,141-231`). The same limits at global scope appear in `tests/functional/functional_websocket_test.rs:692-712`.

**GW-005 · stale DP fence**
- **Feasible, but needs a CP+DP pair (not file mode).**
- File-mode data planes are impossible: a DP gets config only from a CP, and the fence is installed only in dp mode (`src/modes/data_plane.rs:44`). A CP always needs a database; SQLite works (`env_config.rs:6897-6905`; `docs/cp_dp_mode.md:1121-1125`).
- Real CP recipe:
  1. Start the CP with `cpdp-cp.conf`.
  2. `POST http://127.0.0.1:18790/proxies` with `cpdp-seed-proxy.json`. This needs an HS256 admin JWT: `iss=ferrum-edge`, `role: admin`, plus `sub`, `iat`, `nbf`, `exp` and `jti` (`docs/configuration.md:170-173`; `tests/common/gateway_harness.rs:1416-1435`).
  3. Start the DP with `cpdp-dp.conf`. `/cpdp/echo` on 18780 returns 200.
  4. Kill the CP and wait more than 5 s.
- Expected: **503** `{"error":"Gateway configuration stale"}`, `X-Gateway-Error: config_stale`. DP `/health` returns 503 `unavailable`. Recovery comes after the CP restarts and a snapshot is applied.
- Orphan variant (`cpdp-dp-orphan.conf`): about 2 s after start, the same 503 appears, because authority starts `Lost` (`src/dp_config_freshness.rs:347-365,657-680`).
- Default action is `fail_closed`; no opt-in is needed (`docs/configuration.md:479-480`).
- Evidence: S (`src/proxy/mod.rs:29874-29903`).

**GW-006 · no matched route**
- `GET :18080/gw/no-such-route` returns **404** `{"error":"Not Found"}` with no `X-Gateway-Error`.
- Evidence: S (`src/proxy/mod.rs:30966-30975`).
- Lookalike: an application 404 through `/ok/missing`.

**GW-007 · method not allowed**
- `DELETE /gw/methods` (core) returns **405** `{"error":"Method Not Allowed"}` with `Allow: GET, POST`, before any plugin runs.
- Evidence: S (`src/proxy/mod.rs:31059-31081,24862-24884`).
- Do not use TRACE or CONNECT. Those are rejected before routing with a fixed `Allow` list (`mod.rs:30369-30396`).

**GW-008 · request size ceiling**
- `POST /gw/request-size` with Content-Length 2048 against a 1024-byte limit (core).
- Client sees: **413** `{"error":"Request body too large","limit":1024}` from the plugin fast path. A chunked upload gets core enforcement: 413 `{"error":"Request body exceeds maximum size"}`. There is no `X-Gateway-Error`.
- Evidence: S (`src/plugins/request_size_limiting.rs:120-192`; `docs/size_limits.md:45-49,224-233`). The 413 itself is T (`functional_chunked_response_size_limits_test.rs:143`).

**GW-009 · response-transformer output ceiling**
- Route: `/gw/transform-ceiling` (policy).
- Fixture: 19206 returns `{}`. The transformer adds a 115-char field, making 129 bytes against a 128-byte limit.
- Client sees: **502** `{"error":"Response body too large","limit":128}`, `X-Gateway-Error: overload`.
- Log: `dispatch_policy_rejected`, plus a WARN "output exceeds response size policy".
- Control: `/gw/transform-boundary` (114 chars) returns 200 with a 128-byte body.
- Evidence: T (`tests/functional/functional_chunked_response_size_limits_test.rs:22-205`).

**GW-010 · WAF block**
- Route: `/gw/waf` (policy).
- Send the header `x-lab-waf-test: 1`, or a POST JSON body containing `ANVIL-LAB-WAF-MARKER`.
- Client sees: **403** `{"error":"Forbidden"}` (`application/json`) with no `X-Gateway-Error`.
- Evidence: S (`src/plugins/waf/mod.rs:62-92,319-467,686-698`; rule keys `waf/rules.rs:11-24`; targets `rules.rs:1103-1157`). The config shape follows the unit test at `waf/mod.rs:2322-2335`; there is no functional test.
- Lookalike: GW-016 returns an identical body.

**GW-011 · ACL denial**
- `/gw/acl` (auth) with alice's key (`X-Lab-Api-Key`, group `engineering`) returns **403** `{"error":"Consumer is not allowed"}`. Bob's key (`lab-admins`) returns 200.
- Evidence: S (`src/plugins/access_control.rs:152-270`).

**GW-012 · OPA explicit denial**
- `/gw/opa-deny` (policy): the mock returns `{"result": false}`, giving **403** `{"error":"forbidden by policy"}`.
- `/gw/opa-allow` (mock returns `{"result": true}`) gives 200.
- The OPA call is `POST {opa_host}/v1/data/{policy_path}`.
- Evidence: S (`src/plugins/opa.rs:35-38,476-495,695-771`). Config shape: `tests/functional/functional_opa_key_auth_redaction_test.rs:94-138`.

**GW-013 · OPA unavailable (fail-closed)**
- `/gw/opa-timeout`: 19203 never answers within the 500 ms `timeout_ms`.
- `/gw/opa-refused`: nothing listens on 19209.
- Both give **503** `{"error":"authorization service unavailable"}`. No `X-Gateway-Error` is expected (plugin reject; **verify live**).
- Fail-closed is the default (`opa.rs:773-784`).
- Evidence: S (`opa.rs:37-38,505-535,625-652`).

**GW-014 · IP restriction**
- `/gw/ip-deny` (policy; `deny: [127.0.0.1]`) returns **403** `{"error":"IP address denied"}`.
- Evidence: S (`src/plugins/ip_restriction.rs:23,157-275`).
- `geo_restriction` needs an `.mmdb` database (`db_path`) and fails open on lookup failure. It is not configured here.

**GW-015 · OpenAPI validation**
- `POST /gw/openapi/items` (policy).
- Malformed JSON gives **400** `application/problem+json`, title `Request body validation failed`, detail `Invalid JSON body: …`.
- A schema violation (for example `{"name":"x","qty":0}`) gives 400 with detail `request body does not satisfy the request schema at … (keyword 'minimum')`.
- A valid body gives 200.
- Any other path under `/gw/openapi` gives 400 `Unknown OpenAPI operation`.
- Evidence: S (`src/plugins/openapi_validator.rs:992-1061,2578-2580,5769-5787`). Config shape: `tests/functional/functional_openapi_client_contract_test.rs:517-615`.

**GW-016 · application 403 lookalike**
- `/gw/app-403` (core).
- Fixture: 19022 returns 403 with `application/json` body `{"error":"Forbidden"}`, byte-identical to the WAF reject.
- The client sees the same thing as GW-010, and neither carries a token. Anvil must not claim WAF.
- Evidence: S (`src/retry.rs:281-291`).

**GW-017 · application 5xx**
- `/gw/app-500/500` (core): the fixture's 500 is passed through **with `X-Gateway-Error: backend_error` added by the gateway**.
- `/gw/app-500/504`: the application's own 504 is passed through **with `X-Gateway-Error: backend_timeout`**. This is a lookalike of UP-010.
- Log: no `error_class`, or the metric token `backend_error`.
- Evidence: S (`src/proxy/mod.rs:39446-39461`; `src/retry.rs:281-291`).

**GW-018 · degraded but successful routing**
- `/gw/degraded` (core; `upstream_id: ups-degraded`; active probe on `/lab-health` every 1 s, `unhealthy_threshold: 1`).
- Fixture: 19024 returns 503 on `/lab-health` and 200 elsewhere.
- About 2 s after readiness, every request returns **200** with `X-Gateway-Upstream-Status: degraded`, plus the WARN "All upstream targets unhealthy, using fallback target".
- Control: `/gw/degraded-direct` returns 200 with no header.
- Evidence: S (`src/load_balancer.rs:5299-5311`; `src/proxy/backend_dispatch.rs:278-286,490-497`; `src/health_check.rs:3099-3150`). The header has no functional-test coverage.
- Docs and code disagree about whether a proxied success clears an active mark; the code says it does not (`docs/load_balancing.md:656` vs `health_check.rs:2320-2336`).

**GW-019 · header mutation after error / forged metadata**
- (a) `/gw/header-mutation-error` (policy): the backend is refused (19207), and a response hook adds `X-Gateway-Error: lab-spoofed-token` and `X-Gateway-Upstream-Status: degraded`.
  - Expected: `X-Gateway-Error: connection_failure`. The authoritative value is restored (`mod.rs:24802-24830`; unit test `tests/unit/gateway_core/error_response_headers_tests.rs:67-101`).
  - The spoofed `degraded` survives, because it is not gateway-owned when there is no fallback (**I**, verify live; also verify that response hooks run on this path).
- (b) `/gw/header-mutation-ok`: 200. The hook's `X-Gateway-Error` is **stripped** (`mod.rs:39449`); its `X-Gateway-Upstream-Status: degraded` **reaches the client** (S/I).
- (c) `/gw/backend-forged-headers`: the fixture on 19208 itself sends both headers on a 200. Same result as (b).
- Anvil must treat a `degraded` marker without corroboration as untrusted.

**GW-020 · AI policy / provider failure** (partially feasible)
- (a) `/gw/ai/guard`: POST `{"model":"gpt-3.5-turbo","max_tokens":50,"messages":[…]}` returns **400** containing "not in the allowed models list". Evidence: T (`tests/functional/functional_ai_plugins_test.rs:1232-1318`).
- (b) `/gw/ai/budget`: the mock reports `usage.total_tokens` 25 or more per call. Once the 50-token window is exhausted: **429** `{"error":"AI token rate limit exceeded",…}` plus `x-ai-ratelimit-*` headers. Evidence: S (`src/plugins/ai_rate_limiter.rs:458-527,805-827`); reservation/charging timing needs **live validation**.
- (c) `/gw/ai/provider`: the mock returns an OpenAI-style 429 or 500. The 429 passes through without a token; **the 500 gains `X-Gateway-Error: backend_error`**.
- Only local mocks are used; this verifies adapter behavior, not provider availability.

### 5.3 Frontend TLS (tls profile, `https://localhost:18343/tls/echo`, trusting `frontend-ca.pem`)

The client CA makes certificates mandatory, with no per-proxy switch (`src/tls/mod.rs:1341-1366`). The request is refused before routing, with no backend dial (`docs/frontend_tls.md:83-85`).

**TLS-005 · no client certificate**
- Under TLS 1.3 the client may complete its side of the handshake and then see alert `certificate_required` (116) on first read. Under TLS 1.2 the handshake fails.
- Anvil must not report an HTTP status.
- Evidence: T (`tests/functional/functional_mtls_test.rs:416-478`; both handshake shapes accepted at `:1192-1203`; `tests/integration/frontend_tls_live_reload_tests.rs:981-984`).

**TLS-006 · certificate from a rogue CA**
- Handshake rejected. The alert is expected to be `unknown_ca` (48): this is rustls behavior (**I**); the test asserts only that the request fails.
- Evidence: T (`functional_mtls_test.rs:483-547`).

**TLS-008 · valid mTLS**
- 200 from the echo backend.
- Evidence: T (`functional_mtls_test.rs:347-411`).

Note: the same route on plaintext `:18380` bypasses mTLS. Use it only as a clearly labeled control.

### 5.4 Authentication (auth profile, `:18180`)

When no credential is found, the auth plugin passes (`Continue`). The chain then ends with **401** `{"error":"Authentication required"}` and `WWW-Authenticate` taken from the first plugin that defines a challenge, else the literal `ferrum-edge` (`src/proxy/mod.rs:28957-29008,29775-29790`).

**AUTH-001 · API key header name**
- The right key under `X-API-Key` (wrong name) gives **401** `Authentication required` with `WWW-Authenticate: ferrum-edge`.
- The same key under `X-Lab-Api-Key` gives 200, and the backend sees no key (`hide_credentials`).
- An unknown key gives 401 `{"error":"Invalid API key"}`.
- Evidence: S (`src/plugins/key_auth.rs:55-135,186-212`). Body text is asserted in `tests/functional/functional_auth_acl_test.rs:1402-1428`.

**AUTH-003 · Basic credentials**
- A wrong password gives **401** `{"error":"Invalid credentials"}` with `WWW-Authenticate: Basic realm="ferrum-edge", charset="UTF-8"`.
- `alice:anvil-lab-alice-password` gives 200.
- Evidence: S (`src/plugins/basic_auth.rs:164-226`).

**AUTH-007 · JWT consumer claim**
- Route: `/auth/jwt`; the identity claim is `anvil_consumer`.
- An HS256 token signed with alice's secret but carrying only `sub: alice` gives **401** `{"error":"JWT missing identity claim"}`.
- `anvil_consumer: nobody` gives 401 `{"error":"Invalid JWT token"}`.
- `anvil_consumer: alice` with an `exp` gives 200.
- Evidence: S (`src/plugins/jwt_auth.rs:56-125,218-270`; lookup `src/consumer_index.rs:465-488`).

**AUTH-018 · HMAC v2 happy path**
- Header: `Authorization: hmac username="alice", algorithm="hmac-sha256", nonce="<≥32 hex or ≥22 base64url>", signature="<std base64>"`.
- The signature is HMAC-SHA256 with alice's secret bytes over this signing string:

  ```text
  ferrum-hmac-v2\n{NAMESPACE=ferrum}\n{USERNAME}\n{AUTHORITY}\n{METHOD}\n{PATH}\n{QUERY}\n{DATE}\n{DIGEST_HEADER_VALUE}\n{NONCE}
  ```

  - `PATH` is the **raw client path before strip**.
  - `QUERY` is the raw query without `?`.
  - `DATE` is the literal `Date` header value (not `X-Date`), within ±300 s.
  - `AUTHORITY` is the Host, lowercased, with the default port dropped.
- Exactly one digest header is required, **even for an empty body**: `Content-Digest: sha-256=:<b64>:` or `Digest: sha-256=<b64>`.
- Expected: 200.
- Evidence: S (`src/plugins/hmac_auth.rs:20,1902-1943,381-418,1267-1298`; `src/proxy/mod.rs:46861-46883`). Reference signer: `tests/common/hmac_helpers.rs:125-162`. End-to-end test: `tests/functional/functional_auth_acl_test.rs:3045-3171`.

**AUTH-019 · HMAC body mutation**
- Changing the body after signing gives **401** `{"error":"Digest header does not match request body"}`.
- Evidence: S (`hmac_auth.rs:221-225`).

**AUTH-020 · HMAC replay**
- Re-sending an identical signed request gives **401** `{"error":"Signed request has already been used"}`. A fresh nonce and re-sign gives 200.
- The replay store is in-process (`replay_scope: process`); markers are kept 601 s (`hmac_auth.rs:138,214`).
- At capacity it returns 503 `Signed-request replay protection is at capacity`.
- Evidence: T (`functional_auth_acl_test.rs:3045-3171`).

**AUTH-021 · raw path and query**
- The gateway signs and verifies the exact raw wire path and query, so duplicate or order-sensitive parameters are compared byte-for-byte.
- **Constraint:** `%2F`, dot segments, backslashes and `%XX` of non-pchar bytes (for example `%20`) are rejected with **400 before authentication** (`docs/routing.md:22`). Vectors must stay within the canonical path grammar; the query string is not subject to that rule.
- Evidence: S.

**AUTH-022 · both digest headers**
- Sending both `Digest` and `Content-Digest` gives **401** `{"error":"Ambiguous Digest and Content-Digest headers"}`.
- Evidence: S (`hmac_auth.rs:222,381-418`).

**AUTH-024 · DPoP binding**
- Route: `/auth/dpop`, sent with `Authorization: DPoP <access token>` and a `DPoP: <proof>` header.
- Access token:
  - ES256 or RS256, `kid` in the JWKS served by 19102.
  - `iss=https://idp.anvil-lab.invalid`, `aud=anvil-lab-api`, `exp`.
  - `cnf.jkt` equal to the proof key's thumbprint.
- Proof:
  - `typ: dpop+jwt`, ES256 or RS256, with a `jwk` in the header.
  - `htm`: the method.
  - `htu`: `http://127.0.0.1:18180/auth/dpop`, built from the Host header and path with query dropped.
  - `iat` within 30 s; `jti` present; `ath` present.
- Expected: 200.
- Failures:
  - 401 `DPoP proof required`
  - 401 `Invalid DPoP proof`
  - 401 `DPoP URL mismatch`
  - 401 `DPoP validation failed` (every crypto or claim failure collapses to this)
  - 401 `Invalid or unrecognized JWT`
- Evidence: S (`src/plugins/jwks_auth.rs:256-308,1196-1236,2192-2250`; `src/plugins/dpop.rs:93-194`). `http://127.0.0.1` JWKS is allowed for loopback only (`jwks_auth.rs:2218-2250`).

**AUTH-025 · DPoP replay or nonce challenge** (partially feasible)
- Replaying the proof gives **401** `{"error":"DPoP replay"}` (`jwks_auth.rs:1264-1291`).
- **The server-nonce challenge is not implemented in v0.9.5**: no `DPoP-Nonce` and no `use_dpop_nonce` anywhere in src or docs.
- The nonce half of the scenario is not live-testable against this gateway. Use an Anvil-side mock authorization server for challenge-retry logic.

AUTH-023 (legacy v1) was not requested. The `hmac_auth` v1 profile exists and requires `allow_unsafe_replayable_v1: true` (`hmac_auth.rs:957-995`).

### 5.5 Protocols (streams profile)

**PROTO-006 · HTTP/3**
- Forced H3 to `https://localhost:18443/proto/h3` (UDP, ALPN `h3`, TLS 1.3 forced) returns 200.
- H1 and H2 responses carry `Alt-Svc: h3=":18443"; ma=86400`.
- Evidence: T (`tests/functional/functional_websocket_test.rs:3517-3538`; `src/http3/server.rs:600-699`; `src/proxy/mod.rs:9365-9371`).
- Alt-Svc is advertised whenever `FERRUM_ENABLE_HTTP3=true`, even if QUIC failed to start. It is not proof of an H3 listener.

**PROTO-012 · WebSocket over HTTP/2 extended CONNECT**
- RFC 8441 is **supported and always on**: `SETTINGS_ENABLE_CONNECT_PROTOCOL` is advertised on both h2c (18480) and h2 over TLS (18443).
- `:protocol=websocket` to `/proto/ws` gives 200 and echo. Any other `:protocol` gets 405.
- Evidence: T (`functional_websocket_test.rs:2194-2264`; `src/proxy/mod.rs:14022-14024,22087-22089,2406-2413`).

**PROTO-013 · WebSocket over HTTP/3 extended CONNECT**
- RFC 9220 is **supported**, gated by `FERRUM_HTTP3_WEBSOCKET_ENABLED` (default `true`). When the gate is off, the response is 501.
- The backend leg is HTTP/1.1 Upgrade.
- Evidence: T (`functional_websocket_test.rs:2959,3066,3204`; `docs/http3.md:863-874,1022-1029`).

**PROTO-014 · gRPC HTTP 200 with an error status**
- `/anvil.lab.v1.Probe/Fail` over h2c (18480) or h2 (18443) returns **HTTP 200** with trailers `grpc-status: 5` and `grpc-message`, forwarded unmodified. The trailers-only form is preserved too.
- `/anvil.lab.v1.Down/*` (closed port) returns HTTP 200 with `grpc-status: 14`.
- Evidence: T (`tests/functional/functional_grpc_test.rs:940-980,1084-1112`; `tests/functional/scripted_backend_h2_tests.rs:864-915,1781-1830`).

**PROTO-019 · TCP half-close**
- The client connects to 18401, writes, then `shutdown(Write)`. The fixture on 19404 replies after EOF and then closes.
- The client receives the reply followed by EOF. FIN is propagated in both directions.
- Evidence: T (`tests/functional/functional_tcp_proxy_test.rs:998-1064`; `src/proxy/tcp_proxy.rs:8454-8465`).

**PROTO-020 · UDP silent peer**
- Datagram to 18402 → fixture 19406, which never replies.
- The client observes nothing. The gateway session expires after 30 s (`udp_idle_timeout_seconds`). There is no gateway error signal on UDP.
- Evidence: S (`types.rs:2882-2885`).

**PROTO-021 · UDP loss and reorder**
- The fixture on 19407 drops, reorders or duplicates by sequence number on its echo leg. The gateway relays datagrams as they arrive.
- The fault comes from the fixture, not the gateway; ground truth is the fixture log.
- Note the default response-amplification cap of 8.0 on UDP; keep echoes at or below request size (`types.rs:7548-7551`).
- Evidence: S.

**PROTO-022 · DTLS handshake / mTLS**
- Happy path: DTLS to 18405, trusting `frontend-ca`, then echo.
- Wrong root: the client trusts `rogue-ca`, so the client itself aborts the handshake.
- Wrong identity (tls profile, 18301, DTLS client CA set): a missing or rogue client certificate is refused. Ferrum closes the session; the alert type is chosen by the DTLS library.
- Evidence: S (`src/dtls/mod.rs:3284-3290,3583-3600,4259-4286`). A test config with a DTLS client CA is at `tests/functional/functional_mtls_acl_test.rs:678-735`, and plain DTLS at `tests/functional/functional_udp_proxy_test.rs:1309-1314,1483-1489`.
- If certificate material is missing, the DTLS listener is **deferred** (health degraded) rather than failing startup (`src/proxy/stream_listener.rs:3110-3159`). Check `/health`.

### 5.6 Feasibility summary

**Live-feasible:** UP-001..015, UP-020; GW-001..004, GW-006..018; TLS-005/006/008; AUTH-001, 003, 007, 018..022, 024; PROTO-006, 012, 013, 014, 019..022.

**Feasible outside file mode:** GW-005, which needs a CP (SQLite) plus DP, or the orphan-DP variant.

**Partial:**
- GW-003: the in-connection 503 is racy.
- GW-019: the hook-on-error path needs live confirmation.
- GW-020: budget charging needs live confirmation.
- UP-016: only through the nondeterministic UP-006 path.
- UP-006: the TLS 1.3 variant's class is intentionally ambiguous.
- AUTH-025: replay only; the server nonce is not implemented.

**Not feasible with v0.9.5 file mode:**
- UP-017: needs a lab-only hook; none exists in the release build.
- UP-018: `port_overrides` is rejected in file mode; mesh only.
- UP-019: mesh trust pools only.

## 6. Caveats and doc-versus-code discrepancies found

**Silent misconfiguration traps**
- Circuit breaker, retry, health-check and target keys are not `deny_unknown_fields`; run `lint-profiles.rb`.
- A proxy-scoped plugin that is not listed in its proxy's `plugins` never runs, and validation stays silent.

**Wrong field names to avoid**
- `backend_protocol` does not exist.
- The TLS-to-TCP scheme is `tcps`, not `tcp_tls`: code comments still say `tcp_tls` (`types.rs:2605`), but only the six canonical strings parse.
- The `jwks_auth` provider `audience` field is legacy; use `audiences` (`jwks_auth.rs:2477-2489`).

**Docs that are wrong or stale for v0.9.5**
- `docs/tcp_udp_proxy.md:436` names `FERRUM_TLS_CERT_PATH`, which does not exist.
- `docs/routing.md:14` says WebSocket on H3 returns 501; that is only true when the gate is off.
- `docs/configuration.md:1091` says `FERRUM_MAX_CONNECTIONS` "queues when full"; the code RSTs.
- `docs/load_balancing.md:131,656,665` contradict the code: subset fallback returns no target, and proxied success does not clear active marks.

**macOS**
- Raise `ulimit -n`.
- `curl` downloads are not quarantined; a browser download would need `xattr -d com.apple.quarantine`.
- The UP-003 backlog trick relies on BSD SYN-drop behavior.

**Log hygiene**
- Access logs redact `authorization`, `cookie`, `password`, `secret` and `token` metadata keys (`docs/configuration.md:59`).
- Fixture logs are Anvil-owned and must apply the same redaction before any safe-share export.
