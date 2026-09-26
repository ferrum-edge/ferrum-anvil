// API auth editor (identity presented to the API — not the app login).
import { useEffect, useState } from "react";
import { api, onOAuthFlow, type FlowEvent, type JwtInspection, type SendInput, type TokenSummary } from "./api";
import type { AuthConfig, DpopConfig, HmacConfig, JwtAlgorithm, OAuth2Config, SensitiveValue, WsseConfig } from "./generated/contracts";
import { Modal, SecretField } from "./ui";
import { JwtSvidFields, defaultJwtSvid } from "./WorkloadApi";

const TYPES: { id: AuthConfig["type"]; label: string }[] = [
  { id: "inherit", label: "Inherit from folder/workspace" },
  { id: "none", label: "No auth" },
  { id: "api_key", label: "API key" },
  { id: "basic", label: "Basic" },
  { id: "bearer", label: "Bearer token" },
  { id: "jwt", label: "JWT (sign locally)" },
  { id: "jwt_svid", label: "JWT-SVID (SPIFFE)" },
  { id: "oauth2", label: "OAuth 2.0" },
  { id: "hmac", label: "HMAC signature (Ferrum)" },
  { id: "dpop", label: "DPoP (RFC 9449)" },
  { id: "wsse", label: "WS-Security UsernameToken" },
  { id: "multi", label: "Multiple (all applied)" },
];

const EMPTY: SensitiveValue = { kind: "template", value: "" };

function defaults(t: AuthConfig["type"]): AuthConfig {
  switch (t) {
    case "inherit":
    case "none":
      return { type: t };
    case "api_key":
      return { type: "api_key", name: "X-API-Key", value: EMPTY, location: "header" };
    case "basic":
      return { type: "basic", username: "", password: EMPTY };
    case "bearer":
      return { type: "bearer", token: EMPTY, prefix: "Bearer" };
    case "jwt":
      return { type: "jwt", algorithm: "HS256", signing_key: EMPTY, claims: { expires_in_secs: 300, extra_json: "{}" }, prefix: "Bearer" };
    case "jwt_svid":
      return { type: "jwt_svid", config: defaultJwtSvid() };
    case "oauth2":
      return { type: "oauth2", config: { grant: "client_credentials", token_url: "", client_id: "", client_secret: EMPTY, scope: "", client_auth: "basic_header", refresh_skew_secs: 30 } };
    case "hmac":
      return { type: "hmac", config: { profile: "ferrum_v2", username: "", secret: EMPTY, algorithm: "hmac_sha256", digest_header: "content_digest" } };
    case "dpop":
      return { type: "dpop", config: { access_token: EMPTY, private_key_pem: EMPTY, dpop_scheme: true, handle_nonce_challenge: true } };
    case "wsse":
      return { type: "wsse", config: { username: "", password: EMPTY, password_type: "password_digest", timestamp_ttl_secs: 300 } };
    case "multi":
      return { type: "multi", profiles: [] };
  }
}

export function AuthEditor(props: {
  value: AuthConfig;
  onChange: (a: AuthConfig) => void;
  workspaceId: string | null;
  allowInherit?: boolean;
  nested?: boolean;
  /** The request this auth belongs to (enables interactive OAuth sign-in). */
  signInInput?: SendInput | null;
}) {
  const a = props.value;
  const types = TYPES.filter((t) => (props.allowInherit === false ? t.id !== "inherit" : true) && (!props.nested || (t.id !== "multi" && t.id !== "inherit")));
  return (
    <div className="col" style={{ gap: 12, maxWidth: 760 }}>
      <label className="lbl">
        Type
        <select className="field" value={a.type} onChange={(e) => props.onChange(defaults(e.target.value as AuthConfig["type"]))}>
          {types.map((t) => (
            <option key={t.id} value={t.id}>
              {t.label}
            </option>
          ))}
        </select>
      </label>
      <Fields {...props} />
    </div>
  );
}

function Fields({
  value: a,
  onChange,
  workspaceId,
  signInInput,
}: {
  value: AuthConfig;
  onChange: (a: AuthConfig) => void;
  workspaceId: string | null;
  signInInput?: SendInput | null;
}) {
  switch (a.type) {
    case "inherit":
      return <p className="hint">Uses the nearest folder's auth, then the workspace's. The Effective tab shows which one applies.</p>;
    case "none":
      return <p className="hint">No credentials are added. Inherited auth is not applied.</p>;
    case "api_key":
      return (
        <>
          <div className="row">
            <label className="lbl grow">
              Name
              <input className="field mono" value={a.name} onChange={(e) => onChange({ ...a, name: e.target.value })} />
            </label>
            <label className="lbl">
              Sent in
              <select className="field" value={a.location ?? "header"} onChange={(e) => onChange({ ...a, location: e.target.value as "header" })}>
                <option value="header">Header</option>
                <option value="query">Query parameter</option>
                <option value="cookie">Cookie</option>
              </select>
            </label>
          </div>
          <SecretField label="Key" value={a.value} onChange={(value) => onChange({ ...a, value })} workspaceId={workspaceId} />
          {a.location === "query" && <div className="warn-box">Keys in the query string often end up in proxy and server access logs. Anvil redacts it in history, but intermediaries may not.</div>}
        </>
      );
    case "basic":
      return (
        <>
          <label className="lbl">
            Username
            <input className="field mono" value={a.username} onChange={(e) => onChange({ ...a, username: e.target.value })} />
          </label>
          <SecretField label="Password" value={a.password} onChange={(password) => onChange({ ...a, password })} workspaceId={workspaceId} />
        </>
      );
    case "bearer":
      return (
        <>
          <SecretField label="Token" value={a.token} onChange={(token) => onChange({ ...a, token })} workspaceId={workspaceId} />
          <label className="lbl" style={{ maxWidth: 200 }}>
            Prefix
            <input className="field mono" value={a.prefix ?? "Bearer"} onChange={(e) => onChange({ ...a, prefix: e.target.value })} />
          </label>
          <JwtInspectButton />
        </>
      );
    case "jwt":
      return <JwtFields a={a} onChange={onChange} workspaceId={workspaceId} />;
    case "jwt_svid":
      return <JwtSvidFields c={a.config} onChange={(config) => onChange({ ...a, config })} workspaceId={workspaceId} />;
    case "oauth2":
      return (
        <>
          <OAuthFields c={a.config} onChange={(config) => onChange({ ...a, config })} workspaceId={workspaceId} />
          {a.config.grant !== "client_credentials" && <OAuthSignIn input={signInInput ?? null} />}
        </>
      );
    case "hmac":
      return <HmacFields c={a.config} onChange={(config) => onChange({ ...a, config })} workspaceId={workspaceId} />;
    case "dpop":
      return <DpopFields c={a.config} onChange={(config) => onChange({ ...a, config })} workspaceId={workspaceId} />;
    case "wsse":
      return <WsseFields c={a.config} onChange={(config) => onChange({ ...a, config })} workspaceId={workspaceId} />;
    case "multi":
      return (
        <div className="col">
          <p className="hint">Each profile is applied in order to the same final request (for example an API key plus a JWT). Body-dependent signatures run last over the final bytes.</p>
          {a.profiles.map((p, i) => (
            <fieldset key={i} style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10 }}>
              <legend className="faint">Profile {i + 1}</legend>
              <AuthEditor
                value={p}
                nested
                workspaceId={workspaceId}
                signInInput={signInInput}
                onChange={(np) => onChange({ ...a, profiles: a.profiles.map((x, j) => (j === i ? np : x)) })}
              />
              <button className="btn small danger" style={{ marginTop: 8 }} onClick={() => onChange({ ...a, profiles: a.profiles.filter((_, j) => j !== i) })}>
                Remove
              </button>
            </fieldset>
          ))}
          <button className="btn small" style={{ alignSelf: "start" }} onClick={() => onChange({ ...a, profiles: [...a.profiles, defaults("api_key")] })}>
            + Add profile
          </button>
        </div>
      );
  }
}

function JwtFields({ a, onChange, workspaceId }: { a: Extract<AuthConfig, { type: "jwt" }>; onChange: (a: AuthConfig) => void; workspaceId: string | null }) {
  const c = a.claims;
  const setC = (patch: Partial<typeof c>) => onChange({ ...a, claims: { ...c, ...patch } });
  const hmac = a.algorithm.startsWith("HS");
  return (
    <>
      <div className="row">
        <label className="lbl">
          Algorithm
          <select className="field" value={a.algorithm} onChange={(e) => onChange({ ...a, algorithm: e.target.value as JwtAlgorithm })}>
            {(["HS256", "HS384", "HS512", "RS256", "ES256"] as const).map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </label>
        <label className="lbl grow">
          Key id (kid)
          <input className="field mono" value={a.kid ?? ""} onChange={(e) => onChange({ ...a, kid: e.target.value || null })} />
        </label>
      </div>
      <SecretField label={hmac ? "Shared secret" : "Private key (PEM)"} multiline={!hmac} value={a.signing_key} onChange={(signing_key) => onChange({ ...a, signing_key })} workspaceId={workspaceId} />
      {!hmac && <PemFromFile label="Load private key file into the vault" workspaceId={workspaceId} onSecret={(signing_key) => onChange({ ...a, signing_key })} />}
      <div className="row" style={{ flexWrap: "wrap" }}>
        <Text label="iss" value={c.iss} onChange={(iss) => setC({ iss })} />
        <Text label="sub" value={c.sub} onChange={(sub) => setC({ sub })} />
        <Text label="aud" value={c.aud} onChange={(aud) => setC({ aud })} />
      </div>
      <div className="row">
        <Num label="Lifetime (s)" value={c.expires_in_secs} onChange={(expires_in_secs) => setC({ expires_in_secs })} />
        <Num label="nbf offset (s)" value={c.not_before_offset_secs} onChange={(not_before_offset_secs) => setC({ not_before_offset_secs })} />
      </div>
      <label className="lbl">
        Extra claims (JSON object, may use {"{{variables}}"})
        <textarea className="field" rows={4} value={c.extra_json ?? "{}"} onChange={(e) => setC({ extra_json: e.target.value })} />
      </label>
      <div className="row">
        <Text label="Header" value={a.header_name ?? "Authorization"} onChange={(h) => onChange({ ...a, header_name: h ?? "Authorization" })} />
        <Text label="Prefix" value={a.prefix ?? "Bearer"} onChange={(p) => onChange({ ...a, prefix: p ?? "" })} />
      </div>
      <p className="hint">A fresh token (iat/exp/jti) is signed for every send, so retries and load iterations never reuse an expired token. Anvil does not invent issuers or call a gateway token endpoint.</p>
    </>
  );
}

function OAuthFields({ c, onChange, workspaceId }: { c: OAuth2Config; onChange: (c: OAuth2Config) => void; workspaceId: string | null }) {
  return (
    <>
      <label className="lbl">
        Grant
        <select className="field" value={c.grant} onChange={(e) => onChange({ ...c, grant: e.target.value as OAuth2Config["grant"] })}>
          <option value="client_credentials">Client credentials</option>
          <option value="refresh_token">Refresh token (uses a cached refresh token)</option>
          <option value="authorization_code_pkce">Authorization code + PKCE (system browser)</option>
        </select>
      </label>
      <Text label="Token URL" value={c.token_url} onChange={(token_url) => onChange({ ...c, token_url: token_url ?? "" })} />
      {c.grant === "authorization_code_pkce" && <Text label="Authorization URL" value={c.authorization_url} onChange={(authorization_url) => onChange({ ...c, authorization_url: authorization_url ?? "" })} />}
      <Text label="Client id" value={c.client_id} onChange={(client_id) => onChange({ ...c, client_id: client_id ?? "" })} />
      <SecretField label="Client secret (optional for public clients)" value={c.client_secret} onChange={(client_secret) => onChange({ ...c, client_secret: client_secret as OAuth2Config["client_secret"] })} workspaceId={workspaceId} />
      <div className="row">
        <Text label="Scope" value={c.scope} onChange={(scope) => onChange({ ...c, scope: scope ?? "" })} />
        <Text label="Audience" value={c.audience} onChange={(audience) => onChange({ ...c, audience: audience ?? "" })} />
      </div>
      <div className="row">
        <label className="lbl">
          Client authentication
          <select className="field" value={c.client_auth ?? "basic_header"} onChange={(e) => onChange({ ...c, client_auth: e.target.value as "basic_header" })}>
            <option value="basic_header">HTTP Basic header</option>
            <option value="request_body">Form body</option>
          </select>
        </label>
        <Num label="Refresh before expiry (s)" value={c.refresh_skew_secs} onChange={(v) => onChange({ ...c, refresh_skew_secs: v ?? 30 })} />
      </div>
      <p className="hint">
        Tokens are acquired through the same transport, proxy and TLS settings as the request, once for concurrent sends. They live in memory only and are cleared on lock.
        {c.grant === "authorization_code_pkce" && " Authorization code sign-in opens your system browser and listens only on a 127.0.0.1 loopback redirect bound to this attempt's state."}
      </p>
    </>
  );
}

/** Interactive sign-in for authorization-code (PKCE) profiles: system
 * browser + loopback redirect. The token never reaches the webview. */
function OAuthSignIn({ input }: { input: SendInput | null }) {
  const [status, setStatus] = useState<TokenSummary | null>(null);
  const [events, setEvents] = useState<FlowEvent[]>([]);
  const [attempt, setAttempt] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const refresh = () => {
    if (input) void api.oauthTokenStatus(input).then(setStatus).catch(() => setStatus(null));
  };
  useEffect(refresh, [JSON.stringify(input)]);
  useEffect(() => {
    const un = onOAuthFlow((e) => {
      if (e.attempt === attempt) setEvents((x) => [...x, e.event]);
    });
    return () => void un.then((f) => f());
  }, [attempt]);
  if (!input) return <p className="hint">Save the request to sign in from here.</p>;
  const last = events[events.length - 1];
  const manual = events.find((e) => e.type === "browser_open_failed") as Extract<FlowEvent, { type: "browser_open_failed" }> | undefined;
  return (
    <fieldset className="box">
      <legend>Sign-in</legend>
      <div className="row">
        {status ? (
          <span className="badge ok">
            signed in · {status.token_type}
            {status.expires_at ? ` · expires ${new Date(status.expires_at).toLocaleTimeString()}` : ""}
            {status.refresh_token_available ? " · refreshable" : ""}
          </span>
        ) : (
          <span className="badge">not signed in</span>
        )}
        <span className="spacer" />
        {attempt ? (
          <button className="btn small" onClick={() => void api.oauthCancel(attempt)}>
            Cancel sign-in
          </button>
        ) : (
          <button
            className="btn small primary"
            onClick={async () => {
              const id = crypto.randomUUID();
              setErr(null);
              setEvents([]);
              setAttempt(id);
              try {
                await api.oauthSignIn(input, id);
                refresh();
              } catch (e) {
                setErr(String((e as Error).message));
              } finally {
                setAttempt(null);
              }
            }}
          >
            Sign in with browser…
          </button>
        )}
        {status && !attempt && (
          <button
            className="btn small"
            onClick={async () => {
              await api.oauthSignOut(input);
              refresh();
            }}
          >
            Sign out
          </button>
        )}
      </div>
      {attempt && last && <div className="hint">{describeFlow(last)}</div>}
      {manual && (
        <div className="warn-box">
          The browser could not be opened automatically. Open this URL yourself: <span className="mono">{manual.authorization_url}</span>
        </div>
      )}
      {err && <div className="bad-box">{err}</div>}
      <p className="hint">Tokens stay in memory in the backend and are cleared on lock; sending uses the cached token and its refresh token.</p>
    </fieldset>
  );
}

function describeFlow(e: FlowEvent): string {
  switch (e.type) {
    case "listener_ready":
      return "Waiting for the browser…";
    case "browser_opened":
      return "Complete the sign-in in your browser.";
    case "callback_ignored":
      return `Ignored an unrelated callback (${e.reason}).`;
    case "callback_accepted":
      return "Callback received.";
    case "exchanging_code":
      return "Exchanging the authorization code…";
    case "verifying_identity":
      return "Verifying…";
    case "completed":
      return "Signed in.";
    case "failed":
      return `Sign-in failed: ${e.message}`;
    default:
      return "";
  }
}

function HmacFields({ c, onChange, workspaceId }: { c: HmacConfig; onChange: (c: HmacConfig) => void; workspaceId: string | null }) {
  const legacy = c.profile === "ferrum_v1_legacy";
  return (
    <>
      <div className="row">
        <label className="lbl">
          Profile
          <select className="field" value={c.profile ?? "ferrum_v2"} onChange={(e) => onChange({ ...c, profile: e.target.value as HmacConfig["profile"] })}>
            <option value="ferrum_v2">Ferrum v2 (nonce, single-use)</option>
            <option value="ferrum_v1_legacy">Ferrum v1 legacy (replayable)</option>
          </select>
        </label>
        <label className="lbl">
          Algorithm
          <select className="field" value={c.algorithm ?? "hmac_sha256"} onChange={(e) => onChange({ ...c, algorithm: e.target.value as HmacConfig["algorithm"] })}>
            <option value="hmac_sha256">HMAC-SHA256</option>
            <option value="hmac_sha384">HMAC-SHA384</option>
            <option value="hmac_sha512">HMAC-SHA512</option>
          </select>
        </label>
        <label className="lbl">
          Body digest header
          <select className="field" value={c.digest_header ?? "content_digest"} onChange={(e) => onChange({ ...c, digest_header: e.target.value as HmacConfig["digest_header"] })}>
            <option value="content_digest">Content-Digest</option>
            <option value="legacy_digest">Digest (legacy)</option>
          </select>
        </label>
      </div>
      <Text label="Username" value={c.username} onChange={(username) => onChange({ ...c, username: username ?? "" })} />
      <SecretField label="Secret" value={c.secret} onChange={(secret) => onChange({ ...c, secret })} workspaceId={workspaceId} />
      <Text label="Namespace (if the gateway profile binds one)" value={c.namespace} onChange={(namespace) => onChange({ ...c, namespace: namespace ?? "" })} />
      {legacy && (
        <label className="check warn-box">
          <input type="checkbox" checked={!!c.allow_unsafe_legacy} onChange={(e) => onChange({ ...c, allow_unsafe_legacy: e.target.checked })} />I understand v1 signatures can be replayed and only need them for an older gateway.
        </label>
      )}
      <p className="hint">The signature is computed per send over the final method, path, query, date, body digest and a fresh nonce — retries and load iterations never reuse a nonce.</p>
    </>
  );
}

function DpopFields({ c, onChange, workspaceId }: { c: DpopConfig; onChange: (c: DpopConfig) => void; workspaceId: string | null }) {
  const [jkt, setJkt] = useState<string | null>(null);
  return (
    <>
      <SecretField label="Access token" value={c.access_token} onChange={(access_token) => onChange({ ...c, access_token: access_token as DpopConfig["access_token"] })} workspaceId={workspaceId} />
      <SecretField label="Proof key (EC P-256 private key, PEM)" multiline value={c.private_key_pem} onChange={(private_key_pem) => onChange({ ...c, private_key_pem: private_key_pem as DpopConfig["private_key_pem"] })} workspaceId={workspaceId} />
      <div className="row">
        <button
          className="btn small"
          disabled={!workspaceId}
          onClick={async () => {
            if (!workspaceId) return;
            const g = await api.generateDpopKey(workspaceId, "DPoP proof key");
            setJkt(g.jkt);
            onChange({ ...c, private_key_pem: { kind: "secret", secret: g.secret } });
          }}
        >
          Generate a new key in the vault
        </button>
        {jkt && (
          <span className="faint mono" title="JWK SHA-256 thumbprint (cnf.jkt)">
            jkt: {jkt}
          </span>
        )}
      </div>
      <label className="check">
        <input type="checkbox" checked={c.dpop_scheme !== false} onChange={(e) => onChange({ ...c, dpop_scheme: e.target.checked })} />
        Present the token as <code>DPoP</code> (otherwise legacy <code>Bearer</code>)
      </label>
      <label className="check">
        <input type="checkbox" checked={c.handle_nonce_challenge !== false} onChange={(e) => onChange({ ...c, handle_nonce_challenge: e.target.checked })} />
        Answer one <code>use_dpop_nonce</code> challenge with a fresh proof (only for requests safe to repeat)
      </label>
    </>
  );
}

function WsseFields({ c, onChange, workspaceId }: { c: WsseConfig; onChange: (c: WsseConfig) => void; workspaceId: string | null }) {
  return (
    <>
      <Text label="Username" value={c.username} onChange={(username) => onChange({ ...c, username: username ?? "" })} />
      <SecretField label="Password" value={c.password} onChange={(password) => onChange({ ...c, password })} workspaceId={workspaceId} />
      <div className="row">
        <label className="lbl">
          Password type
          <select className="field" value={c.password_type ?? "password_digest"} onChange={(e) => onChange({ ...c, password_type: e.target.value as WsseConfig["password_type"] })}>
            <option value="password_digest">PasswordDigest</option>
            <option value="password_text">PasswordText</option>
          </select>
        </label>
        <Num label="Timestamp lifetime (s)" value={c.timestamp_ttl_secs} onChange={(timestamp_ttl_secs) => onChange({ ...c, timestamp_ttl_secs })} />
      </div>
      <SecretField label="Signed SAML assertion XML (optional, embedded verbatim)" multiline value={c.saml_assertion ?? undefined} onChange={(saml_assertion) => onChange({ ...c, saml_assertion })} workspaceId={workspaceId} />
      <p className="hint">The security header is inserted into the SOAP envelope at send time. Anvil never mints SAML assertions.</p>
    </>
  );
}

export function PemFromFile(props: { label: string; workspaceId: string | null; onSecret: (v: SensitiveValue) => void }) {
  const [err, setErr] = useState<string | null>(null);
  return (
    <div className="row">
      <button
        className="btn small"
        disabled={!props.workspaceId}
        title={props.workspaceId ? undefined : "Open a workspace to keep values in its vault"}
        onClick={async () => {
          const workspaceId = props.workspaceId;
          if (!workspaceId) return;
          setErr(null);
          try {
            const file = await api.chooseFile("pem_file");
            if (!file) return;
            const r = await api.readTextFile(file.token, workspaceId, file.file_name || "key");
            if (r.secret) props.onSecret({ kind: "secret", secret: r.secret });
          } catch (e) {
            setErr(String((e as Error).message));
          }
        }}
      >
        {props.label}
      </button>
      {err && <span className="faint">{err}</span>}
    </div>
  );
}

function JwtInspectButton() {
  const [openDlg, setOpen] = useState(false);
  const [token, setToken] = useState("");
  const [res, setRes] = useState<JwtInspection | null>(null);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button className="btn small ghost" style={{ alignSelf: "start" }} onClick={() => setOpen(true)}>
        Inspect a JWT…
      </button>
      {openDlg && (
        <Modal title="Inspect JWT (decoded locally)" onClose={() => setOpen(false)}>
          <textarea className="field" rows={4} value={token} onChange={(e) => setToken(e.target.value)} placeholder="eyJ…" />
          <button
            className="btn"
            onClick={async () => {
              setErr(null);
              try {
                setRes(await api.jwtInspect(token.trim()));
              } catch (e) {
                setRes(null);
                setErr(String((e as Error).message));
              }
            }}
          >
            Decode
          </button>
          {err && <div className="bad-box">{err}</div>}
          {res && (
            <div className="col">
              <div className="row">
                <span className={`badge ${res.time_status === "valid" || res.time_status === "no_expiry" ? "ok" : "bad"}`}>{res.time_status.replace(/_/g, " ")}</span>
                <span className="badge">signature not verified</span>
              </div>
              <pre className="code">{JSON.stringify(res.header, null, 2)}</pre>
              <pre className="code">{JSON.stringify(res.claims, null, 2)}</pre>
              {res.notes.map((n, i) => (
                <div key={i} className="hint">
                  {n}
                </div>
              ))}
            </div>
          )}
        </Modal>
      )}
    </>
  );
}

function Text(props: { label: string; value?: string | null; onChange: (v: string | null) => void }) {
  return (
    <label className="lbl grow">
      {props.label}
      <input className="field mono" value={props.value ?? ""} onChange={(e) => props.onChange(e.target.value === "" ? null : e.target.value)} />
    </label>
  );
}

function Num(props: { label: string; value?: number | null; onChange: (v: number | null) => void }) {
  return (
    <label className="lbl">
      {props.label}
      <input className="field mono" style={{ width: 150 }} inputMode="numeric" value={props.value ?? ""} onChange={(e) => props.onChange(e.target.value === "" ? null : Number(e.target.value))} />
    </label>
  );
}
