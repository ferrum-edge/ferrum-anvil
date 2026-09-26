// SPIFFE Workload API in the renderer: the JWT-SVID auth editor, the
// Workload API client-identity fields of a TLS profile, a probe button
// ("what does this endpoint issue to Anvil?") and the evidence view for a
// record. The backend does every Workload API call; keys and tokens never
// reach the webview — only SPIFFE IDs, expiry, key ids and check results.
import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, type WorkloadProbe } from "./api";
import type { CheckResult, ClientIdentity, JwtSvidConfig, JwtSvidSource, JwtSvidSummary, WorkloadApiCall, WorkloadApiEvidence } from "./generated/contracts";
import { SecretField, humanize } from "./ui";

const ENDPOINT_PLACEHOLDER = "unix:///run/spire/sockets/agent.sock";

export function defaultJwtSvid(): JwtSvidConfig {
  return {
    source: { kind: "workload_api" },
    audiences: [],
    endpoint: "",
    verify_with_bundles: true,
    send_despite_failed_checks: false,
    header_name: "Authorization",
    prefix: "Bearer",
  };
}

function callResult(c: WorkloadApiCall): string {
  const r = c.result;
  switch (r.result) {
    case "ok":
      return c.cached ? "OK (cached)" : "OK";
    case "unavailable":
      return `unavailable: ${r.detail}`;
    case "timeout":
      return `no answer within ${r.deadline_ms} ms`;
    case "status":
      return `${r.code_name}${r.message ? ` "${r.message}"` : ""}`;
    case "no_identity":
      return `no identity: ${r.detail}`;
    case "malformed":
      return `malformed answer: ${r.detail}`;
  }
}

function checkBadge(r: CheckResult) {
  return r === "passed" ? "badge ok" : r === "failed" ? "badge bad" : "badge";
}

export function JwtSvidChecks({ j }: { j: JwtSvidSummary }) {
  return (
    <table className="grid" aria-label="JWT-SVID checks">
      <tbody>
        <tr><td className="k">Subject</td><td className="v mono">{j.subject ?? "—"}</td></tr>
        <tr><td className="k">Audience (aud)</td><td className="v mono">{j.audiences.join(", ") || "—"}</td></tr>
        <tr><td className="k">Algorithm / key id</td><td className="v mono">{j.algorithm ?? "—"} / {j.key_id ?? "—"}</td></tr>
        <tr><td className="k">Expires</td><td className="v">{j.expires_at ?? "—"}</td></tr>
        {j.checks.map((c) => (
          <tr key={c.check}>
            <td className="k">{humanize(c.check)} check</td>
            <td className="v">
              <span className={checkBadge(c.result)}>{humanize(c.result)}</span> {c.detail}
            </td>
          </tr>
        ))}
        {j.sent_despite_failed_checks && (
          <tr><td className="k">Sent</td><td className="v"><span className="badge warn">despite failed checks (profile setting)</span></td></tr>
        )}
      </tbody>
    </table>
  );
}

/** Workload API evidence of one execution (Connection tab). */
export function WorkloadEvidenceView({ w }: { w: WorkloadApiEvidence }) {
  return (
    <div className="col" data-testid="workload-evidence">
      <h4 className="faint" style={{ margin: "6px 0 0" }}>SPIFFE Workload API</h4>
      <table className="grid">
        <tbody>
          {w.calls.map((c, i) => (
            <tr key={i}>
              <td className="k">{c.rpc}</td>
              <td className="v">
                <span className="mono">{c.endpoint}</span> ({c.endpoint_source === "environment" ? "SPIFFE_ENDPOINT_SOCKET" : "profile"}) · {c.purpose} → {callResult(c)}
                {c.caller_uid != null ? ` · Anvil runs as uid ${c.caller_uid}` : ""}
              </td>
            </tr>
          ))}
          {w.x509_svids.map((s, i) => (
            <tr key={`x${i}`}>
              <td className="k">X.509-SVID ({s.tls_profile})</td>
              <td className="v">
                <span className="mono">{s.spiffe_id}</span> · expires {s.certificate.not_after} · {s.bundle_trusted ? `trust-domain bundle trusted (${s.bundle_certificates} CA)` : "bundle not trusted"}
                {s.federated_trust_domains.length > 0 ? ` · federated bundles recorded, not trusted: ${s.federated_trust_domains.join(", ")}` : ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {w.jwt_svid && <JwtSvidChecks j={w.jwt_svid} />}
      <p className="hint">Private keys and the JWT-SVID itself are never recorded.</p>
    </div>
  );
}

/** Ask the backend what the endpoint issues to this process. */
export function WorkloadProbeButton(props: { endpoint: string; audience?: string | null }) {
  const [res, setRes] = useState<WorkloadProbe | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="col">
      <button
        className="btn small"
        style={{ alignSelf: "start" }}
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setErr(null);
          try {
            setRes(await api.workloadProbe(props.endpoint, props.audience ?? null));
          } catch (e) {
            setRes(null);
            setErr(String((e as Error).message));
          } finally {
            setBusy(false);
          }
        }}
      >
        Test the Workload API
      </button>
      {err && <div className="bad-box">{err}</div>}
      {res && (
        <div className="col" data-testid="workload-probe">
          {res.endpoint_error ? (
            <div className="bad-box">{res.endpoint_error}</div>
          ) : (
            <table className="grid">
              <tbody>
                {res.calls.map((c, i) => (
                  <tr key={i}>
                    <td className="k">{c.rpc}</td>
                    <td className="v">{callResult(c)}{c.caller_uid != null ? ` · Anvil runs as uid ${c.caller_uid}` : ""}</td>
                  </tr>
                ))}
                {res.x509_svids.map((s) => (
                  <tr key={s.spiffe_id}><td className="k">X.509-SVID</td><td className="v mono">{s.spiffe_id} · expires {s.not_after}</td></tr>
                ))}
                {res.jwt_bundles.map((b) => (
                  <tr key={b.trust_domain}><td className="k">JWT bundle</td><td className="v mono">{b.trust_domain} · keys {b.key_ids.join(", ")}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          {res.jwt_svid && <JwtSvidChecks j={res.jwt_svid} />}
        </div>
      )}
    </div>
  );
}

function sourceOf(kind: JwtSvidSource["kind"], prev: JwtSvidSource): JwtSvidSource {
  if (kind === prev.kind) return prev;
  if (kind === "value") return { kind: "value", token: { kind: "template", value: "" } };
  if (kind === "file") return { kind: "file", path: "" };
  return { kind: "workload_api" };
}

/** JWT-SVID auth profile fields. */
export function JwtSvidFields({ c, onChange, workspaceId }: { c: JwtSvidConfig; onChange: (c: JwtSvidConfig) => void; workspaceId: string | null }) {
  const src = c.source;
  const needsEndpoint = src.kind === "workload_api" || !!c.verify_with_bundles;
  return (
    <>
      <label className="lbl">
        Token source
        <select className="field" value={src.kind} onChange={(e) => onChange({ ...c, source: sourceOf(e.target.value as JwtSvidSource["kind"], src) })}>
          <option value="workload_api">SPIFFE Workload API (FetchJWTSVID)</option>
          <option value="value">Variable or vault value</option>
          <option value="file">File (read at send time)</option>
        </select>
      </label>
      {src.kind === "value" && (
        <SecretField label="JWT-SVID" value={src.token} workspaceId={workspaceId} onChange={(token) => onChange({ ...c, source: { kind: "value", token } })} />
      )}
      {src.kind === "file" && (
        <div className="row">
          <label className="lbl grow">
            Token file
            <input className="field mono" value={src.path} placeholder="/run/secrets/jwt_svid.token" onChange={(e) => onChange({ ...c, source: { kind: "file", path: e.target.value } })} />
          </label>
          <button
            className="btn small"
            style={{ alignSelf: "end" }}
            onClick={async () => {
              const path = await open({ multiple: false, directory: false });
              if (typeof path === "string") onChange({ ...c, source: { kind: "file", path } });
            }}
          >
            Choose…
          </button>
        </div>
      )}
      <label className="lbl">
        Audiences (comma-separated; each must be in the token's aud)
        <input
          className="field mono"
          value={(c.audiences ?? []).join(", ")}
          placeholder="spiffe://example.org/api"
          onChange={(e) => onChange({ ...c, audiences: e.target.value.split(",").map((s) => s.trim()).filter((s) => s !== "") })}
        />
      </label>
      {(c.audiences ?? []).length === 0 && <div className="warn-box">Set the verifier's audience; a JWT-SVID profile without one is refused before anything is sent.</div>}
      <label className="lbl">
        SPIFFE ID ({src.kind === "workload_api" ? "request this identity; empty = the workload's default" : "the token's sub must equal it; empty = any workload ID"})
        <input className="field mono" value={c.spiffe_id ?? ""} placeholder="spiffe://example.org/ns/default/sa/app" onChange={(e) => onChange({ ...c, spiffe_id: e.target.value || null })} />
      </label>
      <label className="check">
        <input type="checkbox" checked={!!c.verify_with_bundles} onChange={(e) => onChange({ ...c, verify_with_bundles: e.target.checked })} />
        Verify the signature against the trust domain's JWT bundle (FetchJWTBundles) before sending
      </label>
      {needsEndpoint && (
        <label className="lbl">
          Workload API endpoint (empty = SPIFFE_ENDPOINT_SOCKET)
          <input className="field mono" value={c.endpoint ?? ""} placeholder={ENDPOINT_PLACEHOLDER} onChange={(e) => onChange({ ...c, endpoint: e.target.value })} />
        </label>
      )}
      <div className="row">
        <label className="lbl grow">
          Header
          <input className="field mono" value={c.header_name ?? "Authorization"} onChange={(e) => onChange({ ...c, header_name: e.target.value })} />
        </label>
        <label className="lbl grow">
          Prefix
          <input className="field mono" value={c.prefix ?? "Bearer"} onChange={(e) => onChange({ ...c, prefix: e.target.value })} />
        </label>
      </div>
      <label className="check">
        <input type="checkbox" checked={!!c.send_despite_failed_checks} onChange={(e) => onChange({ ...c, send_despite_failed_checks: e.target.checked })} />
        Send even when a local check fails (to test how the verifier treats a bad token)
      </label>
      {c.send_despite_failed_checks && <div className="warn-box">An expired, mis-addressed or unverifiable JWT-SVID will be sent. The failed checks stay on the result as warnings.</div>}
      {needsEndpoint && <WorkloadProbeButton endpoint={c.endpoint ?? ""} audience={src.kind === "workload_api" ? (c.audiences ?? [])[0] ?? null : null} />}
      <p className="hint">
        Before sending, Anvil checks that the token is a JWT-SVID (an asymmetric alg, a workload SPIFFE ID as sub), that every audience above is in aud and that exp is in the future by this machine's clock; verifiers use their own clock and leeway. Fetched tokens are cached in memory until half their lifetime, never written, and cleared on lock.
      </p>
    </>
  );
}

type WorkloadIdentity = Extract<ClientIdentity, { format: "workload_api" }>;

/** Workload API client identity of a TLS profile. */
export function WorkloadIdentityFields({ id, onChange }: { id: WorkloadIdentity; onChange: (id: WorkloadIdentity) => void }) {
  return (
    <div className="col" style={{ marginTop: 8 }}>
      <label className="lbl">
        Workload API endpoint (empty = SPIFFE_ENDPOINT_SOCKET)
        <input className="field mono" value={id.endpoint ?? ""} placeholder={ENDPOINT_PLACEHOLDER} onChange={(e) => onChange({ ...id, endpoint: e.target.value })} />
      </label>
      <label className="lbl">
        SPIFFE ID (when the workload holds several; empty = the default SVID)
        <input className="field mono" value={id.spiffe_id ?? ""} placeholder="spiffe://example.org/ns/default/sa/app" onChange={(e) => onChange({ ...id, spiffe_id: e.target.value || null })} />
      </label>
      <label className="check">
        <input type="checkbox" checked={!!id.trust_bundle} onChange={(e) => onChange({ ...id, trust_bundle: e.target.checked })} />
        Also trust the SVID's trust-domain bundle from the Workload API (for verifying mesh servers by SPIFFE ID)
      </label>
      <WorkloadProbeButton endpoint={id.endpoint ?? ""} />
      <p className="hint">
        The X.509-SVID is fetched (FetchX509SVID) when a TLS request uses this profile and fetched again at half its lifetime, as SPIFFE agents rotate. Its private key stays in memory in the backend and is cleared on lock. The Workload API identifies Anvil by the user it runs as; federated bundles are shown but never trusted.
      </p>
    </div>
  );
}
