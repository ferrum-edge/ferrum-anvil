// Management dialogs: environments, connection profiles, export/import and
// app settings. All persistence happens in Rust.
import { useEffect, useState } from "react";
import { api, type ExportPreview, type FileGrant, type ImportReport, type ProviderInfo, type SpecImported, type SystemInfo } from "./api";
import type {
  AppSettings,
  ClientIdentity,
  Environment,
  HboneMarker,
  HboneOptions,
  IntegrationProfile,
  KeyValue,
  ProxyProfile,
  TlsProfile,
  Variable,
  Workspace,
} from "./generated/contracts";
import { PemFromFile } from "./AuthEditor";
import { SpecImport } from "./SpecImport";
import { Modal, SecretField, Tabs, humanize } from "./ui";
import { WorkloadIdentityFields } from "./WorkloadApi";

const now = () => new Date().toISOString();

/** Ferrum Edge releases with a source-audited catalog in anvil-diagnostics
 * (`catalog/ferrum/<id>/outcomes.json`), newest first; new profiles use the first. */
export const FERRUM_COMPATIBILITY = [
  { id: "ferrum-edge-0.9.7", label: "Ferrum Edge 0.9.7" },
  { id: "ferrum-edge-0.9.5", label: "Ferrum Edge 0.9.5" },
] as const;

// ------------------------------------------------------------ environments

export function EnvironmentsDialog(props: { workspace: Workspace; onClose: () => void; onChanged: () => void }) {
  const [envs, setEnvs] = useState<Environment[]>([]);
  const [sel, setSel] = useState<string>("__base");
  const [draft, setDraft] = useState<Variable[]>([]);
  const [name, setName] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const load = async () => {
    const e = await api.environments(props.workspace.id);
    setEnvs(e);
    return e;
  };
  useEffect(() => {
    void load();
  }, []);
  useEffect(() => {
    if (sel === "__base") {
      setDraft(props.workspace.variables ?? []);
      setName("Workspace variables");
    } else {
      const e = envs.find((x) => x.id === sel);
      setDraft(e?.variables ?? []);
      setName(e?.name ?? "");
    }
  }, [sel, envs]);
  const saveIt = async () => {
    setErr(null);
    try {
      if (sel === "__base") await api.saveWorkspace({ ...props.workspace, variables: draft });
      else {
        const e = envs.find((x) => x.id === sel)!;
        await api.saveEnvironment({ ...e, name, variables: draft });
      }
      await load();
      props.onChanged();
    } catch (e) {
      setErr(String((e as Error).message));
    }
  };
  return (
    <Modal
      title="Environments and variables"
      wide
      onClose={props.onClose}
      footer={
        <>
          {sel !== "__base" && (
            <button
              className="btn danger"
              onClick={async () => {
                await api.deleteEnvironment(sel);
                setSel("__base");
                await load();
                props.onChanged();
              }}
            >
              Delete environment
            </button>
          )}
          <span className="spacer" />
          <button className="btn primary" onClick={saveIt}>
            Save
          </button>
        </>
      }
    >
      <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: 14 }}>
        <div className="col">
          <button className={`btn ${sel === "__base" ? "primary" : ""}`} onClick={() => setSel("__base")}>
            Workspace base
          </button>
          {envs.map((e) => (
            <button key={e.id} className={`btn ${sel === e.id ? "primary" : ""}`} onClick={() => setSel(e.id)}>
              {e.name}
            </button>
          ))}
          <button
            className="btn ghost"
            onClick={async () => {
              const e = await api.saveEnvironment({ id: crypto.randomUUID(), schema_version: 1, created_at: now(), updated_at: now(), workspace_id: props.workspace.id, name: "New environment", variables: [] });
              await load();
              setSel(e.id);
              props.onChanged();
            }}
          >
            + New environment
          </button>
        </div>
        <div className="col">
          {sel !== "__base" && (
            <label className="lbl">
              Name
              <input className="field" value={name} onChange={(e) => setName(e.target.value)} />
            </label>
          )}
          <p className="hint">Precedence: run values → request → folders → active environment → workspace base. Secret variables are masked, redacted from history and exported only as placeholders unless you choose an encrypted export.</p>
          <VariablesEditor vars={draft} onChange={setDraft} workspaceId={props.workspace.id} />
          {err && <div className="bad-box">{err}</div>}
        </div>
      </div>
    </Modal>
  );
}

export function VariablesEditor(props: { vars: Variable[]; onChange: (v: Variable[]) => void; workspaceId: string }) {
  const set = (i: number, v: Variable) => props.onChange(props.vars.map((x, j) => (j === i ? v : x)));
  return (
    <div className="col">
      {props.vars.map((v, i) => (
        <div key={i} className="row" style={{ alignItems: "flex-end" }}>
          <input type="checkbox" aria-label="Enabled" checked={v.enabled !== false} onChange={(e) => set(i, { ...v, enabled: e.target.checked })} />
          <label className="lbl" style={{ width: 200 }}>
            Name
            <input className="field mono" value={v.name} onChange={(e) => set(i, { ...v, name: e.target.value })} />
          </label>
          <div className="grow">
            {v.secret ? (
              <SecretField label="Value (secret)" value={v.value} workspaceId={props.workspaceId} onChange={(value) => set(i, { ...v, value })} />
            ) : (
              <label className="lbl">
                Value
                <input className="field mono" value={v.value.kind === "template" ? v.value.value : ""} onChange={(e) => set(i, { ...v, value: { kind: "template", value: e.target.value } })} />
              </label>
            )}
          </div>
          <label className="check" style={{ paddingBottom: 6 }}>
            <input type="checkbox" checked={!!v.secret} onChange={(e) => set(i, { ...v, secret: e.target.checked })} />
            secret
          </label>
          <button className="btn ghost icon-btn" aria-label="Remove variable" onClick={() => props.onChange(props.vars.filter((_, j) => j !== i))}>
            ✕
          </button>
        </div>
      ))}
      <button className="btn small" style={{ alignSelf: "start" }} onClick={() => props.onChange([...props.vars, { name: "", value: { kind: "template", value: "" }, enabled: true }])}>
        + Variable
      </button>
    </div>
  );
}

// ------------------------------------------------------- connection profiles

type PTab = "tls" | "proxy" | "ferrum";

export function ProfilesDialog(props: { workspaceId: string; onClose: () => void; onChanged: () => void }) {
  const [tab, setTab] = useState<PTab>("tls");
  const [tls, setTls] = useState<TlsProfile[]>([]);
  const [proxy, setProxy] = useState<ProxyProfile[]>([]);
  const [ints, setInts] = useState<IntegrationProfile[]>([]);
  const [editing, setEditing] = useState<{ kind: PTab; value: TlsProfile | ProxyProfile | IntegrationProfile } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = async () => {
    const [a, b, c] = await Promise.all([api.tlsProfiles(props.workspaceId), api.proxyProfiles(props.workspaceId), api.integrations(props.workspaceId)]);
    setTls(a);
    setProxy(b);
    setInts(c);
  };
  useEffect(() => {
    void load();
  }, []);
  const base = { id: crypto.randomUUID(), workspace_id: props.workspaceId, created_at: now(), updated_at: now() };
  const saveIt = async () => {
    if (!editing) return;
    setErr(null);
    try {
      if (editing.kind === "tls") await api.saveTlsProfile(editing.value as TlsProfile);
      if (editing.kind === "proxy") await api.saveProxyProfile(editing.value as ProxyProfile);
      if (editing.kind === "ferrum") await api.saveIntegration(editing.value as IntegrationProfile);
      setEditing(null);
      await load();
      props.onChanged();
    } catch (e) {
      setErr(String((e as Error).message));
    }
  };
  return (
    <Modal
      title="Connection profiles"
      wide
      onClose={props.onClose}
      footer={
        editing ? (
          <>
            <button className="btn" onClick={() => setEditing(null)}>
              Back
            </button>
            <button className="btn primary" onClick={saveIt}>
              Save profile
            </button>
          </>
        ) : undefined
      }
    >
      {!editing && (
        <>
          <Tabs
            tabs={[
              { id: "tls" as PTab, label: "TLS & client certificates", count: tls.length },
              { id: "proxy" as PTab, label: "Proxies", count: proxy.length },
              { id: "ferrum" as PTab, label: "Ferrum gateways", count: ints.length },
            ]}
            value={tab}
            onChange={setTab}
          />
          {tab === "tls" && (
            <ProfileList
              items={tls.map((p) => ({ id: p.id, name: p.name, meta: `${p.verify === false ? "⚠ verification off" : "verification on"}${spiffeLabel(p)} · ${p.client_identity ? `client cert (${p.client_identity.format})` : "no client cert"} · ${(p.extra_roots_pem ?? []).length} extra CA${p.server_name_override ? ` · SNI ${p.server_name_override}` : ""}` }))}
              onEdit={(id) => setEditing({ kind: "tls", value: tls.find((p) => p.id === id)! })}
              onNew={() => setEditing({ kind: "tls", value: { ...base, name: "New TLS profile", verify: true, use_system_roots: true, extra_roots_pem: [], bindings: [], min_version: "tls12" } })}
            />
          )}
          {tab === "proxy" && (
            <ProfileList
              items={proxy.map((p) => ({ id: p.id, name: p.name, meta: `${p.kind === "hbone" ? "HBONE" : p.kind} ${p.address}${p.tls_profile_id ? ` · TLS: ${tls.find((t) => t.id === p.tls_profile_id)?.name ?? "missing profile"}` : ""}${p.no_proxy ? ` · bypass: ${p.no_proxy}` : ""}` }))}
              onEdit={(id) => setEditing({ kind: "proxy", value: proxy.find((p) => p.id === id)! })}
              onNew={() => setEditing({ kind: "proxy", value: { ...base, name: "New proxy", kind: "http", address: "127.0.0.1:8080", no_proxy: "localhost,127.0.0.1" } })}
            />
          )}
          {tab === "ferrum" && (
            <>
              <p className="hint">
                Declaring a destination as a Ferrum Edge gateway lets Anvil treat its <code>X-Gateway-Error</code> markers as gateway-authored (still coarse). Without a profile, the same header from any server is only a “Ferrum-like marker”.
              </p>
              <ProfileList
                items={ints.map((p) => ({ id: p.id, name: p.name, meta: `${p.compatibility_id} · ${p.hosts.map((h) => h.host + (h.port ? `:${h.port}` : "")).join(", ")}${p.require_verified_tls === false ? " · plain-HTTP trust (lab)" : ""}` }))}
                onEdit={(id) => setEditing({ kind: "ferrum", value: ints.find((p) => p.id === id)! })}
                onNew={() => setEditing({ kind: "ferrum", value: { ...base, name: "My gateway", kind: "ferrum_gateway", hosts: [{ host: "gateway.example.com" }], compatibility_id: FERRUM_COMPATIBILITY[0].id, require_verified_tls: true } })}
              />
            </>
          )}
        </>
      )}
      {editing?.kind === "tls" && <TlsForm p={editing.value as TlsProfile} onChange={(value) => setEditing({ kind: "tls", value })} />}
      {editing?.kind === "proxy" && <ProxyForm p={editing.value as ProxyProfile} tlsProfiles={tls} onChange={(value) => setEditing({ kind: "proxy", value })} />}
      {editing?.kind === "ferrum" && <FerrumForm p={editing.value as IntegrationProfile} onChange={(value) => setEditing({ kind: "ferrum", value })} />}
      {err && <div className="bad-box">{err}</div>}
    </Modal>
  );
}

function ProfileList(props: { items: { id: string; name: string; meta: string }[]; onEdit: (id: string) => void; onNew: () => void }) {
  return (
    <div className="col">
      {props.items.length === 0 && <div className="faint">None yet.</div>}
      {props.items.map((i) => (
        <button key={i.id} className="btn" style={{ height: "auto", padding: 10, justifyContent: "space-between" }} onClick={() => props.onEdit(i.id)}>
          <b>{i.name}</b>
          <span className="faint">{i.meta}</span>
        </button>
      ))}
      <button className="btn ghost" style={{ alignSelf: "start" }} onClick={props.onNew}>
        + New
      </button>
    </div>
  );
}

function hostsText(h: { host: string; port?: number | null }[] | undefined) {
  return (h ?? []).map((b) => b.host + (b.port ? `:${b.port}` : "")).join(", ");
}
function parseHosts(s: string) {
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .map((x) => {
      const m = /^(.*?)(?::(\d+))?$/.exec(x)!;
      return { host: m[1], port: m[2] ? Number(m[2]) : null };
    });
}

function spiffeLabel(p: TlsProfile) {
  const s = p.server_spiffe;
  if (!s || !(s.expected_server_spiffe_id || s.trust_domain)) return "";
  return ` · SPIFFE ${s.expected_server_spiffe_id || `trust domain ${s.trust_domain}`}`;
}

export function TlsForm({ p, onChange }: { p: TlsProfile; onChange: (p: TlsProfile) => void }) {
  const id: ClientIdentity | null | undefined = p.client_identity;
  const spiffe = p.server_spiffe != null;
  return (
    <div className="col">
      <label className="lbl">
        Name
        <input className="field" value={p.name} onChange={(e) => onChange({ ...p, name: e.target.value })} />
      </label>
      <label className="check">
        <input type="checkbox" checked={p.verify !== false} onChange={(e) => onChange({ ...p, verify: e.target.checked })} />
        Verify the server certificate (recommended)
      </label>
      {p.verify === false && (
        <div className="warn-box">
          <b>Verification disabled.</b> The connection stays encrypted but the server is not authenticated — anyone on the path could impersonate it. Prefer adding the server's CA below. This bypass applies only to requests that select this profile, is shown on every response, and is never enabled by an import.
        </div>
      )}
      <label className="check">
        <input type="checkbox" checked={p.use_system_roots !== false} onChange={(e) => onChange({ ...p, use_system_roots: e.target.checked })} />
        Trust the operating system's certificate store
      </label>
      <label className="lbl">
        Additional trusted CA certificates (PEM, scoped to this profile — never installed into the OS)
        <textarea
          className="field"
          rows={4}
          value={(p.extra_roots_pem ?? []).join("\n")}
          onChange={(e) => onChange({ ...p, extra_roots_pem: e.target.value.trim() ? [e.target.value] : [] })}
          placeholder="-----BEGIN CERTIFICATE-----"
        />
      </label>
      <button
        className="btn small"
        style={{ alignSelf: "start" }}
        onClick={async () => {
          const file = await api.chooseFile("pem_file");
          if (!file) return;
          const r = await api.readTextFile(file.token, p.workspace_id, null);
          if (r.text) onChange({ ...p, extra_roots_pem: [...(p.extra_roots_pem ?? []), r.text] });
        }}
      >
        Add CA from file…
      </button>
      <div className="row">
        <label className="lbl">
          Minimum TLS version
          <select className="field" value={p.min_version ?? "tls12"} onChange={(e) => onChange({ ...p, min_version: e.target.value as "tls12" })}>
            <option value="tls12">TLS 1.2</option>
            <option value="tls13">TLS 1.3</option>
          </select>
        </label>
        <label className="lbl grow">
          SNI / verification name override (advanced)
          <input
            className="field mono"
            value={p.server_name_override ?? ""}
            placeholder="outbound_.8080_._.svc.ns.svc.cluster.local"
            onChange={(e) => onChange({ ...p, server_name_override: e.target.value || null })}
          />
        </label>
      </div>
      {p.server_name_override && (
        <p className="hint">
          Sent as the TLS server name (SNI) instead of the URL host; the HTTP authority is unchanged. The certificate is verified against this name{spiffe ? ", or against the SPIFFE identity below when set" : ""}.
        </p>
      )}
      <fieldset style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10 }}>
        <legend className="faint">Server identity (SPIFFE / mesh)</legend>
        <label className="check">
          <input
            type="checkbox"
            checked={spiffe}
            onChange={(e) => onChange({ ...p, server_spiffe: e.target.checked ? { expected_server_spiffe_id: "", trust_domain: "" } : null })}
          />
          Verify the server by its SPIFFE ID instead of the host name
        </label>
        {spiffe && (
          <div className="col" style={{ marginTop: 8 }}>
            <p className="hint">
              The server's X.509-SVID must chain to the CA certificates above (the trust domain's bundle) and carry exactly one <code>spiffe://</code> URI SAN. DNS names in the certificate are not used. Set an exact ID, a trust domain, or both.
            </p>
            <label className="lbl">
              Expected server SPIFFE ID
              <input
                className="field mono"
                value={p.server_spiffe?.expected_server_spiffe_id ?? ""}
                placeholder="spiffe://cluster.local/ns/default/sa/my-service"
                onChange={(e) => onChange({ ...p, server_spiffe: { ...p.server_spiffe, expected_server_spiffe_id: e.target.value || null } })}
              />
            </label>
            <label className="lbl">
              Trusted trust domain
              <input
                className="field mono"
                value={p.server_spiffe?.trust_domain ?? ""}
                placeholder="cluster.local"
                onChange={(e) => onChange({ ...p, server_spiffe: { ...p.server_spiffe, trust_domain: e.target.value || null } })}
              />
            </label>
            {!(p.server_spiffe?.expected_server_spiffe_id || p.server_spiffe?.trust_domain) && <div className="warn-box">Set an expected SPIFFE ID or a trust domain; an empty SPIFFE check falls back to host-name verification.</div>}
            {(p.extra_roots_pem ?? []).length === 0 && !(id?.format === "workload_api" && id.trust_bundle) && (
              <div className="warn-box">Add the trust domain's CA certificates (its trust bundle) above, or take the bundle from the Workload API below; SPIFFE verification needs them.</div>
            )}
          </div>
        )}
      </fieldset>
      <fieldset style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10 }}>
        <legend className="faint">Client certificate (mTLS)</legend>
        <div className="row">
          <select
            className="field"
            value={id?.format ?? "none"}
            onChange={(e) =>
              onChange({
                ...p,
                client_identity:
                  e.target.value === "none"
                    ? null
                    : e.target.value === "pem"
                      ? { format: "pem", cert_chain_pem: "", private_key_pem: { kind: "template", value: "" } }
                      : e.target.value === "workload_api"
                        ? { format: "workload_api", endpoint: "", trust_bundle: true }
                        : { format: "pkcs12", bundle_b64: { kind: "template", value: "" }, password: { kind: "template", value: "" } },
              })
            }
          >
            <option value="none">None</option>
            <option value="pem">PEM certificate + key</option>
            <option value="pkcs12">PKCS#12 (.p12 / .pfx)</option>
            <option value="workload_api">SPIFFE Workload API (X.509-SVID)</option>
          </select>
        </div>
        {id?.format === "pem" && (
          <div className="col" style={{ marginTop: 8 }}>
            <label className="lbl">
              Certificate chain (PEM)
              <textarea className="field" rows={4} value={id.cert_chain_pem} onChange={(e) => onChange({ ...p, client_identity: { ...id, cert_chain_pem: e.target.value } })} />
            </label>
            <button
              className="btn small"
              style={{ alignSelf: "start" }}
              onClick={async () => {
                const file = await api.chooseFile("pem_file");
                if (!file) return;
                const r = await api.readTextFile(file.token, p.workspace_id, null);
                if (r.text) onChange({ ...p, client_identity: { ...id, cert_chain_pem: r.text } });
              }}
            >
              Load certificate file…
            </button>
            <SecretField label="Private key (PEM)" multiline value={id.private_key_pem} workspaceId={p.workspace_id} onChange={(v) => onChange({ ...p, client_identity: { ...id, private_key_pem: v as typeof id.private_key_pem } })} />
            <PemFromFile label="Load private key file into the vault" workspaceId={p.workspace_id} onSecret={(v) => onChange({ ...p, client_identity: { ...id, private_key_pem: v as typeof id.private_key_pem } })} />
          </div>
        )}
        {id?.format === "pkcs12" && (
          <div className="col" style={{ marginTop: 8 }}>
            <p className="hint">Pick the .p12/.pfx file; it is stored in the vault. Legacy RC2/3DES bundles are supported.</p>
            <P12Picker workspaceId={p.workspace_id} onSecret={(v) => onChange({ ...p, client_identity: { ...id, bundle_b64: v as typeof id.bundle_b64 } })} current={id.bundle_b64.kind === "secret" ? id.bundle_b64.secret.label : null} />
            <SecretField label="Bundle password" value={id.password} workspaceId={p.workspace_id} onChange={(v) => onChange({ ...p, client_identity: { ...id, password: v } })} />
          </div>
        )}
        {id?.format === "workload_api" && <WorkloadIdentityFields id={id} onChange={(v) => onChange({ ...p, client_identity: v })} />}
        {id && (
          <label className="lbl" style={{ marginTop: 8 }}>
            Present only to these hosts (comma-separated; empty = any request using this profile)
            <input className="field mono" value={hostsText(p.bindings)} onChange={(e) => onChange({ ...p, bindings: parseHosts(e.target.value) })} placeholder="api.internal.example.com, *.mtls.example.com:8443" />
          </label>
        )}
        {id && (p.bindings ?? []).length === 0 && <div className="warn-box" style={{ marginTop: 8 }}>This certificate will be offered to any server a request using this profile connects to, including redirect targets.</div>}
      </fieldset>
    </div>
  );
}

function P12Picker(props: { workspaceId: string; onSecret: (v: { kind: "secret"; secret: { id: string; label: string } }) => void; current: string | null }) {
  const [err, setErr] = useState<string | null>(null);
  return (
    <div className="row">
      {props.current && <span className="badge accent">🔒 {props.current}</span>}
      <button
        className="btn small"
        onClick={async () => {
          setErr(null);
          try {
            const file = await api.chooseFile("pkcs12_file", { filters: [{ name: "PKCS#12", extensions: ["p12", "pfx"] }] });
            if (!file) return;
            // The bundle goes straight into the vault as base64; only a reference returns.
            const r = await api.readTextFile(file.token, props.workspaceId, file.file_name || "client.p12", true);
            if (r.secret) props.onSecret({ kind: "secret", secret: r.secret });
          } catch (e) {
            setErr(String((e as Error).message));
          }
        }}
      >
        Choose .p12 / .pfx…
      </button>
      {err && <span className="faint">{err}</span>}
    </div>
  );
}

function headersText(h: KeyValue[] | undefined) {
  return (h ?? []).map((x) => `${x.name}: ${x.value}`).join("\n");
}
function parseHeaders(t: string): KeyValue[] {
  return t
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const i = l.indexOf(":");
      return i < 0 ? { name: l, value: "", enabled: true } : { name: l.slice(0, i).trim(), value: l.slice(i + 1).trim(), enabled: true };
    });
}

export function ProxyForm({ p, tlsProfiles, onChange }: { p: ProxyProfile; tlsProfiles: TlsProfile[]; onChange: (p: ProxyProfile) => void }) {
  const hbone = p.kind === "hbone";
  const opts: HboneOptions = p.hbone ?? { marker: "none", extra_headers: [] };
  const setHbone = (h: HboneOptions) => onChange({ ...p, hbone: h });
  const tlsProfile = tlsProfiles.find((t) => t.id === p.tls_profile_id);
  return (
    <div className="col">
      <label className="lbl">
        Name
        <input className="field" value={p.name} onChange={(e) => onChange({ ...p, name: e.target.value })} />
      </label>
      <div className="row">
        <label className="lbl">
          Type
          <select
            className="field"
            value={p.kind}
            onChange={(e) => {
              const kind = e.target.value as ProxyProfile["kind"];
              onChange(kind === "hbone" ? { ...p, kind, username: null, password: null, hbone: p.hbone ?? { marker: "none", extra_headers: [] } } : { ...p, kind });
            }}
          >
            <option value="http">HTTP (CONNECT)</option>
            <option value="https">HTTPS (TLS to proxy)</option>
            <option value="socks5">SOCKS5</option>
            <option value="hbone">HBONE (mesh: HTTP/2 CONNECT over mTLS)</option>
          </select>
        </label>
        <label className="lbl grow">
          {hbone ? "HBONE endpoint (host:port)" : "Address (host:port)"}
          <input className="field mono" value={p.address} onChange={(e) => onChange({ ...p, address: e.target.value })} />
        </label>
      </div>
      {(hbone || p.kind === "https") && (
        <label className="lbl">
          {hbone ? "TLS profile for the endpoint (client SVID, trust bundle, expected SPIFFE ID)" : "TLS profile for the proxy (optional; default: system roots, strict)"}
          <select className="field" value={p.tls_profile_id ?? ""} onChange={(e) => onChange({ ...p, tls_profile_id: e.target.value || null })}>
            <option value="">{hbone ? "Choose a TLS profile…" : "Default (system roots)"}</option>
            {tlsProfiles.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>
        </label>
      )}
      {hbone && !p.tls_profile_id && <div className="warn-box">HBONE is mutual TLS: select a TLS profile with the workload's client SVID and the mesh trust bundle. Requests through this proxy are refused before sending until one is set.</div>}
      {hbone && tlsProfile && !tlsProfile.client_identity && <div className="warn-box">The selected TLS profile has no client certificate: the endpoint will not see an authenticated mesh peer.</div>}
      {hbone && tlsProfile && tlsProfile.verify === false && <div className="warn-box">The selected TLS profile disables verification: the HBONE endpoint's identity is not authenticated (shown on every response).</div>}
      {hbone && (
        <fieldset style={{ border: "1px solid var(--border)", borderRadius: 8, padding: 10 }}>
          <legend className="faint">HBONE CONNECT</legend>
          <p className="hint">
            Anvil sends <code>CONNECT</code> with <code>:authority</code> = the request's host:port over HTTP/2; a 2xx opens the tunnel and the request (HTTP, TLS, WebSocket or TCP) runs inside it. A fresh tunnel is opened per request.
          </p>
          <p className="hint" data-testid="hbone-udp-help">
            UDP requests (udp://) use a datagram tunnel: the <code>CONNECT</code> always carries the marker with the value <code>udp</code> ({(opts.marker ?? "none") === "istio_protocol" ? "x-istio-protocol: udp" : "x-ferrum-mesh-protocol: udp"}), and each datagram is one [u16 length][payload] record on the stream.
          </p>
          <div className="row">
            <label className="lbl">
              Protocol marker
              <select className="field" value={opts.marker ?? "none"} onChange={(e) => setHbone({ ...opts, marker: e.target.value as HboneMarker })}>
                <option value="none">None (Istio ztunnel style)</option>
                <option value="ferrum_mesh_protocol">x-ferrum-mesh-protocol: hbone</option>
                <option value="istio_protocol">x-istio-protocol: hbone</option>
              </select>
            </label>
            <label className="lbl grow">
              Baggage (optional)
              <input
                className="field mono"
                value={opts.baggage ?? ""}
                placeholder="source.principal=spiffe://cluster.local/ns/default/sa/client"
                onChange={(e) => setHbone({ ...opts, baggage: e.target.value || null })}
              />
            </label>
          </div>
          <p className="hint">A marker never authenticates the client; identity baggage is honored only from trusted assertors that match the client SVID.</p>
          <label className="lbl">
            Extra CONNECT headers (one "Name: value" per line)
            <textarea className="field mono" rows={2} value={headersText(opts.extra_headers)} onChange={(e) => setHbone({ ...opts, extra_headers: parseHeaders(e.target.value) })} />
          </label>
        </fieldset>
      )}
      {!hbone && (
        <>
          <label className="lbl">
            Username (optional)
            <input className="field mono" value={p.username ?? ""} onChange={(e) => onChange({ ...p, username: e.target.value || null })} />
          </label>
          <SecretField label="Password (optional)" value={p.password ?? undefined} workspaceId={p.workspace_id} onChange={(password) => onChange({ ...p, password })} />
        </>
      )}
      <label className="lbl">
        Bypass for (NO_PROXY: hosts, suffixes, CIDRs, * for all)
        <input className="field mono" value={p.no_proxy ?? ""} onChange={(e) => onChange({ ...p, no_proxy: e.target.value })} />
      </label>
    </div>
  );
}

function FerrumForm({ p, onChange }: { p: IntegrationProfile; onChange: (p: IntegrationProfile) => void }) {
  return (
    <div className="col">
      <label className="lbl">
        Name
        <input className="field" value={p.name} onChange={(e) => onChange({ ...p, name: e.target.value })} />
      </label>
      <label className="lbl">
        Gateway frontend hosts (comma-separated, optional :port)
        <input className="field mono" value={hostsText(p.hosts)} onChange={(e) => onChange({ ...p, hosts: parseHosts(e.target.value) })} />
      </label>
      <label className="lbl">
        Compatibility catalog
        <select className="field" value={p.compatibility_id} onChange={(e) => onChange({ ...p, compatibility_id: e.target.value })}>
          {FERRUM_COMPATIBILITY.map((c) => (
            <option key={c.id} value={c.id}>
              {c.label}
            </option>
          ))}
          {!FERRUM_COMPATIBILITY.some((c) => c.id === p.compatibility_id) && <option value={p.compatibility_id}>{p.compatibility_id} (no catalog in this build)</option>}
        </select>
      </label>
      <label className="check">
        <input type="checkbox" checked={p.require_verified_tls !== false} onChange={(e) => onChange({ ...p, require_verified_tls: e.target.checked })} />
        Trust markers only over a verified TLS connection
      </label>
      {p.require_verified_tls === false && <div className="warn-box">Plain-HTTP trust is meant for local labs. Any host on the path could forge markers; findings are capped at “likely”.</div>}
      <label className="lbl">
        Console link (optional, opened read-only)
        <input className="field mono" value={p.console_url ?? ""} onChange={(e) => onChange({ ...p, console_url: e.target.value || null })} />
      </label>
      <p className="hint">An authorized diagnostic-detail endpoint is not available on current gateway releases; Anvil relies on the public markers and its own observations.</p>
    </div>
  );
}

// ------------------------------------------------------------ export/import

const MODES = [
  { id: "share_safely", label: "Share safely", desc: "No secrets. Sensitive literals become placeholders; recipients fill them in." },
  { id: "encrypted_transfer", label: "Encrypted transfer", desc: "Includes vault secrets, encrypted with a passphrase you give the recipient separately." },
  { id: "full_backup", label: "Full backup", desc: "Everything including history and settings, encrypted. Restores into a clean install without this computer's keychain." },
];

export function ExportDialog(props: { workspace: Workspace | null; onClose: () => void; notify: (m: string) => void }) {
  const [mode, setMode] = useState("share_safely");
  const [scope, setScope] = useState<"workspace" | "all">(props.workspace ? "workspace" : "all");
  const [preview, setPreview] = useState<ExportPreview | null>(null);
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const wsId = scope === "workspace" ? props.workspace?.id ?? null : null;
  const effMode = scope === "all" ? "full_backup" : mode;
  useEffect(() => {
    setPreview(null);
    api
      .exportPreview(wsId, effMode)
      .then(setPreview)
      .catch((e) => setErr(String((e as Error).message)));
  }, [effMode, wsId]);
  const encrypted = effMode !== "share_safely";
  const go = async () => {
    setErr(null);
    if (encrypted && (pass.length < 8 || pass !== pass2)) return setErr("Enter the same passphrase twice (at least 8 characters).");
    const stamp = new Date().toISOString().slice(0, 10);
    setBusy(true);
    try {
      const file = await api.chooseFile("bundle_export", {
        file_name: `${scope === "all" ? "anvil-backup" : props.workspace!.name.replace(/[^\w.-]+/g, "_")}-${stamp}.anvil`,
        filters: [{ name: "Anvil bundle", extensions: ["anvil"] }],
      });
      if (!file) return;
      const n = await api.exportToPath(wsId, effMode, encrypted ? pass : null, file.token);
      props.notify(`Exported ${(n / 1024).toFixed(1)} KB to ${file.file_name}`);
      props.onClose();
    } catch (e) {
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Export"
      onClose={props.onClose}
      footer={
        <button className="btn primary" disabled={busy || !preview} onClick={go}>
          {busy ? "Exporting…" : "Choose file and export"}
        </button>
      }
    >
      <div className="row">
        <label className="check">
          <input type="radio" name="scope" disabled={!props.workspace} checked={scope === "workspace"} onChange={() => setScope("workspace")} />
          This workspace{props.workspace ? ` (${props.workspace.name})` : ""}
        </label>
        <label className="check">
          <input type="radio" name="scope" checked={scope === "all"} onChange={() => setScope("all")} />
          Whole app backup
        </label>
      </div>
      {scope === "workspace" && (
        <div className="col">
          {MODES.filter((m) => m.id !== "full_backup").map((m) => (
            <label key={m.id} className="check" style={{ alignItems: "flex-start" }}>
              <input type="radio" name="mode" checked={mode === m.id} onChange={() => setMode(m.id)} />
              <span>
                <b>{m.label}</b> <span className="faint">— {m.desc}</span>
              </span>
            </label>
          ))}
        </div>
      )}
      {scope === "all" && <p className="hint">{MODES[2].desc}</p>}
      {preview && (
        <div className="col">
          <table className="grid">
            <tbody>
              {Object.entries(preview.manifest.counts).map(([k, v]) => (
                <tr key={k}>
                  <td className="k">{humanize(k)}</td>
                  <td className="v">{v}</td>
                </tr>
              ))}
              <tr>
                <td className="k">Vault secrets included</td>
                <td className="v">{preview.secrets_included}</td>
              </tr>
              <tr>
                <td className="k">Sensitive literals replaced by placeholders</td>
                <td className="v">{preview.literals_moved}</td>
              </tr>
            </tbody>
          </table>
          {preview.manifest.excluded.length > 0 && <div className="hint">Excluded: {preview.manifest.excluded.join(", ")}</div>}
          {preview.manifest.device_bindings.length > 0 && <div className="warn-box">Needs rebinding on the other machine: {preview.manifest.device_bindings.join(", ")}</div>}
          {preview.manifest.content_warnings.length > 0 && (
            <details>
              <summary className="muted">{preview.manifest.content_warnings.length} content warning(s)</summary>
              <ul>
                {preview.manifest.content_warnings.map((w, i) => (
                  <li key={i} className="mono">
                    {w.pointer}: {w.reason}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
      {encrypted && (
        <div className="row">
          <label className="lbl grow">
            Bundle passphrase
            <input className="field" type="password" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="new-password" />
          </label>
          <label className="lbl grow">
            Repeat
            <input className="field" type="password" value={pass2} onChange={(e) => setPass2(e.target.value)} autoComplete="new-password" />
          </label>
        </div>
      )}
      {err && <div className="bad-box">{err}</div>}
    </Modal>
  );
}

export function ImportDialog(props: {
  onClose: () => void;
  onImported: (workspaces: string[]) => void;
  workspaceId: string | null;
  workspaceName: string | null;
  onSpecImported: (r: SpecImported) => void;
}) {
  const [tab, setTab] = useState<"spec" | "bundle">("spec");
  const [file, setFile] = useState<FileGrant | null>(null);
  const [pass, setPass] = useState("");
  const [policy, setPolicy] = useState("duplicate");
  const [preview, setPreview] = useState<ImportReport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const choose = async () => {
    setErr(null);
    try {
      const f = await api.chooseFile("bundle_import", { filters: [{ name: "Anvil bundle", extensions: ["anvil", "zip"] }] });
      if (f) {
        setFile(f);
        setPreview(null);
      }
    } catch (e) {
      setErr(String((e as Error).message));
    }
  };
  const doPreview = async () => {
    if (!file) return;
    setErr(null);
    setBusy(true);
    try {
      setPreview(await api.importPreview(file.token, pass || null, policy));
    } catch (e) {
      setPreview(null);
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };
  const apply = async () => {
    if (!file) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await api.importApply(file.token, pass || null, policy);
      props.onImported(r.workspace_ids);
      props.onClose();
    } catch (e) {
      setErr(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Import"
      wide
      onClose={props.onClose}
      footer={
        tab === "bundle" ? (
          <>
            <button className="btn" disabled={!file || busy} onClick={doPreview}>
              Preview
            </button>
            <button className="btn primary" disabled={!preview || busy} onClick={apply}>
              Import
            </button>
          </>
        ) : undefined
      }
    >
      <Tabs
        tabs={[
          { id: "spec" as const, label: "API spec or collection" },
          { id: "bundle" as const, label: "Anvil bundle / backup" },
        ]}
        value={tab}
        onChange={setTab}
      />
      {tab === "spec" && <SpecImport workspaceId={props.workspaceId} workspaceName={props.workspaceName} onImported={props.onSpecImported} />}
      {tab === "bundle" && bundleBody()}
    </Modal>
  );
  function bundleBody() {
    return (
      <>
      <div className="row">
        <button className="btn" data-autofocus onClick={choose}>
          Choose bundle…
        </button>
        <span className="mono faint grow" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>
          {file?.file_name ?? "No file selected"}
        </span>
      </div>
      <label className="lbl">
        Passphrase (for encrypted bundles)
        <input className="field" type="password" value={pass} onChange={(e) => setPass(e.target.value)} />
      </label>
      <label className="lbl">
        If objects already exist
        <select className="field" value={policy} onChange={(e) => setPolicy(e.target.value)}>
          <option value="duplicate">Import as copies (new ids)</option>
          <option value="merge">Merge (keep existing, add new)</option>
          <option value="replace">Replace existing</option>
        </select>
      </label>
      <p className="hint">Nothing is changed until you press Import. Imports never run requests, scripts or load plans, and never enable a TLS bypass. Objects are written in one transaction; a checkpoint copy is kept on disk.</p>
      {preview && (
        <div className="col">
          <table className="grid">
            <tbody>
              <tr><td className="k">To create</td><td className="v">{preview.plan.to_create}</td></tr>
              <tr><td className="k">To replace</td><td className="v">{preview.plan.to_replace}</td></tr>
              <tr><td className="k">Skipped (already present)</td><td className="v">{preview.plan.skipped_existing}</td></tr>
              <tr><td className="k">Secrets</td><td className="v">{preview.secrets_restored ? "restored from the encrypted bundle" : "not included"}</td></tr>
            </tbody>
          </table>
          {preview.missing_secrets.length > 0 && <div className="warn-box">You'll need to fill in {preview.missing_secrets.length} placeholder(s): {preview.missing_secrets.slice(0, 8).join(", ")}</div>}
          {preview.plan.foreign_secrets.length > 0 && preview.plan.policy === "replace" && (
            <div className="bad-box">Replace can't overwrite secrets that belong to a workspace outside this bundle: {preview.plan.foreign_secrets.slice(0, 8).join(", ")}. Import as copies instead.</div>
          )}
          {preview.plan.foreign_secrets.length > 0 && preview.plan.policy === "merge" && (
            <div className="warn-box">These secrets already exist here in another workspace and are kept; the imported items that use them won't resolve them: {preview.plan.foreign_secrets.slice(0, 8).join(", ")}</div>
          )}
          {preview.warnings.map((w, i) => (
            <div key={i} className="warn-box">
              {w}
            </div>
          ))}
        </div>
      )}
      {err && <div className="bad-box">{err}</div>}
      </>
    );
  }
}

// ---------------------------------------------------------------- settings

export function SettingsDialog(props: { onClose: () => void; onSaved: (s: AppSettings) => void }) {
  const [s, setS] = useState<AppSettings | null>(null);
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    api.settings().then(setS);
    api.systemInfo().then(setInfo);
  }, []);
  if (!s) return null;
  return (
    <Modal
      title="Settings"
      onClose={props.onClose}
      footer={
        <button
          className="btn primary"
          onClick={async () => {
            try {
              await api.saveSettings(s);
              props.onSaved(s);
              props.onClose();
            } catch (e) {
              setErr(String((e as Error).message));
            }
          }}
        >
          Save
        </button>
      }
    >
      <div className="row">
        <label className="lbl">
          Theme
          <select className="field" value={s.theme} onChange={(e) => setS({ ...s, theme: e.target.value as AppSettings["theme"] })}>
            <option value="system">System</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
          </select>
        </label>
        <label className="lbl">
          Lock after inactivity (minutes, 0 = never)
          <input className="field mono" style={{ width: 120 }} value={s.lock.idle_minutes} onChange={(e) => setS({ ...s, lock: { ...s.lock, idle_minutes: Number(e.target.value) || 0 } })} />
        </label>
      </div>
      <label className="check">
        <input type="checkbox" checked={s.lock.lock_on_os_lock} onChange={(e) => setS({ ...s, lock: { ...s.lock, lock_on_os_lock: e.target.checked } })} />
        Lock when the computer sleeps
      </label>
      <label className="check">
        <input type="checkbox" checked={s.history.enabled} onChange={(e) => setS({ ...s, history: { ...s.history, enabled: e.target.checked } })} />
        Keep request history
      </label>
      <label className="check">
        <input type="checkbox" checked={s.history.keep_response_bodies} onChange={(e) => setS({ ...s, history: { ...s.history, keep_response_bodies: e.target.checked } })} />
        Keep response bodies in history (encrypted)
      </label>
      <div className="row">
        <label className="lbl">
          History retention (days)
          <input className="field mono" style={{ width: 120 }} value={s.history.max_age_days} onChange={(e) => setS({ ...s, history: { ...s.history, max_age_days: Number(e.target.value) || 0 } })} />
        </label>
        <label className="lbl">
          History size cap (MB)
          <input
            className="field mono"
            style={{ width: 120 }}
            value={Math.round(s.history.max_total_bytes / 1024 / 1024)}
            onChange={(e) => setS({ ...s, history: { ...s.history, max_total_bytes: (Number(e.target.value) || 0) * 1024 * 1024 } })}
          />
        </label>
      </div>
      <label className="lbl">
        Extra names to always redact (comma-separated headers, params, fields)
        <input className="field mono" value={s.redaction_names.join(", ")} onChange={(e) => setS({ ...s, redaction_names: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })} />
      </label>
      <ChangePassphrase />
      <Providers />
      <button
        className="btn danger small"
        style={{ alignSelf: "start" }}
        onClick={async () => {
          await api.historyClear(null);
          setErr("History cleared.");
        }}
      >
        Clear all history
      </button>
      {info && (
        <table className="grid">
          <tbody>
            <tr><td className="k">Version</td><td className="v">{info.version}</td></tr>
            <tr><td className="k">Engine</td><td className="v">{info.engine}</td></tr>
            <tr><td className="k">Diagnostic catalog</td><td className="v">{info.catalog}</td></tr>
            <tr><td className="k">System trust anchors</td><td className="v">{info.system_roots}</td></tr>
            <tr><td className="k">Platform</td><td className="v">{info.platform}</td></tr>
            <tr><td className="k">Data directory</td><td className="v">{info.data_dir}</td></tr>
          </tbody>
        </table>
      )}
      {err && <div className="hint">{err}</div>}
    </Modal>
  );
}

function ChangePassphrase() {
  const [open, setOpen] = useState(false);
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  if (!open)
    return (
      <button className="btn small" style={{ alignSelf: "start" }} onClick={() => setOpen(true)}>
        Change unlock passphrase…
      </button>
    );
  return (
    <fieldset className="box">
      <legend>Change unlock passphrase</legend>
      <div className="row">
        <input className="field grow" type="password" aria-label="New passphrase" placeholder="new passphrase" value={a} onChange={(e) => setA(e.target.value)} autoComplete="new-password" />
        <input className="field grow" type="password" aria-label="Repeat passphrase" placeholder="repeat" value={b} onChange={(e) => setB(e.target.value)} autoComplete="new-password" />
        <button
          className="btn small"
          onClick={async () => {
            if (a.length < 8 || a !== b) return setMsg("Enter the same passphrase twice (at least 8 characters).");
            try {
              await api.changePassphrase(a);
              setA("");
              setB("");
              setMsg("Passphrase changed. The recovery key still works.");
            } catch (e) {
              setMsg(String((e as Error).message));
            }
          }}
        >
          Save
        </button>
      </div>
      {msg && <div className="hint">{msg}</div>}
    </fieldset>
  );
}

function Providers() {
  const [list, setList] = useState<ProviderInfo[] | null>(null);
  useEffect(() => {
    api.loginProviders().then(setList).catch(() => setList([]));
  }, []);
  if (!list) return null;
  return (
    <details>
      <summary className="muted">Sign-in providers (optional, identity only)</summary>
      <p className="hint">
        A linked provider identity can be required before unlocking, but it never encrypts or unlocks your data by itself — the passphrase, recovery key or OS keychain does.
      </p>
      <table className="grid">
        <tbody>
          {list.map((p) => (
            <tr key={p.id}>
              <td>{p.display_name}</td>
              <td>
                {p.availability.status === "available" ? (
                  <span className="badge ok">available{p.test_only ? " (test build)" : ""}</span>
                ) : (
                  <span className="badge warn" title={p.availability.reason}>
                    unavailable
                  </span>
                )}
              </td>
              <td className="faint" style={{ fontSize: 11 }}>
                {p.availability.status === "unavailable" ? p.owner_actions.join("; ") : p.native_flow}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}
