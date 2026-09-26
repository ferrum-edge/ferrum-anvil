// Response and diagnosis view. Remote content is rendered as inert text only
// (no HTML rendering, no links, no scripts).
import { useEffect, useMemo, useState } from "react";
import type { ExecutionView } from "./api";
import type { AttemptObservation, DiagnosticFinding, PhaseTiming, ProtocolStatus, SourceScope, StreamTranscript, TlsObservation, TunnelObservation } from "./generated/contracts";
import { Tabs, fmtBytes, fmtUs, humanize } from "./ui";
import { ProxyHeaderEvidence } from "./ProxyProtocolEditor";
import { WorkloadEvidenceView } from "./WorkloadApi";

type Tab = "diagnosis" | "body" | "messages" | "headers" | "timing" | "connection" | "attempts" | "tests";

const SCOPE_LABEL: Record<SourceScope, string> = {
  local_client: "This app (nothing sent)",
  forward_proxy: "Forward proxy",
  client_to_peer: "Your connection → destination",
  gateway_admission: "Gateway policy/admission",
  gateway_to_upstream: "Gateway → backend",
  upstream_application: "Backend application",
  response_delivery: "Response delivery",
  unknown: "Origin not established",
};

const CONF_LABEL = { confirmed: "Confirmed", likely: "Likely", unknown: "Unknown", conflicting_evidence: "Conflicting evidence" } as const;

export function ResponsePanel(props: { view: ExecutionView | null; running: boolean; progressBytes: number | null; onCancel: () => void }) {
  const { view, running } = props;
  const findings = view?.record.findings ?? [];
  const hasProblems = findings.some((f) => f.severity !== "info");
  const [tab, setTab] = useState<Tab>("diagnosis");
  // Each new result opens on its diagnosis (or body/messages when quiet),
  // never on a tab left over from a previous request.
  const recordId = view?.record.id;
  useEffect(() => setTab("diagnosis"), [recordId]);
  const isStream = !!view?.record.stream;
  const quiet = !hasProblems && findings.length === 0 && !!view;
  const effectiveTab: Tab = tab === "diagnosis" && quiet ? (isStream ? "messages" : "body") : tab === "body" && isStream && !view?.record.response ? "messages" : tab;

  if (running) {
    return (
      <div className="resp">
        <div className="progress" />
        <div className="empty">
          <div>
            <div className="big">Sending…</div>
            {props.progressBytes != null && <div className="faint">{fmtBytes(props.progressBytes)} received</div>}
            <button className="btn" style={{ marginTop: 12 }} onClick={props.onCancel}>
              Cancel (Esc)
            </button>
          </div>
        </div>
      </div>
    );
  }
  if (!view) {
    return (
      <div className="empty">
        <div>
          <div className="big">Send the request. See what happened. Know what to check next.</div>
          <div>⌘/Ctrl + Enter sends · ⌘/Ctrl + S saves</div>
        </div>
      </div>
    );
  }
  const r = view.record;
  const resp = r.response;
  const status = resp?.status;
  const last = r.attempts[r.attempts.length - 1];
  const stream = r.stream;
  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: "diagnosis", label: "Diagnosis", count: findings.length },
    ...(stream ? [{ id: "messages" as Tab, label: "Messages", count: stream.messages.length }] : []),
    ...(stream && !resp ? [] : [{ id: "body" as Tab, label: "Body" }]),
    { id: "headers", label: "Headers", count: (resp?.headers.length ?? 0) + (resp?.trailers.length ?? 0) },
    { id: "timing", label: "Timing" },
    { id: "connection", label: "Connection" },
    { id: "attempts", label: "Attempts", count: r.attempts.length > 1 ? r.attempts.length : undefined },
    { id: "tests", label: "Tests", count: r.assertion_results.length || undefined },
  ];
  return (
    <div className="resp">
      <div className="resp-head">
        {status != null ? <span className={`status-code s${String(status)[0]}`}>{status}</span> : !stream && <span className="status-code s5">No response</span>}
        {resp?.reason && <span className="muted">{resp.reason}</span>}
        <ProtocolBadge p={r.outcome.protocol_status} />
        <Dim label="Transport" value={r.outcome.transport} good={r.outcome.transport === "completed"} />
        <Dim label="Application" value={r.outcome.application} good={r.outcome.application === "success"} />
        <Dim label="Tests" value={r.outcome.assertions} good={r.outcome.assertions !== "fail"} />
        <Dim label="Dispatch" value={r.outcome.dispatch} good={r.outcome.dispatch !== "may_have_been_sent"} />
        <span className="spacer" />
        <span className="faint">{fmtUs(last?.duration_us)}</span>
        <span className="faint">{fmtBytes(resp?.body.wire_bytes)}</span>
        {resp?.http_version && <span className="badge">{resp.http_version}</span>}
        {r.outcome.warnings.map((w) => (
          <span key={w.code} className="badge warn" title={w.message}>
            {humanize(w.code)}
          </span>
        ))}
      </div>
      <Tabs tabs={tabs} value={effectiveTab} onChange={setTab} />
      <div className="pane">
        {effectiveTab === "diagnosis" && <Findings view={view} />}
        {effectiveTab === "messages" && stream && <Messages t={stream} />}
        {effectiveTab === "body" && <Body view={view} />}
        {effectiveTab === "headers" && <Headers view={view} />}
        {effectiveTab === "timing" && <Timing attempt={last} />}
        {effectiveTab === "connection" && (
          <>
            <Connection attempt={last} />
            {r.prepared.workload_api && <WorkloadEvidenceView w={r.prepared.workload_api} />}
          </>
        )}
        {effectiveTab === "attempts" && <Attempts attempts={r.attempts} />}
        {effectiveTab === "tests" && <TestsView view={view} />}
      </div>
    </div>
  );
}

function Dim(props: { label: string; value: string; good: boolean }) {
  return (
    <span className="dim">
      {props.label}
      <b style={{ color: props.good ? "var(--ok)" : props.value === "not_run" || props.value === "not_evaluated" ? "var(--text-2)" : "var(--bad)" }}>{humanize(props.value)}</b>
    </span>
  );
}

function Findings({ view }: { view: ExecutionView }) {
  const r = view.record;
  const [copied, setCopied] = useState(false);
  if (r.findings.length === 0) {
    return (
      <div className="ok-box">
        No problems detected. {r.outcome.summary}
      </div>
    );
  }
  const bundle = () => {
    const b = { format: "anvil-support-bundle", version: 1, generated_at: new Date().toISOString(), note: "Redacted by Anvil; review before sharing.", record: r };
    void navigator.clipboard.writeText(JSON.stringify(b, null, 2)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <div>
      <div className="row" style={{ marginBottom: 10 }}>
        <span className="summary-line">{r.outcome.summary}</span>
        <span className="spacer" />
        <button className="btn small" onClick={bundle}>
          {copied ? "Copied" : "Copy redacted support bundle"}
        </button>
      </div>
      {r.findings.map((f, i) => (
        <FindingCard key={`${f.code}-${i}`} f={f} />
      ))}
      <p className="hint">
        Diagnoses come from deterministic rules over what this app observed (catalog {r.catalog_version}). “Unknown” means the evidence cannot distinguish the listed causes — that is a correct answer, not a gap.
      </p>
    </div>
  );
}

export function FindingCard({ f }: { f: DiagnosticFinding }) {
  return (
    <article className={`finding sev-${f.severity}`} aria-label={f.title}>
      <div className="finding-head">
        <div className="grow">
          <div className="finding-title">{f.title}</div>
          <div className="row" style={{ marginTop: 4, flexWrap: "wrap" }}>
            <span className={`badge conf-${f.confidence}`}>{CONF_LABEL[f.confidence]}</span>
            <span className="badge">{SCOPE_LABEL[f.scope]}</span>
            <span className="owner">Owner: {humanize(f.owner)}</span>
            <span className="faint mono" style={{ fontSize: 10 }}>
              {f.code}
            </span>
          </div>
        </div>
      </div>
      <div className="finding-body">
        <div>{f.explanation}</div>
        {f.does_not_prove.length > 0 && (
          <div>
            <h4>This does not prove</h4>
            <ul>{f.does_not_prove.map((d, i) => <li key={i}>{d}</li>)}</ul>
          </div>
        )}
        {f.alternatives.length > 0 && (
          <div>
            <h4>Other possibilities</h4>
            <ul>{f.alternatives.map((d, i) => <li key={i}>{d}</li>)}</ul>
          </div>
        )}
        {f.remediation.length > 0 && (
          <div>
            <h4>What to check next</h4>
            <ul>
              {f.remediation.map((d, i) => (
                <li key={i}>
                  {d.text} <span className="owner">— {humanize(d.owner)}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {f.confirm_with.length > 0 && (
          <div>
            <h4>What would confirm this</h4>
            <ul>{f.confirm_with.map((d, i) => <li key={i}>{d}</li>)}</ul>
          </div>
        )}
        {f.evidence.length > 0 && (
          <details className="evidence">
            <summary>Evidence ({f.evidence.length})</summary>
            <table className="grid" style={{ marginTop: 6 }}>
              <thead>
                <tr><th>Source</th><th>Key</th><th>Observed</th></tr>
              </thead>
              <tbody>
                {f.evidence.map((e, i) => (
                  <tr key={i}>
                    <td className="k">{humanize(e.source)}</td>
                    <td className="k">{e.key}</td>
                    <td className="v">{e.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        )}
      </div>
    </article>
  );
}

function Body({ view }: { view: ExecutionView }) {
  const [mode, setMode] = useState<"pretty" | "raw" | "hex">(view.body.pretty ? "pretty" : view.body.is_binary ? "hex" : "raw");
  const b = view.body;
  const resp = view.record.response;
  if (!resp) return <div className="faint">No response body — the exchange ended before a response.</div>;
  const text = mode === "pretty" ? b.pretty ?? b.text : mode === "hex" ? b.hex : b.text;
  return (
    <div className="col">
      <div className="row" style={{ flexWrap: "wrap" }}>
        <div className="row" role="group" aria-label="Body view">
          {b.pretty && <button className={`btn small ${mode === "pretty" ? "primary" : ""}`} onClick={() => setMode("pretty")}>Pretty</button>}
          {!b.is_binary && <button className={`btn small ${mode === "raw" ? "primary" : ""}`} onClick={() => setMode("raw")}>Raw</button>}
          {b.hex && <button className={`btn small ${mode === "hex" ? "primary" : ""}`} onClick={() => setMode("hex")}>Hex</button>}
        </div>
        <span className="faint">
          {resp.body.content_type ?? "no content-type"}
          {resp.body.content_encoding ? ` · ${resp.body.content_encoding} (decoded ${fmtBytes(resp.body.decoded_bytes)})` : ""} · wire {fmtBytes(resp.body.wire_bytes)}
          {resp.body.declared_length != null ? ` of declared ${fmtBytes(resp.body.declared_length)}` : ""} · {humanize(resp.body.completeness)}
        </span>
      </div>
      {resp.body.display_truncated && (
        <div className="warn-box">
          Showing the first {fmtBytes(resp.body.captured_bytes)} (display/history limit). The response itself {resp.body.completeness === "complete" ? "completed normally" : "did not complete"}.
        </div>
      )}
      {resp.body.completeness === "incomplete" && <div className="bad-box">This body is incomplete: the stream ended before its framing finished. Do not treat it as a full response.</div>}
      <pre className="code" aria-label="Response body">{text ?? ""}</pre>
    </div>
  );
}

function Headers({ view }: { view: ExecutionView }) {
  const resp = view.record.response;
  if (!resp) return <div className="faint">No response headers were received.</div>;
  return (
    <div className="col">
      <table className="grid">
        <tbody>
          {resp.headers.map((h, i) => (
            <tr key={i}>
              <td className="k">{h.name}</td>
              <td className="v">{h.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h4 className="faint">Trailers {resp.trailers_received ? "" : "(none received)"}</h4>
      {resp.trailers.length > 0 && (
        <table className="grid">
          <tbody>
            {resp.trailers.map((h, i) => (
              <tr key={i}>
                <td className="k">{h.name}</td>
                <td className="v">{h.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h4 className="faint">Request as sent (redacted)</h4>
      <table className="grid">
        <tbody>
          {view.record.prepared.headers.map((h, i) => (
            <tr key={i}>
              <td className="k">{h.name}</td>
              <td className="v">{h.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Timing({ attempt }: { attempt?: AttemptObservation }) {
  const total = useMemo(() => Math.max(1, attempt?.duration_us ?? 1, ...(attempt?.phases.map((p) => p.end_us ?? 0) ?? [1])), [attempt]);
  if (!attempt) return null;
  const phases = attempt.phases.filter((p) => p.phase !== "queue" || (p.end_us ?? 0) - (p.start_us ?? 0) > 50);
  return (
    <div className="col">
      <div className="wf" role="table" aria-label="Phase timing">
        {phases.map((p, i) => (
          <PhaseRow key={i} p={p} total={total} />
        ))}
      </div>
      <p className="hint">
        Phases are measured on a monotonic clock. “Reused” and “not applicable” phases have no new measurement — a pooled connection does not repeat DNS/TLS. Concurrent phases may overlap. Time to first byte includes gateway and backend work that the client cannot separate.
      </p>
      <table className="grid">
        <tbody>
          <tr><td className="k">Request headers (logical{attempt.bytes.request_headers_estimated ? ", estimated" : ""})</td><td className="v">{fmtBytes(attempt.bytes.request_headers_logical)}</td></tr>
          <tr><td className="k">Request body</td><td className="v">{fmtBytes(attempt.bytes.request_body)}</td></tr>
          <tr><td className="k">Response headers (logical)</td><td className="v">{fmtBytes(attempt.bytes.response_headers_logical)}</td></tr>
          <tr><td className="k">Response body (wire)</td><td className="v">{fmtBytes(attempt.bytes.response_body_wire)}</td></tr>
          <tr><td className="k">Connection bytes written / read</td><td className="v">{fmtBytes(attempt.bytes.connection_bytes_written)} / {fmtBytes(attempt.bytes.connection_bytes_read)} (connection-scoped, incl. TLS)</td></tr>
        </tbody>
      </table>
    </div>
  );
}

function PhaseRow({ p, total }: { p: PhaseTiming; total: number }) {
  const dur = p.start_us != null && p.end_us != null ? p.end_us - p.start_us : null;
  const left = p.start_us != null ? (p.start_us / total) * 100 : 0;
  const width = dur != null ? Math.max(0.5, (dur / total) * 100) : 0;
  return (
    <>
      <span>{humanize(p.phase)}</span>
      <div className="wf-bar" title={p.detail ?? undefined}>
        {dur != null && <div className={`wf-fill ${p.status}`} style={{ left: `${left}%`, width: `${width}%` }} />}
        {dur == null && <span className="faint" style={{ fontSize: 11, paddingLeft: 4 }}>{humanize(p.status)}{p.detail ? ` — ${p.detail}` : ""}</span>}
      </div>
      <span className="mono" style={{ textAlign: "right" }}>{dur != null ? fmtUs(dur) : ""}</span>
    </>
  );
}

function Connection({ attempt }: { attempt?: AttemptObservation }) {
  const c = attempt?.connection;
  if (!c) return <div className="faint">No connection was established for this attempt.</div>;
  return (
    <div className="col">
      <table className="grid">
        <tbody>
          <tr><td className="k">Connection</td><td className="v">#{c.id} {c.reused ? `reused (served ${c.prior_requests} earlier request(s))` : "new"}</td></tr>
          <tr><td className="k">Protocol</td><td className="v">{c.protocol ?? "—"}</td></tr>
          <tr><td className="k">Remote / local</td><td className="v">{c.remote_address ?? "—"} / {c.local_address ?? "—"}</td></tr>
          <tr><td className="k">Resolved ({c.resolution_source ?? "—"})</td><td className="v">{c.resolved_addresses.join(", ") || "—"}</td></tr>
          {c.via_proxy && <tr><td className="k">Via proxy</td><td className="v">{c.via_proxy}</td></tr>}
          {c.connect_attempts.map((a, i) => (
            <tr key={i}><td className="k">Connect attempt</td><td className="v">{a.address} → {a.failure ? humanize(a.failure) : "connected"} {a.duration_us != null ? `(${fmtUs(a.duration_us)})` : ""}</td></tr>
          ))}
        </tbody>
      </table>
      {c.tunnel && <TunnelView t={c.tunnel} />}
      {c.tls && <TlsView t={c.tls} title={c.tunnel ? "TLS with the destination (inside the tunnel)" : "TLS"} />}
      {c.proxy_header && <ProxyHeaderEvidence h={c.proxy_header} />}
    </div>
  );
}

function TunnelView({ t }: { t: TunnelObservation }) {
  return (
    <div className="col">
      <h4 className="faint" style={{ margin: "6px 0 0" }}>HBONE tunnel (outer leg)</h4>
      <table className="grid">
        <tbody>
          <tr><td className="k">Endpoint</td><td className="v">{t.endpoint}</td></tr>
          <tr><td className="k">Remote / local</td><td className="v">{t.remote_address ?? "—"} / {t.local_address ?? "—"}</td></tr>
          <tr><td className="k">CONNECT :authority</td><td className="v">{t.authority}</td></tr>
          <tr><td className="k">CONNECT status</td><td className="v">{t.connect_status ?? "no answer"}</td></tr>
          {t.connect_headers.map((h, i) => (
            <tr key={i}><td className="k">CONNECT header</td><td className="v">{h.name}: {h.value}</td></tr>
          ))}
          {t.refusal_body != null && <tr><td className="k">Refusal body (untrusted)</td><td className="v mono">{t.refusal_body}{t.refusal_body_truncated ? " …" : ""}</td></tr>}
          {t.failure && <tr><td className="k">Tunnel failure</td><td className="v">{humanize(t.failure.kind)} at {humanize(t.failure.phase)}: {t.failure.message}</td></tr>}
          {t.phases.map((p, i) => (
            <tr key={`p${i}`}><td className="k">{humanize(p.phase)}</td><td className="v">{humanize(p.status)}{p.start_us != null && p.end_us != null ? ` (${fmtUs(p.end_us - p.start_us)})` : ""}{p.detail ? ` — ${p.detail}` : ""}</td></tr>
          ))}
        </tbody>
      </table>
      {t.tls && <TlsView t={t.tls} title="Mutual TLS with the HBONE endpoint" />}
    </div>
  );
}

function identityCheck(t: TlsObservation) {
  const c = t.identity_check;
  if (!c) return "—";
  if (c.method === "host_name") return `host name ${c.name}`;
  if (c.method === "spiffe_id") return `SPIFFE ID ${c.expected}`;
  return `SPIFFE trust domain ${c.trust_domain}`;
}

function TlsView({ t, title = "TLS" }: { t: TlsObservation; title?: string }) {
  const v = t.verification;
  return (
    <div className="col">
      <h4 className="faint" style={{ margin: "6px 0 0" }}>{title}</h4>
      <table className="grid">
        <tbody>
          <tr><td className="k">Server name (SNI)</td><td className="v">{t.sni ?? `none sent (${t.server_name})`}{t.server_name_overridden ? " — from the TLS profile override" : ""}</td></tr>
          <tr><td className="k">Identity checked</td><td className="v">{identityCheck(t)}</td></tr>
          {t.peer_spiffe_id && <tr><td className="k">Peer SPIFFE ID</td><td className="v mono">{t.peer_spiffe_id}</td></tr>}
          <tr><td className="k">Version / cipher</td><td className="v">{t.version ?? "—"} / {t.cipher_suite ?? "—"}</td></tr>
          <tr><td className="k">ALPN offered → negotiated</td><td className="v">{t.alpn_offered.join(", ") || "—"} → {t.alpn_negotiated ?? "none"}</td></tr>
          <tr>
            <td className="k">Verification</td>
            <td className="v">
              {v.result === "verified" && <span className="badge ok">verified</span>}
              {v.result === "failed" && <span className="badge bad">failed: {humanize(v.problem)}</span>}
              {v.result === "bypassed" && <span className="badge warn">bypassed{v.would_have_failed ? ` (would fail: ${humanize(v.would_have_failed)})` : ""}</span>}
              {v.result === "not_reached" && <span className="badge">not reached</span>}
            </td>
          </tr>
          <tr><td className="k">Client certificate requested</td><td className="v">{t.client_certificate_requested == null ? "not observed" : t.client_certificate_requested ? "yes" : "no"}</td></tr>
          <tr><td className="k">Client certificate presented</td><td className="v">{t.client_certificate_presented ? t.client_certificate_presented.subject : "none"}</td></tr>
          {t.alert_received && <tr><td className="k">Alert received</td><td className="v">{t.alert_received}</td></tr>}
          {t.resumed != null && <tr><td className="k">Session resumed</td><td className="v">{t.resumed ? "yes" : "no"}</td></tr>}
        </tbody>
      </table>
      {t.peer_certificates.map((c, i) => (
        <details key={i} open={i === 0}>
          <summary className="muted">{i === 0 ? "Peer certificate" : `Chain certificate ${i}`}: {c.subject}</summary>
          <table className="grid">
            <tbody>
              <tr><td className="k">Issuer</td><td className="v">{c.issuer}</td></tr>
              <tr><td className="k">Valid</td><td className="v">{c.not_before} → {c.not_after}</td></tr>
              <tr><td className="k">SANs</td><td className="v">{c.subject_alt_names.join(", ") || "—"}</td></tr>
              <tr><td className="k">SHA-256</td><td className="v">{c.sha256_fingerprint}</td></tr>
              <tr><td className="k">Key</td><td className="v">{c.key_algorithm}{c.is_ca ? " (CA)" : ""}</td></tr>
            </tbody>
          </table>
        </details>
      ))}
    </div>
  );
}

function Attempts({ attempts }: { attempts: AttemptObservation[] }) {
  return (
    <table className="grid">
      <thead>
        <tr><th>#</th><th>Why</th><th>Request</th><th>Result</th><th>Dispatch</th><th>Time</th></tr>
      </thead>
      <tbody>
        {attempts.map((a) => (
          <tr key={a.index}>
            <td className="k">{a.index}</td>
            <td className="k">{a.reason.reason === "redirect" ? `redirect ${a.reason.status}` : a.reason.reason === "retry" ? `retry after ${humanize(a.reason.after)}` : a.reason.reason === "protocol_fallback" ? `fallback from ${a.reason.from}` : humanize(a.reason.reason)}</td>
            <td className="v">{a.method} {a.url}</td>
            <td className="v">{a.response_status ?? (a.failure ? humanize(a.failure.kind) : "—")}</td>
            <td className="k">{humanize(a.dispatch)}</td>
            <td className="k">{fmtUs(a.duration_us)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TestsView({ view }: { view: ExecutionView }) {
  const res = view.record.assertion_results;
  if (res.length === 0) return <div className="faint">No assertions configured. Add them in the Tests tab of the request.</div>;
  return (
    <table className="grid">
      <tbody>
        {res.map((a, i) => (
          <tr key={i}>
            <td className="k" style={{ color: a.passed ? "var(--ok)" : "var(--bad)" }}>{a.passed ? "✓ pass" : "✗ fail"}</td>
            <td>{a.label}</td>
            <td className="v">{a.message}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ProtocolBadge({ p }: { p?: ProtocolStatus | null }) {
  if (!p) return null;
  switch (p.protocol) {
    case "grpc":
      return (
        <span className={`badge ${p.grpc_status === 0 ? "ok" : "bad"}`} title={`status from ${humanize(p.source)}`}>
          gRPC {p.grpc_status ?? "no status"}
          {p.grpc_message ? ` · ${p.grpc_message}` : ""}
        </span>
      );
    case "websocket":
      return (
        <span className="badge">
          WebSocket{p.close_code != null ? ` closed ${p.close_code}${p.close_reason ? ` (${p.close_reason})` : ""} by ${humanize(p.closed_by)}` : ` · ${humanize(p.closed_by)}`}
        </span>
      );
    case "sse":
      return <span className="badge">SSE · {p.events} events · {humanize(p.closed_by)}</span>;
    case "tcp":
      return (
        <span className="badge">
          TCP · sent {fmtBytes(p.bytes_sent)} · received {fmtBytes(p.bytes_received)}
          {p.half_closed ? " · half-closed" : ""} · {humanize(p.closed_by)}
        </span>
      );
    case "udp": {
      const m = p.masque;
      const via = m
        ? m.connect_status != null && (m.connect_status < 200 || m.connect_status > 299)
          ? ` · MASQUE proxy ${m.proxy} refused (${m.connect_status})`
          : ` · via MASQUE ${m.proxy}${m.encoding ? ` (${m.encoding === "capsule" ? "capsules" : "QUIC datagrams"})` : ""}`
        : "";
      return (
        <span className={`badge${m && m.closed_by === "abnormal" ? " bad" : ""}`} title={m ? `CONNECT-UDP tunnel to ${m.target}; closed by ${humanize(m.closed_by)}` : undefined}>
          UDP · {p.datagrams_sent} sent · {p.datagrams_received} received in {p.window_ms} ms{via}
        </span>
      );
    }
    default:
      return null;
  }
}

function Messages({ t }: { t: StreamTranscript }) {
  return (
    <div className="col">
      <div className="faint">
        {t.sent_count} sent ({fmtBytes(t.sent_bytes)}) · {t.received_count} received ({fmtBytes(t.received_bytes)})
        {t.dropped_messages > 0 ? ` · ${t.dropped_messages} older messages not retained` : ""}
      </div>
      <table className="grid">
        <thead>
          <tr>
            <th>Time</th>
            <th></th>
            <th>Kind</th>
            <th>Size</th>
            <th>Content</th>
          </tr>
        </thead>
        <tbody>
          {t.messages.map((m, i) => (
            <tr key={i}>
              <td className="k">{fmtUs(m.offset_us)}</td>
              <td className="k" style={{ color: m.direction === "sent" ? "var(--info)" : "var(--ok)" }}>
                {m.direction === "sent" ? "→" : "←"}
              </td>
              <td className="k">
                {m.kind}
                {m.event_type ? ` · ${m.event_type}` : ""}
                {m.event_id ? ` #${m.event_id}` : ""}
              </td>
              <td className="k">{fmtBytes(m.size)}</td>
              <td className="v">
                {m.preview}
                {m.preview_truncated ? " …" : ""}
                {m.preview_is_hex ? <span className="faint"> (hex)</span> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
