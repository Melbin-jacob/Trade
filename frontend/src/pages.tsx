import { useCallback, useEffect, useState } from "react";
import { api, ApiError, type AuditEntry, type Cosign, type Detail, type Diff, type Me, type Summary } from "./api";
import { Calendar, CategoryBars, DecisionTree, DiffViewer, Gauge, SeverityBadge, StateBadge, TaskCard } from "./components";

export type Go = (route: string) => void;

function useLoad<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const reload = useCallback(() => {
    fn().then((d) => { setData(d); setError(null); }).catch((e: Error) => setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => { reload(); }, [reload]);
  return { data, error, reload };
}

const Err = ({ msg }: { msg: string | null }) => (msg ? <div className="notice error">{msg}</div> : null);
const fmtDate = (s: string | null) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—");

/* ================================================================ Compliance Hub */
export function Hub({ go, filter }: { go: Go; filter: string }) {
  const { data, error } = useLoad(api.dashboard, []);
  const { data: audit } = useLoad(() => api.audit(12), []);
  if (error) return <Err msg={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const f = filter.toLowerCase();
  const cards = data.attention.cards.filter((c) => !f || `${c.shipment_id} ${c.reference} ${c.title}`.toLowerCase().includes(f));
  const bucketOf = new Map(data.attention.cards.map((c) => [c.shipment_id, c.free_time.bucket]));
  return (
    <>
      <h2 style={{ marginTop: 0 }}>Compliance Health Summary</h2>
      <div className="grid-3">
        <div className="card">
          <div className="card-title">Overall Compliance Score <span className="info-dot" title="Average of the category scores for all active shipments">i</span></div>
          <Gauge score={data.overall_score} />
        </div>
        <div className="card">
          <div className="card-title">Category Highlights <span className="info-dot" title="Hover a bar for its definition">i</span></div>
          <CategoryBars categories={data.categories} />
        </div>
        <div className="card">
          <Calendar events={data.calendar.map((e) => ({ ...e, bucket: bucketOf.get(e.shipment_id) ?? "later" }))}
                    onPick={(id) => go(`/shipments/${id}`)} />
        </div>
      </div>

      <h2>Tasks Requiring Immediate Attention</h2>
      <div className="legend">
        <span style={{ ["--c" as string]: "var(--red)" }}>{data.attention.buckets.demurrage} accruing demurrage</span>
        <span style={{ ["--c" as string]: "var(--amber)" }}>{data.attention.buckets.soon} free time ends within 3 days</span>
        <span style={{ ["--c" as string]: "var(--green)" }}>{data.attention.buckets.later} free time ends in more than 3 days</span>
      </div>
      {cards.length === 0 ? <div className="card empty">Nothing needs attention. 🎉</div> : (
        <div className="grid-3">
          {cards.map((c) => <TaskCard key={c.shipment_id} card={c} onOpen={() => go(`/shipments/${c.shipment_id}`)} />)}
        </div>
      )}

      <div className="grid-2" style={{ marginTop: 8 }}>
        <div>
          <h2>Pipeline Overview</h2>
          <div className="state-tiles">
            <div className="tile"><span className="muted">Active shipments</span><b>{data.active_shipments}</b></div>
            {Object.entries(data.states).map(([s, n]) => (
              <div className="tile" key={s}><StateBadge state={s} /><b style={{ marginTop: 8 }}>{n}</b></div>
            ))}
          </div>
        </div>
        <div>
          <h2>Recent Ledger Activity</h2>
          <div className="card" style={{ padding: 8 }}>
            <table>
              <tbody>
                {(audit ?? []).map((e) => (
                  <tr key={e.sequence}>
                    <td className="mono faint">#{e.sequence}</td>
                    <td>{e.event}<div className="faint" style={{ fontSize: 12 }}>{e.aggregate_id}</div></td>
                    <td className="muted" style={{ fontSize: 12 }}>{e.actor.id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}

/* ================================================================ Shipments */
export function Shipments({ go, filter, me }: { go: Go; filter: string; me: Me }) {
  const { data, error, reload } = useLoad(api.shipments, []);
  const [form, setForm] = useState({ shipment_id: "", reference: "", free_time_expires_at: "" });
  const [msg, setMsg] = useState<string | null>(null);
  const canOpen = me.roles.some((r) => r === "reviewer" || r === "compliance_officer");
  const f = filter.toLowerCase();
  const rows = (data ?? []).filter((s) => !f || `${s.shipment_id} ${s.reference} ${s.state}`.toLowerCase().includes(f));
  const submit = async () => {
    try {
      await api.openShipment({ shipment_id: form.shipment_id.trim(), reference: form.reference.trim(),
        ...(form.free_time_expires_at ? { free_time_expires_at: new Date(form.free_time_expires_at).toISOString() } : {}) });
      setMsg(null); setForm({ shipment_id: "", reference: "", free_time_expires_at: "" }); reload();
    } catch (e) { setMsg((e as Error).message); }
  };
  return (
    <>
      <Err msg={error ?? msg} />
      {canOpen && (
        <div className="card" style={{ marginBottom: 22 }}>
          <h3>Open a shipment</h3>
          <div className="row" style={{ alignItems: "flex-end" }}>
            <label className="field" style={{ flex: 1 }}>Shipment ID
              <input type="text" placeholder="SHP-2026-000200" value={form.shipment_id} onChange={(e) => setForm({ ...form, shipment_id: e.target.value })} /></label>
            <label className="field" style={{ flex: 1 }}>PO / reference
              <input type="text" value={form.reference} onChange={(e) => setForm({ ...form, reference: e.target.value })} /></label>
            <label className="field" style={{ flex: 1 }}>Free time expires
              <input type="datetime-local" value={form.free_time_expires_at} onChange={(e) => setForm({ ...form, free_time_expires_at: e.target.value })} /></label>
            <button className="btn" onClick={submit} disabled={!form.shipment_id || !form.reference}>Open</button>
          </div>
        </div>
      )}
      <div className="card" style={{ padding: 8 }}>
        <table>
          <thead><tr><th>Shipment</th><th>Reference</th><th>State</th><th>Open issues</th><th>Documents</th><th>Free time</th></tr></thead>
          <tbody>
            {rows.map((s: Summary) => (
              <tr key={s.shipment_id} className="clickable" onClick={() => go(`/shipments/${s.shipment_id}`)}>
                <td><b>{s.shipment_id}</b></td>
                <td>{s.reference}</td>
                <td><StateBadge state={s.state} /></td>
                <td>{s.open_issues}{s.critical_issues > 0 && <span className="badge red" style={{ marginLeft: 8 }}>{s.critical_issues} critical</span>}</td>
                <td className="muted">{Object.keys(s.documents).length} types</td>
                <td>{s.free_time.days_left === null ? "—" : s.free_time.days_left < 0
                  ? <span className="badge red">demurrage {Math.abs(Math.floor(s.free_time.days_left))}d</span>
                  : `${Math.floor(s.free_time.days_left)} days`}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <div className="empty">No shipments.</div>}
      </div>
    </>
  );
}

/* ================================================================ Shipment detail */
type Tab = "issues" | "tree" | "remediation" | "documents" | "actions" | "history";

export function ShipmentDetail({ id, go }: { id: string; go: Go }) {
  const { data, error, reload } = useLoad(() => api.shipment(id), [id]);
  const [tab, setTab] = useState<Tab>("issues");
  const [selected, setSelected] = useState<string | null>(null);
  const [diff, setDiff] = useState<Diff | null>(null);
  const [doc, setDoc] = useState<{ url: string; title: string } | null>(null);
  const [notice, setNotice] = useState<{ kind: "ok" | "error" | "info"; text: string } | null>(null);

  useEffect(() => {
    if (!data) return;
    const first = data.issues.find((i) => i.status === "open") ?? data.issues[0];
    // Re-validation can retire issues; never request a diff for one that no longer exists.
    if (selected && !data.issues.some((i) => i.id === selected)) setSelected(first?.id ?? null);
    else if (!selected && first) setSelected(first.id);
  }, [data, selected]);
  useEffect(() => {
    if (!selected) { setDiff(null); return; }
    api.diff(id, selected).then(setDiff).catch(() => setDiff(null));
  }, [id, selected, data]);
  useEffect(() => () => { if (doc) URL.revokeObjectURL(doc.url); }, [doc]);

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    try { await fn(); setNotice({ kind: "ok", text: ok }); reload(); }
    catch (e) { setNotice({ kind: "error", text: e instanceof ApiError ? e.message : String(e) }); }
  };
  const openDoc = async (sha: string, title: string) => {
    try { const b = await api.document(id, sha); setDoc({ url: URL.createObjectURL(b), title }); }
    catch (e) { setNotice({ kind: "error", text: (e as Error).message }); }
  };

  if (error) return <Err msg={error} />;
  if (!data) return <div className="empty">Loading…</div>;
  const open = data.issues.filter((i) => i.status === "open");

  return (
    <>
      <div className="row" style={{ marginBottom: 6 }}>
        <button className="btn ghost sm" onClick={() => go("/shipments")}>← Shipments</button>
        <h2 style={{ margin: "0 8px" }}>{data.shipment_id}</h2>
        <StateBadge state={data.state} />
        <span className="muted">Ref. {data.reference}</span>
        <span className="spacer" />
        {data.free_time.expires_at && (
          <span className={`badge ${data.free_time.bucket === "demurrage" ? "red" : data.free_time.bucket === "soon" ? "amber" : "green"}`}>
            Free time {data.free_time.bucket === "demurrage" ? "expired" : "ends"} {fmtDate(data.free_time.expires_at)}
          </span>
        )}
      </div>
      {data.blocking_reasons.length > 0 && (
        <div className="notice info"><b>Not ready for filing:</b> {data.blocking_reasons.join(" · ")}</div>
      )}
      {notice && <div className={`notice ${notice.kind}`}>{notice.text}</div>}

      <div className="tabs" role="tablist">
        {([["issues", `Issues (${open.length})`], ["tree", "Decision tree"], ["remediation", data.proposal ? "Remediation ●" : "Remediation"],
           ["documents", "Documents"], ["actions", "Actions"], ["history", "Audit trail"]] as [Tab, string][]).map(([t, label]) => (
          <button key={t} role="tab" className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)}>{label}</button>
        ))}
      </div>

      {tab === "issues" && (
        data.issues.length === 0 ? <div className="card empty">No issues on the current document set.</div> : (
          <div className="split">
            <div>
              {data.issues.map((i) => (
                <div key={i.id} className={`issue ${selected === i.id ? "selected" : ""} ${i.status}`} onClick={() => setSelected(i.id)}>
                  <div className="row" style={{ marginBottom: 6 }}>
                    <SeverityBadge severity={i.severity} />
                    <span className="badge">{i.kind.replace("_", " ")}</span>
                    {i.status === "waived" && <span className="badge green">waived</span>}
                  </div>
                  <div>{i.message}</div>
                  <div className="mono faint" style={{ marginTop: 4 }}>{i.rule_id}</div>
                </div>
              ))}
            </div>
            <div className="card">
              <h3>Why this was flagged</h3>
              {diff ? (
                <>
                  <p style={{ marginTop: 0 }}>{diff.issue.message}</p>
                  <DiffViewer sides={diff.sides} onOpenDoc={(sha, t) => openDoc(sha, t)} />
                </>
              ) : <div className="empty">Select an issue.</div>}
            </div>
          </div>
        )
      )}

      {tab === "tree" && (
        <div className="card">
          <div className="row" style={{ marginBottom: 12 }}>
            <h3 style={{ margin: 0 }}>Rule evaluation</h3><span className="mono faint">{data.ruleset_version}</span>
          </div>
          {data.decision_tree ? <DecisionTree nodes={data.decision_tree} focus={selected} />
            : <div className="empty">The current document set has not been validated yet.</div>}
          {data.screening && (
            <>
              <h3 style={{ marginTop: 22 }}>Sanctions & embargo screening — <span style={{ color: data.screening.result === "hit" ? "var(--red)" : "var(--green)" }}>{data.screening.result}</span></h3>
              {data.screening.matches.length > 0 && (
                <table>
                  <thead><tr><th>Party</th><th>Role</th><th>Listed as</th><th>List</th><th>Score</th></tr></thead>
                  <tbody>{data.screening.matches.map((m, k) => (
                    <tr key={k}><td>{m.party}</td><td>{m.role}</td><td>{m.listed_name}</td><td>{m.list} {m.uid}</td><td>{m.score}</td></tr>
                  ))}</tbody>
                </table>
              )}
              <div className="faint" style={{ fontSize: 12, marginTop: 6 }}>Lists: {Object.values(data.screening.list_versions ?? {}).join(", ")}</div>
            </>
          )}
        </div>
      )}

      {tab === "remediation" && <Remediation data={data} act={act} />}

      {tab === "documents" && (
        <div className="grid-2">
          <div className="card">
            <h3>Document versions</h3>
            <table>
              <thead><tr><th>Document</th><th>Version</th><th>Channel</th><th>Hash</th><th /></tr></thead>
              <tbody>
                {data.documents.flatMap((d) => d.versions.map((v) => (
                  <tr key={v.content_sha256}>
                    <td>{d.doc_type.replace(/_/g, " ")}{v.current && <span className="badge green" style={{ marginLeft: 6 }}>current</span>}</td>
                    <td>v{v.version}{!v.extracted && <span className="badge amber" style={{ marginLeft: 6 }}>extracting</span>}</td>
                    <td className="muted">{v.source_channel}</td>
                    <td className="mono faint" title={v.content_sha256}>{v.content_sha256.slice(0, 12)}…</td>
                    <td><button className="btn ghost sm" onClick={() => openDoc(v.content_sha256, `${d.doc_type} v${v.version}`)}>View</button></td>
                  </tr>
                )))}
              </tbody>
            </table>
          </div>
          <Upload id={id} act={act} />
        </div>
      )}

      {tab === "actions" && <Actions data={data} act={act} />}

      {tab === "history" && (
        <div className="card" style={{ padding: 8 }}>
          <table>
            <thead><tr><th>#</th><th>When</th><th>Event</th><th>Actor</th><th>Entry hash</th></tr></thead>
            <tbody>{[...data.history].reverse().map((h) => (
              <tr key={h.sequence}>
                <td className="mono">{h.sequence}</td><td className="muted">{fmtDate(h.at)}</td><td>{h.event}</td>
                <td>{h.actor.id} <span className="faint">({h.actor.kind}{h.actor.second_approver ? ` + ${h.actor.second_approver}` : ""})</span></td>
                <td className="mono faint" title={h.entry_hash}>{h.entry_hash.slice(0, 16)}…</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}

      {doc && (
        <div className="card" style={{ marginTop: 22 }}>
          <div className="row" style={{ marginBottom: 10 }}>
            <h3 style={{ margin: 0 }}>{doc.title.replace(/_/g, " ")}</h3><span className="spacer" />
            <button className="btn ghost sm" onClick={() => setDoc(null)}>Close</button>
          </div>
          <iframe className="doc" src={doc.url} title={doc.title} sandbox="allow-same-origin" />
        </div>
      )}
    </>
  );
}

function Remediation({ data, act }: { data: Detail; act: (fn: () => Promise<unknown>, ok: string) => Promise<void> }) {
  const [reason, setReason] = useState("");
  const p = data.proposal;
  if (!p) return <div className="card empty">No remediation draft is waiting for review.</div>;
  const can = data.actions.includes("approve_remediation");
  return (
    <div className="grid-2">
      <div className="card">
        <div className="row" style={{ marginBottom: 12 }}>
          <h3 style={{ margin: 0 }}>Draft correction request</h3>
          <span className="badge blue">{p.draft_parsed.generated_by === "llm" ? "AI drafted" : "Template"}</span>
        </div>
        <div className="muted" style={{ marginBottom: 6 }}>To: <b style={{ color: "var(--text)" }}>{p.draft_parsed.to.join(", ")}</b> <span className="faint">(from your counterparty directory)</span></div>
        <div className="muted" style={{ marginBottom: 12 }}>Subject: <b style={{ color: "var(--text)" }}>{p.draft_parsed.subject}</b></div>
        <div className="email">{p.draft_parsed.body}</div>
        <div className="mono faint" style={{ marginTop: 8 }}>content hash {p.draft_sha256}</div>
      </div>
      <div className="card">
        <h3>Decision</h3>
        <p className="muted" style={{ marginTop: 0 }}>Approving sends exactly the text on the left. The approval records this content hash, and the dispatcher refuses to send anything that does not match it.</p>
        <p className="muted">Addresses {p.issue_ids.length} issue(s): <span className="mono">{p.issue_ids.join(", ")}</span></p>
        <button className="btn" disabled={!can} onClick={() => act(() => api.approve(data.shipment_id, p.proposal_id, p.draft_sha256), "Approved — the email is queued for dispatch.")}>
          Approve & send
        </button>
        <div style={{ marginTop: 22 }}>
          <label className="field">Reject with reason (min. 20 characters)
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Supplier already confirmed by phone; waiting for revised B/L instead." />
          </label>
          <button className="btn ghost" style={{ marginTop: 8 }} disabled={!can || reason.trim().length < 20}
                  onClick={() => act(() => api.reject(data.shipment_id, p.proposal_id, reason), "Draft rejected.")}>Reject draft</button>
        </div>
        {!can && <p className="faint">Your role cannot approve remediation drafts.</p>}
      </div>
    </div>
  );
}

const DOC_TYPES = ["", "commercial_invoice", "bill_of_lading", "packing_list", "certificate_of_origin", "phytosanitary_certificate"];

function Upload({ id, act }: { id: string; act: (fn: () => Promise<unknown>, ok: string) => Promise<void> }) {
  const [file, setFile] = useState<File | null>(null);
  const [type, setType] = useState("");
  return (
    <div className="card">
      <h3>Upload a document</h3>
      <p className="muted" style={{ marginTop: 0 }}>Files are type-checked, malware-scanned, encrypted and versioned. A new version restarts extraction and validation.</p>
      <label className="field">File (PDF, PNG, JPEG, TIFF)
        <input type="file" accept=".pdf,.png,.jpg,.jpeg,.tif,.tiff" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
      <label className="field" style={{ marginTop: 10 }}>Document type
        <select value={type} onChange={(e) => setType(e.target.value)}>
          {DOC_TYPES.map((t) => <option key={t} value={t}>{t ? t.replace(/_/g, " ") : "Detect automatically"}</option>)}
        </select></label>
      <button className="btn" style={{ marginTop: 12 }} disabled={!file}
              onClick={() => file && act(async () => {
                const r = await api.upload(id, file, type || undefined);
                if (r.outcome !== "accepted") throw new Error(`${r.outcome}: ${r.reason ?? ""}`);
              }, "Document accepted — the pipeline is processing it.")}>Upload</button>
    </div>
  );
}

function Actions({ data, act }: { data: Detail; act: (fn: () => Promise<unknown>, ok: string) => Promise<void> }) {
  const open = data.issues.filter((i) => i.status === "open");
  const [picked, setPicked] = useState<string[]>([]);
  const [why, setWhy] = useState("");
  const [holdWhy, setHoldWhy] = useState("");
  const [system, setSystem] = useState("CBSA-CARM");
  const has = (a: string) => data.actions.includes(a);
  return (
    <div className="grid-2">
      <div className="card">
        <h3>Waive or confirm issues</h3>
        {!has("waive_issues") ? <p className="muted">Not available for your role or in this state.</p> : (
          <>
            <p className="muted" style={{ marginTop: 0 }}>Use this to confirm a low-confidence field or accept a discrepancy. Critical issues need a second officer to co-sign.</p>
            {open.map((i) => (
              <label key={i.id} className="row" style={{ marginBottom: 6, alignItems: "flex-start" }}>
                <input type="checkbox" checked={picked.includes(i.id)}
                       onChange={(e) => setPicked(e.target.checked ? [...picked, i.id] : picked.filter((x) => x !== i.id))} />
                <span><SeverityBadge severity={i.severity} /> {i.message}</span>
              </label>
            ))}
            <label className="field" style={{ marginTop: 8 }}>Justification (min. 20 characters)
              <textarea value={why} onChange={(e) => setWhy(e.target.value)} /></label>
            <button className="btn" style={{ marginTop: 8 }} disabled={!picked.length || why.trim().length < 20}
                    onClick={() => act(async () => {
                      const r = await api.waive(data.shipment_id, picked, why);
                      setPicked([]); setWhy("");
                      if (r.status === "cosign_required") throw new Error("Co-sign requested — a second compliance officer must approve it under Approvals.");
                    }, "Issues waived.")}>Submit</button>
          </>
        )}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
        {has("release_hold") && (
          <div className="card">
            <h3>Release compliance hold</h3>
            <p className="muted" style={{ marginTop: 0 }}>Needs two different compliance officers.</p>
            <label className="field">Justification<textarea value={holdWhy} onChange={(e) => setHoldWhy(e.target.value)} /></label>
            <button className="btn danger" style={{ marginTop: 8 }} disabled={holdWhy.trim().length < 20}
                    onClick={() => act(() => api.releaseHold(data.shipment_id, holdWhy), "Release requested — waiting for a second officer to co-sign.")}>Request release</button>
          </div>
        )}
        <div className="card">
          <h3>Customs filing</h3>
          {!has("submit_filing") ? <p className="muted">{data.state === "filed" ? "Declaration filed." : "Available to customs filers once the shipment is ready for filing."}</p> : (
            <>
              <p className="muted" style={{ marginTop: 0 }}>You are approving the declaration for this exact document set:</p>
              <div className="mono" style={{ wordBreak: "break-all", marginBottom: 10 }}>{data.docset_hash}</div>
              <label className="field">Customs system
                <select value={system} onChange={(e) => setSystem(e.target.value)}>
                  <option>CBSA-CARM</option><option>US-ACE</option><option>EU-ICS2</option></select></label>
              <button className="btn" style={{ marginTop: 10 }}
                      onClick={() => act(() => api.file(data.shipment_id, system, data.docset_hash), "Declaration approved and queued for transmission.")}>File declaration</button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/* ================================================================ Approvals */
export function Approvals({ me, go }: { me: Me; go: Go }) {
  const { data, error, reload } = useLoad(api.cosigns, []);
  const [msg, setMsg] = useState<{ kind: string; text: string } | null>(null);
  return (
    <>
      <p className="muted" style={{ marginTop: 0 }}>Four-eyes approvals: these actions take effect only when a different officer co-signs.</p>
      <Err msg={error} />
      {msg && <div className={`notice ${msg.kind}`}>{msg.text}</div>}
      {(data ?? []).length === 0 ? <div className="card empty">No pending co-sign requests.</div> : (
        <div className="grid-2">
          {(data ?? []).map((r: Cosign) => (
            <div className="card" key={r.id}>
              <div className="row"><span className="badge amber">{r.kind === "release_hold" ? "Release hold" : "Waive critical issue"}</span>
                <a href="#" onClick={(e) => { e.preventDefault(); go(`/shipments/${r.shipment_id}`); }}>{r.shipment_id}</a></div>
              <p>Requested by <b>{r.requested_by}</b> · {fmtDate(r.created_at)}</p>
              <div className="email" style={{ fontSize: 13 }}>{String(r.params.justification ?? "")}</div>
              {Array.isArray(r.params.issue_ids) && <p className="mono faint">{(r.params.issue_ids as string[]).join(", ")}</p>}
              <button className="btn" style={{ marginTop: 12 }} disabled={r.requested_by === me.id}
                      onClick={() => api.cosign(r.id).then(() => { setMsg({ kind: "ok", text: "Co-signed and applied." }); reload(); })
                        .catch((e: Error) => setMsg({ kind: "error", text: e.message }))}>
                {r.requested_by === me.id ? "You requested this" : "Co-sign"}
              </button>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

/* ================================================================ Audit ledger */
export function AuditLedger({ me }: { me: Me }) {
  const { data, error } = useLoad(() => api.audit(300), []);
  const [verify, setVerify] = useState<string | null>(null);
  const canVerify = me.roles.some((r) => r === "auditor" || r === "compliance_officer");
  return (
    <>
      <div className="row" style={{ marginBottom: 16 }}>
        <p className="muted" style={{ margin: 0 }}>Append-only, hash-chained and Ed25519-signed. Every state change, document version, LLM call, external API call and dispatch is recorded here.</p>
        <span className="spacer" />
        {canVerify && <button className="btn" onClick={() => api.verify().then((v) =>
          setVerify(v.ok ? `✓ Chain intact — ${v.entries_checked} entries verified (head ${v.head.slice(0, 16)}…)` : `✕ Verification failed at #${v.failed_sequence}: ${v.reason}`))
          .catch((e: Error) => setVerify(e.message))}>Verify chain</button>}
      </div>
      {verify && <div className={`notice ${verify.startsWith("✓") ? "ok" : "error"}`}>{verify}</div>}
      <Err msg={error} />
      <div className="card" style={{ padding: 8 }}>
        <table>
          <thead><tr><th>#</th><th>When</th><th>Type</th><th>Event</th><th>Subject</th><th>Actor</th><th>Hash → prev</th></tr></thead>
          <tbody>{(data ?? []).map((e: AuditEntry) => (
            <tr key={e.sequence}>
              <td className="mono">{e.sequence}</td><td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtDate(e.at)}</td>
              <td><span className="badge">{e.aggregate_type}</span></td><td>{e.event}</td>
              <td className="mono faint" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>{e.aggregate_id}</td>
              <td>{e.actor.id}</td>
              <td className="mono faint">{e.entry_hash.slice(0, 10)}… → {e.prev_hash.slice(0, 10)}…</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </>
  );
}
