// Typed client for the Sentinel API. Tokens live in sessionStorage (tab-scoped), never localStorage.

export type Bucket = "demurrage" | "soon" | "later" | "unknown";
export interface FreeTime { expires_at: string | null; days_left: number | null; bucket: Bucket }
export interface Category { key: string; label: string; score: number | null; hint: string }
export interface Card {
  shipment_id: string; reference: string; state: string; title: string; description: string;
  free_time: FreeTime; owner: string; progress: number; progress_label: string;
}
export interface Dashboard {
  generated_at: string; overall_score: number | null; categories: Category[];
  attention: { buckets: Record<"demurrage" | "soon" | "later", number>; cards: Card[] };
  calendar: { date: string; shipment_id: string; reference: string; kind: string }[];
  states: Record<string, number>; holds: number; active_shipments: number;
}
export interface Summary {
  shipment_id: string; reference: string; state: string; open_issues: number; critical_issues: number;
  documents: Record<string, number>; free_time: FreeTime; awaiting_approval: boolean; updated_seq: number;
}
export interface Evidence { doc_type: string; content_sha256: string; field_path: string; value: string | null }
export interface IssueView {
  id: string; kind: string; severity: string; rule_id: string; message: string; evidence?: Evidence[];
  status: "open" | "waived"; waiver: string | null;
}
export interface TraceNode {
  rule_id: string; check: string; outcome: "pass" | "fail" | "skip"; inputs: Record<string, string>;
  detail: string; issue_id: string | null; children: TraceNode[];
}
export interface Proposal {
  proposal_id: string; draft_sha256: string; recipients: string[]; issue_ids: string[]; proposed_by: string;
  draft_parsed: { to: string[]; subject: string; body: string; generated_by: string };
}
export interface DocVersions {
  doc_type: string;
  versions: { version: number; content_sha256: string; source_channel: string; extracted: boolean; current: boolean }[];
}
export interface Detail extends Omit<Summary, "documents"> {
  docset_hash: string; blocking_reasons: string[]; issues: IssueView[];
  documents: DocVersions[];
  proposal: Proposal | null;
  screening: { result: string; matches: Record<string, string>[]; list_versions: Record<string, string> } | null;
  decision_tree: TraceNode[] | null; ruleset_version: string | null;
  history: { sequence: number; at: string; event: string; actor: Record<string, string>; entry_hash: string }[];
  actions: string[];
}
export interface FieldView {
  value: unknown; confidence: string; extractor: string; raw_text: string | null;
  source: { page: number } | null; needs_review: boolean;
}
export interface DiffSide {
  doc_type: string; content_sha256: string; field_path: string; highlight: string; value: string | null;
  fields: { path: string; data: unknown }[]; context: { path: string; data: unknown }[];
}
export interface Diff { issue: IssueView; sides: DiffSide[] }
export interface Cosign {
  id: string; kind: string; shipment_id: string; requested_by: string; params: Record<string, unknown>;
  created_at: string; expires_at: string;
}
export interface AuditEntry {
  sequence: number; at: string; aggregate_type: string; aggregate_id: string; event: string;
  actor: Record<string, string>; entry_hash: string; prev_hash: string; key_id: string;
}
export interface Me { id: string; tenant_id: string; roles: string[]; permissions: string[] }

const TOKEN_KEY = "sentinel.token";
export const session = {
  get: () => sessionStorage.getItem(TOKEN_KEY),
  set: (t: string) => sessionStorage.setItem(TOKEN_KEY, t),
  clear: () => sessionStorage.removeItem(TOKEN_KEY),
};

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function request<T>(method: string, path: string, body?: unknown, raw = false): Promise<T> {
  const headers: Record<string, string> = {};
  const token = session.get();
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload: BodyInit | undefined;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  const res = await fetch(path, { method, headers, body: payload });
  if (res.status === 401) { session.clear(); window.dispatchEvent(new Event("sentinel:logout")); }
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const j = await res.json();
      msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail);
    } catch { /* not json */ }
    throw new ApiError(res.status, msg);
  }
  return (raw ? res.blob() : res.json()) as Promise<T>;
}

const sid = (id: string) => encodeURIComponent(id);
export const api = {
  config: () => request<{ auth: "dev" | "oidc"; issuer?: string; client_id?: string; audience?: string }>("GET", "/api/v1/config"),
  devUsers: () => request<{ id: string; name: string; roles: string[] }[]>("GET", "/api/v1/dev/users"),
  devToken: (user: string) => request<{ token: string; name: string }>("POST", "/api/v1/dev/token", { user }),
  me: () => request<Me>("GET", "/api/v1/me"),
  dashboard: () => request<Dashboard>("GET", "/api/v1/dashboard"),
  shipments: () => request<Summary[]>("GET", "/api/v1/shipments"),
  openShipment: (b: { shipment_id: string; reference: string; free_time_expires_at?: string }) =>
    request<Summary>("POST", "/api/v1/shipments", b),
  shipment: (id: string) => request<Detail>("GET", `/api/v1/shipments/${sid(id)}`),
  diff: (id: string, issue: string) => request<Diff>("GET", `/api/v1/shipments/${sid(id)}/issues/${sid(issue)}/diff`),
  document: (id: string, sha: string) => request<Blob>("GET", `/api/v1/shipments/${sid(id)}/documents/${sha}`, undefined, true),
  upload: (id: string, file: File, docType?: string) => {
    const fd = new FormData();
    fd.append("file", file);
    if (docType) fd.append("doc_type", docType);
    return request<{ outcome: string; reason: string | null; doc_type: string | null }>("POST", `/api/v1/shipments/${sid(id)}/documents`, fd);
  },
  approve: (id: string, pid: string, draft_sha256: string) =>
    request<Summary>("POST", `/api/v1/shipments/${sid(id)}/proposals/${pid}/approve`, { draft_sha256 }),
  reject: (id: string, pid: string, reason: string) =>
    request<Summary>("POST", `/api/v1/shipments/${sid(id)}/proposals/${pid}/reject`, { reason }),
  waive: (id: string, issue_ids: string[], justification: string) =>
    request<{ status: string }>("POST", `/api/v1/shipments/${sid(id)}/waivers`, { issue_ids, justification }),
  releaseHold: (id: string, justification: string) =>
    request<{ status: string }>("POST", `/api/v1/shipments/${sid(id)}/hold-release`, { justification }),
  file: (id: string, customs_system: string, reviewed_docset_hash: string) =>
    request<{ filing_payload_sha256: string }>("POST", `/api/v1/shipments/${sid(id)}/filing`, { customs_system, reviewed_docset_hash }),
  cancel: (id: string, reason: string) => request<Summary>("POST", `/api/v1/shipments/${sid(id)}/cancel`, { reason }),
  cosigns: () => request<Cosign[]>("GET", "/api/v1/cosign"),
  cosign: (rid: string) => request<Summary>("POST", `/api/v1/cosign/${rid}/approve`),
  audit: (limit = 200) => request<AuditEntry[]>("GET", `/api/v1/audit?limit=${limit}`),
  verify: () => request<{ ok: boolean; entries_checked: number; failed_sequence: number | null; reason: string | null; head: string }>("GET", "/api/v1/ledger/verify"),
};
