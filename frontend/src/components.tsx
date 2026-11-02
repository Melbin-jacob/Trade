import { useMemo, useState } from "react";
import type { Card, Category, DiffSide, FieldView, TraceNode } from "./api";

/* ---------------------------------------------------------------- icons */
const P = { fill: "none", stroke: "currentColor", strokeWidth: 1.7, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
export const Icon = {
  hub: <svg width="20" height="20" viewBox="0 0 24 24" {...P}><rect x="3" y="3" width="7" height="7" rx="2" /><rect x="14" y="3" width="7" height="7" rx="2" /><rect x="3" y="14" width="7" height="7" rx="2" /><rect x="14" y="14" width="7" height="7" rx="2" /></svg>,
  ship: <svg width="20" height="20" viewBox="0 0 24 24" {...P}><path d="M3 17l2 4h14l2-4" /><path d="M5 17V9h14v8" /><path d="M9 9V5h6v4" /></svg>,
  alert: <svg width="20" height="20" viewBox="0 0 24 24" {...P}><path d="M12 3l9 16H3z" /><path d="M12 10v4M12 17h.01" /></svg>,
  check: <svg width="20" height="20" viewBox="0 0 24 24" {...P}><rect x="4" y="3" width="16" height="18" rx="3" /><path d="M8.5 12.5l2.5 2.5 4.5-5" /></svg>,
  ledger: <svg width="20" height="20" viewBox="0 0 24 24" {...P}><path d="M6 3h9l3 3v15H6z" /><path d="M9 10h6M9 14h6M9 18h4" /></svg>,
  search: <svg width="18" height="18" viewBox="0 0 24 24" {...P}><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></svg>,
  logout: <svg width="18" height="18" viewBox="0 0 24 24" {...P}><path d="M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10" /></svg>,
};

export function Logo() {
  return (
    <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden>
      <path d="M16 2 29 9v14L16 30 3 23V9z" fill="var(--brand)" />
      <path d="M10 16.5l4 4 8-9" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export const STATE_LABEL: Record<string, string> = {
  awaiting_documents: "Awaiting documents", extracting: "Extracting", validating: "Validating",
  exception_open: "Exception open", remediation_pending_approval: "Draft awaiting approval",
  awaiting_correction: "Awaiting correction", compliance_hold: "Compliance hold", ready_for_filing: "Ready for filing",
  filed: "Filed", closed: "Closed", cancelled: "Cancelled",
};

export function StateBadge({ state }: { state: string }) {
  const tone = state === "compliance_hold" ? "red"
    : ["exception_open", "remediation_pending_approval"].includes(state) ? "amber"
    : ["ready_for_filing", "filed", "closed"].includes(state) ? "green" : "blue";
  return <span className={`badge ${tone}`}>{STATE_LABEL[state] ?? state}</span>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge ${severity === "critical" ? "red" : severity === "warning" ? "amber" : ""}`}>{severity}</span>;
}

/* ---------------------------------------------------------------- gauge */
const polar = (cx: number, cy: number, r: number, deg: number) => {
  const a = (Math.PI / 180) * deg;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
};
function arc(cx: number, cy: number, r: number, from: number, to: number) {
  const [x1, y1] = polar(cx, cy, r, from);
  const [x2, y2] = polar(cx, cy, r, to);
  return `M ${x1} ${y1} A ${r} ${r} 0 ${to - from > 180 ? 1 : 0} 1 ${x2} ${y2}`;
}

export function Gauge({ score }: { score: number | null }) {
  const s = score ?? 0;
  // 240-degree dial from 150deg (bottom-left) to 390deg (bottom-right)
  const start = 150, sweep = 240;
  const needle = start + (sweep * s) / 100;
  const [nx, ny] = polar(150, 135, 80, needle);
  const label = score === null ? "No data" : s >= 85 ? "Excellent" : s >= 70 ? "Good" : s >= 50 ? "At risk" : "Critical";
  const color = s >= 85 ? "var(--green)" : s >= 70 ? "#8a6a00" : "var(--red)";
  return (
    <div className="gauge-wrap">
      <svg width="300" height="230" viewBox="0 0 300 230" role="img" aria-label={`Compliance score ${s}%`}>
        <path d={arc(150, 135, 110, 150, 270)} stroke="var(--red)" strokeWidth="26" fill="none" strokeLinecap="round" />
        <path d={arc(150, 135, 110, 272, 340)} stroke="var(--amber)" strokeWidth="26" fill="none" />
        <path d={arc(150, 135, 110, 342, 390)} stroke="var(--green)" strokeWidth="26" fill="none" strokeLinecap="round" />
        <line x1="150" y1="135" x2={nx} y2={ny} stroke="var(--faint)" strokeWidth="7" strokeLinecap="round" />
        <circle cx="150" cy="135" r="7" fill="var(--surface)" stroke="var(--faint)" strokeWidth="3" />
      </svg>
      <div className="gauge-scale"><span>0%</span><span>100%</span></div>
      <div className="gauge-score">{score === null ? "—" : `${s}%`}</div>
      <div className="gauge-label" style={{ color }}>{label}</div>
    </div>
  );
}

export function CategoryBars({ categories }: { categories: Category[] }) {
  return (
    <>
      {categories.map((c) => {
        const v = c.score ?? 0;
        const tone = v >= 85 ? "good" : v >= 70 ? "warn" : "bad";
        return (
          <div className="cat" key={c.key} title={c.hint}>
            <div className="cat-head"><span>{c.label}</span><span>{c.score === null ? "n/a" : `${v}%`}</span></div>
            <div className="bar"><span className={tone} style={{ width: `${v}%` }} /></div>
          </div>
        );
      })}
    </>
  );
}

/* ---------------------------------------------------------------- calendar */
const DOW = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
export function Calendar({ events, onPick }: {
  events: { date: string; shipment_id: string; bucket: string }[]; onPick: (shipmentId: string) => void;
}) {
  const today = new Date();
  const [cursor, setCursor] = useState(new Date(today.getFullYear(), today.getMonth(), 1));
  const days = useMemo(() => {
    const first = new Date(cursor.getFullYear(), cursor.getMonth(), 1);
    const startDay = new Date(first);
    startDay.setDate(1 - first.getDay());
    return Array.from({ length: 42 }, (_, i) => {
      const d = new Date(startDay);
      d.setDate(startDay.getDate() + i);
      return d;
    });
  }, [cursor]);
  const iso = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  const byDay = new Map<string, { shipment_id: string; bucket: string }[]>();
  events.forEach((e) => byDay.set(e.date, [...(byDay.get(e.date) ?? []), e]));
  const colour = (b: string) => (b === "demurrage" ? "var(--red)" : b === "soon" ? "var(--amber)" : "var(--green)");
  return (
    <div>
      <div className="cal-head">
        <button aria-label="Previous month" onClick={() => setCursor(new Date(cursor.getFullYear(), cursor.getMonth() - 1, 1))}>‹</button>
        <span>{cursor.toLocaleString(undefined, { month: "long", year: "numeric" })}</span>
        <button aria-label="Next month" onClick={() => setCursor(new Date(cursor.getFullYear(), cursor.getMonth() + 1, 1))}>›</button>
      </div>
      <div className="cal">
        {DOW.map((d) => <div key={d} className="dow">{d}</div>)}
        {days.slice(0, 35).map((d) => {
          const ev = byDay.get(iso(d));
          const cls = ["day", d.getMonth() !== cursor.getMonth() ? "out" : "", iso(d) === iso(today) ? "today" : ""].join(" ");
          return (
            <div key={iso(d)} className={cls} style={{ cursor: ev ? "pointer" : undefined }}
                 title={ev?.map((e) => `${e.shipment_id}: free time expires`).join("\n")}
                 onClick={() => ev && onPick(ev[0].shipment_id)}>
              {d.getDate()}
              {ev && <span className="dot" style={{ background: colour(ev[0].bucket) }} />}
            </div>
          );
        })}
      </div>
      <div className="cal-legend">
        <span>● <span style={{ color: "var(--red)" }}>demurrage</span></span>
        <span>● <span style={{ color: "#8a6a00" }}>≤ 3 days</span></span>
        <span>● <span style={{ color: "var(--green)" }}>later</span></span>
        <span>Free-time expiry</span>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- task card */
export function TaskCard({ card, onOpen }: { card: Card; onOpen: () => void }) {
  const ft = card.free_time;
  const status = ft.bucket === "demurrage" ? `Demurrage · ${Math.abs(Math.floor(ft.days_left ?? 0))}d overdue`
    : ft.bucket === "soon" ? `Within ${Math.ceil(ft.days_left ?? 0)} day${Math.ceil(ft.days_left ?? 0) === 1 ? "" : "s"}`
    : ft.bucket === "later" ? `${Math.floor(ft.days_left ?? 0)} days left` : "No free-time data";
  const pillColor = ft.bucket === "demurrage" ? "var(--red)" : ft.bucket === "soon" ? "#c27c0e" : "var(--green)";
  return (
    <div className={`task ${ft.bucket}`}>
      <span className="pill" style={{ color: pillColor }}>{status}</span>
      <h4 title={card.title}>{card.title}</h4>
      <p title={card.description}>{card.shipment_id} · {card.reference} · {card.description}</p>
      <p>Assigned to <b style={{ color: "var(--text)" }}>{card.owner}</b></p>
      <div className="progress"><span style={{ width: `${card.progress}%` }} /></div>
      <span className="muted" style={{ fontSize: 13 }}>{card.progress}% resolved — {card.progress_label}</span>
      <div className="row">
        <button className="btn" onClick={onOpen}>Review</button>
        <button className="btn ghost" onClick={onOpen}>View details</button>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- diff viewer */
function isField(x: unknown): x is FieldView {
  return typeof x === "object" && x !== null && "confidence" in x && "extractor" in x;
}

export function formatValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    if ("amount" in o && "currency" in o) return `${o.currency} ${Number(o.amount).toLocaleString(undefined, { minimumFractionDigits: 2 })}`;
    if ("amount" in o && "unit" in o) return `${Number(o.amount).toLocaleString(undefined, { minimumFractionDigits: 2 })} ${o.unit}`;
    return JSON.stringify(v);
  }
  return String(v);
}

function rows(data: unknown, prefix = ""): { name: string; f: FieldView }[] {
  if (isField(data)) return [{ name: prefix || "value", f: data }];
  if (typeof data === "object" && data !== null && !Array.isArray(data)) {
    return Object.entries(data as Record<string, unknown>).flatMap(([k, v]) =>
      isField(v) ? [{ name: k, f: v }] : typeof v === "object" && v !== null && !Array.isArray(v) ? rows(v, k) : []);
  }
  return [];
}

export function DiffViewer({ sides, onOpenDoc }: { sides: DiffSide[]; onOpenDoc: (sha: string, docType: string) => void }) {
  if (!sides.length) return <div className="empty">No document evidence attached to this issue.</div>;
  return (
    <div className="diff">
      {sides.map((s, i) => {
        const blocks = s.context.length ? s.context : s.fields;
        return (
          <div className="diff-col" key={i}>
            <header>
              <div>
                <b>{s.doc_type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}</b>
                <div className="mono faint">{s.field_path}</div>
              </div>
              <button className="btn ghost sm" onClick={() => onOpenDoc(s.content_sha256, s.doc_type)}>Original</button>
            </header>
            {blocks.map((b) => (
              <table key={b.path}>
                <thead><tr><th colSpan={3}>{b.path}</th></tr></thead>
                <tbody>
                  {rows(b.data).map(({ name, f }) => {
                    const hl = name === s.highlight || s.field_path.endsWith(name);
                    return (
                      <tr key={name} className={hl ? "hl" : ""}>
                        <td className="muted" style={{ width: "34%" }}>{name.replace(/_/g, " ")}</td>
                        <td>
                          <b>{formatValue(f.value)}</b>
                          {f.value === null && f.raw_text && <div className="mono faint">read: “{f.raw_text}”</div>}
                        </td>
                        <td style={{ width: 72, textAlign: "right" }}>
                          <span className={`conf ${f.needs_review ? "low" : "ok"}`} title={`${f.extractor}${f.source ? ` · page ${f.source.page}` : ""}`}>
                            {Number(f.confidence).toFixed(1)}%
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ))}
          </div>
        );
      })}
    </div>
  );
}

/* ---------------------------------------------------------------- decision tree */
function Node({ n, focus }: { n: TraceNode; focus?: string | null }) {
  const [open, setOpen] = useState(n.outcome === "fail");
  const mark = n.outcome === "pass" ? "✓" : n.outcome === "fail" ? "✕" : "–";
  const hasKids = n.children.length > 0;
  return (
    <li className="node">
      <div className="node-head" style={{ cursor: hasKids ? "pointer" : undefined, fontWeight: focus && n.issue_id === focus ? 700 : undefined }}
           onClick={() => hasKids && setOpen(!open)}>
        <span className={`outcome ${n.outcome}`}>{mark}</span>
        <span>{n.check}</span>
        <span className="mono faint">{n.rule_id}</span>
        {hasKids && <span className="faint">{open ? "▾" : "▸"}</span>}
      </div>
      {Object.keys(n.inputs).length > 0 && (
        <div className="node-inputs">
          {Object.entries(n.inputs).map(([k, v]) => <span className="kv" key={k}><span className="muted">{k}:</span> {v}</span>)}
        </div>
      )}
      {n.detail && n.outcome === "fail" && <div style={{ margin: "4px 0 0 26px", color: "var(--red)" }}>{n.detail}</div>}
      {hasKids && open && <ul className="tree">{n.children.map((c, i) => <Node key={i} n={c} focus={focus} />)}</ul>}
    </li>
  );
}

export function DecisionTree({ nodes, focus }: { nodes: TraceNode[]; focus?: string | null }) {
  return <ul className="tree tree-root">{nodes.map((n, i) => <Node key={i} n={n} focus={focus} />)}</ul>;
}
