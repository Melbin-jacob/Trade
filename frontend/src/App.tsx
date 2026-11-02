import { useCallback, useEffect, useState } from "react";
import { api, session, type Me } from "./api";
import { completeOidcLogin, devLogin, logout, startOidcLogin } from "./auth";
import { Icon, Logo } from "./components";
import { Approvals, AuditLedger, Hub, ShipmentDetail, Shipments } from "./pages";

function useRoute(): [string, (r: string) => void] {
  const read = () => location.hash.replace(/^#/, "") || "/hub";
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const on = () => setRoute(read());
    addEventListener("hashchange", on);
    return () => removeEventListener("hashchange", on);
  }, []);
  return [route, (r: string) => { location.hash = r; window.scrollTo(0, 0); }];
}

function Login({ onDone }: { onDone: () => void }) {
  const [cfg, setCfg] = useState<Awaited<ReturnType<typeof api.config>> | null>(null);
  const [users, setUsers] = useState<{ id: string; name: string; roles: string[] }[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  useEffect(() => {
    api.config().then(async (c) => {
      setCfg(c);
      if (c.auth === "dev") setUsers(await api.devUsers());
      else if (await completeOidcLogin(c.issuer!, c.client_id!)) onDone();
    }).catch((e: Error) => setErr(e.message));
  }, [onDone]);
  return (
    <div className="login">
      <div className="card">
        <div className="logo" style={{ margin: "0 0 18px" }}><Logo /> Trade-Lane Sentinel</div>
        {err && <div className="notice error">{err}</div>}
        {cfg?.auth === "oidc" && (
          <button className="btn" style={{ width: "100%" }} onClick={() => startOidcLogin(cfg.issuer!, cfg.client_id!, cfg.audience)}>
            Sign in with your organisation
          </button>
        )}
        {cfg?.auth === "dev" && (
          <>
            <div className="notice info">Demo environment — choose a persona. Production sign-in uses your identity provider with MFA.</div>
            {cfg.access_code_required && (
              <label className="field" style={{ marginBottom: 14 }}>Access code
                <input type="text" autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)}
                       placeholder="Provided by your administrator" /></label>
            )}
            {users.map((u) => (
              <button key={u.id} className="user-option" disabled={!!cfg.access_code_required && !code}
                      onClick={() => devLogin(u.id, code.trim()).then(onDone).catch((e: Error) => setErr(e.message))}>
                <span className="avatar">{u.name.split(" ").map((p) => p[0]).join("")}</span>
                <span><b>{u.name}</b><div className="muted">{u.roles.join(", ").replace(/_/g, " ")}</div></span>
              </button>
            ))}
          </>
        )}
      </div>
    </div>
  );
}

const NAV = [
  { route: "/hub", label: "Compliance Hub", icon: Icon.hub },
  { route: "/shipments", label: "Shipments", icon: Icon.ship },
  { route: "/approvals", label: "Approvals", icon: Icon.check },
  { route: "/audit", label: "Audit Ledger", icon: Icon.ledger },
];

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [authed, setAuthed] = useState(!!session.get());
  const [route, go] = useRoute();
  const [filter, setFilter] = useState("");
  const [pending, setPending] = useState(0);

  const loadMe = useCallback(() => {
    if (!session.get()) { setAuthed(false); return; }
    api.me().then((m) => { setMe(m); setAuthed(true); }).catch(() => setAuthed(false));
  }, []);
  useEffect(() => { loadMe(); }, [loadMe]);
  useEffect(() => {
    const out = () => { setMe(null); setAuthed(false); };
    addEventListener("sentinel:logout", out);
    return () => removeEventListener("sentinel:logout", out);
  }, []);
  useEffect(() => {
    if (me) api.cosigns().then((c) => setPending(c.length)).catch(() => setPending(0));
  }, [me, route]);

  if (!authed || !me) return <Login onDone={loadMe} />;

  const shipmentMatch = route.match(/^\/shipments\/(SHP-\d{4}-\d{6})$/);
  const section = shipmentMatch ? "/shipments" : route;
  const title = shipmentMatch ? "Shipment Review" : NAV.find((n) => n.route === route)?.label ?? "Compliance Hub";
  const name = sessionStorage.getItem("sentinel.name") ?? me.id;

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="logo"><Logo /> Trade-Lane Sentinel</div>
        {NAV.map((n) => (
          <button key={n.route} className={`nav-item ${section === n.route ? "active" : ""}`} onClick={() => go(n.route)}>
            {n.icon}{n.label}{n.route === "/approvals" && pending > 0 && <span className="nav-badge">{pending}</span>}
          </button>
        ))}
        <div className="sidebar-foot">
          <div className="user-chip">
            <span className="avatar">{name.split(/[ .]/).map((p) => p[0]?.toUpperCase()).join("").slice(0, 2)}</span>
            <span><b>{name}</b><div className="muted" style={{ fontSize: 12 }}>{me.roles.join(", ").replace(/_/g, " ")}</div></span>
          </div>
          <button className="nav-item" onClick={() => { logout(); setMe(null); setAuthed(false); }}>{Icon.logout} Sign out</button>
        </div>
      </aside>
      <main className="main">
        <div className="topbar">
          <h1>{title}</h1>
          {!shipmentMatch && route !== "/audit" && (
            <label className="search">
              {Icon.search}
              <input placeholder="Search shipments, references…" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Search" />
              <span className="kbd">⌘K</span>
            </label>
          )}
        </div>
        {shipmentMatch ? <ShipmentDetail id={shipmentMatch[1]} go={go} />
          : route === "/shipments" ? <Shipments go={go} filter={filter} me={me} />
          : route === "/approvals" ? <Approvals me={me} go={go} />
          : route === "/audit" ? <AuditLedger me={me} />
          : <Hub go={go} filter={filter} />}
      </main>
    </div>
  );
}
