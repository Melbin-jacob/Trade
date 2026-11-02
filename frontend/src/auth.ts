// OIDC authorization-code flow with PKCE (public SPA client) for production;
// a user picker for the local demo. Access tokens are kept in sessionStorage only.
import { api, session } from "./api";

const VERIFIER = "sentinel.pkce.verifier";
const STATE = "sentinel.pkce.state";

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return btoa(String.fromCharCode(...arr)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function random(n = 32): string {
  return b64url(crypto.getRandomValues(new Uint8Array(n)));
}

async function discovery(issuer: string) {
  const res = await fetch(`${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error("identity provider unavailable");
  return res.json() as Promise<{ authorization_endpoint: string; token_endpoint: string }>;
}

export async function startOidcLogin(issuer: string, clientId: string, audience?: string) {
  const d = await discovery(issuer);
  const verifier = random(48);
  const state = random(16);
  sessionStorage.setItem(VERIFIER, verifier);
  sessionStorage.setItem(STATE, state);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const params = new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: `${location.origin}/`,
    scope: "openid profile", code_challenge: challenge, code_challenge_method: "S256", state,
  });
  if (audience) params.set("audience", audience);
  location.assign(`${d.authorization_endpoint}?${params}`);
}

export async function completeOidcLogin(issuer: string, clientId: string): Promise<boolean> {
  const q = new URLSearchParams(location.search);
  const code = q.get("code");
  if (!code) return false;
  if (q.get("state") !== sessionStorage.getItem(STATE)) throw new Error("login state mismatch");
  const d = await discovery(issuer);
  const res = await fetch(d.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code, client_id: clientId, redirect_uri: `${location.origin}/`,
      code_verifier: sessionStorage.getItem(VERIFIER) ?? "",
    }),
  });
  sessionStorage.removeItem(VERIFIER);
  sessionStorage.removeItem(STATE);
  if (!res.ok) throw new Error("token exchange failed");
  const tok = await res.json();
  session.set(tok.access_token);
  history.replaceState(null, "", location.pathname + location.hash);
  return true;
}

export async function devLogin(user: string, accessCode = ""): Promise<string> {
  const r = await api.devToken(user, accessCode);
  session.set(r.token);
  sessionStorage.setItem("sentinel.name", r.name);
  return r.name;
}

export function logout() {
  session.clear();
  sessionStorage.removeItem("sentinel.name");
}
