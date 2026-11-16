import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { OAuthProvider } from "./oauth.js";

const APPROVAL = "lb_bridge_test_secret";
const REDIRECT = "https://gemini.example.com/oauth/callback";

let server: http.Server;
let base: string;
let provider: OAuthProvider;
let tmpDir: string;

function pkce() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

async function register(body: Record<string, unknown> = {}) {
  const res = await fetch(`${base}/oauth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ redirect_uris: [REDIRECT], client_name: "Gemini", ...body }),
  });
  return { status: res.status, json: (await res.json()) as any };
}

async function approve(clientId: string, challenge: string, token = APPROVAL, action = "approve") {
  const form = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT,
    response_type: "code",
    state: "xyz",
    code_challenge: challenge,
    code_challenge_method: "S256",
    approval_token: token,
    action,
  });
  return fetch(`${base}/oauth/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
    redirect: "manual",
  });
}

async function token(params: Record<string, string>, basic?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
  if (basic) headers.Authorization = `Basic ${basic}`;
  const res = await fetch(`${base}/oauth/token`, { method: "POST", headers, body: new URLSearchParams(params).toString() });
  return { status: res.status, json: (await res.json()) as any };
}

beforeEach(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-oauth-"));
  provider = new OAuthProvider({ approvalSecret: APPROVAL, storePath: path.join(tmpDir, "store.json") });
  server = http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", base);
    if (!(await provider.handle(req, res, url.pathname, url, base))) {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("Bridge OAuth provider", () => {
  it("serves RFC 9728 and RFC 8414 metadata", async () => {
    const pr = (await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json()) as any;
    expect(pr.resource).toBe(`${base}/mcp`);
    expect(pr.authorization_servers).toEqual([base]);

    const as = (await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()) as any;
    expect(as.issuer).toBe(base);
    expect(as.registration_endpoint).toBe(`${base}/oauth/register`);
    expect(as.code_challenge_methods_supported).toEqual(["S256"]);
    expect(provider.wwwAuthenticate(base)).toContain(`resource_metadata="${base}/.well-known/oauth-protected-resource"`);
  });

  it("completes DCR + PKCE + token + refresh rotation for a confidential client", async () => {
    const reg = await register();
    expect(reg.status).toBe(201);
    expect(reg.json.client_secret).toBeTruthy();

    const { verifier, challenge } = pkce();
    const authRes = await approve(reg.json.client_id, challenge);
    expect(authRes.status).toBe(302);
    const loc = new URL(authRes.headers.get("location")!);
    expect(loc.origin + loc.pathname).toBe(REDIRECT);
    expect(loc.searchParams.get("state")).toBe("xyz");
    const code = loc.searchParams.get("code")!;

    const basic = Buffer.from(`${reg.json.client_id}:${reg.json.client_secret}`).toString("base64");
    const tok = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier }, basic);
    expect(tok.status).toBe(200);
    expect(provider.validateAccessToken(tok.json.access_token)).toBe(true);

    // code is single-use
    const replay = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier }, basic);
    expect(replay.json.error).toBe("invalid_grant");

    const refreshed = await token({ grant_type: "refresh_token", refresh_token: tok.json.refresh_token }, basic);
    expect(refreshed.status).toBe(200);
    expect(provider.validateAccessToken(refreshed.json.access_token)).toBe(true);

    // old refresh token rotated out
    const reuse = await token({ grant_type: "refresh_token", refresh_token: tok.json.refresh_token }, basic);
    expect(reuse.json.error).toBe("invalid_grant");
  });

  it("accepts the Gemini app connector DCR payload (6 redirect URIs, client_secret_post, no scope)", async () => {
    const id = "user_bound_custom-mcp-1234567890-nexus";
    const hosts = ["oauth-redirect-sandbox.googleusercontent.com", "oauth-redirect-test.googleusercontent.com", "oauth-redirect.googleusercontent.com"];
    const redirectUris = hosts.flatMap((h) => [`https://${h}/r/${id}`, `https://${h}/a/${id}`]);
    const res = await fetch(`${base}/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "Google",
        redirect_uris: redirectUris,
        response_types: ["code"],
        grant_types: ["authorization_code", "refresh_token"],
        token_endpoint_auth_method: "client_secret_post",
      }),
    });
    expect(res.status).toBe(201);
    const json = (await res.json()) as any;
    expect(json.redirect_uris).toHaveLength(6);
    expect(json.client_secret).toBeTruthy();

    // client_secret_post at the token endpoint
    const { verifier, challenge } = pkce();
    const form = new URLSearchParams({
      client_id: json.client_id, redirect_uri: redirectUris[2], response_type: "code", state: "g",
      code_challenge: challenge, code_challenge_method: "S256", approval_token: APPROVAL, action: "approve",
    });
    const auth = await fetch(`${base}/oauth/authorize`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form.toString(), redirect: "manual" });
    const code = new URL(auth.headers.get("location")!).searchParams.get("code")!;
    const tok = await token({ grant_type: "authorization_code", code, redirect_uri: redirectUris[2], code_verifier: verifier, client_id: json.client_id, client_secret: json.client_secret });
    expect(tok.status).toBe(200);
  });

  it("supports public clients (token_endpoint_auth_method=none)", async () => {
    const reg = await register({ token_endpoint_auth_method: "none" });
    expect(reg.json.client_secret).toBeUndefined();
    const { verifier, challenge } = pkce();
    const code = new URL((await approve(reg.json.client_id, challenge)).headers.get("location")!).searchParams.get("code")!;
    const tok = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: reg.json.client_id });
    expect(tok.status).toBe(200);
  });

  it("refuses approval without the correct Bridge token", async () => {
    const reg = await register();
    const { challenge } = pkce();
    const res = await approve(reg.json.client_id, challenge, "wrong");
    expect(res.status).toBe(401);
    expect(res.headers.get("location")).toBeNull();
  });

  it("redirects with access_denied when the user denies", async () => {
    const reg = await register();
    const res = await approve(reg.json.client_id, pkce().challenge, "", "deny");
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("location")!).searchParams.get("error")).toBe("access_denied");
  });

  it("rejects bad PKCE verifier, wrong client secret and unregistered redirect", async () => {
    const reg = await register();
    const { challenge } = pkce();
    const code = new URL((await approve(reg.json.client_id, challenge)).headers.get("location")!).searchParams.get("code")!;
    const basic = Buffer.from(`${reg.json.client_id}:${reg.json.client_secret}`).toString("base64");
    const bad = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: "nope" }, basic);
    expect(bad.json.error).toBe("invalid_grant");

    const wrongSecret = await token({ grant_type: "refresh_token", refresh_token: "x" }, Buffer.from(`${reg.json.client_id}:bad`).toString("base64"));
    expect(wrongSecret.status).toBe(401);

    const res = await fetch(
      `${base}/oauth/authorize?client_id=${reg.json.client_id}&redirect_uri=${encodeURIComponent("https://evil.example/cb")}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`
    );
    expect(res.status).toBe(400);

    const nonHttps = await register({ redirect_uris: ["http://evil.example/cb"] });
    expect(nonHttps.status).toBe(400);
  });

  it("persists clients and tokens across restarts", async () => {
    const reg = await register({ token_endpoint_auth_method: "none" });
    const { verifier, challenge } = pkce();
    const code = new URL((await approve(reg.json.client_id, challenge)).headers.get("location")!).searchParams.get("code")!;
    const tok = await token({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: reg.json.client_id });

    const raw = fs.readFileSync(path.join(tmpDir, "store.json"), "utf-8");
    expect(raw).not.toContain(tok.json.access_token);

    const reloaded = new OAuthProvider({ approvalSecret: APPROVAL, storePath: path.join(tmpDir, "store.json") });
    expect(reloaded.validateAccessToken(tok.json.access_token)).toBe(true);
    expect(reloaded.validateAccessToken("nexus_at_bogus")).toBe(false);
  });
});
