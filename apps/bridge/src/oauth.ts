/**
 * Minimal OAuth 2.1 Authorization Server for remote MCP clients
 * (Gemini web "custom connector", ChatGPT connectors, etc.).
 *
 * - RFC 9728 Protected Resource Metadata
 * - RFC 8414 Authorization Server Metadata
 * - RFC 7591 Dynamic Client Registration
 * - RFC 7636 PKCE (S256 only)
 * - Refresh token rotation
 *
 * Approval requires the local Bridge token to be typed into the consent page,
 * so knowing the public tunnel URL is not enough to obtain an access token.
 */
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000; // 1h
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30d
const AUTH_CODE_TTL_MS = 5 * 60 * 1000; // 5min
const MAX_CLIENTS = 200;

interface OAuthClient {
  client_id: string;
  client_secret_hash?: string;
  token_endpoint_auth_method: "none" | "client_secret_basic" | "client_secret_post";
  redirect_uris: string[];
  client_name?: string;
  created_at: number;
  /** Static clients configured via env accept any https redirect URI. */
  static?: boolean;
}

interface StoredToken {
  client_id: string;
  exp: number;
}

interface OAuthStore {
  clients: Record<string, OAuthClient>;
  accessTokens: Record<string, StoredToken>;
  refreshTokens: Record<string, StoredToken>;
}

interface PendingCode {
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  exp: number;
}

export interface OAuthProviderOptions {
  /** Secret the human must type on the consent page (the Bridge token). */
  approvalSecret: string;
  storePath: string;
  /** Returns false when the caller exceeded the auth attempt budget. */
  checkApprovalRateLimit?: (req: http.IncomingMessage) => boolean;
  checkRegistrationRateLimit?: (req: http.IncomingMessage) => boolean;
  staticClient?: { clientId: string; clientSecret: string };
  now?: () => number;
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function randomToken(prefix: string): string {
  return `${prefix}${crypto.randomBytes(32).toString("base64url")}`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function isAllowedRedirectUri(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.hash) return false;
    if (u.protocol === "https:") return true;
    // Loopback redirects for native/CLI clients (RFC 8252)
    return u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "[::1]");
  } catch {
    return false;
  }
}

function readBody(req: http.IncomingMessage, maxBytes = 64 * 1024): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > maxBytes) {
        req.destroy();
        reject(new Error("Request body too large"));
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function parseBody(raw: string, contentType = ""): Record<string, any> {
  if (!raw.trim()) return {};
  if (contentType.includes("application/json")) {
    try {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      return {};
    }
  }
  return Object.fromEntries(new URLSearchParams(raw).entries());
}

function sendJson(res: http.ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    Pragma: "no-cache",
    ...extraHeaders,
  });
  res.end(JSON.stringify(body));
}

function sendOAuthError(res: http.ServerResponse, status: number, error: string, description: string): void {
  sendJson(res, status, { error, error_description: description });
}

function sendHtml(res: http.ServerResponse, status: number, html: string): void {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action *; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
  });
  res.end(html);
}

export class OAuthProvider {
  private store: OAuthStore;
  private codes = new Map<string, PendingCode>();
  private readonly opts: OAuthProviderOptions;
  private readonly now: () => number;

  constructor(opts: OAuthProviderOptions) {
    this.opts = opts;
    this.now = opts.now ?? Date.now;
    this.store = this.load();
    if (opts.staticClient?.clientId && opts.staticClient.clientSecret) {
      this.store.clients[opts.staticClient.clientId] = {
        client_id: opts.staticClient.clientId,
        client_secret_hash: sha256(opts.staticClient.clientSecret),
        token_endpoint_auth_method: "client_secret_post",
        redirect_uris: [],
        client_name: "Static OAuth client",
        created_at: this.now(),
        static: true,
      };
    }
  }

  // ---------------------------------------------------------------- storage

  private load(): OAuthStore {
    try {
      if (fs.existsSync(this.opts.storePath)) {
        const parsed = JSON.parse(fs.readFileSync(this.opts.storePath, "utf-8"));
        return {
          clients: parsed.clients ?? {},
          accessTokens: parsed.accessTokens ?? {},
          refreshTokens: parsed.refreshTokens ?? {},
        };
      }
    } catch (err: any) {
      console.warn("[OAuth] Failed to load OAuth store, starting fresh:", err?.message || String(err));
    }
    return { clients: {}, accessTokens: {}, refreshTokens: {} };
  }

  private persist(): void {
    this.prune();
    const persistable: OAuthStore = {
      clients: Object.fromEntries(Object.entries(this.store.clients).filter(([, c]) => !c.static)),
      accessTokens: this.store.accessTokens,
      refreshTokens: this.store.refreshTokens,
    };
    try {
      fs.mkdirSync(path.dirname(this.opts.storePath), { recursive: true });
      const tmp = `${this.opts.storePath}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(persistable), { encoding: "utf-8", mode: 0o600 });
      fs.renameSync(tmp, this.opts.storePath);
    } catch (err: any) {
      console.warn("[OAuth] Failed to persist OAuth store:", err?.message || String(err));
    }
  }

  private prune(): void {
    const now = this.now();
    for (const map of [this.store.accessTokens, this.store.refreshTokens]) {
      for (const [k, v] of Object.entries(map)) {
        if (v.exp <= now) delete map[k];
      }
    }
    for (const [k, v] of this.codes) {
      if (v.exp <= now) this.codes.delete(k);
    }
  }

  // ---------------------------------------------------------------- public API

  validateAccessToken(token: string): boolean {
    const entry = this.store.accessTokens[sha256(token)];
    return Boolean(entry && entry.exp > this.now() && this.store.clients[entry.client_id]);
  }

  resourceMetadataUrl(base: string): string {
    return `${base}/.well-known/oauth-protected-resource`;
  }

  /** Header value for 401 responses on the protected MCP resource. */
  wwwAuthenticate(base: string, error?: string): string {
    const parts = [`Bearer realm="Nexus MCP"`, `resource_metadata="${this.resourceMetadataUrl(base)}"`, `scope="mcp"`];
    if (error) parts.push(`error="${error}"`);
    return parts.join(", ");
  }

  /** Returns true if the request was an OAuth route and has been answered. */
  async handle(req: http.IncomingMessage, res: http.ServerResponse, pathname: string, url: URL, base: string): Promise<boolean> {
    const method = req.method || "GET";

    if (
      method === "GET" &&
      (pathname === "/.well-known/oauth-protected-resource" || pathname.startsWith("/.well-known/oauth-protected-resource/"))
    ) {
      sendJson(res, 200, {
        resource: `${base}/mcp`,
        authorization_servers: [base],
        bearer_methods_supported: ["header"],
        scopes_supported: ["mcp"],
        resource_name: "Nexus MCP Bridge",
      });
      return true;
    }

    if (
      method === "GET" &&
      (pathname === "/.well-known/oauth-authorization-server" ||
        pathname.startsWith("/.well-known/oauth-authorization-server/") ||
        pathname === "/.well-known/openid-configuration" ||
        pathname.startsWith("/.well-known/openid-configuration/"))
    ) {
      sendJson(res, 200, {
        issuer: base,
        authorization_endpoint: `${base}/oauth/authorize`,
        token_endpoint: `${base}/oauth/token`,
        registration_endpoint: `${base}/oauth/register`,
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
        scopes_supported: ["mcp"],
      });
      return true;
    }

    if (pathname === "/oauth/register" && method === "POST") {
      await this.handleRegister(req, res);
      return true;
    }
    if (pathname === "/oauth/authorize" && method === "GET") {
      this.handleAuthorizeGet(res, url);
      return true;
    }
    if (pathname === "/oauth/authorize" && method === "POST") {
      await this.handleAuthorizePost(req, res, base);
      return true;
    }
    if (pathname === "/oauth/token" && method === "POST") {
      await this.handleToken(req, res);
      return true;
    }
    if (pathname.startsWith("/oauth/")) {
      sendOAuthError(res, 405, "invalid_request", "Unsupported OAuth endpoint or method");
      return true;
    }
    return false;
  }

  // ---------------------------------------------------------------- DCR

  private async handleRegister(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (this.opts.checkRegistrationRateLimit && !this.opts.checkRegistrationRateLimit(req)) {
      sendOAuthError(res, 429, "slow_down", "Too many registration attempts");
      return;
    }
    let body: Record<string, any>;
    try {
      body = parseBody(await readBody(req), String(req.headers["content-type"] || "application/json"));
    } catch {
      sendOAuthError(res, 413, "invalid_client_metadata", "Body too large");
      return;
    }

    const redirectUris = body.redirect_uris;
    if (!Array.isArray(redirectUris) || redirectUris.length === 0 || redirectUris.length > 10) {
      sendOAuthError(res, 400, "invalid_redirect_uri", "redirect_uris must be a non-empty array");
      return;
    }
    for (const uri of redirectUris) {
      if (typeof uri !== "string" || !isAllowedRedirectUri(uri)) {
        sendOAuthError(res, 400, "invalid_redirect_uri", `Unsupported redirect_uri: ${String(uri).slice(0, 200)}`);
        return;
      }
    }

    const requestedMethod = body.token_endpoint_auth_method ?? "client_secret_basic";
    if (!["none", "client_secret_basic", "client_secret_post"].includes(requestedMethod)) {
      sendOAuthError(res, 400, "invalid_client_metadata", "Unsupported token_endpoint_auth_method");
      return;
    }
    const grantTypes: string[] = Array.isArray(body.grant_types) ? body.grant_types : ["authorization_code", "refresh_token"];
    if (!grantTypes.includes("authorization_code")) {
      sendOAuthError(res, 400, "invalid_client_metadata", "authorization_code grant is required");
      return;
    }

    // Evict oldest dynamic clients beyond capacity
    const dynamicClients = Object.values(this.store.clients).filter((c) => !c.static);
    if (dynamicClients.length >= MAX_CLIENTS) {
      dynamicClients.sort((a, b) => a.created_at - b.created_at);
      for (const c of dynamicClients.slice(0, dynamicClients.length - MAX_CLIENTS + 1)) {
        delete this.store.clients[c.client_id];
      }
    }

    const clientId = `nexus_client_${crypto.randomBytes(16).toString("hex")}`;
    const clientSecret = requestedMethod === "none" ? undefined : randomToken("nexus_secret_");
    const clientName = typeof body.client_name === "string" ? body.client_name.slice(0, 120) : undefined;
    const issuedAt = Math.floor(this.now() / 1000);

    this.store.clients[clientId] = {
      client_id: clientId,
      client_secret_hash: clientSecret ? sha256(clientSecret) : undefined,
      token_endpoint_auth_method: requestedMethod,
      redirect_uris: redirectUris,
      client_name: clientName,
      created_at: this.now(),
    };
    this.persist();

    sendJson(res, 201, {
      client_id: clientId,
      ...(clientSecret ? { client_secret: clientSecret, client_secret_expires_at: 0 } : {}),
      client_id_issued_at: issuedAt,
      client_name: clientName,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: requestedMethod,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: "mcp",
    });
  }

  // ---------------------------------------------------------------- authorize

  private validateAuthorizeParams(params: Record<string, any>): { ok: true; client: OAuthClient } | { ok: false; message: string } {
    const client = this.store.clients[String(params.client_id || "")];
    if (!client) return { ok: false, message: "Unknown client_id. Remove and re-add the connector." };
    const redirectUri = String(params.redirect_uri || "");
    const redirectOk = client.static ? isAllowedRedirectUri(redirectUri) : client.redirect_uris.includes(redirectUri);
    if (!redirectOk) return { ok: false, message: "redirect_uri is not registered for this client." };
    if (params.response_type !== "code") return { ok: false, message: "response_type must be 'code'." };
    if (!params.code_challenge || params.code_challenge_method !== "S256") {
      return { ok: false, message: "PKCE with code_challenge_method=S256 is required." };
    }
    return { ok: true, client };
  }

  private handleAuthorizeGet(res: http.ServerResponse, url: URL): void {
    const params = Object.fromEntries(url.searchParams.entries());
    const check = this.validateAuthorizeParams(params);
    if (!check.ok) {
      sendHtml(res, 400, this.renderPage("授权请求无效", `<p class="err">${escapeHtml(check.message)}</p>`));
      return;
    }
    sendHtml(res, 200, this.renderConsent(params, check.client));
  }

  private async handleAuthorizePost(req: http.IncomingMessage, res: http.ServerResponse, base: string): Promise<void> {
    let params: Record<string, any>;
    try {
      params = parseBody(await readBody(req), String(req.headers["content-type"] || ""));
    } catch {
      sendHtml(res, 413, this.renderPage("请求过大", ""));
      return;
    }
    const check = this.validateAuthorizeParams(params);
    if (!check.ok) {
      sendHtml(res, 400, this.renderPage("授权请求无效", `<p class="err">${escapeHtml(check.message)}</p>`));
      return;
    }

    const redirect = new URL(String(params.redirect_uri));
    if (params.state) redirect.searchParams.set("state", String(params.state));
    redirect.searchParams.set("iss", base);

    if (params.action !== "approve") {
      redirect.searchParams.set("error", "access_denied");
      res.writeHead(302, { Location: redirect.toString(), "Cache-Control": "no-store" });
      res.end();
      return;
    }

    if (this.opts.checkApprovalRateLimit && !this.opts.checkApprovalRateLimit(req)) {
      sendHtml(res, 429, this.renderConsent(params, check.client, "尝试次数过多，请一分钟后再试。"));
      return;
    }

    const typed = String(params.approval_token || "").trim();
    if (!typed || !safeEqual(typed, this.opts.approvalSecret)) {
      sendHtml(res, 401, this.renderConsent(params, check.client, "Bridge 令牌不正确。"));
      return;
    }

    const code = randomToken("nexus_code_");
    this.codes.set(sha256(code), {
      client_id: check.client.client_id,
      redirect_uri: String(params.redirect_uri),
      code_challenge: String(params.code_challenge),
      exp: this.now() + AUTH_CODE_TTL_MS,
    });
    redirect.searchParams.set("code", code);
    res.writeHead(302, { Location: redirect.toString(), "Cache-Control": "no-store" });
    res.end();
  }

  // ---------------------------------------------------------------- token

  private authenticateClient(req: http.IncomingMessage, body: Record<string, any>): OAuthClient | null {
    let clientId = typeof body.client_id === "string" ? body.client_id : "";
    let clientSecret = typeof body.client_secret === "string" ? body.client_secret : "";

    const authHeader = String(req.headers.authorization || "");
    if (authHeader.toLowerCase().startsWith("basic ")) {
      try {
        const decoded = Buffer.from(authHeader.slice(6).trim(), "base64").toString("utf-8");
        const idx = decoded.indexOf(":");
        if (idx >= 0) {
          clientId = decodeURIComponent(decoded.slice(0, idx));
          clientSecret = decodeURIComponent(decoded.slice(idx + 1));
        }
      } catch {
        return null;
      }
    }

    const client = this.store.clients[clientId];
    if (!client) return null;
    if (client.client_secret_hash) {
      if (!clientSecret || !safeEqual(sha256(clientSecret), client.client_secret_hash)) return null;
    }
    return client;
  }

  private issueTokens(clientId: string): Record<string, unknown> {
    const accessToken = randomToken("nexus_at_");
    const refreshToken = randomToken("nexus_rt_");
    const now = this.now();
    this.store.accessTokens[sha256(accessToken)] = { client_id: clientId, exp: now + ACCESS_TOKEN_TTL_MS };
    this.store.refreshTokens[sha256(refreshToken)] = { client_id: clientId, exp: now + REFRESH_TOKEN_TTL_MS };
    this.persist();
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
      refresh_token: refreshToken,
      scope: "mcp",
    };
  }

  private async handleToken(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    let body: Record<string, any>;
    try {
      body = parseBody(await readBody(req), String(req.headers["content-type"] || ""));
    } catch {
      sendOAuthError(res, 413, "invalid_request", "Body too large");
      return;
    }

    const client = this.authenticateClient(req, body);
    if (!client) {
      sendJson(res, 401, { error: "invalid_client", error_description: "Client authentication failed" }, {
        "WWW-Authenticate": 'Basic realm="Nexus OAuth"',
      });
      return;
    }

    if (body.grant_type === "authorization_code") {
      const codeKey = sha256(String(body.code || ""));
      const pending = this.codes.get(codeKey);
      this.codes.delete(codeKey); // one-time use regardless of outcome
      if (!pending || pending.exp <= this.now() || pending.client_id !== client.client_id) {
        sendOAuthError(res, 400, "invalid_grant", "Authorization code is invalid or expired");
        return;
      }
      if (String(body.redirect_uri || "") !== pending.redirect_uri) {
        sendOAuthError(res, 400, "invalid_grant", "redirect_uri mismatch");
        return;
      }
      const verifier = String(body.code_verifier || "");
      const computed = crypto.createHash("sha256").update(verifier).digest("base64url");
      if (!verifier || !safeEqual(computed, pending.code_challenge)) {
        sendOAuthError(res, 400, "invalid_grant", "PKCE verification failed");
        return;
      }
      sendJson(res, 200, this.issueTokens(client.client_id));
      return;
    }

    if (body.grant_type === "refresh_token") {
      const key = sha256(String(body.refresh_token || ""));
      const entry = this.store.refreshTokens[key];
      if (!entry || entry.exp <= this.now() || entry.client_id !== client.client_id) {
        sendOAuthError(res, 400, "invalid_grant", "Refresh token is invalid or expired");
        return;
      }
      delete this.store.refreshTokens[key]; // rotation
      sendJson(res, 200, this.issueTokens(client.client_id));
      return;
    }

    sendOAuthError(res, 400, "unsupported_grant_type", "Only authorization_code and refresh_token are supported");
  }

  // ---------------------------------------------------------------- HTML

  private renderConsent(params: Record<string, any>, client: OAuthClient, error?: string): string {
    const keys = ["client_id", "redirect_uri", "response_type", "state", "code_challenge", "code_challenge_method", "scope", "resource"];
    const hidden = keys
      .filter((k) => params[k] !== undefined)
      .map((k) => `<input type="hidden" name="${k}" value="${escapeHtml(String(params[k]))}">`)
      .join("\n");
    let redirectHost = "";
    try {
      redirectHost = new URL(String(params.redirect_uri)).host;
    } catch {}
    const name = client.client_name || client.client_id;
    return this.renderPage(
      "授权访问本地 Nexus",
      `<p><b>${escapeHtml(name)}</b> 请求通过 MCP 访问你电脑上的 Nexus。</p>
<p class="muted">授权完成后将跳转到：<code>${escapeHtml(redirectHost)}</code></p>
<p class="muted">批准后，该客户端可调用 Nexus Bridge 暴露的全部 MCP 工具（受 Nexus 本地权限与审批策略约束）。</p>
${error ? `<p class="err">${escapeHtml(error)}</p>` : ""}
<form method="POST" action="/oauth/authorize" autocomplete="off">
${hidden}
<label for="t">Bridge 令牌</label>
<p class="muted">桌面版 / 直接启动：<code>%LOCALAPPDATA%\\LocalBridge\\data\\bridge-token.key</code><br>
OPEN-SOURCE-START.ps1 启动：<code>apps\\nexus-open-cloud\\.local-bridge-token</code></p>
<input id="t" type="password" name="approval_token" placeholder="lb_bridge_..." autofocus>
<div class="row">
<button type="submit" name="action" value="deny" class="secondary">拒绝</button>
<button type="submit" name="action" value="approve">批准</button>
</div>
</form>`
    );
  }

  private renderPage(title: string, body: string): string {
    return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#f5f5f7;color:#1d1d1f;margin:0;padding:16px}
@media (prefers-color-scheme:dark){body{background:#111;color:#eee}.card{background:#1c1c1e!important}input{background:#2c2c2e;color:#eee;border-color:#444!important}}
.card{max-width:460px;margin:8vh auto;background:#fff;border-radius:12px;padding:24px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 16px}.muted{color:#888;font-size:13px}.err{color:#d93025}
label{display:block;font-size:13px;margin:16px 0 6px}input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #ccc;border-radius:8px;font-size:14px}
.row{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
button{padding:9px 18px;border-radius:8px;border:0;background:#1a73e8;color:#fff;font-size:14px;cursor:pointer}
button.secondary{background:transparent;color:inherit;border:1px solid #999}
code{font-size:12px;word-break:break-all}
</style></head><body><div class="card"><h1>${escapeHtml(title)}</h1>${body}</div></body></html>`;
  }
}
