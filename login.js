/**
 * Cloudflare Pages Function — POST /api/login
 *
 * Set these in Pages → Settings → Environment variables:
 *   USERS_JSON  = {"users":[{"username":"Alice","password":"secret","role":"user"}]}
 *   KEYS_JSON   = {"keys":[{"key":"XXXX-...","username":"Alice","expires":null}]}
 *
 * Optional:
 *   ALLOW_ORIGIN = https://jaymods-menu.pages.dev
 */

function corsHeaders(origin, allowOrigin) {
  const allowed = allowOrigin || "*";
  const acao = allowed === "*" ? "*" : (origin === allowed ? allowed : allowed);
  return {
    "Access-Control-Allow-Origin": acao,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };
}

function json(body, status, headers) {
  return new Response(JSON.stringify(body), { status, headers });
}

function parseEnvJSON(raw, fallback) {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function b64url(buf) {
  let s = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function makeToken(payload, secret) {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const data = new TextEncoder().encode(`${header}.${body}`);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret || "change-me-in-production"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, data);
  return `${header}.${body}.${b64url(sig)}`;
}

export async function onRequestOptions(context) {
  const allow = context.env.ALLOW_ORIGIN || "*";
  return new Response(null, {
    status: 204,
    headers: corsHeaders(context.request.headers.get("Origin"), allow),
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const headers = corsHeaders(request.headers.get("Origin"), env.ALLOW_ORIGIN);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "Invalid JSON body" }, 400, headers);
  }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");
  const keyStr = String(body.key || "").trim();

  if (!username || !password) {
    return json({ ok: false, error: "Username and password required" }, 400, headers);
  }
  if (!keyStr) {
    return json({ ok: false, error: "License key required" }, 400, headers);
  }

  const usersData = parseEnvJSON(env.USERS_JSON, { users: [] });
  const keysData = parseEnvJSON(env.KEYS_JSON, { keys: [] });
  const users = usersData.users || usersData || [];
  const keys = keysData.keys || keysData || [];

  if (!users.length) {
    return json({ ok: false, error: "Server auth not configured (USERS_JSON)" }, 500, headers);
  }

  const user = users.find(
    (u) =>
      String(u.username || "").toLowerCase() === username.toLowerCase() &&
      String(u.password || "") === password
  );

  if (!user) {
    // Constant-ish delay would be better; keep simple
    return json({ ok: false, error: "Invalid username or password" }, 401, headers);
  }

  const key = keys.find(
    (k) => String(k.key || "").trim().toUpperCase() === keyStr.toUpperCase()
  );

  if (!key) {
    return json({ ok: false, error: "License key not found" }, 401, headers);
  }

  const bound = String(key.username || "").trim().toLowerCase();
  if (bound && bound !== username.toLowerCase()) {
    return json({ ok: false, error: "Key is not assigned to this account" }, 401, headers);
  }

  if (key.expires) {
    const exp = new Date(key.expires);
    if (!isNaN(exp.getTime()) && exp < new Date()) {
      return json({ ok: false, error: "License key expired" }, 401, headers);
    }
  }

  const token = await makeToken(
    {
      sub: user.username,
      role: user.role || "user",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 12, // 12h
    },
    env.TOKEN_SECRET
  );

  return json(
    {
      ok: true,
      token,
      user: {
        username: user.username,
        role: user.role || "user",
      },
    },
    200,
    headers
  );
}

// Reject GET etc.
export async function onRequest(context) {
  if (context.request.method === "POST") return onRequestPost(context);
  if (context.request.method === "OPTIONS") return onRequestOptions(context);
  const headers = corsHeaders(context.request.headers.get("Origin"), context.env.ALLOW_ORIGIN);
  return json({ ok: false, error: "Method not allowed" }, 405, headers);
}
