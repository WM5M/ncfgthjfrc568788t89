/**
 * Cloudflare Pages Function — POST /api/login
 * 
 * Place at: functions/api/login.js in your GitHub repo (WM5M/jaymods-menu)
 *
 * Required environment variables (Cloudflare Pages → Settings → Variables):
 *   USERS_JSON    {"users":[{"username":"JayMods808","password":"KingLeo92","role":"admin"}]}
 *   KEYS_JSON     {"keys":[{"key":"ABCDEF-123456-FEDCBA-654321","username":"JayMods808","expires":null}]}
 *   TOKEN_SECRET  any long random string
 *   ALLOW_ORIGIN  https://jaymods-menu.pages.dev
 */

export async function onRequestOptions({ request, env }) {
  return new Response(null, {
    status: 204,
    headers: corsHeaders(env),
  });
}

export async function onRequestPost({ request, env }) {
  const cors = corsHeaders(env);

  // Parse body
  let body;
  try { body = await request.json(); }
  catch { return json({ ok: false, error: "Bad request." }, 400, cors); }

  const username = (body.username || "").trim();
  const password = (body.password || "");
  const keyStr   = (body.key     || "").trim().toUpperCase();

  if (!username || !password || !keyStr)
    return json({ ok: false, error: "Username, password and license key are all required." }, 400, cors);

  // ── Load users from env var ───────────────────────────────────────────────
  let users = [];
  try {
    const parsed = JSON.parse(env.USERS_JSON || "{}");
    users = parsed.users || parsed;
    if (!Array.isArray(users)) throw new Error("USERS_JSON must be an array or {users:[]}");
  } catch (e) {
    return json({ ok: false, error: "Server config error (users): " + e.message }, 500, cors);
  }

  // ── Validate username + password ──────────────────────────────────────────
  const user = users.find(u =>
    u.username.toLowerCase() === username.toLowerCase() &&
    u.password === password
  );
  if (!user)
    return json({ ok: false, error: "Invalid username or password." }, 401, cors);

  // ── Load keys from env var ────────────────────────────────────────────────
  let keys = [];
  try {
    const parsed = JSON.parse(env.KEYS_JSON || "{}");
    keys = parsed.keys || parsed;
    if (!Array.isArray(keys)) throw new Error("KEYS_JSON must be an array or {keys:[]}");
  } catch (e) {
    return json({ ok: false, error: "Server config error (keys): " + e.message }, 500, cors);
  }

  // ── Validate license key ──────────────────────────────────────────────────
  const kv = validateKey(username, keyStr, keys);
  if (!kv.ok)
    return json({ ok: false, error: `Key rejected: ${kv.reason}` }, 401, cors);

  // ── Issue token ───────────────────────────────────────────────────────────
  const token = await makeToken(username, env.TOKEN_SECRET || "changeme-set-TOKEN_SECRET");

  return json({
    ok: true,
    user: { username: user.username, role: user.role || "user" },
    token,
    keyInfo: kv.info,
  }, 200, cors);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function corsHeaders(env) {
  const origin = env.ALLOW_ORIGIN || "*";
  return {
    "Access-Control-Allow-Origin":  origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };
}

function json(data, status, headers) {
  return new Response(JSON.stringify(data), { status, headers });
}

function validateKey(username, keyStr, keys) {
  for (const k of keys) {
    if ((k.key || "").toUpperCase() !== keyStr) continue;

    // Key found — check username binding
    const bound = (k.username || "").trim().toLowerCase();
    if (bound && bound !== username.toLowerCase())
      return { ok: false, reason: "Key is not assigned to this account." };

    // Check expiry
    const exp = k.expires;
    if (exp === null || exp === undefined || exp === "")
      return { ok: true, info: "lifetime" };

    const expDate = new Date(exp);
    if (isNaN(expDate.getTime()))
      return { ok: false, reason: "Key expiry date is invalid." };
    if (Date.now() > expDate.getTime())
      return { ok: false, reason: `Key expired on ${expDate.toISOString().slice(0,10)}.` };

    const daysLeft = Math.ceil((expDate.getTime() - Date.now()) / 86400000);
    return { ok: true, info: `expires in ${daysLeft}d` };
  }
  return { ok: false, reason: "Key not found." };
}

async function makeToken(username, secret) {
  const payload = btoa(JSON.stringify({
    u: username,
    iat: Date.now(),
    exp: Date.now() + 86_400_000,
  }));
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false, ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
    const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
    return `${payload}.${sigB64}`;
  } catch {
    return payload;
  }
}
