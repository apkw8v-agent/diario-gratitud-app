// Diario de gratitud - val HTTP en Val Town. Codigo publico generico: sin secretos ni datos personales.
//
// Modelo de seguridad (probado contra el almacen real antes del despliegue):
// - La usuaria configura su propia clave una sola vez con un enlace unico (SETUP_TOKEN en env);
//   en el almacen solo queda un hash PBKDF2-SHA256 (210k iteraciones, sal aleatoria, pepper en env).
// - El login crea una sesion: cookie HttpOnly+Secure+SameSite=Strict con id aleatorio;
//   en el almacen solo se guarda el hash del id, con caducidad deslizante de 30 dias.
// - El agente entra con un Bearer token distinto, del que solo hay hash en env.
//   Ningun token va en el frontend.
// - Fuerza bruta: contador por IP con bloqueo de 15 min tras 5 fallos.
// - Cada entrada es una clave propia en el almacen: altas sin read-modify-write,
//   asi que una escritura de ella y una del agente simultaneas no se pisan.
// - /api/* se sirve con Cache-Control: no-store y el service worker no cachea la API.
const UP_URL = Deno.env.get("UPSTASH_REDIS_REST_URL") ?? "";
const UP_TOKEN = Deno.env.get("UPSTASH_REDIS_REST_TOKEN") ?? "";
const AGENT_TOKEN_HASH = Deno.env.get("AGENT_TOKEN_HASH") ?? "";
const SETUP_TOKEN = Deno.env.get("SETUP_TOKEN") ?? "";
const PEPPER = Deno.env.get("PEPPER") ?? "";
const SESSION_TTL_S = 30 * 24 * 3600;
const MAX_FAILS = 5;
const LOCK_S = 15 * 60;
const textEncoder = new TextEncoder();
async function redis(...command) {
    const res = await fetch(UP_URL, {
        method: "POST",
        headers: { Authorization: `Bearer ${UP_TOKEN}`, "Content-Type": "application/json" },
        body: JSON.stringify(command),
    });
    if (!res.ok)
        throw new Error("store");
    const data = await res.json();
    if (data.error)
        throw new Error("store");
    return data.result;
}
function makeStore(prefix) {
    return {
        async get(key) {
            const raw = await redis("GET", `${prefix}:${key}`);
            return raw == null ? null : JSON.parse(raw);
        },
        async setJSON(key, value) {
            await redis("SET", `${prefix}:${key}`, JSON.stringify(value));
        },
        async delete(key) {
            await redis("DEL", `${prefix}:${key}`);
        },
        async list() {
            const keys = await redis("KEYS", `${prefix}:*`);
            return { blobs: (keys || []).map((k) => ({ key: k.slice(prefix.length + 1) })) };
        },
    };
}
const entriesStore = makeStore("entries");
const sessionsStore = makeStore("sessions");
const failuresStore = makeStore("failures");
const usersStore = makeStore("users");
async function sha256hex(text) {
    const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(text));
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hashMatches(plain, expectedHashHex) {
    if (!plain || !expectedHashHex)
        return false;
    const actual = await sha256hex(plain);
    if (actual.length !== expectedHashHex.length)
        return false;
    let diff = 0;
    for (let i = 0; i < actual.length; i++)
        diff |= actual.charCodeAt(i) ^ expectedHashHex.charCodeAt(i);
    return diff === 0;
}
function b64encode(bytes) {
    return btoa(String.fromCharCode(...bytes));
}
function b64decode(s) {
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
async function pbkdf2Hex(secret, salt) {
    const key = await crypto.subtle.importKey("raw", textEncoder.encode(secret + PEPPER), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", iterations: 210000, salt }, key, 256);
    return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function json(body, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extraHeaders },
    });
}
function clientKey(request, scope) {
    const ip = (request.headers.get("x-forwarded-for") || "").split(",")[0].trim() || "unknown";
    return `${scope}:${ip}`;
}
async function gate(key) {
    const row = await failuresStore.get(key);
    const now = Math.floor(Date.now() / 1000);
    if (row && row.locked_until && row.locked_until > now)
        return { locked: true, retryAfter: row.locked_until - now };
    return { locked: false, retryAfter: 0 };
}
async function recordFailure(key) {
    const now = Math.floor(Date.now() / 1000);
    const row = await failuresStore.get(key);
    const fails = (row?.fails || 0) + 1;
    const lockedUntil = fails >= MAX_FAILS ? now + LOCK_S : null;
    await failuresStore.setJSON(key, { fails: lockedUntil ? 0 : fails, locked_until: lockedUntil, updated_at: now });
    return lockedUntil ? LOCK_S : 0;
}
async function clearFailures(key) {
    await failuresStore.delete(key);
}
function getCookie(request, name) {
    const header = request.headers.get("Cookie") || "";
    for (const part of header.split(";")) {
        const [k, ...rest] = part.trim().split("=");
        if (k === name)
            return rest.join("=");
    }
    return null;
}
async function sessionFromCookie(request) {
    const sid = getCookie(request, "sid");
    if (!sid || sid.length < 32 || sid.length > 128)
        return null;
    const hash = await sha256hex(sid);
    const row = await sessionsStore.get(hash);
    if (!row)
        return null;
    const now = Math.floor(Date.now() / 1000);
    if (row.expires_at <= now) {
        await sessionsStore.delete(hash);
        return null;
    }
    if (row.expires_at - now < SESSION_TTL_S / 2) {
        await sessionsStore.setJSON(hash, { ...row, expires_at: now + SESSION_TTL_S, last_seen: now });
    }
    return { idHash: hash };
}
async function agentAuthorized(request) {
    const header = request.headers.get("Authorization") || "";
    if (!header.startsWith("Bearer "))
        return false;
    const token = header.slice(7).trim();
    if (token.length < 32 || token.length > 128)
        return false;
    return hashMatches(token, AGENT_TOKEN_HASH);
}
async function authenticate(request) {
    if (await sessionFromCookie(request))
        return "session";
    const header = request.headers.get("Authorization") || "";
    if (header.startsWith("Bearer ")) {
        const key = clientKey(request, "agent");
        const { locked, retryAfter } = await gate(key);
        if (locked)
            return { error: json({ error: "locked" }, 429, { "Retry-After": String(retryAfter) }) };
        if (await agentAuthorized(request)) {
            await clearFailures(key);
            return "agent";
        }
        const wait = await recordFailure(key);
        return { error: json({ error: "unauthorized" }, 401, wait ? { "Retry-After": String(wait) } : {}) };
    }
    return null;
}
function originAllowed(request) {
    const origin = request.headers.get("Origin");
    if (!origin)
        return true;
    try {
        return new URL(origin).host === new URL(request.url).host;
    }
    catch {
        return false;
    }
}
function validDate(value) {
    return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(value));
}
function validText(value) {
    return typeof value === "string" && value.trim().length > 0 && value.length <= 8000;
}
function nowIso() {
    return new Date().toISOString();
}
async function isConfigured() {
    return (await usersStore.get("owner")) !== null;
}
async function handle(request, path) {
    const method = request.method;
    if (path === "/api/setup/status" && method === "GET") {
        return json({ configured: await isConfigured() });
    }
    if (path === "/api/setup" && method === "POST") {
        if (!originAllowed(request))
            return json({ error: "forbidden" }, 403);
        const key = clientKey(request, "setup");
        const { locked, retryAfter } = await gate(key);
        if (locked)
            return json({ error: "locked", retry_after: retryAfter }, 429, { "Retry-After": String(retryAfter) });
        if (await isConfigured())
            return json({ error: "already_configured" }, 403);
        let body;
        try {
            body = await request.json();
        }
        catch {
            return json({ error: "bad_request" }, 400);
        }
        if (!SETUP_TOKEN || body?.setupToken !== SETUP_TOKEN) {
            await recordFailure(key);
            return json({ error: "invalid_setup_link" }, 403);
        }
        if (typeof body?.secret !== "string" || body.secret.length < 12 || body.secret.length > 64) {
            return json({ error: "weak_secret" }, 400);
        }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const hash = await pbkdf2Hex(body.secret, salt);
        await usersStore.setJSON("owner", { salt: b64encode(salt), hash, created_at: nowIso() });
        await clearFailures(key);
        const sid = crypto.randomUUID() + crypto.randomUUID().replaceAll("-", "");
        const sidHash = await sha256hex(sid);
        const now = Math.floor(Date.now() / 1000);
        await sessionsStore.setJSON(sidHash, { created_at: now, expires_at: now + SESSION_TTL_S, last_seen: now });
        return json({ ok: true }, 200, { "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_S}` });
    }
    if (path === "/api/login" && method === "POST") {
        if (!originAllowed(request))
            return json({ error: "forbidden" }, 403);
        const key = clientKey(request, "login");
        const { locked, retryAfter } = await gate(key);
        if (locked)
            return json({ error: "locked", retry_after: retryAfter }, 429, { "Retry-After": String(retryAfter) });
        let body;
        try {
            body = await request.json();
        }
        catch {
            return json({ error: "bad_request" }, 400);
        }
        const user = await usersStore.get("owner");
        const ok = !!user && typeof body?.secret === "string" &&
            await pbkdf2Hex(body.secret, b64decode(user.salt)) === user.hash;
        if (!ok) {
            const wait = await recordFailure(key);
            return json({ error: "invalid" }, 401, wait ? { "Retry-After": String(wait) } : {});
        }
        await clearFailures(key);
        const sid = crypto.randomUUID() + crypto.randomUUID().replaceAll("-", "");
        const hash = await sha256hex(sid);
        const now = Math.floor(Date.now() / 1000);
        await sessionsStore.setJSON(hash, { created_at: now, expires_at: now + SESSION_TTL_S, last_seen: now });
        return json({ ok: true }, 200, { "Set-Cookie": `sid=${sid}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_S}` });
    }
    if (path === "/api/logout" && method === "POST") {
        const session = await sessionFromCookie(request);
        if (session)
            await sessionsStore.delete(session.idHash);
        return json({ ok: true }, 200, { "Set-Cookie": "sid=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
    }
    // Todo lo demas requiere autenticacion.
    const auth = await authenticate(request);
    if (auth && typeof auth === "object" && "error" in auth)
        return auth.error;
    if (!auth)
        return json({ error: "unauthorized" }, 401);
    if (path === "/api/session" && method === "GET") {
        return json({ authenticated: true, via: auth });
    }
    if (path === "/api/entries" && method === "GET") {
        const { blobs } = await entriesStore.list();
        const entries = await Promise.all(blobs.map((b) => entriesStore.get(b.key)));
        entries.sort((a, b) => (a.entry_date === b.entry_date
            ? String(a.created_at).localeCompare(String(b.created_at))
            : String(b.entry_date).localeCompare(String(a.entry_date))));
        return json({ entries });
    }
    if (path === "/api/entries" && method === "POST") {
        if (!originAllowed(request))
            return json({ error: "forbidden" }, 403);
        let body;
        try {
            body = await request.json();
        }
        catch {
            return json({ error: "bad_request" }, 400);
        }
        if (!validDate(body?.entry_date) || !validText(body?.text))
            return json({ error: "bad_request" }, 400);
        const source = auth === "agent" && typeof body.source === "string" && body.source.length <= 500
            ? body.source : (auth === "agent" ? "agent" : "app");
        const id = crypto.randomUUID();
        const stamp = nowIso();
        await entriesStore.setJSON(id, {
            id, entry_date: body.entry_date, text: body.text.trim(), source,
            created_at: stamp, updated_at: stamp,
        });
        return json({ ok: true, id }, 201);
    }
    const entryMatch = path.match(/^\/api\/entries\/([0-9a-f-]{36})$/);
    if (entryMatch && method === "PUT") {
        if (!originAllowed(request))
            return json({ error: "forbidden" }, 403);
        let body;
        try {
            body = await request.json();
        }
        catch {
            return json({ error: "bad_request" }, 400);
        }
        if (!validText(body?.text))
            return json({ error: "bad_request" }, 400);
        const existing = await entriesStore.get(entryMatch[1]);
        if (!existing)
            return json({ error: "not_found" }, 404);
        await entriesStore.setJSON(entryMatch[1], { ...existing, text: body.text.trim(), updated_at: nowIso() });
        return json({ ok: true });
    }
    if (entryMatch && method === "DELETE") {
        if (!originAllowed(request))
            return json({ error: "forbidden" }, 403);
        const existing = await entriesStore.get(entryMatch[1]);
        if (!existing)
            return json({ error: "not_found" }, 404);
        await entriesStore.delete(entryMatch[1]);
        return json({ ok: true });
    }
    return json({ error: "not_found" }, 404);
}
// --- Assets estaticos inline (inyectados en build; contenido generico) ---
import { ASSETS1 } from "./assets1.ts";
import { ASSETS2 } from "./assets2.ts";
const ASSETS = { ...ASSETS1, ...ASSETS2 };
const SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; manifest-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Robots-Tag": "noindex, nofollow",
    "Referrer-Policy": "no-referrer",
};
function serveAsset(key) {
    const a = ASSETS[key];
    if (!a)
        return null;
    const bytes = b64decode(a.b64);
    const headers = { "Content-Type": a.type, ...SEC_HEADERS };
    if (key === "/sw.js") {
        headers["Cache-Control"] = "no-cache";
        headers["Service-Worker-Allowed"] = "/";
    }
    else if (key === "/index.html") {
        headers["Cache-Control"] = "no-store";
    }
    else {
        if (key.startsWith("/icons/")) {
            headers["Cache-Control"] = "public, max-age=604800, immutable";
        }
        else {
            // app.js/styles/manifest: revalidar siempre; las actualizaciones usan nombres versionados.
            headers["Cache-Control"] = "no-cache";
        }
    }
    return new Response(bytes, { headers });
}
const ROUTES = {
    "/": "/index.html",
    "/index.html": "/index.html",
    "/app.js": "/app.v2.js",
    "/app.v2.js": "/app.v2.js",
    "/styles.css": "/styles.v2.css",
    "/styles.v2.css": "/styles.v2.css",
    "/sw.js": "/sw.js",
    "/manifest.webmanifest": "/manifest.webmanifest",
    "/icons/icon-192.png": "/icons/icon-192.png",
    "/icons/icon-512.png": "/icons/icon-512.png",
    "/icons/icon-maskable-512.png": "/icons/icon-maskable-512.png",
};
export default async function (request) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    try {
        if (request.method === "GET" && ROUTES[path]) {
            const r = serveAsset(ROUTES[path]);
            if (r)
                return r;
        }
        return await handle(request, path);
    }
    catch {
        return json({ error: "internal" }, 500);
    }
}
