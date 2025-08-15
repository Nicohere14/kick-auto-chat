import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import crypto from "crypto";
import fs from "fs";
import path from "path";

/* ===== ENV ===== */
const {
  PORT = 3000,
  // Kick
  KICK_CLIENT_ID,
  KICK_CLIENT_SECRET,
  KICK_REDIRECT_URI,
  ALLOWED_SLUGS = "",
  // Messaging
  CHAT_MESSAGE = "Cześć czacie! 👋",
  CHAT_MESSAGES_JSON = "",
  INTERVAL_MINUTES = "5",
  JITTER_SECONDS = "30,60",
  POLL_SECONDS = "60",
  VERIFY_WEBHOOK_SIGNATURE = "false",
  // Admin / opcje
  ADMIN_KEY = "",
  SUBSCRIBE_KEY = "",
  // Pliki pomocnicze (PKCE, backup)
  DATA_DIR = ".",
  // KV (Upstash REST)
  UPSTASH_REDIS_REST_URL = "",
  UPSTASH_REDIS_REST_TOKEN = "",
  // Opcjonalny awaryjny backup
  KICK_REFRESH_TOKEN = ""
} = process.env;

/* ===== Folder na pliki pomocnicze ===== */
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const TOKENS_FILE = path.join(DATA_DIR, "tokens.json");
const PKCE_FILE   = path.join(DATA_DIR, "pkce.json");

/* ===== Konfiguracja ===== */
const allowedSlugs = ALLOWED_SLUGS.split(",").map(s => s.trim()).filter(Boolean);
const intervalMs = Math.max(1, Number(INTERVAL_MINUTES)) * 60_000;
const [jMinRaw, jMaxRaw] = (JITTER_SECONDS || "30,60").split(",");
const jMin = Math.abs(Number(jMinRaw || 30));
const jMax = Math.abs(Number(jMaxRaw || 60));
const jitterMs = () =>
  (Math.floor(Math.random() * (Math.max(jMin, jMax) - Math.min(jMin, jMax) + 1)) + Math.min(jMin, jMax)) * 1000;
const pollMs = Math.max(30, Number(POLL_SECONDS)) * 1000;

/* ===== Wiadomości (rotacja) ===== */
let chatMessages = [];
try {
  if (CHAT_MESSAGES_JSON) {
    const arr = JSON.parse(CHAT_MESSAGES_JSON);
    if (Array.isArray(arr) && arr.length) chatMessages = arr.map(String);
  }
} catch (e) {
  console.warn("CHAT_MESSAGES_JSON parse error:", e.message);
}
if (chatMessages.length === 0) chatMessages = [CHAT_MESSAGE];
let msgIndex = 0;
const nextMessage = () => chatMessages[(msgIndex++) % chatMessages.length];

/* ===== KV (Upstash REST) helpery ===== */
const TOKENS_KV_KEY = "kick_tokens_v1";

async function kvGet(key) {
  if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) return null;
  const r = await fetch(`${UPSTASH_REDIS_REST_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${UPSTASH_REDIS_REST_TOKEN}` }
  });
  if (!r.ok) return null;
  const j = await r.json();
  try { return j?.result ? JSON.parse(j.result) : null; } catch { return null; }
}
async function kvSet(key, obj) {
  if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) return;
  const val = encodeURIComponent(JSON.stringify(obj));
  await fetch(`${UPSTASH_REDIS_REST_URL}/set/${encodeURIComponent(key)}/${val}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${UPSTASH_REDIS_REST_TOKEN}` }
  }).catch(()=>{});
}

/* ===== Tokeny / PKCE ===== */
let tokens = { access_token: null, refresh_token: null, expires_at: 0 };
function saveTokensToFile() {
  try { fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2)); } catch {}
}
async function saveTokensEverywhere() {
  saveTokensToFile();
  await kvSet(TOKENS_KV_KEY, tokens);
}
async function loadTokensOnBoot() {
  // 1) Priorytet: KV
  const fromKv = await kvGet(TOKENS_KV_KEY);
  if (fromKv && fromKv.refresh_token) { tokens = fromKv; return; }
  // 2) Backup: plik
  if (fs.existsSync(TOKENS_FILE)) {
    try {
      const f = JSON.parse(fs.readFileSync(TOKENS_FILE, "utf-8"));
      if (f?.refresh_token) tokens = f;
    } catch {}
  }
  // 3) Awaryjny ENV
  if (!tokens.refresh_token && KICK_REFRESH_TOKEN) {
    tokens.refresh_token = KICK_REFRESH_TOKEN.trim();
  }
}

/* PKCE (persist) */
let pkceStore = fs.existsSync(PKCE_FILE) ? JSON.parse(fs.readFileSync(PKCE_FILE, "utf-8")) : {};
const savePkce = () => fs.writeFileSync(PKCE_FILE, JSON.stringify(pkceStore, null, 2));
const setPkce = (state, verifier) => { pkceStore[state] = { verifier, ts: Date.now() }; savePkce(); };
const getPkce = (state) => {
  const rec = pkceStore[state];
  if (!rec) return null;
  delete pkceStore[state];
  savePkce();
  return rec.verifier;
};

/* ===== App ===== */
const app = express();
app.use(bodyParser.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(bodyParser.urlencoded({ extended: true, verify: (req, res, buf) => { req.rawBody = buf; } }));

/* ===== OAuth helpers ===== */
async function refreshIfNeeded() {
  const now = Math.floor(Date.now() / 1000);
  if (tokens.access_token && now < Number(tokens.expires_at || 0) - 60) return tokens.access_token;
  if (!tokens.refresh_token) throw new Error("Brak refresh_token – uruchom /auth/start");

  const params = new URLSearchParams();
  params.append("grant_type", "refresh_token");
  params.append("client_id", KICK_CLIENT_ID);
  params.append("client_secret", KICK_CLIENT_SECRET);
  params.append("refresh_token", tokens.refresh_token);

  const { data } = await axios.post("https://id.kick.com/oauth/token", params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000
  });

  tokens.access_token = data.access_token;
  tokens.refresh_token = data.refresh_token; // ROTACJA!
  tokens.expires_at = Math.floor(Date.now()/1000) + (data.expires_in || 3600);
  await saveTokensEverywhere();
  return tokens.access_token;
}

let appToken = { token: null, expires_at: 0 };
async function getAppToken() {
  const now = Math.floor(Date.now()/1000);
  if (appToken.token && now < Number(appToken.expires_at || 0) - 60) return appToken.token;

  const params = new URLSearchParams();
  params.append("grant_type", "client_credentials");
  params.append("client_id", KICK_CLIENT_ID);
  params.append("client_secret", KICK_CLIENT_SECRET);

  const { data } = await axios.post("https://id.kick.com/oauth/token", params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000
  });

  appToken.token = data.access_token;
  appToken.expires_at = now + (data.expires_in || 3600);
  return appToken.token;
}

/* ===== API helpers ===== */
async function getChannelsBySlugs(slugs) {
  const list = (Array.isArray(slugs) ? slugs : [slugs]).map(s => String(s || "").trim()).filter(Boolean);
  if (list.length === 0) return [];
  const token = await getAppToken();
  const base = "https://api.kick.com/public/v1/channels";
  const headers = { Authorization: `Bearer ${token}` };
  const timeout = 15000;

  if (list.length === 1) {
    const slug = encodeURIComponent(list[0]);
    try {
      const { data } = await axios.get(`${base}/${slug}`, { headers, timeout });
      const ch = data?.data || data;
      if (ch) return [ch];
    } catch (e) { if (e?.response?.status && e.response.status !== 404) throw e; }
  }
  try {
    const qs = list.map(s => `slug=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${base}?${qs}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) return data.data;
  } catch {}
  try {
    const qsArr = list.map(s => `slug[]=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${base}?${qsArr}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) return data.data;
  } catch {}
  return [];
}

async function sendChatMessage({ broadcaster_user_id, content, type = "user" }) {
  const token = await refreshIfNeeded();
  await axios.post("https://api.kick.com/public/v1/chat", {
    broadcaster_user_id, content, type
  }, { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 });
}

/* ===== Pętla wysyłek ===== */
const postingLoops = new Map();
function startPostingLoop(broadcaster_user_id, type = "user") {
  if (postingLoops.has(broadcaster_user_id)) return;
  let cancelled = false;
  const tick = async () => {
    if (cancelled) return;
    try {
      const msg = nextMessage();
      await sendChatMessage({ broadcaster_user_id, content: msg, type });
      console.log(new Date().toISOString(), "sent", { broadcaster_user_id, msg });
    } catch (e) {
      const status = e?.response?.status;
      const detail = e?.response?.data || e.message;
      console.error("Chat send error", status, detail);
      if (status === 401 || status === 403) { stopPostingLoop(broadcaster_user_id); return; }
    } finally {
      if (!cancelled) setTimeout(tick, intervalMs + jitterMs());
    }
  };
  postingLoops.set(broadcaster_user_id, { cancel: () => { cancelled = true; } });
  setTimeout(tick, 10_000 + jitterMs());
  console.log("Posting loop START", broadcaster_user_id);
}
function stopPostingLoop(broadcaster_user_id) {
  const c = postingLoops.get(broadcaster_user_id);
  if (c) { c.cancel(); postingLoops.delete(broadcaster_user_id); console.log("Posting loop STOP", broadcaster_user_id); }
}

/* ===== Webhook security ===== */
let cachedPublicKey = null;
async function getKickPublicKey() {
  if (cachedPublicKey) return cachedPublicKey;
  try {
    const { data } = await axios.get("https://api.kick.com/public/v1/public-key", { timeout: 15000 });
    cachedPublicKey = data?.data?.public_key || null;
  } catch (e) { console.warn("Unable to fetch Kick public key:", e.message); }
  return cachedPublicKey;
}
function verifyWebhookSignature(req) {
  if (String(VERIFY_WEBHOOK_SIGNATURE).toLowerCase() !== "true") return true;
  const messageId = req.get("Kick-Event-Message-Id");
  const timestamp = req.get("Kick-Event-Message-Timestamp");
  const signatureB64 = req.get("Kick-Event-Signature");
  if (!messageId || !timestamp || !signatureB64 || !req.rawBody) return false;
  try {
    const payload = Buffer.from(`${messageId}.${timestamp}.${req.rawBody}`);
    const signature = Buffer.from(signatureB64, "base64");
    const pubKeyPem = cachedPublicKey;
    if (!pubKeyPem) return false;
    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(payload); verifier.end();
    return verifier.verify(pubKeyPem, signature);
  } catch (e) { console.error("Signature verify error:", e.message); return false; }
}

/* ===== ROUTES ===== */

// Webhook: start/stop pętli
app.post("/webhook", async (req, res) => {
  try {
    await getKickPublicKey();
    if (!verifyWebhookSignature(req)) return res.status(401).send("Invalid signature");
    const eventType = req.get("Kick-Event-Type");
    if (eventType === "livestream.status.updated") {
      const { broadcaster, is_live } = req.body || {};
      const id = broadcaster?.user_id;
      const slug = broadcaster?.channel_slug;
      if (!id) return res.sendStatus(204);
      if (!allowedSlugs.includes(String(slug))) return res.sendStatus(204);
      if (is_live) startPostingLoop(id); else stopPostingLoop(id);
    }
    res.sendStatus(200);
  } catch (e) {
    console.error("Webhook error:", e.message); res.sendStatus(500);
  }
});

// Polling fallback
async function pollingTick() {
  try {
    if (allowedSlugs.length === 0) return;
    const chans = await getChannelsBySlugs(allowedSlugs);
    for (const ch of chans) {
      const id = ch.broadcaster_user_id;
      const isLive = ch.stream?.is_live === true;
      if (isLive) startPostingLoop(id); else stopPostingLoop(id);
    }
  } catch (e) { console.error("Polling error:", e.message); }
}

// OAuth start
app.get("/auth/start", (req, res) => {
  if (!KICK_CLIENT_ID || !KICK_REDIRECT_URI) return res.status(400).send("Missing OAuth envs");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const hash = crypto.createHash("sha256").update(codeVerifier).digest();
  const codeChallenge = Buffer.from(hash).toString("base64url");
  const state = crypto.randomBytes(8).toString("hex");
  const store = fs.existsSync(PKCE_FILE) ? JSON.parse(fs.readFileSync(PKCE_FILE, "utf-8")) : {};
  store[state] = { verifier: codeVerifier, ts: Date.now() };
  fs.writeFileSync(PKCE_FILE, JSON.stringify(store, null, 2));

  const params = new URLSearchParams({
    response_type: "code",
    client_id: KICK_CLIENT_ID,
    redirect_uri: KICK_REDIRECT_URI,
    scope: "user:read channel:read chat:write events:subscribe",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state
  });
  res.redirect(`https://id.kick.com/oauth/authorize?${params.toString()}`);
});

// OAuth callback
app.get("/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const store = fs.existsSync(PKCE_FILE) ? JSON.parse(fs.readFileSync(PKCE_FILE, "utf-8")) : {};
    const codeVerifier = state ? store[String(state)]?.verifier : null;
    if (!code || !codeVerifier) return res.status(400).send("Brak code/code_verifier (uruchom /auth/start jeszcze raz).");

    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      redirect_uri: KICK_REDIRECT_URI,
      code_verifier: codeVerifier,
      code: String(code)
    });

    const { data } = await axios.post("https://id.kick.com/oauth/token", params, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000
    });

    tokens.access_token = data.access_token;
    tokens.refresh_token = data.refresh_token;
    tokens.expires_at = Math.floor(Date.now()/1000) + (data.expires_in || 3600);
    await saveTokensEverywhere();

    res.send("OK – tokeny zapisane (KV). Możesz zamknąć tę kartę.");
  } catch (e) {
    console.error("Callback error detail:", e.response?.data || e.message);
    res.status(500).send("Błąd callback: " + (e.response?.data?.error_description || e.message));
  }
});

// Subskrypcja eventów (POST)
app.post("/subscribe", async (req, res) => {
  try {
    const token = await refreshIfNeeded();
    const { data } = await axios.post("https://api.kick.com/public/v1/events/subscriptions", {
      events: [{ name: "livestream.status.updated", version: 1 }],
      method: "webhook"
    }, { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 });
    res.json({ ok: true, created: data?.data || null });
  } catch (e) {
    res.status(e?.response?.status || 500).json({ ok: false, error: e?.response?.data || e.message });
  }
});

// Opcjonalny GET-fallback do klikania w przeglądarce
app.get("/subscribe", async (req, res) => {
  try {
    if (SUBSCRIBE_KEY) {
      if (req.query.key !== SUBSCRIBE_KEY) return res.status(403).send("Forbidden");
    } else {
      return res.status(405).send("Use POST /subscribe or set SUBSCRIBE_KEY to enable GET.");
    }
    const token = await refreshIfNeeded();
    const { data } = await axios.post("https://api.kick.com/public/v1/events/subscriptions", {
      events: [{ name: "livestream.status.updated", version: 1 }],
      method: "webhook"
    }, { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 });
    res.json({ ok: true, created: data?.data || null });
  } catch (e) {
    res.status(e?.response?.status || 500).json({ ok: false, error: e?.response?.data || e.message });
  }
});

// Health
app.get("/health", (req, res) => res.send("ok"));

/* ===== Admin: wysyłka testowa ===== */
app.get("/admin/send", async (req, res) => {
  try {
    const key = req.query.key || req.get("X-Admin-Key");
    if (!ADMIN_KEY || key !== ADMIN_KEY) return res.status(403).send("Forbidden");

    const slug = String(req.query.slug || allowedSlugs[0] || "").trim();
    const msg  = String(req.query.msg  || "TEST 👋").substring(0, 280);
    if (!slug) return res.status(400).json({ error: "Brak slug" });
    if (!allowedSlugs.includes(slug)) return res.status(403).json({ error: "Slug poza ALLOWED_SLUGS" });

    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id;
    if (!id) return res.status(404).json({ error: `Kanał ${slug} nie znaleziony` });

    await sendChatMessage({ broadcaster_user_id: id, content: msg, type: "user" });
    return res.json({ ok: true, sent_to: { slug, id }, msg });
  } catch (e) {
    return res.status(e?.response?.status || 500).json({ ok: false, status: e?.response?.status, data: e?.response?.data || e.message });
  }
});

/* ===== Admin: podejrzyj refresh (jednorazowo, z kluczem) ===== */
app.get("/admin/peek-refresh", async (req, res) => {
  try {
    if (!ADMIN_KEY || req.query.key !== ADMIN_KEY) return res.status(403).send("Forbidden");
    return res.json({ refresh_token: tokens?.refresh_token || null });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ===== Start serwera ===== */
await loadTokensOnBoot();

app.listen(PORT, async () => {
  console.log(`kick-auto-chat listening on :${PORT}`);
  setInterval(pollingTick, pollMs);
  pollingTick();
});
