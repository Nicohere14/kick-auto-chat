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
  KICK_CLIENT_ID,
  KICK_CLIENT_SECRET,
  KICK_REDIRECT_URI,
  ALLOWED_SLUGS = "",
  CHAT_MESSAGE = "Cześć czacie! 👋",
  CHAT_MESSAGES_JSON = "",
  INTERVAL_MINUTES = "5",
  JITTER_SECONDS = "30,60",
  POLL_SECONDS = "120",
  VERIFY_WEBHOOK_SIGNATURE = "false",
  // poniższe do obsługi bez Shell'a
  KICK_REFRESH_TOKEN = "",
  ADMIN_KEY = "",
  SUBSCRIBE_KEY = "",
  DATA_DIR = ".", // ustaw np. /data gdy używasz persistent disk
} = process.env;

/* ===== Katalog na pliki ===== */
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

/* ===== Ustawienia interwałów ===== */
const allowedSlugs = ALLOWED_SLUGS.split(",").map(s => s.trim()).filter(Boolean);
const intervalMs = Math.max(1, Number(INTERVAL_MINUTES)) * 60_000;
const [jMinRaw, jMaxRaw] = (JITTER_SECONDS || "30,60").split(",");
const jMin = Math.abs(Number(jMinRaw || 30));
const jMax = Math.abs(Number(jMaxRaw || 60));
const jitterMs = () =>
  (Math.floor(Math.random() * (Math.max(jMin, jMax) - Math.min(jMin, jMax) + 1)) + Math.min(jMin, jMax)) * 1000;
const pollMs = Math.max(30, Number(POLL_SECONDS)) * 1000;

/* ===== Rotacja wiadomości ===== */
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

/* ===== Tokeny i PKCE ===== */
const TOKENS_FILE = path.join(DATA_DIR, "tokens.json");
let tokens = fs.existsSync(TOKENS_FILE)
  ? JSON.parse(fs.readFileSync(TOKENS_FILE, "utf-8"))
  : { access_token: null, refresh_token: null, expires_at: 0 };

// Fallback: jeśli plik zniknął po redeployu, weź refresh z ENV
if (!tokens.refresh_token && KICK_REFRESH_TOKEN) {
  tokens.refresh_token = KICK_REFRESH_TOKEN.trim();
}

let appToken = { token: null, expires_at: 0 };
const postingLoops = new Map(); // broadcaster_user_id -> controller

const PKCE_FILE = path.join(DATA_DIR, "pkce.json");
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
  tokens.refresh_token = data.refresh_token;
  tokens.expires_at = Math.floor(Date.now()/1000) + (data.expires_in || 3600);
  fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
  return tokens.access_token;
}

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
  const list = (Array.isArray(slugs) ? slugs : [slugs])
    .map(s => String(s || "").trim())
    .filter(Boolean);

  if (list.length === 0) return [];

  const token = await getAppToken();
  const base = "https://api.kick.com/public/v1/channels";
  const headers = { Authorization: `Bearer ${token}` };
  const timeout = 15000;

  // 1) path /channels/{slug}
  if (list.length === 1) {
    const slug = encodeURIComponent(list[0]);
    try {
      const { data } = await axios.get(`${base}/${slug}`, { headers, timeout });
      const ch = data?.data || data;
      if (ch) return [ch];
    } catch (e) {
      if (e?.response?.status && e.response.status !== 404) throw e;
    }
  }

  // 2) query ?slug=a&slug=b
  try {
    const qs = list.map(s => `slug=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${base}?${qs}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) return data.data;
  } catch (_) {}

  // 3) query ?slug[]=a&slug[]=b
  try {
    const qsArr = list.map(s => `slug[]=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${base}?${qsArr}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) return data.data;
  } catch (_) {}

  return [];
}

async function sendChatMessage({ broadcaster_user_id, content, type = "user" }) {
  const token = await refreshIfNeeded();
  await axios.post("https://api.kick.com/public/v1/chat", {
    broadcaster_user_id, content, type
  }, { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 });
}

/* ===== Pętla wysyłek ===== */
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

  const controller = { cancel: () => { cancelled = true; } };
  postingLoops.set(broadcaster_user_id, controller);
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

// webhook od Kick (start/stop pętli)
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

// fallback: okresowe sprawdzanie LIVE
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
  setPkce(state, codeVerifier);

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
    const codeVerifier = state ? getPkce(String(state)) : null;
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
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 15000
    });

    tokens.access_token = data.access_token;
    tokens.refresh_token = data.refresh_token;
    tokens.expires_at = Math.floor(Date.now()/1000) + (data.expires_in || 3600);
    fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));

    res.send("OK – tokeny zapisane. Możesz zamknąć tę kartę.");
  } catch (e) {
    console.error("Callback error detail:", e.response?.data || e.message);
    res.status(500).send("Błąd callback: " + (e.response?.data?.error_description || e.message));
  }
});

// subskrypcja eventów (POST – właściwy)
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

// opcjonalny GET-fallback do kliknięcia w przeglądarce (zabezpieczony kluczem)
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

// health
app.get("/health", (req, res) => res.send("ok"));

/* ===== ADMIN: jednorazowy podgląd refresh_token (z kluczem) ===== */
app.get("/admin/peek-refresh", (req, res) => {
  try {
    if (!ADMIN_KEY || req.query.key !== ADMIN_KEY) return res.status(403).send("Forbidden");
    if (!fs.existsSync(TOKENS_FILE)) return res.status(404).json({ error: "tokens.json not found" });
    const raw = JSON.parse(fs.readFileSync(TOKENS_FILE, "utf-8"));
    if (!raw?.refresh_token) return res.status(404).json({ error: "no refresh_token in file" });
    res.json({ refresh_token: raw.refresh_token });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ===== Boot ===== */
app.listen(PORT, async () => {
  console.log(`kick-auto-chat listening on :${PORT}`);
  setInterval(pollingTick, pollMs);
  pollingTick();
});
