import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { io } from "socket.io-client";

/* =========================
 * UA / nagłówki „jak przeglądarka”
 * ========================= */
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

const JSON_HEADERS = {
  "User-Agent": UA,
  "Accept": "application/json, text/plain, */*",
  "Referer": "https://kick.com/",
};

const HTML_HEADERS = {
  "User-Agent": UA,
  "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Referer": "https://kick.com/",
};

/* =========================
 * ENV
 * ========================= */
const {
  PORT = 3000,

  KICK_CLIENT_ID,
  KICK_CLIENT_SECRET,
  KICK_REDIRECT_URI,

  ALLOWED_SLUGS = "",

  // Wiadomości (jedna lub lista)
  CHAT_MESSAGE = "Cześć czacie!",
  CHAT_MESSAGES_JSON = "",
  CHAT_MESSAGES_B64 = "",
  MSG_NO_REPEAT_COUNT = "8",

  // Harmonogram
  INTERVAL_MINUTES = "5",
  JITTER_SECONDS = "30,60",
  POLL_SECONDS = "60",

  // NOWE: losowy zakres (minuty) – nadpisuje fallback gdy ustawione
  RAND_MIN_MINUTES = "",
  RAND_MAX_MINUTES = "",

  // Webhook security
  VERIFY_WEBHOOK_SIGNATURE = "false",

  // Admin / pomocnicze
  ADMIN_KEY = "",
  SUBSCRIBE_KEY = "",

  DATA_DIR = ".",

  // KV (opcjonalnie)
  UPSTASH_REDIS_REST_URL = "",
  UPSTASH_REDIS_REST_TOKEN = "",

  // Awaryjny refresh z ENV (opcjonalnie)
  KICK_REFRESH_TOKEN = "",

  // Echo spamu (WS)
  CMD_ECHO_ENABLED = "true",
  CMD_ECHO_MIN_RUN = "5",
  CMD_ECHO_COOLDOWN_SECONDS = "60",
  CMD_ECHO_EXCLUDE = "!points",

  // NOWE: ręczne nadpisanie chatroom_id (np. "rybsonlol:2968509,holly-s:123456")
  CHATROOM_ID_OVERRIDES = "",
} = process.env;

/* ---- Parsowanie CHATROOM_ID_OVERRIDES ---- */
const CHATROOM_OVERRIDES = String(CHATROOM_ID_OVERRIDES || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean)
  .reduce((acc, pair) => {
    const [slug, id] = pair.split(":").map((x) => (x || "").trim());
    if (slug && id && /^\d+$/.test(id)) acc[slug.toLowerCase()] = Number(id);
    return acc;
  }, {});

/* =========================
 * STORAGE
 * ========================= */
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const TOKENS_FILE = path.join(DATA_DIR, "tokens.json");
const PKCE_FILE = path.join(DATA_DIR, "pkce.json");

/* =========================
 * KONFIG
 * ========================= */
const allowedSlugs = ALLOWED_SLUGS.split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

const intervalMs = Math.max(1, Number(INTERVAL_MINUTES)) * 60_000;
const [jMinRaw, jMaxRaw] = (JITTER_SECONDS || "30,60").split(",");
const jMin = Math.abs(Number(jMinRaw || 30));
const jMax = Math.abs(Number(jMaxRaw || 60));
const jitterMs = () =>
  (Math.floor(Math.random() * (Math.max(jMin, jMax) - Math.min(jMin, jMax) + 1)) + Math.min(jMin, jMax)) * 1000;


// === Losowy harmonogram ===
// Jeśli ustawione RAND_* → używamy PRAWDZIWEGO randomu (min..max minut).
// W przeciwnym razie fallback: INTERVAL_MINUTES + JITTER_SECONDS.
const useRandInterval = String(RAND_MIN_MINUTES).trim() !== "" && String(RAND_MAX_MINUTES).trim() !== "";
function nextDelayMs() {
  if (useRandInterval) {
    const lo = Math.min(Number(RAND_MIN_MINUTES) || 0, Number(RAND_MAX_MINUTES) || 0);
    const hi = Math.max(Number(RAND_MIN_MINUTES) || 0, Number(RAND_MAX_MINUTES) || 0);
    const secs = Math.floor(Math.random() * ((hi * 60) - (lo * 60) + 1)) + (lo * 60);
    const ms = secs * 1000;
    console.log(`Next message in ~${(ms / 60000).toFixed(1)} min`);
    return ms;
  }
  const ms = intervalMs + jitterMs();
  console.log(`Next message in ~${(ms / 60000).toFixed(1)} min (fallback interval+jitter)`);
  return ms;
}

const pollMs = Math.max(30, Number(POLL_SECONDS)) * 1000;

/* =========================
 * WIADOMOŚCI (bez dopinek)
 * ========================= */
function decodeB64Lines(b64) {
  try {
    const raw = Buffer.from(b64, "base64").toString("utf-8");
    return raw.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

let baseMessages = [];
let source = "CHAT_MESSAGE";

if (CHAT_MESSAGES_B64) {
  baseMessages = decodeB64Lines(CHAT_MESSAGES_B64);
  source = "CHAT_MESSAGES_B64";
}
if (!baseMessages.length && CHAT_MESSAGES_JSON) {
  try {
    const arr = JSON.parse(CHAT_MESSAGES_JSON);
    if (Array.isArray(arr) && arr.length) {
      baseMessages = arr.map(String);
      source = "CHAT_MESSAGES_JSON";
    }
  } catch {
    console.warn("CHAT_MESSAGES_JSON parse error – pomijam.");
  }
}
if (!baseMessages.length) baseMessages = [String(CHAT_MESSAGE)];

console.log(`Loaded ${baseMessages.length} messages from ${source}`);

function shuffle(a) {
  const r = a.slice();
  for (let i = r.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [r[i], r[j]] = [r[j], r[i]];
  }
  return r;
}

function normalizeMsg(s) {
  let t = s.toLowerCase();
  t = t.replace(/:[a-z0-9_]+:?/gi, ""); // np. :points
  t = t.replace(/[^\p{L}\p{N}]+/gu, ""); // wywal interpunkcję/emoji
  t = t.replace(/(.)\1{2,}/g, "$1$1"); // xddddd -> xdd
  return t.trim();
}

const tinySyn = new Map([
  ["xd", ["xd", "xD", "XD", "XDD"]],
  ["gg", ["gg", "GG"]],
  ["wp", ["wp", "WP"]],
  ["kekw", ["KEKW", "kekw"]],
]);

function variate(s) {
  const key = normalizeMsg(s);
  if (tinySyn.has(key)) {
    const arr = tinySyn.get(key);
    return arr[Math.floor(Math.random() * arr.length)];
  }
  return s;
}

const noRepeatCount = Math.max(2, Number(MSG_NO_REPEAT_COUNT) || 8);
const recentByChannel = new Map(); // id -> {list,set}
const bagByChannel = new Map(); // id -> [msgs]

function getRecent(id) {
  if (!recentByChannel.has(id)) recentByChannel.set(id, { list: [], set: new Set() });
  return recentByChannel.get(id);
}
function remember(id, norm) {
  const mem = getRecent(id);
  if (!mem.set.has(norm)) {
    mem.list.push(norm);
    mem.set.add(norm);
    while (mem.list.length > noRepeatCount) {
      const old = mem.list.shift();
      mem.set.delete(old);
    }
  }
}
function nextFromBag(id) {
  let bag = bagByChannel.get(id);
  if (!bag || !bag.length) {
    bag = shuffle(baseMessages);
    bagByChannel.set(id, bag);
  }
  return bag.shift();
}
function nextMessageFor(id) {
  for (let i = 0; i < baseMessages.length + 3; i++) {
    const raw = nextFromBag(id) || baseMessages[Math.floor(Math.random() * baseMessages.length)];
    const variant = variate(raw);
    const norm = normalizeMsg(variant);
    const mem = getRecent(id);
    if (!mem.set.has(norm)) {
      remember(id, norm);
      return variant;
    }
  }
  const fallback = variate(baseMessages[Math.floor(Math.random() * baseMessages.length)]);
  remember(id, normalizeMsg(fallback));
  return fallback;
}

/* =========================
 * KV (Upstash) – opcjonalnie
 * ========================= */
const TOKENS_KV_KEY = "kick_tokens_v1";

async function kvGet(key) {
  if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) return null;
  const r = await fetch(`${UPSTASH_REDIS_REST_URL}/get/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${UPSTASH_REDIS_REST_TOKEN}` },
  });
  if (!r.ok) return null;
  const j = await r.json();
  try {
    return j?.result ? JSON.parse(j.result) : null;
  } catch {
    return null;
  }
}
async function kvSet(key, obj) {
  if (!UPSTASH_REDIS_REST_URL || !UPSTASH_REDIS_REST_TOKEN) return;
  const val = encodeURIComponent(JSON.stringify(obj));
  await fetch(`${UPSTASH_REDIS_REST_URL}/set/${encodeURIComponent(key)}/${val}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${UPSTASH_REDIS_REST_TOKEN}` },
  }).catch(() => {});
}

/* =========================
 * TOKENY
 * ========================= */
let tokens = { access_token: null, refresh_token: null, expires_at: 0 };

function saveTokensToFile() {
  try {
    fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
  } catch {}
}
async function saveTokensEverywhere() {
  saveTokensToFile();
  await kvSet(TOKENS_KV_KEY, tokens);
}
async function loadTokensOnBoot() {
  const fromKv = await kvGet(TOKENS_KV_KEY);
  if (fromKv && fromKv.refresh_token) {
    tokens = fromKv;
    return;
  }
  if (fs.existsSync(TOKENS_FILE)) {
    try {
      const f = JSON.parse(fs.readFileSync(TOKENS_FILE, "utf-8"));
      if (f?.refresh_token) tokens = f;
    } catch {}
  }
  if (!tokens.refresh_token && KICK_REFRESH_TOKEN) tokens.refresh_token = KICK_REFRESH_TOKEN.trim();
}

/* =========================
 * EXPRESS
 * ========================= */
const app = express();
app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);
app.use(
  bodyParser.urlencoded({
    extended: true,
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

/* =========================
 * OAUTH HELPERS
 * ========================= */
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
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 15000,
  });

  tokens.access_token = data.access_token;
  tokens.refresh_token = data.refresh_token;
  tokens.expires_at = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);
  await saveTokensEverywhere();
  return tokens.access_token;
}

let appToken = { token: null, expires_at: 0 };
async function getAppToken() {
  const now = Math.floor(Date.now() / 1000);
  if (appToken.token && now < Number(appToken.expires_at || 0) - 60) return appToken.token;

  const params = new URLSearchParams();
  params.append("grant_type", "client_credentials");
  params.append("client_id", KICK_CLIENT_ID);
  params.append("client_secret", KICK_CLIENT_SECRET);

  const { data } = await axios.post("https://id.kick.com/oauth/token", params, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 15000,
  });

  appToken.token = data.access_token;
  appToken.expires_at = now + (data.expires_in || 3600);
  return appToken.token;
}

/* =========================
 * API HELPERS
 * ========================= */
const channelIdCache = new Map(); // slug -> broadcaster_user_id

async function getChannelsBySlugs(slugs) {
  const list = (Array.isArray(slugs) ? slugs : [slugs])
    .map((s) => String(s || "").trim().toLowerCase())
    .filter(Boolean);
  if (!list.length) return [];
  const token = await getAppToken();
  const base = "https://api.kick.com/public/v1/channels";
  const headers = { Authorization: `Bearer ${token}` };
  const timeout = 15000;

  if (list.length === 1) {
    const slug = encodeURIComponent(list[0]);
    try {
      const { data } = await axios.get(`${base}/${slug}`, { headers, timeout });
      const ch = data?.data || data;
      if (ch) {
        channelIdCache.set(ch.slug || list[0], ch.broadcaster_user_id);
        return [ch];
      }
    } catch (e) {
      if (e?.response?.status && e.response.status !== 404) throw e;
    }
  }

  try {
    const qs = list.map((s) => `slug=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${base}?${qs}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) {
      for (const ch of data.data) channelIdCache.set(ch.slug, ch.broadcaster_user_id);
      return data.data;
    }
  } catch {}
  try {
    const qs = list.map((s) => `slug[]=${encodeURIComponent(s)}`).join("&");
    const { data } = await axios.get(`${base}?${qs}`, { headers, timeout });
    if (Array.isArray(data?.data) && data.data.length) {
      for (const ch of data.data) channelIdCache.set(ch.slug, ch.broadcaster_user_id);
      return data.data;
    }
  } catch {}
  return [];
}

async function sendChatMessage({ broadcaster_user_id, content, type = "user" }) {
  const token = await refreshIfNeeded();
  await axios.post(
    "https://api.kick.com/public/v1/chat",
    { broadcaster_user_id, content, type },
    { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 }
  );
  markEchoSent(broadcaster_user_id, content);
}

/* =========================
 * PĘTLA WIADOMOŚCI
 * ========================= */
const postingLoops = new Map();

function startPostingLoop(broadcaster_user_id, type = "user") {
  if (postingLoops.has(broadcaster_user_id)) return;
  let cancelled = false;

  const tick = async () => {
    if (cancelled) return;
    try {
      const msg = nextMessageFor(broadcaster_user_id);
      await sendChatMessage({ broadcaster_user_id, content: msg, type });
      console.log(
        new Date().toISOString(),
        "sent { broadcaster_user_id:",
        broadcaster_user_id,
        ", msg: '",
        msg,
        "' }"
      );
    } catch (e) {
      const status = e?.response?.status;
      const detail = e?.response?.data || e.message;
      console.error("Chat send error", status, detail);
      if (status === 401 || status === 403) {
        stopPostingLoop(broadcaster_user_id);
        return;
      }
    } finally {
      if (!cancelled) setTimeout(tick, nextDelayMs());
    }
  };

  postingLoops.set(broadcaster_user_id, { cancel: () => (cancelled = true) });
  setTimeout(tick, nextDelayMs());
  console.log("Posting loop START", broadcaster_user_id);

  const slug =
    [...channelIdCache.entries()].find(([, id]) => id === broadcaster_user_id)?.[0] ||
    allowedSlugs.find(Boolean);
  if (slug) ensureWsListener(slug, broadcaster_user_id);
}
function stopPostingLoop(broadcaster_user_id) {
  const c = postingLoops.get(broadcaster_user_id);
  if (c) {
    c.cancel();
    postingLoops.delete(broadcaster_user_id);
    console.log("Posting loop STOP", broadcaster_user_id);
  }
}

/* =========================
 * WEBHOOK SECURITY (opcjonalne)
 * ========================= */
let cachedPublicKey = null;
async function getKickPublicKey() {
  if (cachedPublicKey) return cachedPublicKey;
  try {
    const { data } = await axios.get("https://api.kick.com/public/v1/public-key", { timeout: 15000 });
    cachedPublicKey = data?.data?.public_key || null;
  } catch (e) {
    console.warn("Unable to fetch Kick public key:", e.message);
  }
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
    verifier.update(payload);
    verifier.end();
    return verifier.verify(pubKeyPem, signature);
  } catch (e) {
    console.error("Signature verify error:", e.message);
    return false;
  }
}

/* =========================
 * ECHO SPAMU (WS)
 * ========================= */
const echoEnabled = String(CMD_ECHO_ENABLED).toLowerCase() === "true";
const echoMinRun = Math.max(2, Number(CMD_ECHO_MIN_RUN) || 5);
const echoCooldownMs = Math.max(5, Number(CMD_ECHO_COOLDOWN_SECONDS) || 60) * 1000;
const echoExclude = new Set(
  (CMD_ECHO_EXCLUDE || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)
);

const echoStateByChannel = new Map(); // id -> { current, count, lastSentAt }
const echoRecentSent = new Map(); // id -> Map<content, ts>
function markEchoSent(id, content) {
  const m = echoRecentSent.get(id) || new Map();
  m.set(content, Date.now());
  for (const [msg, ts] of m) if (Date.now() - ts > 30_000) m.delete(msg);
  echoRecentSent.set(id, m);
}
function wasEchoSentRecently(id, content) {
  const m = echoRecentSent.get(id);
  if (!m) return false;
  const ts = m.get(content);
  return Boolean(ts && Date.now() - ts < 30_000);
}

/* =========================
 * WEBHOOK (tylko LIVE on/off)
 * ========================= */
app.post("/webhook", async (req, res) => {
  try {
    await getKickPublicKey();
    if (!verifyWebhookSignature(req)) return res.status(401).send("Invalid signature");

    const eventType = req.get("Kick-Event-Type");
    if (eventType === "livestream.status.updated") {
      const { broadcaster, is_live } = req.body || {};
      const id = broadcaster?.user_id;
      const slug = String(broadcaster?.channel_slug || "").toLowerCase();
      if (id && allowedSlugs.includes(slug)) {
        if (is_live) startPostingLoop(id);
        else stopPostingLoop(id);
      }
      return res.sendStatus(200);
    }

    res.sendStatus(200);
  } catch (e) {
    console.error("Webhook error:", e.message);
    res.sendStatus(500);
  }
});

/* =========================
 * POLLING LIVE – fallback
 * ========================= */
async function pollingTick() {
  try {
    if (!allowedSlugs.length) return;
    const chans = await getChannelsBySlugs(allowedSlugs);
    for (const ch of chans) {
      const id = ch.broadcaster_user_id;
      const slug = String(ch.slug || "").toLowerCase();
      const isLive = ch.stream?.is_live === true;
      if (isLive) {
        channelIdCache.set(slug, id);
        startPostingLoop(id);
        ensureWsListener(slug, id);
      } else {
        stopPostingLoop(id);
      }
    }
  } catch (e) {
    console.error("Polling error:", e.message);
  }
}

/* =========================
 * OAUTH FLOW
 * ========================= */
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
    state,
  });
  res.redirect(`https://id.kick.com/oauth/authorize?${params.toString()}`);
});

app.get("/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const store = fs.existsSync(PKCE_FILE) ? JSON.parse(fs.readFileSync(PKCE_FILE, "utf-8")) : {};
    const codeVerifier = state ? store[String(state)]?.verifier : null;
    if (!code || !codeVerifier)
      return res.status(400).send("Brak code/code_verifier (uruchom /auth/start jeszcze raz).");

    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      redirect_uri: KICK_REDIRECT_URI,
      code_verifier: codeVerifier,
      code: String(code),
    });

    const { data } = await axios.post("https://id.kick.com/oauth/token", params, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 15000,
    });

    tokens.access_token = data.access_token;
    tokens.refresh_token = data.refresh_token;
    tokens.expires_at = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);
    await saveTokensEverywhere();

    res.send("OK – tokeny zapisane. Możesz zamknąć kartę.");
  } catch (e) {
    console.error("Callback error detail:", e.response?.data || e.message);
    res.status(500).send("Błąd callback: " + (e.response?.data?.error_description || e.message));
  }
});

/* =========================
 * SUBSKRYPCJA (tylko LIVE)
 * ========================= */
app.post("/subscribe", async (req, res) => {
  try {
    const token = await refreshIfNeeded();
    const { data } = await axios.post(
      "https://api.kick.com/public/v1/events/subscriptions",
      {
        events: [{ name: "livestream.status.updated", version: 1 }],
        method: "webhook",
      },
      { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 }
    );
    res.json({ ok: true, created: data?.data || null });
  } catch (e) {
    res
      .status(e?.response?.status || 500)
      .json({ ok: false, error: e?.response?.data || e.message });
  }
});

app.get("/subscribe", async (req, res) => {
  try {
    if (SUBSCRIBE_KEY) {
      if (req.query.key !== SUBSCRIBE_KEY) return res.status(403).send("Forbidden");
    } else {
      return res.status(405).send("Use POST /subscribe or set SUBSCRIBE_KEY to enable GET.");
    }
    const token = await refreshIfNeeded();
    const { data } = await axios.post(
      "https://api.kick.com/public/v1/events/subscriptions",
      {
        events: [{ name: "livestream.status.updated", version: 1 }],
        method: "webhook",
      },
      { headers: { Authorization: `Bearer ${token}` }, timeout: 15000 }
    );
    res.json({ ok: true, created: data?.data || null });
  } catch (e) {
    res
      .status(e?.response?.status || 500)
      .json({ ok: false, error: e?.response?.data || e.message });
  }
});

/* =========================
 * HEALTH & ADMIN
 * ========================= */
app.get("/health", (req, res) => res.send("ok"));

app.get("/admin/send", async (req, res) => {
  try {
    const key = req.query.key || req.get("X-Admin-Key");
    if (!ADMIN_KEY || key !== ADMIN_KEY) return res.status(403).send("Forbidden");

    const slug = String(req.query.slug || allowedSlugs[0] || "").toLowerCase();
    const msg = String(req.query.msg || "TEST").substring(0, 280);
    if (!slug) return res.status(400).json({ error: "Brak slug" });
    if (!allowedSlugs.includes(slug)) return res.status(403).json({ error: "Slug poza ALLOWED_SLUGS" });

    const chans = await getChannelsBySlugs([slug]);
    const id = chans?.[0]?.broadcaster_user_id;
    if (!id) return res.status(404).json({ error: `Kanał ${slug} nie znaleziony` });

    await sendChatMessage({ broadcaster_user_id: id, content: msg, type: "user" });
    return res.json({ ok: true, sent_to: { slug, id }, msg });
  } catch (e) {
    return res
      .status(e?.response?.status || 500)
      .json({ ok: false, status: e?.response?.status, data: e?.response?.data || e.message });
  }
});

app.get("/admin/peek-refresh", async (req, res) => {
  try {
    if (!ADMIN_KEY || req.query.key !== ADMIN_KEY) return res.status(403).send("Forbidden");
    return res.json({ refresh_token: tokens?.refresh_token || null });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* =========================
 * DIAGNOSTYKA CHATROOM (z UA + HTML)
 * ========================= */
app.get("/admin/debug-chatroom", async (req, res) => {
  try {
    if (!ADMIN_KEY || req.query.key !== ADMIN_KEY) return res.status(403).send("Forbidden");
    const slug = String(req.query.slug || "").toLowerCase();
    if (!slug) return res.status(400).json({ error: "Brak slug" });

    const out = { slug };

    try {
      const { data } = await axios.get(
        `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`,
        { timeout: 15000, headers: JSON_HEADERS }
      );
      out.v2_chatroom = data?.chatroom?.id ?? data?.data?.chatroom?.id ?? null;
      out.v2_user_id = data?.user_id ?? data?.data?.user_id ?? null;
    } catch (e) {
      out.v2_error = String(e?.response?.status || e.message);
    }

    try {
      const { data } = await axios.get(
        `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/chatroom`,
        { timeout: 15000, headers: JSON_HEADERS }
      );
      out.endpoint_chatroom = data ?? null;
    } catch (e) {
      out.endpoint_chatroom_error = String(e?.response?.status || e.message);
    }

    try {
      const { data: html } = await axios.get(`https://kick.com/${encodeURIComponent(slug)}`, {
        timeout: 15000,
        headers: HTML_HEADERS,
        responseType: "text",
      });
      let m = /"chatroom"\s*:\s*\{\s*"id"\s*:\s*(\d+)/.exec(html);
      if (!m) m = /"chatroom_id"\s*:\s*(\d+)/.exec(html);
      out.html_chatroom = m ? Number(m[1]) : null;

      const u = /"user_id"\s*:\s*(\d+)/.exec(html);
      out.html_user_id = u ? Number(u[1]) : null;
    } catch (e) {
      out.html_error = String(e?.response?.status || e.message);
    }

    res.json(out);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* =========================
 * WS CZATU – override + pobieranie chatroom_id
 * ========================= */
const wsBySlug = new Map();
const missingChatLogOnce = new Set();

async function getChannelWithChatroom(slug) {
  // 0) NAJPIERW: override z ENV – omija 403/WAF i nie pyta Kicka
  const ov = CHATROOM_OVERRIDES[slug];
  if (ov) {
    let ch = (await getChannelsBySlugs([slug]))?.[0] || null;
    if (!ch) ch = { slug, broadcaster_user_id: channelIdCache.get(slug) ?? null };
    return { ch, chatroom_id: ov };
  }

  let ch = null;
  let chatroom_id = null;

  // 1) public API
  try {
    ch = (await getChannelsBySlugs([slug]))?.[0] || null;
    chatroom_id = ch?.chatroom?.id ?? ch?.chatroom_id ?? null;
  } catch {}

  // 2) frontowy endpoint JSON – z UA
  if (!chatroom_id) {
    try {
      const { data } = await axios.get(
        `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`,
        { timeout: 15000, headers: JSON_HEADERS }
      );
      chatroom_id = data?.chatroom?.id ?? data?.data?.chatroom?.id ?? null;
      if (!ch && data) {
        ch = {
          slug,
          broadcaster_user_id:
            data?.user_id ?? data?.data?.user_id ?? channelIdCache.get(slug) ?? null,
        };
      }
    } catch {}
  }

  // 3) ten sam endpoint jako TEXT + regex – z UA
  if (!chatroom_id) {
    try {
      const { data: raw } = await axios.get(
        `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}`,
        { timeout: 15000, headers: HTML_HEADERS, responseType: "text" }
      );
      let m = /"chatroom"\s*:\s*\{\s*"id"\s*:\s*(\d+)/.exec(raw);
      if (!m) m = /"chatroom_id"\s*:\s*(\d+)/.exec(raw);
      if (m) chatroom_id = Number(m[1]);
    } catch {}
  }

  // 4) osobny endpoint /chatroom – z UA
  if (!chatroom_id) {
    try {
      const { data } = await axios.get(
        `https://kick.com/api/v2/channels/${encodeURIComponent(slug)}/chatroom`,
        { timeout: 15000, headers: JSON_HEADERS }
      );
      chatroom_id = data?.id ?? null;
    } catch {}
  }

  // 5) fallback: HTML kanału – regex + user_id
  if (!chatroom_id) {
    try {
      const { data: html } = await axios.get(`https://kick.com/${encodeURIComponent(slug)}`, {
        timeout: 15000,
        headers: HTML_HEADERS,
        responseType: "text",
      });
      let m = /"chatroom"\s*:\s*\{\s*"id"\s*:\s*(\d+)/.exec(html);
      if (!m) m = /"chatroom_id"\s*:\s*(\d+)/.exec(html);
      if (m) chatroom_id = Number(m[1]);
      if (!ch) {
        const u = /"user_id"\s*:\s*(\d+)/.exec(html);
        ch = { slug, broadcaster_user_id: u ? Number(u[1]) : channelIdCache.get(slug) ?? null };
      }
    } catch {}
  }

  return { ch, chatroom_id };
}

function ensureWsListener(slugRaw, broadcaster_user_id) {
  if (!echoEnabled) return;
  const slug = String(slugRaw || "").toLowerCase();
  if (wsBySlug.has(slug)) return;

  getChannelWithChatroom(slug)
    .then(({ chatroom_id }) => {
      if (!chatroom_id) {
        if (!missingChatLogOnce.has(slug)) {
          console.warn(`Brak chatroom_id dla ${slug}`);
          missingChatLogOnce.add(slug);
        }
        setTimeout(() => {
          wsBySlug.delete(slug);
          ensureWsListener(slug, broadcaster_user_id);
        }, 60_000);
        return;
      }

      const socket = io("https://chat.kick.com", {
        transports: ["websocket"],
        forceNew: true,
        reconnection: true,
        reconnectionDelayMax: 15000,
      });
      wsBySlug.set(slug, socket);

      socket.on("connect", () => {
        try {
          socket.emit("SUBSCRIBE", { room: `chatrooms:${chatroom_id}` });
        } catch {}
        console.log(`WS connected for ${slug} (chatrooms:${chatroom_id})`);
      });

      socket.on("disconnect", () => console.log(`WS disconnected for ${slug}`));

      const onMsg = async (payload) => {
        try {
          const raw = payload?.content ?? payload?.message?.content ?? "";
          const content = String(raw || "").trim();
          if (!content) return;

          const lower = content.toLowerCase();
          if (!lower.startsWith("!")) return;
          if (echoExclude.has(lower)) return;
          if (wasEchoSentRecently(broadcaster_user_id, content)) return;

          const st = echoStateByChannel.get(broadcaster_user_id) || { current: "", count: 0, lastSentAt: 0 };
          if (st.current === lower) st.count += 1;
          else {
            st.current = lower;
            st.count = 1;
          }

          const now = Date.now();
          if (st.count >= echoMinRun && now - st.lastSentAt > echoCooldownMs) {
            try {
              await sendChatMessage({ broadcaster_user_id, content, type: "user" });
              st.lastSentAt = now;
              st.count = 0;
            } catch {}
          }
          echoStateByChannel.set(broadcaster_user_id, st);
        } catch {}
      };

      socket.on("message", onMsg);
      socket.on("chat_message", onMsg);
    })
    .catch(() => {});
}

/* =========================
 * START
 * ========================= */
await loadTokensOnBoot();

app.listen(PORT, () => {
  console.log(`kick-auto-chat listening on :${PORT}`);
  setInterval(pollingTick, pollMs);
  pollingTick();
});
