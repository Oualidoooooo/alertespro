// =====================================================================
//  AlertesPro – serveur en ligne (Cloudflare Worker + base de données D1)
//
//  - Comptes : inscription (sur invitation), connexion, réglages,
//    résultats sauvegardés pour chaque personne
//  - Un seul bot Telegram pour tout le monde : chaque compte envoie son
//    code secret au bot et reçoit SES alertes, calculées pour SON argent
//  - Protections : 1 % de risque par défaut (2 % max), stop du jour à -3 %,
//    3 trades en cours maximum, volume réduit si la marge est trop grande
//
//  À régler dans Cloudflare (le bouton « Deploy to Cloudflare » le fait) :
//    Base D1 reliée sous le nom :  DB
//    Secret                      :  TG_TOKEN (jeton du bot donné par @BotFather)
//    Secret facultatif           :  ROBOT_KEY (sinon calculée depuis TG_TOKEN)
// =====================================================================

const VERSION = "1.0";
const APP_URL = "https://oualidoooooo.github.io/Full-pizza/mt5-alertes/app/";
const TZ = "Europe/Paris";

const RISK_DEFAULT = 1;          // % du capital risqué par trade
const RISK_MIN = 0.25;
const RISK_MAX = 2;              // jamais plus : c'est ce qui évite de cramer un compte
const DAILY_STOP_PCT = 3;        // après -3 % dans la journée : plus de signaux jusqu'à demain
const MAX_OPEN = 3;              // trades en cours maximum par compte
const MARGIN_SHARE = 0.5;        // la marge d'un trade ne dépasse pas 50 % du capital
const LEVERAGE = { fx: 30, gold: 20, index: 20, other: 10, stock: 5, crypto: 2 }; // levier max d'un particulier (ESMA)
const SESSION_DAYS = 90;
const PBKDF2_ITER = 10000;
const ROBOT_ONLINE_SEC = 20 * 60;
const ROBOT_ALERT_SEC = 30 * 60;
const OPEN_WINDOW = 3 * 86400;
const MAX_TG_PER_EVENT = 45;     // Cloudflare gratuit : 50 requêtes sortantes par événement
const SEP = "━━━━━━━━━━━━━━━";

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pass_hash TEXT NOT NULL, pass_salt TEXT NOT NULL, capital REAL NOT NULL DEFAULT 1000, risk_pct REAL NOT NULL DEFAULT 1, markets TEXT NOT NULL DEFAULT '*', paused INTEGER NOT NULL DEFAULT 0, is_admin INTEGER NOT NULL DEFAULT 0, link_code TEXT UNIQUE, tg_chat TEXT UNIQUE, tg_name TEXT, stopped_until INTEGER NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0, reset_hash TEXT, reset_until INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, eid TEXT UNIQUE, sid TEXT, kind TEXT NOT NULL, sym TEXT, side TEXT, data TEXT NOT NULL, created INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS alerts_sid ON alerts(sid)",
  "CREATE TABLE IF NOT EXISTS deliveries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, alert_id INTEGER NOT NULL, sid TEXT, kind TEXT NOT NULL, sym TEXT, lot REAL NOT NULL DEFAULT 0, risk REAL NOT NULL DEFAULT 0, gain REAL NOT NULL DEFAULT 0, note TEXT, result TEXT, r REAL, money REAL, closed INTEGER, created INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS deliveries_user ON deliveries(user_id, id)",
  "CREATE INDEX IF NOT EXISTS deliveries_sid ON deliveries(sid)",
  "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, updated INTEGER NOT NULL)",
].join("\n");

let schemaReady = false;
let hookReady = false;

// =====================================================================
//  Outils
// =====================================================================
const now = () => Math.floor(Date.now() / 1000);
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS } });
const fail = (status, error) => json({ ok: false, error }, status);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const num = (v) => {
  if (v == null || v === "") return NaN;
  const n = typeof v === "number" ? v : parseFloat(String(v).replace(",", "."));
  return Number.isFinite(n) ? n : NaN;
};
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const round2 = (v) => Math.round(v * 100) / 100;

const NF = {};
function fmt(v, d = 2) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "–";
  const f = NF[d] || (NF[d] = new Intl.NumberFormat("fr-FR", { minimumFractionDigits: d, maximumFractionDigits: d }));
  return f.format(n);
}
// chiffre « propre » : 1 → "1", 0.5 → "0,5", 1.25 → "1,25"
const fmtShort = (v) => fmt(v, 2).replace(/,00$/, "").replace(/(,\d)0$/, "$1");
function px(v, dg) {
  const n = Number(v);
  if (v == null || v === "" || !Number.isFinite(n)) return "–";
  const d = Number.isFinite(dg) ? clamp(Math.round(dg), 0, 8) : 5;
  return n.toFixed(d);
}
const cur$ = (cur) => (!cur || cur === "EUR" ? "€" : cur);
function money(v, cur, sign = true) {
  const s = sign ? (v > 0.004 ? "+" : v < -0.004 ? "−" : "") : "";
  return s + fmt(Math.abs(v)) + " " + cur$(cur);
}

function randomCode(len, alphabet) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += alphabet[b % alphabet.length];
  return out;
}
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // sans I, O, 0, 1 (faciles à confondre)
const TOKEN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function sha256hex(text) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}
async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITER }, key, 256));
}
function sameText(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length || !a.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function robotKey(env) {
  if (env.ROBOT_KEY) return String(env.ROBOT_KEY);
  if (!env.TG_TOKEN) return "";
  return (await sha256hex(env.TG_TOKEN + ":alertespro-robot")).slice(0, 32);
}
async function webhookSecret(env) {
  return (await sha256hex((env.TG_TOKEN || "") + ":alertespro-webhook")).slice(0, 48);
}

// ------------------------------------------------------------ heure de Paris
let DTF = null;
function parisParts(ts) {
  DTF = DTF || new Intl.DateTimeFormat("fr-FR", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", weekday: "short", hourCycle: "h23" });
  const o = {};
  for (const p of DTF.formatToParts(new Date(ts * 1000))) o[p.type] = p.value;
  return o;
}
function hhmm(ts) {
  if (!Number.isFinite(ts) || ts <= 0) return "–";
  const p = parisParts(ts);
  return p.hour + ":" + p.minute;
}
function parisDayStart(ts) {
  const p = parisParts(ts);
  return ts - (+p.hour * 3600 + +p.minute * 60 + +p.second);
}
const nextParisMidnight = (ts) => parisDayStart(ts) + 86400;

// ------------------------------------------------------------ base de données
async function ensureSchema(env) {
  if (schemaReady) return;
  if (!env.DB) throw new Error("Base D1 non reliée (liaison « DB » manquante)");
  await env.DB.exec(SCHEMA);
  schemaReady = true;
}
async function kvGet(env, k) {
  const row = await env.DB.prepare("SELECT v, updated FROM kv WHERE k = ?").bind(k).first();
  if (!row) return null;
  try { return { value: JSON.parse(row.v), updated: row.updated }; } catch (e) { return null; }
}
async function kvSet(env, k, value) {
  await env.DB.prepare("INSERT INTO kv (k, v, updated) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated = excluded.updated")
    .bind(k, JSON.stringify(value), now()).run();
}
async function kvDel(env, k) {
  await env.DB.prepare("DELETE FROM kv WHERE k = ?").bind(k).run();
}
const userById = (env, id) => env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
async function allUsers(env) {
  return (await env.DB.prepare("SELECT * FROM users ORDER BY is_admin DESC, id").all()).results || [];
}
async function newCode(env, column, len) {
  let code = randomCode(len, CODE_ALPHABET);
  for (let i = 0; i < 5 && (await env.DB.prepare("SELECT id FROM users WHERE " + column + " = ?").bind(code).first()); i++) code = randomCode(len, CODE_ALPHABET);
  return code;
}
async function inviteCode(env) {
  const row = await kvGet(env, "invite");
  if (row && row.value && row.value.code) return row.value.code;
  const code = randomCode(6, CODE_ALPHABET);
  await kvSet(env, "invite", { code });
  return code;
}
async function robotStatus(env) {
  const st = await kvGet(env, "status");
  const v = st && st.value ? st.value : null;
  return { v, updated: st ? st.updated : 0, online: !!(st && now() - st.updated < ROBOT_ONLINE_SEC), rr: v && v.rr > 0 ? +v.rr : 2, cur: (v && v.cur) || "EUR" };
}

// =====================================================================
//  Telegram
// =====================================================================
async function tg(env, method, body) {
  const base = env.TG_API || "https://api.telegram.org";
  try {
    const r = await fetch(base + "/bot" + env.TG_TOKEN + "/" + method, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
    let j = null;
    try { j = await r.json(); } catch (e) {}
    return j || { ok: false, error_code: r.status };
  } catch (e) {
    return { ok: false, error_code: 0, description: String(e) };
  }
}

async function send(env, chat, text, extra) {
  const body = { chat_id: chat, text, parse_mode: "HTML", disable_web_page_preview: true, ...(extra || {}) };
  let r = await tg(env, "sendMessage", body);
  if (!r.ok && r.error_code === 429) {
    const wait = clamp((r.parameters && r.parameters.retry_after) || 1, 1, 5);
    await new Promise((res) => setTimeout(res, wait * 1000));
    r = await tg(env, "sendMessage", body);
  }
  if (!r.ok && (r.error_code === 403 || (r.error_code === 400 && /chat not found/i.test(r.description || "")))) {
    // la personne a bloqué ou supprimé le bot : on retire le lien (elle pourra le refaire depuis l'appli)
    await env.DB.prepare("UPDATE users SET tg_chat = NULL, tg_name = NULL WHERE tg_chat = ?").bind(String(chat)).run();
  }
  return r;
}

// outbox : liste de [chat, texte, extra]
async function sendAll(env, outbox) {
  const list = outbox.filter((m) => m && m[0]).slice(0, MAX_TG_PER_EVENT);
  for (let i = 0; i < list.length; i += 15) {
    await Promise.allSettled(list.slice(i, i + 15).map(([chat, text, extra]) => send(env, chat, text, extra)));
  }
}

const appButton = (label) => ({ reply_markup: { inline_keyboard: [[{ text: label || "📱 Ouvrir l'appli AlertesPro", url: APP_URL }]] } });

async function botUsername(env) {
  const cached = await kvGet(env, "bot");
  if (cached && cached.value && cached.value.username) return cached.value.username;
  if (!env.TG_TOKEN) return "";
  const me = await tg(env, "getMe", {});
  if (me.ok && me.result) {
    await kvSet(env, "bot", { username: me.result.username });
    return me.result.username;
  }
  return "";
}

async function registerBot(env, origin) {
  const me = await tg(env, "getMe", {});
  if (!me.ok) return { ok: false, step: "getMe", detail: me };
  await kvSet(env, "bot", { username: me.result.username });
  const hook = await tg(env, "setWebhook", { url: origin + "/telegram", secret_token: await webhookSecret(env), allowed_updates: ["message", "edited_message"], drop_pending_updates: true });
  if (!hook.ok) return { ok: false, step: "setWebhook", detail: hook, username: me.result.username };
  await tg(env, "setMyCommands", { commands: [
    { command: "moi", description: "Mon compte et mon bilan" },
    { command: "marches", description: "Ce que je risque et peux gagner sur chaque marché" },
    { command: "capital", description: "Changer mon capital (ex. /capital 1500)" },
    { command: "risque", description: "Risque par trade en % (0,25 à 2)" },
    { command: "pause", description: "Ne plus recevoir de signaux" },
    { command: "reprendre", description: "Recevoir de nouveau les signaux" },
    { command: "aide", description: "Liste des commandes" },
  ] });
  await tg(env, "setMyDescription", { description: "AlertesPro t'envoie les signaux ACHAT / VENTE du robot MT5, calculés pour TON argent : entrée, Stop Loss, Take Profit, volume, et combien tu peux perdre ou gagner. Crée ton compte dans l'appli puis relie ce Telegram." });
  await tg(env, "setMyShortDescription", { short_description: "Signaux de trading MT5 personnalisés : entrée, SL, TP, volume et € en jeu." });
  return { ok: true, username: me.result.username };
}

async function ensureWebhook(env, origin) {
  if (hookReady || !env.TG_TOKEN) return;
  if (!/^https:\/\//.test(origin) && !env.TG_API) return; // en local, pas de webhook
  const want = { origin, t: (await sha256hex(env.TG_TOKEN)).slice(0, 16), v: VERSION };
  const cur = await kvGet(env, "hook");
  if (cur && cur.value && cur.value.origin === want.origin && cur.value.t === want.t && cur.value.v === want.v) { hookReady = true; return; }
  const r = await registerBot(env, origin);
  if (r.ok) { await kvSet(env, "hook", want); hookReady = true; }
  else console.log("webhook", JSON.stringify(r));
}

// =====================================================================
//  Calcul du trade pour une personne
// =====================================================================
function stepDecimals(step) {
  const s = String(step);
  if (s.includes("e-")) return parseInt(s.split("e-")[1], 10);
  return s.includes(".") ? s.split(".")[1].length : 0;
}

// m : { entry, sl, rr, vpe, npe, cls, vmin, vstep, vmax }
//   vpe = euros gagnés ou perdus quand le prix bouge de 1, avec 1 lot
//   npe = valeur totale d'1 lot en euros (pour la marge)
function sizeTrade(user, m) {
  const riskMoney = user.capital * user.risk_pct / 100;
  const dist = Math.abs(m.entry - m.sl);
  const lossPerLot = dist * m.vpe;
  const step = m.vstep > 0 ? m.vstep : 0.01;
  const vmin = m.vmin > 0 ? m.vmin : step;
  const rr = m.rr > 0 ? m.rr : 2;
  if (!(lossPerLot > 0) || !Number.isFinite(lossPerLot)) return { ok: false, reason: "data", riskMoney };
  const dec = stepDecimals(step);
  let lot = Math.floor(riskMoney / lossPerLot / step + 1e-9) * step;
  let marginCapped = false;
  const lev = LEVERAGE[m.cls] || LEVERAGE.other;
  const marginPerLot = m.npe > 0 ? m.npe / lev : 0;
  if (marginPerLot > 0) {
    const maxLot = Math.floor(user.capital * MARGIN_SHARE / marginPerLot / step + 1e-9) * step;
    if (maxLot < lot) { lot = maxLot; marginCapped = true; }
  }
  if (m.vmax > 0) lot = Math.min(lot, m.vmax);
  lot = +lot.toFixed(dec);
  if (lot < vmin - 1e-9) {
    const minRisk = vmin * lossPerLot;
    const marginBlocked = marginPerLot > 0 && vmin * marginPerLot > user.capital * MARGIN_SHARE;
    return { ok: false, reason: marginBlocked && minRisk <= riskMoney ? "margin" : "small", minRisk, minCapital: Math.ceil(Math.max(minRisk / (user.risk_pct / 100), marginBlocked ? vmin * marginPerLot / MARGIN_SHARE : 0)), riskMoney };
  }
  const risk = lot * lossPerLot;
  return { ok: true, lot, lotTxt: lot.toFixed(dec), risk, gain: risk * rr, riskMoney, marginCapped, margin: lot * marginPerLot, rr };
}

// =====================================================================
//  Comptes
// =====================================================================
function publicUser(u, bot) {
  return {
    id: u.id, name: u.name, email: u.email, capital: u.capital, riskPct: u.risk_pct, admin: !!u.is_admin,
    riskMoney: round2(u.capital * u.risk_pct / 100), dailyStop: round2(u.capital * DAILY_STOP_PCT / 100),
    markets: u.markets === "*" ? "*" : u.markets.split(",").filter(Boolean), paused: !!u.paused,
    telegram: u.tg_chat ? { linked: true, name: u.tg_name || "" } : { linked: false },
    linkCode: u.link_code, linkUrl: bot ? "https://t.me/" + bot + "?start=" + u.link_code : "",
    stoppedUntil: u.stopped_until > now() ? u.stopped_until : 0,
    created: u.created,
  };
}

async function statsByUser(env, ids) {
  const out = new Map();
  for (const id of ids) out.set(id, { wins: 0, losses: 0, money: 0, today: 0, open: 0 });
  const t = now();
  const dayStart = parisDayStart(t);
  for (let i = 0; i < ids.length; i += 80) {
    const part = ids.slice(i, i + 80);
    const rows = (await env.DB.prepare(
      "SELECT user_id, " +
      "SUM(CASE WHEN result IS NOT NULL AND r > 0 THEN 1 ELSE 0 END) AS wins, " +
      "SUM(CASE WHEN result IS NOT NULL AND r < 0 THEN 1 ELSE 0 END) AS losses, " +
      "SUM(CASE WHEN result IS NOT NULL THEN money ELSE 0 END) AS money, " +
      "SUM(CASE WHEN result IS NOT NULL AND closed >= ? THEN money ELSE 0 END) AS today, " +
      "SUM(CASE WHEN result IS NULL AND created > ? THEN 1 ELSE 0 END) AS open " +
      "FROM deliveries WHERE kind = 'signal' AND lot > 0 AND user_id IN (" + part.map(() => "?").join(",") + ") GROUP BY user_id"
    ).bind(dayStart, t - OPEN_WINDOW, ...part).all()).results || [];
    for (const r of rows) out.set(r.user_id, { wins: r.wins || 0, losses: r.losses || 0, money: round2(r.money || 0), today: round2(r.today || 0), open: r.open || 0 });
  }
  return out;
}
const userStats = async (env, id) => (await statsByUser(env, [id])).get(id);

async function getUserByToken(env, req) {
  const auth = req.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+([A-Za-z0-9]{20,})$/);
  if (!m) return null;
  const th = await sha256hex(m[1]);
  return (await env.DB.prepare("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires > ?").bind(th, now()).first()) || null;
}
async function newSession(env, userId) {
  const token = randomCode(40, TOKEN_ALPHABET);
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, expires) VALUES (?, ?, ?)").bind(await sha256hex(token), userId, now() + SESSION_DAYS * 86400).run();
  return token;
}

async function mePayload(env, u) {
  const bot = await botUsername(env);
  const rs = await robotStatus(env);
  return {
    ok: true,
    user: publicUser(u, bot),
    stats: await userStats(env, u.id),
    robot: { online: rs.online, lastSeen: rs.updated, symbols: rs.v && Array.isArray(rs.v.markets) ? rs.v.markets.map((m) => m.sym) : [], tf: rs.v ? rs.v.tf || "" : "", rr: rs.rr, cur: rs.cur },
    bot,
    limits: { riskMin: RISK_MIN, riskMax: RISK_MAX, riskDefault: RISK_DEFAULT, dailyStopPct: DAILY_STOP_PCT, maxOpen: MAX_OPEN },
  };
}

const cleanEmail = (e) => String(e || "").trim().toLowerCase();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
function checkCapital(c) {
  return c >= 50 && c <= 1000000 ? null : "Le capital doit être entre 50 € et 1 000 000 €.";
}

async function apiInfo(env) {
  const n = (await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first()).n;
  const rs = await robotStatus(env);
  return json({ ok: true, name: "AlertesPro", version: VERSION, needInvite: n > 0, bot: await botUsername(env), robot: { online: rs.online, lastSeen: rs.updated } });
}

async function apiSignup(env, body) {
  const name = String(body.name || "").trim().slice(0, 40);
  const email = cleanEmail(body.email);
  const password = String(body.password || "");
  const capital = num(body.capital);
  if (!name) return fail(400, "Écris ton prénom.");
  if (!EMAIL_RE.test(email) || email.length > 120) return fail(400, "Adresse e-mail invalide.");
  if (password.length < 8) return fail(400, "Mot de passe trop court : 8 caractères minimum.");
  if (password.length > 200) return fail(400, "Mot de passe trop long.");
  const capErr = checkCapital(capital);
  if (capErr) return fail(400, capErr);
  const count = (await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first()).n;
  if (count > 0) {
    const invite = String(body.invite || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (!invite) return fail(403, "Il faut le code d'invitation (demande le lien à la personne qui t'a invité).");
    if (!sameText(invite, await inviteCode(env))) return fail(403, "Code d'invitation incorrect.");
  }
  if (await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first()) return fail(409, "Cet e-mail a déjà un compte. Connecte-toi.");
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await hashPassword(password, salt);
  const code = await newCode(env, "link_code", 8);
  const res = await env.DB.prepare("INSERT INTO users (email, name, pass_hash, pass_salt, capital, risk_pct, is_admin, link_code, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(email, name, hash, salt, round2(capital), RISK_DEFAULT, count === 0 ? 1 : 0, code, now()).run();
  const userId = res.meta.last_row_id;
  if (count === 0) await inviteCode(env);
  const token = await newSession(env, userId);
  return json({ ...(await mePayload(env, await userById(env, userId))), token });
}

// renvoie "" si bon, null si mauvais, ou un message si bloqué
async function checkPassword(env, u, password) {
  if (u.locked_until > now()) return "Trop d'essais. Réessaie dans " + Math.ceil((u.locked_until - now()) / 60) + " min.";
  if (!sameText(await hashPassword(password, u.pass_salt), u.pass_hash)) {
    const fails = u.fails + 1;
    await env.DB.prepare("UPDATE users SET fails = ?, locked_until = ? WHERE id = ?").bind(fails >= 5 ? 0 : fails, fails >= 5 ? now() + 900 : 0, u.id).run();
    return fails >= 5 ? "Trop d'essais. Réessaie dans 15 min." : null;
  }
  if (u.fails) await env.DB.prepare("UPDATE users SET fails = 0, locked_until = 0 WHERE id = ?").bind(u.id).run();
  return "";
}

async function apiLogin(env, body) {
  const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(cleanEmail(body.email)).first();
  if (!u) return fail(401, "E-mail ou mot de passe incorrect.");
  const err = await checkPassword(env, u, String(body.password || ""));
  if (err === null) return fail(401, "E-mail ou mot de passe incorrect.");
  if (err) return fail(429, err);
  const token = await newSession(env, u.id);
  return json({ ...(await mePayload(env, u)), token });
}

async function apiForgot(env, body) {
  const generic = json({ ok: true, message: "Si ce compte existe et que son Telegram est relié, un code vient d'être envoyé sur Telegram." });
  const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(cleanEmail(body.email)).first();
  if (!u || !u.tg_chat) return { res: generic };
  if (u.reset_until - 540 > now()) return { res: generic }; // un code par minute maximum
  const code = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
  await env.DB.prepare("UPDATE users SET reset_hash = ?, reset_until = ? WHERE id = ?").bind(await sha256hex(code + ":" + u.id), now() + 600, u.id).run();
  return {
    res: generic,
    outbox: [[u.tg_chat, "🔑 <b>Code pour changer ton mot de passe</b>\n\n<code>" + code + "</code>\n\nValable 10 minutes. Si ce n'est pas toi, ignore ce message."]],
  };
}

async function apiReset(env, body) {
  const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(cleanEmail(body.email)).first();
  const code = String(body.code || "").replace(/\D/g, "");
  const password = String(body.password || "");
  if (password.length < 8) return fail(400, "Nouveau mot de passe trop court : 8 caractères minimum.");
  if (!u || !u.reset_hash || u.reset_until < now()) return fail(400, "Code expiré : redemande un code.");
  if (u.locked_until > now()) return fail(429, "Trop d'essais. Réessaie dans " + Math.ceil((u.locked_until - now()) / 60) + " min.");
  if (!sameText(await sha256hex(code + ":" + u.id), u.reset_hash)) {
    const fails = u.fails + 1;
    await env.DB.prepare("UPDATE users SET fails = ?, locked_until = ? WHERE id = ?").bind(fails >= 5 ? 0 : fails, fails >= 5 ? now() + 900 : 0, u.id).run();
    return fail(400, "Code incorrect.");
  }
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  await env.DB.prepare("UPDATE users SET pass_hash = ?, pass_salt = ?, reset_hash = NULL, reset_until = 0, fails = 0, locked_until = 0 WHERE id = ?")
    .bind(await hashPassword(password, salt), salt, u.id).run();
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id).run();
  const token = await newSession(env, u.id);
  return json({ ...(await mePayload(env, await userById(env, u.id))), token });
}

async function apiUpdateMe(env, u, body) {
  const sets = [], vals = [];
  if (body.name != null) {
    const name = String(body.name).trim().slice(0, 40);
    if (!name) return fail(400, "Écris ton prénom.");
    sets.push("name = ?"); vals.push(name);
  }
  if (body.capital != null) {
    const c = num(body.capital);
    const err = checkCapital(c);
    if (err) return fail(400, err);
    sets.push("capital = ?"); vals.push(round2(c));
  }
  if (body.riskPct != null) {
    const r = num(body.riskPct);
    if (!(r >= RISK_MIN && r <= RISK_MAX)) return fail(400, "Pour protéger ton compte, le risque va de " + fmtShort(RISK_MIN) + " % à " + RISK_MAX + " % par trade.");
    sets.push("risk_pct = ?"); vals.push(round2(r));
  }
  if (body.markets != null) {
    const list = body.markets === "*" ? "*" : (Array.isArray(body.markets) ? body.markets : []).map((s) => String(s).replace(/[^A-Za-z0-9._#-]/g, "").slice(0, 20)).filter(Boolean).slice(0, 50).join(",");
    sets.push("markets = ?"); vals.push(list || "*");
  }
  if (body.paused != null) { sets.push("paused = ?"); vals.push(body.paused ? 1 : 0); }
  if (sets.length) await env.DB.prepare("UPDATE users SET " + sets.join(", ") + " WHERE id = ?").bind(...vals, u.id).run();
  return json(await mePayload(env, await userById(env, u.id)));
}

async function apiAlerts(env, u, url) {
  const limit = clamp(parseInt(url.searchParams.get("limit") || "60", 10) || 60, 1, 200);
  const rows = (await env.DB.prepare(
    "SELECT d.id, d.kind, d.sym, d.sid, d.lot, d.risk, d.gain, d.note, d.result, d.r, d.money, d.closed, d.created, a.data " +
    "FROM deliveries d JOIN alerts a ON a.id = d.alert_id WHERE d.user_id = ? ORDER BY d.id DESC LIMIT ?").bind(u.id, limit).all()).results || [];
  return json({
    ok: true,
    now: now(),
    alerts: rows.map((r) => {
      let data = {};
      try { data = JSON.parse(r.data); } catch (e) {}
      return { id: r.id, kind: r.kind, sym: r.sym, sid: r.sid, lot: r.lot, risk: r.risk, gain: r.gain, note: r.note, result: r.result, r: r.r, money: r.money, closed: r.closed, created: r.created, data };
    }),
  });
}

function marketSim(u, m, rr) {
  const px0 = num(m.px), sld = num(m.sld);
  return sizeTrade(u, { entry: px0, sl: px0 - sld, rr, vpe: num(m.vpe), npe: num(m.npe), cls: m.cls, vmin: num(m.vmin), vstep: num(m.vstep), vmax: num(m.vmax) });
}

async function apiMarkets(env, u) {
  const rs = await robotStatus(env);
  if (!rs.v) return json({ ok: true, online: false, updated: 0, markets: [] });
  const followed = u.markets === "*" ? null : new Set(u.markets.split(","));
  const markets = (rs.v.markets || []).map((m) => {
    const s = marketSim(u, m, rs.rr);
    return {
      sym: m.sym, dir: m.dir, rsi: num(m.rsi), px: num(m.px), dg: num(m.dg), news: m.news || "", slp: num(m.slp), sig: m.sig || "",
      ok: s.ok, lot: s.ok ? s.lotTxt : null, risk: s.ok ? round2(s.risk) : null, gain: s.ok ? round2(s.gain) : null,
      minRisk: s.minRisk ? round2(s.minRisk) : null, minCapital: s.minCapital || null, reason: s.ok ? "" : s.reason, marginCapped: !!s.marginCapped,
      followed: !followed || followed.has(m.sym),
    };
  });
  return json({ ok: true, online: rs.online, updated: rs.updated, tf: rs.v.tf || "", rr: rs.rr, cur: rs.cur, markets });
}

async function apiAdmin(env, u) {
  const users = await allUsers(env);
  const stats = await statsByUser(env, users.map((x) => x.id));
  const rs = await robotStatus(env);
  return json({
    ok: true,
    invite: await inviteCode(env),
    robot: { online: rs.online, lastSeen: rs.updated, version: rs.v ? rs.v.ver || "" : "", tf: rs.v ? rs.v.tf || "" : "", symbols: rs.v && rs.v.markets ? rs.v.markets.map((m) => m.sym) : [] },
    members: users.map((x) => {
      const st = stats.get(x.id) || { wins: 0, losses: 0 };
      return { id: x.id, name: x.name, email: x.email, admin: !!x.is_admin, telegram: !!x.tg_chat, paused: !!x.paused, capital: x.capital, created: x.created, trades: st.wins + st.losses };
    }),
  });
}

async function deleteUser(env, id) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM deliveries WHERE user_id = ?").bind(id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id),
    env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id),
  ]);
  // il faut toujours un administrateur
  const admin = await env.DB.prepare("SELECT id FROM users WHERE is_admin = 1").first();
  if (!admin) await env.DB.prepare("UPDATE users SET is_admin = 1 WHERE id = (SELECT MIN(id) FROM users)").run();
}

// =====================================================================
//  Messages Telegram
// =====================================================================
const SIDE = (side) => (side === "buy" ? "ACHAT" : "VENTE");

function signalMsg(a, s, u, cur) {
  const buy = a.side === "buy";
  const dg = a.dg;
  const L = [
    (buy ? "🟢🟢 <b>ACHAT · " : "🔴🔴 <b>VENTE · ") + esc(a.sym) + "</b>" + (a.tf ? " (" + esc(a.tf) + ")" : ""),
    SEP,
    "💶 Entrée : <code>" + px(a.entry, dg) + "</code>",
    "🛑 Stop Loss : <code>" + px(a.sl, dg) + "</code>" + (Number.isFinite(a.slp) ? " (" + fmt(a.slp, 1) + " pips)" : ""),
    "🎯 Take Profit : <code>" + px(a.tp, dg) + "</code>" + (Number.isFinite(a.tpp) ? " (" + fmt(a.tpp, 1) + " pips)" : ""),
  ];
  if (s.ok) {
    L.push("📦 Volume : <code>" + s.lotTxt + "</code> lot", SEP,
      "🔴 Si Stop Loss : <b>" + money(-s.risk, cur) + "</b> (" + fmtShort(s.risk / u.capital * 100) + " % de ton capital)",
      "🟢 Si Take Profit : <b>" + money(s.gain, cur) + "</b>");
    if (s.marginCapped) L.push("🛡️ Volume réduit pour ne pas bloquer trop de marge");
  } else if (s.reason === "data") {
    L.push(SEP, "⚠️ Volume impossible à calculer pour ce marché : <b>passe ton tour</b>.");
  } else {
    L.push(SEP, "⛔ <b>Passe ton tour</b> : avec " + money(u.capital, cur, false) + ", même le plus petit volume (" + px(a.vmin || 0.01, stepDecimals(a.vstep > 0 ? a.vstep : 0.01)) + " lot) " +
      (s.reason === "margin" ? "bloquerait trop de marge." : "risquerait " + money(s.minRisk || 0, cur, false) + ", c'est trop pour ton compte."),
      "💡 Il faudrait environ " + money(s.minCapital || 0, cur, false) + " de capital pour ce trade.");
  }
  L.push(SEP, "⏱ À prendre avant <b>" + hhmm(a.vu) + "</b>");
  if (Number.isFinite(a.lim)) L.push("⚠️ Trop tard si le prix est " + (buy ? "au-dessus de " : "en dessous de ") + "<code>" + px(a.lim, dg) + "</code>");
  if (s.ok) L.push("", "📲 <b>Dans MT5</b> : " + esc(a.sym) + " › Nouvel ordre › Volume <b>" + s.lotTxt + "</b> › SL <b>" + px(a.sl, dg) + "</b> › TP <b>" + px(a.tp, dg) + "</b> › <b>" + (buy ? "BUY (acheter)" : "SELL (vendre)") + "</b>");
  if (a.rs) L.push("", "📊 <i>" + esc(String(a.rs).slice(0, 300)) + "</i>");
  if (a.news) L.push("📰 Annonce économique proche : " + esc(String(a.news).slice(0, 100)));
  return L.join("\n");
}

function preMsg(a, s, cur) {
  const left = Number.isFinite(a.at) ? a.at - now() : 0;
  const L = ["🟡 <b>PRÉPARE-TOI · " + esc(a.sym) + "</b>", SEP,
    "⏳ " + (a.side === "buy" ? "🟢 ACHAT" : "🔴 VENTE") + " possible à <b>" + hhmm(a.at) + "</b>" + (left > 5 ? " (dans " + (left >= 90 ? Math.round(left / 60) + " min" : left + " s") + ")" : ""),
    "📱 Ouvre MT5 sur " + esc(a.sym) + " maintenant"];
  if (s && s.ok) L.push("📦 Volume prévu : environ <b>" + s.lotTxt + "</b> lot (risque ≈ " + money(-s.risk, cur) + ")");
  L.push("✋ N'entre pas avant le signal : il peut encore s'annuler");
  return L.join("\n");
}

function statsLine(st, cur) {
  return "📊 Ton bilan : ✅ " + st.wins + " gagné" + (st.wins > 1 ? "s" : "") + " · ❌ " + st.losses + " perdu" + (st.losses > 1 ? "s" : "") + " · <b>" + money(st.money, cur) + "</b>";
}

function resultMsg(ev, d, st, cur) {
  const head = ev.res === "tp" ? "✅ <b>TAKE PROFIT · " : ev.res === "sl" ? "❌ <b>STOP LOSS · " : "⌛ <b>FIN DU TRADE · ";
  const L = [head + esc(ev.sym) + "</b>", SEP];
  if (d.lot > 0) {
    L.push((d.money >= 0 ? "💰 Résultat : <b>" : "💸 Résultat : <b>") + money(d.money, cur) + "</b> (" + (ev.r > 0 ? "+" : "") + fmt(ev.r, 2) + " R)");
    if (ev.res !== "tp" && ev.res !== "sl") L.push("👉 Le trade a duré trop longtemps : ferme-le dans MT5 si ce n'est pas déjà fait.");
  } else {
    L.push("ℹ️ Tu n'avais pas pris ce trade (protection de ton compte).");
  }
  L.push("↔️ " + SIDE(ev.side) + " à " + px(ev.entry, ev.dg) + " → sortie " + px(ev.exit, ev.dg), SEP, statsLine(st, cur));
  if (d.lot > 0) L.push("📅 Aujourd'hui : <b>" + money(st.today, cur) + "</b>");
  return L.join("\n");
}

function profileMsg(u, st, cur, rr) {
  const riskMoney = u.capital * u.risk_pct / 100;
  const state = u.stopped_until > now() ? "🛑 stop jusqu'à demain (protection)" : u.paused ? "⏸️ en pause" : "🔔 actives";
  return ["👤 <b>" + esc(u.name) + "</b>", SEP,
    "💼 Capital : <b>" + money(u.capital, cur, false) + "</b>",
    "🛡️ Risque : " + fmtShort(u.risk_pct) + " % → max <b>" + money(riskMoney, cur, false) + "</b> de perte par trade",
    "🎯 Gain visé : environ <b>" + money(riskMoney * rr, cur, false) + "</b> par trade gagnant",
    "🛑 Stop du jour : après " + money(u.capital * DAILY_STOP_PCT / 100, cur, false) + " de pertes",
    "📈 Marchés : " + (u.markets === "*" ? "tous" : esc(u.markets.split(",").join(", "))),
    "🔔 Alertes : " + state, SEP,
    statsLine(st, cur),
    "📅 Aujourd'hui : " + money(st.today, cur) + " · ⏳ En cours : " + st.open].join("\n");
}

const DIR_TXT = { up: "↗️ hausse", down: "↘️ baisse", flat: "➡️ sans tendance" };
function marketsMsg(u, rs) {
  if (!rs.v || !Array.isArray(rs.v.markets) || !rs.v.markets.length) return "📈 Le robot n'a pas encore envoyé les marchés. Réessaie dans quelques minutes.";
  const L = ["📈 <b>Tes marchés</b> (capital " + money(u.capital, rs.cur, false) + ", risque " + fmtShort(u.risk_pct) + " %)", SEP];
  for (const m of rs.v.markets) {
    if (!wantsMarket(u, m.sym)) continue;
    const s = marketSim(u, m, rs.rr);
    L.push("<b>" + esc(m.sym) + "</b> " + (DIR_TXT[m.dir] || ""));
    L.push(s.ok ? "   📦 " + s.lotTxt + " lot · 🔴 " + money(-s.risk, rs.cur) + " · 🟢 " + money(s.gain, rs.cur)
      : "   ⛔ capital trop petit (il faudrait ~" + money(s.minCapital || 0, rs.cur, false) + ")");
  }
  L.push(SEP, rs.online ? "🤖 Robot en ligne" : "😴 Robot hors ligne (MT5 fermé ?)", "<i>Montants pour un signal moyen d'aujourd'hui.</i>");
  return L.join("\n");
}

const HELP = ["ℹ️ <b>Commandes</b>", SEP,
  "/moi : ton compte et ton bilan",
  "/marches : ce que tu risques et peux gagner sur chaque marché",
  "/capital 1500 : changer ton capital",
  "/risque 1 : risque par trade en % (0,25 à 2)",
  "/pause : ne plus recevoir de signaux",
  "/reprendre : recevoir de nouveau les signaux",
  "/aide : cette liste"].join("\n");

// =====================================================================
//  Bot Telegram (messages reçus)
// =====================================================================
async function onTelegram(env, update) {
  const msg = update.message || update.edited_message;
  if (!msg || !msg.chat || msg.chat.type !== "private" || typeof msg.text !== "string") return;
  const chat = String(msg.chat.id);
  const text = msg.text.trim();
  const tgName = [msg.from && msg.from.first_name, msg.from && msg.from.last_name].filter(Boolean).join(" ").slice(0, 60);
  const reply = (t, extra) => send(env, chat, t, extra);
  let user = await env.DB.prepare("SELECT * FROM users WHERE tg_chat = ?").bind(chat).first();
  const rs = await robotStatus(env);
  const cur = rs.cur;

  const [cmdRaw, ...args] = text.split(/\s+/);
  const cmd = cmdRaw.toLowerCase().split("@")[0];
  let code = "";
  if (cmd === "/start" && args[0]) code = args[0];
  else if (/^[A-Za-z0-9]{8}$/.test(text)) code = text;
  code = code.toUpperCase().replace(/[^A-Z0-9]/g, "");

  // ---- liaison avec le code secret de l'appli
  if (code) {
    const target = await env.DB.prepare("SELECT * FROM users WHERE link_code = ?").bind(code).first();
    if (!target) return reply("❓ Code inconnu.\nOuvre l'appli AlertesPro › <b>Compte</b> › <b>Relier Telegram</b>.", appButton());
    if (target.tg_chat && target.tg_chat !== chat) return reply("🔒 Ce code est déjà relié à un autre Telegram.\nDans l'appli : <b>Compte › Relier un autre Telegram</b> pour avoir un nouveau code.", appButton());
    await env.DB.prepare("UPDATE users SET tg_chat = NULL, tg_name = NULL WHERE tg_chat = ? AND id <> ?").bind(chat, target.id).run();
    await env.DB.prepare("UPDATE users SET tg_chat = ?, tg_name = ? WHERE id = ?").bind(chat, tgName, target.id).run();
    const u = await userById(env, target.id);
    const riskMoney = u.capital * u.risk_pct / 100;
    return reply(["🎉 <b>Bienvenue " + esc(u.name) + " !</b>", "Ton compte AlertesPro est relié à ce Telegram.", SEP,
      "💼 Capital : <b>" + money(u.capital, cur, false) + "</b>",
      "🔴 Par trade, tu risques au maximum <b>" + money(riskMoney, cur, false) + "</b>",
      "🟢 Par trade gagnant, tu vises environ <b>" + money(riskMoney * rs.rr, cur, false) + "</b>",
      "🛑 Stop automatique après " + money(u.capital * DAILY_STOP_PCT / 100, cur, false) + " de pertes dans la journée", SEP,
      "Tu recevras ici :",
      "🟡 la pré-alerte, 1 minute avant",
      "🟢🔴 le signal, calculé pour ton argent",
      "✅❌ le résultat et ton bilan", "",
      "Commandes : /moi /marches /pause /aide",
      "⚠️ <i>Signaux automatiques : aucun gain n'est garanti. Commence sur un compte démo.</i>"].join("\n"), appButton());
  }

  if (!user) {
    return reply(["👋 <b>Bienvenue sur AlertesPro !</b>", "",
      "1️⃣ Crée ton compte dans l'appli (avec le lien d'invitation qu'on t'a envoyé)",
      "2️⃣ Dans <b>Compte</b>, touche <b>Relier Telegram</b>", "",
      "Ou envoie-moi directement ton code secret à 8 caractères."].join("\n"), appButton());
  }

  if (cmd === "/start" || cmd === "/moi" || cmd === "/bilan" || cmd === "/compte") return reply(profileMsg(user, await userStats(env, user.id), cur, rs.rr), appButton());
  if (cmd === "/marches" || cmd === "/marchés") return reply(marketsMsg(user, rs));
  if (cmd === "/pause") {
    await env.DB.prepare("UPDATE users SET paused = 1 WHERE id = ?").bind(user.id).run();
    return reply("⏸️ <b>Signaux en pause.</b>\nTu reçois quand même les résultats des trades en cours.\n/reprendre pour relancer.");
  }
  if (cmd === "/reprendre") {
    await env.DB.prepare("UPDATE users SET paused = 0 WHERE id = ?").bind(user.id).run();
    return reply("▶️ <b>Signaux relancés.</b>" + (user.stopped_until > now() ? "\n🛑 Le stop du jour reste actif jusqu'à minuit." : ""));
  }
  if (cmd === "/capital") {
    const c = num(args[0]);
    if (checkCapital(c)) return reply("Écris par exemple : <code>/capital 1500</code> (entre 50 et 1 000 000).");
    await env.DB.prepare("UPDATE users SET capital = ? WHERE id = ?").bind(round2(c), user.id).run();
    user = await userById(env, user.id);
    return reply("✅ Capital mis à jour.\n\n" + profileMsg(user, await userStats(env, user.id), cur, rs.rr));
  }
  if (cmd === "/risque") {
    const r = num(args[0]);
    if (!(r >= RISK_MIN && r <= RISK_MAX)) return reply("🛡️ Pour protéger ton compte, le risque va de " + fmtShort(RISK_MIN) + " % à " + RISK_MAX + " % par trade.\nExemple : <code>/risque 1</code>");
    await env.DB.prepare("UPDATE users SET risk_pct = ? WHERE id = ?").bind(round2(r), user.id).run();
    user = await userById(env, user.id);
    return reply("✅ Risque mis à jour.\n\n" + profileMsg(user, await userStats(env, user.id), cur, rs.rr));
  }
  return reply(HELP, appButton());
}

// =====================================================================
//  Événements envoyés par le robot MT5
// =====================================================================
function wantsMarket(u, sym) {
  return u.markets === "*" || u.markets.split(",").includes(sym);
}

// enregistre l'alerte ; renvoie 0 si elle a déjà été reçue (le robot a réessayé)
async function insertAlert(env, ev) {
  const r = await env.DB.prepare("INSERT OR IGNORE INTO alerts (eid, sid, kind, sym, side, data, created) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(ev.eid || null, ev.sid || null, ev.type, ev.sym || null, ev.side || null, JSON.stringify(ev), now()).run();
  return r.meta.changes ? r.meta.last_row_id : 0;
}

async function openCounts(env) {
  const rows = (await env.DB.prepare("SELECT user_id, COUNT(*) AS n FROM deliveries WHERE kind = 'signal' AND result IS NULL AND lot > 0 AND created > ? GROUP BY user_id")
    .bind(now() - OPEN_WINDOW).all()).results || [];
  return new Map(rows.map((r) => [r.user_id, r.n]));
}

const tradeOf = (ev) => ({ entry: ev.entry, sl: ev.sl, rr: ev.rr, vpe: ev.vpe, npe: ev.npe, cls: ev.cls, vmin: ev.vmin, vstep: ev.vstep, vmax: ev.vmax });

async function onSignal(env, ev) {
  if (ev.sid && (await env.DB.prepare("SELECT id FROM alerts WHERE sid = ? AND kind = 'signal'").bind(ev.sid).first())) return { dup: true };
  const alertId = await insertAlert(env, ev);
  if (!alertId) return { dup: true };
  const cur = ev.cur || "EUR";
  const users = await allUsers(env);
  const open = await openCounts(env);
  const t = now(), stmts = [], outbox = [];
  for (const u of users) {
    if (u.paused || u.stopped_until > t || !wantsMarket(u, ev.sym)) continue;
    if ((open.get(u.id) || 0) >= MAX_OPEN) {
      stmts.push(env.DB.prepare("INSERT INTO deliveries (user_id, alert_id, sid, kind, sym, note, created) VALUES (?, ?, ?, 'signal', ?, 'max_open', ?)").bind(u.id, alertId, ev.sid, ev.sym, t));
      outbox.push([u.tg_chat, "ℹ️ Signal " + esc(ev.sym) + " pas envoyé : tu as déjà " + MAX_OPEN + " trades en cours.\n🛡️ C'est une protection pour ton compte."]);
      continue;
    }
    const s = sizeTrade(u, tradeOf(ev));
    const note = s.ok ? (s.marginCapped ? "margin" : null) : s.reason + (s.minCapital ? ":" + s.minCapital : "");
    stmts.push(env.DB.prepare("INSERT INTO deliveries (user_id, alert_id, sid, kind, sym, lot, risk, gain, note, created) VALUES (?, ?, ?, 'signal', ?, ?, ?, ?, ?, ?)")
      .bind(u.id, alertId, ev.sid, ev.sym, s.ok ? s.lot : 0, s.ok ? round2(s.risk) : round2(s.minRisk || 0), s.ok ? round2(s.gain) : 0, note, t));
    outbox.push([u.tg_chat, signalMsg(ev, s, u, cur)]);
  }
  if (stmts.length) await env.DB.batch(stmts);
  return { result: { users: stmts.length, telegram: outbox.filter((m) => m[0]).length }, outbox };
}

async function onPre(env, ev) {
  const alertId = await insertAlert(env, ev);
  if (!alertId) return { dup: true };
  const cur = ev.cur || "EUR";
  const users = await allUsers(env);
  const open = await openCounts(env);
  const t = now(), stmts = [], outbox = [];
  const canSize = Number.isFinite(ev.px) && Number.isFinite(ev.sld) && ev.sld > 0;
  for (const u of users) {
    if (u.paused || u.stopped_until > t || !wantsMarket(u, ev.sym) || (open.get(u.id) || 0) >= MAX_OPEN) continue;
    const s = canSize ? sizeTrade(u, { ...tradeOf(ev), entry: ev.px, sl: ev.px - ev.sld }) : null;
    stmts.push(env.DB.prepare("INSERT INTO deliveries (user_id, alert_id, kind, sym, lot, risk, gain, created) VALUES (?, ?, 'pre', ?, ?, ?, ?, ?)")
      .bind(u.id, alertId, ev.sym, s && s.ok ? s.lot : 0, s && s.ok ? round2(s.risk) : 0, s && s.ok ? round2(s.gain) : 0, t));
    outbox.push([u.tg_chat, preMsg(ev, s, cur)]);
  }
  if (stmts.length) await env.DB.batch(stmts);
  return { result: { users: stmts.length }, outbox };
}

async function onCancel(env, ev) {
  const alertId = await insertAlert(env, ev);
  if (!alertId) return { dup: true };
  const t = now();
  const rows = (await env.DB.prepare("SELECT DISTINCT u.id, u.tg_chat FROM deliveries d JOIN users u ON u.id = d.user_id WHERE d.kind = 'pre' AND d.sym = ? AND d.created > ?")
    .bind(ev.sym, t - 900).all()).results || [];
  const stmts = rows.map((u) => env.DB.prepare("INSERT INTO deliveries (user_id, alert_id, kind, sym, created) VALUES (?, ?, 'cancel', ?, ?)").bind(u.id, alertId, ev.sym, t));
  if (stmts.length) await env.DB.batch(stmts);
  const text = "⚪ <b>ANNULÉ · " + esc(ev.sym) + "</b>\nLes conditions ne sont plus réunies.\n👉 <b>Ne fais rien</b> sur " + esc(ev.sym) + ".";
  return { result: { users: rows.length }, outbox: rows.map((u) => [u.tg_chat, text]) };
}

async function onResult(env, ev) {
  const alertId = await insertAlert(env, ev);
  if (!alertId) return { dup: true };
  const cur = ev.cur || "EUR";
  const r = Number.isFinite(ev.r) ? ev.r : 0;
  const ds = (await env.DB.prepare("SELECT d.*, u.tg_chat, u.capital, u.stopped_until FROM deliveries d JOIN users u ON u.id = d.user_id WHERE d.sid = ? AND d.kind = 'signal' AND d.result IS NULL")
    .bind(ev.sid).all()).results || [];
  if (!ds.length) return { result: { users: 0 }, outbox: [] };
  const t = now();
  for (const d of ds) d.money = d.lot > 0 ? round2(r * d.risk) : 0;
  await env.DB.batch(ds.map((d) => env.DB.prepare("UPDATE deliveries SET result = ?, r = ?, money = ?, closed = ? WHERE id = ?").bind(ev.res || "exp", r, d.money, t, d.id)));
  const stats = await statsByUser(env, [...new Set(ds.map((d) => d.user_id))]);
  const outbox = [], stops = [];
  for (const d of ds) {
    const st = stats.get(d.user_id);
    let text = resultMsg(ev, d, st, cur);
    // stop du jour : -3 % du capital
    if (d.lot > 0 && d.money < 0 && d.stopped_until <= t && st.today <= -(d.capital * DAILY_STOP_PCT / 100) && !stops.includes(d.user_id)) {
      stops.push(d.user_id);
      text += "\n\n" + ["🛑 <b>STOP POUR AUJOURD'HUI</b>", SEP,
        "Tu as perdu " + money(-st.today, cur, false) + " aujourd'hui (" + DAILY_STOP_PCT + " % de ton capital).",
        "Plus de signaux jusqu'à demain : c'est ce qui protège ton compte.",
        "Les trades en cours continuent jusqu'à leur Stop Loss ou Take Profit."].join("\n");
    }
    outbox.push([d.tg_chat, text]);
  }
  if (stops.length) await env.DB.batch(stops.map((id) => env.DB.prepare("UPDATE users SET stopped_until = ? WHERE id = ?").bind(nextParisMidnight(t), id)));
  return { result: { users: ds.length, stops: stops.length }, outbox };
}

async function onStatus(env, ev) {
  await kvSet(env, "status", ev);
  const off = await kvGet(env, "robot_off");
  if (!off) return { result: { stored: true }, outbox: [] };
  await kvDel(env, "robot_off");
  const admins = (await env.DB.prepare("SELECT tg_chat FROM users WHERE is_admin = 1 AND tg_chat IS NOT NULL").all()).results || [];
  return { result: { stored: true }, outbox: admins.map((a) => [a.tg_chat, "✅ <b>Robot reconnecté</b>\nLes alertes reprennent normalement."]) };
}

function bad(message) { const e = new Error(message); e.status = 400; throw e; }
const NUM_FIELDS = ["entry", "sl", "tp", "lim", "r", "exit", "vpe", "npe", "vmin", "vstep", "vmax", "rr", "slp", "tpp", "at", "vu", "dg", "px", "sld"];
async function onRobotEvent(env, ev) {
  const type = String(ev.type || "");
  if (type === "status") return onStatus(env, ev);
  for (const k of NUM_FIELDS) if (ev[k] != null) ev[k] = num(ev[k]);
  ev.sym = String(ev.sym || "").slice(0, 30);
  if (!ev.sym) bad("sym manquant");
  const side = String(ev.side || "").toLowerCase();
  ev.side = side === "buy" || side === "achat" ? "buy" : side === "sell" || side === "vente" ? "sell" : side;
  if (type === "signal") {
    if (!Number.isFinite(ev.entry) || !Number.isFinite(ev.sl) || !Number.isFinite(ev.tp)) bad("entry/sl/tp manquants");
    return onSignal(env, ev);
  }
  if (type === "pre") return onPre(env, ev);
  if (type === "cancel") return onCancel(env, ev);
  if (type === "result") return onResult(env, ev);
  bad("type inconnu : " + type);
}

// =====================================================================
//  Tâche planifiée (toutes les 15 min) : robot muet ? ménage
// =====================================================================
function marketOpen(ts) {
  const p = parisParts(ts);
  const h = +p.hour + +p.minute / 60;
  const wd = String(p.weekday || "").toLowerCase();
  if (wd.startsWith("sam")) return false;
  if (wd.startsWith("dim")) return h >= 23.5;
  if (wd.startsWith("ven")) return h < 22;
  return true;
}

async function cron(env) {
  await ensureSchema(env);
  const t = now();
  await env.DB.prepare("DELETE FROM sessions WHERE expires < ?").bind(t).run();
  const rs = await robotStatus(env);
  if (!rs.updated || t - rs.updated < ROBOT_ALERT_SEC || !marketOpen(t)) return;
  if (await kvGet(env, "robot_off")) return;
  await kvSet(env, "robot_off", { since: rs.updated });
  const admins = (await env.DB.prepare("SELECT tg_chat FROM users WHERE is_admin = 1 AND tg_chat IS NOT NULL").all()).results || [];
  await sendAll(env, admins.map((a) => [a.tg_chat, "⚠️ <b>Le robot ne répond plus</b> depuis " + hhmm(rs.updated) + ".\nMT5 est peut-être fermé, ou l'ordinateur en veille.\n👉 Rouvre MT5 pour que tout le monde continue de recevoir les alertes."]));
}

// =====================================================================
//  Pages simples
// =====================================================================
function page(title, body, status = 200) {
  return new Response('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + esc(title) +
    '</title><body style="font-family:system-ui,sans-serif;background:#0b1020;color:#e9eef7;padding:24px;line-height:1.5"><div style="max-width:560px;margin:auto">' + body + "</div></body>",
    { status, headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function setup(env, url) {
  const key = url.searchParams.get("key") || "";
  if (!sameText(key, await robotKey(env))) return page("Clé invalide", "<h2>❌ Clé invalide</h2><p>Ajoute <code>?key=</code> suivi de la clé du robot à l'adresse.</p>", 403);
  if (!env.TG_TOKEN) return page("Jeton manquant", "<h2>❌ Secret TG_TOKEN manquant</h2><p>Ajoute le jeton du bot : Cloudflare › ton Worker › Settings › Variables and Secrets.</p>");
  const r = await registerBot(env, url.origin);
  if (!r.ok) return page("Erreur", "<h2>⚠️ Telegram a refusé (" + esc(r.step) + ")</h2><pre>" + esc(JSON.stringify(r.detail)) + "</pre>");
  await kvSet(env, "hook", { origin: url.origin, t: (await sha256hex(env.TG_TOKEN)).slice(0, 16), v: VERSION });
  hookReady = true;
  const rs = await robotStatus(env);
  return page("Serveur prêt", "<h2>✅ Serveur AlertesPro prêt</h2><p>Bot : <b>@" + esc(r.username) + "</b></p><p>Robot MT5 : " + (rs.online ? "✅ en ligne" : "😴 pas encore connecté") + "</p><p>Adresse du serveur :</p><p><code style=\"font-size:16px\">" + esc(url.origin) + "</code></p>");
}

async function readJson(req) {
  try { const b = await req.json(); return b && typeof b === "object" ? b : {}; } catch (e) { return {}; }
}

// =====================================================================
//  Routeur
// =====================================================================
async function handle(req, env, ctx) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = req.method;
  await ensureSchema(env);
  ctx.waitUntil(ensureWebhook(env, url.origin).catch((e) => console.log("webhook", e && e.stack || e)));
  const later = (outbox) => { if (outbox && outbox.length) ctx.waitUntil(sendAll(env, outbox).catch((e) => console.log("send", e && e.stack || e))); };

  if (path === "/" && method === "GET") {
    if ((req.headers.get("Accept") || "").includes("text/html")) return page("AlertesPro", "<h2>✅ Serveur AlertesPro en marche</h2><p>Version " + VERSION + ". Ouvre l'appli : <a style=\"color:#7cc4ff\" href=\"" + APP_URL + "\">" + APP_URL + "</a></p>");
    return json({ ok: true, name: "AlertesPro", version: VERSION });
  }
  if (path === "/setup" && method === "GET") return setup(env, url);

  if (path === "/telegram" && method === "POST") {
    if (!sameText(req.headers.get("X-Telegram-Bot-Api-Secret-Token") || "", await webhookSecret(env))) return fail(403, "forbidden");
    const update = await readJson(req);
    ctx.waitUntil(onTelegram(env, update).catch((e) => console.log("telegram", e && e.stack || e)));
    return json({ ok: true });
  }

  if (path === "/robot/event" && method === "POST") {
    if (!sameText(req.headers.get("X-Robot-Key") || "", await robotKey(env))) return fail(403, "Clé du robot invalide.");
    const ev = await readJson(req);
    const out = await onRobotEvent(env, ev);
    later(out.outbox);
    return json({ ok: true, ...(out.dup ? { dup: true } : out.result) });
  }

  if (path === "/api/info" && method === "GET") return apiInfo(env);
  if (path === "/api/signup" && method === "POST") return apiSignup(env, await readJson(req));
  if (path === "/api/login" && method === "POST") return apiLogin(env, await readJson(req));
  if (path === "/api/forgot" && method === "POST") { const o = await apiForgot(env, await readJson(req)); later(o.outbox); return o.res; }
  if (path === "/api/reset" && method === "POST") return apiReset(env, await readJson(req));

  if (path.startsWith("/api/")) {
    const u = await getUserByToken(env, req);
    if (!u) return fail(401, "Session expirée : reconnecte-toi.");
    if (path === "/api/me" && method === "GET") return json(await mePayload(env, u));
    if (path === "/api/me" && method === "PUT") return apiUpdateMe(env, u, await readJson(req));
    if (path === "/api/me/relink" && method === "POST") {
      await env.DB.prepare("UPDATE users SET link_code = ?, tg_chat = NULL, tg_name = NULL WHERE id = ?").bind(await newCode(env, "link_code", 8), u.id).run();
      return json(await mePayload(env, await userById(env, u.id)));
    }
    if (path === "/api/me/test" && method === "POST") {
      if (!u.tg_chat) return fail(400, "Relie d'abord ton Telegram.");
      const r = await send(env, u.tg_chat, "✅ <b>Test AlertesPro</b>\nTon Telegram est bien relié à ton compte, " + esc(u.name) + " 👍");
      return r.ok ? json({ ok: true }) : fail(502, "Telegram n'a pas pu envoyer le message (as-tu bloqué le bot ?).");
    }
    if (path === "/api/alerts" && method === "GET") return apiAlerts(env, u, url);
    if (path === "/api/markets" && method === "GET") return apiMarkets(env, u);
    if (path === "/api/logout" && method === "POST") {
      const m = (req.headers.get("Authorization") || "").match(/^Bearer\s+(\S+)$/);
      if (m) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256hex(m[1])).run();
      return json({ ok: true });
    }
    if (path === "/api/me/delete" && method === "POST") {
      const body = await readJson(req);
      const err = await checkPassword(env, u, String(body.password || ""));
      if (err === null) return fail(401, "Mot de passe incorrect.");
      if (err) return fail(429, err);
      await deleteUser(env, u.id);
      return json({ ok: true });
    }
    if (path.startsWith("/api/admin")) {
      if (!u.is_admin) return fail(403, "Réservé à l'administrateur.");
      if (path === "/api/admin" && method === "GET") return apiAdmin(env, u);
      if (path === "/api/admin/invite" && method === "POST") {
        await kvSet(env, "invite", { code: randomCode(6, CODE_ALPHABET) });
        return apiAdmin(env, u);
      }
      if (path === "/api/admin/remove" && method === "POST") {
        const body = await readJson(req);
        const id = parseInt(body.id, 10);
        if (!id || id === u.id) return fail(400, "Impossible de retirer ce compte.");
        await deleteUser(env, id);
        return apiAdmin(env, u);
      }
    }
  }
  return fail(404, "Introuvable.");
}

export default {
  async fetch(req, env, ctx) {
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    try {
      return await handle(req, env, ctx);
    } catch (e) {
      console.log("erreur", e && e.stack || e);
      return fail((e && e.status) || 500, (e && e.status ? "" : "Erreur du serveur : ") + (e && e.message || e));
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(cron(env).catch((e) => console.log("cron", e && e.stack || e)));
  },
};
