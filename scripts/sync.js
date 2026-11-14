/**
 * Sports events sync — Priofy API → events.json
 *
 * API তে ঢুকতে অ্যাপের মতোই সাইন করা হেডার লাগে:
 *   x-timestamp : বর্তমান সময় (milliseconds)
 *   x-signature : Base64( HMAC-SHA256(timestamp, SECRET) )
 *
 * রেসপন্সের ফিল্ডগুলো AES-128-CBC দিয়ে এনক্রিপ্টেড থাকে (enc: true),
 * সেগুলো ডিক্রিপ্ট করে নতুন টার্গেট ফরম্যাটে (stream_url_alpha সহ) সেভ হয়।
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ── Config (GitHub Secrets / env দিয়ে বদলানো যায়, না দিলে ডিফল্ট) ──────────────
const API_URL = process.env.API_URL || "https://priofyapi.shopnilofficial47.workers.dev/";
const HMAC_SECRET = process.env.HMAC_SECRET || "PriofySecure2026_LiveApp";
const AES_KEY = process.env.AES_KEY || "PriofySecure2026"; // 16 bytes
const AES_IV = process.env.AES_IV || "PriofyAppIV_2026"; // 16 bytes

// সোর্স API-এর date/time যদি UTC হয় তবে 0 রাখুন; আগে থেকেই BST হলে 6 দিন
const SOURCE_TZ_OFFSET_HOURS = Number(process.env.SOURCE_TZ_OFFSET_HOURS ?? 0);

const USER_AGENT =
  "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36";

const OUTPUT_FILE = path.join(__dirname, "..", "events.json");
const MAX_RETRIES = 3;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// ── Crypto helpers ────────────────────────────────────────────────────────────
function sign(timestamp) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(timestamp).digest("base64");
}

/** AES-128-CBC ডিক্রিপ্ট; ব্যর্থ হলে null */
function aesDecrypt(str) {
  try {
    const decipher = crypto.createDecipheriv(
      "aes-128-cbc",
      Buffer.from(AES_KEY, "utf8"),
      Buffer.from(AES_IV, "utf8")
    );
    return Buffer.concat([
      decipher.update(Buffer.from(str, "base64")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}

/** AES → না হলে সাধারণ Base64 (valid হলে) → না হলে যেমন আছে তেমনই */
function dec(str) {
  if (!str || typeof str !== "string") return "";
  const trimmed = str.trim();
  const viaAes = aesDecrypt(trimmed);
  if (viaAes !== null) return viaAes.trim();

  const looksBase64 = /^[A-Za-z0-9+/]+=*$/.test(trimmed) && trimmed.length % 4 === 0;
  if (looksBase64) {
    try {
      const decoded = Buffer.from(trimmed, "base64").toString("utf8").trim();
      // কেবল প্রিন্টেবল ASCII হলেই Base64 ডিকোড হিসেবে নিন
      if (decoded && /^[\x20-\x7E]+$/.test(decoded)) {
        return decoded;
      }
    } catch {
      return trimmed;
    }
  }
  return trimmed;
}

/**
 * DRM ডিকোড: plain "kid:key" বা license URL ফেরত দেয় (Base64 ডাবল-এনকোডেড থাকলেও ডিকোড করবে)
 */
function decodeDrmPlain(value) {
  if (!value) return "";
  let plain = dec(value);
  if (!plain) return "";

  const looksBase64 =
    !plain.includes(":") &&
    !plain.startsWith("http") &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(plain) &&
    plain.length % 4 === 0;

  if (looksBase64) {
    try {
      const inner = Buffer.from(plain, "base64").toString("utf8").trim();
      if (inner.includes(":") || inner.startsWith("http")) {
        plain = inner;
      }
    } catch {
      // ignore
    }
  }
  return plain;
}

// ── Formatting & Mapping helpers ──────────────────────────────────────────────
function slugify(text) {
  return String(text || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function buildTitle(team1, team2, league, fallbackId) {
  const t1 = (team1 || "").trim();
  const t2 = (team2 || "").trim();
  if (t1 && t2) {
    return t1.toLowerCase() === t2.toLowerCase() ? t1 : `${t1} vs ${t2}`;
  }
  return t1 || t2 || (league || "").trim() || String(fallbackId);
}

function detectSport(league, title, raw) {
  if (raw.sport) {
    return {
      sport: raw.sport,
      sub_category: raw.sub_category || raw.sport,
    };
  }
  const text = `${league} ${title}`.toLowerCase();

  if (/\b(f1|formula\s*1|motogp|nascar|motorsport|rally|indycar)\b/.test(text)) {
    return { sport: "Motorsport", sub_category: "Motorsports" };
  }
  if (/\b(cricket|ipl|bpl|psl|bbl|cpl|t20|odi|test|icc|bcci|pcb|bcb)\b/.test(text)) {
    return { sport: "Cricket", sub_category: "Cricket" };
  }
  if (
    /\b(football|soccer|premier league|epl|la liga|serie a|bundesliga|ligue 1|ucl|champions league|europa|mls|fifa|uefa|afc|world cup)\b/.test(
      text
    )
  ) {
    return { sport: "Football", sub_category: "Football" };
  }
  if (/\b(nba|basketball|euroleague|wnba|ncaa)\b/.test(text)) {
    return { sport: "Basketball", sub_category: "Basketball" };
  }
  if (/\b(atp|wta|tennis|wimbledon|us open|french open|australian open)\b/.test(text)) {
    return { sport: "Tennis", sub_category: "Tennis" };
  }
  if (/\b(ufc|mma|boxing|wwe|aew|fight night)\b/.test(text)) {
    return { sport: "Combat Sports", sub_category: "MMA & Boxing" };
  }
  if (/\b(hockey|nhl|fih)\b/.test(text)) {
    return { sport: "Hockey", sub_category: "Hockey" };
  }
  return { sport: "Sports", sub_category: league || "General" };
}

/** সোর্সের date + time স্ট্রিং থেকে Date অবজেক্ট তৈরি */
function parseEventDate(dateStr, timeStr) {
  const combined = `${dateStr || ""} ${timeStr || ""}`.trim();
  if (!combined) return null;

  // যদি আগে থেকেই timezone উল্লেখ থাকে (Z, +06:00, GMT, UTC ইত্যাদি)
  const hasTz = /(Z|[+-]\d{2}:?\d{2}|GMT|UTC|BST)/i.test(combined);
  if (hasTz) {
    const normalized = combined.replace(/\bBST\b/i, "+06:00");
    const parsed = new Date(normalized);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  // Timezone না থাকলে UTC ধরে নিয়ে SOURCE_TZ_OFFSET_HOURS বিয়োগ করা হচ্ছে
  const parsed = new Date(`${combined} UTC`);
  if (Number.isNaN(parsed.getTime())) {
    const fallback = new Date(combined);
    return Number.isNaN(fallback.getTime()) ? null : fallback;
  }
  return new Date(parsed.getTime() - SOURCE_TZ_OFFSET_HOURS * 60 * 60 * 1000);
}

/** "Nov 20, 2026, 06:30:55 AM" ফরম্যাটে BST সময় */
function formatBstDateTime(dateObj) {
  if (!dateObj || Number.isNaN(dateObj.getTime())) return "";
  const bst = new Date(dateObj.getTime() + 6 * 60 * 60 * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  const h24 = bst.getUTCHours();
  const h12 = h24 % 12 === 0 ? 12 : h24 % 12;

  return (
    `${MONTHS[bst.getUTCMonth()]} ${pad(bst.getUTCDate())}, ${bst.getUTCFullYear()}, ` +
    `${pad(h12)}:${pad(bst.getUTCMinutes())}:${pad(bst.getUTCSeconds())} ${h24 < 12 ? "AM" : "PM"}`
  );
}

function resolveStatus(raw, startDate, isHot, now) {
  if (raw.status && typeof raw.status === "string") {
    return raw.status.trim().toUpperCase();
  }
  if (!startDate) {
    return isHot ? "LIVE" : "UPCOMING";
  }
  const nowMs = now.getTime();
  const startMs = startDate.getTime();
  const liveWindowMs = 4 * 60 * 60 * 1000; // শুরু হওয়ার ৪ ঘণ্টা পর্যন্ত LIVE ধরা হলো

  if (nowMs < startMs) return "UPCOMING";
  if (nowMs <= startMs + liveWindowMs || isHot) return "LIVE";
  return "COMPLETED";
}

/**
 * স্ট্রিম অবজেক্টকে "url|user-agent=...&Referer=...&Origin=...&drm_key=..." ফরম্যাটে রূপান্তর
 */
function buildPipeStreamUrl({ url, userAgent, referer, origin, drm }) {
  const cleanUrl = (url || "").trim();
  if (!cleanUrl) return "";

  const [baseUrl, existingPipe = ""] = cleanUrl.split("|");
  const params = existingPipe ? existingPipe.split("&").filter(Boolean) : [];
  const hasParam = (key) =>
    params.some((p) => p.split("=")[0].trim().toLowerCase() === key.toLowerCase());

  if (userAgent && !hasParam("user-agent")) {
    params.push(`user-agent=${userAgent}`);
  }
  if (referer && !hasParam("referer")) {
    params.push(`Referer=${referer}`);
  }
  if (origin && !hasParam("origin")) {
    params.push(`Origin=${origin}`);
  }
  if (drm && !hasParam("drm_key") && !hasParam("drm_license")) {
    const keyName = drm.startsWith("http") ? "drm_license" : "drm_key";
    params.push(`${keyName}=${drm}`);
  }

  return params.length > 0 ? `${baseUrl}|${params.join("&")}` : baseUrl;
}

/** স্ট্রিম লিস্ট থেকে stream_url_alpha অবজেক্ট তৈরি */
function buildStreamMap(streams) {
  const map = {};
  const nameCount = {};

  streams.forEach((s, i) => {
    const finalUrl = buildPipeStreamUrl(s);
    if (!finalUrl) return;

    const baseName = (s.name || `Server ${i + 1}`).trim();
    if (!Object.prototype.hasOwnProperty.call(map, baseName)) {
      map[baseName] = finalUrl;
      nameCount[baseName] = 1;
    } else {
      nameCount[baseName] += 1;
      map[`${baseName} (${nameCount[baseName]})`] = finalUrl;
    }
  });

  return map;
}

// ── Event decoding ────────────────────────────────────────────────────────────
function extractEncrypted(id, raw) {
  const streams = Array.isArray(raw.s)
    ? raw.s
        .filter((s) => s && typeof s === "object")
        .map((s) => ({
          name: dec(s.n),
          url: dec(s.u),
          referer: dec(s.ref),
          origin: dec(s.org || s.origin),
          userAgent: dec(s.ua),
          drm: decodeDrmPlain(s.drm),
        }))
    : [];

  return {
    id,
    date: raw.d || "",
    time: raw.t || "",
    league: dec(raw.l),
    team1: dec(raw.t1),
    team2: dec(raw.t2),
    logo1: dec(raw.lg1),
    logo2: dec(raw.lg2),
    leagueLogo: dec(raw.llg),
    isHot: Boolean(raw.is_hot),
    visibility: raw.visibility || "",
    raw,
    streams,
  };
}

/** enc নেই এমন প্লেইন ফরম্যাট */
function extractPlain(id, raw) {
  const list = Array.isArray(raw.link_live)
    ? raw.link_live
    : Array.isArray(raw.buttons)
    ? raw.buttons
    : [];

  const streams = list
    .filter((s) => s && typeof s === "object")
    .map((s, i) => ({
      name: s.display_name || s.name || `Server ${i + 1}`,
      url: s.stream_link || s.videoURL || s.url || "",
      referer: s.referer || raw.referer || s.headers?.Referer || "",
      origin: s.origin || s.headers?.Origin || "",
      userAgent: s.userAgent || s.user_agent || s.headers?.["User-Agent"] || "",
      drm: decodeDrmPlain(s.drm || s.drmLicenseUrl || s.drm_key || ""),
    }));

  return {
    id,
    date: raw.d || raw.matchDate || "",
    time: raw.t || raw.matchTime || "",
    league: raw.league_name || raw.league || "",
    team1: raw.localteam_name || raw.team1 || "",
    team2: raw.visitorteam_name || raw.team2 || "",
    logo1: raw.localteam_logo || raw.logo1 || "",
    logo2: raw.visitorteam_logo || raw.logo2 || "",
    leagueLogo: raw.league_logo || raw.leagueLogo || "",
    isHot: Boolean(raw.is_hot),
    visibility: raw.visibility || "",
    raw,
    streams,
  };
}

function formatEvent(id, raw, now, usedIds) {
  const decoded = raw.enc === true ? extractEncrypted(id, raw) : extractPlain(id, raw);
  const title = buildTitle(decoded.team1, decoded.team2, decoded.league, id);
  const { sport, sub_category } = detectSport(decoded.league, title, raw);

  const startDate = parseEventDate(decoded.date, decoded.time);
  const formattedTime = startDate
    ? formatBstDateTime(startDate)
    : `${decoded.date} ${decoded.time}`.trim();

  // match_id তৈরি এবং ডুপ্লিকেট এড়ানো
  let matchId = String(raw.match_id || slugify(title) || id);
  if (usedIds.has(matchId)) {
    matchId = `${matchId}-${slugify(id) || usedIds.size}`;
  }
  usedIds.add(matchId);

  const isFree =
    typeof raw.is_free === "boolean"
      ? raw.is_free
      : ["free", "public"].includes(String(decoded.visibility).toLowerCase());

  const logo = raw.logo || decoded.leagueLogo || decoded.logo1 || decoded.logo2 || "";
  const coverImage = raw.cover_image || decoded.logo1 || decoded.leagueLogo || decoded.logo2 || "";

  return {
    _sortMs: startDate ? startDate.getTime() : Number.MAX_SAFE_INTEGER,
    data: {
      match_id: matchId,
      title,
      sport,
      sub_category,
      status: resolveStatus(raw, startDate, decoded.isHot, now),
      start_time_bst: formattedTime,
      time: formattedTime,
      logo,
      cover_image: coverImage,
      is_free: isFree,
      stream_url_alpha: buildStreamMap(decoded.streams),
    },
  };
}

// ── Fetch ─────────────────────────────────────────────────────────────────────
async function fetchOnce() {
  const timestamp = String(Date.now());
  const res = await fetch(API_URL, {
    method: "GET",
    headers: {
      "x-timestamp": timestamp,
      "x-signature": sign(timestamp),
      "User-Agent": USER_AGENT,
      Accept: "application/json",
    },
    signal: AbortSignal.timeout(20000),
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  if (text.includes("Access Denied")) throw new Error(`API: ${text.slice(0, 200)}`);

  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error("JSON parse failed: " + e.message);
  }
}

async function fetchData() {
  let lastErr;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fetchOnce();
    } catch (err) {
      lastErr = err;
      console.warn(`⚠️  Attempt ${attempt}/${MAX_RETRIES} failed: ${err.message}`);
      if (attempt < MAX_RETRIES) await new Promise((r) => setTimeout(r, 2000 * attempt));
    }
  }
  throw lastErr;
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log(`[${new Date().toISOString()}] Fetching from API...`);

  const raw = await fetchData();
  if (!raw || typeof raw !== "object") throw new Error("Invalid response from API");

  const entries = Array.isArray(raw)
    ? raw.map((e, i) => [String(e?.id ?? i), e])
    : Object.entries(raw);

  const now = new Date();
  const usedIds = new Set();

  const formatted = entries
    .filter(([, e]) => e && typeof e === "object")
    .map(([id, e]) => formatEvent(id, e, now, usedIds));

  if (formatted.length === 0) {
    throw new Error("API returned 0 events — পুরনো events.json অক্ষত রাখা হলো");
  }

  // সময় অনুযায়ী সর্ট করে কেবল চূড়ান্ত অবজেক্ট রাখা
  formatted.sort((a, b) => a._sortMs - b._sortMs);
  const events = formatted.map((item) => item.data);

  const readable = `${formatBstDateTime(now)} BST`;

  const output = {
    last_updated: readable,
    last_updated_iso: now.toISOString(),
    total_events: events.length,
    events,
  };

  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2), "utf8");
  console.log(`[${now.toISOString()}] ✅ Saved ${events.length} events → last_updated: ${readable}`);
}

main().catch((err) => {
  console.error("❌ Error:", err.message);
  process.exit(1);
});
