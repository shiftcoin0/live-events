/**
 * Sports events sync — Priofy API → events.json
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ── Config (GitHub Secrets / env দিয়ে বদলানো যায়, না দিলে ডিফল্ট) ──────────────
const API_URL = process.env.API_URL || "https://priofyapi.shopnilofficial47.workers.dev/";
const HMAC_SECRET = process.env.HMAC_SECRET || "PriofySecure2026_LiveApp";
const AES_KEY = process.env.AES_KEY || "PriofySecure2026"; // 16 bytes
const AES_IV = process.env.AES_IV || "PriofyAppIV_2026"; // 16 bytes

// সোর্স API-এর সময় BST (বাংলাদেশ সময়) হলে 6 রাখুন; UTC হলে 0 করুন
const SOURCE_TZ_OFFSET_HOURS = Number(process.env.SOURCE_TZ_OFFSET_HOURS ?? 6);

const USER_AGENT =
  "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36";

const OUTPUT_FILE = path.join(__dirname, "..", "events.json");
const MAX_RETRIES = 3;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

const MONTH_MAP = {
  jan: 1, january: 1,
  feb: 2, february: 2,
  mar: 3, march: 3,
  apr: 4, april: 4,
  may: 5,
  jun: 6, june: 6,
  jul: 7, july: 7,
  aug: 8, august: 8,
  sep: 9, sept: 9, september: 9,
  oct: 10, october: 10,
  nov: 11, november: 11,
  dec: 12, december: 12,
};

const KNOWN_STATUSES = new Set([
  "UPCOMING",
  "LIVE",
  "ENDED",
  "FINISHED",
  "COMPLETED",
  "HALFTIME",
  "HT",
  "FT",
  "NS",
  "SCHEDULED",
  "POSTPONED",
  "CANCELLED",
  "CANCELED",
  "ABANDONED",
  "DELAYED",
  "INPLAY",
  "PLAYING",
  "SOON",
  "OVER",
]);

const EMPTY_VALUES = new Set(["", "NULL", "NONE", "N/A", "NA", "UNDEFINED"]);

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
      if (decoded && /^[\x20-\x7E]+$/.test(decoded)) {
        return decoded;
      }
    } catch {
      return trimmed;
    }
  }
  return trimmed;
}

/** স্ট্যাটাস ডিকোড (AES, plain text অথবা Base64 সব ফরম্যাট সাপোর্ট করবে) */
function decStatus(val) {
  if (val === null || val === undefined) return "";
  if (typeof val !== "string") return "";
  const trimmed = val.trim();
  if (!trimmed) return "";

  const viaAes = aesDecrypt(trimmed);
  if (viaAes !== null) {
    const clean = viaAes.trim().toUpperCase();
    return EMPTY_VALUES.has(clean) ? "" : clean;
  }

  const upper = trimmed.toUpperCase();
  if (EMPTY_VALUES.has(upper)) return "";
  if (KNOWN_STATUSES.has(upper)) return upper;

  const looksBase64 = /^[A-Za-z0-9+/]+=*$/.test(trimmed) && trimmed.length % 4 === 0;
  if (looksBase64) {
    try {
      const decoded = Buffer.from(trimmed, "base64").toString("utf8").trim().toUpperCase();
      if (decoded && /^[A-Z0-9 _-]+$/.test(decoded) && !EMPTY_VALUES.has(decoded)) {
        return decoded;
      }
    } catch {
      // ignore
    }
  }

  return upper;
}

function isTruthyFlag(val) {
  if (val === true || val === 1) return true;
  if (typeof val === "string") {
    const v = dec(val).toLowerCase();
    return v === "true" || v === "1" || v === "yes";
  }
  return false;
}

/** DRM ডিকোড: plain "kid:key" বা license URL ফেরত দেয় */
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
    const s = dec(String(raw.sport));
    const sub = raw.sub_category ? dec(String(raw.sub_category)) : s;
    return { sport: s, sub_category: sub };
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

/** যেকোনো date + time ফরম্যাট থেকে নির্ভুলভাবে Date অবজেক্ট তৈরি */
function parseEventDate(dateStr, timeStr) {
  const combined = `${(dateStr || "").trim()} ${(timeStr || "").trim()}`.trim();
  if (!combined) return null;

  // Explicit timezone চেক
  let explicitOffsetMin = null;
  if (/\bBST\b/i.test(combined)) explicitOffsetMin = 6 * 60;
  else if (/\bIST\b/i.test(combined)) explicitOffsetMin = 5 * 60 + 30;
  else if (/\b(UTC|GMT)\b/i.test(combined) || /Z$/i.test(combined)) explicitOffsetMin = 0;
  else {
    const tzMatch = combined.match(/([+-])(\d{2}):?(\d{2})\s*$/);
    if (tzMatch) {
      const signVal = tzMatch[1] === "-" ? -1 : 1;
      explicitOffsetMin = signVal * (Number(tzMatch[2]) * 60 + Number(tzMatch[3]));
    }
  }

  // Date অংশ বের করা
  let year, month, day, m;
  if ((m = combined.match(/\b(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})\b/))) {
    year = Number(m[1]);
    month = Number(m[2]);
    day = Number(m[3]);
  } else if ((m = combined.match(/\b(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})\b/))) {
    const p1 = Number(m[1]);
    const p2 = Number(m[2]);
    year = Number(m[3]);
    if (p2 > 12) {
      month = p1;
      day = p2;
    } else {
      day = p1;
      month = p2;
    }
  } else if ((m = combined.match(/\b(\d{1,2})\s+([A-Za-z]+),?\s+(\d{4})\b/))) {
    day = Number(m[1]);
    month = MONTH_MAP[m[2].toLowerCase()];
    year = Number(m[3]);
  } else if ((m = combined.match(/\b([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})\b/))) {
    month = MONTH_MAP[m[1].toLowerCase()];
    day = Number(m[2]);
    year = Number(m[3]);
  }

  // Time অংশ বের করা (21:00, 09:00 PM, 9:00:30 pm ইত্যাদি)
  let hour = 0;
  let minute = 0;
  let second = 0;
  const tm = combined.match(/\b(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)?\b/i);
  if (tm) {
    hour = Number(tm[1]);
    minute = Number(tm[2]);
    second = tm[3] ? Number(tm[3]) : 0;
    const ampm = tm[4] ? tm[4].toUpperCase() : "";
    if (ampm === "PM" && hour < 12) hour += 12;
    if (ampm === "AM" && hour === 12) hour = 0;
  }

  if (year && month && day && month >= 1 && month <= 12 && day >= 1 && day <= 31) {
    const offsetMin =
      explicitOffsetMin !== null ? explicitOffsetMin : SOURCE_TZ_OFFSET_HOURS * 60;
    const utcMs = Date.UTC(year, month - 1, day, hour, minute, second) - offsetMin * 60 * 1000;
    return new Date(utcMs);
  }

  // Fallback native Date
  const normalized = combined.replace(/\bBST\b/i, "+06:00");
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) return null;
  if (explicitOffsetMin === null) {
    return new Date(parsed.getTime() - SOURCE_TZ_OFFSET_HOURS * 60 * 60 * 1000);
  }
  return parsed;
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
  // ১) সোর্স API থেকে সরাসরি স্ট্যাটাস চেক
  const rawStatusCandidates = [
    raw.status,
    raw.st,
    raw.match_status,
    raw.matchStatus,
    raw.event_status,
    raw.eventStatus,
    raw.live_status,
    raw.liveStatus,
    raw.current_status,
    raw.status_text,
    raw.state,
    raw.match_state,
    raw.badge,
  ];

  for (const candidate of rawStatusCandidates) {
    const decoded = decStatus(candidate);
    if (decoded) {
      return decoded;
    }
  }

  // ২) সোর্সে বুলিয়ান/স্ট্রিং ফ্ল্যাগ থাকলে
  if (isTruthyFlag(raw.is_live) || isTruthyFlag(raw.isLive) || isTruthyFlag(raw.live)) return "LIVE";
  if (isTruthyFlag(raw.is_ended) || isTruthyFlag(raw.isEnded) || isTruthyFlag(raw.ended)) return "ENDED";
  if (isTruthyFlag(raw.is_finished) || isTruthyFlag(raw.isFinished) || isTruthyFlag(raw.finished)) return "FINISHED";

  // ৩) সোর্স API-তে কোনো স্ট্যাটাস না থাকলে সময় অনুযায়ী fallback
  if (!startDate) {
    return isHot ? "LIVE" : "UPCOMING";
  }

  const nowMs = now.getTime();
  const startMs = startDate.getTime();
  const liveWindowMs = 4 * 60 * 60 * 1000;

  if (nowMs < startMs) return "UPCOMING";
  if (nowMs <= startMs + liveWindowMs || isHot) return "LIVE";
  return "ENDED";
}

function buildPipeStreamUrl({ url, userAgent, referer, origin, drm }) {
  const cleanUrl = (url || "").trim();
  if (!cleanUrl) return "";

  const [baseUrl, existingPipe = ""] = cleanUrl.split("|");
  const params = existingPipe ? existingPipe.split("&").filter(Boolean) : [];
  const hasParam = (key) =>
    params.some((p) => p.split("=")[0].trim().toLowerCase() === key.toLowerCase());

  if (userAgent && !hasParam("user-agent")) params.push(`user-agent=${userAgent}`);
  if (referer && !hasParam("referer")) params.push(`Referer=${referer}`);
  if (origin && !hasParam("origin")) params.push(`Origin=${origin}`);
  if (drm && !hasParam("drm_key") && !hasParam("drm_license")) {
    const keyName = drm.startsWith("http") ? "drm_license" : "drm_key";
    params.push(`${keyName}=${drm}`);
  }

  return params.length > 0 ? `${baseUrl}|${params.join("&")}` : baseUrl;
}

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
    date: dec(raw.d) || "",
    time: dec(raw.t) || "",
    league: dec(raw.l),
    team1: dec(raw.t1),
    team2: dec(raw.t2),
    logo1: dec(raw.lg1),
    logo2: dec(raw.lg2),
    leagueLogo: dec(raw.llg),
    isHot: isTruthyFlag(raw.is_hot),
    visibility: raw.visibility || "",
    raw,
    streams,
  };
}

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
    isHot: isTruthyFlag(raw.is_hot),
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
    _rawDate: decoded.date,
    _rawTime: decoded.time,
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

  const validEntries = entries.filter(([, e]) => e && typeof e === "object");
  const formatted = validEntries.map(([id, e]) => formatEvent(id, e, now, usedIds));

  if (formatted.length === 0) {
    throw new Error("API returned 0 events — পুরনো events.json অক্ষত রাখা হলো");
  }

  // ডিবাগ লগ (প্রথম ইভেন্টের কী ও সময় যাচাই করার জন্য)
  console.log("ℹ️ Sample raw keys:", Object.keys(validEntries[0][1]));
  console.log(
    `ℹ️ Sample event: "${formatted[0].data.title}" | raw="${formatted[0]._rawDate} ${formatted[0]._rawTime}" | start_time_bst="${formatted[0].data.start_time_bst}" | status="${formatted[0].data.status}"`
  );

  formatted.sort((a, b) => a._sortMs - b._sortMs);
  const events = formatted.map((item) => item.data);

  const statusSummary = events.reduce((acc, ev) => {
    acc[ev.status] = (acc[ev.status] || 0) + 1;
    return acc;
  }, {});

  const readable = `${formatBstDateTime(now)} BST`;

  const output = {
    last_updated: readable,
    last_updated_iso: now.toISOString(),
    total_events: events.length,
    events,
  };

  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2), "utf8");
  console.log(
    `[${now.toISOString()}] ✅ Saved ${events.length} events → Status summary:`,
    statusSummary
  );
}

main().catch((err) => {
  console.error("❌ Error:", err.message);
  process.exit(1);
});
