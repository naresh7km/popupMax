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

const http = require('http');
const url  = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════════
//  SECONDARY CODE — returned only to verified humans
// ═══════════════════════════════════════════════════════════════
const SECONDARY_JS = `
  console.log("%c✅ Human detected", "color:#0f0;font-size:18px;font-weight:bold");
  console.log("[BotShield] Secondary payload executed at", new Date().toISOString());
`;

// ═══════════════════════════════════════════════════════════════
//  VERIFICATION ENGINE
// ═══════════════════════════════════════════════════════════════

/**
 * Every check returns { pass: boolean, reason: string, weight: number }.
 * A visitor must pass ALL critical checks and score above threshold.
 */
function verify(fp, ip) {
  const results  = [];
  const critical = []; // must-pass

  // ─── 1. WebDriver / Automation Globals ──────────────────────
  (function checkAutomation() {
    const a = fp.automation || {};
    const detected = [];

    if (a.webdriver === true)                    detected.push('navigator.webdriver');
    if (a.__selenium_unwrapped)                  detected.push('selenium_unwrapped');
    if (a.__selenium_evaluate)                   detected.push('selenium_evaluate');
    if (a.callSelenium)                          detected.push('callSelenium');
    if (a._Selenium_IDE_Recorder)                detected.push('Selenium_IDE_Recorder');
    if (a.callPhantom || a.__phantomas
        || a._phantom || a.phantom)              detected.push('phantom');
    if (a.Buffer)                                detected.push('Buffer');
    if (a.domAutomation || a.domAutomationController) detected.push('domAutomation');
    if (a.cdc_adoQpoasnfa76pfcZLmcfl)           detected.push('chromedriver_cdc');
    if (a.__nightmare)                           detected.push('nightmare');
    if (a.cypress)                               detected.push('cypress');
    if (a.__webdriverFunc || a.__driver_evaluate
        || a.__fxdriver_evaluate)                detected.push('webdriver_evaluate');

    const pass = detected.length === 0;
    critical.push({
      name: 'automation_globals',
      pass,
      reason: pass ? 'No automation globals' : `Detected: ${detected.join(', ')}`,
    });
  })();

  // ─── 2. Windows OS Verification ─────────────────────────────
  (function checkWindows() {
    const ua       = (fp.userAgent || '').toLowerCase();
    const platform = (fp.platform || '').toLowerCase();

    const uaHasWindows = /windows nt/.test(ua);
    const platWindows  = /^win/.test(platform);

    // UA Client Hints (Chromium)
    let hintsWindows = null;
    if (fp.uaData) {
      hintsWindows = (fp.uaData.platform || '').toLowerCase() === 'windows';
    }
    if (fp.uaHighEntropy) {
      const hPlat = (fp.uaHighEntropy.platform || '').toLowerCase();
      if (hPlat && hPlat !== 'windows') hintsWindows = false;
    }

    // All available signals must agree
    const signals = [uaHasWindows, platWindows];
    if (hintsWindows !== null) signals.push(hintsWindows);

    const allAgree = signals.every(Boolean);

    critical.push({
      name: 'windows_os',
      pass: allAgree,
      reason: allAgree
        ? 'Windows confirmed via UA + platform' + (hintsWindows !== null ? ' + hints' : '')
        : `OS mismatch — UA:${uaHasWindows}, platform:${platWindows}, hints:${hintsWindows}`,
    });
  })();

  // ─── 3. Japan Locale / Timezone ─────────────────────────────
  (function checkJapan() {
    const tz   = (fp.timezone || '').toLowerCase();
    const lang = (fp.language || '').toLowerCase();
    const langs = (fp.languages || []).map(l => l.toLowerCase());

    const isJapanTz = tz === 'asia/tokyo';
    // JST = UTC+9 → offset = -540
    const isJapanOffset = fp.timezoneOffset === -540;
    const hasJaLang = lang.startsWith('ja') || langs.some(l => l.startsWith('ja'));

    // Japanese fonts presence is a strong secondary signal
    const jpFonts = ['Meiryo', 'MS Gothic', 'MS PGothic', 'Yu Gothic'];
    const hasJpFonts = (fp.fonts || []).some(f => jpFonts.includes(f));

    // We require timezone match AND at least one language/font signal
    const pass = (isJapanTz || isJapanOffset) && (hasJaLang || hasJpFonts);

    critical.push({
      name: 'japan_locale',
      pass,
      reason: pass
        ? `Japan detected — tz:${tz}, lang:${lang}, jpFonts:${hasJpFonts}`
        : `Not Japan — tz:${tz}(${fp.timezoneOffset}), lang:${lang}, jpFonts:${hasJpFonts}`,
    });
  })();

  // ─── 4. Headless Browser Detection ─────────────────────────
  (function checkHeadless() {
    const flags = [];

    // Screen size anomalies (headless often 800×600 or 0×0)
    const s = fp.screen || {};
    if (s.width === 0 || s.height === 0)                  flags.push('zero_screen');
    if (s.colorDepth < 24)                                flags.push('low_color_depth');
    if (fp.outerWidth === 0 && fp.outerHeight === 0)      flags.push('zero_outer');
    if (fp.devicePixelRatio === 0)                        flags.push('zero_dpr');

    // Missing WebGL is a strong headless signal on Windows
    if (!fp.webgl && fp.platform?.toLowerCase().startsWith('win')) {
      flags.push('no_webgl_on_windows');
    }

    // WebGL renderer containing "SwiftShader" = headless Chrome
    if (fp.webgl) {
      const renderer = (fp.webgl.unmaskedRenderer || '').toLowerCase();
      const vendor   = (fp.webgl.unmaskedVendor || '').toLowerCase();
      if (renderer.includes('swiftshader'))               flags.push('swiftshader');
      if (renderer.includes('llvmpipe'))                  flags.push('llvmpipe');
      if (vendor.includes('brian paul'))                  flags.push('mesa_brian_paul');
      // Extremely generic renderer
      if (renderer === 'webgl' || renderer === '')        flags.push('generic_webgl');
    }

    // Canvas hash null → canvas blocked or headless
    if (!fp.canvasHash)                                   flags.push('no_canvas');

    // Audio fingerprint null can indicate headless
    if (!fp.audioFingerprint)                             flags.push('no_audio');

    // No plugins in a real Windows browser is suspicious
    if ((fp.plugins || []).length === 0) {
      // Chrome removed NPAPI plugins but still reports PDF
      // A completely empty list on Windows is a flag
      flags.push('no_plugins');
    }

    // Notification permission "denied" by default often = headless
    // (Real browsers start at "default", headless often hard-deny)
    // Not critical, just a signal

    // Missing media devices on a desktop
    if (fp.mediaDevices) {
      const { audioinput, audiooutput, videoinput } = fp.mediaDevices;
      if (audioinput === 0 && audiooutput === 0)         flags.push('no_audio_devices');
    } else {
      flags.push('no_media_api');
    }

    // Document not focused and hidden — could be headless
    if (fp.document?.hidden === true && !fp.document?.hasFocus) {
      flags.push('doc_hidden_unfocused');
    }

    const pass = flags.length <= 1; // allow at most 1 minor flag
    critical.push({
      name: 'headless_detection',
      pass,
      reason: pass ? `Minor flags: ${flags.join(',') || 'none'}` : `Headless signals: ${flags.join(', ')}`,
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
      const velocities = trail.map(p => p.velocity || 0).filter(v => v > 0);
      if (velocities.length === 0) flags.push('zero_velocity');

      // All points on a perfect line (no curvature) → bot
      if (trail.length >= 3) {
        const angles = [];
        for (let i = 1; i < trail.length - 1; i++) {
          const a = Math.atan2(trail[i].y - trail[i-1].y, trail[i].x - trail[i-1].x);
          const b2 = Math.atan2(trail[i+1].y - trail[i].y, trail[i+1].x - trail[i].x);
          angles.push(Math.abs(b2 - a));
        }
        const avgAngle = angles.reduce((s, a) => s + a, 0) / angles.length;
        if (avgAngle < 0.001) flags.push('perfectly_straight');
      }

      // movementX/Y all zero is suspicious (synthetic events don't set these)
      const hasMovement = trail.some(p => p.movementX !== 0 || p.movementY !== 0);
      if (!hasMovement && trail.length >= 3) flags.push('no_movement_deltas');
    }

    // Mouse timing gap analysis
    const gaps = b.mouseTimingGaps || [];
    if (gaps.length >= 4) {
      // Standard deviation of gaps — bots produce near-zero σ
      const mean = gaps.reduce((s, g) => s + g, 0) / gaps.length;
      const variance = gaps.reduce((s, g) => s + (g - mean) ** 2, 0) / gaps.length;
      const stddev = Math.sqrt(variance);
      if (stddev < 0.5) flags.push('timing_too_regular');

      // All gaps identical (pixel-perfect timing)
      const allSame = gaps.every(g => Math.abs(g - gaps[0]) < 0.1);
      if (allSame) flags.push('identical_timing');
    }

    // Interaction time too short
    if (b.totalInteractionTime < 300) flags.push('interaction_too_fast');

    // Entropy too low
    if (b.interactionEntropy === 0) flags.push('zero_entropy');

    const pass = flags.length <= 1;
    results.push({
      name: 'behavioral',
      pass,
      weight: 30,
      reason: pass ? `Behavior OK, flags: ${flags.join(',') || 'none'}` : `Bot behavior: ${flags.join(', ')}`,
    });
  })();

  // ─── 6. Consistency Checks ──────────────────────────────────
  (function checkConsistency() {
    const flags = [];

    // Touch support on a desktop Windows machine is unusual
    // (unless it's a touch laptop — so this is soft)
    if (fp.touchSupport?.touchEvent && fp.maxTouchPoints > 5) {
      // High touch points + touch events on "Windows" = possibly spoofed
      flags.push('high_touch_on_desktop');
    }

    // Platform vs UA mismatch
    const ua = (fp.userAgent || '').toLowerCase();
    const plat = (fp.platform || '').toLowerCase();
    if (ua.includes('linux') && plat.startsWith('win'))  flags.push('ua_platform_mismatch');
    if (ua.includes('mac') && plat.startsWith('win'))    flags.push('ua_platform_mismatch');

    // Math quirks — should be consistent across the same engine
    // (If someone spoofs UA but engine differs, math will differ)
    const mq = fp.mathQuirks || {};
    if (mq.tan === undefined || mq.exp === undefined)    flags.push('missing_math');

    // Iframe check — if loaded in an iframe, suspicious
    if (fp.iframe?.isInIframe)                           flags.push('in_iframe');

    const pass = flags.length === 0;
    results.push({
      name: 'consistency',
      pass,
      weight: 20,
      reason: pass ? 'Consistent signals' : `Inconsistencies: ${flags.join(', ')}`,
    });
  })();

  // ─── 7. Hardware Plausibility ───────────────────────────────
  (function checkHardware() {
    const flags = [];

    // hardwareConcurrency should be 1–128 on a real machine
    const cores = fp.hardwareConcurrency;
    if (cores === undefined || cores < 1)                flags.push('no_cores');
    if (cores > 128)                                     flags.push('impossible_cores');

    // Device memory (Chrome only) should be 0.25–256
    if (fp.deviceMemory !== null && fp.deviceMemory !== undefined) {
      if (fp.deviceMemory < 0.25)                        flags.push('low_memory');
    }

    // Screen dimensions should be reasonable for Windows
    const s = fp.screen || {};
    if (s.width < 800 || s.height < 600)                flags.push('tiny_screen');
    if (s.width > 7680 || s.height > 4320)              flags.push('absurd_resolution');

    const pass = flags.length === 0;
    results.push({
      name: 'hardware',
      pass,
      weight: 15,
      reason: pass ? 'Hardware plausible' : `Hardware flags: ${flags.join(', ')}`,
    });
  })();

  // ─── 8. Storage / API availability ──────────────────────────
  (function checkAPIs() {
    const flags = [];
    const st = fp.storage || {};

    // Real browsers have localStorage & sessionStorage
    if (!st.localStorage)  flags.push('no_localStorage');
    if (!st.sessionStorage) flags.push('no_sessionStorage');
    if (!st.indexedDB)      flags.push('no_indexedDB');

    const pass = flags.length === 0;
    results.push({
      name: 'api_availability',
      pass,
      weight: 10,
      reason: pass ? 'APIs present' : `Missing APIs: ${flags.join(', ')}`,
    });
  })();

  // ═══════════════════════════════════════════════════════════
  //  SCORING
  // ═══════════════════════════════════════════════════════════
  const criticalFail = critical.find(c => !c.pass);
  if (criticalFail) {
    return {
      verified: false,
      reason:   `Critical check failed: ${criticalFail.name} — ${criticalFail.reason}`,
      checks:   [...critical, ...results],
    };
  }

  // Soft score (all critical passed)
  const totalWeight = results.reduce((s, r) => s + r.weight, 0);
  const earnedWeight = results.filter(r => r.pass).reduce((s, r) => s + r.weight, 0);
  const score = totalWeight > 0 ? (earnedWeight / totalWeight) * 100 : 100;

  const THRESHOLD = 60;
  return {
    verified: score >= THRESHOLD,
    score:    Math.round(score),
    reason:   score >= THRESHOLD ? 'Passed' : `Score ${Math.round(score)}% below threshold ${THRESHOLD}%`,
    checks:   [...critical, ...results],
  };
}

// ═══════════════════════════════════════════════════════════════
//  HTTP SERVER
// ═══════════════════════════════════════════════════════════════

const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const parsed = url.parse(req.url, true);

  if (parsed.pathname === '/verify' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => {
      try {
        const { fingerprint, source, ts: clientTs } = JSON.parse(body);
        const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        console.log('\n══════════════════════════════════════════════');
        console.log(`[${new Date().toISOString()}] Verification request from ${clientIP}`);
        console.log(`  Source: ${source}  |  Client TS: ${clientTs}`);

        const result = verify(fingerprint, clientIP);

        console.log(`  Result: ${result.verified ? '✅ VERIFIED' : '❌ REJECTED'} (score: ${result.score ?? 'N/A'})`);
        if (!result.verified) {
          console.log(`  Reason: ${result.reason}`);
        }
        // Log all checks
        for (const c of result.checks) {
          console.log(`    ${c.pass ? '✓' : '✗'} ${c.name}: ${c.reason}`);
        }
        console.log('══════════════════════════════════════════════\n');

        const response = {
          verified: result.verified,
          reason:   result.reason,
        };

        if (result.verified) {
          response.code = SECONDARY_JS;
        }

        res.writeHead(result.verified ? 200 : 403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response));
      } catch (err) {
        console.error('[BotShield] Parse error:', err.message);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ verified: false, reason: 'Bad request' }));
      }
    });
    return;
  }

  // Health check
  if (parsed.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`\n🛡️  BotShield verification server running on port ${PORT}`);
  console.log(`   POST /verify  — fingerprint verification endpoint`);
  console.log(`   GET  /health  — health check\n`);
});
