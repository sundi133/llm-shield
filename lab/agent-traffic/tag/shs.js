/* shs.js: lab prototype of Shield's agent-detection tag (spec section 2.3).
 *
 * Sends counts, timings and hashes only: never key codes, field values, page
 * text, query strings or full URLs. One beacon on load (device and automation
 * traits), one on submit or leaving the page (interaction summary and trap
 * results). The collector answers 204 with no body, so nothing here can learn
 * a verdict.
 *
 * Install: <script src="/_shs/shs.js?k=SITE_KEY" async></script>
 */
(function () {
  'use strict';
  var d = document, w = window, n = navigator;
  if (w.__shs) return;
  w.__shs = true;

  var me = d.currentScript;
  var KEY = '';
  try { KEY = new URL(me.src, location.href).searchParams.get('k') || ''; } catch (e) { /* no key */ }
  var ENDPOINT = (me && me.getAttribute('data-endpoint')) || '/_shs/b';
  var PAGE = location.pathname.replace(/\/\d+(?=\/|$)/g, '/:id').slice(0, 120);

  // ── session join: first-party cookie, 30-minute idle expiry ──────────────
  function hex(len) {
    var a = new Uint8Array(len);
    (w.crypto || w.msCrypto).getRandomValues(a);
    return Array.prototype.map.call(a, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  var m = d.cookie.match(/(?:^|; )_shs=([0-9a-f]{24})(?:;|$)/);
  var SHS = m ? m[1] : hex(12);
  d.cookie = '_shs=' + SHS + '; path=/; max-age=1800; SameSite=Lax';

  function fnv(str) {
    var h = 0x811c9dc5;
    for (var i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return ('0000000' + h.toString(16)).slice(-8);
  }

  // ── device (A9, device cohorts) ───────────────────────────────────────────
  function renderer() {
    try {
      var gl = d.createElement('canvas').getContext('webgl');
      if (!gl) return ['', 'none'];
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      var r = String(ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER) || '');
      var cls = /swiftshader|llvmpipe|softpipe|software|basic render/i.test(r) ? 'software'
        : /vmware|virtualbox|parallels|qxl|virgl|virtio|hyper-v|red hat/i.test(r) ? 'vm' : r ? 'gpu' : 'unknown';
      return [r.slice(0, 120), cls];
    } catch (e) { return ['', 'error']; }
  }
  function canvasHash() {
    try {
      var c = d.createElement('canvas'); c.width = 240; c.height = 40;
      var x = c.getContext('2d');
      x.textBaseline = 'top'; x.font = '16px Arial'; x.fillStyle = '#f60'; x.fillRect(100, 1, 62, 20);
      x.fillStyle = '#069'; x.fillText('Shield tag, 0123 éß', 2, 15);
      x.fillStyle = 'rgba(102,204,0,0.7)'; x.fillText('Shield tag, 0123 éß', 4, 17);
      return fnv(c.toDataURL());
    } catch (e) { return ''; }
  }
  function fontsHash() {
    var fonts = ['Arial', 'Helvetica Neue', 'Segoe UI', 'Roboto', 'Ubuntu', 'DejaVu Sans', 'Liberation Sans',
      'Noto Sans', 'Calibri', 'Cambria', 'Menlo', 'Consolas', 'Courier New', 'Georgia', 'Verdana',
      'Tahoma', 'Trebuchet MS', 'Futura', 'Gill Sans', 'Optima', 'SF Pro Text', 'Cantarell', 'Droid Sans'];
    try {
      var x = d.createElement('canvas').getContext('2d'), s = 'mmmmmmmmmmlli10OQ', base = {}, out = [];
      ['monospace', 'serif'].forEach(function (b) { x.font = '72px ' + b; base[b] = x.measureText(s).width; });
      fonts.forEach(function (f) {
        for (var b in base) {
          x.font = '72px "' + f + '",' + b;
          if (x.measureText(s).width !== base[b]) { out.push(f); return; }
        }
      });
      return fnv(out.join(','));
    } catch (e) { return ''; }
  }
  function device() {
    var r = renderer(), tz = '';
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { /* none */ }
    return {
      renderer: r[0], renderer_class: r[1], cores: n.hardwareConcurrency || 0, memory: n.deviceMemory || 0,
      screen: screen.width + 'x' + screen.height, dpr: w.devicePixelRatio || 1, tz: tz,
      langs: (n.languages || []).slice(0, 5).join(','), touch: n.maxTouchPoints || 0,
      canvas_hash: canvasHash(), fonts_hash: fontsHash()
    };
  }

  // ── automation traces (A8) ────────────────────────────────────────────────
  function automation() {
    var cdp = false;
    try {
      // A browser-control (CDP) client with the Runtime domain on serializes
      // console arguments, which reads this getter. Measured in the lab, not assumed.
      var e = new Error();
      Object.defineProperty(e, 'stack', { configurable: false, get: function () { cdp = true; return ''; } });
      console.debug(e);
    } catch (x) { /* ignore */ }
    var mismatch = '', ua = n.userAgent, uad = n.userAgentData;
    if (uad) {
      var plat = uad.platform || '';
      var claims = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'macOS'
        : /Linux/.test(ua) ? 'Linux' : '';
      if (claims && plat && claims !== plat) mismatch = 'platform';
      var cv = (ua.match(/Chrome\/(\d+)/) || [])[1];
      var hv = (uad.brands || []).filter(function (b) { return /Chrome|Chromium/.test(b.brand); })
        .map(function (b) { return b.version; })[0];
      if (cv && hv && cv !== hv) mismatch = mismatch ? mismatch + ',version' : 'version';
    } else if (/Chrome\//.test(ua) && !/Edg|OPR|Mobile/.test(ua)) {
      mismatch = 'no_client_hints';
    }
    return {
      webdriver: !!n.webdriver, cdp: cdp,
      headless_shape: w.outerWidth === 0 || w.outerHeight === 0 || /HeadlessChrome/.test(ua),
      hints_mismatch: mismatch
    };
  }

  // ── interaction (A7) ──────────────────────────────────────────────────────
  var I = { keys: 0, inputs: 0, corrections: 0, clicks: 0, centre_clicks: 0, clicks_without_move: 0,
    pointer_moves: 0, untrusted_events: 0 };
  var fields = new Map(), keyTimes = [], offsets = [], straight = [], trail = [], firstInput = 0, dirty = 0;

  function field(t) {
    if (!t || !/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return null;
    var f = fields.get(t);
    if (!f) { f = { k: 0, i: 0 }; fields.set(t, f); }
    return f;
  }
  function touched(e) {
    dirty++;
    if (!e.isTrusted) I.untrusted_events++;
    if (!firstInput) firstInput = Math.round(performance.now());
  }
  d.addEventListener('keydown', function (e) {
    touched(e); I.keys++;
    if (e.key === 'Backspace' || e.key === 'Delete') I.corrections++;
    if (keyTimes.length < 500) keyTimes.push(e.timeStamp);
    var f = field(e.target); if (f) f.k++;
  }, true);
  d.addEventListener('input', function (e) { touched(e); I.inputs++; var f = field(e.target); if (f) f.i++; }, true);
  d.addEventListener('change', function (e) { var f = field(e.target); if (f && e.target.tagName === 'SELECT') f.k++; }, true);
  d.addEventListener('mousemove', function (e) {
    if (!e.isTrusted) I.untrusted_events++;
    I.pointer_moves++; trail.push([e.clientX, e.clientY]); if (trail.length > 60) trail.shift();
  }, true);
  d.addEventListener('click', function (e) {
    touched(e); I.clicks++;
    if (e.detail === 0) return;                      // keyboard-activated click: no pointer position
    var t = e.target && e.target.getBoundingClientRect ? e.target.getBoundingClientRect() : null;
    if (t && t.width && t.height) {
      var off = Math.hypot(e.clientX - (t.left + t.width / 2), e.clientY - (t.top + t.height / 2));
      offsets.push(off); if (off <= 2) I.centre_clicks++;
    }
    if (trail.length < 2) { I.clicks_without_move++; straight.push(1); }
    else {
      var len = 0;
      for (var i = 1; i < trail.length; i++) len += Math.hypot(trail[i][0] - trail[i - 1][0], trail[i][1] - trail[i - 1][1]);
      var a = trail[0], b = trail[trail.length - 1];
      straight.push(len ? Math.hypot(b[0] - a[0], b[1] - a[1]) / len : 1);
    }
    trail = [];
  }, true);

  function stats(xs) {
    if (!xs.length) return [0, 0];
    var mean = xs.reduce(function (s, x) { return s + x; }, 0) / xs.length;
    var sd = Math.sqrt(xs.reduce(function (s, x) { return s + (x - mean) * (x - mean); }, 0) / xs.length);
    return [mean, mean ? sd / mean : 0];
  }
  function interaction() {
    var gaps = [];
    for (var i = 1; i < keyTimes.length; i++) { var g = keyTimes[i] - keyTimes[i - 1]; if (g > 0 && g < 3000) gaps.push(g); }
    var ks = stats(gaps), without = 0;
    fields.forEach(function (f) { if (f.i > 0 && f.k === 0) without++; });
    return {
      keys: I.keys, inputs: I.inputs, inputs_without_keys: without, fields_touched: fields.size,
      corrections: I.corrections, clicks: I.clicks, centre_clicks: I.centre_clicks,
      clicks_without_move: I.clicks_without_move,
      click_centre_offset_px: Math.round(stats(offsets)[0] * 10) / 10,
      pointer_moves: I.pointer_moves,
      pointer_straightness: Math.round(stats(straight)[0] * 1000) / 1000,
      untrusted_events: I.untrusted_events,
      key_gap_mean_ms: Math.round(ks[0]), key_gap_cv: Math.round(ks[1] * 1000) / 1000,
      first_input_ms: firstInput
    };
  }

  // ── traps (section 2.4): filled in by the trap snippet, read here ─────────
  function traps() {
    var t = w.__shsTraps || { shown: [], hit: [] };
    return { shown: t.shown.slice(0, 8), hit: t.hit.slice(0, 8) };
  }

  // ── beacons ───────────────────────────────────────────────────────────────
  function send(kind, extra) {
    var body = { v: 1, site_key: KEY, shs: SHS, page: PAGE, t: Math.round(performance.now()), kind: kind };
    for (var k in extra) body[k] = extra[k];
    var data = JSON.stringify(body);
    try {
      if (n.sendBeacon && n.sendBeacon(ENDPOINT, new Blob([data], { type: 'text/plain' }))) return;
    } catch (e) { /* fall through */ }
    try { fetch(ENDPOINT, { method: 'POST', body: data, keepalive: true, credentials: 'same-origin' }); } catch (e) { /* lost */ }
  }
  var sentAt = -1;
  function flush(kind) {
    if (dirty === sentAt) return;
    sentAt = dirty;
    send(kind, { interaction: interaction(), traps: traps() });
  }
  function onLoad() { setTimeout(function () { send('load', { device: device(), automation: automation() }); }, 0); }
  if (d.readyState === 'complete') onLoad(); else w.addEventListener('load', onLoad);
  d.addEventListener('submit', function () { flush('submit'); }, true);
  w.addEventListener('pagehide', function () { flush('leave'); });
  d.addEventListener('visibilitychange', function () { if (d.visibilityState === 'hidden') flush('leave'); });
})();
