// AI agent detection page (docs/specs/agent-impersonation-defense.md, rev 8
// step R7), mounted by the tenant portal (Security Operations > AI Agent
// Detection). Four sections: Tag, Detections, Fleets, Enforcement.
//
// Beacon-derived values (renderers, pages, reasons) came from visitors'
// browsers: every value goes through esc() before it reaches innerHTML.
(function () {
  'use strict';

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, c => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function when(t) { return t ? new Date(t * 1000).toLocaleString() : ''; }
  function ago(t) {
    if (!t) return 'never';
    const s = Math.max(0, Date.now() / 1000 - t);
    return s < 90 ? `${Math.round(s)} s ago` : s < 5400 ? `${Math.round(s / 60)} min ago`
      : s < 172800 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} days ago`;
  }
  const BAND = { clear_agent: ['badge badge-danger', 'clear agent'], grey: ['badge badge-warn', 'grey'],
                 human_like: ['badge badge-basic', 'human-like'] };
  function band(b) { const x = BAND[b] || BAND.human_like; return `<span class="${x[0]}">${esc(x[1])}</span>`; }
  function short(shs) { return `<span class="badge badge-id">${esc(String(shs || '').slice(0, 10))}</span>`; }

  function mount(opts) {
    const root = opts.root, api = opts.api, apiBase = opts.apiBase || '';
    const toast = opts.toast || ((m) => alert(m));
    const st = { section: 'tag', band: 'flagged', detail: null };

    root.innerHTML = `
      <div class="card" style="display:flex;gap:1.25rem;flex-wrap:wrap;align-items:center;" data-ad="stats">Loading...</div>
      <div style="display:flex;gap:0.5rem;margin:0.75rem 0;flex-wrap:wrap;">
        <button class="small" data-ad-sec="tag">Tag</button>
        <button class="small" data-ad-sec="detections">Detections</button>
        <button class="small" data-ad-sec="fleets">Fleets</button>
        <button class="small" data-ad-sec="enforcement">Enforcement</button>
        <button class="small" data-ad-sec="decoys">Decoys</button>
      </div>
      <div data-ad="body"></div>`;
    const $ = sel => root.querySelector(`[data-ad="${sel}"]`);
    const body = () => $('body');

    async function call(path, o) {
      try { return await api(path, o); } catch (e) { toast(e.message, 'error'); throw e; }
    }

    // ── header stats ─────────────────────────────────────────────────
    async function loadStats() {
      try {
        const s = await api('/v1/agent-detection/stats?days=1');
        const d = (s.days || [])[0] || {};
        const modes = (s.enforcement || {}).modes || {};
        const TYPE = { shs: 'session cookie', client: 'browser signature' };
        const enforced = Object.keys(modes).filter(k => modes[k] === 'enforce').map(k => TYPE[k] || k);
        const mode = s.enforcement && s.enforcement.paused ? '<span class="badge badge-danger">paused (kill switch)</span>'
          : enforced.length ? `<span class="badge badge-success">enforcing ${esc(enforced.join(', '))}</span>`
          : '<span class="badge badge-basic">watch mode</span>';
        $('stats').innerHTML = [
          ['Beacons today', d.beacons || 0], ['Sessions scored', d.sessions_scored || 0],
          ['New clear agents', d.clear_agent || 0], ['New grey', d.grey || 0],
          ['Active fleets', s.fleets_active || 0], ['Active indicators', s.indicators_active || 0],
        ].map(([k, v]) => `<div><div style="font-size:11px;color:var(--text-muted);">${esc(k)}</div>
          <div style="font-size:20px;font-weight:600;">${esc(v)}</div></div>`).join('') +
          `<div style="margin-left:auto;">${mode}</div>`;
      } catch (e) { $('stats').textContent = e.message; }
    }

    // ── Tag ──────────────────────────────────────────────────────────
    async function loadTag() {
      body().innerHTML = 'Loading...';
      const t = await call('/v1/agent-detection/tag');
      const keys = t.site_keys || [];
      body().innerHTML = `
        <div class="card">
          <div style="font-weight:600;margin-bottom:0.25rem;">Tag ${esc(t.version)}</div>
          <div style="font-size:12px;color:var(--text-muted);">One script on the pages you want protected. It sends counts,
            timings and hashes only, never what people type, and never blocks or slows a page.
            ${t.configured ? '' : '<br><b>The tag and collector addresses are not configured on this deployment;</b> the snippets show placeholders.'}</div>
        </div>
        <div class="card">
          <div style="font-weight:600;margin-bottom:0.25rem;">New site key</div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:0.5rem;">One origin per line, for example https://shop.example.com.</div>
          <textarea data-ad="origins" rows="2" style="width:100%;min-height:0;height:56px;" placeholder="https://shop.example.com"></textarea>
          <div style="display:flex;gap:1rem;flex-wrap:wrap;font-size:13px;margin:0.5rem 0;">
            <label><input type="checkbox" data-ad="consent"> Run only after consent</label>
            <label><input type="checkbox" data-ad="cdn"> Our CDN forwards /_shs/ to the collector</label>
            <label><input type="checkbox" data-ad="traps" checked> Hidden traps</label>
            <label><input type="checkbox" data-ad="decoys"> Decoy key on pages</label>
            <input data-ad="label" type="text" maxlength="80" placeholder="Label (optional)" style="flex:1;min-width:140px;">
          </div>
          <button class="primary small" data-ad-act="create-key">Create site key</button>
        </div>
        ${keys.length ? keys.map(k => keyCard(k)).join('') :
          '<div class="card" style="font-size:13px;color:var(--text-muted);">No site keys yet.</div>'}`;
    }
    function keyCard(k) {
      const r = k.reporting;
      const status = r && r.last_beacon ? `<span class="badge badge-success">reporting</span>
          last beacon ${esc(ago(r.last_beacon))}; ${esc(Object.entries(r.kinds || {}).map(([a, b]) => `${b} ${a}`).join(', '))}
          ${r.traps_shown ? '; traps shown' : ''}`
        : '<span class="badge badge-warn">no beacons yet</span> install the snippet, then load a page';
      return `<div class="card">
        <div style="display:flex;justify-content:space-between;gap:0.5rem;flex-wrap:wrap;">
          <div><b>${esc(k.label || 'Site key')}</b> <span class="badge badge-id">${esc(k.site_key)}</span></div>
          <button class="small" data-ad-act="delete-key" data-key="${esc(k.site_key)}">Delete</button>
        </div>
        <div style="font-size:12px;color:var(--text-muted);margin:0.35rem 0;">
          ${esc((k.origins || []).join(', '))} · consent ${esc(k.consent)} · traps ${k.traps === false ? 'off' : 'on'}
          · ${k.xff_hops === 2 ? 'through your CDN' : 'direct'} · decoy key ${k.decoys ? 'on' : 'off'}</div>
        <div style="font-size:13px;margin-bottom:0.5rem;">${status}</div>
        <div style="font-size:12px;font-weight:600;">Snippet, first-party (route /_shs/ on your CDN to the collector)</div>
        <pre style="white-space:pre-wrap;word-break:break-all;font-size:11px;">${esc(k.snippet_first_party)}</pre>
        <div style="font-size:12px;font-weight:600;">Snippet, direct to the collector</div>
        <pre style="white-space:pre-wrap;word-break:break-all;font-size:11px;">${esc(k.snippet_direct)}</pre>
      </div>`;
    }
    async function createKey() {
      const origins = $('origins').value.split(/\s+/).map(s => s.trim()).filter(Boolean);
      await call('/v1/agent-detection/sitekeys', { method: 'POST', body: JSON.stringify({
        origins, consent: $('consent').checked ? 'required' : 'none', xff_hops: $('cdn').checked ? 2 : 1,
        traps: $('traps').checked, decoys: $('decoys').checked, label: $('label').value }) });
      toast('Site key created', 'success');
      loadTag();
    }

    // ── Detections ───────────────────────────────────────────────────
    async function loadDetections() {
      body().innerHTML = 'Loading...';
      const d = await call(`/v1/agent-detection/detections?band=${encodeURIComponent(st.band)}&limit=200`);
      const rows = d.detections || [];
      body().innerHTML = `
        <div class="card">
          <div style="display:flex;gap:0.5rem;align-items:center;margin-bottom:0.5rem;">
            <select data-ad="band">
              ${['flagged', 'clear_agent', 'grey', 'all'].map(b => `<option value="${b}" ${b === st.band ? 'selected' : ''}>${
                { flagged: 'Clear agents and grey', clear_agent: 'Clear agents', grey: 'Grey', all: 'All sessions' }[b]}</option>`).join('')}
            </select>
            <span style="font-size:12px;color:var(--text-muted);">${rows.length} shown, last 24 h</span>
          </div>
          ${rows.length ? `<div class="gov-table-wrap"><table class="gov-table"><thead><tr>
            <th>Last seen</th><th>Session</th><th>Verdict</th><th>Why</th><th>Fleet</th></tr></thead><tbody>
            ${rows.map(r => `<tr data-ad-act="open-session" data-shs="${esc(r.shs)}" style="cursor:pointer;">
              <td>${esc(when(r.last))}</td><td>${short(r.shs)}</td>
              <td>${band(r.band)} ${esc(r.score)}</td>
              <td style="font-size:12px;">${(r.reasons || []).map(x => esc(x)).join('<br>')}</td>
              <td>${r.fleet_id ? short(r.fleet_id) : ''}</td></tr>`).join('')}
            </tbody></table></div>` : '<div style="font-size:13px;color:var(--text-muted);">Nothing flagged in the last 24 hours.</div>'}
        </div>
        <div class="card" data-ad="session" style="display:none;"></div>`;
    }
    async function openSession(shs) {
      const s = await call(`/v1/agent-detection/sessions/${encodeURIComponent(shs)}`);
      const it = s.interaction || {};
      const box = $('session');
      box.style.display = '';
      box.innerHTML = `<div style="font-weight:600;">Session ${short(s.shs)} ${band(s.band)} score ${esc(s.score)}</div>
        <div style="font-size:12px;color:var(--text-muted);margin:0.25rem 0 0.5rem;">${esc(when(s.first))} to ${esc(when(s.last))}
          · ${esc(s.beacons)} beacons · ${esc(s.clients)} client(s) · ${esc(s.networks)} network(s) · detector pack ${esc(s.pack)}</div>
        <div style="font-size:13px;"><b>Reasons</b><br>${(s.reasons || []).map(x => esc(x)).join('<br>') || 'none'}</div>
        <div style="font-size:13px;margin-top:0.5rem;"><b>Pages</b> ${esc((s.pages || []).join(' → '))}</div>
        <div style="font-size:13px;margin-top:0.5rem;"><b>Graphics</b> ${esc(s.renderer)} (${esc(s.renderer_class)})</div>
        <div style="font-size:13px;margin-top:0.5rem;"><b>Interaction</b> ${esc(it.keys)} keys, ${esc(it.inputs)} inputs,
          ${esc(it.inputs_without_keys)} fields changed with no keys, ${esc(it.clicks)} clicks
          (${esc(it.centre_clicks)} on the exact centre, ${esc(it.clicks_without_move)} with no pointer path)</div>
        <div style="font-size:13px;margin-top:0.5rem;"><b>Traps</b> shown ${esc(((s.traps || {}).shown || []).join(', ') || 'none')};
          hits ${esc(((s.traps || {}).hits || []).map(h => h.trap + (h.code_match ? ' (own code)' : h.code_from ? ' (another session’s code)' : '')).join(', ') || 'none')}
          ${(s.links || []).length ? `; linked to ${s.links.map(short).join(' ')}` : ''}</div>`;
      box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // ── Fleets ───────────────────────────────────────────────────────
    async function loadFleets() {
      body().innerHTML = 'Loading...';
      const d = await call('/v1/agent-detection/fleets');
      const fleets = d.fleets || [];
      body().innerHTML = fleets.length ? fleets.map(f => `<div class="card">
          <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:0.5rem;">
            <div><b>Fleet</b> ${short(f.id)} · ${esc(f.member_count)} sessions across ${esc(f.networks)} networks</div>
            <div style="font-size:12px;color:var(--text-muted);">${esc(when(f.first_seen))} to ${esc(when(f.last_seen))}</div>
          </div>
          <div style="font-size:13px;margin-top:0.4rem;"><b>Linked by</b> ${esc(Object.entries(f.traits || {}).map(([k, v]) => `${k} (${v} pairs)`).join(', '))}</div>
          <div style="font-size:13px;margin-top:0.3rem;"><b>Verdicts</b> ${esc(Object.entries(f.bands || {}).map(([k, v]) => `${v} ${k.replace('_', ' ')}`).join(', '))}</div>
          <div style="font-size:13px;margin-top:0.3rem;"><b>Pages</b> ${esc(Object.entries(f.pages || {}).map(([k, v]) => `${k} ×${v}`).join(', '))}</div>
          <div style="font-size:13px;margin-top:0.3rem;"><b>Shared device</b> ${(f.devices || []).map(x =>
            `${short(x.hash)} ${x.rare ? '<span class="badge badge-danger">rare</span>' : '<span class="badge badge-basic">common, not used</span>'}`).join(' ') || 'none'}</div>
          <div style="font-size:13px;margin-top:0.3rem;"><b>Browser signature</b> ${(f.clients || []).map(x =>
            `${esc((x.value || x.hash).slice(0, 90))} ${x.rare ? '<span class="badge badge-danger">rare</span>' : '<span class="badge badge-basic">common, withheld</span>'}`).join('<br>') || 'none'}</div>
        </div>`).join('') : '<div class="card" style="font-size:13px;color:var(--text-muted);">No fleets in the last 24 hours.</div>';
    }

    // ── Enforcement ──────────────────────────────────────────────────
    async function loadEnforcement() {
      body().innerHTML = 'Loading...';
      const [p, tokens, log] = await Promise.all([
        call('/v1/agent-detection/indicators/preview'), call('/v1/agent-detection/feed-tokens'),
        call('/v1/agent-detection/enforcement/log?limit=30')]);
      const s = p.settings || {};
      const modeSel = (type, label) => `<label style="font-size:13px;">${esc(label)}
        <select data-ad="mode-${type}">${['monitor', 'enforce'].map(m =>
          `<option value="${m}" ${(s.modes || {})[type] === m ? 'selected' : ''}>${m === 'monitor' ? 'Watch' : 'Enforce'}</option>`).join('')}</select></label>`;
      const items = p.indicators || [];
      body().innerHTML = `
        ${s.paused ? `<div class="card" style="border-color:var(--danger,#b91c1c);">
          <b>Publishing is paused (kill switch).</b> The feed is empty. <button class="small primary" data-ad-act="resume">Resume</button></div>` : ''}
        <div class="card">
          <div style="font-weight:600;margin-bottom:0.25rem;">Mode</div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:0.5rem;">In watch mode indicators are computed and listed
            below, but the feed stays empty and no webhook fires. Your edge does the challenging; Shield never blocks anything itself.</div>
          <div style="display:flex;gap:1rem;flex-wrap:wrap;align-items:center;">
            ${modeSel('shs', 'Session cookie')} ${modeSel('client', 'Browser signature')}
            <label style="font-size:13px;">Action <select data-ad="action">${['challenge', 'block', 'log'].map(a =>
              `<option ${s.action === a ? 'selected' : ''}>${a}</option>`).join('')}</select></label>
            <label style="font-size:13px;">Lifetime (min) <input data-ad="lifetime" type="number" min="5" max="1440"
              value="${esc(Math.round((s.lifetime_s || 3600) / 60))}" style="width:80px;"></label>
            <button class="primary small" data-ad-act="save-mode">Save</button>
            <button class="small" data-ad-act="kill" style="margin-left:auto;color:var(--danger,#b91c1c);">Kill switch: clear all</button>
          </div>
        </div>
        <div class="card">
          <div style="font-weight:600;margin-bottom:0.5rem;">Indicators (${esc(items.length)}: ${esc(p.published)} published, ${esc(p.would_publish)} watch only)</div>
          ${items.length ? `<div class="gov-table-wrap"><table class="gov-table"><thead><tr>
            <th>Type</th><th>Value</th><th>Why</th><th>Mode</th><th>Expires</th><th></th></tr></thead><tbody>
            ${items.slice(0, 300).map(i => `<tr><td>${esc(i.type === 'shs' ? 'session' : 'browser')}</td>
              <td style="font-size:11px;max-width:320px;word-break:break-all;">${esc(i.value)}</td>
              <td style="font-size:12px;">${esc(i.reason)}</td>
              <td>${i.mode === 'enforce' ? '<span class="badge badge-success">published</span>' : `<span class="badge badge-basic">${esc(i.mode)}</span>`}</td>
              <td style="font-size:12px;">${esc(when(i.expires))}</td>
              <td><button class="small" data-ad-act="revoke" data-id="${esc(i.id)}">Revoke</button></td></tr>`).join('')}
            </tbody></table></div>` : '<div style="font-size:13px;color:var(--text-muted);">No indicators right now.</div>'}
        </div>
        <div class="card">
          <div style="font-weight:600;margin-bottom:0.25rem;">Feed for your edge</div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:0.5rem;">Your firewall, CDN or a cron job polls the feed
            every 60 s with a feed token. A feed token reads the feed and nothing else.</div>
          <pre style="white-space:pre-wrap;word-break:break-all;font-size:11px;">curl -s -H "X-Shield-Feed-Token: $TOKEN" "${esc(apiBase)}/v1/agent-detection/indicators?format=nginx" -o /etc/nginx/shield/agd.conf</pre>
          ${(tokens.feed_tokens || []).map(t => `<div style="font-size:13px;display:flex;gap:0.5rem;align-items:center;margin:0.25rem 0;">
            <span class="badge badge-id">${esc(t.id)}</span> ${esc(t.label)} · ends …${esc(t.hint)} · ${esc(when(t.created))}
            <button class="small" data-ad-act="delete-token" data-id="${esc(t.id)}">Delete</button></div>`).join('')}
          <div style="display:flex;gap:0.5rem;margin-top:0.5rem;">
            <input data-ad="token-label" type="text" maxlength="80" placeholder="Label, for example prod edge">
            <button class="small primary" data-ad-act="create-token">New feed token</button>
          </div>
          <div data-ad="new-token"></div>
        </div>
        <div class="card">
          <div style="font-weight:600;margin-bottom:0.5rem;">Recent enforcement events</div>
          <div style="font-size:12px;">${(log.events || []).map(e => `${esc(when(e.ts))} · ${esc(e.event)} ${esc(
            Object.entries(e).filter(([k]) => !['ts', 'event'].includes(k)).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' '))}`).join('<br>') || 'none yet'}</div>
        </div>`;
    }
    async function saveMode() {
      await call('/v1/agent-detection/enforcement', { method: 'PUT', body: JSON.stringify({
        modes: { shs: $('mode-shs').value, client: $('mode-client').value }, action: $('action').value,
        lifetime_s: Math.round(Number($('lifetime').value || 60) * 60) }) });
      toast('Enforcement saved', 'success');
      await Promise.all([loadEnforcement(), loadStats()]);
    }

    // ── Decoys (rev 9) ───────────────────────────────────────────────
    async function loadDecoys() {
      body().innerHTML = 'Loading...';
      const [dc, t, det] = await Promise.all([call('/v1/agent-detection/decoys'), call('/v1/agent-detection/tag'),
        call('/v1/agent-detection/detections?band=all&limit=500')]);
      const keys = t.site_keys || [];
      const hits = (det.detections || []).filter(x => (x.decoys || []).length);
      const lines = (arr) => esc((arr || []).join('\n'));
      body().innerHTML = `
        <div class="card">
          <div style="font-weight:600;margin-bottom:0.25rem;">Decoys ${dc.enabled ? '<span class="badge badge-success">on</span>' : '<span class="badge badge-basic">off</span>'}</div>
          <div style="font-size:12px;color:var(--text-muted);margin-bottom:0.5rem;">Things no real visitor needs: a staff login, config files, a hidden API,
            and a key in your page code. Each answers with an instruction only an AI agent follows. A bare request never flags anyone;
            following the instruction does. Check that none of the paths below exists on your site.</div>
          <div style="display:flex;gap:1rem;flex-wrap:wrap;align-items:center;font-size:13px;">
            <label><input type="checkbox" data-ad="dc-enabled" ${dc.enabled ? 'checked' : ''}> Decoys on</label>
            <label>Your key format <input data-ad="dc-prefix" type="text" maxlength="30" value="${esc(dc.key_prefix)}" style="width:120px;"></label>
            <label>Your site runs on <select data-ad="dc-stack">${(dc.stacks || []).map(x =>
              `<option ${x === dc.stack ? 'selected' : ''}>${esc(x)}</option>`).join('')}</select></label>
          </div>
          <div style="display:flex;gap:1rem;flex-wrap:wrap;margin-top:0.5rem;font-size:12px;">
            <label style="flex:1;min-width:200px;">Paths that exist on your site (one per line)
              <textarea data-ad="dc-avoid" rows="3" style="width:100%;min-height:0;height:64px;">${lines(dc.avoid)}</textarea></label>
            <label style="flex:1;min-width:200px;">Your scanners: IP ranges (one per line)
              <textarea data-ad="dc-cidrs" rows="3" style="width:100%;min-height:0;height:64px;">${lines((dc.scanners || {}).cidrs)}</textarea></label>
            <label style="flex:1;min-width:200px;">Your scanners: user agent contains (one per line)
              <textarea data-ad="dc-uas" rows="3" style="width:100%;min-height:0;height:64px;">${lines((dc.scanners || {}).uas)}</textarea></label>
          </div>
          <div style="display:flex;gap:0.5rem;margin-top:0.5rem;">
            <button class="primary small" data-ad-act="save-decoys">Save</button>
            <button class="small" data-ad-act="reroll-decoys">Draw a new set</button>
          </div>
        </div>
        <div class="card">
          <div style="font-weight:600;margin-bottom:0.25rem;">This site's decoys</div>
          <div style="font-size:13px;">${Object.entries(dc.decoys || {}).map(([k, v]) =>
            `<div><b>${esc(k)}</b> ${esc(Array.isArray(v) ? v.join(', ') : v)}</div>`).join('')}</div>
          <div style="font-size:13px;margin-top:0.5rem;">Add to robots.txt: <code>${esc(dc.robots_txt_line)}</code></div>
          <div style="font-size:13px;margin-top:0.75rem;">Edge rules for
            <select data-ad="dc-key">${keys.map(k => `<option value="${esc(k.site_key)}">${esc(k.label || k.site_key)}</option>`).join('')}</select>
            <button class="small" data-ad-act="edge-rules" ${keys.length ? '' : 'disabled'}>Show</button></div>
          <pre data-ad="dc-rules" style="white-space:pre-wrap;word-break:break-all;font-size:11px;display:none;"></pre>
        </div>
        <div class="card">
          <div style="font-weight:600;margin-bottom:0.5rem;">Recent decoy hits (${esc(hits.length)} sessions, last 24 h)</div>
          ${hits.length ? `<div class="gov-table-wrap"><table class="gov-table"><thead><tr>
            <th>Last seen</th><th>Session</th><th>Verdict</th><th>Decoys</th><th>Tag</th></tr></thead><tbody>
            ${hits.slice(0, 100).map(x => `<tr><td>${esc(when(x.last))}</td><td>${short(x.shs)}</td><td>${band(x.band)} ${esc(x.score)}</td>
              <td style="font-size:12px;">${esc(x.decoys.map(h => h.decoy + (h.followed ? ' followed' : '') + (h.key_match ? ' key used' : '')).join(', '))}</td>
              <td>${x.pseudo ? 'no tag' : 'tag'}</td></tr>`).join('')}
            </tbody></table></div>` : '<div style="font-size:13px;color:var(--text-muted);">No decoy hits yet.</div>'}
        </div>`;
    }
    async function saveDecoys() {
      const lines = sel => $(sel).value.split('\n').map(x => x.trim()).filter(Boolean);
      await call('/v1/agent-detection/decoys', { method: 'PUT', body: JSON.stringify({
        enabled: $('dc-enabled').checked, key_prefix: $('dc-prefix').value.trim(), stack: $('dc-stack').value,
        avoid: lines('dc-avoid'), scanners: { cidrs: lines('dc-cidrs'), uas: lines('dc-uas') } }) });
      toast('Decoys saved', 'success');
      await loadDecoys();
    }

    // ── events ───────────────────────────────────────────────────────
    root.addEventListener('change', e => {
      if (e.target.matches('[data-ad="band"]')) { st.band = e.target.value; loadDetections(); }
    });
    root.addEventListener('click', async e => {
      const sec = e.target.closest('[data-ad-sec]');
      if (sec) { st.section = sec.getAttribute('data-ad-sec'); return load(); }
      const el = e.target.closest('[data-ad-act]');
      if (!el) return;
      const act = el.getAttribute('data-ad-act');
      try {
        if (act === 'create-key') await createKey();
        if (act === 'delete-key' && confirm('Delete this site key? Pages using it stop reporting.')) {
          await call(`/v1/agent-detection/sitekeys/${encodeURIComponent(el.dataset.key)}`, { method: 'DELETE' });
          loadTag();
        }
        if (act === 'open-session') await openSession(el.dataset.shs);
        if (act === 'save-mode') await saveMode();
        if (act === 'revoke') {
          await call(`/v1/agent-detection/indicators/${encodeURIComponent(el.dataset.id)}/revoke`, { method: 'POST' });
          toast('Revoked; held back for 24 hours', 'success'); loadEnforcement();
        }
        if (act === 'kill' && confirm('Clear every indicator and pause publishing? Your edge stops challenging at its next poll.')) {
          await call('/v1/agent-detection/indicators/clear', { method: 'POST' });
          toast('Cleared and paused', 'success'); await Promise.all([loadEnforcement(), loadStats()]);
        }
        if (act === 'resume') {
          await call('/v1/agent-detection/indicators/resume', { method: 'POST' }); await Promise.all([loadEnforcement(), loadStats()]);
        }
        if (act === 'create-token') {
          const t = await call('/v1/agent-detection/feed-tokens', { method: 'POST',
            body: JSON.stringify({ label: $('token-label').value }) });
          await loadEnforcement();
          $('new-token').innerHTML = `<div class="toast success" style="margin-top:0.5rem;">Copy it now, it is shown once:
            <pre style="white-space:pre-wrap;word-break:break-all;">${esc(t.token)}</pre></div>`;
        }
        if (act === 'save-decoys') await saveDecoys();
        if (act === 'reroll-decoys' && confirm('Draw new decoy paths and values? Download the edge rules again afterwards.')) {
          await call('/v1/agent-detection/decoys/reroll', { method: 'POST' }); await loadDecoys();
        }
        if (act === 'edge-rules') {
          const r = await call(`/v1/agent-detection/decoys/edge?format=json&site_key=${encodeURIComponent($('dc-key').value)}`);
          const box = $('dc-rules'); box.style.display = ''; box.textContent = r.nginx || '';
        }
        if (act === 'delete-token' && confirm('Delete this feed token? An edge using it stops getting updates.')) {
          await call(`/v1/agent-detection/feed-tokens/${encodeURIComponent(el.dataset.id)}`, { method: 'DELETE' });
          loadEnforcement();
        }
      } catch (_) { /* toast already shown */ }
    });

    function load() {
      root.querySelectorAll('[data-ad-sec]').forEach(b => b.classList.toggle('primary', b.getAttribute('data-ad-sec') === st.section));
      loadStats();
      const f = { tag: loadTag, detections: loadDetections, fleets: loadFleets, enforcement: loadEnforcement,
                  decoys: loadDecoys }[st.section];
      return f().catch(() => {});
    }
    return { load };
  }

  window.AgentDetectionUI = { mount, esc };
})();
