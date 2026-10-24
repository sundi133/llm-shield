// Webhook inbox page (docs/specs/webhook-inbox.md, task 3), shared by the
// tenant portal (Settings > Inbound webhooks) and the admin console
// (Inbound webhooks). Each page passes its own API caller and base path.
//
// Everything a delivery holds came from outside Shield: every value goes
// through esc() before it reaches innerHTML.
(function () {
  'use strict';

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, c => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function when(t) { return t ? new Date(t * 1000).toLocaleString() : ''; }
  function size(n) {
    n = Number(n) || 0;
    return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
  }
  const MASKED = /…\(\d+\)$/;
  const SIG_COLOR = { verified: 'var(--success, #15803d)', failed: 'var(--danger, #b91c1c)',
                      absent: 'var(--warning, #b45309)', not_configured: 'var(--text-muted)' };
  const SIG_TEXT = { verified: 'verified', failed: 'failed', absent: 'no signature',
                     not_configured: 'not checked' };

  function mount(opts) {
    const root = opts.root;
    const api = opts.api;
    const operator = opts.mode === 'operator';
    const st = { owner: 'platform', inboxes: [], open: null, cursor: null };

    root.innerHTML = `
      <div class="card">
        <div style="font-weight:600;margin-bottom:0.25rem;">New inbox</div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:0.75rem;">
          You get a receiving URL and a signing secret, shown once. Paste them into the partner's
          webhook form (for example Lifecycle Webhooks: Webhook URL and Webhook Signing Secret).
          Every delivery is then recorded here as it arrived, with credentials masked.</div>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
          <input data-ib="name" type="text" maxlength="100" placeholder="Name, for example Rafay lifecycle" style="flex:2;min-width:180px;">
          <input data-ib="source" type="text" maxlength="100" placeholder="Partner (optional)" style="flex:1;min-width:120px;">
          <button class="primary small" data-ib-act="create">Create inbox</button>
        </div>
        <div data-ib="created" style="display:none;margin-top:0.75rem;"></div>
        <div data-ib="msg"></div>
      </div>
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.5rem;">
          <div style="font-weight:600;">Inboxes</div>
          <div style="display:flex;gap:0.5rem;align-items:center;">
            ${operator ? `<select data-ib="owner-kind"><option value="platform">Platform</option>
              <option value="all">All owners</option><option value="tenant">A tenant</option></select>
              <input data-ib="owner-tenant" type="text" placeholder="Tenant ID" style="display:none;width:140px;">` : ''}
            <button class="small" data-ib-act="refresh">Refresh</button>
          </div>
        </div>
        <div data-ib="list" style="font-size:13px;">Loading...</div>
      </div>
      <div class="card" data-ib="detail" style="display:none;"></div>
      <div class="card" data-ib="delivery" style="display:none;"></div>`;
    const $ = sel => root.querySelector(`[data-ib="${sel}"]`);

    function msg(text, ok) {
      const el = $('msg');
      el.className = ok ? 'toast success' : 'toast error';
      el.textContent = text;
      el.classList.remove('hidden');
      el.style.display = '';
      if (ok) setTimeout(() => { el.style.display = 'none'; }, 3000);
    }
    function base() { return opts.base; }
    function dbase(i) { return `${opts.base}/${encodeURIComponent(i.inbox_id)}/deliveries`; }
    function readOnly(inbox) { return operator && inbox.owner !== 'platform'; }

    function showOnce(title, rows) {
      const el = $('created');
      el.style.display = '';
      el.innerHTML = `<div style="border:1px solid var(--border);border-radius:6px;padding:0.75rem;">
        <div style="font-weight:600;margin-bottom:0.5rem;">${esc(title)}</div>
        ${rows.map(([label, value]) => `<div style="margin-bottom:0.5rem;">
          <div style="font-size:11px;color:var(--text-muted);">${esc(label)}</div>
          <div style="display:flex;gap:0.5rem;align-items:center;">
            <code data-ib-copyval style="flex:1;word-break:break-all;font-size:12px;">${esc(value)}</code>
            <button class="small" data-ib-act="copy">Copy</button></div></div>`).join('')}
        <div style="font-size:12px;color:var(--text-muted);">Shown once. Store them now; rotating
          gives new ones and the old ones stop working.</div>
        <button class="small" data-ib-act="dismiss" style="margin-top:0.5rem;">Done</button></div>`;
    }

    async function load() {
      const q = operator ? `?owner=${encodeURIComponent(st.owner)}` : '';
      try {
        const d = await api(`${base()}${q}`);
        st.inboxes = d.inboxes || [];
        st.limit = d.limit;
        renderList();
      } catch (e) { $('list').textContent = e.message; }
    }

    function renderList() {
      const limit = st.limit;
      const el = $('list');
      if (!st.inboxes.length) { el.textContent = 'No inboxes yet.'; return; }
      el.innerHTML = `<table style="width:100%;border-collapse:collapse;"><thead><tr style="text-align:left;color:var(--text-muted);">
        <th>Inbox</th>${operator ? '<th>Owner</th>' : ''}<th>Last delivery</th><th>24 hours</th><th>Kept</th><th>Signature</th><th>Status</th></tr></thead><tbody>${
        st.inboxes.map(i => `<tr data-ib-row="${esc(i.inbox_id)}" style="cursor:pointer;border-top:1px solid var(--border);">
          <td><b>${esc(i.name)}</b>${i.source ? `<br><span style="color:var(--text-muted);font-size:11px;">${esc(i.source)}</span>` : ''}</td>
          ${operator ? `<td>${esc(i.owner)}</td>` : ''}
          <td>${esc(when(i.last_delivery_at)) || '<span style="color:var(--text-muted);">none yet</span>'}</td>
          <td>${Number(i.deliveries_24h) || 0}</td>
          <td>${Number(i.deliveries_kept) || 0}${i.old_url_deliveries ? `<br><span style="color:var(--warning, #b45309);font-size:11px;">${Number(i.old_url_deliveries)} to an old URL</span>` : ''}</td>
          <td>${esc(i.signing && i.signing.scheme)}${i.require_signature ? ' (required)' : ''}</td>
          <td>${i.enabled ? 'on' : 'off'}</td></tr>`).join('')}</tbody></table>
        ${limit ? `<div style="font-size:11px;color:var(--text-muted);margin-top:0.5rem;">${st.inboxes.length} of at most ${Number(limit)}</div>` : ''}`;
    }

    async function openInbox(id) {
      const inbox = st.inboxes.find(i => i.inbox_id === id);
      if (!inbox) return;
      st.open = inbox;
      st.cursor = null;
      $('delivery').style.display = 'none';
      renderDetail(inbox);
      await loadDeliveries(false);
    }

    function renderDetail(i) {
      const ro = readOnly(i);
      const s = i.signing || {};
      const dis = ro ? 'disabled' : '';
      const el = $('detail');
      el.style.display = '';
      el.innerHTML = `
        <div style="display:flex;justify-content:space-between;gap:0.5rem;flex-wrap:wrap;">
          <div><div style="font-weight:600;">${esc(i.name)}</div>
            <div style="font-size:11px;color:var(--text-muted);">${esc(i.inbox_id)} &middot; ${esc(i.owner)} &middot; created ${esc(when(i.created_at))}${i.created_by ? ` by ${esc(i.created_by)}` : ''}</div></div>
          ${ro ? '<div style="font-size:12px;color:var(--text-muted);">A tenant\'s inbox: read only here, changed in that tenant\'s portal.</div>'
               : `<div style="display:flex;gap:0.4rem;flex-wrap:wrap;">
            <button class="small" data-ib-act="rotate-url">New URL</button>
            <button class="small" data-ib-act="rotate-secret">New secret</button>
            <button class="small danger" data-ib-act="delete">Delete</button></div>`}
        </div>
        <div class="grid-2" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:0.5rem;margin-top:0.75rem;font-size:12px;">
          <label>Receiving<br><select data-ib="f-enabled" ${dis}><option value="true">On</option><option value="false">Off: answers 410</option></select></label>
          <label>Signature check<br><select data-ib="f-scheme" ${dis}>${['none', 'hmac-sha256', 'hmac-sha1'].map(x =>
            `<option value="${x}" ${s.scheme === x ? 'selected' : ''}>${x === 'none' ? 'None: record only' : x}</option>`).join('')}</select></label>
          <label>Signature header<br><input data-ib="f-header" type="text" value="${esc(s.header)}" placeholder="x-signature" ${dis}></label>
          <label>Prefix<br><input data-ib="f-prefix" type="text" value="${esc(s.prefix)}" placeholder="sha256=" ${dis}></label>
          <label>Encoding<br><select data-ib="f-encoding" ${dis}>${['hex', 'base64'].map(x =>
            `<option value="${x}" ${s.encoding === x ? 'selected' : ''}>${x}</option>`).join('')}</select></label>
          <label>Unsigned deliveries<br><select data-ib="f-require" ${dis}><option value="false">Record</option><option value="true">Refuse (401), still recorded</option></select></label>
          <label>Keep for (days, 1 to 90)<br><input data-ib="f-retention" type="text" inputmode="numeric" value="${Number(i.retention_days) || 30}" ${dis}></label>
        </div>
        ${ro ? '' : '<div style="margin-top:0.5rem;"><button class="primary small" data-ib-act="save">Save</button></div>'}
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:1rem;">
          <div style="font-weight:600;">Deliveries</div>
          <button class="small" data-ib-act="deliveries">Refresh</button></div>
        <div data-ib="dlist" style="font-size:12px;margin-top:0.5rem;">Loading...</div>`;
      $('f-enabled').value = String(!!i.enabled);
      $('f-require').value = String(!!i.require_signature);
    }

    async function loadDeliveries(more) {
      const i = st.open;
      const q = `?limit=50${more && st.cursor ? `&cursor=${encodeURIComponent(st.cursor)}` : ''}`;
      try {
        const d = await api(`${dbase(i)}${q}`);
        st.cursor = d.next_cursor;
        const el = $('dlist');
        const rows = (d.deliveries || []).map(x => `<tr data-ib-dlv="${esc(x.id)}" style="cursor:pointer;border-top:1px solid var(--border);">
          <td>${esc(when(x.received_at))}</td><td>${esc(x.method)}</td>
          <td>${esc(x.event) || '<span style="color:var(--text-muted);">none</span>'}</td>
          <td>${esc(size(x.size))}</td>
          <td style="color:${SIG_COLOR[x.signature] || 'inherit'};">${esc(SIG_TEXT[x.signature] || x.signature)}${x.rejected ? ' (refused)' : ''}</td>
          <td>${esc(x.source_ip)}</td></tr>`).join('');
        if (!more) {
          if (!rows) { el.textContent = 'Nothing received yet. Send a test from the partner, or with curl.'; return; }
          el.innerHTML = `<table style="width:100%;border-collapse:collapse;"><thead><tr style="text-align:left;color:var(--text-muted);">
            <th>Received</th><th>Method</th><th>Event</th><th>Size</th><th>Signature</th><th>From</th></tr></thead><tbody>${rows}</tbody></table>
            <div data-ib="dmore"></div>`;
        } else {
          el.querySelector('tbody').insertAdjacentHTML('beforeend', rows);
        }
        $('dmore').innerHTML = st.cursor ? `<button class="small" data-ib-act="more" style="margin-top:0.5rem;">Older (${Number(d.total)} kept)</button>` : '';
      } catch (e) { $('dlist').textContent = e.message; }
    }

    async function openDelivery(id) {
      let d;
      try { d = await api(`${dbase(st.open)}/${encodeURIComponent(id)}`); }
      catch (e) { msg(e.message); return; }
      let body = d.body || '';
      let pretty = false;
      if (!d.binary && !d.body_truncated && body.trim()) {
        try { body = JSON.stringify(JSON.parse(body), null, 2); pretty = true; } catch (e) { /* as received */ }
      }
      const sig = d.signature || {};
      const hint = /^would verify as (hmac-sha\d+), header (\S+), prefix '([^']*)', (hex|base64)$/.exec(sig.detail || '');
      const qs = Object.entries(d.query || {}).map(([k, v]) => `${k}=${v}`).join('&');
      const el = $('delivery');
      el.style.display = '';
      el.innerHTML = `
        <div style="display:flex;justify-content:space-between;gap:0.5rem;">
          <div style="font-weight:600;">Delivery ${esc(d.id)}</div>
          <button class="small" data-ib-act="close-delivery">Close</button></div>
        <pre class="mono" style="white-space:pre-wrap;word-break:break-all;margin:0.5rem 0;">${esc(d.method)} ${esc(d.path)}${qs ? '?' + esc(qs) : ''}</pre>
        <div style="font-size:12px;color:var(--text-muted);">Received ${esc(when(d.received_at))} from ${esc(d.source_ip)}
          &middot; ${esc(size(d.size))} &middot; sha256 <code>${esc(d.body_sha256)}</code>
          ${d.body_decompressed ? ' &middot; decompressed for display' : ''}</div>
        <div style="margin:0.75rem 0;padding:0.5rem 0.75rem;border-left:3px solid ${SIG_COLOR[sig.result] || 'var(--border)'};">
          <b>Signature: ${esc(SIG_TEXT[sig.result] || sig.result)}</b>${d.rejected ? ' (refused with 401, recorded anyway)' : ''}
          <div style="font-size:12px;">${esc(sig.detail)}</div>
          ${hint && !readOnly(st.open) ? `<button class="small" data-ib-act="apply-hint" data-scheme="${esc(hint[1])}" data-header="${esc(hint[2])}"
            data-prefix="${esc(hint[3])}" data-encoding="${esc(hint[4])}" style="margin-top:0.4rem;">Use these signature settings</button>` : ''}
        </div>
        <div style="font-weight:600;margin-top:0.5rem;">Headers, in the order received</div>
        <table style="width:100%;border-collapse:collapse;font-size:12px;"><tbody>${(d.headers || []).map(([n, v]) =>
          `<tr style="border-top:1px solid var(--border);"><td style="padding:2px 6px;white-space:nowrap;vertical-align:top;"><code>${esc(n)}</code></td>
           <td style="padding:2px 6px;word-break:break-all;"><code>${esc(v)}</code>${MASKED.test(v) ? ' <span style="font-size:10px;color:var(--warning, #b45309);">masked</span>' : ''}</td></tr>`).join('')}</tbody></table>
        <div style="font-weight:600;margin-top:0.75rem;">Body${pretty ? ' (JSON, formatted)' : d.binary ? ' (binary, base64)' : ''}${d.body_truncated ? ' (first 64 KB)' : ''}</div>
        ${(d.body_masked_fields || []).length ? `<div style="font-size:12px;color:var(--warning, #b45309);">Masked: ${d.body_masked_fields.map(esc).join(', ')}</div>` : ''}
        ${d.body_json_error ? `<div style="font-size:12px;color:var(--danger, #b91c1c);">Not valid JSON: ${esc(d.body_json_error)}</div>` : ''}
        <pre class="mono" style="white-space:pre-wrap;word-break:break-all;max-height:420px;overflow:auto;">${esc(body) || '<span style="color:var(--text-muted);">(empty)</span>'}</pre>`;
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    async function save(changes) {
      const i = st.open;
      const d = await api(`${base()}/${encodeURIComponent(i.inbox_id)}`, { method: 'PUT', body: JSON.stringify(changes) });
      Object.assign(i, d.inbox);
      // An open delivery shows how it was checked when it arrived; after a
      // change its "use these settings" offer is stale.
      $('delivery').style.display = 'none';
      renderDetail(i);
      await loadDeliveries(false);
      renderList();
    }

    root.addEventListener('change', e => {
      if (e.target.matches('[data-ib="owner-kind"]')) {
        const t = $('owner-tenant');
        t.style.display = e.target.value === 'tenant' ? '' : 'none';
        if (e.target.value !== 'tenant') { st.owner = e.target.value; reset(); load(); }
      }
    });
    root.addEventListener('keydown', e => {
      if (e.key === 'Enter' && e.target.matches('[data-ib="owner-tenant"]') && e.target.value.trim()) {
        st.owner = e.target.value.trim(); reset(); load();
      }
    });
    function reset() { st.open = null; $('detail').style.display = 'none'; $('delivery').style.display = 'none'; }

    root.addEventListener('click', async e => {
      const row = e.target.closest('[data-ib-row]');
      if (row) return openInbox(row.getAttribute('data-ib-row'));
      const dlv = e.target.closest('[data-ib-dlv]');
      if (dlv) return openDelivery(dlv.getAttribute('data-ib-dlv'));
      const btn = e.target.closest('[data-ib-act]');
      if (!btn) return;
      const act = btn.getAttribute('data-ib-act');
      const i = st.open;
      try {
        if (act === 'create') {
          const name = $('name').value.trim();
          if (!name) return msg('Give the inbox a name');
          const d = await api(base(), { method: 'POST', body: JSON.stringify({ name, source: $('source').value.trim() }) });
          $('name').value = ''; $('source').value = '';
          showOnce(`Inbox "${d.inbox.name}" created`, [['Webhook URL', d.url], ['Webhook signing secret', d.signing_secret]]);
          if (operator && st.owner !== 'platform' && st.owner !== 'all') { st.owner = 'platform'; $('owner-kind').value = 'platform'; }
          await load();
        } else if (act === 'copy') {
          const v = btn.parentElement.querySelector('[data-ib-copyval]').textContent;
          try { await navigator.clipboard.writeText(v); msg('Copied', true); }
          catch (err) { msg('Could not copy: select the text and copy it'); }
        } else if (act === 'dismiss') {
          $('created').style.display = 'none'; $('created').innerHTML = '';
        } else if (act === 'refresh') {
          await load();
        } else if (act === 'deliveries') {
          await Promise.all([loadDeliveries(false), load()]);
        } else if (act === 'more') {
          await loadDeliveries(true);
        } else if (act === 'close-delivery') {
          $('delivery').style.display = 'none';
        } else if (act === 'save') {
          const days = $('f-retention').value.trim();
          if (!/^\d+$/.test(days)) return msg('Keep for: a number of days, 1 to 90');
          await save({
            enabled: $('f-enabled').value === 'true',
            require_signature: $('f-require').value === 'true',
            retention_days: parseInt(days, 10),
            signing: { scheme: $('f-scheme').value, header: $('f-header').value.trim(),
                       prefix: $('f-prefix').value, encoding: $('f-encoding').value },
          });
          msg('Saved', true);
        } else if (act === 'apply-hint') {
          await save({ signing: { scheme: btn.dataset.scheme, header: btn.dataset.header,
                                  prefix: btn.dataset.prefix, encoding: btn.dataset.encoding } });
          msg('Signature settings saved. New deliveries are checked with them.', true);
        } else if (act === 'rotate-url') {
          if (!confirm('Make a new URL? The current one stops working at once, so update the partner\'s form.')) return;
          const d = await api(`${base()}/${encodeURIComponent(i.inbox_id)}/rotate-url`, { method: 'POST' });
          showOnce(`New URL for "${i.name}"`, [['Webhook URL', d.url]]);
          $('created').scrollIntoView({ behavior: 'smooth' });
        } else if (act === 'rotate-secret') {
          if (!confirm('Make a new signing secret? Deliveries signed with the old one will fail the check.')) return;
          const d = await api(`${base()}/${encodeURIComponent(i.inbox_id)}/rotate-secret`, { method: 'POST' });
          showOnce(`New signing secret for "${i.name}"`, [['Webhook signing secret', d.signing_secret]]);
          $('created').scrollIntoView({ behavior: 'smooth' });
        } else if (act === 'delete') {
          if (!confirm(`Delete "${i.name}" and every delivery it recorded? Its URL stops working.`)) return;
          await api(`${base()}/${encodeURIComponent(i.inbox_id)}`, { method: 'DELETE' });
          reset();
          msg('Deleted', true);
          await load();
        }
      } catch (err) { msg(err.message); }
    });

    return { load };
  }

  window.InboxUI = { mount, esc };
})();
