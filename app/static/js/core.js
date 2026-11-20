/* SecureScan AI web UI - core helpers (no external dependencies, safe DOM building only) */
(function () {
  'use strict';
  const SS = (window.SS = { user: null, token: null, view: {}, cleanup: null });
  const NS = 'http://www.w3.org/2000/svg';

  /* ---------- DOM builder: h('div.card#id', {attrs}, ...children) ---------- */
  function addKids(el, kids) {
    for (const k of kids) {
      if (k === null || k === undefined || k === false || k === true) continue;
      if (Array.isArray(k)) addKids(el, k);
      else if (k instanceof Node) el.appendChild(k);
      else el.appendChild(document.createTextNode(String(k)));
    }
  }
  SS.h = function (sel, attrs, ...kids) {
    if (attrs !== null && attrs !== undefined && (typeof attrs !== 'object' || attrs instanceof Node || Array.isArray(attrs))) {
      kids.unshift(attrs); attrs = null;
    }
    const tag = (/^[a-z][a-z0-9]*/i.exec(sel) || ['div'])[0];
    const el = document.createElement(tag);
    for (const m of sel.matchAll(/\.([\w-]+)/g)) el.classList.add(m[1]);
    const id = /#([\w-]+)/.exec(sel); if (id) el.id = id[1];
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') String(v).split(' ').filter(Boolean).forEach((c) => el.classList.add(c));
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (['value', 'checked', 'disabled', 'selected', 'hidden', 'open'].includes(k)) el[k] = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    addKids(el, kids);
    return el;
  };
  SS.s = function (tag, attrs, ...kids) {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined) el.setAttribute(k, v);
    addKids(el, kids);
    return el;
  };
  const h = SS.h;
  SS.clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
  SS.add = function (el, ...kids) { addKids(el, kids); return el; };  // safe append: flattens arrays, skips null/false

  /* ---------- Icons (24x24 stroke set) ---------- */
  const ICONS = {
    dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
    scan: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12l6-6"/>',
    history: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    report: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.5 3-6 6.5-6s6.5 2.5 6.5 6"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18 14.5c2 .7 3.5 2.6 3.5 5.5"/>',
    settings: '<path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7M12 17h.01"/>',
    shield: '<path d="M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5L16 9.5"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.7 3.8 5.7 3.8 9S14.5 18.3 12 21c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z"/>',
    code: '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14"/>',
    upload: '<path d="M12 16V4M7 9l5-5 5 5M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>',
    download: '<path d="M12 4v12M7 11l5 5 5-5M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>',
    check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>', x: '<path d="M6 6l12 12M18 6L6 18"/>',
    alert: '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/>', chevron: '<path d="M9 6l6 6-6 6"/>',
    trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
    logout: '<path d="M9 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3M15 8l4 4-4 4M19 12H9"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5"/>',
    moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"/>',
    search: '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>', plus: '<path d="M12 5v14M5 12h14"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>',
    refresh: '<path d="M20 11a8 8 0 0 0-14.5-3.5L3 10M3 4v6h6M4 13a8 8 0 0 0 14.5 3.5L21 14M21 20v-6h-6"/>',
    lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    external: '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
    bolt: '<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>', info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>', back: '<path d="M15 6l-6 6 6 6"/>',
  };
  SS.icon = function (name, size) {
    const svg = SS.s('svg', { viewBox: '0 0 24 24', width: size || 18, height: size || 18, fill: 'none', stroke: 'currentColor',
      'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', class: 'i', 'aria-hidden': 'true' });
    svg.innerHTML = ICONS[name] || '';
    return svg;
  };

  /* ---------- Formatting & vocabulary ---------- */
  SS.SEV = {
    critical: { label: 'Critical', color: 'var(--critical)' }, high: { label: 'High', color: 'var(--high)' },
    medium: { label: 'Medium', color: 'var(--medium)' }, low: { label: 'Low', color: 'var(--low)' },
    info: { label: 'Info', color: 'var(--info)' },
  };
  SS.SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  SS.TYPE_LABEL = { vulnerability: 'Verified vulnerability', misconfiguration: 'Misconfiguration', missing_control: 'Missing control',
    potential: 'Needs review', observation: 'Observation' };
  SS.TYPE_HELP = { vulnerability: 'Confirmed by an engine, for example a known CVE matched to an exact package version.',
    misconfiguration: 'A weakness that was directly observed in the configuration.',
    missing_control: 'A recommended protection is absent. This is a hardening gap, not proof of an exploit.',
    potential: 'A heuristic match. A person must review it to confirm whether it is a real problem.',
    observation: 'Informational only.' };
  SS.RISK = { critical: 'Critical risk', high: 'High risk', medium: 'Medium risk', low: 'Low risk', minimal: 'Minimal risk' };
  SS.sev = (s) => h('span.sev.' + s, SS.SEV[s] ? SS.SEV[s].label : s);
  SS.statusBadge = function (st) {
    const cls = { completed: 'ok', failed: 'bad', running: 'run', queued: 'run', cancelled: 'warn' }[st] || '';
    return h('span.badge.' + cls, st === 'running' ? h('span.spinner', { style: { width: '10px', height: '10px', borderWidth: '2px' } }) : null,
      st.charAt(0).toUpperCase() + st.slice(1));
  };
  SS.scoreColor = (n) => (n >= 80 ? 'var(--ok)' : n >= 50 ? 'var(--medium)' : 'var(--critical)');
  SS.fmtDate = function (iso) {
    if (!iso) return '-';
    const d = new Date(iso); if (isNaN(d)) return '-';
    return d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  };
  SS.ago = function (iso) {
    if (!iso) return '-';
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 45) return 'just now'; if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago'; if (s < 604800) return Math.round(s / 86400) + ' d ago';
    return SS.fmtDate(iso);
  };
  SS.duration = function (a, b) {
    if (!a) return '-';
    const s = Math.max(0, Math.round(((b ? new Date(b) : new Date()) - new Date(a)) / 1000));
    return s < 60 ? s + ' s' : Math.floor(s / 60) + ' min ' + (s % 60) + ' s';
  };
  SS.bytes = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB');
  SS.hostOf = function (target) { try { return new URL(target).host || target; } catch (e) { return target; } };

  /* ---------- Session, API ---------- */
  SS.loadSession = function () {
    const raw = sessionStorage.getItem('ss-session') || localStorage.getItem('ss-session');
    if (!raw) return false;
    try { const s = JSON.parse(raw); SS.token = s.token; SS.user = s.user; return !!SS.token; } catch (e) { return false; }
  };
  SS.saveSession = function (token, user, remember) {
    SS.token = token; SS.user = user;
    const store = remember ? localStorage : sessionStorage;
    sessionStorage.removeItem('ss-session'); localStorage.removeItem('ss-session');
    store.setItem('ss-session', JSON.stringify({ token, user }));
  };
  SS.clearSession = function () { SS.token = null; SS.user = null; sessionStorage.removeItem('ss-session'); localStorage.removeItem('ss-session'); };
  SS.isAdmin = () => SS.user && ['admin', 'super_admin'].includes(SS.user.role);
  SS.canScan = () => SS.user && SS.user.role !== 'read_only';

  function fail(message, status) { return Object.assign(new Error(message), { status }); }
  SS.api = async function (path, opts) {
    const { method = 'GET', body, form, raw = false } = opts || {};
    const headers = {};
    if (SS.token) headers.Authorization = 'Bearer ' + SS.token;
    let payload;
    if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); } else if (form) payload = form;
    let res;
    try { res = await fetch('/api' + path, { method, headers, body: payload, cache: 'no-store' }); } catch (e) {
      throw fail('Cannot reach the server. Check that it is running and that you are on the same network.', 0);
    }
    if (res.status === 401 && SS.token) {
      SS.clearSession(); SS.go('#/login');
      throw fail('Your session has expired. Please sign in again.', 401);
    }
    if (raw && res.ok) return res;
    const data = await res.json().catch(() => null);
    if (!res.ok) throw fail((data && data.detail) || 'Request failed (' + res.status + ').', res.status);
    return data;
  };
  SS.upload = function (path, form, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api' + path);
      xhr.setRequestHeader('Authorization', 'Bearer ' + SS.token);
      xhr.upload.onprogress = (e) => { if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total); };
      xhr.onerror = () => reject(fail('Upload failed. Check your connection.', 0));
      xhr.onload = () => {
        let data = null; try { data = JSON.parse(xhr.responseText); } catch (e) { /* ignore */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(fail((data && data.detail) || 'Upload failed (' + xhr.status + ').', xhr.status));
      };
      xhr.send(form);
    });
  };
  SS.download = async function (path, filename) {
    const res = await SS.api(path, { raw: true });
    const url = URL.createObjectURL(await res.blob());
    const a = h('a', { href: url, download: filename });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  };

  /* ---------- Toasts, modals, confirm ---------- */
  SS.toast = function (msg, kind) {
    const box = document.getElementById('toasts');
    const t = h('div.toast' + (kind ? '.' + kind : ''), { role: kind === 'bad' ? 'alert' : null }, msg);
    box.appendChild(t); setTimeout(() => t.remove(), kind === 'bad' ? 7000 : 3800);
  };
  SS.modal = function ({ title, body, actions = [], wide = false, onClose }) {
    const prev = document.activeElement;
    const close = () => { overlay.remove(); document.removeEventListener('keydown', onKey); if (prev && prev.focus) prev.focus(); if (onClose) onClose(); };
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    const foot = actions.length ? h('div.modal-foot', actions.map((a) => h('button.btn' + (a.kind ? '.' + a.kind : ''), {
      type: 'button', onclick: async (e) => { const b = e.currentTarget; b.disabled = true; try { const keep = await a.onClick(close); if (keep === false) b.disabled = false; } catch (err) { b.disabled = false; SS.toast(err.message, 'bad'); } },
    }, a.label))) : null;
    const overlay = h('div.overlay', { onclick: (e) => { if (e.target === overlay) close(); } },
      h('div.modal' + (wide ? '.wide' : ''), { role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
        h('div.modal-head', h('h3', title), h('button.btn.ghost.iconbtn', { type: 'button', 'aria-label': 'Close', onclick: close }, SS.icon('x'))),
        h('div.modal-body', body), foot));
    document.body.appendChild(overlay); document.addEventListener('keydown', onKey);
    const first = overlay.querySelector('input,select,button.primary'); if (first) first.focus();
    return { close };
  };
  SS.confirm = (title, message, label, danger) => new Promise((resolve) => {
    let settled = false;
    const settle = (v) => { if (!settled) { settled = true; resolve(v); } };
    SS.modal({ title, body: h('p', { style: { margin: 0 } }, message), onClose: () => settle(false), actions: [
      { label: 'Cancel', onClick: (close) => close() },
      { label: label || 'Confirm', kind: danger ? 'danger' : 'primary', onClick: (close) => { settle(true); close(); } }] });
  });

  /* ---------- Misc UI helpers ---------- */
  SS.empty = (icon, title, text, action) => h('div.empty', SS.icon(icon, 36), h('h3', title), h('p', text), action || null);
  SS.loading = () => h('div.page-loading', h('span.spinner', { style: { width: '28px', height: '28px' } }));
  SS.field = (label, input, hint) => h('label.field', label, input, hint ? h('span.hint', hint) : null);
  SS.copyText = async function (text) {
    try { await navigator.clipboard.writeText(text); SS.toast('Copied to clipboard', 'ok'); } catch (e) { SS.toast('Copy failed. Select the text and copy it manually.', 'bad'); }
  };
  SS.theme = {
    init() { const t = localStorage.getItem('ss-theme') || (matchMedia && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'); this.set(t); },
    set(t) { document.documentElement.dataset.theme = t; localStorage.setItem('ss-theme', t); const m = document.querySelector('meta[name=theme-color]'); if (m) m.content = t === 'light' ? '#f3f6fc' : '#0a1020'; },
    toggle() { this.set(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light'); },
  };
})();
