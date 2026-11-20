/* Router, application shell and start-up */
(function () {
  'use strict';
  const { h } = SS;
  let shell = null;

  SS.go = function (hash) { if (location.hash === hash) route(); else location.hash = hash; };
  SS.logout = async function () {
    try { await SS.api('/auth/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
    SS.clearSession(); shell = null; SS.go('#/login');
  };

  const ROUTES = [
    [/^#\/dashboard$/, 'dashboard', 'Dashboard', 'dashboard'],
    [/^#\/scan\/new$/, 'newScan', 'New scan', 'scan'],
    [/^#\/scans\/([a-f0-9]{8,64})$/, 'scanDetail', 'Scan results', 'history'],
    [/^#\/history$/, 'history', 'Scan history', 'history'],
    [/^#\/reports$/, 'reports', 'Reports', 'reports'],
    [/^#\/users$/, 'users', 'User management', 'users'],
    [/^#\/settings(?:\/(\w+))?$/, 'settings', 'Settings', 'settings'],
    [/^#\/help$/, 'help', 'Help', 'help'],
  ];

  function buildShell(root) {
    const links = {};
    const link = (key, href, label, icon, cls) => { const a = h('a' + (cls ? '.' + cls : ''), { href }, SS.icon(icon, 19), label); links[key] = a; return a; };
    const nav = h('nav.nav', { 'aria-label': 'Main' }, link('dashboard', '#/dashboard', 'Dashboard', 'dashboard'), SS.canScan() ? link('scan', '#/scan/new', 'New scan', 'scan') : null,
      link('history', '#/history', 'Scan history', 'history'), link('reports', '#/reports', 'Reports', 'report'),
      h('div.sep'), SS.isAdmin() ? link('users', '#/users', 'Users', 'users') : null, link('settings', '#/settings', 'Settings', 'settings'), link('help', '#/help', 'Help', 'help'));
    const u = SS.user;
    const sidebar = h('aside.sidebar', h('div.brand', h('img', { src: '/assets/logo.svg', alt: '' }), h('div', 'SecureScan AI', h('small', 'Vulnerability assessment'))), nav,
      h('div.side-foot', h('div.userchip', h('div.avatar', (u.full_name || u.username).slice(0, 2).toUpperCase()), h('div.grow', h('b.ellipsis', { style: { display: 'block' } }, u.full_name || u.username), h('span.small.faint', u.role_label)),
        h('button.btn.ghost.iconbtn', { type: 'button', title: 'Sign out', 'aria-label': 'Sign out', onclick: SS.logout }, SS.icon('logout', 18)))));
    const title = h('h1');
    const dot = h('span.dot'), connText = h('span.t', 'Checking...');
    const conn = h('button.conn', { type: 'button', title: 'Test the server connection', onclick: ping, style: { cursor: 'pointer' } }, dot, connText);
    const themeBtn = h('button.btn.ghost.iconbtn', { type: 'button', 'aria-label': 'Toggle light and dark theme', onclick: () => { SS.theme.toggle(); } }, SS.icon('sun', 19));
    const topbar = h('header.topbar', title, h('div.row', conn, themeBtn));
    const content = h('main.content', { id: 'content', tabindex: -1 });
    const bnav = h('nav.bottom-nav', { 'aria-label': 'Primary' },
      ...[['dashboard', '#/dashboard', 'Home', 'dashboard']].map((x) => link('m-' + x[0], x[1], x[2], x[3])), link('m-history', '#/history', 'History', 'history'),
      SS.canScan() ? h('a.cta', { href: '#/scan/new', 'aria-label': 'New scan' }, h('span.pill', SS.icon('plus', 24)), 'Scan') : null,
      link('m-reports', '#/reports', 'Reports', 'report'), link('m-settings', '#/settings', 'Settings', 'settings'));
    SS.clear(root).appendChild(h('div.shell', sidebar, h('div.main', topbar, content), bnav));
    async function ping() {
      try { await fetch('/api/health', { cache: 'no-store' }).then((r) => { if (!r.ok) throw new Error(); }); dot.className = 'dot ok'; connText.textContent = 'Connected'; }
      catch (e) { dot.className = 'dot bad'; connText.textContent = 'Offline - tap to retry'; }
    }
    ping();
    const timer = setInterval(() => { if (!document.body.contains(content)) clearInterval(timer); else ping(); }, 20000);
    return { content, links, setTitle(t) { title.textContent = t; document.title = t + ' - SecureScan AI'; },
      setActive(key) { Object.entries(links).forEach(([k, a]) => a.classList.toggle('active', k === key || k === 'm-' + key)); } };
  }

  function route() {
    if (SS.cleanup) { try { SS.cleanup(); } catch (e) { /* ignore */ } SS.cleanup = null; }
    const hash = location.hash || '#/dashboard';
    const root = document.getElementById('app');
    if (!SS.token) {
      if (hash !== '#/login') { location.replace('#/login'); return; }
      shell = null; document.title = 'Sign in - SecureScan AI'; SS.view.login(root); return;
    }
    if (SS.user.must_change_password) {
      if (hash !== '#/change-password') { location.replace('#/change-password'); return; }
      shell = null; SS.view.changePassword(root); return;
    }
    if (hash === '#/login' || hash === '#/change-password') { location.replace('#/dashboard'); return; }
    if (!shell || !root.contains(shell.content)) shell = buildShell(root);
    for (const [re, view, title, nav] of ROUTES) {
      const m = re.exec(hash);
      if (m) {
        shell.setTitle(title); shell.setActive(nav); SS.clear(shell.content);
        SS.view[view](shell.content, m[1]); window.scrollTo(0, 0); return;
      }
    }
    SS.go('#/dashboard');
  }

  async function boot() {
    SS.theme.init();
    if (SS.loadSession()) {
      try { const remember = !!localStorage.getItem('ss-session'); const me = await SS.api('/auth/me'); SS.saveSession(SS.token, me, remember); }
      catch (e) { SS.clearSession(); }
    }
    window.addEventListener('hashchange', route);
    route();
  }
  boot();
})();
