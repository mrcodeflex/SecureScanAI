// Headless smoke test of the real web UI: login -> dashboard -> scan -> results -> history -> reports -> users -> settings -> logout.
const { JSDOM, VirtualConsole } = require('jsdom');
const BASE = process.env.BASE, FIXTURE = process.env.FIXTURE;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0, passed = 0;
function check(name, cond, extra) { if (cond) { passed++; console.log('  ok  ' + name); } else { failures++; console.log('  FAIL ' + name + (extra ? ' -> ' + extra : '')); } }

(async () => {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => { if (!/navigation|createObjectURL|scrollTo|not implemented/i.test(e.message)) errors.push(e.message); });
  const dom = await JSDOM.fromURL(BASE + '/', {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(w) {
      w.fetch = (u, o) => fetch(new URL(u, BASE), o);
      w.matchMedia = () => ({ matches: false, addEventListener() {}, addListener() {} });
      w.crypto = require('crypto').webcrypto; w.scrollTo = () => {};
      w.URL.createObjectURL = () => 'blob:test'; w.URL.revokeObjectURL = () => {};
      w.navigator.clipboard = { writeText: async () => {} };
      w.addEventListener('error', (e) => errors.push('window error: ' + e.message));
    },
  });
  const w = dom.window, d = w.document;
  const $ = (s, r) => (r || d).querySelector(s), $$ = (s, r) => Array.from((r || d).querySelectorAll(s));
  const waitFor = async (fn, what, ms = 20000) => { const end = Date.now() + ms; while (Date.now() < end) { try { const v = fn(); if (v) return v; } catch (e) { /* retry */ } await sleep(80); } throw new Error('timeout waiting for ' + what); };
  const type = (el, v) => { el.value = v; el.dispatchEvent(new w.Event('input', { bubbles: true })); el.dispatchEvent(new w.Event('change', { bubbles: true })); };
  const btnByText = (t, root) => $$('button,a.btn', root).find((b) => b.textContent.trim().includes(t));
  const go = async (hash, sel, what) => { w.location.hash = hash; return waitFor(() => $(sel), what); };
  const goText = async (hash, text) => { w.location.hash = hash; return waitFor(() => ($('#content') || {}).textContent && $('#content').textContent.includes(text), 'page text "' + text + '"'); };

  try {
    console.log('Login');
    await waitFor(() => $('.auth form'), 'login form');
    check('login screen shows brand panel', !!$('.auth-art'));
    type($('input[name=username]'), 'uiadmin'); type($('input[name=password]'), 'wrong-password-1');
    $('.auth form').dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => $('.err') && $('.err').textContent.includes('Invalid'), 'bad-login error');
    check('wrong password shows a generic error', true);
    type($('input[name=password]'), process.env.ADMIN_PASS);
    $('.auth form').dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => $('.shell'), 'application shell');
    check('signed in and shell rendered', !!$('.sidebar') && !!$('.bottom-nav'));

    console.log('Dashboard');
    await waitFor(() => $('.kpi'), 'dashboard KPIs');
    check('KPI cards render (4)', $$('.kpi').length === 4);
    check('five severity tiles render', $$('.sevtile').length === 5);
    check('empty state shown before any scan', !!$('.empty'));

    console.log('Website scan (Beginner)');
    await go('#/scan/new', '.dropzone, input[type=url]', 'new scan page');
    check('mode choices render', $$('.mode').length === 2);
    type($('input[type=url]'), FIXTURE);
    btnByText('Start scan').click();
    await waitFor(() => $('.err') && $('.err').textContent.includes('authorized'), 'authorization required error');
    check('scan blocked until authorization ticked', true);
    $$('input[type=checkbox]').find((c) => c.closest('label.check') && c.closest('label.check').textContent.includes('authorized to scan this website')).checked = true;
    btnByText('Start scan').click();
    await waitFor(() => /#\/scans\/[a-f0-9]+/.test(w.location.hash), 'scan page navigation');
    await waitFor(() => $('.radar') || $('.finding'), 'progress or results');
    await waitFor(() => $('.finding'), 'findings list', 40000);
    check('results show a score ring', !!$('.card svg[role=img][aria-label^="Security score"]'));
    const nFind = $$('.finding').length;
    check('findings rendered (>= 6)', nFind >= 6, String(nFind));
    check('severity filter chips render', $$('.chip').length === 6);
    $('.finding-head').click();
    check('finding expands with simple explanation', !!$('.finding.open h4') && $('.finding.open').textContent.includes('How to fix it'));
    btnByText('Technical').click();
    await sleep(100); $('.finding-head').click();
    check('technical view shows rule and engine', $('.finding.open').textContent.includes('Rule') && $('.finding.open').textContent.includes('Engine'));
    const q = $('input[type=search]'); type(q, 'cookie'); await sleep(50);
    check('search filters findings', $$('.finding:not(.hidden)').length > 0 && $$('.finding:not(.hidden)').length < nFind);
    type(q, '');
    check('download buttons present (PDF/JSON/CSV)', ['PDF', 'JSON', 'CSV'].every((t) => btnByText(t)));
    btnByText('JSON').click(); await sleep(400);

    console.log('Source scan (ZIP upload)');
    await go('#/scan/new', '.modechoice', 'new scan page');
    btnByText('Source code').click(); await sleep(50);
    const zip = require('zlib'); // build a tiny valid zip in memory via python-free approach: store method
    function makeZip(name, text) {
      const data = Buffer.from(text), crc = (function () { let c, t = []; for (let n = 0; n < 256; n++) { c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } let x = 0xffffffff; for (const b of data) x = t[(x ^ b) & 0xff] ^ (x >>> 8); return (x ^ 0xffffffff) >>> 0; })();
      const nm = Buffer.from(name), lh = Buffer.alloc(30), ch = Buffer.alloc(46), eo = Buffer.alloc(22);
      lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nm.length, 26);
      ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nm.length, 28);
      const cdOff = lh.length + nm.length + data.length, cdLen = ch.length + nm.length;
      eo.writeUInt32LE(0x06054b50, 0); eo.writeUInt16LE(1, 8); eo.writeUInt16LE(1, 10); eo.writeUInt32LE(cdLen, 12); eo.writeUInt32LE(cdOff, 16);
      return Buffer.concat([lh, nm, data, ch, nm, eo]);
    }
    const bytes = makeZip('app.py', 'import os\nos.system("ping " + host)\nDEBUG = True\n');
    const fileInput = $('input[type=file]');
    Object.defineProperty(fileInput, 'files', { value: [new w.File([bytes], 'sample.zip', { type: 'application/zip' })], configurable: true });
    fileInput.dispatchEvent(new w.Event('change', { bubbles: true }));
    await waitFor(() => $('.dropzone').textContent.includes('sample.zip'), 'file chosen');
    $$('input[type=checkbox]').find((c) => c.closest('label.check') && c.closest('label.check').textContent.includes('own this code')).checked = true;
    btnByText('Start scan').click();
    await waitFor(() => /#\/scans\/[a-f0-9]+/.test(w.location.hash), 'source scan navigation');
    await waitFor(() => $('.finding'), 'source findings', 40000);
    check('source findings reference file and line', $$('.finding-head').some((b) => b.textContent.includes('app.py:')));
    check('built-in rule findings are labelled "Needs review"', $$('.badge').some((b) => b.textContent.includes('Needs review')));

    console.log('History and reports');
    await go('#/history', 'table.table tbody tr', 'history rows');
    check('history lists both scans', $$('table.table tbody tr').length >= 2);
    await go('#/reports', '.grid.g2 .card', 'reports');
    check('reports page offers 3 formats per scan', $$('.card').filter((c) => ['PDF', 'JSON', 'CSV'].every((t) => c.textContent.includes(t))).length >= 2);
    await go('#/dashboard', '.kpi', 'dashboard again');
    await waitFor(() => $$('.kpi .v')[0].textContent === '2', 'dashboard total scans = 2');
    check('dashboard counts come from real scans', $$('.kpi .v')[0].textContent === '2' && !!$('svg[aria-label="Findings by severity"]'));

    console.log('Administration');
    await goText('#/users', 'Add user');
    check('user table lists the administrator', $('#content table.table').textContent.includes('uiadmin'));
    btnByText('Add user').click();
    await waitFor(() => $('.modal'), 'add user modal');
    const inputs = $$('.modal input.input');
    type(inputs[0], 'ui.newbie'); type(inputs[1], 'UI Newbie');
    if (!btnByText('Create user', $('.modal'))) console.log('DEBUG modal foot:', ($('.modal-foot')||{}).outerHTML, 'buttons:', $$('button', $('.modal')).map((b) => b.textContent));
    btnByText('Create user', $('.modal')).click();
    await waitFor(() => d.body.textContent.includes('ui.newbie'), 'new user in table');
    check('admin can create a user', true);
    await goText('#/settings/engines', 'Semgrep');
    check('engines page is honest about Semgrep/Trivy', $('#content').textContent.includes('not installed') && $('#content').textContent.includes('Trivy'));
    await goText('#/settings/targets', 'Add authorized target');
    await goText('#/settings/audit', 'scan created');
    check('audit log records scans', $('#content').textContent.includes('scan created') && $('#content').textContent.includes('login'));
    await goText('#/help', 'Quick start');
    check('help page renders sections', $$('details').length >= 6);

    console.log('Theme and logout');
    $('button[aria-label^="Toggle"]').click();
    check('theme toggles to light', d.documentElement.dataset.theme === 'light');
    $('button[aria-label="Sign out"]').click();
    await waitFor(() => $('.auth form'), 'back at login');
    check('sign out returns to login', !w.localStorage.getItem('ss-session') && !w.sessionStorage.getItem('ss-session'));
  } catch (e) {
    failures++; console.log('  FAIL ' + e.message);
  }
  check('no uncaught script errors', errors.length === 0, errors.slice(0, 3).join(' | '));
  console.log(`\n${passed} passed, ${failures} failed`);
  process.exit(failures ? 1 : 0);
})();
