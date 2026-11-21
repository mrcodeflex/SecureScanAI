/* Users, settings and help */
(function () {
  'use strict';
  const { h } = SS;
  const ROLE_LABEL = { super_admin: 'Super Administrator', admin: 'Administrator', user: 'Standard User', read_only: 'Read-only User' };
  const ROLE_HELP = { super_admin: 'Full control, including administrator accounts.', admin: 'Manages users, authorized targets and sees all scans.',
    user: 'Runs scans and sees their own results.', read_only: 'Views scans and downloads reports; cannot start scans.' };
  function genPassword() {
    const a = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789', b = new Uint32Array(18);
    crypto.getRandomValues(b); return Array.from(b, (x) => a[x % a.length]).join('') + '7';
  }
  const initials = (u) => (u.full_name || u.username).trim().slice(0, 2).toUpperCase();

  /* ----------------------------- Users ----------------------------- */
  SS.view.users = async function (box) {
    SS.cleanup = null;
    if (!SS.isAdmin()) { SS.clear(box).appendChild(SS.empty('lock', 'Administrators only', 'You do not have access to user management.')); return; }
    const roles = SS.user.role === 'super_admin' ? ['super_admin', 'admin', 'user', 'read_only'] : ['user', 'read_only'];
    const roleSelect = (val) => h('select.select', roles.map((r) => h('option', { value: r, selected: r === val }, ROLE_LABEL[r])));
    async function load() {
      SS.clear(box).appendChild(SS.loading());
      let users; try { users = await SS.api('/users'); } catch (e) { SS.clear(box).appendChild(SS.empty('alert', 'Could not load users', e.message)); return; }
      const canManage = (u) => SS.user.role === 'super_admin' || ['user', 'read_only'].includes(u.role);
      const rows = users.map((u) => {
        const self = u.id === SS.user.id;
        const act = [];
        if (canManage(u)) {
          act.push(h('button.btn.sm', { type: 'button', onclick: () => editUser(u) }, 'Edit'));
          if (!self) act.push(h('button.btn.sm', { type: 'button', onclick: () => resetPw(u) }, SS.icon('key', 14), 'Reset'),
            h('button.btn.sm', { type: 'button', onclick: () => toggle(u) }, u.is_active ? 'Disable' : 'Enable'),
            h('button.btn.sm.danger', { type: 'button', 'aria-label': 'Delete ' + u.username, onclick: () => remove(u) }, SS.icon('trash', 14)));
        }
        act.push(h('button.btn.sm.ghost', { type: 'button', onclick: () => activity(u) }, 'Activity'));
        return h('tr', h('td', { dataset: { l: 'User' } }, h('div.row', h('div.avatar', initials(u)), h('div', h('b', u.username, self ? h('span.badge', { style: { marginLeft: '8px' } }, 'you') : null), h('div.small.faint', u.full_name || u.email || '')))),
          h('td', { dataset: { l: 'Role' } }, h('span.badge', ROLE_LABEL[u.role])), h('td', { dataset: { l: 'Status' } }, h('span.badge' + (u.is_active ? '.ok' : '.bad'), u.is_active ? 'Active' : 'Disabled'), u.must_change_password ? h('div.small.faint', 'Must change password') : null),
          h('td.muted.hide-m', SS.ago(u.last_login_at)), h('td.hide-m', String(u.scan_count)), h('td', h('div.row.wrap', { style: { gap: '6px' } }, act)));
      });
      SS.clear(box).appendChild(h('div.stack.gap-l', h('div.row.between.wrap', h('div', h('h2', { style: { fontSize: '22px' } }, 'User management'), h('p.muted', { style: { margin: '2px 0 0' } }, 'Only administrators can create accounts. Public registration is disabled.')),
        h('button.btn.primary', { type: 'button', onclick: addUser }, SS.icon('plus', 16), 'Add user')),
        h('div.card.flush', h('div.table-wrap', h('table.table.stackable', h('thead', h('tr', ['User', 'Role', 'Status', 'Last sign-in', 'Scans', 'Actions'].map((x) => h('th', { class: ['Last sign-in', 'Scans'].includes(x) ? 'hide-m' : '' }, x)))), h('tbody', rows)))),
        h('div.card', h('h2', 'Roles'), h('div.grid.g2', Object.keys(ROLE_LABEL).map((r) => h('div', h('b', ROLE_LABEL[r]), h('div.small.muted', ROLE_HELP[r])))))));
    }
    function addUser() {
      const f = { username: h('input.input', { autocapitalize: 'none', autocomplete: 'off', spellcheck: 'false' }), name: h('input.input', { autocomplete: 'off' }), email: h('input.input', { type: 'email', autocomplete: 'off' }),
        role: roleSelect('user'), pw: h('input.input.mono', { type: 'text', autocomplete: 'off', value: genPassword() }), must: h('input', { type: 'checkbox', checked: true }) };
      SS.modal({ title: 'Add user', body: h('div.stack', SS.field('Username', f.username, '3-32 characters: lowercase letters, digits, dot, dash, underscore.'), SS.field('Full name', f.name), SS.field('Email (optional)', f.email), SS.field('Role', f.role),
        SS.field('Initial password', h('div.row', h('div.grow', f.pw), h('button.btn.iconbtn', { type: 'button', 'aria-label': 'Generate password', onclick: () => { f.pw.value = genPassword(); } }, SS.icon('refresh', 16))), 'Share it securely. At least 12 characters with letters and numbers.'),
        h('label.row.small', f.must, ' Require a password change at first sign-in')),
      actions: [{ label: 'Cancel', onClick: (c) => c() }, { label: 'Create user', kind: 'primary', onClick: async (close) => {
        await SS.api('/users', { method: 'POST', body: { username: f.username.value, full_name: f.name.value, email: f.email.value, role: f.role.value, password: f.pw.value, must_change_password: f.must.checked } });
        close(); SS.toast('User created', 'ok'); load(); } }] });
    }
    function editUser(u) {
      const f = { name: h('input.input', { value: u.full_name }), email: h('input.input', { type: 'email', value: u.email }), role: roleSelect(u.role) };
      if (u.id === SS.user.id) f.role.disabled = true;
      if (!roles.includes(u.role)) SS.add(f.role, h('option', { value: u.role, selected: true }, ROLE_LABEL[u.role]));
      SS.modal({ title: 'Edit ' + u.username, body: h('div.stack', SS.field('Full name', f.name), SS.field('Email', f.email), SS.field('Role', f.role, u.id === SS.user.id ? 'You cannot change your own role.' : null)),
        actions: [{ label: 'Cancel', onClick: (c) => c() }, { label: 'Save', kind: 'primary', onClick: async (close) => {
          await SS.api('/users/' + u.id, { method: 'PATCH', body: { full_name: f.name.value, email: f.email.value, role: f.role.value } }); close(); SS.toast('User updated', 'ok'); load(); } }] });
    }
    function resetPw(u) {
      const custom = h('input.input.mono', { type: 'text', placeholder: 'Leave empty to generate a temporary password', autocomplete: 'off' });
      SS.modal({ title: 'Reset password for ' + u.username, body: h('div.stack', h('p.muted', { style: { margin: 0 } }, 'The user is signed out everywhere and must choose a new password at the next sign-in.'), SS.field('New password (optional)', custom)),
        actions: [{ label: 'Cancel', onClick: (c) => c() }, { label: 'Reset password', kind: 'primary', onClick: async (close) => {
          const r = await SS.api('/users/' + u.id + '/reset-password', { method: 'POST', body: { new_password: custom.value || null } }); close();
          const pw = r.temporary_password || custom.value;
          SS.modal({ title: 'Password reset', body: h('div.stack', h('p', 'Give this temporary password to ' + u.username + '. It is shown only once.'), h('pre.codeblock', { style: { fontSize: '16px' } }, pw)),
            actions: [{ label: 'Copy', onClick: async () => { await SS.copyText(pw); return false; } }, { label: 'Done', kind: 'primary', onClick: (c) => c() }] }); } }] });
    }
    async function toggle(u) {
      if (u.is_active && !(await SS.confirm('Disable ' + u.username + '?', 'They will be signed out and unable to sign in until re-enabled.', 'Disable', true))) return;
      try { await SS.api('/users/' + u.id, { method: 'PATCH', body: { is_active: !u.is_active } }); SS.toast(u.is_active ? 'User disabled' : 'User enabled', 'ok'); load(); } catch (e) { SS.toast(e.message, 'bad'); }
    }
    async function remove(u) {
      if (!(await SS.confirm('Delete ' + u.username + '?', 'The account is removed permanently. Their past scans stay in the history.', 'Delete user', true))) return;
      try { await SS.api('/users/' + u.id, { method: 'DELETE' }); SS.toast('User deleted', 'ok'); load(); } catch (e) { SS.toast(e.message, 'bad'); }
    }
    async function activity(u) {
      let r; try { r = await SS.api('/users/' + u.id + '/activity'); } catch (e) { SS.toast(e.message, 'bad'); return; }
      SS.modal({ title: 'Activity: ' + u.username, wide: true, body: h('div.stack.gap-l', h('h4', 'Recent scans'),
        r.scans.length ? h('div.stack.gap-s', r.scans.map((s) => h('a.row.small', { href: '#/scans/' + s.id, onclick: () => document.querySelector('.overlay') && document.querySelector('.overlay').remove() }, SS.statusBadge(s.status), h('span.ellipsis.grow', s.target), h('span.faint', SS.ago(s.created_at))))) : h('p.muted.small', 'No scans.'),
        h('h4', 'Recent events'), r.events.length ? h('div.stack.gap-s', r.events.slice(0, 40).map((e) => h('div.row.small', h('span.badge', e.action.replace(/_/g, ' ')), h('span.muted.ellipsis.grow', e.detail), h('span.faint', SS.ago(e.created_at))))) : h('p.muted.small', 'No events.')),
      actions: [{ label: 'Close', kind: 'primary', onClick: (c) => c() }] });
    }
    load();
  };

  /* ----------------------------- Settings ----------------------------- */
  SS.view.settings = async function (box, tab) {
    SS.cleanup = null;
    const tabs = [['profile', 'Profile'], ['engines', 'Scan engines'], ['targets', 'Authorized targets']];
    if (SS.isAdmin()) tabs.push(['audit', 'Audit log']);
    tabs.push(['system', 'System']);
    tab = tabs.some((t) => t[0] === tab) ? tab : 'profile';
    const pane = h('div');
    SS.clear(box).appendChild(h('div.stack', h('div', h('h2', { style: { fontSize: '22px' } }, 'Settings')),
      h('div.tabs', { role: 'tablist' }, tabs.map(([k, l]) => h('button' + (k === tab ? '.on' : ''), { type: 'button', role: 'tab', onclick: () => SS.go('#/settings/' + k) }, l))), pane));
    const render = { profile, engines, targets, audit, system }[tab];
    pane.appendChild(SS.loading());
    try { SS.clear(pane).appendChild(await render()); } catch (e) { SS.clear(pane).appendChild(SS.empty('alert', 'Could not load this section', e.message)); }

    async function profile() {
      const u = SS.user;
      const cur = h('input.input', { type: 'password', autocomplete: 'current-password' }), n1 = h('input.input', { type: 'password', autocomplete: 'new-password' }), n2 = h('input.input', { type: 'password', autocomplete: 'new-password' });
      const err = h('div.err', { role: 'alert' });
      const themeNow = document.documentElement.dataset.theme;
      return h('div.grid.g2',
        h('div.stack.gap-l', h('div.card', h('div.row', { style: { gap: '14px' } }, h('div.avatar', { style: { width: '52px', height: '52px', fontSize: '18px' } }, initials(u)), h('div', h('h3', u.full_name || u.username), h('div.muted.small', '@' + u.username + ' - ' + ROLE_LABEL[u.role]))),
          h('dl.kv', { style: { marginTop: '16px' } }, h('dt', 'Email'), h('dd', u.email || '-'), h('dt', 'Last sign-in'), h('dd', SS.fmtDate(u.last_login_at)), h('dt', 'Server'), h('dd.mono', location.origin))),
          h('div.card', h('h2', 'Appearance'), h('div.seg', [['dark', 'moon', 'Dark'], ['light', 'sun', 'Light']].map(([k, ic, l]) => h('button' + (themeNow === k ? '.on' : ''), { type: 'button', onclick: () => { SS.theme.set(k); SS.view.settings(box, 'profile'); } }, SS.icon(ic, 16), l)))),
          SS.isAdmin() ? h('a.card.row.between', { href: '#/users', style: { textDecoration: 'none', color: 'inherit' } }, h('div.row', SS.icon('users', 20), h('div', h('b', 'User management'), h('div.small.muted', 'Create, edit and disable accounts'))), SS.icon('chevron', 16)) : null,
          h('a.card.row.between', { href: '#/help', style: { textDecoration: 'none', color: 'inherit' } }, h('div.row', SS.icon('help', 20), h('div', h('b', 'Help and documentation'), h('div.small.muted', 'Modes, severities, scoring and responsible use'))), SS.icon('chevron', 16)),
          h('button.btn.danger.block', { type: 'button', onclick: () => SS.logout() }, SS.icon('logout', 16), 'Sign out')),
        h('form.card.stack', { novalidate: true, onsubmit: async (e) => { e.preventDefault(); err.textContent = '';
          if (n1.value !== n2.value) { err.textContent = 'The new passwords do not match.'; return; }
          try { await SS.api('/auth/change-password', { method: 'POST', body: { current_password: cur.value, new_password: n1.value } }); SS.toast('Password changed. Other sessions were signed out.', 'ok'); cur.value = n1.value = n2.value = ''; } catch (ex) { err.textContent = ex.message; } } },
          h('h2', 'Change password'), SS.field('Current password', cur), SS.field('New password', n1, 'At least 12 characters, with letters and numbers.'), SS.field('Repeat new password', n2), err, h('div', h('button.btn.primary', { type: 'submit' }, 'Update password'))));
    }

    async function engines() {
      const list = await SS.api('/system/engines');
      const cls = { installed: '.ok', available: '.ok', not_installed: '.warn', disabled: '', unreachable: '.bad' };
      return h('div.stack.gap-l', h('div.callout', SS.icon('info', 18), 'The built-in engines always work. Optional engines are used only when they are really installed or reachable; otherwise the scan is labelled "not performed".'),
        h('div.grid.g2', list.map((e) => h('div.card.stack.gap-s', h('div.row.between', h('b', e.name), h('span.badge' + (cls[e.state] || ''), e.state.replace('_', ' '))),
          h('div.small.muted', e.kind === 'website' ? 'Website scanning' : 'Source-code scanning', e.version ? ' - v' + e.version : ''), h('div.small', e.detail),
          e.state !== 'installed' && e.install_hint ? h('div.codeblock.small', e.install_hint) : null,
          e.docs ? h('a.small', { href: e.docs, target: '_blank', rel: 'noopener noreferrer' }, 'Documentation ', SS.icon('external', 12)) : null))));
    }

    async function targets() {
      const list = await SS.api('/targets');
      const p = h('input.input', { placeholder: 'example.com or *.example.com', autocapitalize: 'none', spellcheck: 'false' }), note = h('input.input', { placeholder: 'Note (optional)' });
      const add = async () => { try { await SS.api('/targets', { method: 'POST', body: { pattern: p.value, note: note.value } }); SS.toast('Target added', 'ok'); SS.view.settings(box, 'targets'); } catch (e) { SS.toast(e.message, 'bad'); } };
      return h('div.stack.gap-l', h('div.callout.warn', SS.icon('alert', 18), 'Active checks and OWASP ZAP run only against hosts on this list. Add a host only if you own it or have written permission to test it.'),
        SS.isAdmin() ? h('div.card', h('h2', 'Add authorized target'), h('div.row.wrap', h('div.grow', { style: { minWidth: '220px' } }, p), h('div.grow', { style: { minWidth: '180px' } }, note), h('button.btn.primary', { type: 'button', onclick: add }, SS.icon('plus', 16), 'Add'))) : null,
        h('div.card.flush', list.length ? h('div.table-wrap', h('table.table.stackable', h('thead', h('tr', ['Host', 'Note', 'Added by', ''].map((x) => h('th', x)))), h('tbody', list.map((t) => h('tr', h('td.mono', { dataset: { l: 'Host' } }, t.pattern), h('td.muted', { dataset: { l: 'Note' } }, t.note || '-'), h('td.muted', { dataset: { l: 'Added by' } }, t.created_by),
          h('td', SS.isAdmin() ? h('button.btn.sm.danger', { type: 'button', onclick: async () => { if (await SS.confirm('Remove ' + t.pattern + '?', 'Active checks against this host will no longer be allowed.', 'Remove', true)) { await SS.api('/targets/' + t.id, { method: 'DELETE' }); SS.view.settings(box, 'targets'); } } }, SS.icon('trash', 14)) : null)))))) : SS.empty('shield', 'No authorized targets', 'Passive scans work for any public site. Add hosts here to allow active checks.')));
    }

    async function audit() {
      const events = await SS.api('/audit?limit=150');
      return h('div.card.flush', h('div.table-wrap', h('table.table.stackable', h('thead', h('tr', ['Time', 'User', 'Action', 'Detail', 'IP'].map((x) => h('th', x)))),
        h('tbody', events.map((e) => h('tr', h('td.muted', { dataset: { l: 'Time' } }, SS.fmtDate(e.created_at)), h('td', { dataset: { l: 'User' } }, e.username || '-'), h('td', { dataset: { l: 'Action' } }, h('span.badge', e.action.replace(/_/g, ' '))),
          h('td.muted', { dataset: { l: 'Detail' } }, e.detail), h('td.mono.small.muted', { dataset: { l: 'IP' } }, e.ip)))))));
    }

    async function system() {
      const i = await SS.api('/system/info');
      return h('div.stack.gap-l', h('div.card', h('h2', 'Server'), h('dl.kv', h('dt', 'Version'), h('dd', i.app + ' ' + i.version), h('dt', 'Address'), h('dd.mono', location.origin), h('dt', 'Upload limit'), h('dd', i.max_upload_mb + ' MB'),
        h('dt', 'Session length'), h('dd', Math.round(i.session_minutes / 60 * 10) / 10 + ' hours'), h('dt', 'Request cap'), h('dd', i.max_requests_per_scan + ' HTTP requests per scan'),
        h('dt', 'Private targets'), h('dd', i.allow_private_targets ? h('span.badge.warn', 'Allowed (development setting)') : h('span.badge.ok', 'Blocked')), h('dt', 'Allowlist only'), h('dd', i.require_allowlist_for_all ? 'All scans require an allowlisted host' : 'Only active checks require it'))),
        h('div.card', h('h2', 'Security score methodology'), h('p.muted', { style: { margin: 0 } }, i.score_methodology)));
    }
  };

  /* ----------------------------- Help ----------------------------- */
  SS.view.help = function (box) {
    SS.cleanup = null;
    const sec = (title, ...content) => h('details.card', h('summary', { style: { cursor: 'pointer', fontWeight: 700, fontSize: '15px' } }, title), h('div.stack', { style: { marginTop: '12px', color: 'var(--muted)' } }, content));
    SS.clear(box).appendChild(h('div.stack.gap-l', { style: { maxWidth: '860px' } }, h('div', h('h2', { style: { fontSize: '22px' } }, 'Help and documentation')),
      sec('Quick start', h('ol', { style: { margin: 0, paddingLeft: '20px' } }, h('li', 'Open New scan and choose Website or Source code.'), h('li', 'Enter the address (or choose a ZIP file) and tick the authorization box.'), h('li', 'Press Start scan. Progress is shown live; you can leave the page.'), h('li', 'Open the results, then download a PDF, JSON or CSV report.'))),
      sec('Beginner and Advanced mode', h('p', 'Beginner mode runs the standard passive checks and explains every result in plain language with a clear fix.'), h('p', 'Advanced mode lets you pick individual checks and engines and shows technical evidence, CWE references, CVSS where an engine supplies it, rule IDs and scan configuration. You can switch between the Simple and Technical view on any result.')),
      sec('Severity levels', ...SS.SEV_ORDER.map((k) => h('div.row', SS.sev(k), h('span', { critical: 'Direct, severe impact. Fix immediately.', high: 'Serious weakness. Fix soon.', medium: 'Meaningful weakness or missing protection.', low: 'Minor weakness or hardening gap.', info: 'Information only.' }[k])))),
      sec('Finding types', ...Object.keys(SS.TYPE_LABEL).map((k) => h('div', h('b', { style: { color: 'var(--text)' } }, SS.TYPE_LABEL[k]), h('div', SS.TYPE_HELP[k])))),
      sec('Passive and active checks', h('p', 'Passive checks only look at normal responses from the site (headers, cookies, TLS certificate, forms, error pages). Active checks send a few harmless probe requests and run only against hosts on the authorization allowlist. SecureScan AI never sends exploit payloads, guesses passwords or performs destructive tests.')),
      sec('Responsible use', h('p', 'Scan only systems you own or have written permission to test. Every scan is recorded in the audit log with the user, time and target.'), h('p', 'Local and private network addresses are blocked to prevent the scanner being used against internal services.')),
      sec('Optional engines', h('p', 'Semgrep, Trivy and OWASP ZAP are optional. See Settings > Scan engines for what is installed and how to add the rest. Anything not installed is labelled "scan not performed".')),
      sec('Troubleshooting', h('p', 'Cannot sign in: ask an administrator to reset your password. Scan failed: the message on the scan page explains why (unreachable host, blocked address, invalid ZIP...). Phone cannot connect: use the computer\'s LAN address, not localhost, and allow the port in Windows Firewall.'))));
  };
})();
