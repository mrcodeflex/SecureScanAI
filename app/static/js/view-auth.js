/* Login and forced password-change screens */
(function () {
  'use strict';
  const { h } = SS;

  SS.view.login = function (root) {
    SS.clear(root);
    const err = h('div.err', { role: 'alert' });
    const user = h('input.input', { type: 'text', name: 'username', autocomplete: 'username', required: true, autocapitalize: 'none', spellcheck: 'false' });
    const pass = h('input.input', { type: 'password', name: 'password', autocomplete: 'current-password', required: true });
    const remember = h('input', { type: 'checkbox' });
    const btn = h('button.btn.primary.lg.block', { type: 'submit' }, 'Sign in');
    const status = h('span.conn', h('span.dot'), h('span.t', 'Checking server...'));
    SS.api('/health').then(() => { status.firstChild.className = 'dot ok'; status.lastChild.textContent = 'Server connected'; })
      .catch(() => { status.firstChild.className = 'dot bad'; status.lastChild.textContent = 'Server not reachable'; });
    const form = h('form.stack.gap-l', {
      novalidate: true,
      onsubmit: async (e) => {
        e.preventDefault(); err.textContent = '';
        if (!user.value.trim() || !pass.value) { err.textContent = 'Enter your username and password.'; return; }
        btn.disabled = true; btn.textContent = 'Signing in...';
        try {
          const r = await SS.api('/auth/login', { method: 'POST', body: { username: user.value, password: pass.value } });
          SS.saveSession(r.token, r.user, remember.checked);
          SS.go(r.user.must_change_password ? '#/change-password' : '#/dashboard');
        } catch (ex) { err.textContent = ex.message; btn.disabled = false; btn.textContent = 'Sign in'; pass.value = ''; pass.focus(); }
      },
    },
      SS.field('Username', user), SS.field('Password', pass),
      h('label.row.small.muted', { style: { cursor: 'pointer' } }, remember, ' Keep me signed in on this device'),
      err, btn);
    root.appendChild(h('div.auth',
      h('div.auth-art',
        h('div.brand', h('img', { src: '/assets/logo.svg', alt: '' }), h('div', 'SecureScan AI', h('small', 'Vulnerability assessment'))),
        h('div', h('h2', 'Find weaknesses before attackers do.'),
          h('ul', h('li', SS.icon('globe', 20), h('span', 'Website scans with plain-language results and clear fixes.')),
            h('li', SS.icon('code', 20), h('span', 'Source-code ZIP analysis with secrets, injection and dependency checks.')),
            h('li', SS.icon('report', 20), h('span', 'Professional PDF, JSON and CSV reports from real scan data.')))),
        h('p.small', { style: { color: '#7f90b8' } }, 'Private platform. Scan only systems you own or are authorized to test.')),
      h('div.auth-form', h('div.auth-card.stack.gap-l',
        h('div', h('h1', 'Sign in'), h('p.muted', { style: { margin: 0 } }, 'Use the account created by your administrator.')),
        form, status,
        h('p.small.faint', SS.icon('lock', 14), ' Public registration is disabled. Contact your administrator for access.')))));
    user.focus();
  };

  SS.view.changePassword = function (root) {
    SS.clear(root);
    const cur = h('input.input', { type: 'password', autocomplete: 'current-password', required: true });
    const n1 = h('input.input', { type: 'password', autocomplete: 'new-password', required: true });
    const n2 = h('input.input', { type: 'password', autocomplete: 'new-password', required: true });
    const err = h('div.err', { role: 'alert' });
    const btn = h('button.btn.primary.lg.block', { type: 'submit' }, 'Update password');
    root.appendChild(h('div.auth-form', { style: { minHeight: '100vh' } }, h('div.auth-card.stack.gap-l',
      h('div.brand', h('img', { src: '/assets/logo.svg', alt: '' }), 'SecureScan AI'),
      h('div', h('h1', 'Choose a new password'), h('p.muted', { style: { margin: 0 } }, 'Your administrator requires a new password before you continue.')),
      h('form.stack.gap-l', { novalidate: true, onsubmit: async (e) => {
        e.preventDefault(); err.textContent = '';
        if (n1.value !== n2.value) { err.textContent = 'The new passwords do not match.'; return; }
        btn.disabled = true;
        try {
          const r = await SS.api('/auth/change-password', { method: 'POST', body: { current_password: cur.value, new_password: n1.value } });
          SS.saveSession(SS.token, r.user, !!localStorage.getItem('ss-session')); SS.toast('Password updated', 'ok'); SS.go('#/dashboard');
        } catch (ex) { err.textContent = ex.message; btn.disabled = false; }
      } },
        SS.field('Current (temporary) password', cur),
        SS.field('New password', n1, 'At least 12 characters, with letters and numbers.'),
        SS.field('Repeat new password', n2), err, btn),
      h('button.btn.ghost', { type: 'button', onclick: async () => { try { await SS.api('/auth/logout', { method: 'POST' }); } catch (e) { /* ignore */ } SS.clearSession(); SS.go('#/login'); } }, 'Sign out'))));
  };
})();
