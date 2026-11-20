/* New scan (website + source ZIP) */
(function () {
  'use strict';
  const { h } = SS;

  SS.view.newScan = async function (box) {
    SS.clear(box).appendChild(SS.loading());
    if (!SS.canScan()) { SS.clear(box).appendChild(SS.empty('lock', 'Read-only account', 'Your role can view results but cannot start scans.')); return; }
    let checks = [], engines = [], targets = [], info = {};
    try { [checks, engines, targets, info] = await Promise.all([SS.api('/system/checks'), SS.api('/system/engines'), SS.api('/targets'), SS.api('/system/info')]); }
    catch (e) { SS.clear(box).appendChild(SS.empty('alert', 'Could not load scan options', e.message)); return; }

    const st = { kind: 'website', mode: 'beginner', file: null };
    const url = h('input.input', { type: 'url', inputmode: 'url', placeholder: 'https://example.com', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', 'aria-label': 'Website address' });
    const authz = h('input', { type: 'checkbox' });
    const authzSrc = h('input', { type: 'checkbox' });
    const err = h('div.err', { role: 'alert' });
    const checkBoxes = {};
    const engineBoxes = {};
    const activeToggle = h('input', { type: 'checkbox' });
    const advWeb = h('div.stack', { hidden: true });
    const advSrc = h('div.stack', { hidden: true });
    const hostAllowed = () => {
      try { const host = new URL(url.value.trim()).hostname.toLowerCase(); return targets.some((t) => t.pattern.startsWith('*.') ? host.endsWith(t.pattern.slice(1)) && host !== t.pattern.slice(2) : t.pattern === host); } catch (e) { return false; }
    };

    const passive = checks.filter((c) => c.kind === 'passive'), active = checks.filter((c) => c.kind === 'active');
    const checkRow = (c, def) => { const cb = h('input', { type: 'checkbox', checked: def }); checkBoxes[c.id] = cb;
      return h('label.check', cb, h('div', h('b', c.label), h('span', c.description))); };
    const activeNote = h('div.callout.warn', SS.icon('alert', 18), h('div', 'Active checks send a few harmless probe requests (for example to common sensitive paths). They are available only for hosts on the authorization allowlist.',
      SS.isAdmin() ? [' Add the host under ', h('a', { href: '#/settings/targets' }, 'Settings > Authorized targets'), '.'] : ' Ask an administrator to add the host to the allowlist.'));
    const zap = engines.find((e) => e.id === 'zap');
    const zapBox = h('input', { type: 'checkbox', disabled: !zap || zap.state !== 'installed' });
    engineBoxes.zap = zapBox;
    SS.add(advWeb, h('h3', { style: { fontSize: '14px' } }, 'Passive checks'), h('div.grid.g2', passive.map((c) => checkRow(c, true))),
      h('h3', { style: { fontSize: '14px' } }, 'Active checks (authorized targets only)'), activeNote,
      h('label.check', activeToggle, h('div', h('b', 'Enable active checks'), h('span', 'Requires the target host to be allowlisted and the authorization box below to be ticked.'))),
      h('div.grid.g2', active.map((c) => checkRow(c, true))),
      h('label.check' + (zapBox.disabled ? '.disabled' : ''), zapBox, h('div', h('b', 'OWASP ZAP spider + passive scan'), h('span', zapBox.disabled ? 'Not available: ' + (zap ? zap.detail : 'not configured') : 'Runs through your ZAP instance (allowlisted targets only).'))));

    ['semgrep', 'trivy', 'osv'].forEach((id) => {
      const e = engines.find((x) => x.id === id) || { name: id, state: 'not_installed', detail: '' };
      const ok = e.state === 'installed' || e.state === 'available';
      const cb = h('input', { type: 'checkbox', checked: ok, disabled: !ok }); engineBoxes[id] = cb;
      SS.add(advSrc, h('label.check' + (ok ? '' : '.disabled'), cb, h('div', h('b', e.name, ' ', h('span.badge' + (ok ? '.ok' : ''), ok ? 'available' : e.state.replace('_', ' '))),
        h('span', ok ? e.detail : 'Scan not performed unless installed. ' + (e.install_hint || '')))));
    });

    const kindSeg = h('div.seg', { role: 'tablist' });
    const modeBox = h('div.modechoice');
    const webForm = h('div.stack.gap-l');
    const srcForm = h('div.stack.gap-l');
    const fileInput = h('input', { type: 'file', accept: '.zip,application/zip', class: 'sr', tabindex: -1 });
    const fileLabel = h('div', h('b', 'Drop a .zip file here or click to browse'), h('div.small.muted', 'Up to ' + info.max_upload_mb + ' MB. Code is read, never executed.'));
    const drop = h('div.dropzone', { tabindex: 0, role: 'button', 'aria-label': 'Choose a ZIP file', onclick: () => fileInput.click(), onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } } }, SS.icon('upload', 34), fileLabel);
    const setFile = (f) => { st.file = f; SS.add(SS.clear(fileLabel), f ? [h('b', f.name), h('div.small.muted', SS.bytes(f.size))] : [h('b', 'Drop a .zip file here or click to browse')]); };
    fileInput.addEventListener('change', () => setFile(fileInput.files[0] || null));
    ['dragover', 'dragenter'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
    ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
    drop.addEventListener('drop', (e) => { if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]); });
    const prog = h('div.bar', { hidden: true }, h('i', { style: { width: '0%' } }));
    const submit = h('button.btn.primary.lg', { type: 'button' }, SS.icon('bolt', 18), 'Start scan');

    function refresh() {
      SS.add(SS.clear(kindSeg), ...[['website', 'globe', 'Website'], ['source', 'code', 'Source code']].map(([k, ic, l]) =>
        h('button' + (st.kind === k ? '.on' : ''), { type: 'button', role: 'tab', 'aria-selected': String(st.kind === k), onclick: () => { st.kind = k; refresh(); } }, SS.icon(ic, 16), l)));
      SS.add(SS.clear(modeBox), ...[['beginner', 'eye', 'Beginner', 'Enter an address, press Scan, get a plain-language report.'], ['advanced', 'settings', 'Advanced', 'Choose individual checks and engines and see full technical evidence.']].map(([k, ic, t, d]) =>
        h('button.mode' + (st.mode === k ? '.on' : ''), { type: 'button', onclick: () => { st.mode = k; refresh(); } }, SS.icon(ic, 22), h('div', h('b', t), h('span', d)))));
      webForm.hidden = st.kind !== 'website'; srcForm.hidden = st.kind !== 'source';
      advWeb.hidden = st.mode !== 'advanced'; advSrc.hidden = st.mode !== 'advanced';
      activeToggle.disabled = false;
    }
    url.addEventListener('input', () => { activeNote.classList.toggle('hidden', hostAllowed()); });

    SS.add(webForm, SS.field('Website address', h('div.input-icon', SS.icon('globe', 18), url), 'Public http:// or https:// address. Local and private network addresses are blocked.'),
      advWeb,
      h('label.check', authz, h('div', h('b', 'I am authorized to scan this website'), h('span', 'I own it or have written permission from the owner. Scans are recorded in the audit log.'))));
    SS.add(srcForm, fileInput, drop, prog, advSrc,
      h('label.check', authzSrc, h('div', h('b', 'I own this code or am authorized to assess it'), h('span', 'The archive is checked, scanned as text and deleted afterwards. Nothing in it is executed or installed.'))));

    submit.addEventListener('click', async () => {
      err.textContent = '';
      submit.disabled = true;
      try {
        let scan;
        if (st.kind === 'website') {
          if (!url.value.trim()) throw new Error('Enter the website address to scan.');
          if (!authz.checked) throw new Error('Confirm that you are authorized to scan this website.');
          const adv = st.mode === 'advanced';
          const selected = adv ? Object.keys(checkBoxes).filter((k) => checkBoxes[k].checked) : null;
          scan = await SS.api('/scans/website', { method: 'POST', body: { url: url.value.trim(), mode: st.mode, checks: selected, active_checks: adv && activeToggle.checked,
            engines: adv && engineBoxes.zap.checked ? ['zap'] : [], authorization_confirmed: true } });
        } else {
          if (!st.file) throw new Error('Choose a .zip file to scan.');
          if (!authzSrc.checked) throw new Error('Confirm that you are authorized to assess this code.');
          const f = new FormData();
          f.append('file', st.file); f.append('mode', st.mode); f.append('authorization_confirmed', 'true');
          f.append('engines', ['semgrep', 'trivy', 'osv'].filter((k) => engineBoxes[k].checked).join(','));
          prog.hidden = false;
          scan = await SS.upload('/scans/source', f, (p) => { prog.firstChild.style.width = Math.round(p * 100) + '%'; });
        }
        SS.go('#/scans/' + scan.id);
      } catch (e) { err.textContent = e.message; prog.hidden = true; submit.disabled = false; }
    });

    refresh();
    SS.clear(box).appendChild(h('div.stack.gap-l', { style: { maxWidth: '860px' } },
      h('div', h('h2', { style: { fontSize: '22px' } }, 'Start a new scan'), h('p.muted', { style: { margin: '2px 0 0' } }, 'Choose what to assess, then how much detail you want.')),
      h('div.card.stack.gap-l', h('div', kindSeg), h('div.stack', h('b', 'Mode'), modeBox), webForm, srcForm, err, h('div.row.wrap', submit,
        h('span.small.muted', 'Scans run on this server in the background. You can leave the page.')))));
  };
})();
