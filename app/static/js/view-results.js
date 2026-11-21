/* Scan detail, history and reports */
(function () {
  'use strict';
  const { h } = SS;
  const FMT = [['pdf', 'PDF'], ['json', 'JSON'], ['csv', 'CSV']];

  function downloadButtons(scan, small) {
    return FMT.map(([f, l]) => h('button.btn' + (small ? '.sm' : ''), { type: 'button', title: 'Download ' + l + ' report',
      onclick: async (e) => { const b = e.currentTarget; b.disabled = true; try { await SS.download('/scans/' + scan.id + '/report.' + f, 'SecureScanAI-' + scan.report_id + '.' + f); SS.toast(l + ' report downloaded', 'ok'); } catch (ex) { SS.toast(ex.message, 'bad'); } b.disabled = false; } },
      SS.icon('download', 15), l));
  }

  function findingCard(f, technical) {
    const open = { v: false };
    const where = f.url || (f.file_path ? f.file_path + (f.line ? ':' + f.line : '') : '');
    const body = h('div.finding-body');
    const card = h('div.finding.' + f.severity);
    function build() {
      SS.clear(body);
      if (!technical) {
        SS.add(body, h('h4', 'What this means'), h('p', f.simple_explanation || f.description),
          f.why_it_matters ? [h('h4', 'Why it matters'), h('p', f.why_it_matters)] : null,
          h('h4', 'How to fix it'), h('p', f.remediation || 'No remediation guidance available.'),
          f.evidence ? h('details', { style: { marginTop: '14px' } }, h('summary.small.muted', { style: { cursor: 'pointer' } }, 'Show evidence'), h('pre.codeblock', { style: { marginTop: '8px' } }, f.evidence)) : null,
          h('p.small.faint', { style: { marginTop: '12px' } }, SS.TYPE_LABEL[f.finding_type] + ': ' + SS.TYPE_HELP[f.finding_type]));
      } else {
        const rows = [['Type', SS.TYPE_LABEL[f.finding_type] || f.finding_type], ['Confidence', f.confidence], ['Engine', f.engine], ['Rule', f.rule_id || '-'], ['Category', f.category]];
        if (where) rows.push([f.url ? 'Affected URL' : 'Location', where]);
        if (f.http_status) rows.push(['HTTP status', String(f.http_status)]);
        const dl = h('dl.kv', { style: { marginTop: '12px' } });
        rows.forEach(([k, v]) => SS.add(dl, h('dt', k), h('dd', k === 'Rule' || k.includes('URL') || k === 'Location' ? h('span.mono', v) : v)));
        if (f.cwe) SS.add(dl, h('dt', 'CWE'), h('dd', f.cwe.split(',').map((c, i) => { const n = (c.match(/\d+/) || [])[0]; return [i ? ', ' : '', n ? h('a', { href: 'https://cwe.mitre.org/data/definitions/' + n + '.html', target: '_blank', rel: 'noopener noreferrer' }, c.trim()) : c]; })));
        if (f.cvss_score || f.cvss_vector) SS.add(dl, h('dt', 'CVSS'), h('dd', (f.cvss_score ? f.cvss_score + ' ' : '') + (f.cvss_vector ? '(' + f.cvss_vector + ')' : '')));
        SS.add(body, h('h4', 'Description'), h('p', f.description || f.simple_explanation), dl,
          f.evidence ? [h('h4', 'Evidence'), h('pre.codeblock', f.evidence)] : null, h('h4', 'Remediation'), h('p', f.remediation),
          f.references && f.references.length ? [h('h4', 'References'), f.references.map((r) => h('div', /^https?:\/\//.test(r) ? h('a.small', { href: r, target: '_blank', rel: 'noopener noreferrer' }, r) : r))] : null);
      }
    }
    build();
    const head = h('button.finding-head', { type: 'button', 'aria-expanded': 'false', onclick: () => { open.v = !open.v; card.classList.toggle('open', open.v); head.setAttribute('aria-expanded', String(open.v)); } },
      SS.sev(f.severity), h('div.grow', h('b', { style: { display: 'block' } }, f.title), h('span.small.faint.ellipsis', { style: { display: 'block' } }, f.category + (where ? ' - ' + where : ''))),
      f.finding_type === 'potential' ? h('span.badge.warn.hide-m', 'Needs review') : null, h('span.chev', SS.icon('chevron', 16)));
    card.append(head, body);
    card.rebuild = build;
    return card;
  }

  SS.view.scanDetail = async function (box, id) {
    SS.clear(box).appendChild(SS.loading());
    let alive = true, timer = null, technical = null;
    const filter = { sev: null, q: '', type: '' };
    SS.cleanup = () => { alive = false; clearTimeout(timer); };

    async function load() {
      let scan;
      try { scan = await SS.api('/scans/' + id); } catch (e) { if (alive) SS.clear(box).appendChild(SS.empty('alert', 'Scan not available', e.message, h('a.btn', { href: '#/history' }, 'Back to history'))); return; }
      if (!alive) return;
      if (technical === null) technical = scan.mode === 'advanced';
      if (scan.status === 'queued' || scan.status === 'running') { renderRunning(scan); timer = setTimeout(load, 1500); } else renderDone(scan);
    }

    function header(scan) {
      return h('div.row.between.wrap', h('div.row', h('a.btn.ghost.iconbtn', { href: '#/history', 'aria-label': 'Back to history' }, SS.icon('back', 18)),
        h('div', h('h2', { style: { fontSize: '20px', wordBreak: 'break-all' } }, scan.scan_type === 'website' ? SS.hostOf(scan.target) : scan.target),
          h('div.small.muted', (scan.scan_type === 'website' ? 'Website scan' : 'Source code scan') + ' - ' + scan.mode + ' mode - ' + scan.report_id))), SS.statusBadge(scan.status));
    }

    function renderRunning(scan) {
      let cancelBtn = h('button.btn.danger', { type: 'button', onclick: async (e) => { e.currentTarget.disabled = true; try { await SS.api('/scans/' + id + '/cancel', { method: 'POST' }); SS.toast('Cancelling...'); } catch (ex) { SS.toast(ex.message, 'bad'); } } }, SS.icon('stop', 16), 'Cancel scan');
      if (!SS.canScan()) cancelBtn = null;
      SS.clear(box).appendChild(h('div.stack.gap-l', { style: { maxWidth: '900px' } }, header(scan),
        h('div.card', h('div.radar-wrap', SS.charts.radar(), h('div.stack',
          h('div', h('div.muted.small', scan.status === 'queued' ? 'Waiting for a free scan slot' : 'Scanning'), h('div', { style: { fontSize: '40px', fontWeight: 750, letterSpacing: '-.03em' } }, scan.progress + '%')),
          h('div.bar', h('i', { style: { width: scan.progress + '%' } })), h('p.muted', { style: { margin: 0 }, 'aria-live': 'polite' }, scan.progress_message),
          h('div.small.faint', 'Elapsed: ' + SS.duration(scan.started_at || scan.created_at)), h('div', cancelBtn)))),
        h('div.callout', SS.icon('info', 18), 'You can leave this page. The scan keeps running on the server and appears in your history.')));
    }

    function renderDone(scan) {
      if (scan.status !== 'completed') {
        SS.clear(box).appendChild(h('div.stack.gap-l', { style: { maxWidth: '800px' } }, header(scan),
          h('div.card', SS.empty(scan.status === 'failed' ? 'alert' : 'stop', scan.status === 'failed' ? 'The scan could not be completed' : 'The scan was cancelled', scan.error || 'No results were saved.',
            h('div.row', { style: { justifyContent: 'center' } }, h('a.btn.primary', { href: '#/scan/new' }, 'Start a new scan'), h('button.btn.danger', { type: 'button', onclick: del }, SS.icon('trash', 16), 'Delete'))))));
        return;
      }
      const list = h('div.stack');
      const cards = scan.findings.map((f) => ({ f, el: findingCard(f, technical) }));
      const countLine = h('div.small.muted');
      const chipBox = h('div.chips');
      const q = h('input.input', { type: 'search', placeholder: 'Search findings...', 'aria-label': 'Search findings', oninput: (e) => { filter.q = e.target.value.toLowerCase(); apply(); } });
      const typeSel = h('select.select', { 'aria-label': 'Filter by type', style: { maxWidth: '220px' }, onchange: (e) => { filter.type = e.target.value; apply(); } },
        h('option', { value: '' }, 'All types'), Object.entries(SS.TYPE_LABEL).map(([k, v]) => h('option', { value: k }, v)));
      function apply() {
        let shown = 0;
        cards.forEach(({ f, el }) => {
          const ok = (!filter.sev || f.severity === filter.sev) && (!filter.type || f.finding_type === filter.type) &&
            (!filter.q || (f.title + f.category + f.evidence + (f.file_path || '') + (f.url || '') + (f.rule_id || '')).toLowerCase().includes(filter.q));
          el.classList.toggle('hidden', !ok); if (ok) shown++;
        });
        countLine.textContent = 'Showing ' + shown + ' of ' + cards.length + ' finding(s)';
        SS.add(SS.clear(chipBox), h('button.chip' + (!filter.sev ? '.on' : ''), { type: 'button', onclick: () => { filter.sev = null; apply(); } }, 'All ', h('b', String(cards.length))),
          ...SS.SEV_ORDER.map((k) => h('button.chip' + (filter.sev === k ? '.on' : ''), { type: 'button', onclick: () => { filter.sev = filter.sev === k ? null : k; apply(); } },
            h('span.sev.' + k, { style: { padding: 0, background: 'none' } }), SS.SEV[k].label, ' ', h('b', String(scan.summary[k] || 0)))));
      }
      cards.forEach(({ el }) => list.appendChild(el));
      apply();
      const viewSeg = h('div.seg', ...[[false, 'Simple'], [true, 'Technical']].map(([v, l]) => h('button' + (technical === v ? '.on' : ''), { type: 'button', onclick: () => { technical = v; renderDone(scan); } }, l)));
      const side = h('div.stack.gap-l',
        h('div.card', h('h2', 'Reports'), h('div.row.wrap', downloadButtons(scan, false))),
        h('div.card', h('h2', 'Scan details'), h('dl.kv',
          h('dt', 'Target'), h('dd.mono', scan.target), h('dt', 'Started'), h('dd', SS.fmtDate(scan.started_at)), h('dt', 'Duration'), h('dd', SS.duration(scan.started_at, scan.finished_at)),
          h('dt', 'Requested by'), h('dd', scan.owner || '-'), h('dt', 'Active checks'), h('dd', scan.active_checks ? 'Yes (authorized target)' : 'No, passive only'),
          scan.config && scan.config.checks ? [h('dt', 'Checks'), h('dd.small', scan.config.checks.join(', '))] : null)),
        h('div.card', h('h2', 'Engines'), h('div.stack.gap-s', scan.engines.map((e) => h('div', h('div.row.between', h('b', e.name), h('span.badge' + ({ completed: '.ok', failed: '.bad', not_installed: '.warn', skipped: '.warn' }[e.status] || ''), e.status.replace('_', ' '))), h('div.small.muted', e.detail))))),
        scan.notes.length ? h('div.card', h('h2', 'Notes and limitations'), h('ul.small.muted', { style: { margin: 0, paddingLeft: '18px' } }, scan.notes.map((n) => h('li', n)))) : null,
        SS.canScan() ? h('button.btn.danger', { type: 'button', onclick: del }, SS.icon('trash', 16), 'Delete scan') : null);
      const score = h('div.card', h('div.row.wrap', { style: { gap: '28px' } }, SS.charts.ring(scan.score), h('div.stack.gap-s', { style: { flex: 1, minWidth: '200px' } },
        h('div', h('div.small.muted', 'Overall risk'), h('div', { style: { fontSize: '24px', fontWeight: 750, color: scan.risk_level === 'minimal' || scan.risk_level === 'low' ? 'var(--ok)' : scan.risk_level === 'medium' ? 'var(--medium)' : 'var(--critical)' } }, SS.RISK[scan.risk_level] || '-')),
        h('div.small.muted', scan.summary.total + ' finding(s) from ' + scan.engines.filter((e) => e.status === 'completed').length + ' engine(s).'),
        h('details', h('summary.small.muted', { style: { cursor: 'pointer' } }, 'How is the score calculated?'), h('p.small.muted', 'Starts at 100. Each distinct rule deducts points by severity (critical 25, high 12, medium 5, low 2) multiplied by confidence. Repeats count once; observations are not scored. It is an indicator, not a guarantee.')))));
      SS.clear(box).appendChild(h('div.stack.gap-l', header(scan), h('div.grid.g-main',
        h('div.stack.gap-l', score, h('div.card.stack', h('div.row.between.wrap', h('h2', { style: { margin: 0 } }, 'Findings'), viewSeg), chipBox,
          h('div.row.wrap', h('div.grow', { style: { minWidth: '180px' } }, q), typeSel), countLine,
          scan.findings.length ? list : SS.empty('shield', 'No findings', 'None of the checks that were run reported a problem. This does not prove the target is secure.'))), side)));
    }

    async function del() {
      if (!(await SS.confirm('Delete this scan?', 'The scan, its findings and reports will be permanently removed.', 'Delete', true))) return;
      try { await SS.api('/scans/' + id, { method: 'DELETE' }); SS.toast('Scan deleted', 'ok'); SS.go('#/history'); } catch (e) { SS.toast(e.message, 'bad'); }
    }
    load();
  };

  SS.view.history = async function (box) {
    const st = { q: '', status: '', type: '', offset: 0, limit: 15 };
    SS.cleanup = null;
    const body = h('div');
    const q = h('input.input', { type: 'search', placeholder: 'Search by target...', 'aria-label': 'Search scans' });
    let t = null;
    q.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { st.q = q.value.trim(); st.offset = 0; load(); }, 300); });
    const sel = (label, opts, key) => h('select.select', { 'aria-label': label, style: { maxWidth: '170px' }, onchange: (e) => { st[key] = e.target.value; st.offset = 0; load(); } }, opts.map(([v, l]) => h('option', { value: v }, l)));
    async function load() {
      SS.clear(body).appendChild(SS.loading());
      const p = new URLSearchParams({ limit: st.limit, offset: st.offset }); if (st.q) p.set('q', st.q); if (st.status) p.set('status', st.status); if (st.type) p.set('scan_type', st.type);
      let r; try { r = await SS.api('/scans?' + p); } catch (e) { SS.clear(body).appendChild(SS.empty('alert', 'Could not load history', e.message)); return; }
      if (!r.items.length) { SS.clear(body).appendChild(SS.empty('history', 'No scans found', st.q || st.status || st.type ? 'Try changing the filters.' : 'Scans you run will appear here.')); return; }
      const rows = r.items.map((s) => h('tr.click', { tabindex: 0, onclick: () => SS.go('#/scans/' + s.id), onkeydown: (e) => { if (e.key === 'Enter') SS.go('#/scans/' + s.id); } },
        h('td', { dataset: { l: 'Target' } }, h('div.row', SS.icon(s.scan_type === 'website' ? 'globe' : 'code', 17), h('b.ellipsis', { style: { maxWidth: '300px' }, title: s.target }, s.scan_type === 'website' ? SS.hostOf(s.target) : s.target))),
        h('td.hide-m', s.scan_type === 'website' ? 'Website' : 'Source ZIP', h('div.small.faint', s.mode)), h('td', { dataset: { l: 'Status' } }, SS.statusBadge(s.status)),
        h('td', { dataset: { l: 'Score' } }, s.score == null ? '-' : h('b', { style: { color: SS.scoreColor(s.score) } }, String(s.score))),
        h('td', { dataset: { l: 'Findings' } }, s.summary && s.summary.total != null ? String(s.summary.total) + (s.summary.critical || s.summary.high ? ' (' + ((s.summary.critical || 0) + (s.summary.high || 0)) + ' high+)' : '') : '-'),
        h('td.muted', { dataset: { l: 'Date' } }, SS.fmtDate(s.created_at)), h('td.hide-m', SS.isAdmin() ? s.owner : '')));
      const page = Math.floor(st.offset / st.limit) + 1, pages = Math.max(1, Math.ceil(r.total / st.limit));
      SS.add(SS.clear(body), h('div.table-wrap', h('table.table.stackable', h('thead', h('tr', ['Target', 'Type', 'Status', 'Score', 'Findings', 'Date', SS.isAdmin() ? 'Owner' : ''].map((x) => h('th', { class: ['Type', 'Owner', ''].includes(x) ? 'hide-m' : '' }, x)))), h('tbody', rows))),
        h('div.row.between', { style: { padding: '12px 16px' } }, h('span.small.muted', r.total + ' scan(s) - page ' + page + ' of ' + pages),
          h('div.row', h('button.btn.sm', { type: 'button', disabled: st.offset === 0, onclick: () => { st.offset -= st.limit; load(); } }, 'Previous'), h('button.btn.sm', { type: 'button', disabled: st.offset + st.limit >= r.total, onclick: () => { st.offset += st.limit; load(); } }, 'Next'))));
    }
    SS.clear(box).appendChild(h('div.stack.gap-l', h('div.row.between.wrap', h('div', h('h2', { style: { fontSize: '22px' } }, 'Scan history'), h('p.muted', { style: { margin: '2px 0 0' } }, SS.isAdmin() || SS.user.role === 'read_only' ? 'All scans on this server.' : 'Your scans.')),
      SS.canScan() ? h('a.btn.primary', { href: '#/scan/new' }, SS.icon('plus', 16), 'New scan') : null),
      h('div.row.wrap', h('div.grow', { style: { minWidth: '200px' } }, q), sel('Status', [['', 'All statuses'], ['completed', 'Completed'], ['running', 'Running'], ['failed', 'Failed'], ['cancelled', 'Cancelled']], 'status'),
        sel('Type', [['', 'All types'], ['website', 'Website'], ['source', 'Source code']], 'type')),
      h('div.card.flush', body)));
    load();
  };

  SS.view.reports = async function (box) {
    SS.cleanup = null; SS.clear(box).appendChild(SS.loading());
    let r; try { r = await SS.api('/scans?status=completed&limit=100'); } catch (e) { SS.clear(box).appendChild(SS.empty('alert', 'Could not load reports', e.message)); return; }
    SS.clear(box).appendChild(h('div.stack.gap-l', h('div', h('h2', { style: { fontSize: '22px' } }, 'Reports'), h('p.muted', { style: { margin: '2px 0 0' } }, 'Download PDF, JSON or CSV reports generated from stored scan results.')),
      r.items.length ? h('div.grid.g2', r.items.map((s) => h('div.card.stack', h('div.row.between', h('div.row', SS.icon(s.scan_type === 'website' ? 'globe' : 'code', 18), h('b.ellipsis', { title: s.target }, s.scan_type === 'website' ? SS.hostOf(s.target) : s.target)),
        h('b', { style: { color: SS.scoreColor(s.score), fontSize: '18px' } }, String(s.score))),
        h('div.small.muted', s.report_id + ' - ' + SS.fmtDate(s.finished_at) + ' - ' + (s.summary.total || 0) + ' finding(s)'),
        h('div.row.wrap', downloadButtons(s, true), h('a.btn.sm.ghost', { href: '#/scans/' + s.id }, 'Open', SS.icon('chevron', 14)))))) : h('div.card', SS.empty('report', 'No reports yet', 'Reports become available when a scan completes.'))));
  };
})();
