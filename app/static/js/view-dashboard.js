/* Dashboard */
(function () {
  'use strict';
  const { h } = SS;

  function scanLabel(s) { return s.scan_type === 'website' ? SS.hostOf(s.target) : s.target; }

  SS.recentTable = function (scans) {
    return h('div.table-wrap', h('table.table.stackable', h('thead', h('tr', ['Target', 'Status', 'Score', 'When'].map((t) => h('th', t)))),
      h('tbody', scans.map((s) => h('tr.click', { tabindex: 0, onclick: () => SS.go('#/scans/' + s.id),
        onkeydown: (e) => { if (e.key === 'Enter') SS.go('#/scans/' + s.id); } },
        h('td', { dataset: { l: 'Target' } }, h('div.row', SS.icon(s.scan_type === 'website' ? 'globe' : 'code', 17), h('div', h('b.ellipsis', { style: { maxWidth: '260px', display: 'block' }, title: s.target }, scanLabel(s)),
          h('span.small.faint', s.scan_type === 'website' ? 'Website' : 'Source ZIP', ' - ', s.mode)))),
        h('td', { dataset: { l: 'Status' } }, SS.statusBadge(s.status), s.status === 'running' ? h('span.small.muted', ' ' + s.progress + '%') : null),
        h('td', { dataset: { l: 'Score' } }, s.score == null ? h('span.faint', '-') : h('b', { style: { color: SS.scoreColor(s.score) } }, String(s.score))),
        h('td.muted', { dataset: { l: 'When' } }, SS.ago(s.created_at)))))));
  };

  SS.view.dashboard = async function (box) {
    SS.clear(box).appendChild(SS.loading());
    let timer = null, alive = true;
    SS.cleanup = () => { alive = false; clearTimeout(timer); };
    async function load() {
      let d;
      try { d = await SS.api('/dashboard'); } catch (e) { if (alive) SS.clear(box).appendChild(SS.empty('alert', 'Could not load the dashboard', e.message)); return; }
      if (!alive) return;
      render(d);
      if (d.totals.running > 0) timer = setTimeout(load, 3000);
    }
    function render(d) {
      const t = d.totals, name = SS.user.full_name || SS.user.username;
      const kpi = (icon, label, value, sub) => h('div.card.kpi', h('div.l', SS.icon(icon, 16), label), h('div.v', String(value)), sub ? h('div.small.faint', sub) : null);
      const sevTiles = SS.SEV_ORDER.map((k) => h('div.card.sevtile', { style: { '--c': SS.SEV[k].color } },
        h('div.small.muted', SS.SEV[k].label), h('div.v', String(d.severity[k] || 0))));
      const catCard = h('div.card', h('h2', 'Most frequent finding categories'),
        d.categories.length ? SS.charts.hbars(d.categories) : h('p.muted', 'No findings recorded yet.'));
      const donutCard = h('div.card', h('h2', 'Findings by severity'),
        h('div.row.wrap', { style: { justifyContent: 'center', gap: '24px' } }, SS.charts.donut(d.severity),
          h('div.legend', SS.SEV_ORDER.map((k) => h('div', { style: { '--c': SS.SEV[k].color } }, h('i'), h('span.muted', SS.SEV[k].label), h('b', { style: { marginLeft: 'auto', paddingLeft: '14px' } }, String(d.severity[k] || 0)))))));
      const recent = h('div.card.flush', h('div.card-head', { style: { padding: '18px 18px 0' } }, h('h2', 'Recent scans'),
        h('a.btn.ghost.sm', { href: '#/history' }, 'View all', SS.icon('chevron', 14))),
        d.recent_scans.length ? SS.recentTable(d.recent_scans) : SS.empty('scan', 'No scans yet', 'Run your first scan to see results here.',
          SS.canScan() ? h('a.btn.primary', { href: '#/scan/new' }, SS.icon('plus', 16), 'New scan') : null));
      const left = h('div.stack.gap-l', recent, h('div.card', h('h2', 'Scans in the last 14 days'), SS.charts.dayBars(d.scans_per_day)));
      const right = h('div.stack.gap-l', donutCard, catCard);
      const activity = d.activity ? h('div.card', h('h2', 'Recent user activity'), d.activity.length ? h('div.stack.gap-s', d.activity.map((a) =>
        h('div.row.small', h('span.badge', a.action.replace(/_/g, ' ')), h('b', a.username || 'system'), h('span.muted.ellipsis.grow', a.detail), h('span.faint', SS.ago(a.created_at))))) : h('p.muted', 'No activity.')) : null;
      SS.clear(box).appendChild(h('div.stack.gap-l',
        h('div.row.between.wrap', h('div', h('h2', { style: { fontSize: '22px' } }, 'Welcome back, ' + name),
          h('p.muted', { style: { margin: '2px 0 0' } }, d.scope === 'all' ? 'Overview of all scans on this server.' : 'Overview of your scans.')),
          SS.canScan() ? h('a.btn.primary.lg', { href: '#/scan/new' }, SS.icon('plus', 18), 'New scan') : null),
        h('div.grid.g4.kpi-row', kpi('scan', 'Total scans', t.scans, t.running ? t.running + ' running' : null), kpi('check', 'Completed', t.completed),
          kpi('alert', 'Failed', t.failed), kpi('shield', 'Average score', t.average_score == null ? '-' : t.average_score, 'of completed scans')),
        h('div.grid.g5.sev-row', sevTiles), h('div.grid.g-main', left, right), activity));
    }
    load();
  };
})();
