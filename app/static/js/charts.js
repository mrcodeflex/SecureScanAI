/* SecureScan AI - small SVG/CSS chart helpers (values always come from the API) */
(function () {
  'use strict';
  const { s, h } = SS;
  SS.charts = {
    donut(counts, size) {
      size = size || 176; const r = 64, c = 2 * Math.PI * r;
      const total = SS.SEV_ORDER.reduce((n, k) => n + (counts[k] || 0), 0);
      const svg = s('svg', { viewBox: '0 0 176 176', width: size, height: size, role: 'img', 'aria-label': 'Findings by severity' });
      svg.appendChild(s('circle', { cx: 88, cy: 88, r, fill: 'none', stroke: 'var(--line)', 'stroke-width': 18 }));
      let offset = 0;
      if (total) SS.SEV_ORDER.forEach((k) => {
        const n = counts[k] || 0; if (!n) return;
        const len = (n / total) * c;
        svg.appendChild(s('circle', { cx: 88, cy: 88, r, fill: 'none', stroke: SS.SEV[k].color, 'stroke-width': 18,
          'stroke-dasharray': Math.max(0, len - 2) + ' ' + (c - Math.max(0, len - 2)), 'stroke-dashoffset': -offset, transform: 'rotate(-90 88 88)' },
          s('title', {}, SS.SEV[k].label + ': ' + n)));
        offset += len;
      });
      svg.appendChild(s('text', { x: 88, y: 88, 'text-anchor': 'middle', 'font-size': 30, 'font-weight': 750, fill: 'var(--text)' }, String(total)));
      svg.appendChild(s('text', { x: 88, y: 108, 'text-anchor': 'middle', 'font-size': 11, fill: 'var(--muted)' }, 'findings'));
      return svg;
    },
    ring(score, size, caption) {
      size = size || 132; const r = 52, c = 2 * Math.PI * r, v = Math.max(0, Math.min(100, score == null ? 0 : score));
      const svg = s('svg', { viewBox: '0 0 132 132', width: size, height: size, role: 'img', 'aria-label': 'Security score ' + v + ' out of 100' });
      svg.appendChild(s('circle', { cx: 66, cy: 66, r, fill: 'none', stroke: 'var(--line)', 'stroke-width': 11 }));
      svg.appendChild(s('circle', { cx: 66, cy: 66, r, fill: 'none', stroke: SS.scoreColor(v), 'stroke-width': 11, 'stroke-linecap': 'round',
        'stroke-dasharray': (v / 100) * c + ' ' + c, transform: 'rotate(-90 66 66)' }));
      svg.appendChild(s('text', { x: 66, y: 72, 'text-anchor': 'middle', 'font-size': 34, 'font-weight': 750, fill: 'var(--text)' }, score == null ? '-' : String(v)));
      svg.appendChild(s('text', { x: 66, y: 92, 'text-anchor': 'middle', 'font-size': 10.5, fill: 'var(--muted)' }, caption || 'out of 100'));
      return svg;
    },
    hbars(items) {
      const max = Math.max(1, ...items.map((i) => i.count));
      return h('div', items.map((i) => h('div.hbar', h('span.ellipsis', { title: i.name }, i.name),
        h('div.bar', h('i', { style: { width: Math.max(3, (i.count / max) * 100) + '%' } })), h('b', String(i.count)))));
    },
    dayBars(days) {
      const max = Math.max(1, ...days.map((d) => d.count)), w = 520, ht = 120, bw = w / days.length;
      const svg = s('svg', { viewBox: '0 0 ' + w + ' ' + (ht + 22), width: '100%', role: 'img', 'aria-label': 'Scans per day, last 14 days', preserveAspectRatio: 'none' });
      days.forEach((d, i) => {
        const bh = d.count ? Math.max(6, (d.count / max) * ht) : 3;
        svg.appendChild(s('rect', { x: i * bw + 5, y: ht - bh, width: bw - 10, height: bh, rx: 4, fill: d.count ? 'var(--brand)' : 'var(--line)' },
          s('title', {}, d.date + ': ' + d.count + ' scan(s)')));
        if (i % 3 === 0) svg.appendChild(s('text', { x: i * bw + bw / 2, y: ht + 16, 'text-anchor': 'middle', 'font-size': 11, fill: 'var(--faint)' }, d.date.slice(5)));
      });
      return svg;
    },
    radar() {
      const svg = s('svg', { class: 'radar', viewBox: '0 0 200 200', 'aria-hidden': 'true' });
      const defs = s('defs', {}, s('radialGradient', { id: 'rg', cx: '50%', cy: '50%', r: '50%' },
        s('stop', { offset: '0', 'stop-color': '#22d3ee', 'stop-opacity': '0.0' }), s('stop', { offset: '1', 'stop-color': '#22d3ee', 'stop-opacity': '0.55' })));
      svg.appendChild(defs);
      [95, 70, 45, 20].forEach((r) => svg.appendChild(s('circle', { cx: 100, cy: 100, r, fill: 'none', stroke: 'var(--line-2)', 'stroke-width': 1 })));
      svg.appendChild(s('path', { d: 'M5 100H195M100 5V195', stroke: 'var(--line)', 'stroke-width': 1 }));
      svg.appendChild(s('g', { class: 'sweep' }, s('path', { d: 'M100 100 L100 5 A95 95 0 0 1 167 33 Z', fill: 'url(#rg)' }),
        s('path', { d: 'M100 100 L100 5', stroke: '#22d3ee', 'stroke-width': 2 })));
      [[140, 70], [62, 128], [128, 150]].forEach(([x, y]) => svg.appendChild(s('circle', { class: 'blip', cx: x, cy: y, r: 4, fill: 'var(--brand-2)' })));
      return svg;
    },
  };
})();
