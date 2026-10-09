'use strict';

let refreshTimer   = null;
let summaryPoller  = null;

// ── Summary bar ──────────────────────────────────────────────────────────────

function fmtNumber(n) {
  if (n === null || n === undefined) return '—';
  return Number(n).toLocaleString();
}

function renderSummary(d) {
  const fwTotal     = document.getElementById('statFwTotal');
  const rulesTotal  = document.getElementById('statRulesTotal');
  const meta        = document.getElementById('summaryMeta');
  const fwBreakdown = document.getElementById('statFwBreakdown');

  if (d.status === 'pending' || d.status === 'running') {
    // Keep spinners — already in HTML
    return;
  }

  if (d.status === 'error') {
    fwTotal.textContent    = '—';
    rulesTotal.textContent = '—';
    meta.textContent       = 'Summary unavailable';
    if (fwBreakdown) fwBreakdown.textContent = '';
    return;
  }

  // Totals
  fwTotal.textContent    = fmtNumber(d.firewalls_total);
  rulesTotal.textContent = fmtNumber(d.rules_total);

  // HA / standalone breakdown (absent on snapshots from before this field existed)
  if (fwBreakdown) {
    if (d.ha_clusters != null && d.standalones != null) {
      const clusterWord = d.ha_clusters === 1 ? 'cluster' : 'clusters';
      const haMembers = d.ha_clusters * 2;
      fwBreakdown.textContent = `${d.ha_clusters} HA ${clusterWord} (${haMembers} members) · ${d.standalones} standalone`;
    } else {
      fwBreakdown.textContent = '';
    }
  }

  // Footer meta
  if (d.last_updated) {
    const ts = new Date(d.last_updated);
    meta.textContent = 'Counts as of ' + ts.toLocaleString();
  }

  renderAdomSummary(d.adom_breakdown || []);
}

function renderAdomSummary(breakdown) {
  const card = document.getElementById('adomSummaryCard');
  const grid = document.getElementById('adomSummaryGrid');
  if (!card || !grid) return;
  if (!breakdown || !breakdown.length) { card.style.display = 'none'; return; }
  card.style.display = '';
  grid.innerHTML = breakdown.map(d => `
    <div class="adom-tile">
      <div class="adom-tile-name">${escHtml(d.name)}</div>
      <div class="adom-tile-stat">${d.fw_count} firewall${d.fw_count !== 1 ? 's' : ''}</div>
      <div class="adom-tile-stat">${Number(d.rule_count).toLocaleString()} rules</div>
    </div>`).join('');
}

function startSummaryPoller(onDone) {
  if (summaryPoller) return;
  summaryPoller = setInterval(async () => {
    try {
      const r = await fetch('/api/summary');
      if (r.status === 401) { clearInterval(summaryPoller); summaryPoller = null; return; }
      const d = await r.json();
      renderSummary(d);
      if (d.status !== 'pending' && d.status !== 'running') {
        clearInterval(summaryPoller);
        summaryPoller = null;
        if (onDone) onDone(d);
      }
    } catch (_) {}
  }, 5000);
}

async function loadSummary() {
  try {
    const resp = await fetch('/api/summary');
    if (resp.status === 401) return;
    const d = await resp.json();
    renderSummary(d);
    if (d.status === 'pending' || d.status === 'running') startSummaryPoller(loadTrendCharts);
  } catch (_) {}
}

(function () {
  const btn  = document.getElementById('summaryRefreshBtn');
  const meta = document.getElementById('summaryMeta');
  if (!btn) return;
  btn.addEventListener('click', async function () {
    btn.disabled = true;
    const prev = meta.textContent;
    meta.textContent = 'Recalculating…';
    try {
      const resp = await fetch('/api/summary/refresh', { method: 'POST' });
      if (!resp.ok) throw new Error('request failed');
      // Stop any existing poller so ours takes over
      clearInterval(summaryPoller);
      summaryPoller = null;
      startSummaryPoller(function () {
        btn.disabled = false;
        loadTrendCharts();
      });
    } catch (_) {
      meta.textContent = prev;
      btn.disabled = false;
    }
  });
}());


function renderCard(d) {
  const statusClass = `status-${d.status || 'unknown'}`;

  const diskRow = d.disk_used && d.disk_used !== 'n/a'
    ? `<div class="card-row"><span class="card-row-label">Disk</span><span class="card-row-value">${escHtml(d.disk_used)}</span></div>`
    : '';

  let cpuMemRow;
  if (d.snmp_status && d.snmp_status !== 'ok') {
    const label = d.snmp_status === 'timeout' ? 'SNMP timeout'
      : d.snmp_status === 'disabled' ? 'SNMP disabled'
      : 'SNMP unreachable';
    cpuMemRow = `<div class="card-row"><span class="card-row-label">CPU / Mem</span><span class="card-row-value text-muted">${escHtml(label)}</span></div>`;
  } else if (d.cpu !== null && d.cpu !== undefined && d.mem !== null && d.mem !== undefined) {
    cpuMemRow = `<div class="card-row"><span class="card-row-label">CPU / Mem</span><span class="card-row-value">${d.cpu}% / ${d.mem}%</span></div>`;
  } else {
    cpuMemRow = '';
  }

  const errorRow = d.error
    ? `<div class="card-row card-row-error"><span class="card-row-value text-danger">${escHtml(d.error)}</span></div>`
    : '';

  return `
<div class="infra-card ${statusClass}">
  <div class="infra-card-stripe"></div>
  <div class="infra-card-body">
    <div class="card-name-block">
      <div class="card-title">${escHtml(d.label)}</div>
      <div class="card-subtitle">${escHtml(d.host)} &bull; ${escHtml(d.type)}</div>
    </div>
    <div class="card-detail-block">
      <div class="card-col card-col-hostname">
        <div class="card-row"><span class="card-row-label">Hostname</span><span class="card-row-value">${escHtml(d.hostname)}</span></div>
      </div>
      <div class="card-col card-col-meta">
        <div class="card-row"><span class="card-row-label">Version</span><span class="card-row-value">${escHtml(d.version)}</span></div>
        <div class="card-row"><span class="card-row-label">Serial</span><span class="card-row-value">${escHtml(d.serial)}</span></div>
        <div class="card-row"><span class="card-row-label">HA Mode / Role</span><span class="card-row-value">${escHtml(d.ha_mode)} / ${escHtml(d.ha_role)}</span></div>
        ${cpuMemRow}
        ${diskRow}
      </div>
      ${errorRow}
    </div>
  </div>
</div>`;
}

function escHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function loadInfrastructure() {
  const grid = document.getElementById('infraGrid');
  grid.innerHTML = '<div class="loading-placeholder">Contacting FortiManager…</div>';
  try {
    const resp = await fetch('/api/infrastructure');
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    if (!Array.isArray(data)) {
      grid.innerHTML = `<div class="alert alert-danger">Error: ${escHtml(JSON.stringify(data))}</div>`;
      return;
    }
    grid.innerHTML = data.map(renderCard).join('');
    document.getElementById('lastUpdated').textContent = 'Updated ' + new Date().toLocaleTimeString();
  } catch (err) {
    grid.innerHTML = `<div class="alert alert-danger">Failed to load: ${escHtml(err.message)}</div>`;
  }
}

function scheduleRefresh(seconds) {
  clearInterval(refreshTimer);
  if (seconds > 0) refreshTimer = setInterval(loadInfrastructure, seconds * 1000);
}

document.getElementById('refreshBtn').addEventListener('click', loadInfrastructure);
document.getElementById('autoRefresh').addEventListener('change', function () {
  scheduleRefresh(parseInt(this.value, 10));
});

// ── 30-day trend charts ──────────────────────────────────────────────────────

// Shared tooltip element, created once
const _trendTooltip = (() => {
  const el = document.createElement('div');
  el.className = 'trend-tooltip';
  document.body.appendChild(el);
  return el;
})();

function _showTrendTooltip(evt, text) {
  _trendTooltip.textContent = text;
  _trendTooltip.style.display = 'block';
  _positionTrendTooltip(evt);
}

function _positionTrendTooltip(evt) {
  const gap = 12;
  const tw = _trendTooltip.offsetWidth;
  const th = _trendTooltip.offsetHeight;
  let x = evt.clientX + gap;
  let y = evt.clientY - th - gap;
  if (x + tw > window.innerWidth) x = evt.clientX - tw - gap;
  if (y < 0) y = evt.clientY + gap;
  _trendTooltip.style.left = x + 'px';
  _trendTooltip.style.top  = y + 'px';
}

function _hideTrendTooltip() {
  _trendTooltip.style.display = 'none';
}

function renderTrendChart(svgEl, axisEl, points, valueKey) {
  if (!points || points.length < 1) return;

  const W = 520, H = 80, padL = 0, padR = 0, padT = 8, padB = 4;
  const vals = points.map(p => p[valueKey]);
  const minV = Math.min(...vals);
  const maxV = Math.max(...vals);
  const range = maxV - minV || 1;

  // With a single point, pin it to the center-bottom of the plot area
  const xOf = i => points.length === 1 ? W / 2 : padL + (i / (points.length - 1)) * (W - padL - padR);
  const yOf = v => points.length === 1 ? (H - padB) / 2 : padT + (1 - (v - minV) / range) * (H - padT - padB);

  const ptsStr = points.map((p, i) => `${xOf(i).toFixed(1)},${yOf(p[valueKey]).toFixed(1)}`).join(' ');
  const areaBase = H - padB;
  const coordPairs = ptsStr.split(' ');
  const first = coordPairs[0];
  const last  = coordPairs.slice(-1)[0];

  const lineAndArea = points.length >= 2 ? `
    <polygon points="${first.split(',')[0]},${areaBase} ${ptsStr} ${last.split(',')[0]},${areaBase}"
             fill="url(#tg_${svgEl.id})"/>
    <polyline points="${ptsStr}" fill="none" stroke="var(--accent)" stroke-width="2"
              stroke-linejoin="round" stroke-linecap="round"/>` : '';

  svgEl.setAttribute('viewBox', `0 0 ${W} ${H}`);
  svgEl.innerHTML = `
    <defs>
      <linearGradient id="tg_${svgEl.id}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%"   stop-color="var(--accent)" stop-opacity=".25"/>
        <stop offset="100%" stop-color="var(--accent)" stop-opacity="0"/>
      </linearGradient>
    </defs>
    ${lineAndArea}
    ${points.map((p, i) => `<circle cx="${xOf(i).toFixed(1)}" cy="${yOf(p[valueKey]).toFixed(1)}" r="3.5"
      fill="var(--accent)" style="cursor:crosshair" data-label="${p.date}: ${p[valueKey].toLocaleString()}"></circle>`).join('')}
  `;

  // Attach hover events to each circle
  svgEl.querySelectorAll('circle[data-label]').forEach(c => {
    c.addEventListener('mouseenter', evt => _showTrendTooltip(evt, c.dataset.label));
    c.addEventListener('mousemove',  evt => _positionTrendTooltip(evt));
    c.addEventListener('mouseleave', _hideTrendTooltip);
  });

  // X-axis labels — show first, middle (if >2 pts), last
  const indices = points.length === 1
    ? [0]
    : [0, ...(points.length > 2 ? [Math.floor((points.length - 1) / 2)] : []), points.length - 1];
  axisEl.innerHTML = indices.map(i => {
    const pct = points.length === 1 ? '50%' : ((i / (points.length - 1)) * 100).toFixed(1) + '%';
    return `<span style="position:absolute;left:${pct};transform:translateX(-50%)">${points[i].date.slice(5)}</span>`;
  }).join('');
}

async function loadTrendCharts() {
  try {
    const resp = await fetch('/api/summary/history');
    if (!resp.ok) return;
    const data = await resp.json();
    if (!Array.isArray(data) || data.length < 1) return;

    const container = document.getElementById('trendCharts');
    container.style.display = '';
    renderTrendChart(
      document.getElementById('trendFwSvg'),
      document.getElementById('trendFwAxisX'),
      data, 'firewalls'
    );
    renderTrendChart(
      document.getElementById('trendRulesSvg'),
      document.getElementById('trendRulesAxisX'),
      data, 'rules'
    );
  } catch (_) { /* ignore */ }
}

loadSummary();
loadTrendCharts();
loadInfrastructure();
scheduleRefresh(parseInt(document.getElementById('autoRefresh').value, 10));
