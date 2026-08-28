'use strict';

function escHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ── State ─────────────────────────────────────────────────────────────── */
let allDevices      = [];   // full device list for current ADOM
let selectedVer     = null; // currently selected version filter (null = all)
let detailPage      = 1;
let detailSize      = 20;
let currentAdom     = '';
let globalDevices   = [];   // all-ADOMs device list for click-through
let globalSelVer    = null; // selected version in the global chart
let globalDetPage   = 1;
let globalDetSize   = 10;

/* ── Version sort helper ───────────────────────────────────────────────── */
function sortedVersionEntries(counts) {
  return Object.entries(counts).sort((a, b) => {
    if (a[0] === 'unknown') return 1;
    if (b[0] === 'unknown') return -1;
    return b[0].localeCompare(a[0], undefined, { numeric: true });
  });
}

/* ── Merge vX.Y into vX.Y.Z when only one patch exists for that minor ── */
function normalizeVersions(devices) {
  // Count how many distinct vX.Y.Z patches exist for each vX.Y prefix
  const patchesPerMinor = {};
  for (const d of devices) {
    const v = d.version || 'unknown';
    const full = v.match(/^v?(\d+\.\d+)\.(\d+)$/);
    if (full) {
      const minor = `v${full[1]}`;
      if (!patchesPerMinor[minor]) patchesPerMinor[minor] = new Set();
      patchesPerMinor[minor].add(v);
    }
  }
  // For each device whose version is vX.Y (no patch), if there's exactly one
  // known vX.Y.Z in this dataset, remap it to that patch version
  return devices.map(d => {
    const v = d.version || 'unknown';
    const shortMatch = v.match(/^v?(\d+\.\d+)$/);
    if (!shortMatch) return d;
    const minor = `v${shortMatch[1]}`;
    const patches = patchesPerMinor[minor];
    if (patches && patches.size === 1) {
      return { ...d, version: [...patches][0] };
    }
    return d;
  });
}

/* ── Build a version chart block (shared by global and per-ADOM) ────────── */
function buildVersionChart(devices, label, chartId) {
  const online  = devices.filter(d => d.status !== 'offline');
  const total   = online.length;
  const nOffline = devices.length - total;
  if (total === 0) return '';

  const counts = {};
  for (const d of online) {
    const v = d.version || 'unknown';
    counts[v] = (counts[v] || 0) + 1;
  }
  const sorted = sortedVersionEntries(counts);

  const chartRows = sorted.map(([ver, count]) => {
    const pct    = ((count / total) * 100).toFixed(1);
    const barPct = Math.round((count / total) * 100);
    return `
<div class="version-row" data-ver="${escHtml(ver)}" title="${escHtml(ver)}">
  <div class="version-name">${escHtml(ver)}</div>
  <div class="version-bar-wrap">
    <div class="version-bar" style="width:${barPct}%"></div>
  </div>
  <div class="version-count">${count} device${count !== 1 ? 's' : ''}</div>
  <div class="version-pct">${pct}%</div>
</div>`;
  }).join('');

  const offlineNote = nOffline > 0
    ? ` <span style="font-size:.8em;color:var(--text-muted)">(${nOffline} offline hidden)</span>`
    : '';

  return `
<div class="table-wrapper" style="padding:1.5rem;margin-bottom:1.5rem">
  <div class="version-summary">
    <span class="version-total">${total}</span>
    <span class="version-total-label">online device${total !== 1 ? 's' : ''} — <strong>${escHtml(label)}</strong>${offlineNote}</span>
  </div>
  <div class="version-chart" id="${escHtml(chartId)}">${chartRows}</div>
</div>`;
}

/* ── Global all-ADOM chart — served from cache ─────────────────────────── */
let _globalPollTimer = null;

function _fmtAge(isoStr) {
  if (!isoStr) return '';
  const diff = Math.round((Date.now() - new Date(isoStr).getTime()) / 1000);
  if (diff < 60)  return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function _renderCacheBar(status, lastUpdated, error) {
  const age     = lastUpdated ? `Last updated: ${_fmtAge(lastUpdated)}` : '';
  const spinner = status === 'running' || status === 'pending'
    ? '<span class="versions-cache-spinner">&#8635;</span> ' : '';
  const errNote = error ? `<span style="color:var(--status-red);margin-left:.5rem">${escHtml(error)}</span>` : '';
  return `<div class="versions-cache-bar">
    <span>${spinner}${escHtml(age)}</span>
    ${errNote}
    <button class="btn btn-xs" id="globalRefreshBtn" ${status === 'running' ? 'disabled' : ''}>&#8635; Refresh</button>
  </div>`;
}

async function loadGlobalVersions(forceRefresh) {
  const container = document.getElementById('globalVersionsContent');

  if (forceRefresh) {
    // Kick off a background refresh, then poll
    container.innerHTML = _renderCacheBar('running', null, null) +
      '<div class="loading-placeholder">Refreshing all devices…</div>';
    try { await fetch('/api/devices/all/refresh', { method: 'POST' }); } catch (_) {}
  }

  try {
    const resp = await fetch('/api/devices/all');
    if (resp.status === 401) { location.href = '/login'; return; }
    const payload = await resp.json();

    // Payload is now {devices, last_updated, status, error}
    const devices     = Array.isArray(payload.devices) ? payload.devices : (Array.isArray(payload) ? payload : []);
    const lastUpdated = payload.last_updated || null;
    const status      = payload.status       || 'ok';
    const error       = payload.error        || null;

    // Cache is still warming — show a spinner and poll every 3 s
    if (status === 'running' || status === 'pending') {
      container.innerHTML = _renderCacheBar(status, lastUpdated, error) +
        '<div class="loading-placeholder">Building version index… this may take a minute.</div>';
      _wireRefreshBtn();
      clearTimeout(_globalPollTimer);
      _globalPollTimer = setTimeout(() => loadGlobalVersions(false), 3000);
      return;
    }

    // Cache ready — render
    clearTimeout(_globalPollTimer);
    if (!devices.length) {
      container.innerHTML = _renderCacheBar(status, lastUpdated, error);
      _wireRefreshBtn();
      return;
    }
    globalDevices = normalizeVersions(devices);
    globalSelVer  = null;
    document.getElementById('globalVersionDetail').style.display = 'none';
    container.innerHTML =
      _renderCacheBar(status, lastUpdated, error) +
      buildVersionChart(globalDevices, 'All ADOMs', 'globalVersionChart');
    _wireRefreshBtn();
    _wireGlobalChart();

  } catch (_) {
    container.innerHTML = '<div class="loading-placeholder">Could not load version data.</div>';
  }
}

/* ── Global chart click → show version detail panel ────────────────────── */
function _wireGlobalChart() {
  const chart = document.getElementById('globalVersionChart');
  if (!chart) return;
  chart.addEventListener('click', e => {
    const row = e.target.closest('[data-ver]');
    if (!row) return;
    const ver = row.dataset.ver;
    if (globalSelVer === ver) {
      globalSelVer = null;
      _clearGlobalDetail();
      _refreshGlobalChartActive();
      return;
    }
    globalSelVer  = ver;
    globalDetPage = 1;
    _refreshGlobalChartActive();
    _renderGlobalDetail(ver);
  });
}

function _refreshGlobalChartActive() {
  document.querySelectorAll('#globalVersionChart .version-row').forEach(r => {
    r.classList.toggle('ver-row-active', r.dataset.ver === globalSelVer);
  });
}

function _clearGlobalDetail() {
  const panel = document.getElementById('globalVersionDetail');
  panel.style.display = 'none';
  panel.innerHTML = '';
}

function _renderGlobalDetail(ver) {
  const matched   = globalDevices.filter(d => (d.version || 'unknown') === ver && d.status !== 'offline');
  const panel     = document.getElementById('globalVersionDetail');
  const pageTotal = Math.ceil(matched.length / globalDetSize) || 1;
  globalDetPage   = Math.min(globalDetPage, pageTotal);
  const slice     = matched.slice((globalDetPage - 1) * globalDetSize, globalDetPage * globalDetSize);

  const tableRows = slice.map(d => `
<tr>
  <td>${escHtml(d.name)}</td>
  <td><code>${escHtml(d.ip)}</code></td>
  <td>${escHtml(d.platform)}</td>
  <td>${escHtml(d.adom || '—')}</td>
  <td>${escHtml(d.serial)}</td>
</tr>`).join('');

  const sizeOpts = [10, 25, 50].map(n =>
    `<option value="${n}" ${globalDetSize === n ? 'selected' : ''}>${n}</option>`).join('');

  panel.style.display = '';
  panel.innerHTML = `
<div class="table-wrapper" style="padding:1.5rem;margin-bottom:1.5rem">
  <div class="table-controls" style="margin-bottom:.75rem">
    <span style="font-weight:600">${escHtml(ver)} &mdash; ${matched.length} device${matched.length !== 1 ? 's' : ''} across all ADOMs &mdash; page ${globalDetPage} of ${pageTotal}</span>
    <div class="table-controls-right">
      <select id="globalDetSize" class="form-select-sm">${sizeOpts}</select>
      <span>per page</span>
      <button class="btn btn-sm" id="gdExportCsv"  style="background:var(--surface-alt);border:1px solid var(--border);color:var(--text)">&#8681; CSV</button>
      <button class="btn btn-sm" id="gdExportJson" style="background:var(--surface-alt);border:1px solid var(--border);color:var(--text)">&#8681; JSON</button>
      <button class="btn btn-sm" id="gdExportPdf"  style="background:var(--surface-alt);border:1px solid var(--border);color:var(--text)">&#8681; PDF</button>
      <button class="btn btn-sm btn-ghost" id="globalDetailCloseBtn">&#10005; Close</button>
    </div>
  </div>
  <table class="data-table">
    <thead><tr><th>Name</th><th>IP</th><th>Platform</th><th>ADOM</th><th>Serial</th></tr></thead>
    <tbody>${tableRows || '<tr><td colspan="5" class="empty-state" style="padding:.75rem 1rem">No devices.</td></tr>'}</tbody>
  </table>
  ${_gdPagination(globalDetPage, pageTotal)}
</div>`;

  document.getElementById('globalDetailCloseBtn').addEventListener('click', () => {
    globalSelVer  = null;
    globalDetPage = 1;
    _clearGlobalDetail();
    _refreshGlobalChartActive();
  });

  document.getElementById('globalDetSize').addEventListener('change', function () {
    globalDetSize = parseInt(this.value, 10);
    globalDetPage = 1;
    _renderGlobalDetail(ver);
  });

  panel.querySelectorAll('[data-gdpage]').forEach(btn => {
    btn.addEventListener('click', function () {
      if (this.disabled) return;
      globalDetPage = parseInt(this.dataset.gdpage, 10);
      _renderGlobalDetail(ver);
    });
  });

  document.getElementById('gdExportCsv').addEventListener('click',  () => _gdExport('csv',  ver, matched));
  document.getElementById('gdExportJson').addEventListener('click', () => _gdExport('json', ver, matched));
  document.getElementById('gdExportPdf').addEventListener('click',  () => _gdExportPdf(ver, matched));
}

function _gdPagination(current, total) {
  if (total <= 1) return '';
  function btn(label, page, disabled, active) {
    return `<button class="pg-btn${active ? ' active' : ''}" data-gdpage="${page}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  }
  let h = btn('&laquo;&laquo;', 1, current === 1, false);
  h    += btn('&lsaquo;', current - 1, current === 1, false);
  const s = Math.max(1, current - 2), e = Math.min(total, s + 4);
  for (let i = s; i <= e; i++) h += btn(i, i, false, i === current);
  h += btn('&rsaquo;', current + 1, current === total, false);
  h += btn('&raquo;&raquo;', total, current === total, false);
  return `<div class="pagination">${h}</div>`;
}

function _gdExport(format, ver, matched) {
  const ts       = new Date().toISOString().slice(0, 10);
  const filename = `versions_all_${ver}_${ts}`.replace(/[^a-zA-Z0-9._-]/g, '_');
  let content, mime, ext;
  if (format === 'csv') {
    const header = 'Name,IP,Platform,ADOM,Version,Serial\n';
    const rows   = matched.map(d =>
      [d.name, d.ip, d.platform, d.adom || '', d.version || 'unknown', d.serial]
        .map(v => `"${String(v ?? '').replace(/"/g, '""')}"`)
        .join(',')
    ).join('\n');
    content = header + rows; mime = 'text/csv'; ext = 'csv';
  } else {
    content = JSON.stringify(matched, null, 2); mime = 'application/json'; ext = 'json';
  }
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = `${filename}.${ext}`; a.click();
  URL.revokeObjectURL(url);
}

function _gdExportPdf(ver, matched) {
  const ts    = new Date().toLocaleString();
  const title = `Device Versions — ${ver}`;
  const esc   = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const tableRows = matched.map(d => `
    <tr>
      <td>${esc(d.name)}</td>
      <td>${esc(d.ip)}</td>
      <td>${esc(d.platform)}</td>
      <td>${esc(d.adom || '—')}</td>
      <td>${esc(d.serial)}</td>
    </tr>`).join('');

  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>${esc(title)}</title>
<style>
  body{font-family:sans-serif;font-size:11px;color:#1a2133;margin:1.5cm}
  h1{font-size:16px;margin-bottom:4px}
  .meta{font-size:10px;color:#5a6478;margin-bottom:12px}
  table{width:100%;border-collapse:collapse}
  th{background:#eef1f5;text-align:left;padding:5px 8px;font-size:10px;text-transform:uppercase;border-bottom:2px solid #d0d7e2}
  td{padding:4px 8px;border-bottom:1px solid #d0d7e2;vertical-align:top}
  @media print{body{margin:1cm}}
</style></head><body>
<h1>${esc(title)}</h1>
<div class="meta">Generated ${ts} &bull; ${matched.length} device${matched.length !== 1 ? 's' : ''} across all ADOMs</div>
<table>
  <thead><tr><th>Name</th><th>IP</th><th>Platform</th><th>ADOM</th><th>Serial</th></tr></thead>
  <tbody>${tableRows}</tbody>
</table>
</body></html>`;

  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); win.focus(); win.print(); }
}

function _wireRefreshBtn() {
  const btn = document.getElementById('globalRefreshBtn');
  if (btn) btn.addEventListener('click', () => loadGlobalVersions(true));
}

/* ── ADOM loader ───────────────────────────────────────────────────────── */
async function loadAdoms() {
  const sel = document.getElementById('adomSelect');
  try {
    const resp = await fetch('/api/adoms');
    if (resp.status === 401) { location.href = '/login'; return; }
    const adoms = await resp.json();
    if (!Array.isArray(adoms)) return;
    adoms.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a.name; opt.textContent = a.name;
      sel.appendChild(opt);
    });
  } catch (_) {}
}

/* ── Per-ADOM loader ───────────────────────────────────────────────────── */
async function loadVersions(adom) {
  currentAdom = adom;
  selectedVer = null;
  detailPage  = 1;

  document.getElementById('adomCloseBtn').style.display = '';

  const container = document.getElementById('versionsContent');
  container.innerHTML = '<div class="loading-placeholder">Loading devices…</div>';
  try {
    const resp = await fetch(`/api/adoms/${encodeURIComponent(adom)}/devices`);
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    if (!Array.isArray(data)) {
      container.innerHTML = `<div class="alert alert-danger">${escHtml(JSON.stringify(data))}</div>`;
      return;
    }
    if (data.length === 0) {
      container.innerHTML = '<p class="empty-state">No devices found in this ADOM.</p>';
      return;
    }
    allDevices = normalizeVersions(data);
    renderPage();
  } catch (err) {
    container.innerHTML = `<div class="alert alert-danger">Failed: ${escHtml(err.message)}</div>`;
  }
}

/* ── Pagination helper ─────────────────────────────────────────────────── */
function pgBtn(label, page, disabled, active) {
  return `<button class="pg-btn${active ? ' active' : ''}" data-dpage="${page}" ${disabled ? 'disabled' : ''}>${label}</button>`;
}

function renderPagination(current, total) {
  if (total <= 1) return '';
  let h = pgBtn('&laquo;&laquo;', 1, current === 1, false);
  h    += pgBtn('&lsaquo;', current - 1, current === 1, false);
  const s = Math.max(1, current - 2), e = Math.min(total, s + 4);
  for (let i = s; i <= e; i++) h += pgBtn(i, i, false, i === current);
  h += pgBtn('&rsaquo;', current + 1, current === total, false);
  h += pgBtn('&raquo;&raquo;', total, current === total, false);
  return `<div class="pagination">${h}</div>`;
}

/* ── Per-ADOM full page render ─────────────────────────────────────────── */
function renderPage() {
  const container  = document.getElementById('versionsContent');
  const online     = allDevices.filter(d => d.status !== 'offline');
  const nOffline   = allDevices.length - online.length;
  const chartTotal = online.length;

  // Tally versions — online only for chart
  const counts = {};
  for (const d of online) {
    const v = d.version || 'unknown';
    counts[v] = (counts[v] || 0) + 1;
  }
  const sorted = sortedVersionEntries(counts);

  // Chart rows
  const chartRows = sorted.map(([ver, count]) => {
    const pct    = ((count / chartTotal) * 100).toFixed(1);
    const barPct = Math.round((count / chartTotal) * 100);
    const active = selectedVer === ver ? ' ver-row-active' : '';
    return `
<div class="version-row${active}" data-ver="${escHtml(ver)}" title="Click to filter devices by ${escHtml(ver)}">
  <div class="version-name">${escHtml(ver)}</div>
  <div class="version-bar-wrap">
    <div class="version-bar" style="width:${barPct}%"></div>
  </div>
  <div class="version-count">${count} device${count !== 1 ? 's' : ''}</div>
  <div class="version-pct">${pct}%</div>
</div>`;
  }).join('');

  const offlineNote = nOffline > 0
    ? ` <span style="font-size:.8em;color:var(--text-muted)">(${nOffline} offline hidden)</span>`
    : '';

  // Detail table shows all devices (online + offline); version filter applies to both
  const filtered  = selectedVer
    ? allDevices.filter(d => (d.version || 'unknown') === selectedVer)
    : allDevices;
  const pageTotal = Math.ceil(filtered.length / detailSize) || 1;
  detailPage      = Math.min(detailPage, pageTotal);
  const slice     = filtered.slice((detailPage - 1) * detailSize, detailPage * detailSize);

  const filterLabel = selectedVer
    ? `${escHtml(selectedVer)} — ${filtered.length} device${filtered.length !== 1 ? 's' : ''}`
    : `All versions — ${allDevices.length} device${allDevices.length !== 1 ? 's' : ''}`;

  const offlineBadge = `<span style="display:inline-block;font-size:.7em;padding:1px 5px;border-radius:3px;background:#fee2e2;color:#991b1b;font-weight:600;vertical-align:middle;margin-left:4px">OFFLINE</span>`;

  const tableRows = slice.map(d => {
    const isOffline = d.status === 'offline';
    return `
<tr${isOffline ? ' style="opacity:0.6"' : ''}>
  <td>${escHtml(d.name)}${isOffline ? offlineBadge : ''}</td>
  <td><code>${escHtml(d.ip)}</code></td>
  <td>${escHtml(d.platform)}</td>
  <td>${escHtml(d.version || 'unknown')}</td>
  <td>${escHtml(d.serial)}</td>
</tr>`;
  }).join('');

  const sizeOpts = [10, 20, 50].map(n =>
    `<option value="${n}" ${detailSize === n ? 'selected' : ''}>${n}</option>`).join('');

  container.innerHTML = `
<div class="table-wrapper" style="padding:1.5rem;margin-bottom:1.5rem">
  <div class="version-summary">
    <span class="version-total">${chartTotal}</span>
    <span class="version-total-label">online device${chartTotal !== 1 ? 's' : ''} in <strong>${escHtml(currentAdom)}</strong>${offlineNote}</span>
    ${selectedVer ? `<button class="btn btn-sm" id="clearFilter" style="margin-left:1rem;background:var(--surface-alt);border:1px solid var(--border);color:var(--text)">&#10005; Clear filter</button>` : ''}
  </div>
  <div class="version-chart" id="versionChart">${chartRows}</div>
  <p class="version-click-hint">Click a version bar to filter the device list below.</p>
</div>

<div class="table-wrapper">
  <div class="table-controls">
    <span>${filterLabel} &mdash; page ${detailPage} of ${pageTotal}</span>
    <div class="table-controls-right">
      <select id="detailSize" class="form-select-sm">${sizeOpts}</select>
      <span>per page</span>
      <button class="btn btn-sm" id="exportCsv" style="background:var(--surface-alt);border:1px solid var(--border);color:var(--text)">&#8681; CSV</button>
      <button class="btn btn-sm" id="exportJson" style="background:var(--surface-alt);border:1px solid var(--border);color:var(--text)">&#8681; JSON</button>
    </div>
  </div>
  <table class="data-table">
    <thead><tr><th>Name</th><th>IP</th><th>Platform</th><th>Version</th><th>Serial</th></tr></thead>
    <tbody>${tableRows || '<tr><td colspan="5" class="empty-state" style="padding:.75rem 1rem">No devices match.</td></tr>'}</tbody>
  </table>
  ${renderPagination(detailPage, pageTotal)}
</div>`;

  // ── Wire events ─────────────────────────────────────────────────────────

  // Version bar click — select/deselect
  document.getElementById('versionChart').addEventListener('click', e => {
    const row = e.target.closest('[data-ver]');
    if (!row) return;
    const ver = row.dataset.ver;
    selectedVer = selectedVer === ver ? null : ver;
    detailPage  = 1;
    renderPage();
  });

  // Clear filter button
  const clearBtn = document.getElementById('clearFilter');
  if (clearBtn) clearBtn.addEventListener('click', () => {
    selectedVer = null; detailPage = 1; renderPage();
  });

  // Page size
  document.getElementById('detailSize').addEventListener('change', function () {
    detailSize = parseInt(this.value, 10);
    detailPage = 1;
    renderPage();
  });

  // Pagination
  container.querySelectorAll('[data-dpage]').forEach(btn => {
    btn.addEventListener('click', function () {
      if (this.disabled) return;
      detailPage = parseInt(this.dataset.dpage, 10);
      renderPage();
    });
  });

  // Export CSV
  document.getElementById('exportCsv').addEventListener('click', () => exportData('csv', filtered));

  // Export JSON
  document.getElementById('exportJson').addEventListener('click', () => exportData('json', filtered));
}

/* ── Export ────────────────────────────────────────────────────────────── */
function exportData(format, devices) {
  const adom = currentAdom;
  const ver  = selectedVer || 'all';
  const ts   = new Date().toISOString().slice(0, 10);
  const filename = `versions_${adom}_${ver}_${ts}`.replace(/[^a-zA-Z0-9._-]/g, '_');

  let content, mime, ext;
  if (format === 'csv') {
    const header = 'Name,IP,Platform,Version,Serial,ADOM\n';
    const rows   = devices.map(d =>
      [d.name, d.ip, d.platform, d.version || 'unknown', d.serial, d.adom]
        .map(v => `"${String(v ?? '').replace(/"/g, '""')}"`)
        .join(',')
    ).join('\n');
    content = header + rows;
    mime    = 'text/csv';
    ext     = 'csv';
  } else {
    content = JSON.stringify(devices, null, 2);
    mime    = 'application/json';
    ext     = 'json';
  }

  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `${filename}.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

/* ── Event wiring ──────────────────────────────────────────────────────── */
document.getElementById('adomSelect').addEventListener('change', function () {
  if (this.value) loadVersions(this.value);
  else {
    allDevices = []; selectedVer = null;
    document.getElementById('versionsContent').innerHTML = '';
    document.getElementById('adomCloseBtn').style.display = 'none';
  }
});

document.getElementById('adomCloseBtn').addEventListener('click', () => {
  allDevices = []; selectedVer = null; currentAdom = '';
  document.getElementById('adomSelect').value = '';
  document.getElementById('versionsContent').innerHTML = '';
  document.getElementById('adomCloseBtn').style.display = 'none';
});

document.getElementById('refreshBtn').addEventListener('click', () => {
  // The per-ADOM refresh is a live query; global uses the cache refresh path
  loadGlobalVersions(true);
  const adom = document.getElementById('adomSelect').value;
  if (adom) loadVersions(adom);
});

loadAdoms();
loadGlobalVersions(false);
