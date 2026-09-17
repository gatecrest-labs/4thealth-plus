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

/* ── License state ─────────────────────────────────────────────────────── */
let licenseDevices   = [];
let licenseSelStatus = null;
let licenseSelExpiry = null;   // 'within30' | 'within90' | 'beyond90' | null
let licenseDetPage   = 1;
let licenseDetSize   = 20;

/* ── FortiGuard subscription state ──────────────────────────────────── */
let fgDevices   = [];
let fgSelSub    = null;
let fgSelStatus = null;
let fgDetPage   = 1;
let fgDetSize   = 20;

const FG_KEYS = [
  'antivirus', 'ips', 'web_filtering', 'appctrl',
  'antispam', 'outbreak_prevention', 'firmware_updates', 'forticloud_sandbox',
  'ai_malware_detection', 'blacklisted_certificates',
];
const FG_LABELS = {
  antivirus:                'Antivirus (AV)',
  ips:                      'IPS / NIDS',
  web_filtering:            'Web Filtering',
  appctrl:                  'App Control',
  antispam:                 'Anti-Spam',
  outbreak_prevention:      'Outbreak Prevention',
  firmware_updates:         'Firmware Updates',
  forticloud_sandbox:       'FortiCloud Sandbox',
  ai_malware_detection:     'AI Malware Detection',
  blacklisted_certificates: 'Blocklisted Certificates',
};
const FG_STATUS_DISPLAY = { licensed: 'Licensed', expired: 'Expired', none: 'No License', unknown: 'Unknown' };

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
  loadLicenseStatus(adom);
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

/* ── License donut chart ───────────────────────────────────────────────── */
function buildDonutSVG(licensed, expired, offline, unregistered, unknown) {
  const total = licensed + expired + offline + unregistered + unknown;
  if (total === 0) return '<p class="text-muted">No data</p>';

  const r = 54;
  const cx = 70;
  const cy = 70;
  const circumference = 2 * Math.PI * r;

  const counts  = [licensed, expired, offline, unregistered, unknown];
  const colours = ['#28a745', '#dc3545', '#374151', '#94a3b8', '#ffc107'];
  const labels  = ['Licensed', 'Expired', 'Offline', 'Not Registered', 'Unknown'];
  const keys    = ['licensed', 'expired', 'offline', 'unregistered', 'unknown'];

  let offset = 0;
  const arcs = counts.map((c, i) => {
    const dash   = ((c / total) * circumference).toFixed(2);
    const gap    = (circumference - dash).toFixed(2);
    const rotate = ((offset / total) * 360).toFixed(2);
    offset += c;
    return `<circle
      cx="${cx}" cy="${cy}" r="${r}"
      fill="none"
      stroke="${colours[i]}"
      stroke-width="18"
      stroke-dasharray="${dash} ${gap}"
      transform="rotate(${rotate - 90} ${cx} ${cy})"
      data-status="${keys[i]}"
      style="cursor:pointer"
      title="${labels[i]}: ${c}"
    />`;
  }).join('');

  const legendItems = counts.map((c, i) =>
    `<span class="lic-legend-item" data-status="${keys[i]}" style="cursor:pointer">
       <span class="lic-dot" style="background:${colours[i]}"></span>
       ${escHtml(labels[i])} <strong>${c}</strong>
     </span>`
  ).join('');

  return `
<div class="lic-donut-wrap">
  <svg width="140" height="140" viewBox="0 0 140 140" aria-hidden="true">
    ${arcs}
    <text x="${cx}" y="${cy + 6}" text-anchor="middle" font-size="16" font-weight="bold" fill="currentColor">${total}</text>
  </svg>
  <div class="lic-legend">${legendItems}</div>
</div>`;
}

/* ── Expiring-soon donut (licensed devices, three expiry brackets) ────────── */
function buildExpiryDonutSVG(within30, within90, beyond90) {
  const total = within30 + within90 + beyond90;
  if (total === 0) return '<p style="font-size:.85em;color:var(--text-muted)">No expiry data</p>';

  const r = 54, cx = 70, cy = 70;
  const circumference = 2 * Math.PI * r;

  const counts  = [within30, within90, beyond90];
  const colours = ['#dc3545', '#fd7e14', '#28a745'];
  const labels  = ['≤30 days', '31–90 days', '>90 days'];
  const keys    = ['within30', 'within90', 'beyond90'];

  let offset = 0;
  const arcs = counts.map((c, i) => {
    const dash   = ((c / total) * circumference).toFixed(2);
    const gap    = (circumference - dash).toFixed(2);
    const rotate = ((offset / total) * 360).toFixed(2);
    offset += c;
    return `<circle
      cx="${cx}" cy="${cy}" r="${r}"
      fill="none"
      stroke="${colours[i]}"
      stroke-width="18"
      stroke-dasharray="${dash} ${gap}"
      transform="rotate(${rotate - 90} ${cx} ${cy})"
      data-status="${keys[i]}"
      style="cursor:pointer"
      title="${labels[i]}: ${c}"
    />`;
  }).join('');

  const legendItems = counts.map((c, i) =>
    `<span class="lic-legend-item" data-status="${keys[i]}" style="cursor:pointer">
       <span class="lic-dot" style="background:${colours[i]}"></span>
       ${escHtml(labels[i])} <strong>${c}</strong>
     </span>`
  ).join('');

  return `
<div class="lic-donut-wrap">
  <svg width="140" height="140" viewBox="0 0 140 140" aria-hidden="true">
    ${arcs}
    <text x="${cx}" y="${cy + 6}" text-anchor="middle" font-size="16" font-weight="bold" fill="currentColor">${total}</text>
  </svg>
  <div class="lic-legend">${legendItems}</div>
</div>`;
}

/* ── FortiGuard mini-donut (per-subscription card) ───────────────────────── */
function buildMiniDonutSVG(licensed, expired, noLicense, subKey) {
  const total = licensed + expired + noLicense;
  const r = 36, cx = 45, cy = 45;
  const circ = 2 * Math.PI * r;
  const counts   = [licensed, expired, noLicense];
  const colours  = ['#28a745', '#dc3545', '#6c757d'];
  const statuses = ['licensed', 'expired', 'none'];

  let offset = 0;
  const arcs = total === 0
    ? `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--border)" stroke-width="11"/>`
    : counts.map((c, i) => {
        if (c === 0) { offset += c; return ''; }
        const dash   = ((c / total) * circ).toFixed(2);
        const gap    = (circ - dash).toFixed(2);
        const rotate = ((offset / total) * 360).toFixed(2);
        offset += c;
        return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${colours[i]}" stroke-width="11"
          stroke-dasharray="${dash} ${gap}" transform="rotate(${rotate - 90} ${cx} ${cy})"
          data-subkey="${subKey}" data-status="${statuses[i]}" style="cursor:pointer"/>`;
      }).join('');

  const legend = counts.map((c, i) =>
    `<span class="lic-legend-item" data-subkey="${subKey}" data-status="${statuses[i]}" style="font-size:.82em;cursor:pointer">
       <span class="lic-dot" style="background:${colours[i]}"></span><strong>${c}</strong>
     </span>`
  ).join('');

  return `<div class="lic-donut-wrap" style="gap:.6rem">
  <svg width="90" height="90" viewBox="0 0 90 90" aria-hidden="true">
    ${arcs}
    <text x="${cx}" y="${cy + 5}" text-anchor="middle" font-size="13" font-weight="bold" fill="currentColor">${total}</text>
  </svg>
  <div class="lic-legend" style="gap:.25rem">${legend}</div>
</div>`;
}

/* ── FortiGuard subscription grid ────────────────────────────────────────── */
function renderFortiGuardSection(data, adom) {
  const container = document.getElementById('fortiGuardContent');
  if (!container) return;

  fgSelSub  = null; fgSelStatus = null; fgDetPage = 1;
  fgDevices = data.devices || [];

  if (fgDevices.length === 0) { container.innerHTML = ''; return; }

  const hasSubs = fgDevices.some(d => d.subscriptions && Object.keys(d.subscriptions).length > 0);
  if (!hasSubs) {
    container.innerHTML = `
<div class="table-wrapper" style="margin-top:1rem">
  <div class="table-controls"><strong>FortiGuard Subscriptions</strong></div>
  <p style="padding:1rem;color:var(--text-muted);font-size:.9em">
    Subscription data not yet loaded. Click &#8635; Refresh in the License Status card above to fetch it.
  </p>
</div>`;
    return;
  }

  // Aggregate counts per subscription
  const counts = {};
  for (const key of FG_KEYS) counts[key] = { licensed: 0, expired: 0, none: 0 };
  for (const d of fgDevices) {
    const subs = d.subscriptions || {};
    for (const key of FG_KEYS) {
      const s = (subs[key] || {}).status || 'unknown';
      if (s === 'licensed') counts[key].licensed++;
      else if (s === 'expired') counts[key].expired++;
      else counts[key].none++;
    }
  }

  const cards = FG_KEYS.map(key => {
    const c = counts[key];
    return `<div class="fg-card" data-subkey="${key}">
  <div class="fg-card-title">${escHtml(FG_LABELS[key])}</div>
  ${buildMiniDonutSVG(c.licensed, c.expired, c.none, key)}
</div>`;
  }).join('');

  container.innerHTML = `
<div class="table-wrapper" style="margin-top:1rem">
  <div class="table-controls">
    <strong>FortiGuard Subscriptions</strong>
    <div class="table-controls-right">
      <span style="color:var(--text-muted);font-size:.85em">Click a slice or legend item to list devices.</span>
    </div>
  </div>
  <div class="fg-grid">${cards}</div>
</div>
<div id="fgListContent"></div>`;

  container.addEventListener('click', e => {
    const target = e.target.closest('[data-subkey]');
    if (!target) return;
    const sub    = target.dataset.subkey;
    const status = target.dataset.status || null;
    if (fgSelSub === sub && fgSelStatus === status) {
      fgSelSub = null; fgSelStatus = null;
    } else {
      fgSelSub = sub; fgSelStatus = status;
    }
    fgDetPage = 1;
    container.querySelectorAll('.fg-card').forEach(c =>
      c.classList.toggle('fg-active', c.dataset.subkey === fgSelSub)
    );
    renderFortiGuardList();
  });
}

/* ── FortiGuard device list ──────────────────────────────────────────────── */
function renderFortiGuardList() {
  const listEl = document.getElementById('fgListContent');
  if (!listEl) return;
  if (!fgSelSub) { listEl.innerHTML = ''; return; }

  const filtered = fgDevices.filter(d => {
    const s = ((d.subscriptions || {})[fgSelSub] || {}).status || 'unknown';
    const bucket = (s === 'none' || s === 'unknown') ? 'none' : s;
    return fgSelStatus === null || bucket === fgSelStatus || s === fgSelStatus;
  });

  const total = filtered.length;
  const start = (fgDetPage - 1) * fgDetSize;
  const page  = filtered.slice(start, start + fgDetSize);

  const subLabel = FG_LABELS[fgSelSub] || fgSelSub;
  const heading  = fgSelStatus
    ? `${escHtml(subLabel)} — ${escHtml(FG_STATUS_DISPLAY[fgSelStatus] || fgSelStatus)}`
    : escHtml(subLabel);

  const colourMap = { licensed: '#28a745', expired: '#dc3545', none: '#6c757d', unknown: '#6c757d' };

  const rows = page.map(d => {
    const sub    = ((d.subscriptions || {})[fgSelSub] || {});
    const s      = sub.status || 'unknown';
    const bucket = (s === 'none' || s === 'unknown') ? 'none' : s;
    const colour = colourMap[bucket] || '#6c757d';
    const label  = FG_STATUS_DISPLAY[s] || s;
    return `<tr>
  <td>${escHtml(d.device)}</td>
  <td><span style="color:${colour};font-weight:600">${escHtml(label)}</span></td>
  <td>${escHtml(sub.expires || '—')}</td>
  <td>${escHtml(d.firmware || 'n/a')}</td>
  <td>${escHtml(d.adom || '—')}</td>
</tr>`;
  }).join('');

  const totalPages  = Math.max(1, Math.ceil(total / fgDetSize));
  const sizeOptions = [10, 20, 25, 50].map(n =>
    `<option value="${n}" ${n === fgDetSize ? 'selected' : ''}>${n}</option>`
  ).join('');

  listEl.innerHTML = `
<div class="table-wrapper" style="margin-top:1rem">
  <div class="table-controls">
    <span>Showing: <strong>${heading}</strong> (${total} device${total !== 1 ? 's' : ''})</span>
    <div class="table-controls-right">
      <button class="btn btn-sm btn-secondary" onclick="exportFGData('csv')">CSV</button>
      <button class="btn btn-sm btn-secondary" onclick="exportFGData('json')">JSON</button>
      <button class="btn btn-sm btn-secondary" onclick="exportFGData('pdf')">PDF</button>
    </div>
  </div>
  <table class="data-table">
    <thead><tr><th>Device</th><th>Status</th><th>Expires</th><th>Firmware</th><th>ADOM</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="5" style="padding:.75rem 1rem;text-align:center">No devices</td></tr>'}</tbody>
  </table>
  <div class="table-controls">
    <div id="fgPagination">${renderFGPagination(fgDetPage, totalPages)}</div>
    <div class="table-controls-right">
      <span style="font-size:.85em">Per page:</span>
      <select id="fgSizeSelect" class="form-select-sm">${sizeOptions}</select>
    </div>
  </div>
</div>`;

  document.getElementById('fgSizeSelect').addEventListener('change', e => {
    fgDetSize = parseInt(e.target.value, 10); fgDetPage = 1; renderFortiGuardList();
  });
  listEl.querySelectorAll('[data-fgpage]').forEach(btn => {
    btn.addEventListener('click', () => {
      const p = parseInt(btn.dataset.fgpage, 10);
      if (!isNaN(p) && p !== fgDetPage) { fgDetPage = p; renderFortiGuardList(); }
    });
  });
}

/* ── FortiGuard pagination ───────────────────────────────────────────────── */
function renderFGPagination(current, total) {
  if (total <= 1) return '';
  function fgBtn(label, page, disabled, active) {
    return `<button class="pg-btn${active ? ' active' : ''}" data-fgpage="${page}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  }
  let h = fgBtn('&laquo;&laquo;', 1, current === 1, false) + fgBtn('&lsaquo;', current - 1, current === 1, false);
  const s = Math.max(1, current - 2), e = Math.min(total, s + 4);
  for (let i = s; i <= e; i++) h += fgBtn(i, i, false, i === current);
  h += fgBtn('&rsaquo;', current + 1, current === total, false) + fgBtn('&raquo;&raquo;', total, current === total, false);
  return `<div class="pagination">${h}</div>`;
}

/* ── FortiGuard data export ──────────────────────────────────────────────── */
function exportFGData(format) {
  if (!fgSelSub) return;
  const subLabel = FG_LABELS[fgSelSub] || fgSelSub;
  const rows = fgDevices.filter(d => {
    const s = ((d.subscriptions || {})[fgSelSub] || {}).status || 'unknown';
    const bucket = (s === 'none' || s === 'unknown') ? 'none' : s;
    return fgSelStatus === null || bucket === fgSelStatus || s === fgSelStatus;
  });

  const safeAdom   = (currentAdom || 'all').replace(/[^a-zA-Z0-9._-]/g, '_');
  const safeSub    = fgSelSub.replace(/[^a-zA-Z0-9._-]/g, '_');
  const safeStatus = (fgSelStatus || 'all').replace(/[^a-zA-Z0-9._-]/g, '_');
  const date = new Date().toISOString().slice(0, 10);
  const base = `fortiguard_${safeAdom}_${safeSub}_${safeStatus}_${date}`;

  if (format === 'csv') {
    const header = 'Device,Subscription,Status,Expires,Firmware,ADOM';
    const lines = rows.map(d => {
      const sub = ((d.subscriptions || {})[fgSelSub] || {});
      return [d.device, subLabel, sub.status || 'unknown', sub.expires || '', d.firmware || '', d.adom]
        .map(v => `"${String(v).replace(/"/g, '""')}"`).join(',');
    });
    const blob = new Blob([[header, ...lines].join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = `${base}.csv`; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 0);
  } else if (format === 'json') {
    const out = rows.map(d => {
      const sub = ((d.subscriptions || {})[fgSelSub] || {});
      return { device: d.device, subscription: subLabel, status: sub.status || 'unknown', expires: sub.expires || null, firmware: d.firmware, adom: d.adom };
    });
    const blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = `${base}.json`; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 0);
  } else if (format === 'pdf') {
    const filterLabel = fgSelStatus ? `${subLabel} — ${FG_STATUS_DISPLAY[fgSelStatus] || fgSelStatus}` : subLabel;
    const tableRows = rows.map(d => {
      const sub  = ((d.subscriptions || {})[fgSelSub] || {});
      const sLbl = FG_STATUS_DISPLAY[sub.status || 'unknown'] || sub.status || 'Unknown';
      return `<tr><td>${escHtml(d.device)}</td><td>${escHtml(sLbl)}</td><td>${escHtml(sub.expires || '—')}</td><td>${escHtml(d.firmware || 'n/a')}</td><td>${escHtml(d.adom || '—')}</td></tr>`;
    }).join('');
    const win = window.open('', '_blank');
    win.document.write(`<!DOCTYPE html><html><head><title>${base}</title>
<style>body{font-family:sans-serif;font-size:12px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:4px 8px}th{background:#f0f0f0}</style>
</head><body>
<h2>FortiGuard Subscriptions — ${escHtml(filterLabel)}</h2>
<p>ADOM: ${escHtml(currentAdom || 'all')} &nbsp;|&nbsp; Generated: ${new Date().toLocaleString()}</p>
<table><thead><tr><th>Device</th><th>Status</th><th>Expires</th><th>Firmware</th><th>ADOM</th></tr></thead>
<tbody>${tableRows}</tbody></table>
</body></html>`);
    win.document.close(); win.print();
  }
}

function loadLicenseStatus(adom) {
  const container = document.getElementById('licenseContent');
  if (!container) return;
  container.innerHTML = '<p class="text-muted" style="padding:1rem">Loading license data…</p>';

  const url = adom
    ? `/api/adoms/${encodeURIComponent(adom)}/license`
    : '/api/devices/all/license';

  fetch(url)
    .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
    .then(data => {
      renderLicenseSection(data, adom);
      renderFortiGuardSection(data, adom);
    })
    .catch(err => {
      container.innerHTML = `<p style="padding:1rem;color:var(--danger)">Failed to load license data: ${escHtml(String(err))}</p>`;
      const fg = document.getElementById('fortiGuardContent');
      if (fg) fg.innerHTML = '';
    });
}

function renderLicenseSection(data, adom) {
  const container = document.getElementById('licenseContent');
  if (!container) return;

  licenseDevices   = data.devices || [];
  licenseSelStatus = null;
  licenseSelExpiry = null;
  licenseDetPage   = 1;

  const devices      = licenseDevices;
  const licensed     = devices.filter(d => d.status === 'licensed').length;
  const expired      = devices.filter(d => d.status === 'expired').length;
  const offline      = devices.filter(d => d.status === 'offline').length;
  const unregistered = devices.filter(d => d.status === 'unregistered').length;
  const unknown      = devices.filter(d => d.status === 'unknown').length;

  // Expiry buckets — licensed devices with a known expiry date only
  const now = Date.now(), ms30 = 30 * 864e5, ms90 = 90 * 864e5;
  const withExpiry = devices.filter(d => d.status === 'licensed' && d.expires);
  const exWithin30 = withExpiry.filter(d => new Date(d.expires) - now <= ms30).length;
  const exWithin90 = withExpiry.filter(d => { const df = new Date(d.expires) - now; return df > ms30 && df <= ms90; }).length;
  const exBeyond90 = withExpiry.filter(d => new Date(d.expires) - now > ms90).length;
  const showExpiry = withExpiry.length > 0;

  const lastUpdated = data.last_updated
    ? `Last updated: ${new Date(data.last_updated).toLocaleString()}`
    : 'Not yet updated';
  const cacheStatus = data.status === 'running' ? ' (refreshing…)' : '';

  container.innerHTML = `
<div class="table-wrapper" style="margin-top:1.5rem">
  <div class="table-controls">
    <strong>License Status</strong>
    <div class="table-controls-right">
      <span style="color:var(--text-muted);font-size:.85em">${escHtml(lastUpdated)}${escHtml(cacheStatus)}</span>
      <button class="btn btn-sm btn-ghost" id="licRefreshBtn">&#8635; Refresh</button>
    </div>
  </div>
  <div style="padding:1rem">
    ${devices.length === 0
      ? `<p style="color:var(--text-muted)">${data.status === 'pending' ? 'Cache is warming up — check back in a moment.' : 'No devices found.'}</p>`
      : `<div style="display:flex;gap:3rem;flex-wrap:wrap;align-items:flex-start">
           <div>
             <div style="font-size:.78em;font-weight:600;color:var(--text-muted);margin-bottom:.4rem;text-transform:uppercase;letter-spacing:.05em">By License</div>
             ${buildDonutSVG(licensed, expired, offline, unregistered, unknown)}
           </div>
           ${showExpiry ? `<div>
             <div style="font-size:.78em;font-weight:600;color:var(--text-muted);margin-bottom:.4rem;text-transform:uppercase;letter-spacing:.05em">Expiring Soon</div>
             ${buildExpiryDonutSVG(exWithin30, exWithin90, exBeyond90)}
           </div>` : ''}
         </div>`
    }
    <p style="margin-top:.5rem;color:var(--text-muted);font-size:.85em">Click a slice or legend item to list devices.</p>
  </div>
</div>
<div id="licenseListContent"></div>`;

  // Wire all slice/legend clicks — status keys vs expiry bracket keys
  const statusKeys = new Set(['licensed', 'expired', 'offline', 'unregistered', 'unknown']);
  container.querySelectorAll('[data-status]').forEach(el => {
    el.addEventListener('click', () => {
      const s = el.dataset.status;
      if (statusKeys.has(s)) {
        licenseSelStatus = (licenseSelStatus === s) ? null : s;
        licenseSelExpiry = null;
      } else {
        licenseSelExpiry = (licenseSelExpiry === s) ? null : s;
        licenseSelStatus = null;
      }
      licenseDetPage = 1;
      renderLicenseList();
    });
  });

  // Wire refresh button
  document.getElementById('licRefreshBtn').addEventListener('click', () => {
    fetch('/api/devices/all/license/refresh', { method: 'POST' })
      .then(r => { if (!r.ok) throw new Error(r.status); })
      .then(() => setTimeout(() => loadLicenseStatus(currentAdom), 2000))
      .catch(err => console.warn('License refresh failed:', err));
  });
}

/* ── License pagination helper (uses data-lpage to avoid clash with data-dpage) */
function renderLicPagination(current, total) {
  if (total <= 1) return '';
  function licPgBtn(label, page, disabled, active) {
    return `<button class="pg-btn${active ? ' active' : ''}" data-lpage="${page}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  }
  let h = licPgBtn('&laquo;&laquo;', 1, current === 1, false);
  h    += licPgBtn('&lsaquo;', current - 1, current === 1, false);
  const s = Math.max(1, current - 2), e = Math.min(total, s + 4);
  for (let i = s; i <= e; i++) h += licPgBtn(i, i, false, i === current);
  h += licPgBtn('&rsaquo;', current + 1, current === total, false);
  h += licPgBtn('&raquo;&raquo;', total, current === total, false);
  return `<div class="pagination">${h}</div>`;
}

/* ── License device list with pagination and export ─────────────────────── */
function renderLicenseList() {
  const listEl = document.getElementById('licenseListContent');
  if (!listEl) return;

  if (!licenseSelStatus && !licenseSelExpiry) {
    listEl.innerHTML = '';
    return;
  }

  const now = Date.now(), ms30 = 30 * 864e5, ms90 = 90 * 864e5;
  const expiryMeta = {
    within30: { label: 'Expiring ≤30 days',    colour: '#dc3545' },
    within90: { label: 'Expiring 31–90 days',  colour: '#fd7e14' },
    beyond90: { label: 'Expiring >90 days',    colour: '#28a745' },
  };
  const statusColours = { licensed: '#28a745', expired: '#dc3545', offline: '#374151', unregistered: '#94a3b8', unknown: '#ffc107' };

  let filtered, statusLabel, colour;
  if (licenseSelExpiry) {
    const meta = expiryMeta[licenseSelExpiry];
    statusLabel = meta.label;
    colour      = meta.colour;
    filtered = licenseDevices.filter(d => {
      if (d.status !== 'licensed' || !d.expires) return false;
      const diff = new Date(d.expires) - now;
      if (licenseSelExpiry === 'within30') return diff <= ms30;
      if (licenseSelExpiry === 'within90') return diff > ms30 && diff <= ms90;
      return diff > ms90;
    });
  } else {
    const statusLabels = { unregistered: 'Not Registered' };
    statusLabel = statusLabels[licenseSelStatus]
      || (licenseSelStatus.charAt(0).toUpperCase() + licenseSelStatus.slice(1));
    colour      = statusColours[licenseSelStatus] || '#6c757d';
    filtered    = licenseDevices.filter(d => d.status === licenseSelStatus);
  }

  const total    = filtered.length;
  const start    = (licenseDetPage - 1) * licenseDetSize;
  const page     = filtered.slice(start, start + licenseDetSize);

  const rows = page.map(d => `
<tr>
  <td>${escHtml(d.device)}</td>
  <td><span style="color:${colour};font-weight:600">${escHtml(statusLabel)}</span></td>
  <td>${escHtml(d.expires || '—')}</td>
  <td>${escHtml(d.firmware || 'n/a')}</td>
  <td>${escHtml(d.adom || '—')}</td>
</tr>`).join('');

  const totalPages = Math.max(1, Math.ceil(total / licenseDetSize));

  const sizeOptions = [10, 20, 25, 50].map(n =>
    `<option value="${n}" ${n === licenseDetSize ? 'selected' : ''}>${n}</option>`
  ).join('');

  listEl.innerHTML = `
<div class="table-wrapper" style="margin-top:1rem">
  <div class="table-controls">
    <span>Showing: <strong>${escHtml(statusLabel)}</strong> (${total} device${total !== 1 ? 's' : ''})</span>
    <div class="table-controls-right">
      <button class="btn btn-sm btn-secondary" onclick="exportCurrentLicenseData('csv')">CSV</button>
      <button class="btn btn-sm btn-secondary" onclick="exportCurrentLicenseData('json')">JSON</button>
      <button class="btn btn-sm btn-secondary" onclick="exportCurrentLicenseData('pdf')">PDF</button>
    </div>
  </div>
  <table class="data-table">
    <thead>
      <tr>
        <th>Device</th><th>Status</th><th>Expires</th><th>Firmware</th><th>ADOM</th>
      </tr>
    </thead>
    <tbody>${rows || '<tr><td colspan="5" class="empty-state" style="padding:.75rem 1rem;text-align:center">No devices</td></tr>'}</tbody>
  </table>
  <div class="table-controls">
    <div id="licPagination">${renderLicPagination(licenseDetPage, totalPages)}</div>
    <div class="table-controls-right">
      <span style="font-size:.85em">Per page:</span>
      <select id="licSizeSelect" class="form-select-sm">${sizeOptions}</select>
    </div>
  </div>
</div>`;

  // Wire page-size select
  document.getElementById('licSizeSelect').addEventListener('change', e => {
    licenseDetSize = parseInt(e.target.value, 10);
    licenseDetPage = 1;
    renderLicenseList();
  });

  // Wire pagination buttons
  listEl.querySelectorAll('[data-lpage]').forEach(btn => {
    btn.addEventListener('click', () => {
      const p = parseInt(btn.dataset.lpage, 10);
      if (!isNaN(p) && p !== licenseDetPage) {
        licenseDetPage = p;
        renderLicenseList();
      }
    });
  });
}

/* ── Export helper — re-filters from current state ───────────────────────── */
function exportCurrentLicenseData(format) {
  const now = Date.now(), ms30 = 30 * 864e5, ms90 = 90 * 864e5;
  let rows, label;
  if (licenseSelExpiry) {
    rows = licenseDevices.filter(d => {
      if (d.status !== 'licensed' || !d.expires) return false;
      const diff = new Date(d.expires) - now;
      if (licenseSelExpiry === 'within30') return diff <= ms30;
      if (licenseSelExpiry === 'within90') return diff > ms30 && diff <= ms90;
      return diff > ms90;
    });
    label = licenseSelExpiry;
  } else {
    rows  = licenseDevices.filter(d => d.status === licenseSelStatus);
    label = licenseSelStatus;
  }
  exportLicenseData(format, rows, label);
}

/* ── License data export ─────────────────────────────────────────────────── */
function exportLicenseData(format, rows, status) {
  const safeAdom = (currentAdom || 'all').replace(/[^a-zA-Z0-9._-]/g, '_');
  const date = new Date().toISOString().slice(0, 10);
  const base = `license_${safeAdom}_${status}_${date}`;

  if (format === 'csv') {
    const header = 'Device,Status,Expires,Firmware,ADOM';
    const lines  = rows.map(d =>
      [d.device, d.status, d.expires || '', d.firmware || '', d.adom].map(v =>
        `"${String(v).replace(/"/g, '""')}"`
      ).join(',')
    );
    const blob = new Blob([[header, ...lines].join('\n')], { type: 'text/csv' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `${base}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 0);
  } else if (format === 'json') {
    const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `${base}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 0);
  } else if (format === 'pdf') {
    const expLabels = { within30: 'Expiring ≤30 days', within90: 'Expiring 31–90 days', beyond90: 'Expiring >90 days' };
    const statusLabel = expLabels[status] || (status.charAt(0).toUpperCase() + status.slice(1));
    const tableRows = rows.map(d =>
      `<tr><td>${escHtml(d.device)}</td><td>${escHtml(statusLabel)}</td><td>${escHtml(d.expires || '—')}</td><td>${escHtml(d.firmware || 'n/a')}</td><td>${escHtml(d.adom || '—')}</td></tr>`
    ).join('');
    const win = window.open('', '_blank');
    win.document.write(`<!DOCTYPE html><html><head><title>${base}</title>
<style>body{font-family:sans-serif;font-size:12px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:4px 8px}th{background:#f0f0f0}</style>
</head><body>
<h2>License Status — ${statusLabel}</h2>
<p>ADOM: ${escHtml(currentAdom || 'all')} &nbsp;|&nbsp; Generated: ${new Date().toLocaleString()}</p>
<table><thead><tr><th>Device</th><th>Status</th><th>Expires</th><th>Firmware</th><th>ADOM</th></tr></thead>
<tbody>${tableRows}</tbody></table>
</body></html>`);
    win.document.close();
    win.print();
  }
}

/* ── Event wiring ──────────────────────────────────────────────────────── */
document.getElementById('adomSelect').addEventListener('change', function () {
  if (this.value) loadVersions(this.value);
  else {
    allDevices = []; selectedVer = null;
    document.getElementById('versionsContent').innerHTML = '';
    document.getElementById('adomCloseBtn').style.display = 'none';
    document.getElementById('licenseContent').innerHTML = '';
    loadLicenseStatus('');
  }
});

document.getElementById('adomCloseBtn').addEventListener('click', () => {
  allDevices = []; selectedVer = null; currentAdom = '';
  document.getElementById('adomSelect').value = '';
  document.getElementById('versionsContent').innerHTML = '';
  document.getElementById('adomCloseBtn').style.display = 'none';
  document.getElementById('licenseContent').innerHTML = '';
  loadLicenseStatus('');
});

document.getElementById('refreshBtn').addEventListener('click', () => {
  // The per-ADOM refresh is a live query; global uses the cache refresh path
  loadGlobalVersions(true);
  const adom = document.getElementById('adomSelect').value;
  if (adom) loadVersions(adom);
});

loadAdoms();
loadGlobalVersions(false);
loadLicenseStatus('');
