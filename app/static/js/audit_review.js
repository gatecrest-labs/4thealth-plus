'use strict';

/* ── Utilities ─────────────────────────────────────────────────────────────── */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ── Protocol badge rendering ───────────────────────────────────────────────── */
function protoBadgeHtml(proto) {
  const base = 'display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75rem;font-weight:600;border:1px solid;margin:1px 2px';
  const label = proto.name.toUpperCase();
  if (proto.secure === false)
    return `<span style="${base};color:#dc3545;border-color:#dc3545;background:#fff5f5">${esc(label)}</span>`;
  if (proto.secure === true)
    return `<span style="${base};color:#2d6a2d;border-color:#5a9e5a;background:#f4faf4">${esc(label)}</span>`;
  return `<span style="${base};color:#555;border-color:#aaa;background:#f8f8f8">${esc(label)}</span>`;
}

function protoListHtml(protocols) {
  if (!protocols || !protocols.length) return '<span style="color:#888">—</span>';
  return protocols.map(protoBadgeHtml).join('');
}

/* ── Result badge rendering (CIS and interface checks unified) ──────────────── */
function resultBadgeHtml(result) {
  const base = 'display:inline-block;padding:2px 8px;border-radius:3px;font-size:.75rem;font-weight:700;border:1px solid';
  switch ((result || '').toUpperCase()) {
    case 'INSECURE':
      return `<span style="${base};color:#dc3545;border-color:#dc3545;background:#fff5f5">INSECURE</span>`;
    case 'FAIL':
      return `<span style="${base};color:#b91c1c;border-color:#fca5a5;background:#fee2e2">FAIL</span>`;
    case 'WARN':
      return `<span style="${base};color:#b45309;border-color:#fcd34d;background:#fffbeb">WARN</span>`;
    case 'CONFIG_MISSING':
      return `<span style="${base};color:#92400e;border-color:#fde68a;background:#fef3c7">CONFIG MISSING</span>`;
    case 'PASS':
      return `<span style="${base};color:#166534;border-color:#86efac;background:#dcfce7">PASS</span>`;
    case 'INFO':
      return `<span style="${base};color:#1d4ed8;border-color:#93c5fd;background:#eff6ff">INFO</span>`;
    default:
      return `<span style="${base};color:#555;border-color:#aaa;background:#f8f8f8">${esc(result || '?')}</span>`;
  }
}

/* ── State ──────────────────────────────────────────────────────────────────── */
let allRows       = [];
let lastMeta      = null;
let currentPage   = 1;
let pageSize      = 25;
let filterText    = '';
let filterDevice  = '';
let filterResult  = '';
let activeProtos  = new Set();
let _protoMeta    = {};
let _abortRun     = false;
let _knownDevices = [];

/* ── AI Assist summary ──────────────────────────────────────────────────────── */
let _drAiAssistAvailable = false;

async function checkAiSummaryAvailability() {
  try {
    const resp = await fetch('/api/audit-review/ai-summary-status');
    const data = await resp.json();
    _drAiAssistAvailable = !!data.available;
  } catch (e) {
    _drAiAssistAvailable = false;
  }
}

function showAiSummaryBoxIfAvailable(adom, results, checks) {
  const box = document.getElementById('drAiSummaryBox');
  if (!box) return;
  if (!_drAiAssistAvailable) { box.style.display = 'none'; return; }
  box.style.display = '';
  const btn = document.getElementById('drAiSummaryBtn');
  const out = document.getElementById('drAiSummaryOutput');
  out.textContent = '';
  btn.disabled = false;
  btn.textContent = 'Summarize with AI';
  btn.onclick = async () => {
    btn.disabled = true;
    btn.textContent = 'Summarizing…';
    out.textContent = '';
    try {
      // Slim projection: only the fields the backend's _build_check_summary()
      // and build_narrative()/_fail_rows() actually read, to keep this
      // payload well under Flask's MAX_CONTENT_LENGTH on large ADOMs.
      const slimResults = results.map(d => ({
        device: d.device,
        error: d.error,
        rows: (d.rows || []).map(r => ({
          device: r.device,
          check: r.check,
          result: r.result,
          interface: r.interface,
          detail: r.detail,
        })),
      }));
      const resp = await fetch('/api/audit-review/ai-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ adom, results: slimResults, checks }),
      });
      if (resp.status === 401) { location.href = '/login'; return; }
      if (resp.status === 413) {
        out.textContent = 'AI summary unavailable: response too large (try a smaller ADOM or fewer checks)';
        return;
      }
      const data = await resp.json();
      if (data.narrative) {
        out.textContent = data.narrative;
      } else {
        out.textContent = 'AI summary unavailable: ' + (data.narrative_error || data.error || 'unknown error');
      }
    } catch (e) {
      out.textContent = 'AI summary request failed: ' + e.message;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Summarize with AI';
    }
  };
}

/* ── Error/clear ────────────────────────────────────────────────────────────── */
function showError(msg) {
  const el = document.getElementById('drError');
  el.textContent = msg;
  el.style.display = '';
}
function clearError() {
  const el = document.getElementById('drError');
  el.textContent = '';
  el.style.display = 'none';
}

/* ── Progress bar helpers ───────────────────────────────────────────────────── */
function showProgress(done, total, currentDevice) {
  const wrap = document.getElementById('drProgressWrap');
  const bar  = document.getElementById('drProgressBar');
  const lbl  = document.getElementById('drProgressLabel');
  if (!wrap) return;
  wrap.style.display = '';
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  bar.style.width = pct + '%';
  bar.textContent  = pct + '%';
  const remaining  = total - done;
  lbl.textContent  = `Analysing… ${done} / ${total} devices` +
    (currentDevice ? ` — ${currentDevice}` : '') +
    (remaining > 0  ? ` (${remaining} remaining)` : '');
}

function hideProgress() {
  const wrap = document.getElementById('drProgressWrap');
  if (wrap) wrap.style.display = 'none';
}

/* ── Check parameter panel ──────────────────────────────────────────────────── */
function updateParamsPanel() {
  const checkedKeys = new Set(
    [...document.querySelectorAll('input[name="dr_check"]:checked')].map(cb => cb.value)
  );
  const panel  = document.getElementById('drParamsPanel');
  const fields = document.getElementById('drParamsFields');

  // Find all parameterised checks that are currently selected
  const active = (CHECK_DEFS || []).filter(
    c => checkedKeys.has(c.key) && c.params_schema && c.params_schema.length > 0
  );

  if (!active.length) {
    panel.style.display = 'none';
    return;
  }

  panel.style.display = '';

  // Preserve any values the user has already typed before rebuilding
  const savedValues = {};
  fields.querySelectorAll('.dr-param-input').forEach(inp => {
    savedValues[`${inp.dataset.checkKey}_${inp.dataset.paramKey}`] = inp.value;
  });

  fields.innerHTML = '';

  active.forEach(check => {
    check.params_schema.forEach(param => {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:.6rem;margin-bottom:.5rem;flex-wrap:wrap';

      const lbl = document.createElement('label');
      lbl.style.cssText = 'min-width:180px;font-size:.88rem;font-weight:600;color:var(--text)';
      lbl.textContent = `${check.name} — ${param.label}:`;
      lbl.setAttribute('for', `drParam_${check.key}_${param.key}`);

      const inp = document.createElement('input');
      inp.type = 'text';
      inp.id   = `drParam_${check.key}_${param.key}`;
      inp.dataset.checkKey  = check.key;
      inp.dataset.paramKey  = param.key;
      inp.dataset.paramType = param.type || 'text';
      inp.placeholder = param.placeholder || '';
      inp.className   = 'form-control dr-param-input';
      inp.style.cssText = 'max-width:360px;font-size:.88rem';

      // Restore previously entered value when the panel is rebuilt
      const savedKey = `${check.key}_${param.key}`;
      if (savedValues[savedKey] !== undefined) inp.value = savedValues[savedKey];

      row.appendChild(lbl);
      row.appendChild(inp);
      fields.appendChild(row);
    });
  });
}

function collectCheckParams() {
  const params = {};
  document.querySelectorAll('.dr-param-input').forEach(inp => {
    const ck = inp.dataset.checkKey;
    const pk = inp.dataset.paramKey;
    const pt = inp.dataset.paramType || 'text';
    const val = (inp.value || '').trim();
    if (!params[ck]) params[ck] = {};
    if (pt === 'ip_list') {
      // IP lists: split on whitespace/commas into an array
      params[ck][pk] = val ? val.split(/[\s,]+/).map(s => s.trim()).filter(Boolean) : [];
    } else {
      // text / number: send as a plain string so Python can parse it directly
      params[ck][pk] = val;
    }
  });
  return params;
}

/* ── Device search helpers ──────────────────────────────────────────────────── */

// Parse the device search field into an array of trimmed tokens (lowercase).
// Returns [] if blank or "all".
function parseDeviceSearchTokens() {
  const raw = (document.getElementById('drDeviceSearch').value || '').trim();
  if (!raw || raw.toLowerCase() === 'all') return [];
  return raw.split(/[,\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
}

// Return the subset of _knownDevices that match the current search field.
// Empty tokens (or "all") → all devices.
function resolveTargetDevices() {
  const tokens = parseDeviceSearchTokens();
  if (!tokens.length) return _knownDevices;
  return _knownDevices.filter(d => {
    const name = (d.name || '').toLowerCase();
    const ip   = (d.ip   || '').toLowerCase();
    return tokens.some(t => name === t || ip === t || name.includes(t) || ip.includes(t));
  });
}

function updateDeviceMatchCount() {
  const el = document.getElementById('drDeviceMatchCount');
  if (!_knownDevices.length) { el.textContent = ''; return; }
  const matched = resolveTargetDevices();
  const tokens  = parseDeviceSearchTokens();
  if (!tokens.length) {
    el.textContent = `${_knownDevices.length} device(s) in ADOM`;
  } else {
    el.textContent = `${matched.length} of ${_knownDevices.length} matched`;
  }
  document.getElementById('drRunBtn').disabled = matched.length === 0;
}

/* ── ADOM loader ────────────────────────────────────────────────────────────── */
async function loadAdoms() {
  const sel = document.getElementById('drAdom');
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

/* ── Fetch device list when ADOM changes ────────────────────────────────────── */
async function onAdomChange(adom) {
  _knownDevices = [];
  document.getElementById('drResults').style.display = 'none';
  document.getElementById('drRunBtn').disabled = true;
  document.getElementById('drDeviceMatchCount').textContent = '';
  clearError();
  allRows = [];

  if (!adom) return;

  document.getElementById('drDeviceLoading').style.display = '';
  try {
    const resp = await fetch(`/api/audit-review/adoms/${encodeURIComponent(adom)}/devices`);
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    if (Array.isArray(data)) {
      _knownDevices = data;
      updateDeviceMatchCount();
    }
  } catch (e) {
    showError('Could not load device list: ' + e.message);
  } finally {
    document.getElementById('drDeviceLoading').style.display = 'none';
  }
}

/* ── Run analysis (per-device loop with live progress) ──────────────────────── */
async function runAnalysis() {
  clearError();
  hideProgress();
  const adom = document.getElementById('drAdom').value;
  if (!adom) return;

  const checks = [...document.querySelectorAll('input[name="dr_check"]:checked')].map(cb => cb.value);
  if (!checks.length) { showError('Select at least one check.'); return; }

  const targetDevices = resolveTargetDevices();
  const deviceList    = targetDevices.map(d => d.name).filter(Boolean);
  if (!deviceList.length) { showError('No devices matched — check your firewall filter or select an ADOM.'); return; }

  const checkParams = collectCheckParams();

  _abortRun = false;
  document.getElementById('drRunBtn').disabled        = true;
  const cancelBtn = document.getElementById('drCancelBtn');
  cancelBtn.disabled    = false;
  cancelBtn.textContent = '⏹ Cancel';
  cancelBtn.style.display = '';
  document.getElementById('drRunning').style.display = '';
  document.getElementById('drResults').style.display = 'none';
  document.getElementById('drAiSummaryBox').style.display = 'none';

  const collectedRows = [];
  const reviewed      = [];
  const resultsByDevice = []; // per-device {device, rows, error} — shape the AI summary endpoint expects

  showProgress(0, deviceList.length, deviceList[0]);

  for (let i = 0; i < deviceList.length; i++) {
    if (_abortRun) break;

    const device = deviceList[i];
    showProgress(i, deviceList.length, device);

    try {
      const resp = await fetch('/api/audit-review/run/device', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ adom, device, checks, check_params: checkParams }),
      });
      if (resp.status === 401) { location.href = '/login'; return; }
      const data = await resp.json();
      if (resp.ok && Array.isArray(data.rows)) {
        collectedRows.push(...data.rows);
        reviewed.push(device);
        resultsByDevice.push({ device, rows: data.rows, error: null });
      } else {
        resultsByDevice.push({ device, rows: [], error: data.error || `HTTP ${resp.status}` });
      }
    } catch (e) {
      // network error on one device — skip and continue
      resultsByDevice.push({ device, rows: [], error: e.message });
    }
  }

  showProgress(deviceList.length, deviceList.length, '');

  const runAt = new Date().toLocaleString();
  allRows  = collectedRows;
  lastMeta = {
    adom:         adom,
    run_at:       runAt,
    device_count: reviewed.length,
    checks_run:   checks,
    devices:      reviewed,
    check_params: checkParams,
  };

  // Reset filters
  filterText   = '';
  filterDevice = '';
  filterResult = '';
  currentPage  = 1;
  document.getElementById('drFilter').value       = '';
  document.getElementById('drDeviceFilter').value = '';
  document.getElementById('drResultFilter').value = '';

  populateDeviceFilter(reviewed);
  buildProtoCheckboxes();
  renderTable();

  document.getElementById('drResults').style.display = '';
  showAiSummaryBoxIfAvailable(adom, resultsByDevice, checks);

  const failCount = allRows.filter(r => r.result === 'FAIL' || r.result === 'INSECURE').length;
  const passCount = allRows.filter(r => r.result === 'PASS').length;
  const warnCount = allRows.filter(r => r.result === 'WARN' || r.result === 'CONFIG_MISSING').length;
  let label = `Last run: ${runAt} — ${reviewed.length} device(s) · ${allRows.length} finding(s)`;
  if (failCount) label += ` · ${failCount} fail/insecure`;
  if (warnCount) label += ` · ${warnCount} warn/missing`;
  if (passCount) label += ` · ${passCount} pass`;
  if (_abortRun) label += ' (cancelled)';
  document.getElementById('drLastRunLabel').textContent = label;

  document.getElementById('drRunBtn').disabled        = false;
  cancelBtn.style.display  = 'none';
  cancelBtn.disabled       = false;
  cancelBtn.textContent    = '⏹ Cancel';
  document.getElementById('drRunning').style.display  = 'none';
  setTimeout(hideProgress, 2000);
}

/* ── Protocol checkbox panel (interface check only) ─────────────────────────── */
function buildProtoCheckboxes() {
  _protoMeta = {};
  allRows.forEach(row => {
    (row.protocols || []).forEach(p => {
      if (!(p.name in _protoMeta)) _protoMeta[p.name] = p.secure;
    });
  });

  const panel = document.getElementById('drProtoPanel');
  if (!Object.keys(_protoMeta).length) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = '';

  const sorted = Object.keys(_protoMeta).sort((a, b) => {
    const rank = v => v === false ? 0 : v === true ? 1 : 2;
    const ra = rank(_protoMeta[a]), rb = rank(_protoMeta[b]);
    return ra !== rb ? ra - rb : a.localeCompare(b);
  });

  activeProtos = new Set(sorted);

  const container = document.getElementById('drProtoChecks');
  container.innerHTML = '';

  if (!sorted.length) {
    container.innerHTML = '<span class="text-muted" style="font-size:.82rem">No protocols found.</span>';
    return;
  }

  sorted.forEach(name => {
    const secure = _protoMeta[name];
    const count  = allRows.filter(r => (r.protocols || []).some(p => p.name === name)).length;

    let badgeStyle = 'display:inline-block;padding:1px 5px;border-radius:3px;font-size:.72rem;font-weight:600;border:1px solid;margin-left:4px;vertical-align:middle';
    if (secure === false)  badgeStyle += ';color:#dc3545;border-color:#dc3545;background:#fff5f5';
    else if (secure === true) badgeStyle += ';color:#2d6a2d;border-color:#5a9e5a;background:#f4faf4';
    else                   badgeStyle += ';color:#555;border-color:#aaa;background:#f8f8f8';

    const lbl = document.createElement('label');
    lbl.className = 'checkbox-label';
    lbl.innerHTML =
      `<input type="checkbox" class="dr-proto-cb" value="${esc(name)}" checked />` +
      `<span style="${badgeStyle}">${esc(name.toUpperCase())}</span>` +
      `<span style="font-size:.75rem;color:var(--text-muted);margin-left:3px">(${count})</span>`;
    container.appendChild(lbl);
  });

  container.querySelectorAll('.dr-proto-cb').forEach(cb => {
    cb.addEventListener('change', () => {
      activeProtos = new Set(
        [...container.querySelectorAll('.dr-proto-cb:checked')].map(c => c.value)
      );
      currentPage = 1;
      renderTable();
    });
  });
}

function setAllProtos(checked) {
  document.querySelectorAll('.dr-proto-cb').forEach(cb => { cb.checked = checked; });
  activeProtos = checked ? new Set(Object.keys(_protoMeta)) : new Set();
  currentPage = 1;
  renderTable();
}

/* ── Device dropdown ────────────────────────────────────────────────────────── */
function populateDeviceFilter(deviceNames) {
  const sel = document.getElementById('drDeviceFilter');
  sel.innerHTML = '<option value="">All devices</option>';
  [...new Set(deviceNames)].sort().forEach(name => {
    const opt = document.createElement('option');
    opt.value = name; opt.textContent = name;
    sel.appendChild(opt);
  });
}

/* ── Filtering ──────────────────────────────────────────────────────────────── */
function filtered() {
  const q = filterText.toLowerCase();
  return allRows.filter(row => {
    if (filterDevice && row.device !== filterDevice) return false;
    if (filterResult && (row.result || '') !== filterResult) return false;

    // For interface-protocol rows, apply protocol visibility filter
    if (row.protocols && row.protocols.length > 0 && activeProtos.size > 0) {
      const rowProtos = new Set((row.protocols || []).map(p => p.name));
      if (![...activeProtos].some(p => rowProtos.has(p))) return false;
    }

    if (!q) return true;
    const protoNames = (row.protocols || []).map(p => p.name).join(' ').toLowerCase();
    return (
      (row.device    || '').toLowerCase().includes(q) ||
      (row.check     || '').toLowerCase().includes(q) ||
      (row.result    || '').toLowerCase().includes(q) ||
      (row.detail    || '').toLowerCase().includes(q) ||
      (row.interface || '').toLowerCase().includes(q) ||
      (row.ip        || '').toLowerCase().includes(q) ||
      protoNames.includes(q)
    );
  });
}

function visibleProtocols(row) {
  if (!row.protocols || !row.protocols.length) return [];
  return activeProtos.size > 0
    ? row.protocols.filter(p => activeProtos.has(p.name))
    : row.protocols;
}

/* ── Render table ───────────────────────────────────────────────────────────── */
function renderTable() {
  const rows  = filtered();
  const start = (currentPage - 1) * pageSize;
  const page  = rows.slice(start, start + pageSize);
  const tbody = document.getElementById('drTbody');

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">No results match the current filters.</td></tr>';
    document.getElementById('drPager').innerHTML    = '';
    document.getElementById('drSummary').textContent = buildSummary(rows);
    return;
  }

  tbody.innerHTML = page.map(row => {
    const isCis      = row.type === 'system';
    const resultBadge = resultBadgeHtml(row.result);

    // Scope column: interface + vdom for interface rows; "device-level" for CIS
    let scopeHtml;
    if (isCis) {
      scopeHtml = '<span style="color:var(--text-muted);font-size:.82rem">device-level</span>';
    } else {
      const vdom = row.vdom && row.vdom !== 'root' ? row.vdom : '';
      scopeHtml  =
        `<code>${esc(row.interface)}</code>` +
        (vdom ? ` <span class="dr-vdom-badge">${esc(vdom)}</span>` : '');
    }

    // Detail column: protocol badges for interface rows, plain text for CIS
    let detailHtml;
    if (isCis) {
      detailHtml = row.detail
        ? `<span style="font-size:.84rem">${esc(row.detail)}</span>`
        : '<span style="color:var(--text-muted)">—</span>';
    } else {
      const visProtos = visibleProtocols(row);
      detailHtml = protoListHtml(visProtos);
    }

    // Row highlight
    let rowStyle = '';
    const r = (row.result || '').toUpperCase();
    if (r === 'INSECURE' || r === 'FAIL') rowStyle = ' style="background:#fff8f8"';
    else if (r === 'PASS')                rowStyle = ' style="background:#f6fff8"';

    return `<tr${rowStyle}>
      <td><strong>${esc(row.device)}</strong></td>
      <td style="font-size:.85rem">${esc(row.check || '')}</td>
      <td>${resultBadge}</td>
      <td>${scopeHtml}</td>
      <td><code>${esc(row.ip || '—')}</code></td>
      <td>${detailHtml}</td>
    </tr>`;
  }).join('');

  document.getElementById('drSummary').textContent = buildSummary(rows);
  renderPager(rows.length);
}

function buildSummary(rows) {
  const fail    = rows.filter(r => r.result === 'FAIL' || r.result === 'INSECURE').length;
  const pass    = rows.filter(r => r.result === 'PASS').length;
  const missing = rows.filter(r => r.result === 'CONFIG_MISSING').length;
  const devices = new Set(rows.map(r => r.device)).size;
  let s = `${rows.length} finding(s) · ${devices} device(s)`;
  if (fail)    s += ` · ${fail} fail/insecure`;
  if (missing) s += ` · ${missing} config missing`;
  if (pass)    s += ` · ${pass} pass`;
  return s;
}

/* ── Pagination ─────────────────────────────────────────────────────────────── */
function renderPager(total) {
  const pages = Math.ceil(total / pageSize);
  const pager = document.getElementById('drPager');
  if (pages <= 1) { pager.innerHTML = ''; return; }

  const range = [1];
  for (let p = Math.max(2, currentPage - 2); p <= Math.min(pages - 1, currentPage + 2); p++) range.push(p);
  if (!range.includes(pages)) range.push(pages);

  let html = `<button ${currentPage === 1 ? 'disabled' : ''} data-page="1">&laquo;</button>`;
  html    += `<button ${currentPage === 1 ? 'disabled' : ''} data-page="${currentPage - 1}">&lsaquo;</button>`;
  let prev = 0;
  range.forEach(p => {
    if (p - prev > 1) html += `<span class="pagination-ellipsis">…</span>`;
    html += `<button ${p === currentPage ? 'class="active"' : ''} data-page="${p}">${p}</button>`;
    prev = p;
  });
  html += `<button ${currentPage === pages ? 'disabled' : ''} data-page="${currentPage + 1}">&rsaquo;</button>`;
  html += `<button ${currentPage === pages ? 'disabled' : ''} data-page="${pages}">&raquo;</button>`;
  pager.innerHTML = html;
}

/* ── Exports ────────────────────────────────────────────────────────────────── */
function exportCsv() {
  const rows = filtered();
  if (!rows.length) { showError('No filtered results to export.'); return; }
  clearError();
  const meta = lastMeta || {};
  const header = [
    `ADOM,${meta.adom || ''}`,
    `Date/Time,${meta.run_at || ''}`,
    `Devices Reviewed,${meta.device_count ?? ''}`,
    `Total Findings,${rows.length}`,
    '',
  ].join('\r\n');
  const cols = ['Device', 'Check', 'Result', 'Interface/Scope', 'IP Address', 'Detail/Protocols'];
  const body = [cols.join(','), ...rows.map(r => [
    r.device,
    r.check || '',
    r.result || '',
    r.type === 'system' ? 'device-level' : r.interface,
    r.ip || '',
    r.type === 'system'
      ? (r.detail || '')
      : visibleProtocols(r).map(p => p.name).join(' '),
  ].map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))].join('\r\n');
  download(`device-review-${meta.adom || 'export'}.csv`, header + body, 'text/csv');
}

function exportJson() {
  const meta = lastMeta || {};
  const rows = filtered();
  if (!rows.length) { showError('No filtered results to export.'); return; }
  clearError();
  download(
    `device-review-${meta.adom || 'export'}.json`,
    JSON.stringify({ meta, rows }, null, 2),
    'application/json',
  );
}

function exportPdf() {
  const rows = filtered();
  if (!rows.length) { showError('No filtered results to export.'); return; }
  clearError();
  const meta        = lastMeta || {};
  const ts          = meta.run_at || new Date().toLocaleString();
  const title       = `Device Review — ADOM: ${meta.adom || ''}`;
  const failCount   = rows.filter(r => r.result === 'FAIL' || r.result === 'INSECURE').length;
  const passCount   = rows.filter(r => r.result === 'PASS').length;
  const deviceCount = new Set(rows.map(r => r.device)).size;

  const resultCell = result => {
    switch ((result || '').toUpperCase()) {
      case 'INSECURE':      return '<span style="color:#b91c1c;font-weight:700;background:#fee2e2;padding:0 5px;border-radius:2px">INSECURE</span>';
      case 'FAIL':          return '<span style="color:#b91c1c;font-weight:700;background:#fee2e2;padding:0 5px;border-radius:2px">FAIL</span>';
      case 'WARN':          return '<span style="color:#92400e;background:#fef3c7;padding:0 5px;border-radius:2px">WARN</span>';
      case 'CONFIG_MISSING':return '<span style="color:#92400e;background:#fef3c7;padding:0 5px;border-radius:2px">CONFIG MISSING</span>';
      case 'PASS':          return '<span style="color:#166534;background:#dcfce7;padding:0 5px;border-radius:2px">PASS</span>';
      case 'INFO':          return '<span style="color:#1d4ed8;background:#eff6ff;padding:0 5px;border-radius:2px">INFO</span>';
      default: return esc(result || '?');
    }
  };

  const tableRows = rows.map(r => {
    const rowStyle  = (r.result === 'FAIL' || r.result === 'INSECURE') ? 'background:#fff5f5' : '';
    const scope     = r.type === 'system' ? 'device-level' : r.interface;
    const detailStr = r.type === 'system'
      ? esc(r.detail || '—')
      : visibleProtocols(r).map(p => {
          const s = p.secure === false
            ? 'color:#b91c1c;font-weight:700;background:#fee2e2;padding:0 4px;border-radius:2px;margin:0 1px'
            : p.secure === true
              ? 'color:#166534;font-weight:600;background:#dcfce7;padding:0 4px;border-radius:2px;margin:0 1px'
              : 'color:#374151;background:#f3f4f6;padding:0 4px;border-radius:2px;margin:0 1px';
          return `<span style="${s}">${esc(p.name.toUpperCase())}</span>`;
        }).join('') || '—';
    return `<tr style="${rowStyle}">
      <td>${esc(r.device)}</td>
      <td style="font-size:9px">${esc(r.check || '')}</td>
      <td>${resultCell(r.result)}</td>
      <td><code>${esc(scope)}</code></td>
      <td><code>${esc(r.ip || '—')}</code></td>
      <td>${detailStr}</td>
    </tr>`;
  }).join('');

  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>${esc(title)}</title>
<style>
  body{font-family:Arial,sans-serif;font-size:11px;color:#1a2133;margin:1.5cm}
  h1{font-size:16px;margin-bottom:6px}
  .meta{background:#f3f4f6;border-left:4px solid #3b82f6;padding:8px 12px;border-radius:3px;margin-bottom:14px;font-size:10px}
  .meta table{border:none;width:auto}
  .meta td{padding:1px 14px 1px 0;border:none;background:none}
  .meta td:first-child{font-weight:700;color:#1f2937}
  .stats{display:flex;gap:12px;margin-bottom:14px}
  .stat{padding:4px 12px;border-radius:4px;font-size:11px;font-weight:700}
  .stat-total{background:#f3f4f6;color:#374151}
  .stat-fail{background:#fee2e2;color:#991b1b}
  .stat-pass{background:#dcfce7;color:#166534}
  table.main{width:100%;border-collapse:collapse}
  th{background:#eef1f5;text-align:left;padding:5px 8px;font-size:10px;text-transform:uppercase;border-bottom:2px solid #d0d7e2}
  td{padding:4px 8px;border-bottom:1px solid #e5e7eb;vertical-align:middle}
  code{font-family:monospace;font-size:10px}
  @media print{body{margin:.8cm}.stats{display:block}}
</style></head><body>
<h1>${esc(title)}</h1>
<div class="meta">
  <table>
    <tr><td>ADOM</td><td>${esc(meta.adom || '')}</td></tr>
    <tr><td>Date / Time</td><td>${esc(ts)}</td></tr>
    <tr><td>Devices Reviewed</td><td>${meta.device_count ?? 0}</td></tr>
    <tr><td>Devices in Report</td><td>${deviceCount}</td></tr>
    <tr><td>Findings in Report</td><td>${rows.length}</td></tr>
  </table>
</div>
<div class="stats">
  <span class="stat stat-total">Findings: ${rows.length}</span>
  ${failCount ? `<span class="stat stat-fail">&#9888; Fail/Insecure: ${failCount}</span>` : ''}
  ${passCount ? `<span class="stat stat-pass">&#10003; Pass: ${passCount}</span>` : ''}
</div>
<table class="main">
  <thead><tr><th>Device</th><th>Check</th><th>Result</th><th>Interface/Scope</th><th>IP</th><th>Detail / Protocols</th></tr></thead>
  <tbody>${tableRows}</tbody>
</table>
</body></html>`;

  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); win.focus(); win.print(); }
}

function download(filename, content, mime) {
  const a  = document.createElement('a');
  const bl = new Blob([content], { type: mime });
  a.href   = URL.createObjectURL(bl);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ── Event wiring ───────────────────────────────────────────────────────────── */
document.getElementById('drAdom').addEventListener('change', e => onAdomChange(e.target.value));

document.getElementById('drDeviceSearch').addEventListener('input', updateDeviceMatchCount);

document.getElementById('drChecksAll').addEventListener('click', () => {
  document.querySelectorAll('input[name="dr_check"]').forEach(cb => { cb.checked = true; });
  updateParamsPanel();
});

document.getElementById('drChecksNone').addEventListener('click', () => {
  document.querySelectorAll('input[name="dr_check"]').forEach(cb => { cb.checked = false; });
  updateParamsPanel();
});

document.getElementById('drRunBtn').addEventListener('click', runAnalysis);

document.getElementById('drCancelBtn').addEventListener('click', function () {
  _abortRun = true;
  this.disabled    = true;
  this.textContent = 'Cancelling…';
});

document.getElementById('drFilter').addEventListener('input', e => {
  filterText  = e.target.value;
  currentPage = 1;
  renderTable();
});

document.getElementById('drDeviceFilter').addEventListener('change', e => {
  filterDevice = e.target.value;
  currentPage  = 1;
  renderTable();
});

document.getElementById('drResultFilter').addEventListener('change', e => {
  filterResult = e.target.value;
  currentPage  = 1;
  renderTable();
});

document.getElementById('drPageSize').addEventListener('change', e => {
  pageSize    = parseInt(e.target.value, 10);
  currentPage = 1;
  renderTable();
});

document.getElementById('drPager').addEventListener('click', e => {
  const btn = e.target.closest('button[data-page]');
  if (!btn || btn.disabled) return;
  currentPage = parseInt(btn.dataset.page, 10);
  renderTable();
});

document.getElementById('drProtoAll').addEventListener('click',  () => setAllProtos(true));
document.getElementById('drProtoNone').addEventListener('click', () => setAllProtos(false));

document.getElementById('drExportCsv').addEventListener('click', exportCsv);
document.getElementById('drExportJson').addEventListener('click', exportJson);
document.getElementById('drExportPdf').addEventListener('click', exportPdf);

// Update params panel whenever a check checkbox changes
document.getElementById('drChecks').addEventListener('change', updateParamsPanel);

/* ── Init ───────────────────────────────────────────────────────────────────── */
loadAdoms();
updateParamsPanel();
checkAiSummaryAvailability();

/* ══════════════════════════════════════════════════════════════════════════════
   Hygiene Analysis section
   ══════════════════════════════════════════════════════════════════════════════ */

/* ── Hygiene Analysis state ─────────────────────────────────────────────────── */
let allFindings        = [];
let checkLabels        = {};
let hygieneCurrentPage = 1;
let hygienePageSize    = 25;
let hygieneFilterText  = '';
let filterCheck        = '';
let hygieneMeta        = null;
let pkgPaths           = {};
let _hygieneAiExplainAvailable = false;

async function checkHygieneAiExplainAvailability() {
  try {
    const resp = await fetch('/api/hygiene/ai-explain-status');
    const data = await resp.json();
    _hygieneAiExplainAvailable = !!data.available;
  } catch (e) {
    _hygieneAiExplainAvailable = false;
  }
}

/* ── Hygiene package loader ─────────────────────────────────────────────────── */
async function loadHygienePackages(adom) {
  const sel = document.getElementById('hygienePackage');
  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;
  pkgPaths = {};
  document.getElementById('hygieneRunBtn').disabled = true;
  try {
    const resp = await fetch(`/api/hygiene/adoms/${encodeURIComponent(adom)}/packages`);
    if (resp.status === 401) { location.href = '/login'; return; }
    const pkgs = await resp.json();
    sel.innerHTML = '<option value="">— select package —</option>';
    if (Array.isArray(pkgs)) {
      pkgs.forEach(p => {
        pkgPaths[p.name] = p.path || p.name;
        const opt = document.createElement('option');
        opt.value = p.name; opt.textContent = p.name;
        sel.appendChild(opt);
      });
    }
    sel.disabled = false;
  } catch (_) {
    sel.innerHTML = '<option value="">Failed to load packages</option>';
  }
}

/* ── Run hygiene analysis ───────────────────────────────────────────────────── */
async function runHygieneAnalysis() {
  const adom    = document.getElementById('hygieneAdom').value;
  const pkg     = document.getElementById('hygienePackage').value;
  const path    = pkgPaths[pkg] || pkg;
  const checked = [...document.querySelectorAll('input[name=hygiene_check]:checked')].map(i => i.value);

  if (!adom || !pkg) return;

  const errEl = document.getElementById('hygieneError');
  errEl.style.display = 'none';
  document.getElementById('hygieneResults').style.display = 'none';
  document.getElementById('hygieneRunBtn').disabled = true;
  document.getElementById('hygieneRunning').style.display = '';

  try {
    const resp = await fetch('/api/hygiene/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ adom, package: pkg, path, checks: checked }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      showHygieneError(data.error || 'Analysis failed.');
      return;
    }

    allFindings        = data.findings || [];
    hygieneMeta        = data;
    hygieneCurrentPage = 1;
    hygieneFilterText  = '';
    filterCheck        = '';
    document.getElementById('hygieneFilter').value      = '';
    document.getElementById('hygieneCheckFilter').value = '';
    document.getElementById('hygieneLastRunLabel').textContent =
      `Last run: ${new Date().toLocaleString()} — ${data.policy_count} policies analysed`;

    populateCheckFilter(data.checks_run);
    renderHygieneTable();
    document.getElementById('hygieneResults').style.display = '';
  } catch (err) {
    showHygieneError(err.message);
  } finally {
    document.getElementById('hygieneRunBtn').disabled = false;
    document.getElementById('hygieneRunning').style.display = 'none';
  }
}

function showHygieneError(msg) {
  const el = document.getElementById('hygieneError');
  el.textContent = msg;
  el.style.display = '';
}

/* ── Check filter dropdown population ──────────────────────────────────────── */
function populateCheckFilter(checksRun) {
  const sel = document.getElementById('hygieneCheckFilter');
  sel.innerHTML = '<option value="">All checks</option>';
  checksRun.forEach(key => {
    const opt = document.createElement('option');
    opt.value = key;
    opt.textContent = checkLabels[key] || key;
    sel.appendChild(opt);
  });
}

/* ── Hygiene filtering ──────────────────────────────────────────────────────── */
function hygieneFiltered() {
  return allFindings.filter(f => {
    if (filterCheck && f.check !== filterCheck) return false;
    if (!hygieneFilterText) return true;
    const q = hygieneFilterText.toLowerCase();
    return (
      f.policy_name.toLowerCase().includes(q) ||
      f.policy_id.toLowerCase().includes(q)   ||
      (checkLabels[f.check] || f.check).toLowerCase().includes(q) ||
      f.detail.toLowerCase().includes(q)
    );
  });
}

/* ── Render hygiene table ───────────────────────────────────────────────────── */
function renderHygieneTable() {
  const rows  = hygieneFiltered();
  const total = Math.ceil(rows.length / hygienePageSize) || 1;
  hygieneCurrentPage = Math.min(hygieneCurrentPage, total);
  const slice = rows.slice((hygieneCurrentPage - 1) * hygienePageSize, hygieneCurrentPage * hygienePageSize);

  const meta = hygieneMeta || {};
  document.getElementById('hygieneSummary').textContent =
    `${rows.length === allFindings.length
      ? allFindings.length
      : `${rows.length} of ${allFindings.length}`
    } finding${allFindings.length !== 1 ? 's' : ''} across ${meta.policy_count || '?'} policies` +
    (meta.package ? ` in "${meta.package}"` : '');

  document.getElementById('hygieneCount').textContent =
    `${rows.length} finding${rows.length !== 1 ? 's' : ''} — page ${hygieneCurrentPage} of ${total}`;

  const BADGE_COLORS = {
    unnamed:          '#6366f1',
    unlogged:         '#f59e0b',
    shadow:           '#ef4444',
    disabled:         '#64748b',
    expired:          '#dc2626',
    unhit:            '#0ea5e9',
    over_permissive:  '#f97316',
  };

  const SEVERITY_COLORS = { critical: '#ef4444', high: '#f97316' };

  const tbody = document.getElementById('hygieneTbody');

  const ruleCard = (r, title) => `
    <div class="shadow-rule-card">
      <div class="shadow-rule-title">${esc(title)}</div>
      <div class="shadow-rule-grid">
        <span class="shadow-rule-label">ID</span><span>${esc(r.id)}</span>
        <span class="shadow-rule-label">Name</span><span>${esc(r.name || '—')}</span>
        <span class="shadow-rule-label">Status</span><span style="font-weight:600;color:${r.status==='enable'?'#22c55e':'var(--text-muted)'}">${esc(r.status || '—')}</span>
        <span class="shadow-rule-label">Action</span><span style="font-weight:600;color:${r.action==='deny'||r.action==='block'?'#ef4444':'#22c55e'}">${esc(r.action)}</span>
        <span class="shadow-rule-label">Source</span><span>${esc((r.srcaddr||[]).join(', ') || 'any')}</span>
        <span class="shadow-rule-label">Destination</span><span>${esc((r.dstaddr||[]).join(', ') || 'any')}</span>
        <span class="shadow-rule-label">Service</span><span>${esc((r.service||[]).join(', ') || 'any')}</span>
        ${r.srcintf && r.srcintf.length ? `<span class="shadow-rule-label">Src Interface</span><span>${esc(r.srcintf.join(', '))}</span>` : ''}
        ${r.dstintf && r.dstintf.length ? `<span class="shadow-rule-label">Dst Interface</span><span>${esc(r.dstintf.join(', '))}</span>` : ''}
        ${r.fsso_groups && r.fsso_groups.length ? `<span class="shadow-rule-label">AD Groups</span><span>${esc(r.fsso_groups.join(', '))}</span>` : ''}
        ${r.comment ? `<span class="shadow-rule-label">Comment</span><span style="color:var(--text-muted)">${esc(r.comment)}</span>` : ''}
      </div>
    </div>`;

  const rowsHtml = slice.map((f, i) => {
    const color  = SEVERITY_COLORS[f.severity] || BADGE_COLORS[f.check] || '#94a3b8';
    const label  = checkLabels[f.check] || f.check;
    const rowId  = `finding-detail-${hygieneCurrentPage}-${i}`;
    const isShadow       = f.check === 'shadow' && f.shadow_rule && f.shadowing_rule;
    const hasRuleDetail  = isShadow || !!f.rule_detail;
    const hasDetail      = hasRuleDetail || _hygieneAiExplainAvailable;
    const expandTitle = hasRuleDetail ? 'Show rule details' : 'Explain with AI';
    const expandBtn = hasDetail
      ? ` <button class="shadow-expand-btn" data-target="${rowId}" title="${expandTitle}" aria-expanded="false">&#9660;</button>`
      : '';
    const mainRow = `<tr class="${hasDetail ? 'shadow-finding-row' : ''}" ${hasDetail ? `data-target="${rowId}"` : ''}>
      <td style="font-size:.8rem;color:var(--text-muted)">${esc(String(f.seq || '—'))}</td>
      <td><strong>${esc(f.policy_name)}</strong>${f.policy_id && f.policy_id !== f.policy_name ? `<br><span style="font-size:.75rem;color:var(--text-muted)">id: ${esc(f.policy_id)}</span>` : ''}</td>
      <td><span class="hygiene-badge" style="background:${color}20;color:${color};border-color:${color}40">${esc(label)}</span></td>
      <td style="font-size:.82rem">${esc(f.detail)}${expandBtn}</td>
    </tr>`;

    if (!hasDetail) return mainRow;

    let detailContent;
    if (isShadow) {
      detailContent = ruleCard(f.shadow_rule, 'Shadowed Rule (hidden — never hit)') +
                      ruleCard(f.shadowing_rule, 'Shadowing Rule (earlier — intercepts traffic)');
    } else if (f.rule_detail) {
      detailContent = ruleCard(f.rule_detail, 'Rule Details');
    } else {
      detailContent = '';
    }

    // Absolute index into hygieneFiltered() (not the per-page slice index `i`), so
    // the delegated click handler can look the finding back up correctly
    // regardless of which page is currently rendered.
    const findingIdx = (hygieneCurrentPage - 1) * hygienePageSize + i;
    const explainBlock = _hygieneAiExplainAvailable ? `
      <div class="hygiene-ai-explain" style="margin-top:8px">
        <button class="btn btn-secondary hygiene-explain-btn" type="button" data-finding-idx="${findingIdx}">Explain</button>
        <div class="hygiene-explain-output" style="margin-top:6px;font-size:.85rem;line-height:1.5;white-space:pre-wrap"></div>
      </div>` : '';

    const detailRow = `<tr id="${rowId}" class="shadow-detail-row" style="display:none">
      <td colspan="4">
        <div class="shadow-detail-wrap">${detailContent}${explainBlock}</div>
      </td>
    </tr>`;
    return mainRow + detailRow;
  }).join('') || `<tr><td colspan="4" class="empty-state" style="padding:.85rem 1rem">No findings match your filter.</td></tr>`;

  tbody.innerHTML = rowsHtml;
  renderHygienePagination(total);
}

/* ── Hygiene pagination ─────────────────────────────────────────────────────── */
function renderHygienePagination(total) {
  const pg = document.getElementById('hygienePagination');
  if (total <= 1) { pg.innerHTML = ''; return; }

  function btn(label, page, disabled, active) {
    return `<button class="pg-btn${active ? ' active' : ''}" data-hpage="${page}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  }
  let html = btn('&laquo;&laquo;', 1, hygieneCurrentPage === 1, false);
  html += btn('&lsaquo;', hygieneCurrentPage - 1, hygieneCurrentPage === 1, false);
  const s = Math.max(1, hygieneCurrentPage - 2), e = Math.min(total, s + 4);
  for (let i = s; i <= e; i++) html += btn(i, i, false, i === hygieneCurrentPage);
  html += btn('&rsaquo;', hygieneCurrentPage + 1, hygieneCurrentPage === total, false);
  html += btn('&raquo;&raquo;', total, hygieneCurrentPage === total, false);
  pg.innerHTML = html;
}

/* ── Find Unused Objects ────────────────────────────────────────────────────── */
async function runFindUnused() {
    const adom = document.getElementById('hygieneAdom').value;
    const pkg  = document.getElementById('hygienePackage').value;
    if (!adom || !pkg) return;

    const btn     = document.getElementById('findUnusedBtn');
    const spinner = document.getElementById('unusedSpinner');
    const panel   = document.getElementById('unusedObjectsPanel');
    const content = document.getElementById('unusedObjectsContent');

    btn.disabled = true;
    spinner.style.display = '';
    panel.style.display = '';
    content.innerHTML = '<div class="text-muted py-3 text-center">Scanning objects…</div>';

    try {
        const path   = pkgPaths[pkg] || pkg;
        const scope  = document.getElementById('unusedScope')?.value || 'all';
        const params = new URLSearchParams({ adom, pkg: path, scope });
        const resp = await fetch(`/api/hygiene/unused-objects?${params}`);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            content.innerHTML = `<div class="alert alert-danger mb-0">${esc(err.error || 'Failed to check unused objects.')}</div>`;
            return;
        }
        const data = await resp.json();
        renderUnusedObjects(data);
    } catch (err) {
        content.innerHTML = `<div class="alert alert-danger mb-0">${esc(err.message)}</div>`;
    } finally {
        btn.disabled = false;
        spinner.style.display = 'none';
    }
}

/* ── Unused Objects state ────────────────────────────────────────────────── */
let unusedAllRows  = [];
let unusedFiltered = [];
let unusedPage     = 1;
let unusedPageSize = 25;
let unusedFilter   = '';

function renderUnusedObjects(data) {
    window._unusedObjectsData = data;
    const totalUnused = data.unused_addresses.length + data.unused_services.length;

    document.getElementById('unusedCsvBtn').style.display = totalUnused ? '' : 'none';
    document.getElementById('unusedJsonBtn').style.display = totalUnused ? '' : 'none';

    if (totalUnused === 0) {
        unusedAllRows = [];
        document.getElementById('unusedObjectsContent').innerHTML =
            '<div class="alert alert-success mb-0">No unused objects found in this package.</div>';
        return;
    }

    unusedAllRows = [
        ...data.unused_addresses.map(o => ({ name: o.name, category: 'address', type: o.type, detail: o.detail || '' })),
        ...data.unused_services.map(o  => ({ name: o.name, category: 'service', type: o.type, detail: o.detail || '' })),
    ];
    unusedPage   = 1;
    unusedFilter = '';
    renderUnusedTable();
}

function renderUnusedTable() {
    const content = document.getElementById('unusedObjectsContent');
    const data    = window._unusedObjectsData;
    if (!data) return;

    const q = unusedFilter.toLowerCase();
    unusedFiltered = q
        ? unusedAllRows.filter(r => r.name.toLowerCase().includes(q) || r.detail.toLowerCase().includes(q))
        : unusedAllRows.slice();

    const total = Math.ceil(unusedFiltered.length / unusedPageSize) || 1;
    unusedPage  = Math.min(Math.max(1, unusedPage), total);
    const slice = unusedFiltered.slice((unusedPage - 1) * unusedPageSize, unusedPage * unusedPageSize);

    const psOpts = [10, 25, 50, 100].map(n =>
        `<option value="${n}"${n === unusedPageSize ? ' selected' : ''}>${n}</option>`).join('');

    function pgb(lbl, pg, dis, act) {
        return `<button class="pg-btn${act ? ' active' : ''}" data-uopage="${pg}"${dis ? ' disabled' : ''}>${lbl}</button>`;
    }
    const s = Math.max(1, unusedPage - 2), e = Math.min(total, s + 4);
    let pgHtml = pgb('&laquo;&laquo;', 1, unusedPage === 1, false);
    pgHtml += pgb('&lsaquo;', unusedPage - 1, unusedPage === 1, false);
    for (let i = s; i <= e; i++) pgHtml += pgb(i, i, false, i === unusedPage);
    pgHtml += pgb('&rsaquo;', unusedPage + 1, unusedPage === total, false);
    pgHtml += pgb('&raquo;&raquo;', total, unusedPage === total, false);

    const rows = slice.map(o => {
        const bc  = o.category === 'address' ? 'bg-primary' : 'bg-secondary';
        const lbl = o.type === 'group' ? (o.category === 'address' ? 'address group' : 'service group') : o.category;
        return `<tr><td>${esc(o.name)}</td><td><span class="badge ${bc}">${esc(lbl)}</span></td></tr>`;
    }).join('');

    const showPag = unusedFiltered.length > 10;
    content.innerHTML = `
        <div class="d-flex align-items-center gap-2 mb-2 flex-wrap">
            <input type="text" id="unusedFilterInput" class="form-control form-control-sm" style="max-width:260px"
                placeholder="Filter by name or IP…" value="${esc(unusedFilter)}">
            <span class="text-muted small ms-auto">
                ${unusedFiltered.length} of ${unusedAllRows.length} object(s) &mdash; ${esc(data.checked_at)}
            </span>
        </div>
        <table class="table table-sm table-hover mb-0">
            <thead><tr><th>Object Name</th><th>Type</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>
        ${showPag ? `<div class="d-flex align-items-center justify-content-between mt-2 flex-wrap gap-2">
            <div class="d-flex align-items-center gap-1">
                <label class="text-muted small me-1">Per page:</label>
                <select id="unusedPageSizeSelect" class="form-select form-select-sm" style="width:auto">${psOpts}</select>
            </div>
            <div class="pg-bar">${pgHtml}</div>
            <div class="text-muted small">Page ${unusedPage} of ${total}</div>
        </div>` : ''}`;

    const fi = document.getElementById('unusedFilterInput');
    fi.addEventListener('input', function() {
        unusedFilter = this.value;
        unusedPage   = 1;
        renderUnusedTable();
    });
    if (unusedFilter) { fi.focus(); fi.setSelectionRange(fi.value.length, fi.value.length); }
    const psSel = document.getElementById('unusedPageSizeSelect');
    if (psSel) psSel.addEventListener('change', function() {
        unusedPageSize = parseInt(this.value, 10);
        unusedPage     = 1;
        renderUnusedTable();
    });
}

function exportUnusedCsv() {
    const data = window._unusedObjectsData;
    if (!data || !unusedAllRows.length) return;
    const rows = unusedFiltered.length ? unusedFiltered : unusedAllRows;
    const csvRows = [['Name', 'Category', 'Type'], ...rows.map(o => [o.name, o.category, o.type])];
    const csv = csvRows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const pkg = (data.pkg || 'pkg').replace(/\//g, '_');
    download(`unused-objects-${data.adom}-${pkg}.csv`, csv, 'text/csv');
}

function exportUnusedJson() {
    const data = window._unusedObjectsData;
    if (!data || !unusedAllRows.length) return;
    const rows    = unusedFiltered.length ? unusedFiltered : unusedAllRows;
    const payload = { adom: data.adom, pkg: data.pkg, checked_at: data.checked_at,
                      filter: unusedFilter || null, objects: rows };
    download(`unused-objects-${data.adom}.json`, JSON.stringify(payload, null, 2), 'application/json');
}

/* ── Hygiene exports ────────────────────────────────────────────────────────── */
function exportHygieneCsv() {
  const rows = hygieneFiltered();
  const header = ['Seq', 'Policy ID', 'Policy Name', 'Check', 'Detail'];
  const lines  = [header.join(',')];
  rows.forEach(f => {
    lines.push([
      f.seq,
      `"${String(f.policy_id).replace(/"/g, '""')}"`,
      `"${String(f.policy_name).replace(/"/g, '""')}"`,
      `"${(checkLabels[f.check] || f.check).replace(/"/g, '""')}"`,
      `"${String(f.detail).replace(/"/g, '""')}"`,
    ].join(','));
  });
  download('hygiene_report.csv', lines.join('\r\n'), 'text/csv');
}

function exportHygieneJson() {
  const payload = {
    meta: hygieneMeta,
    generated: new Date().toISOString(),
    findings: hygieneFiltered().map(f => ({ ...f, check_label: checkLabels[f.check] || f.check })),
  };
  download('hygiene_report.json', JSON.stringify(payload, null, 2), 'application/json');
}

function exportHygienePdf() {
  const rows = hygieneFiltered();
  const meta = hygieneMeta || {};
  const ts = new Date().toLocaleString();
  const title = `Rule Review — ${meta.adom || ''} / ${meta.package || ''}`;

  const tableRows = rows.map(f => `
    <tr>
      <td>${esc(String(f.seq || '—'))}</td>
      <td>${esc(f.policy_name)}<br><small>${esc(f.policy_id)}</small></td>
      <td>${esc(checkLabels[f.check] || f.check)}</td>
      <td>${esc(f.detail)}</td>
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
  small{color:#5a6478}
  @media print{body{margin:1cm}}
</style></head><body>
<h1>${esc(title)}</h1>
<div class="meta">Generated ${ts} &bull; ${rows.length} findings &bull; ${meta.policy_count || '?'} policies analysed</div>
<table>
  <thead><tr><th>#</th><th>Rule</th><th>Check</th><th>Detail</th></tr></thead>
  <tbody>${tableRows}</tbody>
</table>
</body></html>`;

  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); win.focus(); win.print(); }
}

/* ── Capture check labels from the rendered checkboxes ─────────────────────── */
function captureCheckLabels() {
  document.querySelectorAll('input[name=hygiene_check]').forEach(inp => {
    const label = inp.closest('label');
    if (label) checkLabels[inp.value] = label.textContent.trim();
  });
}

/* ── AI Explain (single finding) ──────────────────────────────────────────── */
async function runFindingExplain(btn) {
  const idx = parseInt(btn.dataset.findingIdx, 10);
  const finding = hygieneFiltered()[idx];
  const out = btn.nextElementSibling;
  if (!finding || !out) return;
  btn.disabled = true;
  btn.textContent = 'Explaining…';
  out.textContent = '';
  try {
    const resp = await fetch('/api/hygiene/explain-finding', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(finding),
    });
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    out.textContent = data.narrative || ('AI explanation unavailable: ' + (data.narrative_error || data.error || 'unknown error'));
  } catch (e) {
    out.textContent = 'AI explanation request failed: ' + e.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Explain';
  }
}

/* ── ADOM loader for Hygiene Analysis selector ──────────────────────────────── */
async function loadHygieneAdoms() {
  try {
    const resp = await fetch('/api/adoms');
    if (resp.status === 401) { location.href = '/login'; return; }
    const adoms = await resp.json();
    if (!Array.isArray(adoms)) return;
    const sel = document.getElementById('hygieneAdom');
    if (!sel) return;
    adoms.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a.name; opt.textContent = a.name;
      sel.appendChild(opt);
    });
  } catch (_) {}
}

/* ── Hygiene Analysis event listeners ─────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', function () {
  loadHygieneAdoms();
  captureCheckLabels();
  checkHygieneAiExplainAvailability();

  document.getElementById('hygieneAdom').addEventListener('change', function () {
    if (this.value) loadHygienePackages(this.value);
    else {
      const sel = document.getElementById('hygienePackage');
      sel.innerHTML = '<option value="">— select package —</option>';
      sel.disabled = true;
      document.getElementById('hygieneRunBtn').disabled = true;
      document.getElementById('findUnusedBtn').disabled = true;
    }
  });

  document.getElementById('hygienePackage').addEventListener('change', function () {
    document.getElementById('hygieneRunBtn').disabled = !this.value;
    document.getElementById('findUnusedBtn').disabled = !this.value;
  });

  document.getElementById('hygieneRunBtn').addEventListener('click', runHygieneAnalysis);

  document.getElementById('hygieneFilter').addEventListener('input', function () {
    hygieneFilterText  = this.value;
    hygieneCurrentPage = 1;
    renderHygieneTable();
  });

  document.getElementById('hygienePageSize').addEventListener('change', function () {
    hygienePageSize    = parseInt(this.value, 10);
    hygieneCurrentPage = 1;
    renderHygieneTable();
  });

  document.getElementById('hygieneCheckFilter').addEventListener('change', function () {
    filterCheck        = this.value;
    hygieneCurrentPage = 1;
    renderHygieneTable();
  });

  document.getElementById('hygienePagination').addEventListener('click', e => {
    const btn = e.target.closest('[data-hpage]');
    if (!btn || btn.disabled) return;
    hygieneCurrentPage = parseInt(btn.dataset.hpage, 10);
    renderHygieneTable();
  });

  document.getElementById('hygieneTbody').addEventListener('click', e => {
    const expandBtn = e.target.closest('.shadow-expand-btn');
    if (expandBtn) {
      const targetId = expandBtn.dataset.target;
      const detailRow = document.getElementById(targetId);
      if (!detailRow) return;
      const open = detailRow.style.display !== 'none';
      detailRow.style.display = open ? 'none' : '';
      expandBtn.setAttribute('aria-expanded', String(!open));
      expandBtn.innerHTML = open ? '&#9660;' : '&#9650;';
      return;
    }

    const explainBtn = e.target.closest('.hygiene-explain-btn');
    if (explainBtn) runFindingExplain(explainBtn);
  });

  document.getElementById('hygieneCloseBtn').addEventListener('click', () => {
    document.getElementById('hygieneResults').style.display = 'none';
    allFindings = [];
    document.getElementById('hygienePackage').value = '';
    document.getElementById('hygienePackage').disabled = true;
    document.getElementById('hygieneAdom').value = '';
    document.getElementById('hygieneRunBtn').disabled = true;
  });

  document.getElementById('exportCsv').addEventListener('click', exportHygieneCsv);
  document.getElementById('exportJson').addEventListener('click', exportHygieneJson);
  document.getElementById('exportPdf').addEventListener('click', exportHygienePdf);

  document.getElementById('findUnusedBtn')?.addEventListener('click', runFindUnused);
  document.getElementById('unusedCsvBtn')?.addEventListener('click', exportUnusedCsv);
  document.getElementById('unusedJsonBtn')?.addEventListener('click', exportUnusedJson);

  document.getElementById('unusedObjectsContent')?.addEventListener('click', function(e) {
    const btn = e.target.closest('[data-uopage]');
    if (!btn || btn.disabled) return;
    unusedPage = parseInt(btn.dataset.uopage, 10);
    renderUnusedTable();
  });
});
