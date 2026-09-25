'use strict';

/* ── Utilities ─────────────────────────────────────────────────────────────── */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function download(filename, content, mime) {
  const a  = document.createElement('a');
  const bl = new Blob([content], { type: mime });
  a.href   = URL.createObjectURL(bl);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ── State ──────────────────────────────────────────────────────────────────── */
let allDevices     = [];
let filteredDevices = [];
let currentPage    = 1;
let pageSize       = 25;
let filterText     = '';
let pendingOnly    = false;
let currentAdom    = '';
let currentDevice  = null;
let currentDiff    = null;
let exportQueue    = [];  // [{device, ip, adom, summary, vdoms, raw, timestamp}]
let _previewAbort  = null;
let vdomPageState  = new Map(); // vdom.name → { page, pageSize }
let bulkRunning   = false;   // true while a bulk export run is in progress
let bulkCancelled = false;   // set by cancelBulkExport() to abort the loop
let _beforeUnloadHandler = null;
let _pcAiAssistAvailable = false;

/* ── AI diff summary ────────────────────────────────────────────────────────── */
async function checkPcAiSummaryAvailability() {
  try {
    const resp = await fetch('/api/pending-changes/ai-summary-status');
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    _pcAiAssistAvailable = !!data.available;
  } catch (e) {
    _pcAiAssistAvailable = false;
  }
}

// #pcAiSummaryBox is a persistent element (see template comment) that survives
// device switches, but the fetch it triggers does not — a slow AI-summary
// request for device A can resolve after the user has already switched to
// device B. box.dataset.device tags which device the box (and any in-flight
// request) currently belongs to; every place that would write into the box
// checks this tag first and silently discards stale results instead of
// misattributing device A's narrative to device B.
function hidePcAiSummaryBox() {
  const box = document.getElementById('pcAiSummaryBox');
  if (box) { box.style.display = 'none'; box.dataset.device = ''; }
}

// Mirror app/pending_changes_ai.py's _trim_device(): cap total change lines
// across all VDOMs at _PC_AI_MAX_LINES_PER_DEVICE so the POST body stays well
// under Flask's MAX_CONTENT_LENGTH — the server trims to the same budget
// anyway, so sending more only risks a 413 on a large multi-VDOM diff.
const _PC_AI_MAX_LINES_PER_DEVICE = 30;
function trimVdomsForAiSummary(vdoms) {
  let remaining = _PC_AI_MAX_LINES_PER_DEVICE;
  const out = [];
  for (const vdom of (vdoms || [])) {
    if (remaining <= 0) break;
    const changes = (vdom.changes || []).slice(0, remaining);
    remaining -= changes.length;
    out.push({ name: vdom.name || 'root', changes });
  }
  return out;
}

function showPcAiSummaryBoxIfAvailable(adom, device, diffResult) {
  const box = document.getElementById('pcAiSummaryBox');
  if (!box) return;
  const hasChanges = (diffResult.vdoms || []).some(v => (v.changes || []).length);
  if (!_pcAiAssistAvailable || !hasChanges) { box.style.display = 'none'; box.dataset.device = ''; return; }
  box.style.display = '';
  box.dataset.device = device;
  const btn = document.getElementById('pcAiSummaryBtn');
  const out = document.getElementById('pcAiSummaryOutput');
  out.textContent = '';
  btn.disabled = false;
  btn.textContent = 'Summarize with AI';
  btn.onclick = async () => {
    const requestDevice = device; // pin the device this click belongs to
    btn.disabled = true;
    btn.textContent = 'Summarizing…';
    out.textContent = '';
    try {
      const resp = await fetch(
        `/api/pending-changes/adoms/${encodeURIComponent(adom)}/device/${encodeURIComponent(device)}/ai-summary`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ summary: diffResult.summary, vdoms: trimVdomsForAiSummary(diffResult.vdoms) }),
        }
      );
      if (resp.status === 401) { location.href = '/login'; return; }
      if (resp.status === 413) {
        if (box.dataset.device !== requestDevice) return;
        out.textContent = 'AI summary unavailable: diff too large to summarize';
        return;
      }
      const data = await resp.json();
      if (box.dataset.device !== requestDevice) return; // user switched devices while this was in flight
      out.textContent = data.narrative || ('AI summary unavailable: ' + (data.narrative_error || data.error || 'unknown error'));
    } catch (e) {
      if (box.dataset.device !== requestDevice) return;
      out.textContent = 'AI summary request failed: ' + e.message;
    } finally {
      if (box.dataset.device === requestDevice) {
        btn.disabled = false;
        btn.textContent = 'Summarize with AI';
      }
    }
  };
}

/* ── Status badges ───────────────────────────────────────────────────────────── */

// Single-badge for the device table — shows only the highest-priority state so
// rows stay compact and single-line.
function tableBadge(confStatus, dbStatus, pkgStatus) {
  const s = 'display:inline-block;padding:1px 7px;border-radius:3px;font-size:.72rem;font-weight:600;white-space:nowrap;';
  if (confStatus === 'outofsync')
    return `<span style="${s}background:#fef3c7;color:#92400e;border:1px solid #fcd34d" title="Device config is out of sync with FMG">Out of Sync</span>`;
  if (dbStatus === 'modified')
    return `<span style="${s}background:#fef3c7;color:#92400e;border:1px solid #fcd34d" title="FMG database has pending changes not yet installed">Pending</span>`;
  if (pkgStatus === 'modified')
    return `<span style="${s}background:#fef3c7;color:#92400e;border:1px solid #fcd34d" title="Policy package modified in FMG, not yet installed">Pkg Pending</span>`;
  if (confStatus === 'insync')
    return `<span style="${s}background:#dcfce7;color:#166534;border:1px solid #86efac">In Sync</span>`;
  return `<span style="${s}background:#f3f4f6;color:#6b7280;border:1px solid #d1d5db">Unknown</span>`;
}

// Multi-badge for the diff panel header — shows the full picture since there's room.
function syncBadge(confStatus, dbStatus, pkgStatus) {
  const s = 'display:inline-block;padding:1px 7px;border-radius:3px;font-size:.75rem;font-weight:600;white-space:nowrap;';
  let badge = '';
  switch (confStatus) {
    case 'outofsync':
      badge += `<span style="${s}background:#fef3c7;color:#92400e;border:1px solid #fcd34d">Out of Sync</span>`;
      break;
    case 'insync':
      badge += `<span style="${s}background:#dcfce7;color:#166534;border:1px solid #86efac">In Sync</span>`;
      break;
    default:
      badge += `<span style="${s}background:#f3f4f6;color:#6b7280;border:1px solid #d1d5db">Unknown</span>`;
  }
  if (dbStatus === 'modified')
    badge += ` <span style="${s}background:#fef3c7;color:#92400e;border:1px solid #fcd34d" title="FMG database has pending changes not yet installed to the device">Pending Install</span>`;
  if (pkgStatus === 'modified' && dbStatus !== 'modified')
    badge += ` <span style="${s}background:#fef3c7;color:#92400e;border:1px solid #fcd34d" title="Policy package has been modified in FMG but not yet installed">Pkg Modified</span>`;
  return badge;
}

/* ── ADOM loading ───────────────────────────────────────────────────────────── */
async function fetchAdoms() {
  const sel = document.getElementById('pcAdom');
  try {
    const resp = await fetch('/api/pending-changes/adoms');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const adoms = await resp.json();
    sel.innerHTML = '<option value="">— select ADOM —</option>';
    adoms.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a.name;
      opt.textContent = a.name;
      sel.appendChild(opt);
    });
  } catch (e) {
    showDeviceError('Failed to load ADOM list: ' + e.message);
  }
}

/* ── Device loading ─────────────────────────────────────────────────────────── */
async function fetchDevices(adom) {
  currentAdom = adom;
  allDevices = [];
  filteredDevices = [];
  currentPage = 1;
  clearDiffPanel();
  updateExportAllState();          // disable button immediately on ADOM change
  if (!adom) { renderDeviceTable(); return; }

  const loading = document.getElementById('pcAdomLoading');
  loading.style.display = '';
  try {
    const resp = await fetch(`/api/pending-changes/adoms/${encodeURIComponent(adom)}/devices`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    allDevices = await resp.json();
    applyFilters();
  } catch (e) {
    showDeviceError('Failed to load devices: ' + e.message);
  } finally {
    loading.style.display = 'none';
    updateExportAllState();        // enable/disable based on loaded devices
  }
}

/* ── Filtering ──────────────────────────────────────────────────────────────── */
function applyFilters() {
  const q = filterText.toLowerCase();
  filteredDevices = allDevices.filter(d => {
    if (pendingOnly && d.conf_status !== 'outofsync' && d.db_status !== 'modified' && d.pkg_status !== 'modified') return false;
    if (!q) return true;
    return (d.name || '').toLowerCase().includes(q) ||
           (d.ip   || '').toLowerCase().includes(q);
  });
  currentPage = 1;
  renderDeviceTable();
}

/* ── Device table rendering ─────────────────────────────────────────────────── */
function renderDeviceTable() {
  const tbody = document.getElementById('pcDeviceTbody');
  const pager = document.getElementById('pcPager');
  const count = document.getElementById('pcDeviceCount');

  if (!filteredDevices.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">' +
      (currentAdom ? 'No devices match the current filter.' : 'Select an ADOM to load devices.') +
      '</td></tr>';
    pager.innerHTML = '';
    count.textContent = '';
    return;
  }

  const start = (currentPage - 1) * pageSize;
  const page  = filteredDevices.slice(start, start + pageSize);

  tbody.innerHTML = page.map(d => {
    const selected = currentDevice && currentDevice.name === d.name ? 'style="background:var(--surface-alt)"' : '';
    return `<tr ${selected} style="cursor:pointer" data-device="${esc(d.name)}"
              onclick="selectDevice(${esc(JSON.stringify(d))})">
      <td><strong>${esc(d.name)}</strong></td>
      <td><code style="font-size:.82rem">${esc(d.ip || '—')}</code></td>
      <td style="font-size:.82rem">${esc(d.platform || '—')}</td>
      <td>${tableBadge(d.conf_status, d.db_status, d.pkg_status)}</td>
    </tr>`;
  }).join('');

  // Pagination
  const totalPages = Math.ceil(filteredDevices.length / pageSize);
  pager.innerHTML = buildPager(currentPage, totalPages);
  count.textContent = `${filteredDevices.length} device${filteredDevices.length !== 1 ? 's' : ''}`;
}

function buildPager(current, total) {
  if (total <= 1) return '';
  const btn = (label, page, disabled) =>
    `<button class="btn btn-xs" onclick="goPage(${page})" ${disabled ? 'disabled' : ''}>${label}</button>`;
  let html = btn('&laquo;', 1, current === 1) + btn('&lsaquo;', current - 1, current === 1);
  const start = Math.max(1, current - 2);
  const end   = Math.min(total, current + 2);
  if (start > 1) html += '<span style="padding:0 4px">…</span>';
  for (let p = start; p <= end; p++) {
    html += `<button class="btn btn-xs${p === current ? ' btn-primary' : ''}" onclick="goPage(${p})">${p}</button>`;
  }
  if (end < total) html += '<span style="padding:0 4px">…</span>';
  html += btn('&rsaquo;', current + 1, current === total) + btn('&raquo;', total, current === total);
  return html;
}

function goPage(p) {
  currentPage = p;
  renderDeviceTable();
}

/* ── Device selection + preview ─────────────────────────────────────────────── */
function selectDevice(device) {
  currentDevice = device;
  renderDeviceTable(); // re-render to highlight selected row
  loadPreview(currentAdom, device.name);
}

async function loadPreview(adom, deviceName) {
  vdomPageState = new Map();
  if (_previewAbort) { _previewAbort.abort(); }
  _previewAbort = new AbortController();
  const signal = _previewAbort.signal;

  currentDiff = null;
  showDiffSpinner(deviceName, 'Starting…');

  // Step 1: POST to start the async task, get task_id back immediately
  let taskId = null;
  try {
    const resp = await fetch(
      `/api/pending-changes/adoms/${encodeURIComponent(adom)}/device/${encodeURIComponent(deviceName)}/preview`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}), signal }
    );
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
      throw new Error(err.error || `HTTP ${resp.status}`);
    }
    const data = await resp.json();
    taskId = data.task_id;
  } catch (e) {
    if (e.name === 'AbortError') return;
    showDiffError(deviceName, e.message);
    return;
  }

  // Step 2: Poll until done or error, updating the spinner label each cycle
  const POLL_INTERVAL_MS = 2000;
  const poll = async () => {
    if (signal.aborted) return;
    try {
      const resp = await fetch(`/api/pending-changes/task/${encodeURIComponent(taskId)}`, { signal });
      if (signal.aborted) return;
      if (!resp.ok) {
        showDiffError(deviceName, `Poll failed: HTTP ${resp.status}`);
        return;
      }
      const task = await resp.json();
      if (task.status === 'running') {
        showDiffSpinner(deviceName, task.step || 'Working…');
        setTimeout(poll, POLL_INTERVAL_MS);
      } else if (task.status === 'done') {
        currentDiff = task.result;
        currentDiff.adom = adom;
        currentDiff.timestamp = new Date().toISOString();
        renderDiffPanel(currentDiff);
        showPcAiSummaryBoxIfAvailable(adom, deviceName, currentDiff);
      } else {
        showDiffError(deviceName, task.error || 'Unknown error from server.');
      }
    } catch (e) {
      if (e.name === 'AbortError') return;
      showDiffError(deviceName, e.message);
    }
  };
  setTimeout(poll, POLL_INTERVAL_MS);
}

/* ── Per-VDOM pagination ────────────────────────────────────────────────── */
function setVdomPage(vdomName, newPage, newPageSize) {
  const current = vdomPageState.get(vdomName) || { page: 1, pageSize: 25 };
  vdomPageState.set(vdomName, {
    page: newPage,
    pageSize: newPageSize != null ? newPageSize : current.pageSize,
  });
  renderDiffPanel(currentDiff);
}

/* ── Diff panel rendering ───────────────────────────────────────────────────── */
function clearDiffPanel() {
  currentDevice = null;
  currentDiff   = null;
  hidePcAiSummaryBox();
  document.getElementById('pcDiffPanel').innerHTML =
    '<p style="color:var(--text-muted);font-style:italic">Select a device to view pending changes.</p>';
}

function showDiffSpinner(deviceName, step) {
  hidePcAiSummaryBox();
  document.getElementById('pcDiffPanel').innerHTML = `
    <div style="padding:1.5rem;text-align:center">
      <div class="spinner" style="display:inline-block;width:28px;height:28px;border:3px solid var(--border);
           border-top-color:var(--primary,#3b82f6);border-radius:50%;animation:spin 0.8s linear infinite"></div>
      <p style="margin-top:.75rem;color:var(--text-muted);font-style:italic">
        <strong>${esc(deviceName)}</strong>: ${esc(step || 'Starting…')}
      </p>
    </div>
    <style>@keyframes spin{to{transform:rotate(360deg)}}</style>`;
}

function showDiffError(deviceName, msg) {
  hidePcAiSummaryBox();
  document.getElementById('pcDiffPanel').innerHTML =
    `<div class="alert alert-danger"><strong>${esc(deviceName)}</strong>: ${esc(msg)}</div>`;
}

function renderDiffPanel(diff) {
  const hasChanges = diff.vdoms.some(v => v.changes.length > 0);

  // Summary tiles
  const summaryKeys = [
    ['firewall_policy', 'Firewall Policy'],
    ['routing',         'Routing'],
    ['address',         'Address'],
    ['service',         'Service'],
    ['system',          'System'],
    ['other',           'Other'],
  ];
  const tilesHtml = summaryKeys
    .filter(([k]) => diff.summary[k] > 0)
    .map(([k, label]) =>
      `<div style="display:inline-flex;flex-direction:column;align-items:center;
                   padding:.4rem .75rem;border-radius:6px;background:var(--surface-alt);
                   border:1px solid var(--border);margin:.2rem">
        <span style="font-size:1.2rem;font-weight:700">${diff.summary[k]}</span>
        <span style="font-size:.72rem;color:var(--text-muted)">${label}</span>
       </div>`
    ).join('');

  // VDOM diff blocks — show ALL vdoms; vdoms with no changes get a brief note.
  const vdomsHtml = diff.vdoms.map(vdom => {
    if (!vdom.changes.length) {
      return `<details style="margin-top:.6rem">
        <summary style="cursor:pointer;font-weight:500;font-size:.82rem;padding:.2rem 0;
                         color:var(--text-muted);letter-spacing:.03em;text-transform:uppercase">
          vdom: ${esc(vdom.name)}
        </summary>
        <p style="color:var(--text-muted);font-style:italic;font-size:.8rem;margin:.4rem 0 0">No pending changes.</p>
      </details>`;
    }

    if (!vdomPageState.has(vdom.name)) {
      vdomPageState.set(vdom.name, { page: 1, pageSize: 25 });
    }
    const { page, pageSize: ps } = vdomPageState.get(vdom.name);
    const totalLines  = vdom.changes.length;
    const totalPages  = Math.ceil(totalLines / ps);
    const sliceStart  = (page - 1) * ps;
    const pageChanges = vdom.changes.slice(sliceStart, sliceStart + ps);

    const linesHtml = pageChanges.map(c => {
      const cls    = c.type === 'add' ? 'diff-add' : c.type === 'remove' ? 'diff-remove' : 'diff-modify';
      const prefix = c.type === 'add' ? '+' : c.type === 'remove' ? '-' : '~';
      return `<span class="${cls}" style="display:block;padding-left:1.4em;text-indent:-1.4em">${esc(prefix + ' ' + c.line)}</span>`;
    }).join('');

    const vn   = JSON.stringify(vdom.name); // safe JS string literal for onclick
    const pbtn = (label, p, disabled) =>
      `<button class="btn btn-xs" onclick='setVdomPage(${vn},${p},null)' ${disabled ? 'disabled' : ''}>${label}</button>`;

    const paginationHtml = totalLines > ps ? `
      <div style="display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;margin-top:.4rem;font-size:.8rem">
        ${pbtn('&laquo;', 1,           page === 1)}
        ${pbtn('&lsaquo;', page - 1,  page === 1)}
        <span style="color:var(--text-muted);padding:0 .2rem">Page ${page} of ${totalPages}</span>
        ${pbtn('&rsaquo;', page + 1,  page === totalPages)}
        ${pbtn('&raquo;', totalPages,  page === totalPages)}
        <select class="form-select form-select-sm" style="width:70px;font-size:.8rem"
                onchange='setVdomPage(${vn}, 1, parseInt(this.value, 10))'>
          ${[10, 25, 50].map(n => `<option value="${n}"${n === ps ? ' selected' : ''}>${n}</option>`).join('')}
        </select>
        <span style="color:var(--text-muted)">${totalLines} lines total</span>
      </div>` : '';

    return `<details open style="margin-top:.6rem">
      <summary style="cursor:pointer;font-weight:500;font-size:.82rem;padding:.2rem 0;
                       color:var(--text-muted);letter-spacing:.03em;text-transform:uppercase">
        vdom: ${esc(vdom.name)}
      </summary>
      <pre class="diff-block" style="background:var(--surface-alt);border:1px solid var(--border);
           border-radius:4px;padding:.75rem;white-space:pre-wrap;overflow-wrap:break-word;font-size:.8rem;margin:.4rem 0 0">${linesHtml}</pre>
      ${paginationHtml}
    </details>`;
  }).join('');

  const alreadyQueued = exportQueue.some(q => q.device === diff.device && q.adom === diff.adom);
  const addBtnLabel   = alreadyQueued ? 'Already in Queue' : '+ Add to Export Queue';

  document.getElementById('pcDiffPanel').innerHTML = `
    <div style="display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;margin-bottom:.5rem">
      <h4 style="margin:0;flex-shrink:0">${esc(diff.device)}</h4>
      <code style="font-size:.82rem;color:var(--text-muted);flex-shrink:0">${esc(diff.ip || '')}</code>
      <span style="display:flex;gap:.3rem;flex-wrap:nowrap;align-items:center">
        ${syncBadge(diff.conf_status, diff.db_status, diff.pkg_status)}
      </span>
      <span style="margin-left:auto;display:flex;align-items:center;gap:.5rem;flex-shrink:0">
        <button class="btn btn-sm btn-secondary" id="pcAddToQueue" onclick="addToQueue()"
                ${alreadyQueued ? 'disabled' : ''}
                title="Accumulate multiple devices into a single export document for use in a change record.">
          ${addBtnLabel}
        </button>
        <span style="cursor:default;font-size:.8rem;color:var(--text-muted);border:1px solid var(--border);
                     border-radius:50%;width:1.2rem;height:1.2rem;display:inline-flex;align-items:center;
                     justify-content:center;flex-shrink:0"
              title="CLI diff format: lines prefixed + are additions, - are deletions, ~ are modifications. Changes are grouped by VDOM.">?</span>
      </span>
    </div>

    ${tilesHtml ? `<div style="display:flex;flex-wrap:wrap;gap:.3rem;margin-bottom:.6rem">${tilesHtml}</div>` : ''}

    ${hasChanges ? vdomsHtml : '<p style="color:var(--text-muted);font-style:italic">No pending changes found for this device.</p>'}

    <style>
      .diff-add    { color: #166534; display:block }
      .diff-remove { color: #b91c1c; display:block }
      .diff-modify { color: #92400e; display:block }
    </style>`;
}

/* ── Export queue ───────────────────────────────────────────────────────────── */
function addToQueue() {
  if (!currentDiff) return;
  if (exportQueue.some(q => q.device === currentDiff.device && q.adom === currentDiff.adom)) return;
  exportQueue.push({ ...currentDiff });
  renderDiffPanel(currentDiff); // refresh "Add to Queue" button state
  renderQueue();
}

function removeFromQueue(device) {
  exportQueue = exportQueue.filter(q => q.device !== device);
  renderQueue();
  if (currentDiff && currentDiff.device === device) renderDiffPanel(currentDiff);
}

function renderQueue() {
  const footer = document.getElementById('pcQueueFooter');
  const chips  = document.getElementById('pcQueueChips');
  if (!exportQueue.length) {
    footer.style.display = 'none';
    chips.innerHTML = '';
    return;
  }
  footer.style.display = 'flex';
  chips.innerHTML = exportQueue.map(q =>
    `<span style="display:inline-flex;align-items:center;gap:.3rem;padding:2px 8px;
                  border-radius:12px;background:var(--surface-alt);border:1px solid var(--border);
                  font-size:.82rem">
       ${esc(q.device)}
       <button onclick="removeFromQueue(${esc(JSON.stringify(q.device))})"
               style="background:none;border:none;cursor:pointer;padding:0;line-height:1;color:var(--text-muted)">×</button>
     </span>`
  ).join('');
}

/* ── Bulk export state ──────────────────────────────────────────────────────── */
function updateExportAllState() {
  const btn = document.getElementById('pcExportAllBtn');
  const fmt = document.getElementById('pcExportAllFmt');
  const off = bulkRunning || !allDevices.length || !currentAdom;
  if (btn) btn.disabled = off;
  if (fmt) fmt.disabled = off;
}

// Polls a task every 2 s until status is not 'running'. Returns the task object.
// cancelFn() returning true causes an immediate { status: 'cancelled' } return.
async function pollTask(taskId, cancelFn) {
  const POLL_MS = 2000;
  while (true) {
    if (cancelFn()) return { status: 'cancelled', result: null, error: null };
    await new Promise(res => setTimeout(res, POLL_MS));
    if (cancelFn()) return { status: 'cancelled', result: null, error: null };
    try {
      const resp = await fetch(`/api/pending-changes/task/${encodeURIComponent(taskId)}`);
      if (!resp.ok) return { status: 'error', result: null, error: `Poll HTTP ${resp.status}` };
      const task = await resp.json();
      if (task.status !== 'running') return task;
    } catch (e) {
      return { status: 'error', result: null, error: e.message };
    }
  }
}

function cancelBulkExport() {
  bulkCancelled = true;
}

async function exportAllDevices(format) {
  if (bulkRunning || !allDevices.length || !currentAdom) return;
  bulkRunning   = true;
  bulkCancelled = false;
  _beforeUnloadHandler = e => { e.preventDefault(); e.returnValue = ''; };
  window.addEventListener('beforeunload', _beforeUnloadHandler);

  const queueFooter  = document.getElementById('pcQueueFooter');
  const progressEl   = document.getElementById('pcBulkProgress');
  const statusEl     = document.getElementById('pcBulkStatus');
  const queueVisible = queueFooter.style.display !== 'none';

  queueFooter.style.display = 'none';
  progressEl.style.display  = '';
  updateExportAllState();

  const results = [];
  const total   = allDevices.length;

  try {
    for (let i = 0; i < total; i++) {
      if (bulkCancelled) break;
      const device = allDevices[i];
      statusEl.textContent = `Fetching ${i + 1} of ${total} — ${device.name}…`;

      try {
        const postResp = await fetch(
          `/api/pending-changes/adoms/${encodeURIComponent(currentAdom)}/device/${encodeURIComponent(device.name)}/preview`,
          { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) }
        );
        if (!postResp.ok) throw new Error(`HTTP ${postResp.status}`);
        const { task_id } = await postResp.json();

        const taskResult = await pollTask(task_id, () => bulkCancelled);
        if (bulkCancelled) break;

        if (taskResult.status === 'done') {
          const r = taskResult.result;
          const hasChanges = Array.isArray(r.vdoms) && r.vdoms.some(v => v.changes && v.changes.length > 0);
          results.push({
            device:    device.name,
            ip:        r.ip || device.ip || '',
            adom:      currentAdom,
            status:    hasChanges ? 'ok' : 'no_changes',
            summary:   r.summary  || null,
            vdoms:     r.vdoms    || [],
            raw:       r.raw      || null,
            error:     null,
            timestamp: new Date().toISOString(),
          });
        } else {
          results.push({
            device:    device.name,
            ip:        device.ip || '',
            adom:      currentAdom,
            status:    'error',
            summary:   null,
            vdoms:     null,
            raw:       null,
            error:     taskResult.error || 'Unknown error',
            timestamp: new Date().toISOString(),
          });
        }
      } catch (e) {
        results.push({
          device:    device.name,
          ip:        device.ip || '',
          adom:      currentAdom,
          status:    'error',
          summary:   null,
          vdoms:     null,
          raw:       null,
          error:     e.message,
          timestamp: new Date().toISOString(),
        });
      }
    }
  } finally {
    // Restore UI — always runs even if loop throws
    bulkRunning              = false;
    progressEl.style.display = 'none';
    statusEl.textContent     = '';
    if (_beforeUnloadHandler) { window.removeEventListener('beforeunload', _beforeUnloadHandler); _beforeUnloadHandler = null; }
    updateExportAllState();
    if (queueVisible || exportQueue.length) renderQueue();
  }

  if (!bulkCancelled && results.length) {
    if (format === 'csv')  exportAllCsv(results);
    if (format === 'json') exportAllJson(results);
    if (format === 'pdf')  exportAllPdf(results);
  }
}

/* ── Bulk export format generators ─────────────────────────────────────────── */
function exportAllCsv(results) {
  const ts   = new Date().toLocaleString();
  const user = typeof PC_USER !== 'undefined' ? PC_USER : '';
  const adom = currentAdom;
  const withChanges = results.filter(r => r.status === 'ok').length;
  const q    = s => '"' + String(s ?? '').replace(/"/g, '""') + '"';

  let csv = `# Config-Delta — Full ADOM Export\n`;
  csv    += `# ADOM: ${adom}\n# Generated: ${ts}\n# User: ${user}\n`;
  csv    += `# Total devices: ${results.length}\n# Devices with changes: ${withChanges}\n\n`;
  csv    += 'device,ip,vdom,change_type,line,result,error_message\n';

  results.forEach(r => {
    if (r.status === 'ok') {
      (r.vdoms || []).forEach(v => {
        (v.changes || []).forEach(c => {
          csv += `${q(r.device)},${q(r.ip)},${q(v.name)},${q(c.type)},${q(c.line)},ok,\n`;
        });
      });
    } else if (r.status === 'no_changes') {
      csv += `${q(r.device)},${q(r.ip)},,,,no_changes,\n`;
    } else {
      csv += `${q(r.device)},${q(r.ip)},,,,error,${q(r.error)}\n`;
    }
  });

  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  download(`config-delta-${adom || 'export'}-all-${date}.csv`, csv, 'text/csv');
}

function exportAllJson(results) {
  const user = typeof PC_USER !== 'undefined' ? PC_USER : '';
  const adom = currentAdom;
  const payload = {
    adom,
    exported_at: new Date().toISOString(),
    exported_by: user,
    devices: results.map(r => ({
      device:    r.device,
      ip:        r.ip,
      status:    r.status,
      timestamp: r.timestamp,
      summary:   r.summary,
      changes:   r.status === 'ok' ? r.vdoms : null,
      error:     r.error || null,
    })),
  };
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  download(`config-delta-${adom || 'export'}-all-${date}.json`, JSON.stringify(payload, null, 2), 'application/json');
}

function exportAllPdf(results) {
  const ts   = new Date().toLocaleString();
  const user = typeof PC_USER !== 'undefined' ? PC_USER : '';
  const adom = currentAdom;

  function escH(s) {
    return String(s ?? '').replace(/[&<>"']/g,
      c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  const deviceSections = results.map((r, idx) => {
    let body = '';
    if (r.status === 'error') {
      body = `<p style="font-size:10px;color:#b91c1c">Export failed: ${escH(r.error || '')}</p>`;
    } else {
      const s = r.summary || {};
      const summaryItems = Object.entries(s)
        .filter(([, v]) => v > 0)
        .map(([k, v]) => `<span style="margin-right:12px"><strong>${v}</strong> ${k.replace(/_/g, ' ')}</span>`)
        .join('');
      const vdomBlocks = (r.vdoms || []).map(v => {
        if (!v.changes || !v.changes.length) {
          return `<div style="margin-top:8px">
            <strong style="font-size:10px">vdom: ${escH(v.name)}</strong>
            <p style="font-size:9px;color:#6b7280;font-style:italic;margin:2px 0 6px 0">No pending changes.</p>
          </div>`;
        }
        const lines = v.changes.map(c => {
          const color  = c.type === 'add' ? '#166534' : c.type === 'remove' ? '#b91c1c' : '#92400e';
          const prefix = c.type === 'add' ? '+' : c.type === 'remove' ? '-' : '~';
          return `<span style="color:${color};display:block">${escH(prefix + ' ' + c.line)}</span>`;
        }).join('');
        return `<div style="margin-top:8px">
          <strong style="font-size:10px">vdom: ${escH(v.name)}</strong>
          <pre style="background:#f8f9fa;border:1px solid #e5e7eb;border-radius:3px;padding:8px;
                      font-size:9px;margin:4px 0;overflow-wrap:break-word;white-space:pre-wrap">${lines}</pre>
        </div>`;
      }).join('');
      body = (summaryItems ? `<div style="margin-bottom:8px;font-size:10px">${summaryItems}</div>` : '') +
             (vdomBlocks  || '<p style="font-size:10px;color:#6b7280;font-style:italic">No pending changes found.</p>');
    }
    return `<div style="${idx > 0 ? 'page-break-before:always;padding-top:1cm' : ''}">
      <h2 style="font-size:14px;margin:0 0 4px">${escH(r.device)}</h2>
      <div style="font-size:10px;color:#6b7280;margin-bottom:6px"><code>${escH(r.ip || '')}</code></div>
      ${body}
    </div>`;
  }).join('');

  const title = `Config-Delta — ADOM: ${adom}`;
  const html  = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${escH(title)}</title>
<style>
  body{font-family:Arial,sans-serif;font-size:11px;color:#1a2133;margin:1.5cm}
  h1{font-size:16px;margin-bottom:6px}
  .meta{background:#f3f4f6;border-left:4px solid #3b82f6;padding:8px 12px;border-radius:3px;margin-bottom:14px;font-size:10px}
  code{font-family:monospace;font-size:10px}
  .print-btn{display:block;margin:0 0 16px;padding:8px 20px;background:#3b82f6;color:#fff;border:none;border-radius:5px;font-size:13px;cursor:pointer}
  .print-btn:hover{background:#2563eb}
  @media print{@page{margin:1.2cm}.print-btn{display:none!important}}
</style>
<script>window.onload=function(){window.print()}<\/script>
</head><body>
<button class="print-btn" onclick="window.print()">&#128438; Print / Save as PDF</button>
<h1>${escH(title)}</h1>
<div class="meta">
  Generated: ${escH(ts)}<br>User: ${escH(user)}<br>ADOM: ${escH(adom)}<br>
  Total devices: ${results.length} — With changes: ${results.filter(r => r.status === 'ok').length}
</div>
${deviceSections}
</body></html>`;

  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); }
}

/* ── Exports ────────────────────────────────────────────────────────────────── */
function buildMetaHeader() {
  const ts      = new Date().toLocaleString();
  const adom    = exportQueue[0]?.adom || currentAdom || '';
  const devices = exportQueue.map(q => q.device).join(', ');
  return { ts, adom, devices, user: (typeof PC_USER !== 'undefined' ? PC_USER : '') };
}

function exportCsv() {
  if (!exportQueue.length) return;
  const { ts, adom, devices, user } = buildMetaHeader();
  let csv = `# Config-Delta Export\n# Generated: ${ts}\n# User: ${user}\n# ADOM: ${adom}\n# Devices: ${devices}\n`;
  csv += '# Summary\n';
  exportQueue.forEach(q => {
    const s = q.summary;
    csv += `# ${q.device}: firewall_policy=${s.firewall_policy} routing=${s.routing} address=${s.address} service=${s.service} system=${s.system} other=${s.other}\n`;
  });
  csv += '\ndevice,ip,vdom,change_type,line\n';
  exportQueue.forEach(q => {
    q.vdoms.forEach(v => {
      v.changes.forEach(c => {
        const line = c.line.replace(/"/g, '""');
        const device = q.device.replace(/"/g, '""');
        const ip = (q.ip || '').replace(/"/g, '""');
        const vname = v.name.replace(/"/g, '""');
        csv += `"${device}","${ip}","${vname}","${c.type}","${line}"\n`;
      });
    });
  });
  download(`config-delta-${adom || 'export'}.csv`, csv, 'text/csv');
}

function exportJson() {
  if (!exportQueue.length) return;
  const { ts, adom, devices, user } = buildMetaHeader();
  const payload = {
    meta: { generated: ts, user, adom, devices },
    devices: exportQueue.map(q => ({
      device: q.device,
      ip: q.ip,
      conf_status: q.conf_status,
      db_status: q.db_status,
      summary: q.summary,
      vdoms: q.vdoms,
    })),
  };
  download(`config-delta-${adom || 'export'}.json`, JSON.stringify(payload, null, 2), 'application/json');
}

function exportPdf() {
  if (!exportQueue.length) return;
  const { ts, adom, devices, user } = buildMetaHeader();
  const title = `Config-Delta — ADOM: ${adom}`;

  const deviceSections = exportQueue.map((q, idx) => {
    const s = q.summary;
    const summaryItems = Object.entries(s)
      .filter(([,v]) => v > 0)
      .map(([k, v]) => `<span style="margin-right:12px"><strong>${v}</strong> ${k.replace(/_/g,' ')}</span>`)
      .join('');

    const vdomBlocks = q.vdoms.map(v => {
      if (!v.changes.length) {
        return `<div style="margin-top:8px"><strong style="font-size:10px">vdom: ${escHtml(v.name)}</strong>
          <p style="font-size:9px;color:#6b7280;font-style:italic;margin:2px 0 6px 0">No pending changes.</p></div>`;
      }
      const lines = v.changes.map(c => {
        const color = c.type === 'add' ? '#166534' : c.type === 'remove' ? '#b91c1c' : '#92400e';
        const prefix = c.type === 'add' ? '+' : c.type === 'remove' ? '-' : '~';
        return `<span style="color:${color};display:block">${escHtml(prefix + ' ' + c.line)}</span>`;
      }).join('');
      return `<div style="margin-top:8px"><strong style="font-size:10px">vdom: ${escHtml(v.name)}</strong>
        <pre style="background:#f8f9fa;border:1px solid #e5e7eb;border-radius:3px;padding:8px;
                    font-size:9px;margin:4px 0;overflow-wrap:break-word;white-space:pre-wrap">${lines}</pre></div>`;
    }).join('');

    return `<div style="${idx > 0 ? 'page-break-before:always;' : ''}padding-top:${idx > 0 ? '1cm' : '0'}">
      <h2 style="font-size:14px;margin:0 0 4px">${escHtml(q.device)}</h2>
      <div style="font-size:10px;color:#6b7280;margin-bottom:6px">
        <code>${escHtml(q.ip || '')}</code> &nbsp;|&nbsp; ${escHtml(q.conf_status)}${q.db_status === 'modified' ? ' &nbsp;|&nbsp; <strong style="color:#92400e">Pending Install</strong>' : ''}
      </div>
      ${summaryItems ? `<div style="margin-bottom:8px;font-size:10px">${summaryItems}</div>` : ''}
      ${vdomBlocks || '<p style="font-size:10px;color:#6b7280;font-style:italic">No pending changes found.</p>'}
    </div>`;
  }).join('');

  function escHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c =>
      ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
  }

  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${escHtml(title)}</title>
<style>
  body{font-family:Arial,sans-serif;font-size:11px;color:#1a2133;margin:1.5cm}
  h1{font-size:16px;margin-bottom:6px}
  .meta{background:#f3f4f6;border-left:4px solid #3b82f6;padding:8px 12px;border-radius:3px;margin-bottom:14px;font-size:10px}
  code{font-family:monospace;font-size:10px}
  .print-btn{display:block;margin:0 0 16px;padding:8px 20px;background:#3b82f6;color:#fff;border:none;border-radius:5px;font-size:13px;cursor:pointer}
  .print-btn:hover{background:#2563eb}
  @media print{@page{margin:1.2cm}.print-btn{display:none!important}}
</style>
<script>window.onload=function(){window.print()}<\/script>
</head><body>
<button class="print-btn" onclick="window.print()">&#128438; Print / Save as PDF</button>
<h1>${escHtml(title)}</h1>
<div class="meta">
  Generated: ${escHtml(ts)}<br>User: ${escHtml(user)}<br>
  ADOM: ${escHtml(adom)}<br>Devices: ${escHtml(devices)}
</div>
${deviceSections}
</body></html>`;

  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); }
}

/* ── Error helpers ───────────────────────────────────────────────────────────── */
function showDeviceError(msg) {
  const el = document.getElementById('pcDeviceError');
  el.textContent = msg;
  el.style.display = '';
}
function clearDeviceError() {
  const el = document.getElementById('pcDeviceError');
  el.textContent = '';
  el.style.display = 'none';
}

/* ── ADOM change guard ──────────────────────────────────────────────────────── */
function handleAdomChange(adom) {
  if (exportQueue.length > 0) {
    const ok = confirm('Changing ADOM will clear your export queue. Continue?');
    if (!ok) {
      document.getElementById('pcAdom').value = currentAdom;
      return;
    }
    exportQueue = [];
    renderQueue();
  }
  clearDeviceError();
  fetchDevices(adom);
}

/* ── Init ───────────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  fetchAdoms();
  checkPcAiSummaryAvailability();

  document.getElementById('pcAdom').addEventListener('change', e => handleAdomChange(e.target.value));
  document.getElementById('pcPageSize').addEventListener('change', e => {
    pageSize = parseInt(e.target.value, 10);
    currentPage = 1;
    renderDeviceTable();
  });
  document.getElementById('pcSearch').addEventListener('input', e => {
    filterText = e.target.value.trim();
    applyFilters();
  });
  document.getElementById('pcPendingOnly').addEventListener('change', e => {
    pendingOnly = e.target.checked;
    applyFilters();
  });
  document.getElementById('pcExportCsv').addEventListener('click', exportCsv);
  document.getElementById('pcExportJson').addEventListener('click', exportJson);
  document.getElementById('pcExportPdf').addEventListener('click', exportPdf);
});
