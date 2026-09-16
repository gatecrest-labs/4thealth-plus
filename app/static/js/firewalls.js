'use strict';

/* ── Utilities ─────────────────────────────────────────────────────────── */
function escHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function statusDot(status) {
  return `<span class="status-dot ${escHtml(status)}" title="${escHtml(status)}"></span>`;
}

// Convert dotted-decimal mask ("255.255.0.0") or integer to CIDR prefix length.
function maskToCidr(mask) {
  if (mask == null || mask === '') return '';
  if (typeof mask === 'number') return mask;
  if (!String(mask).includes('.')) return mask; // already a prefix length string
  return String(mask).split('.').reduce((n, oct) => {
    let bits = 0, v = parseInt(oct, 10);
    while (v) { bits += v & 1; v >>= 1; }
    return n + bits;
  }, 0);
}

function fmtDest(r) {
  const net = r.ip || r.prefix || r.network || r.destination || '';
  if (!net) return '';
  const cidr = maskToCidr(r.mask);
  return cidr !== '' ? `${net}/${cidr}` : net;
}

function download(filename, content, mime) {
  const a  = document.createElement('a');
  const bl = new Blob([content], { type: mime });
  a.href   = URL.createObjectURL(bl);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ── State ─────────────────────────────────────────────────────────────── */
let allDevices    = [];
let filteredDevices = [];
let currentPage   = 1;
let pageSize      = parseInt(document.getElementById('pageSize').value, 10);
let refreshTimer  = null;
let allAdoms      = [];   // [{name, desc}]
let deviceFilterQ = '';

/* ── ADOM loader ───────────────────────────────────────────────────────── */
async function loadAdoms() {
  try {
    const resp = await fetch('/api/adoms');
    if (resp.status === 401) { location.href = '/login'; return; }
    const adoms = await resp.json();
    if (!Array.isArray(adoms)) return;
    allAdoms = adoms;
    renderAdomOptions(allAdoms);
  } catch (_) {}
}

function renderAdomOptions(list) {
  const sel = document.getElementById('adomSelect');
  const current = sel.value;
  while (sel.options.length > 1) sel.remove(1);
  list.forEach(a => {
    const opt = document.createElement('option');
    opt.value = a.name;
    opt.textContent = a.desc ? `${a.name} — ${a.desc}` : a.name;
    sel.appendChild(opt);
  });
  // restore selection if still in filtered list
  if (list.some(a => a.name === current)) sel.value = current;
}

/* ── Device table ──────────────────────────────────────────────────────── */
function applyDeviceFilter() {
  const q = deviceFilterQ.toLowerCase();
  if (!q) {
    filteredDevices = allDevices;
  } else {
    filteredDevices = allDevices.filter(d =>
      (d.name     || '').toLowerCase().includes(q) ||
      (d.ip       || '').toLowerCase().includes(q) ||
      (d.version  || '').toLowerCase().includes(q) ||
      (d.platform || '').toLowerCase().includes(q) ||
      (d.desc     || '').toLowerCase().includes(q)
    );
  }
  setExportButtonState();
}

function renderTable() {
  applyDeviceFilter();
  const tbody  = document.getElementById('deviceTbody');
  const start  = (currentPage - 1) * pageSize;
  const slice  = filteredDevices.slice(start, start + pageSize);

  tbody.innerHTML = slice.map(d => {
    const descHtml = d.desc
      ? `<div style="font-size:.75rem;color:var(--text-muted,#6b7280);margin-top:2px">${escHtml(d.desc)}</div>`
      : '';
    return `
    <tr>
      <td>${statusDot(d.status)}</td>
      <td><div>${escHtml(d.name)}</div>${descHtml}</td>
      <td><code>${escHtml(d.ip)}</code></td>
      <td>${escHtml(d.platform)}</td>
      <td>${escHtml(d.version)}</td>
      <td><button class="btn btn-sm btn-link" data-adom="${escHtml(d.adom)}" data-device="${escHtml(d.name)}">Details</button></td>
    </tr>`;
  }).join('');

  const total = filteredDevices.length;
  const pages = Math.ceil(total / pageSize) || 1;
  const countText = deviceFilterQ
    ? `${total} of ${allDevices.length} device${allDevices.length !== 1 ? 's' : ''} — page ${currentPage} of ${pages}`
    : `${total} device${total !== 1 ? 's' : ''} — page ${currentPage} of ${pages}`;
  document.getElementById('deviceCount').textContent = countText;

  renderPagination();
}

function renderPagination() {
  const total = Math.ceil(filteredDevices.length / pageSize) || 1;
  const pg    = document.getElementById('pagination');

  function btn(label, page, disabled = false, active = false) {
    return `<button class="pg-btn${active ? ' active' : ''}" data-page="${page}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  }

  let html = btn('&laquo;&laquo;', 1, currentPage === 1);
  html += btn('&lsaquo;', currentPage - 1, currentPage === 1);

  const start = Math.max(1, currentPage - 2);
  const end   = Math.min(total, start + 4);
  for (let i = start; i <= end; i++) html += btn(i, i, false, i === currentPage);

  html += btn('&rsaquo;', currentPage + 1, currentPage === total);
  html += btn('&raquo;&raquo;', total, currentPage === total);

  pg.innerHTML = html;
}

async function loadDevices(adom) {
  document.getElementById('deviceTableWrapper').style.display = 'none';
  document.getElementById('deviceLoading').style.display = 'block';
  try {
    const resp = await fetch(`/api/adoms/${encodeURIComponent(adom)}/devices`);
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    if (!Array.isArray(data)) {
      alert('Error loading devices: ' + JSON.stringify(data));
      return;
    }
    allDevices = data;
    filteredDevices = data;
    deviceFilterQ = '';
    document.getElementById('deviceFilter').value = '';
    currentPage = 1;
    document.getElementById('deviceTableWrapper').style.display = '';
    renderTable();
    setExportButtonState();
  } catch (err) {
    alert('Failed to load devices: ' + err.message);
  } finally {
    document.getElementById('deviceLoading').style.display = 'none';
  }
}

/* ── Device detail modal ───────────────────────────────────────────────── */
let _activeHealthStream = null;

function openModal(title, bodyHtml) {
  document.getElementById('modalTitle').textContent = title;
  document.getElementById('modalBody').innerHTML = bodyHtml;
  document.getElementById('deviceModal').classList.remove('hidden');
}

function closeModal() {
  if (_activeHealthStream) { _activeHealthStream.close(); _activeHealthStream = null; }
  document.getElementById('deviceModal').classList.add('hidden');
}

function subTable(headers, rows, emptyMsg) {
  if (!rows || rows.length === 0) return `<p class="empty-state">${emptyMsg}</p>`;
  const ths = headers.map(h => `<th>${escHtml(h)}</th>`).join('');
  const trs = rows.map(r => `<tr>${r.map(c => `<td>${escHtml(String(c ?? ''))}</td>`).join('')}</tr>`).join('');
  return `<table class="sub-table"><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`;
}

/* ── Interface helper functions (module-scope so widgets can call them) ─── */
function ifaceIp(i) {
  if (Array.isArray(i.ip)) return i.ip.map(a => `${a.ip}/${a.mask}`).join(', ');
  return i.ip || '';
}

function ifaceLink(i) {
  if (i.link === true  || i.link === 1) return 'up';
  if (i.link === false || i.link === 0) return 'down';
  // No live monitor data — fall back to CMDB admin-configured state.
  // Return 'admin-up'/'admin-down' so callers can distinguish config state from live state.
  if (i.status === 'up')   return 'admin-up';
  if (i.status === 'down') return 'admin-down';
  return i.link_status || 'n/a';
}

function ifaceLinkBadge(i) {
  const link = ifaceLink(i);
  const _b = 'display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75rem;font-weight:600;border:1px solid';
  if (link === 'up')         return `<span style="${_b};color:#2d6a2d;border-color:#5a9e5a;background:#f4faf4">UP</span>`;
  if (link === 'down')       return `<span style="${_b};color:#dc3545;border-color:#dc3545;background:#fff5f5">DOWN</span>`;
  if (link === 'admin-up')   return `<span style="${_b};color:#6b7280;border-color:#9ca3af;background:#f9fafb" title="Admin-configured up — no live link data">UP*</span>`;
  if (link === 'admin-down') return `<span style="${_b};color:#6b7280;border-color:#9ca3af;background:#f9fafb" title="Admin-configured down — no live link data">DOWN*</span>`;
  return `<span style="color:#aaa">—</span>`;
}

const _INSECURE_PROTOS = new Set(['http', 'telnet', 'snmp']);
const _KNOWN_PROTOS    = ['https', 'http', 'ssh', 'telnet', 'ping', 'snmp'];

function ifaceProtoHtml(i) {
  let raw = i.allowaccess || i.allow_access || '';
  let tokens = Array.isArray(raw)
    ? raw.map(t => String(t).toLowerCase())
    : String(raw).toLowerCase().split(/[\s,]+/).filter(Boolean);
  const active = tokens.filter(t => _KNOWN_PROTOS.includes(t));
  if (!active.length) return '<span style="color:#888">—</span>';
  const base = 'display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75rem;font-weight:600;border:1px solid;margin:1px 2px';
  return active.map(p => {
    const label = p.toUpperCase();
    return _INSECURE_PROTOS.has(p)
      ? `<span style="${base};color:#dc3545;border-color:#dc3545;background:#fff5f5">${escHtml(label)}</span>`
      : `<span style="${base};color:#2d6a2d;border-color:#5a9e5a;background:#f4faf4">${escHtml(label)}</span>`;
  }).join('');
}

function renderHealthModal(deviceName, d) {
  const cpu = d.cpu ?? 0;
  const mem = d.mem ?? 0;

  const lic = d.license || {};
  const licStatus = lic.status || 'unknown';
  const _expiryColor = expires => {
    if (!expires) return '#16a34a';
    const days = Math.floor((new Date(expires) - Date.now()) / 86400000);
    if (days < 30)  return '#dc2626';
    if (days <= 90) return '#ca8a04';
    return '#16a34a';
  };
  const licColor  = licStatus === 'licensed' ? _expiryColor(lic.expires)
                  : licStatus === 'expired'  ? '#dc2626'
                  : '#6b7280';
  const licLabel  = licStatus === 'licensed'
    ? `Licensed${lic.expires ? ' · exp ' + escHtml(lic.expires) : ''}`
    : licStatus === 'expired' ? 'EXPIRED'
    : 'Unknown';
  const licBadgeHtml = `<span style="display:inline-block;padding:1px 8px;border-radius:4px;font-size:.8rem;font-weight:600;background:${licColor}1a;color:${licColor};border:1px solid ${licColor}66">${licLabel}</span>`;

  // FortiGuard subscription table (shown when subscription data is present)
  const FG_SUB_KEYS   = ['antivirus','ips','web_filtering','appctrl','antispam','outbreak_prevention','firmware_updates','forticloud_sandbox','ai_malware_detection','blacklisted_certificates'];
  const FG_SUB_LABELS = { antivirus:'Antivirus (AV)', ips:'IPS / NIDS', web_filtering:'Web Filtering', appctrl:'App Control', antispam:'Anti-Spam', outbreak_prevention:'Outbreak Prevention', firmware_updates:'Firmware Updates', forticloud_sandbox:'FortiCloud Sandbox', ai_malware_detection:'AI Malware Detection', blacklisted_certificates:'Blocklisted Certificates' };
  const fgSubs = lic.subscriptions || {};
  const fgRows = FG_SUB_KEYS.map(key => {
    const sub = fgSubs[key] || {};
    const s   = sub.status || 'unknown';
    const col = s === 'licensed' ? _expiryColor(sub.expires) : s === 'expired' ? '#dc2626' : '#6b7280';
    const lbl = s === 'licensed' ? 'Licensed' : s === 'expired' ? 'Expired' : s === 'none' ? 'No License' : 'Unknown';
    return `<tr><td>${escHtml(FG_SUB_LABELS[key])}</td><td><span style="color:${col};font-weight:600">&#x25cf; ${escHtml(lbl)}</span></td><td style="color:var(--text-muted)">${escHtml(sub.expires || '—')}</td></tr>`;
  }).join('');
  const fgSubsHtml = Object.keys(fgSubs).length > 0
    ? `<div class="section-title">FortiGuard Subscriptions</div>
<table class="data-table" style="font-size:.85rem"><thead><tr><th>Subscription</th><th>Status</th><th>Expires</th></tr></thead><tbody>${fgRows}</tbody></table>`
    : '';

  // Filter: hide interfaces that have no meaningful IP AND are not up
  const visibleIfaces = (d.interfaces || []).filter(i => {
    const ip   = ifaceIp(i);
    const link = ifaceLink(i);
    const hasIp = ip && ip !== '0.0.0.0/0.0.0.0' && ip !== '0.0.0.0/255.255.255.255';
    return hasIp || link === 'up' || link === 'admin-up';
  });

  // Interface table is rendered as a paginated widget after modal insertion

  // Routes: per-VDOM dicts from backend
  const routesByVdom  = d.routes_by_vdom  || { root: d.routes || [] };
  const routes6ByVdom = d.routes6_by_vdom || {};

  // IPsec — FortiOS phase1 fields: name, rgwy (remote gateway), tun_id, proxyid[].status
  const ipsecRows = (d.ipsec || []).map(t => {
    const saStatus = Array.isArray(t.proxyid) && t.proxyid.length
      ? t.proxyid.map(p => p.status || p.state || '').filter(Boolean).join(', ')
      : (t.status || t.state || 'n/a');
    return [
      t.name || t.tun_name || '',
      t.rgwy || t.remote_gateway || t.gateway || '',
      saStatus,
      t.uptime != null ? t.uptime : '',
    ];
  });

  const ha = d.ha || {};

  // HA mode: dvmdb int (0=Standalone,1=A-P,2=A-A) or proxy string ("standalone","a-p","a-a")
  const HA_MODE = { 0: 'Standalone', 1: 'Active-Passive', 2: 'Active-Active' };
  const rawMode = ha.mode ?? ha.group_mode;
  const haMode  = rawMode != null ? (HA_MODE[rawMode] || String(rawMode)) : 'n/a';

  const descHtml = d.desc
    ? `<div class="device-desc">${escHtml(d.desc)}</div>`
    : '';

  // Assign a distinct pastel color to each VDOM name for consistent cross-table coding
  const VDOM_PALETTE = [
    { bg: '#dbeafe', border: '#3b82f6', text: '#1e40af' }, // blue
    { bg: '#dcfce7', border: '#22c55e', text: '#166534' }, // green
    { bg: '#fef9c3', border: '#eab308', text: '#854d0e' }, // yellow
    { bg: '#fce7f3', border: '#ec4899', text: '#9d174d' }, // pink
    { bg: '#ede9fe', border: '#8b5cf6', text: '#5b21b6' }, // purple
    { bg: '#ffedd5', border: '#f97316', text: '#9a3412' }, // orange
    { bg: '#e0f2fe', border: '#0ea5e9', text: '#0c4a6e' }, // sky
    { bg: '#f0fdf4', border: '#86efac', text: '#14532d' }, // mint
  ];
  const vdomColorMap = {};
  (d.vdoms || []).forEach((v, idx) => {
    vdomColorMap[v.name] = VDOM_PALETTE[idx % VDOM_PALETTE.length];
  });

  function vdomBadge(name) {
    if (name === 'root') return `<span style="display:inline-block;padding:1px 7px;border-radius:3px;font-size:.75rem;font-weight:600;border:1px solid #222;background:#222;color:#fff">${escHtml(name)}</span>`;
    const c = vdomColorMap[name];
    if (!c) return escHtml(name);
    return `<span style="display:inline-block;padding:1px 7px;border-radius:3px;font-size:.75rem;font-weight:600;border:1px solid ${c.border};background:${c.bg};color:${c.text}">${escHtml(name)}</span>`;
  }

  // VDOMs — only shown when device is in VDOM mode
  const vdomSection = d.vdom_mode && (d.vdoms || []).length > 0
    ? `<div class="section-title">VDOMs (${d.vdoms.length})</div>
<table class="sub-table"><thead><tr><th>VDOM</th><th>Op Mode</th></tr></thead><tbody>
${(d.vdoms || []).map(v => `<tr><td>${vdomBadge(v.name)}</td><td>${escHtml(v.opmode || '')}</td></tr>`).join('')}
</tbody></table>`
    : '';

  const html = `
<div class="detail-header">
  <span class="status-dot ${escHtml(d.dot_status || 'unknown')}" style="width:14px;height:14px;flex-shrink:0"></span>
  <div>
    <span class="detail-hostname">${escHtml(d.name)}</span>
    ${descHtml}
  </div>
  <span class="detail-adom-badge">${escHtml(d.adom || '')}</span>
</div>

<div class="detail-grid">
  <div class="detail-item"><span class="detail-label">Mgmt IP</span><span class="detail-value">${escHtml(d.mgmt_ip || '')}</span></div>
  <div class="detail-item"><span class="detail-label">Platform</span><span class="detail-value">${escHtml(d.platform || '')}</span></div>
  <div class="detail-item"><span class="detail-label">Version</span><span class="detail-value">${escHtml(d.version)}</span></div>
  <div class="detail-item"><span class="detail-label">Serial</span><span class="detail-value">${escHtml(d.serial)}</span></div>
  <div class="detail-item"><span class="detail-label">License</span><span class="detail-value">${licBadgeHtml}</span></div>
  <div class="detail-item"><span class="detail-label">CPU</span><span class="detail-value">${cpu}%</span></div>
  <div class="detail-item"><span class="detail-label">Memory</span><span class="detail-value">${mem}%</span></div>
  <div class="detail-item"><span class="detail-label">HA Mode</span><span class="detail-value">${escHtml(haMode)}</span></div>
  <div class="detail-item"><span class="detail-label">Policy Package</span><span class="detail-value">${escHtml(d.policy_package || '—')}</span></div>
</div>

${fgSubsHtml}

${vdomSection}

<div class="section-title">Interfaces (<span id="ifaceCountLabel">${visibleIfaces.length}</span>)</div>
<div id="ifaceWidget"></div>

<div class="section-title">IPv4 Routes</div>
<div id="routeWidget"></div>

<div class="section-title">IPv6 Routes</div>
<div id="route6Widget"></div>

<div class="section-title">BGP Neighbors</div>
<div id="bgpNeighWidget"></div>

<div class="section-title">BGP Advertised Prefixes</div>
<div id="bgpPathsWidget"></div>

<div class="section-title">OSPF Neighbors</div>
<div id="ospfWidget"></div>

<div class="section-title">IPsec Tunnels (${(d.ipsec || []).length})</div>
${subTable(['Tunnel','Remote Gateway','Status','Uptime'], ipsecRows, 'No IPsec tunnels')}`;

  return { html, visibleIfaces, vdomColorMap };
}

/* ── Interface widget (paginated + filterable) ──────────────────────────── */
function renderIfaceWidget(ifaces, vdomBadgeFn) {
  const widget = document.getElementById('ifaceWidget');
  if (!widget) return;

  let filter = '';
  let page   = 1;
  let size   = 25;

  function filtered() {
    if (!filter) return ifaces;
    const q = filter.toLowerCase();
    return ifaces.filter(i =>
      (i.name || '').toLowerCase().includes(q) ||
      (i.vdom || '').toLowerCase().includes(q) ||
      (i.type || '').toLowerCase().includes(q) ||
      ifaceIp(i).toLowerCase().includes(q) ||
      ifaceLink(i).toLowerCase().includes(q)
    );
  }

  function pgBtn(label, pg, disabled, active) {
    return `<button class="pg-btn${active ? ' active' : ''}" data-ifpage="${pg}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  }

  function draw() {
    const rows  = filtered();
    const total = Math.ceil(rows.length / size) || 1;
    page = Math.min(page, total);
    const slice = rows.slice((page - 1) * size, page * size);

    const countEl = document.getElementById('ifaceCountLabel');
    if (countEl) countEl.textContent = filter ? `${rows.length} of ${ifaces.length}` : String(ifaces.length);

    const headers = ['Interface', 'VDOM', 'Type', 'Link', 'IP', 'Speed', 'RxErr', 'TxErr', 'Allowed Protocols'];
    const ths = headers.map(h => `<th>${escHtml(h)}</th>`).join('');
    const trs = slice.map(i => {
      const ifType = (i.type || '').toLowerCase();
      const typeBadge = ifType
        ? `<span style="display:inline-block;font-size:.7rem;padding:1px 5px;border-radius:3px;background:var(--surface-alt,#f3f4f6);color:var(--text-muted,#6b7280);border:1px solid var(--border,#d1d5db)">${escHtml(ifType)}</span>`
        : '<span style="color:#aaa">—</span>';
      return `<tr>
        <td>${escHtml(i.name || i.interface || '')}</td>
        <td>${vdomBadgeFn(i.vdom || '')}</td>
        <td>${typeBadge}</td>
        <td>${ifaceLinkBadge(i)}</td>
        <td>${escHtml(ifaceIp(i))}</td>
        <td>${escHtml(String(i.speed || ''))}</td>
        <td>${escHtml(String(i.rx_errors ?? i.rx_err ?? 0))}</td>
        <td>${escHtml(String(i.tx_errors ?? i.tx_err ?? 0))}</td>
        <td>${ifaceProtoHtml(i)}</td>
      </tr>`;
    }).join('');

    const table = slice.length
      ? `<table class="sub-table"><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`
      : `<p class="empty-state">No interfaces match.</p>`;

    let pgHtml = '';
    if (total > 1) {
      pgHtml += pgBtn('&laquo;&laquo;', 1, page === 1, false);
      pgHtml += pgBtn('&lsaquo;', page - 1, page === 1, false);
      const s = Math.max(1, page - 2), e = Math.min(total, s + 4);
      for (let i = s; i <= e; i++) pgHtml += pgBtn(i, i, false, i === page);
      pgHtml += pgBtn('&rsaquo;', page + 1, page === total, false);
      pgHtml += pgBtn('&raquo;&raquo;', total, page === total, false);
    }

    const shownCount = filter ? `${rows.length} of ${ifaces.length}` : String(ifaces.length);

    widget.innerHTML = `
<div class="route-controls">
  <input type="text" class="form-control iface-filter-input" placeholder="Filter by name, VDOM, IP…" value="${escHtml(filter)}" />
  <select class="form-select-sm iface-size-select">
    <option value="10"  ${size === 10  ? 'selected' : ''}>10</option>
    <option value="25"  ${size === 25  ? 'selected' : ''}>25</option>
    <option value="50"  ${size === 50  ? 'selected' : ''}>50</option>
  </select>
  <span class="text-muted" style="font-size:.8rem">${escHtml(shownCount)} interfaces &bull; page ${page} of ${total}</span>
</div>
${table}
${pgHtml ? `<div class="pagination">${pgHtml}</div>` : ''}`;

    widget.querySelector('.iface-filter-input').addEventListener('input', function () {
      filter = this.value; page = 1; draw();
      const el = widget.querySelector('.iface-filter-input');
      if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); }
    });
    widget.querySelector('.iface-size-select').addEventListener('change', function () {
      size = parseInt(this.value, 10); page = 1; draw();
    });
    widget.querySelectorAll('[data-ifpage]').forEach(btn => {
      btn.addEventListener('click', function () {
        if (!this.disabled) { page = parseInt(this.dataset.ifpage, 10); draw(); }
      });
    });
  }

  draw();
}

/* ── Route widget (per-VDOM tabs, filter + pagination, client-side) ─────── */
function renderRouteWidget(byVdom, colorMap, widgetId) {
  const widget = document.getElementById(widgetId);
  if (!widget) return;

  const vdomNames = Object.keys(byVdom);
  if (!vdomNames.length) {
    widget.innerHTML = '<p class="empty-state">No route data.</p>';
    return;
  }

  // Sort: root first, then alphabetical
  vdomNames.sort((a, b) => {
    if (a === 'root') return -1;
    if (b === 'root') return 1;
    return a.localeCompare(b);
  });

  let activeVdom = vdomNames[0];
  let routeFilter = '';
  let routePage   = 1;
  let routeSize   = 25;

  function vdomTabColor(name) {
    if (name === 'root') return { bg: '#222', border: '#222', text: '#fff' };
    return colorMap[name] || { bg: '#e5e7eb', border: '#9ca3af', text: '#374151' };
  }

  function filtered() {
    const routes = byVdom[activeVdom] || [];
    if (!routeFilter) return routes;
    const q = routeFilter.toLowerCase();
    return routes.filter(r =>
      (r.ip_mask || fmtDest(r)).toLowerCase().includes(q) ||
      (r.gateway || r.nexthop || '').toLowerCase().includes(q) ||
      (r.interface || r.dev || r.device || '').toLowerCase().includes(q) ||
      (r.type || r.protocol || '').toLowerCase().includes(q)
    );
  }

  function pgBtn(label, page, disabled, active) {
    return `<button class="pg-btn${active ? ' active' : ''}" data-rpage="${page}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  }

  function draw() {
    const rows  = filtered();
    const total = Math.ceil(rows.length / routeSize) || 1;
    routePage   = Math.min(routePage, total);
    const slice = rows.slice((routePage - 1) * routeSize, routePage * routeSize);

    // VDOM tabs
    const tabs = vdomNames.map(name => {
      const c       = vdomTabColor(name);
      const isActive = name === activeVdom;
      const count   = (byVdom[name] || []).length;
      const border  = isActive ? `2px solid ${c.border}` : `1px solid ${c.border}`;
      const opacity = isActive ? '1' : '0.55';
      return `<button class="vdom-route-tab" data-vdom="${escHtml(name)}"
        style="padding:3px 10px;border-radius:4px;font-size:.75rem;font-weight:600;cursor:pointer;margin:2px;
               background:${c.bg};color:${c.text};border:${border};opacity:${opacity}">
        ${escHtml(name)} <span style="font-weight:400;font-size:.7rem">(${count})</span>
      </button>`;
    }).join('');

    const trs = slice.map(r => `<tr>
      <td><code>${escHtml(r.ip_mask || fmtDest(r))}</code></td>
      <td>${escHtml(r.gateway || r.nexthop || 'connected')}</td>
      <td>${escHtml(r.interface || r.dev || r.device || '')}</td>
      <td>${escHtml(r.type || r.protocol || '')}</td>
      <td>${escHtml(String(r.metric ?? r.distance ?? ''))}</td>
    </tr>`).join('');

    const thead = `<thead><tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Type</th><th>Metric</th></tr></thead>`;
    const table = rows.length
      ? `<table class="sub-table">${thead}<tbody>${trs}</tbody></table>`
      : `<p class="empty-state">No routes match.</p>`;

    let pgHtml = '';
    if (total > 1) {
      pgHtml += pgBtn('&laquo;', 1, routePage === 1, false);
      pgHtml += pgBtn('&lsaquo;', routePage - 1, routePage === 1, false);
      const s = Math.max(1, routePage - 2), e = Math.min(total, s + 4);
      for (let i = s; i <= e; i++) pgHtml += pgBtn(i, i, false, i === routePage);
      pgHtml += pgBtn('&rsaquo;', routePage + 1, routePage === total, false);
      pgHtml += pgBtn('&raquo;', total, routePage === total, false);
    }

    const allCount   = (byVdom[activeVdom] || []).length;
    const shownCount = routeFilter ? `${rows.length} of ${allCount}` : String(allCount);

    widget.innerHTML = `
<div style="margin-bottom:6px">${tabs}</div>
<div class="route-controls">
  <input type="text" class="form-control route-filter-input" placeholder="Filter by network, gateway, interface…" value="${escHtml(routeFilter)}" />
  <select class="form-select-sm route-size-select">
    <option value="25"  ${routeSize === 25  ? 'selected' : ''}>25</option>
    <option value="50"  ${routeSize === 50  ? 'selected' : ''}>50</option>
    <option value="100" ${routeSize === 100 ? 'selected' : ''}>100</option>
  </select>
  <span class="text-muted" style="font-size:.8rem">${escHtml(shownCount)} routes &bull; page ${routePage} of ${total}</span>
</div>
${table}
${pgHtml ? `<div class="pagination">${pgHtml}</div>` : ''}`;

    widget.querySelectorAll('.vdom-route-tab').forEach(btn => {
      btn.addEventListener('click', function () {
        activeVdom  = this.dataset.vdom;
        routeFilter = '';
        routePage   = 1;
        draw();
      });
    });

    widget.querySelector('.route-filter-input').addEventListener('input', function () {
      routeFilter = this.value;
      routePage   = 1;
      draw();
      const el = widget.querySelector('.route-filter-input');
      if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); }
    });

    widget.querySelector('.route-size-select').addEventListener('change', function () {
      routeSize = parseInt(this.value, 10);
      routePage = 1;
      draw();
    });

    widget.querySelectorAll('[data-rpage]').forEach(btn => {
      btn.addEventListener('click', function () {
        if (this.disabled) return;
        routePage = parseInt(this.dataset.rpage, 10);
        draw();
      });
    });
  }

  draw();
}

/* ── Generic per-VDOM tabbed widget ─────────────────────────────────────── */
// rowsFn(item) → array of <td> HTML strings for one data item
// headers      → array of column header strings
// filterFn(item, q) → bool
function renderVdomWidget(byVdom, colorMap, widgetId, headers, rowsFn, filterFn, emptyMsg, filterPlaceholder) {
  const widget = document.getElementById(widgetId);
  if (!widget) return;

  const vdomNames = Object.keys(byVdom).filter(v => (byVdom[v] || []).length > 0);
  if (!vdomNames.length) {
    widget.innerHTML = `<p class="empty-state">${emptyMsg}</p>`;
    return;
  }
  vdomNames.sort((a, b) => a === 'root' ? -1 : b === 'root' ? 1 : a.localeCompare(b));

  let activeVdom = vdomNames[0];
  let filter = '';
  let page   = 1;
  let size   = 25;

  function vdomTabColor(name) {
    if (name === 'root') return { bg: '#222', border: '#222', text: '#fff' };
    return colorMap[name] || { bg: '#e5e7eb', border: '#9ca3af', text: '#374151' };
  }

  function filtered() {
    const items = byVdom[activeVdom] || [];
    if (!filter) return items;
    const q = filter.toLowerCase();
    return items.filter(item => filterFn(item, q));
  }

  function pgBtn(label, pg, disabled, active) {
    return `<button class="pg-btn${active ? ' active' : ''}" data-vwpage="${pg}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  }

  function draw() {
    const rows  = filtered();
    const total = Math.ceil(rows.length / size) || 1;
    page = Math.min(page, total);
    const slice = rows.slice((page - 1) * size, page * size);

    const tabs = vdomNames.map(name => {
      const c = vdomTabColor(name);
      const isActive = name === activeVdom;
      const count = (byVdom[name] || []).length;
      return `<button class="vdom-route-tab" data-vdom="${escHtml(name)}"
        style="padding:3px 10px;border-radius:4px;font-size:.75rem;font-weight:600;cursor:pointer;margin:2px;
               background:${c.bg};color:${c.text};border:${isActive ? `2px solid ${c.border}` : `1px solid ${c.border}`};opacity:${isActive ? 1 : 0.55}">
        ${escHtml(name)} <span style="font-weight:400;font-size:.7rem">(${count})</span>
      </button>`;
    }).join('');

    const ths = headers.map(h => `<th>${escHtml(h)}</th>`).join('');
    const trs = slice.map(item => `<tr>${rowsFn(item).join('')}</tr>`).join('');
    const table = slice.length
      ? `<table class="sub-table"><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`
      : `<p class="empty-state">No entries match.</p>`;

    const allCount   = (byVdom[activeVdom] || []).length;
    const shownCount = filter ? `${rows.length} of ${allCount}` : String(allCount);

    let pgHtml = '';
    if (total > 1) {
      pgHtml += pgBtn('&laquo;', 1, page === 1, false);
      pgHtml += pgBtn('&lsaquo;', page - 1, page === 1, false);
      const s = Math.max(1, page - 2), e = Math.min(total, s + 4);
      for (let i = s; i <= e; i++) pgHtml += pgBtn(i, i, false, i === page);
      pgHtml += pgBtn('&rsaquo;', page + 1, page === total, false);
      pgHtml += pgBtn('&raquo;', total, page === total, false);
    }

    widget.innerHTML = `
<div style="margin-bottom:6px">${tabs}</div>
<div class="route-controls">
  <input type="text" class="form-control vw-filter-input" placeholder="${escHtml(filterPlaceholder)}" value="${escHtml(filter)}" />
  <select class="form-select-sm vw-size-select">
    <option value="25"  ${size === 25  ? 'selected' : ''}>25</option>
    <option value="50"  ${size === 50  ? 'selected' : ''}>50</option>
    <option value="100" ${size === 100 ? 'selected' : ''}>100</option>
  </select>
  <span class="text-muted" style="font-size:.8rem">${escHtml(shownCount)} entries &bull; page ${page} of ${total}</span>
</div>
${table}
${pgHtml ? `<div class="pagination">${pgHtml}</div>` : ''}`;

    widget.querySelectorAll('.vdom-route-tab').forEach(btn => {
      btn.addEventListener('click', function () {
        activeVdom = this.dataset.vdom;
        filter = '';
        page   = 1;
        draw();
      });
    });
    widget.querySelector('.vw-filter-input').addEventListener('input', function () {
      filter = this.value; page = 1; draw();
      const el = widget.querySelector('.vw-filter-input');
      if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); }
    });
    widget.querySelector('.vw-size-select').addEventListener('change', function () {
      size = parseInt(this.value, 10); page = 1; draw();
    });
    widget.querySelectorAll('[data-vwpage]').forEach(btn => {
      btn.addEventListener('click', function () {
        if (!this.disabled) { page = parseInt(this.dataset.vwpage, 10); draw(); }
      });
    });
  }

  draw();
}

function renderBgpNeighWidget(byVdom, colorMap) {
  renderVdomWidget(
    byVdom, colorMap, 'bgpNeighWidget',
    ['Neighbor IP', 'Local IP', 'Remote AS', 'State', 'Type'],
    b => [
      `<td>${escHtml(b.neighbor_ip || b.neighborip || '')}</td>`,
      `<td>${escHtml(b.local_ip || '')}</td>`,
      `<td>${escHtml(String(b.remote_as || b.remoteas || ''))}</td>`,
      `<td>${escHtml(b.state || '')}</td>`,
      `<td>${escHtml(b.type || '')}</td>`,
    ],
    (b, q) => (b.neighbor_ip||'').includes(q) || (b.local_ip||'').includes(q) ||
              String(b.remote_as||'').includes(q) || (b.state||'').toLowerCase().includes(q),
    'No BGP neighbors.',
    'Filter by neighbor, AS, state…'
  );
}

function renderBgpPathsWidget(byVdom, colorMap) {
  renderVdomWidget(
    byVdom, colorMap, 'bgpPathsWidget',
    ['Prefix', 'Next Hop', 'Origin', 'Best', 'Learned From'],
    p => {
      const prefix = (p.nlri_prefix || '') + (p.nlri_prefix_len != null ? `/${p.nlri_prefix_len}` : '');
      return [
        `<td><code>${escHtml(prefix)}</code></td>`,
        `<td>${escHtml(p.next_hop || '')}</td>`,
        `<td>${escHtml(p.origin || '')}</td>`,
        `<td style="text-align:center">${p.is_best ? '✓' : ''}</td>`,
        `<td>${escHtml(p.learned_from || '')}</td>`,
      ];
    },
    (p, q) => {
      const prefix = `${p.nlri_prefix || ''}/${p.nlri_prefix_len ?? ''}`;
      return prefix.includes(q) || (p.next_hop||'').includes(q) || (p.learned_from||'').includes(q) || (p.origin||'').includes(q);
    },
    'No BGP paths.',
    'Filter by prefix, next hop, neighbor…'
  );
}

function renderOspfWidget(byVdom, colorMap) {
  renderVdomWidget(
    byVdom, colorMap, 'ospfWidget',
    ['Router ID', 'Neighbor IP', 'State', 'Priority'],
    o => [
      `<td>${escHtml(o.router_id || o.neighbor_id || '')}</td>`,
      `<td>${escHtml(o.neighbor_ip || '')}</td>`,
      `<td>${escHtml(o.state || '')}</td>`,
      `<td>${escHtml(String(o.priority ?? ''))}</td>`,
    ],
    (o, q) => (o.router_id||'').includes(q) || (o.neighbor_ip||'').includes(q) || (o.state||'').toLowerCase().includes(q),
    'No OSPF neighbors.',
    'Filter by router ID, neighbor, state…'
  );
}

function loadDeviceDetail(adom, deviceName) {
  openModal(`${deviceName}`, `<div class="health-progress-wrap">
    <div class="health-progress-label" id="healthProgressLabel">Connecting…</div>
    <div class="health-progress-track"><div class="health-progress-bar" id="healthProgressBar">0%</div></div>
  </div>`);

  const url = `/api/adoms/${encodeURIComponent(adom)}/devices/${encodeURIComponent(deviceName)}/health/stream`;
  if (_activeHealthStream) { _activeHealthStream.close(); }
  const es = new EventSource(url);
  _activeHealthStream = es;

  function setProgress(pct, label) {
    const bar = document.getElementById('healthProgressBar');
    const lbl = document.getElementById('healthProgressLabel');
    if (!bar) return;
    bar.style.width  = pct + '%';
    bar.textContent  = pct + '%';
    if (lbl && label) lbl.textContent = label;
  }

  es.onmessage = e => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    const pct = msg.total > 0 ? Math.round((msg.done / msg.total) * 100) : 0;
    setProgress(pct, `${msg.label} (${msg.done}/${msg.total})`);
  };

  es.addEventListener('done', e => {
    es.close(); _activeHealthStream = null;
    let data;
    try { data = JSON.parse(e.data); } catch {
      document.getElementById('modalBody').innerHTML = `<div class="alert alert-danger">Failed to parse response</div>`;
      return;
    }
    if (data.error) {
      document.getElementById('modalBody').innerHTML = `<div class="alert alert-danger">${escHtml(data.error)}</div>`;
      return;
    }
    const { html, visibleIfaces, vdomColorMap } = renderHealthModal(deviceName, data);
    document.getElementById('modalBody').innerHTML = html;

    function _vdomBadge(name) {
      if (name === 'root') return `<span style="display:inline-block;padding:1px 7px;border-radius:3px;font-size:.75rem;font-weight:600;border:1px solid #222;background:#222;color:#fff">${escHtml(name)}</span>`;
      const c = vdomColorMap[name];
      if (!c) return escHtml(name);
      return `<span style="display:inline-block;padding:1px 7px;border-radius:3px;font-size:.75rem;font-weight:600;border:1px solid ${c.border};background:${c.bg};color:${c.text}">${escHtml(name)}</span>`;
    }

    renderIfaceWidget(visibleIfaces, _vdomBadge);
    renderRouteWidget(data.routes_by_vdom  || { root: data.routes || [] }, vdomColorMap, 'routeWidget');
    renderRouteWidget(data.routes6_by_vdom || {}, vdomColorMap, 'route6Widget');
    renderBgpNeighWidget(data.bgp_by_vdom       || {}, vdomColorMap);
    renderBgpPathsWidget(data.bgp_paths_by_vdom || {}, vdomColorMap);
    renderOspfWidget(data.ospf_by_vdom          || {}, vdomColorMap);
  });

  es.addEventListener('error', e => {
    es.close(); _activeHealthStream = null;
    let msg = 'Stream error';
    if (e.data) { try { msg = JSON.parse(e.data).error || msg; } catch {} }
    document.getElementById('modalBody').innerHTML = `<div class="alert alert-danger">${escHtml(msg)}</div>`;
  });

  es.onerror = () => {
    if (!document.getElementById('healthProgressBar')) return;
    es.close(); _activeHealthStream = null;
    document.getElementById('modalBody').innerHTML = `<div class="alert alert-danger">Connection lost while fetching health data</div>`;
  };
}

/* ── Search ────────────────────────────────────────────────────────────── */
async function doSearch() {
  const q = document.getElementById('searchInput').value.trim();
  const resultsDiv = document.getElementById('searchResults');
  if (!q) { resultsDiv.classList.add('hidden'); return; }
  resultsDiv.classList.remove('hidden');
  resultsDiv.innerHTML = '<div class="loading-placeholder">Searching…</div>';
  try {
    const resp = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
    const data = await resp.json();
    if (!Array.isArray(data)) {
      resultsDiv.innerHTML = `<div class="alert alert-danger">${escHtml(JSON.stringify(data))}</div>`;
      return;
    }
    if (data.length === 0) {
      resultsDiv.innerHTML = '<p class="empty-state">No devices matched.</p>';
      return;
    }
    const rows = data.map(d => `<tr>
      <td>${statusDot(d.status)}</td>
      <td>${escHtml(d.name)}</td>
      <td><code>${escHtml(d.ip)}</code></td>
      <td>${escHtml(d.adom)}</td>
      <td>${escHtml(d.platform)}</td>
      <td><button class="btn btn-sm btn-link" data-adom="${escHtml(d.adom)}" data-device="${escHtml(d.name)}">Details</button></td>
    </tr>`).join('');
    resultsDiv.innerHTML = `<table class="sub-table"><thead><tr><th></th><th>Name</th><th>IP</th><th>ADOM</th><th>Platform</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (err) {
    resultsDiv.innerHTML = `<div class="alert alert-danger">${escHtml(err.message)}</div>`;
  }
}

/* ── Auto-refresh ──────────────────────────────────────────────────────── */
function scheduleRefresh(seconds) {
  clearInterval(refreshTimer);
  const adom = document.getElementById('adomSelect').value;
  if (seconds > 0 && adom) refreshTimer = setInterval(() => loadDevices(adom), seconds * 1000);
}

/* ── Exports ────────────────────────────────────────────────────────────── */
const _HA_MODE_LABELS = { 0: 'Standalone', 1: 'Active-Passive', 2: 'Active-Active' };

function haLabel(ha_mode) {
  if (ha_mode === '' || ha_mode == null) return 'Standalone';
  return _HA_MODE_LABELS[ha_mode] ?? _HA_MODE_LABELS[Number(ha_mode)] ?? String(ha_mode);
}

function currentAdom() {
  return document.getElementById('adomSelect').value || 'export';
}

function csvCell(v) {
  return `"${String(v ?? '').replace(/"/g, '""')}"`;
}

function exportCsv() {
  if (!filteredDevices.length) return;
  const adom = currentAdom();
  const ts   = new Date().toLocaleString();
  const meta = [
    `ADOM,${csvCell(adom)}`,
    `Exported,${csvCell(ts)}`,
    `Total Devices,${csvCell(allDevices.length)}`,
    `Filtered Devices,${csvCell(filteredDevices.length)}`,
    '',
  ].join('\r\n');
  const cols = ['Name', 'Comment', 'Management IP', 'Platform', 'Version', 'Serial', 'HA Mode'];
  const body = [
    cols.join(','),
    ...filteredDevices.map(d => [
      d.name    || '',
      d.desc    || '',
      d.ip      || '',
      d.platform|| '',
      d.version || '',
      d.serial  || '',
      haLabel(d.ha_mode),
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')),
  ].join('\r\n');
  download(`firewalls-${adom}.csv`, meta + body, 'text/csv');
}

function exportJson() {
  if (!filteredDevices.length) return;
  const adom = currentAdom();
  const payload = {
    meta: {
      adom,
      exported_at: new Date().toISOString(),
      total: allDevices.length,
      filtered: filteredDevices.length,
    },
    devices: filteredDevices.map(d => ({
      name:     d.name     || '',
      comment:  d.desc     || '',
      mgmt_ip:  d.ip       || '',
      platform: d.platform || '',
      version:  d.version  || '',
      serial:   d.serial   || '',
      ha_mode:  haLabel(d.ha_mode),
    })),
  };
  download(`firewalls-${adom}.json`, JSON.stringify(payload, null, 2), 'application/json');
}

function exportHtml() {
  if (!filteredDevices.length) return;
  const adom  = currentAdom();
  const ts    = new Date().toLocaleString();
  const title = `Firewall Inventory — ADOM: ${escHtml(adom)}`;

  const rows = filteredDevices.map(d => `
    <tr>
      <td>${escHtml(d.name || '')}</td>
      <td>${escHtml(d.desc || '')}</td>
      <td><code>${escHtml(d.ip || '')}</code></td>
      <td>${escHtml(d.platform || '')}</td>
      <td>${escHtml(d.version || '')}</td>
      <td><code>${escHtml(d.serial || '')}</code></td>
      <td>${escHtml(haLabel(d.ha_mode))}</td>
    </tr>`).join('');

  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>${title}</title>
<style>
  body{font-family:Arial,sans-serif;font-size:11px;color:#1a2133;margin:1.5cm}
  h1{font-size:16px;margin-bottom:6px}
  .meta{background:#f3f4f6;border-left:4px solid #3b82f6;padding:8px 12px;border-radius:3px;margin-bottom:14px;font-size:10px}
  .meta table{border:none;width:auto}
  .meta td{padding:1px 14px 1px 0;border:none;background:none}
  .meta td:first-child{font-weight:700;color:#1f2937}
  table{width:100%;border-collapse:collapse;margin-top:8px}
  th{background:#1e3a5f;color:#fff;padding:5px 8px;text-align:left;font-size:10px}
  td{padding:4px 8px;border-bottom:1px solid #e5e7eb;vertical-align:top}
  tr:nth-child(even) td{background:#f9fafb}
  code{font-family:monospace;font-size:10px}
  @media print{body{margin:1cm}}
</style>
</head><body>
<h1>${title}</h1>
<div class="meta">
  <table>
    <tr><td>ADOM</td><td>${escHtml(adom)}</td></tr>
    <tr><td>Exported</td><td>${escHtml(ts)}</td></tr>
    <tr><td>Total Devices</td><td>${allDevices.length}</td></tr>
    <tr><td>Filtered Devices</td><td>${filteredDevices.length}</td></tr>
  </table>
</div>
<table>
  <thead><tr>
    <th>Name</th><th>Comment</th><th>Management IP</th>
    <th>Platform</th><th>Version</th><th>Serial</th><th>HA Mode</th>
  </tr></thead>
  <tbody>${rows}</tbody>
</table>
</body></html>`;

  download(`firewalls-${adom}.html`, html, 'text/html');
}

function setExportButtonState() {
  const disabled = filteredDevices.length === 0;
  ['exportCsvBtn', 'exportJsonBtn', 'exportHtmlBtn'].forEach(id => {
    const btn = document.getElementById(id);
    if (btn) btn.disabled = disabled;
  });
}

/* ── Event wiring ──────────────────────────────────────────────────────── */
document.getElementById('adomSelect').addEventListener('change', function () {
  if (this.value) loadDevices(this.value);
  else { document.getElementById('deviceTableWrapper').style.display = 'none'; }
  scheduleRefresh(parseInt(document.getElementById('autoRefresh').value, 10));
});

document.getElementById('refreshBtn').addEventListener('click', () => {
  const adom = document.getElementById('adomSelect').value;
  if (adom) loadDevices(adom);
});

document.getElementById('autoRefresh').addEventListener('change', function () {
  scheduleRefresh(parseInt(this.value, 10));
});

document.getElementById('pageSize').addEventListener('change', function () {
  pageSize = parseInt(this.value, 10);
  currentPage = 1;
  renderTable();
});

document.getElementById('pagination').addEventListener('click', e => {
  const btn = e.target.closest('[data-page]');
  if (!btn || btn.disabled) return;
  const total = Math.ceil(filteredDevices.length / pageSize);
  currentPage = Math.max(1, Math.min(total, parseInt(btn.dataset.page, 10)));
  renderTable();
});

// Device detail button — event delegation for both table and search results
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-device]');
  if (!btn) return;
  loadDeviceDetail(btn.dataset.adom, btn.dataset.device);
});

document.getElementById('modalClose').addEventListener('click', closeModal);
document.getElementById('deviceModal').addEventListener('click', e => {
  if (e.target === document.getElementById('deviceModal')) closeModal();
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

document.getElementById('searchBtn').addEventListener('click', doSearch);
document.getElementById('searchInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') doSearch();
});

document.getElementById('deviceFilter').addEventListener('input', function () {
  deviceFilterQ = this.value;
  currentPage = 1;
  renderTable();
});

/* ── Deep-link handler ─────────────────────────────────────────────────── */
async function checkDeepLink() {
  const params = new URLSearchParams(location.search);
  const device = params.get('device');
  const adom   = params.get('adom');
  if (!device || !adom) return;

  // Clean URL immediately — prevents re-trigger on refresh
  history.replaceState({}, '', '/firewalls');

  // Pre-fill search and execute it
  document.getElementById('searchInput').value = device;
  await doSearch();

  // Open the detail modal directly — no DOM scan needed
  loadDeviceDetail(adom, device);
}

/* ── Init ──────────────────────────────────────────────────────────────── */
loadAdoms();
scheduleRefresh(parseInt(document.getElementById('autoRefresh').value, 10));
checkDeepLink();
setExportButtonState();
