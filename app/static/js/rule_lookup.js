'use strict';

/* Rule Lookup — searches the server-side rule cache by source / destination / port.
   Relies on globals from hygiene.js: esc(), download(), debounce(). */

let rlRows        = [];
let rlFiltered    = [];
let rlPage        = 1;
let rlPageSize    = 25;
let rlFilter      = '';
let rlField       = '';
let rlRegex       = false;
let rlMeta        = null; // { adom, src, dst, port, last_updated, ... }

const $rl = id => document.getElementById(id);

/* ── Helpers ────────────────────────────────────────────────────────────────── */
function _rlCls(label) {
  if (label === 'exact' || label === 'name') return 'exact';
  if (label === 'broader') return 'broader';
  return 'narrower'; // narrower + overlap
}

const RL_INLINE_NAMES = 3;

function _rlNamesHtml(names, field, hideUnmatched) {
  const hits = (field && field.names) || {};
  const via  = (field && field.via) || {};
  if (!names || !names.length) return '<span style="color:var(--text-muted)">—</span>';
  const one = n => {
    const label = hits[n];
    if (!label) return `<span class="rl-plain">${esc(n)}</span>`;
    const members = via[n] ? `<div class="rl-via">via ${via[n].map(esc).join(', ')}</div>` : '';
    return `<span class="rl-m rl-m-${_rlCls(label)}">${esc(n)}<span class="rl-how">${esc(label)}</span></span>${members}`;
  };
  // Matched names first, so the reason a rule is listed is never hidden.
  const matched = names.filter(n => hits[n]);
  const others  = names.filter(n => !hits[n]);
  // Port column: other services on the rule did not match, so keep them out of sight.
  const room    = hideUnmatched && matched.length ? 0 : Math.max(0, RL_INLINE_NAMES - matched.length);
  const shown   = [...matched, ...others.slice(0, room)];
  const rest    = others.slice(room);
  let html = shown.map(one).join('');
  if (rest.length) {
    const lbl = hideUnmatched && matched.length
      ? `+${rest.length} other service${rest.length === 1 ? '' : 's'} (no match)`
      : `+${rest.length} more`;
    html += `<details class="rl-more"><summary>${lbl}</summary>${rest.map(one).join('')}</details>`;
  }
  return html;
}

function _rlMatchText(names, field) {
  const hits = (field && field.names) || {};
  const via  = (field && field.via) || {};
  return (names || []).filter(n => hits[n])
    .map(n => `${n}: ${hits[n]}${via[n] ? ` (via ${via[n].join(', ')})` : ''}`).join('; ');
}

function _rlFieldText(r, f) {
  switch (f) {
    case 'firewall': return (r.firewalls || []).join(' ');
    case 'package':  return r.package || '';
    case 'name':     return `${r.policy_block || ''} ${r.name || ''}`;
    case 'id':       return String(r.policyid ?? '');
    case 'comment':  return r.comment || '';
    case 'srcaddr':  return (r.srcaddr || []).join(' ');
    case 'dstaddr':  return (r.dstaddr || []).join(' ');
    case 'service':  return (r.service || []).join(' ');
    case 'srcintf':  return (r.srcintf || []).join(' ');
    case 'dstintf':  return (r.dstintf || []).join(' ');
    default:
      return ['firewall', 'package', 'name', 'id', 'comment', 'srcaddr', 'dstaddr',
              'service', 'srcintf', 'dstintf'].map(k => _rlFieldText(r, k)).join('\n');
  }
}

function _rlSearchDesc() {
  const m = rlMeta || {};
  return [m.src && `Source=${m.src}`, m.dst && `Destination=${m.dst}`, m.port && `Port=${m.port}`]
    .filter(Boolean).join(', ');
}

/* ── Search ─────────────────────────────────────────────────────────────────── */
function _rlUpdateSearchBtn() {
  const adom = $rl('rlAdom').value;
  const any  = $rl('rlSrc').value.trim() || $rl('rlDst').value.trim() || $rl('rlPort').value.trim();
  ['rlSrc', 'rlDst', 'rlPort'].forEach(id => { $rl(id).disabled = !adom; });
  $rl('rlSearchBtn').disabled = !adom || !any;
}

async function runRuleLookup(includePortOnly) {
  const adom = $rl('rlAdom').value;
  const src  = $rl('rlSrc').value.trim();
  const dst  = $rl('rlDst').value.trim();
  const port = $rl('rlPort').value.trim();
  if (!adom || !(src || dst || port)) return;

  $rl('rlError').style.display          = 'none';
  $rl('rlSearchBtn').disabled           = true;
  $rl('rlRunning').style.display        = '';
  $rl('rlProgressWrap').style.display   = 'block';

  try {
    const resp = await fetch(`/api/hygiene/adoms/${encodeURIComponent(adom)}/rule-lookup`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ src, dst, port, include_port_only: !!includePortOnly }),
    });
    const data = await resp.json();
    if (resp.status === 202) {
      $rl('rlResults').style.display = 'none';
      $rl('rlError').textContent = 'The rule cache for this ADOM is still being built — try again in a minute.';
      $rl('rlError').style.display = '';
      return;
    }
    if (!resp.ok) {
      $rl('rlResults').style.display = 'none';
      $rl('rlError').textContent = data.error || 'Rule lookup failed.';
      $rl('rlError').style.display = '';
      return;
    }
    rlRows = data.rows || [];
    rlMeta = { adom, src, dst, port, includePortOnly: !!includePortOnly, ...data };
    rlPage = 1;
    applyRlFilter();
    renderRlResults();
    $rl('rlResults').style.display = '';
  } catch (err) {
    $rl('rlError').textContent = err.message;
    $rl('rlError').style.display = '';
  } finally {
    $rl('rlRunning').style.display      = 'none';
    $rl('rlProgressWrap').style.display = 'none';
    _rlUpdateSearchBtn();
  }
}

/* ── Filter ─────────────────────────────────────────────────────────────────── */
function applyRlFilter() {
  if (!rlFilter) { rlFiltered = rlRows; return; }
  let test;
  if (rlRegex) {
    try {
      const re = new RegExp(rlFilter, 'i');
      test = t => re.test(t);
    } catch (_) {
      test = t => t.toLowerCase().includes(rlFilter.toLowerCase());
    }
  } else {
    const q = rlFilter.toLowerCase();
    test = t => t.toLowerCase().includes(q);
  }
  rlFiltered = rlRows.filter(r => test(_rlFieldText(r, rlField)));
}

/* ── Render ─────────────────────────────────────────────────────────────────── */
function _rlRow(r) {
  const m = r.match || {};
  const statusColor = r.status === 'enable' ? 'var(--success, #22c55e)' : 'var(--text-muted)';
  const actionColor = r.action === 'deny' || r.action === 'block' ? '#ef4444' : '#22c55e';
  const intf = [
    ...(r.srcintf || []).map(i => `<span class="pv-intf pv-intf-src" title="Source">${esc(i)}</span>`),
    ...(r.dstintf || []).map(i => `<span class="pv-intf pv-intf-dst" title="Destination">${esc(i)}</span>`),
  ].join('');
  const fw = (r.firewalls || []).length
    ? r.firewalls.map(f => `<div>${esc(f)}</div>`).join('')
    : '<span style="color:var(--text-muted)">—</span>';
  const block = r.policy_block
    ? `<span style="color:var(--text-muted);font-size:.7rem">↳ ${esc(r.policy_block)}</span><br>` : '';
  return `<tr${r.status !== 'enable' ? ' style="opacity:.55"' : ''}>
    <td style="font-size:.8rem">${fw}<div class="rl-sub">${esc(r.package)}</div></td>
    <td>${block}<strong>${esc(r.name || '—')}</strong> <span class="rl-sub">id:${esc(String(r.policyid))}</span>${r.comment ? `<div class="rl-comment" title="${esc(r.comment)}">${esc(r.comment)}</div>` : ''}</td>
    <td><span style="font-size:.75rem;font-weight:600;color:${statusColor}">${esc(r.status)}</span><br><span style="font-size:.75rem;font-weight:600;color:${actionColor}">${esc(r.action)}</span></td>
    <td>${_rlNamesHtml(r.srcaddr, m.src)}</td>
    <td>${_rlNamesHtml(r.dstaddr, m.dst)}</td>
    <td>${_rlNamesHtml(r.service, m.port, true)}</td>
    <td style="font-size:.78rem">${intf || '<span style="color:var(--text-muted)">—</span>'}</td>
  </tr>`;
}

function renderRlResults() {
  const m = rlMeta || {};
  const portOnly = m.port_only_count || 0;

  // Summary + data age
  let summary = `${m.total || 0} rule${m.total === 1 ? '' : 's'} listed`;
  if (m.skipped_count) {
    summary += ` — ${m.skipped_count} rule${m.skipped_count === 1 ? '' : 's'} with all/any or negated fields were not matched`;
  }
  $rl('rlSummary').textContent = summary;
  let asOf = m.last_updated ? `Data as of ${new Date(m.last_updated).toLocaleString()}` : 'Data age unknown';
  if (m.status === 'error') asOf += ` — last refresh failed: ${m.error || 'unknown error'} (showing previous data)`;
  if ((m.package_errors || []).length) asOf += ` — ${m.package_errors.length} package(s) could not be read`;
  $rl('rlAsOf').textContent = asOf;
  $rl('rlAsOf').title = (m.package_errors || []).join('\n');

  // Port-only step
  const banner = $rl('rlPortOnlyBanner');
  if (portOnly > 0 && !m.includePortOnly) {
    $rl('rlPortOnlyText').textContent =
      `${portOnly} more rule${portOnly === 1 ? '' : 's'} match only on port ${m.port}` +
      ` (source and destination do not match).`;
    banner.style.display = '';
  } else {
    banner.style.display = 'none';
  }

  // Table
  const total = Math.ceil(rlFiltered.length / rlPageSize) || 1;
  rlPage = Math.min(rlPage, total);
  const slice = rlFiltered.slice((rlPage - 1) * rlPageSize, rlPage * rlPageSize);
  $rl('rlCount').textContent = rlFiltered.length === rlRows.length
    ? `${rlRows.length} rule${rlRows.length === 1 ? '' : 's'} — page ${rlPage} of ${total}`
    : `${rlFiltered.length} of ${rlRows.length} rules — page ${rlPage} of ${total}`;

  let empty = 'No rules match your filter.';
  if (!rlRows.length) {
    empty = portOnly > 0 && !m.includePortOnly
      ? 'No rules match source or destination.'
      : 'No rules found for this search.';
  }
  $rl('rlTbody').innerHTML = slice.map(_rlRow).join('')
    || `<tr><td colspan="7" class="empty-state" style="padding:.85rem 1rem">${esc(empty)}</td></tr>`;
  renderRlPagination(total);
}

function renderRlPagination(total) {
  const pg = $rl('rlPagination');
  if (total <= 1) { pg.innerHTML = ''; return; }
  const btn = (label, page, disabled, active) =>
    `<button class="pg-btn${active ? ' active' : ''}" data-rlpage="${page}" ${disabled ? 'disabled' : ''}>${label}</button>`;
  let html = btn('&laquo;&laquo;', 1, rlPage === 1, false) + btn('&lsaquo;', rlPage - 1, rlPage === 1, false);
  const s = Math.max(1, rlPage - 2), e = Math.min(total, s + 4);
  for (let i = s; i <= e; i++) html += btn(i, i, false, i === rlPage);
  html += btn('&rsaquo;', rlPage + 1, rlPage === total, false) + btn('&raquo;&raquo;', total, rlPage === total, false);
  pg.innerHTML = html;
}

/* ── Exports ────────────────────────────────────────────────────────────────── */
function _rlHeaderLines() {
  const m = rlMeta || {};
  return [
    `Rule Lookup — ADOM: ${m.adom || ''}`,
    `Search: ${_rlSearchDesc()}`,
    `Generated: ${new Date().toLocaleString()}`,
    `Data as of: ${m.last_updated ? new Date(m.last_updated).toLocaleString() : 'unknown'}`,
    `Filter: ${rlFilter ? `"${rlFilter}"${rlField ? ` in ${rlField}` : ''}${rlRegex ? ' (regex)' : ''}` : 'none'}`,
    `Rules: ${rlFiltered.length} of ${rlRows.length}` +
      (m.port_only_count && !m.includePortOnly ? ` (+${m.port_only_count} port-only not shown)` : ''),
  ];
}

function _rlFile(ext) {
  return `rule-lookup_${((rlMeta || {}).adom || 'adom').replace(/\W+/g, '_')}.${ext}`;
}

function rlExportCsv() {
  const q = s => `"${String(s ?? '').replace(/"/g, '""')}"`;
  const header = ['Firewall / VDOM', 'Package', 'Policy Block', 'ID', 'Name', 'Status', 'Action',
                  'Source', 'Source Match', 'Destination', 'Destination Match',
                  'Service', 'Service Match', 'Src Interface', 'Dst Interface', 'Comment'];
  const lines = [..._rlHeaderLines().map(l => `# ${l}`), header.join(',')];
  rlFiltered.forEach(r => {
    const m = r.match || {};
    lines.push([
      q((r.firewalls || []).join('; ')), q(r.package), q(r.policy_block), q(r.policyid), q(r.name),
      r.status, r.action,
      q((r.srcaddr || []).join('; ')), q(_rlMatchText(r.srcaddr, m.src)),
      q((r.dstaddr || []).join('; ')), q(_rlMatchText(r.dstaddr, m.dst)),
      q((r.service || []).join('; ')), q(_rlMatchText(r.service, m.port)),
      q((r.srcintf || []).join('; ')), q((r.dstintf || []).join('; ')), q(r.comment),
    ].join(','));
  });
  download(_rlFile('csv'), lines.join('\r\n'), 'text/csv');
}

function rlExportJson() {
  const m = rlMeta || {};
  const payload = {
    adom: m.adom,
    generated: new Date().toISOString(),
    data_as_of: m.last_updated || null,
    search: { src: m.src || null, dst: m.dst || null, port: m.port || null },
    filters: { text: rlFilter || null, field: rlField || null, regex: rlRegex },
    total_rules: rlRows.length,
    filtered_rules: rlFiltered.length,
    port_only_count: m.port_only_count || 0,
    skipped_count: m.skipped_count || 0,
    rules: rlFiltered.map(r => ({
      firewalls: r.firewalls, package: r.package, policy_block: r.policy_block || null,
      id: r.policyid, name: r.name, status: r.status, action: r.action,
      srcaddr: r.srcaddr, dstaddr: r.dstaddr, service: r.service,
      srcintf: r.srcintf, dstintf: r.dstintf, comment: r.comment, match: r.match,
    })),
  };
  download(_rlFile('json'), JSON.stringify(payload, null, 2), 'application/json');
}

function rlExportPdf() {
  const title = `Rule Lookup — ${(rlMeta || {}).adom || ''}`;
  const cell = (names, field) => {
    const hits = (field && field.names) || {};
    const via  = (field && field.via) || {};
    return (names || []).map(n => hits[n]
      ? `<div><b>${esc(n)}</b> <small>(${esc(hits[n])}${via[n] ? `; via ${esc(via[n].join(', '))}` : ''})</small></div>`
      : `<div>${esc(n)}</div>`).join('');
  };
  const rows = rlFiltered.map(r => {
    const m = r.match || {};
    const actionColor = r.action === 'deny' || r.action === 'block' ? '#dc2626' : '#16a34a';
    return `<tr${r.status !== 'enable' ? ' style="opacity:.55"' : ''}>
      <td>${(r.firewalls || []).map(f => `<div>${esc(f)}</div>`).join('')}</td>
      <td>${esc(r.package)}</td>
      <td>${r.policy_block ? `<small>↳ ${esc(r.policy_block)}</small><br>` : ''}<strong>${esc(r.name || '—')}</strong><br><small>id: ${esc(String(r.policyid))}</small></td>
      <td>${esc(r.status)}</td>
      <td style="color:${actionColor};font-weight:600">${esc(r.action)}</td>
      <td>${cell(r.srcaddr, m.src)}</td>
      <td>${cell(r.dstaddr, m.dst)}</td>
      <td>${cell(r.service, m.port)}</td>
      <td>${esc((r.srcintf || []).join(', '))} → ${esc((r.dstintf || []).join(', '))}</td>
      <td style="color:#5a6478">${esc(r.comment)}</td>
    </tr>`;
  }).join('');
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>${esc(title)}</title>
<style>
  body{font-family:sans-serif;font-size:10px;color:#1a2133;margin:1cm}
  h1{font-size:14px;margin-bottom:4px}
  .meta{font-size:9px;color:#5a6478;margin-bottom:8px;border-left:3px solid #93c5fd;padding-left:6px}
  table{width:100%;border-collapse:collapse}
  th{background:#eef1f5;text-align:left;padding:4px 6px;font-size:9px;text-transform:uppercase;border-bottom:2px solid #d0d7e2}
  td{padding:3px 6px;border-bottom:1px solid #e5e7eb;vertical-align:top;font-size:9px}
  small{color:#5a6478}
  @media print{body{margin:.5cm}}
</style></head><body>
<h1>${esc(title)}</h1>
<div class="meta">${_rlHeaderLines().map(l => `<div>${esc(l)}</div>`).join('')}</div>
<table><thead><tr><th>Firewall / VDOM</th><th>Package</th><th>Name / ID</th><th>Status</th><th>Action</th><th>Source</th><th>Destination</th><th>Service</th><th>Interfaces</th><th>Comment</th></tr></thead>
<tbody>${rows}</tbody></table></body></html>`;
  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); win.focus(); win.print(); }
}

/* ── Events ─────────────────────────────────────────────────────────────────── */
$rl('rlAdom').addEventListener('change', function () {
  _rlUpdateSearchBtn();
  if (!this.value) { $rl('rlResults').style.display = 'none'; rlRows = []; rlFiltered = []; }
});
['rlSrc', 'rlDst', 'rlPort'].forEach(id => {
  $rl(id).addEventListener('input', _rlUpdateSearchBtn);
  $rl(id).addEventListener('keydown', e => { if (e.key === 'Enter' && !$rl('rlSearchBtn').disabled) runRuleLookup(false); });
});
$rl('rlSearchBtn').addEventListener('click', () => runRuleLookup(false));
$rl('rlPortOnlyBtn').addEventListener('click', () => runRuleLookup(true));

$rl('rlFilter').addEventListener('input', debounce(function () {
  rlFilter = this.value; rlPage = 1; applyRlFilter(); renderRlResults();
}, 200));
$rl('rlFieldFilter').addEventListener('change', function () {
  rlField = this.value; rlPage = 1; applyRlFilter(); renderRlResults();
});
$rl('rlRegexMode').addEventListener('change', function () {
  rlRegex = this.checked; rlPage = 1; applyRlFilter(); renderRlResults();
});
$rl('rlPageSize').addEventListener('change', function () {
  rlPageSize = parseInt(this.value, 10); rlPage = 1; renderRlResults();
});
$rl('rlPagination').addEventListener('click', e => {
  const btn = e.target.closest('[data-rlpage]');
  if (!btn || btn.disabled) return;
  const total = Math.ceil(rlFiltered.length / rlPageSize) || 1;
  rlPage = Math.max(1, Math.min(total, parseInt(btn.dataset.rlpage, 10)));
  renderRlResults();
});

$rl('rlRefreshBtn').addEventListener('click', async () => {
  const adom = $rl('rlAdom').value;
  if (!adom) return;
  $rl('rlRefreshBtn').disabled = true;
  try {
    await fetch(`/api/hygiene/adoms/${encodeURIComponent(adom)}/rule-lookup/refresh`, { method: 'POST' });
    $rl('rlAsOf').textContent = 'Refresh started — search again in a minute or two to see updated data.';
  } finally {
    setTimeout(() => { $rl('rlRefreshBtn').disabled = false; }, 5000);
  }
});

$rl('rlExportCsv').addEventListener('click', rlExportCsv);
$rl('rlExportJson').addEventListener('click', rlExportJson);
$rl('rlExportPdf').addEventListener('click', rlExportPdf);

$rl('rlCloseBtn').addEventListener('click', () => {
  $rl('rlResults').style.display = 'none';
  rlRows = []; rlFiltered = []; rlFilter = '';
  ['rlSrc', 'rlDst', 'rlPort', 'rlFilter'].forEach(id => { $rl(id).value = ''; });
  $rl('rlAdom').value = '';
  _rlUpdateSearchBtn();
});
