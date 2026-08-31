'use strict';

/* ── Utilities ─────────────────────────────────────────────────────────────── */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function debounce(fn, ms) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

/* ── Sub-tab routing ────────────────────────────────────────────────────────── */
const panels = ['query', 'browse', 'seghealth'];

document.querySelectorAll('.zp-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.zp-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const target = btn.dataset.panel;
    panels.forEach(p => {
      const el = document.getElementById(`panel-${p}`);
      if (el) el.style.display = p === target ? '' : 'none';
    });
    if (target === 'browse' && !_browseLoaded) loadBrowse();
    if (target === 'seghealth' && !_segLoaded) loadSegHealth();
  });
});

/* ════════════════════════════════════════════════════════════════════════════
   QUERY PANEL
   ════════════════════════════════════════════════════════════════════════════ */

async function runQuery() {
  const src     = document.getElementById('zpSrc').value.trim();
  const dst     = document.getElementById('zpDst').value.trim();
  const svc     = document.getElementById('zpSvc').value.trim();
  const verbose = document.getElementById('zpVerbose').checked;

  if (!src || !dst) { showQueryError('Source and destination are required.'); return; }

  document.getElementById('zpQueryError').style.display = 'none';
  document.getElementById('zpResults').style.display    = 'none';
  document.getElementById('zpRunning').style.display    = '';
  document.getElementById('zpQueryBtn').disabled        = true;

  try {
    const resp = await fetch('/api/zone/query', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ src, dst, service: svc, verbose }),
    });
    const data = await resp.json();
    if (!resp.ok) { showQueryError(data.error || 'Query failed.'); return; }
    renderQueryResults(data);
    document.getElementById('zpResults').style.display = '';
    document.getElementById('zpStatusLine').textContent = `Last query: ${new Date().toLocaleString()}`;
  } catch (e) {
    showQueryError(e.message);
  } finally {
    document.getElementById('zpRunning').style.display = 'none';
    document.getElementById('zpQueryBtn').disabled     = false;
  }
}

function showQueryError(msg) {
  const el = document.getElementById('zpQueryError');
  el.textContent = msg;
  el.style.display = '';
}

function verdictClass(v) {
  return { ALLOWED: 'ALLOWED', BLOCKED: 'BLOCKED', UNKNOWN: 'UNKNOWN' }[v] || 'UNKNOWN';
}
function verdictLabel(v) {
  return v === 'UNKNOWN' ? 'NO MATCHING RULE' : v;
}

function renderQueryResults(results) {
  const container = document.getElementById('zpResultCards');
  container.innerHTML = '';

  results.forEach(r => {
    const vc = verdictClass(r.verdict);
    const vl = verdictLabel(r.verdict);
    const svcBadge = r.service
      ? `<span class="rr-flow-svc">${esc(r.service)}</span>` : '';

    let govHtml = '';
    const gov = r.governing || [];
    if (gov.length) {
      govHtml = `<div class="rr-card-subsection">
        <div class="rr-subsection-label">Governing rule:</div>
        ${gov.map(p => ruleRowHtml(p)).join('')}
      </div>`;
    } else if (r.verdict === 'UNKNOWN') {
      govHtml = `<div class="rr-no-rule">No policy rule covers this zone pair — treat as implicitly blocked.</div>`;
    }

    let allHtml = '';
    const all = r.all_policies || [];
    if (all.length > gov.length) {
      allHtml = `<details class="rr-details">
        <summary class="rr-details-summary">All matching rules (${all.length})</summary>
        <div class="rr-details-body">${all.map(p => ruleRowHtml(p)).join('')}</div>
      </details>`;
    }

    const card = document.createElement('div');
    card.className = `rr-result-card result-card-${vc}`;
    card.innerHTML = `
      <div class="rr-card-header">
        <div class="rr-card-flow">
          <code>${esc(r.src)}</code>
          <span class="rr-arrow">→</span>
          <code>${esc(r.dst)}</code>
          ${svcBadge}
        </div>
        <div class="rr-card-badges">
          <span class="verdict-${vc}">${esc(vl)}</span>
        </div>
      </div>
      <div class="rr-card-zone-block">
        <div class="rr-card-row rr-zone-zones">
          <span>&#8599; Src zones: <strong>${esc((r.src_zones || []).join(', ') || '(none matched)')}</strong></span><br>
          <span>&#8600; Dst zones: <strong>${esc((r.dst_zones || []).join(', ') || '(none matched)')}</strong></span>
        </div>
        ${govHtml}
        ${allHtml}
      </div>`;
    container.appendChild(card);
  });

  if (!results.length) {
    container.innerHTML = '<div class="empty-state" style="padding:1.5rem">No results returned.</div>';
  }
}

function ruleRowHtml(p) {
  const svc = p.services && p.services.length
    ? `<span class="rr-rule-svc">[${esc(p.services.join(', '))}]</span>` : '';
  const sev = p.severity ? `<span class="rr-rule-sev">(${esc(p.severity)})</span>` : '';
  const atColor = p.access_type === 'allow all'  ? 'var(--success)'
                : p.access_type === 'allow only' ? 'var(--info)'
                : p.access_type === 'block all'  ? 'var(--danger)' : 'var(--warning)';
  return `<div class="rr-rule-row">
    <span class="rr-rule-set">[${esc(p.policy_set || '')}]</span>
    ${esc(p.matched_from_zone || p.from_zone || '')} → ${esc(p.matched_to_zone || p.to_zone || '')}
    &nbsp;|&nbsp;
    <strong style="color:${atColor}">${esc(p.access_type || '')}</strong>
    ${svc} ${sev}
  </div>`;
}

document.getElementById('zpQueryBtn').addEventListener('click', runQuery);
document.getElementById('zpSvc').addEventListener('keydown', e => {
  if (e.key === 'Enter') runQuery();
});

/* ════════════════════════════════════════════════════════════════════════════
   BROWSE PANEL
   ════════════════════════════════════════════════════════════════════════════ */

let _browseLoaded  = false;
let _allZones      = [];
let _allPolicies   = [];
let _selectedZone  = '';

async function loadBrowse() {
  _browseLoaded = true;
  try {
    const [zr, pr] = await Promise.all([
      fetch('/api/zone/zones').then(r => r.json()),
      fetch('/api/zone/policies').then(r => r.json()),
    ]);
    if (zr.error) { showBrowseError(zr.error); return; }
    if (pr.error) { showBrowseError(pr.error); return; }

    _allZones    = zr.zones || [];
    _allPolicies = Array.isArray(pr) ? pr : [];

    document.getElementById('zpStatZones').textContent    = _allZones.length;
    document.getElementById('zpStatSubnets').textContent  = zr.total_subnets || 0;
    document.getElementById('zpStatPolicies').textContent = _allPolicies.length;
    document.getElementById('zpBrowseStats').style.display = '';

    const sel = document.getElementById('zpZoneSelect');
    sel.innerHTML = '<option value="">— Select zone —</option>' +
      [..._allZones].sort((a, b) => a.name.localeCompare(b.name))
        .map(z => `<option value="${esc(z.name)}">${esc(z.name)}</option>`).join('');

    renderZones();
    renderPolicies();
  } catch (e) {
    showBrowseError(e.message);
  }
}

function showBrowseError(msg) {
  const el = document.getElementById('zpBrowseError');
  el.textContent = msg; el.style.display = '';
}

// ── Zone list ────────────────────────────────────────────────────────────────

function renderZones() {
  const q   = (document.getElementById('zpZoneSearch').value || '').toLowerCase();
  const fil = document.getElementById('zpZoneFilter').value;

  const visible = _allZones.filter(z => {
    if (_selectedZone) return z.name === _selectedZone;
    const subnetStr = (z.subnets || []).map(s => s.subnet).join(' ').toLowerCase();
    const textMatch = !q ||
      z.name.toLowerCase().includes(q) ||
      (z.description || '').toLowerCase().includes(q) ||
      subnetStr.includes(q);
    const filterMatch =
      fil === ''             ? true :
      fil === 'has-subnets'  ? z.subnets.length > 0 :
      fil === 'no-subnets'   ? z.subnets.length === 0 :
      fil === 'has-children' ? z.children.length > 0 :
      fil === 'top-level'    ? z.parents.length === 0 : true;
    return textMatch && filterMatch;
  });

  document.getElementById('zpZoneCount').textContent =
    `${visible.length} zone${visible.length !== 1 ? 's' : ''}`;

  const container = document.getElementById('zpZoneList');
  container.innerHTML = visible.map((z, idx) => {
    const parentBadges = z.parents.map(p =>
      `<span class="zp-badge zp-badge-parent" title="Parent zone">${esc(p)}</span>`).join('');
    const childBadge = z.children.length
      ? `<span class="zp-badge zp-badge-child">${z.children.length} child${z.children.length !== 1 ? 'ren' : ''}</span>` : '';
    const subnetBadge = `<span class="zp-badge zp-badge-neutral">${z.subnets.length} subnet${z.subnets.length !== 1 ? 's' : ''}</span>`;

    const subnetTable = z.subnets.length
      ? `<table class="data-table" style="margin-top:.4rem">
          <thead><tr><th>Subnet</th><th>Description</th></tr></thead>
          <tbody>${z.subnets.map(s =>
            `<tr><td style="font-family:monospace;font-size:.82rem">${esc(s.subnet)}</td>
                 <td style="font-size:.8rem;color:var(--text-muted)">${esc(s.description || '—')}</td></tr>`
          ).join('')}</tbody>
        </table>`
      : `<p class="text-muted" style="font-size:.82rem;margin:.25rem 0 0">No subnets assigned.</p>`;

    const meta = [
      z.domain ? `<span class="text-muted">Domain:</span> <strong>${esc(z.domain)}</strong>` : '',
      `<span class="text-muted">Shared:</span> <strong>${z.is_shared ? 'Yes' : 'No'}</strong>`,
      z.description ? `<span class="text-muted">Desc:</span> ${esc(z.description)}` : '',
    ].filter(Boolean).join('&ensp;·&ensp;');

    const hierarchy = [
      z.parents.length ? `<div class="text-muted" style="font-size:.8rem">Parents: ${z.parents.map(p => `<strong>${esc(p)}</strong>`).join(', ')}</div>` : '',
      z.children.length ? `<div class="text-muted" style="font-size:.8rem">Children: ${z.children.map(c => `<strong>${esc(c)}</strong>`).join(', ')}</div>` : '',
    ].filter(Boolean).join('');

    return `<div class="zp-zone-card">
      <div class="zp-zone-header" data-idx="${idx}">
        <span class="zp-zone-name">${esc(z.name)}</span>
        <span class="zp-zone-badges">${parentBadges}${childBadge}${subnetBadge}</span>
        <span class="zp-zone-chevron">&#9660;</span>
      </div>
      <div class="zp-zone-body">
        <div style="font-size:.82rem;margin-bottom:.35rem">${meta}</div>
        ${hierarchy}
        ${subnetTable}
      </div>
    </div>`;
  }).join('') || '<div class="empty-state" style="padding:1rem">No zones match your filter.</div>';

  container.querySelectorAll('.zp-zone-header').forEach(h => {
    h.addEventListener('click', () => {
      h.closest('.zp-zone-card').classList.toggle('zp-open');
    });
  });

  if (visible.length === 1 || _selectedZone) {
    const card = container.querySelector('.zp-zone-card');
    if (card) card.classList.add('zp-open');
  }
}

// ── Policy table ─────────────────────────────────────────────────────────────

function renderPolicies() {
  const q   = (document.getElementById('zpPolSearch').value || '').toLowerCase();
  const acc = document.getElementById('zpPolAccessFilter').value;
  const sev = document.getElementById('zpPolSevFilter').value;

  const visible = _allPolicies.filter(p => {
    const text = [p.policy_set, p.from_zone, p.to_zone, p.description, ...(p.services || [])]
      .join(' ').toLowerCase();
    return (!q || text.includes(q)) &&
           (!acc || p.access_type === acc) &&
           (!sev || p.severity === sev);
  });

  document.getElementById('zpPolCount').textContent =
    `${visible.length} rule${visible.length !== 1 ? 's' : ''}`;

  const ACCESS_COLORS = {
    'allow all':  { bg: 'rgba(34,197,94,.15)',  color: 'var(--success)' },
    'allow only': { bg: 'rgba(6,182,212,.15)',   color: 'var(--info)' },
    'block all':  { bg: 'rgba(239,68,68,.15)',   color: 'var(--danger)' },
    'block only': { bg: 'rgba(245,158,11,.15)',  color: 'var(--warning)' },
  };

  document.getElementById('zpPolTbody').innerHTML = visible.map(p => {
    const at = ACCESS_COLORS[p.access_type] || { bg: 'transparent', color: 'inherit' };
    const sevColor = p.severity === 'critical' ? 'var(--danger)' : 'var(--text-muted)';
    const svcs = (p.services || []).join(', ') || '—';
    return `<tr>
      <td style="font-size:.78rem;color:var(--text-muted)">${p.index}</td>
      <td style="font-size:.82rem">${esc(p.policy_set)}</td>
      <td style="font-family:monospace;font-size:.82rem">${esc(p.from_zone)}</td>
      <td style="font-family:monospace;font-size:.82rem">${esc(p.to_zone)}</td>
      <td><span class="hygiene-badge" style="background:${at.bg};color:${at.color};border-color:${at.color}40">${esc(p.access_type)}</span></td>
      <td style="font-size:.78rem;color:var(--danger)">${esc(svcs)}</td>
      <td><span style="font-size:.75rem;font-weight:600;color:${sevColor}">${esc(p.severity)}</span></td>
      <td style="font-size:.78rem;color:var(--text-muted)">${esc(p.description || '—')}</td>
    </tr>`;
  }).join('') || `<tr><td colspan="8" class="empty-state" style="padding:.85rem">No policies match your filter.</td></tr>`;
}

// Browse sub-tabs
document.querySelectorAll('.zp-browse-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.zp-browse-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const target = btn.dataset.bt;
    ['zones', 'policies'].forEach(t => {
      const el = document.getElementById(`bt-${t}`);
      if (el) el.style.display = t === target ? '' : 'none';
    });
  });
});

const dZoneSearch = debounce(renderZones, 200);
document.getElementById('zpZoneSearch').addEventListener('input', () => {
  _selectedZone = '';
  document.getElementById('zpZoneSelect').value = '';
  dZoneSearch();
});
document.getElementById('zpZoneFilter').addEventListener('change', () => {
  _selectedZone = '';
  document.getElementById('zpZoneSelect').value = '';
  renderZones();
});
document.getElementById('zpZoneSelect').addEventListener('change', function () {
  _selectedZone = this.value;
  document.getElementById('zpZoneSearch').value = '';
  renderZones();
});
const dPolSearch = debounce(renderPolicies, 200);
document.getElementById('zpPolSearch').addEventListener('input', dPolSearch);
document.getElementById('zpPolAccessFilter').addEventListener('change', renderPolicies);
document.getElementById('zpPolSevFilter').addEventListener('change', renderPolicies);


/* ════════════════════════════════════════════════════════════════════════════
   SEGMENTATION HEALTH PANEL
   ════════════════════════════════════════════════════════════════════════════ */

let _segLoaded = false;

async function loadSegHealth() {
  _segLoaded = true;
  document.getElementById('zpSegLoading').style.display = '';
  document.getElementById('zpSegError').style.display   = 'none';
  document.getElementById('zpSegContent').style.display = 'none';

  try {
    const resp = await fetch('/api/zone/segmentation-report');
    const data = await resp.json();
    if (!resp.ok) {
      _segLoaded = false;
      showSegError(data.error || 'Failed to load segmentation report.');
      return;
    }
    renderSegHealth(data);
  } catch (e) {
    _segLoaded = false;
    showSegError(e.message);
  } finally {
    document.getElementById('zpSegLoading').style.display = 'none';
  }
}

function showSegError(msg) {
  const el = document.getElementById('zpSegError');
  el.textContent = msg;
  el.style.display = '';
}

function renderSegHealth(data) {
  // Score
  const score = data.score ?? 100;
  const scoreEl = document.getElementById('zpSegScore');
  scoreEl.textContent = score.toFixed(1) + '%';
  scoreEl.style.color = score >= 80 ? 'var(--success)'
                      : score >= 50 ? 'var(--warning)'
                      : 'var(--danger)';

  document.getElementById('zpSegTotalZones').textContent = data.total_zones ?? '—';
  document.getElementById('zpSegTotalPairs').textContent = data.total_pairs ?? '—';
  document.getElementById('zpSegOpenCount').textContent  = data.open_pair_count ?? 0;

  // Open pairs table
  const pairs = data.open_pairs || [];
  const tbody = document.getElementById('zpOpenPairsTbody');
  if (pairs.length === 0) {
    document.getElementById('zpOpenPairsWrapper').style.display = 'none';
    document.getElementById('zpOpenPairsEmpty').style.display   = '';
  } else {
    document.getElementById('zpOpenPairsWrapper').style.display = '';
    document.getElementById('zpOpenPairsEmpty').style.display   = 'none';
    tbody.innerHTML = pairs.map(p => `<tr>
      <td style="font-family:monospace;font-size:.84rem">${esc(p.from_zone)}</td>
      <td style="font-family:monospace;font-size:.84rem">${esc(p.to_zone)}</td>
      <td style="text-align:center">${p.policy_count}</td>
    </tr>`).join('');
  }

  // Trust mismatches
  const mismatches = data.trust_mismatches || [];
  if (!data.has_trust_levels) {
    document.getElementById('zpTrustNoLevels').style.display = '';
    document.getElementById('zpTrustList').innerHTML = '';
  } else if (mismatches.length === 0) {
    document.getElementById('zpTrustNoLevels').style.display = 'none';
    document.getElementById('zpTrustList').innerHTML =
      '<p class="text-muted" style="font-style:italic;font-size:.87rem">No trust boundary mismatches found.</p>';
  } else {
    document.getElementById('zpTrustNoLevels').style.display = 'none';
    document.getElementById('zpTrustList').innerHTML = mismatches.map(m => {
      const dir = m.delta > 0 ? 'low→high trust' : 'high→low trust';
      return `<div class="zp-zone-card" style="margin-bottom:.5rem;border-left:3px solid var(--warning)">
        <div style="padding:.5rem .75rem;font-size:.87rem">
          <strong style="font-family:monospace">${esc(m.from_zone)}</strong>
          <span style="color:var(--text-muted)"> → </span>
          <strong style="font-family:monospace">${esc(m.to_zone)}</strong>
          <span class="hygiene-badge" style="margin-left:.5rem;background:rgba(245,158,11,.15);color:var(--warning);border-color:#f59e0b40">
            Δ${Math.abs(m.delta)} (${dir})
          </span>
          <span class="text-muted" style="font-size:.8rem;margin-left:.4rem">
            trust ${m.from_trust} → ${m.to_trust} · ${m.policy_count} open polic${m.policy_count === 1 ? 'y' : 'ies'}
          </span>
        </div>
      </div>`;
    }).join('');
  }

  document.getElementById('zpSegContent').style.display = '';
}
