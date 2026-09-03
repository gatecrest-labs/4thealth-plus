'use strict';

/* ── Utilities ─────────────────────────────────────────────────────────────── */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ── State ─────────────────────────────────────────────────────────────────── */
let flows     = [];   // [{src, dst, service, comment}, ...]
let packages  = [];   // [{adom, name, path}, ...]
let results   = [];   // analysis results from server
let pkgPaths  = {};   // package display name → path

/* ── ADOM loader ────────────────────────────────────────────────────────────── */
async function loadAdoms() {
  const sel = document.getElementById('rrAdom');
  try {
    const resp = await fetch('/api/rule-review/adoms');
    if (resp.status === 401) { location.href = '/login'; return; }
    const adoms = await resp.json();
    if (!Array.isArray(adoms)) return;
    adoms.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a; opt.textContent = a;
      sel.appendChild(opt);
    });
  } catch (_) {}
}

async function loadPackages(adom) {
  const sel = document.getElementById('rrPackage');
  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;
  pkgPaths = {};
  document.getElementById('rrAddPkgBtn').disabled = true;
  try {
    const resp = await fetch(`/api/rule-review/adoms/${encodeURIComponent(adom)}/packages`);
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
    sel.innerHTML = '<option value="">Failed to load</option>';
  }
}

/* ── Zone-script status ─────────────────────────────────────────────────────── */
async function checkZoneStatus() {
  try {
    const resp = await fetch('/api/rule-review/zone-status');
    const data = await resp.json();
    const badge = document.getElementById('rrZoneStatus');
    badge.style.display = '';
    if (data.available) {
      badge.textContent = '✓ Zone policy database connected';
      badge.className   = 'rr-zone-badge rr-zone-ok';
    } else {
      badge.textContent = '⚠ Zone policy database not available';
      badge.className   = 'rr-zone-badge rr-zone-warn';
    }
  } catch (_) {}
}

/* ── Flow management ────────────────────────────────────────────────────────── */
function renderFlows() {
  const tbody = document.getElementById('rrFlowTbody');
  const wrap  = document.getElementById('rrFlowTableWrap');
  if (!flows.length) { wrap.style.display = 'none'; tbody.innerHTML = ''; updateReviewBtn(); return; }
  wrap.style.display = '';
  tbody.innerHTML = flows.map((f, i) => `
    <tr>
      <td style="color:var(--text-muted);font-size:.8rem">${i + 1}</td>
      <td><code>${esc(f.src)}</code></td>
      <td><code>${esc(f.dst)}</code></td>
      <td>${esc(f.service) || '<span class="text-muted">—</span>'}</td>
      <td style="color:var(--text-muted);font-size:.82rem">${esc(f.comment) || ''}</td>
      <td><button class="btn btn-sm btn-ghost rr-remove-btn" data-type="flow" data-idx="${i}" title="Remove">&#10005;</button></td>
    </tr>`).join('');
  updateReviewBtn();
}

function splitIPs(raw) {
  return raw.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
}

function addFlow(srcRaw, dstRaw, service, comment) {
  const srcs = splitIPs(srcRaw);
  const dsts = splitIPs(dstRaw);
  service = service.trim();
  comment = comment.trim();
  if (!srcs.length || !dsts.length) return;
  for (const src of srcs) {
    for (const dst of dsts) {
      flows.push({ src, dst, service, comment });
    }
  }
  renderFlows();
  clearFlowInputs();
}

function clearFlowInputs() {
  ['rrSrc','rrDst','rrSvc','rrComment'].forEach(id => {
    document.getElementById(id).value = '';
  });
}

/* ── Package management ─────────────────────────────────────────────────────── */
function renderPackages() {
  const tbody = document.getElementById('rrPkgTbody');
  const wrap  = document.getElementById('rrPkgTableWrap');
  if (!packages.length) { wrap.style.display = 'none'; tbody.innerHTML = ''; updateReviewBtn(); return; }
  wrap.style.display = '';
  tbody.innerHTML = packages.map((p, i) => `
    <tr>
      <td style="color:var(--text-muted);font-size:.8rem">${i + 1}</td>
      <td>${esc(p.adom)}</td>
      <td>${esc(p.name)}</td>
      <td><button class="btn btn-sm btn-ghost rr-remove-btn" data-type="pkg" data-idx="${i}" title="Remove">&#10005;</button></td>
    </tr>`).join('');
  updateReviewBtn();
}

function addPackage() {
  const adom    = document.getElementById('rrAdom').value;
  const pkgName = document.getElementById('rrPackage').value;
  if (!adom || !pkgName) return;
  const path = pkgPaths[pkgName] || pkgName;
  if (packages.some(p => p.adom === adom && p.path === path)) return;
  packages.push({ adom, name: pkgName, path });
  renderPackages();
}

function updateReviewBtn() {
  document.getElementById('rrReviewBtn').disabled = !(flows.length && packages.length);
}

/* ── CSV / XLSX import ──────────────────────────────────────────────────────── */
async function handleImport(file) {
  const statusEl = document.getElementById('rrImportStatus');
  statusEl.textContent = 'Parsing…';
  const fd = new FormData();
  fd.append('file', file);
  try {
    const resp = await fetch('/api/rule-review/parse-import', { method: 'POST', body: fd });
    const data = await resp.json();
    if (!resp.ok) { statusEl.textContent = data.error || 'Import failed'; return; }
    const imported = data.rows || [];
    imported.forEach(r => flows.push(r));
    renderFlows();
    const errs = data.errors || [];
    statusEl.textContent = `Imported ${imported.length} row${imported.length !== 1 ? 's' : ''}` +
      (errs.length ? ` (${errs.length} error${errs.length !== 1 ? 's' : ''}: ${errs[0]})` : '');
  } catch (e) {
    statusEl.textContent = 'Import error: ' + e.message;
  }
  document.getElementById('rrImportFile').value = '';
}

/* ── Analysis ───────────────────────────────────────────────────────────────── */
async function runReview() {
  const errEl = document.getElementById('rrError');
  errEl.style.display = 'none';
  document.getElementById('rrResults').style.display   = 'none';
  document.getElementById('rrCliPanel').style.display  = 'none';
  document.getElementById('rrReviewBtn').disabled = true;
  document.getElementById('rrRunning').style.display   = '';
  checkZoneStatus();

  try {
    const resp = await fetch('/api/rule-review/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ flows, packages }),
    });
    const data = await resp.json();
    if (!resp.ok) { showError(data.error || 'Analysis failed.'); return; }

    results = data.results || [];
    renderResults(data.zone_available);
    document.getElementById('rrResults').style.display = '';
    document.getElementById('rrStatusLine').textContent = `Last run: ${new Date().toLocaleString()}`;
  } catch (e) {
    showError(e.message);
  } finally {
    document.getElementById('rrReviewBtn').disabled = !(flows.length && packages.length);
    document.getElementById('rrRunning').style.display = 'none';
  }
}

function showError(msg) {
  const el = document.getElementById('rrError');
  el.textContent = msg;
  el.style.display = '';
}

/* ── Verdict / zone helpers ─────────────────────────────────────────────────── */
const VERDICT_LABEL = {
  PERMITTED:         'PERMITTED',
  EXPLICITLY_DENIED: 'EXPLICITLY DENIED',
  MODIFIABLE:        'MODIFIABLE',
  NEW_RULE_NEEDED:   'NEW RULE NEEDED',
};

function verdictClass(v) {
  return { PERMITTED: 'ALLOWED', EXPLICITLY_DENIED: 'BLOCKED',
           MODIFIABLE: 'UNKNOWN', NEW_RULE_NEEDED: 'UNKNOWN' }[v] || 'UNKNOWN';
}

function zoneClass(v) {
  return { ALLOWED: 'ALLOWED', BLOCKED: 'BLOCKED',
           UNKNOWN: 'UNKNOWN', UNAVAILABLE: 'UNKNOWN', ERROR: 'BLOCKED' }[v] || 'UNKNOWN';
}

function verdictLabel(v) {
  return VERDICT_LABEL[v] || v;
}

function zoneLabel(v) {
  if (v === 'UNKNOWN') return 'NO RULE';
  return v;
}

/* ── Governing rule HTML (matches zone-script style) ───────────────────────── */
function ruleRowHtml(p) {
  const svc = p.services && p.services.length
    ? `<span class="rr-rule-svc">[${esc(p.services.join(', '))}]</span>` : '';
  const sev = p.severity ? `<span class="rr-rule-sev">(${esc(p.severity)})</span>` : '';
  return `<div class="rr-rule-row">
    <span class="rr-rule-set">[${esc(p.policy_set || '')}]</span>
    ${esc(p.matched_from_zone || p.from_zone || '')} → ${esc(p.matched_to_zone || p.to_zone || '')}
    &nbsp;|&nbsp;
    <strong>${esc(p.access_type || '')}</strong>
    ${svc} ${sev}
  </div>`;
}

/* ── Path-relevance badge ───────────────────────────────────────────────────── */
function pathBadgeHtml(r) {
  const ip = r.path_in_path;
  if (ip === true)  return `<span class="rr-path-badge rr-path-yes">✓ In Path</span>`;
  if (ip === false) return `<span class="rr-path-badge rr-path-no">⚠ Not In Path</span>`;
  return `<span class="rr-path-badge rr-path-unknown">? Path Unknown</span>`;
}

/* ── Results rendering — zone-script card style ─────────────────────────────── */
function renderResults(zoneAvail) {
  const container = document.getElementById('rrResultCards');
  container.innerHTML = '';

  // Summary counts
  const vc = { PERMITTED: 0, EXPLICITLY_DENIED: 0, MODIFIABLE: 0, NEW_RULE_NEEDED: 0 };
  const zc = { ALLOWED: 0, BLOCKED: 0, UNKNOWN: 0 };
  results.forEach(r => {
    if (vc[r.verdict] !== undefined) vc[r.verdict]++;
    if (zc[r.zone_verdict] !== undefined) zc[r.zone_verdict]++;
  });

  const bar = document.getElementById('rrSummaryBar');
  let barHtml = `<span class="rr-summary-chip">${results.length} result${results.length !== 1 ? 's' : ''}</span>`;
  if (vc.PERMITTED)         barHtml += `<span class="rr-summary-chip chip-allowed">${vc.PERMITTED} Permitted</span>`;
  if (vc.NEW_RULE_NEEDED)   barHtml += `<span class="rr-summary-chip chip-unknown">${vc.NEW_RULE_NEEDED} New Rule Needed</span>`;
  if (vc.MODIFIABLE)        barHtml += `<span class="rr-summary-chip chip-warn">${vc.MODIFIABLE} Modifiable</span>`;
  if (vc.EXPLICITLY_DENIED) barHtml += `<span class="rr-summary-chip chip-blocked">${vc.EXPLICITLY_DENIED} Explicitly Denied</span>`;
  if (zoneAvail) {
    if (zc.BLOCKED)  barHtml += `<span class="rr-summary-chip chip-blocked">Zone: ${zc.BLOCKED} Blocked</span>`;
    if (zc.UNKNOWN)  barHtml += `<span class="rr-summary-chip chip-warn">Zone: ${zc.UNKNOWN} No Rule</span>`;
  }
  bar.innerHTML = barHtml;

  // One card per result
  results.forEach((r, idx) => {
    const vClass = verdictClass(r.verdict);
    const vLabel = verdictLabel(r.verdict);
    const zClass = zoneClass(r.zone_verdict);
    const zLabel = zoneLabel(r.zone_verdict);

    // Flow header
    const svcBadge = r.service
      ? `<span class="rr-flow-svc">${esc(r.service)}</span>` : '';
    const pathBadge = pathBadgeHtml(r);

    // Zone section
    let zoneHtml = '';
    if (r.zone_available) {
      const governing = r.zone_governing || [];
      const allPols   = r.zone_all_policies || [];
      let govHtml = '';
      if (governing.length) {
        govHtml = `<div class="rr-card-subsection">
          <div class="rr-subsection-label">Governing rule:</div>
          ${governing.map(ruleRowHtml).join('')}
        </div>`;
      } else if (r.zone_verdict === 'UNKNOWN') {
        govHtml = `<div class="rr-no-rule">No policy rule covers this zone pair — treat as implicitly blocked.</div>`;
      }

      let allPolsHtml = '';
      if (allPols.length > governing.length) {
        allPolsHtml = `<details class="rr-details">
          <summary class="rr-details-summary">All matching rules (${allPols.length})</summary>
          <div class="rr-details-body">${allPols.map(ruleRowHtml).join('')}</div>
        </details>`;
      }

      zoneHtml = `<div class="rr-card-zone-block">
        <div class="rr-card-row rr-zone-header">
          <span class="rr-zone-block-label">Zone Policy</span>
          <span class="verdict-${zClass} rr-zone-verdict">${esc(zLabel)}</span>
        </div>
        <div class="rr-card-row rr-zone-zones">
          <span>&#8599; Src zones: <strong>${esc((r.zone_src || []).join(', ') || '(none matched)')}</strong></span><br>
          <span>&#8600; Dst zones: <strong>${esc((r.zone_dst || []).join(', ') || '(none matched)')}</strong></span>
        </div>
        ${govHtml}
        ${allPolsHtml}
      </div>`;
    } else {
      zoneHtml = `<div class="rr-card-zone-block rr-zone-na">
        <span class="rr-zone-block-label">Zone Policy</span>
        <span class="text-muted" style="font-size:.8rem;margin-left:.5rem">not available</span>
      </div>`;
    }

    // FortiGate policy section
    let fgtHtml = '';
    if (r.matching_rules && r.matching_rules.length) {
      fgtHtml += `<div class="rr-card-subsection">
        <div class="rr-subsection-label">Matching rules:</div>
        ${r.matching_rules.map(m => `
        <div class="rr-rule-row">
          <span class="rr-rule-set">ID ${esc(m.id)}</span>
          ${m.name ? esc(m.name) : '<em>unnamed</em>'}
          &nbsp;|&nbsp;
          <strong style="color:${m.action === 'accept' ? 'var(--success)' : 'var(--danger)'}">${esc(m.action)}</strong>
        </div>`).join('')}
      </div>`;
    }
    if (r.modifiable_rules && r.modifiable_rules.length) {
      fgtHtml += `<div class="rr-card-subsection">
        <div class="rr-subsection-label">Modifiable rules:</div>
        ${r.modifiable_rules.map(m => `
        <div class="rr-rule-row">
          <span class="rr-rule-set">ID ${esc(m.id)}</span>
          ${m.name ? esc(m.name) : '<em>unnamed</em>'}
          &nbsp;|&nbsp; <span style="color:var(--warning)">${esc(m.suggestion)}</span>
        </div>`).join('')}
      </div>`;
    }

    // Path check section
    let pathHtml = '';
    if (r.path_notes && r.path_notes.length) {
      const routeInfo = [];
      if (r.path_src_iface) routeInfo.push(`Src → ${esc(r.path_src_iface)}`);
      if (r.path_dst_iface) routeInfo.push(`Dst → ${esc(r.path_dst_iface)}`);
      pathHtml = `<div class="rr-card-subsection rr-path-section rr-path-${r.path_in_path === true ? 'yes' : r.path_in_path === false ? 'no' : 'unknown'}">
        <div class="rr-subsection-label">Path Analysis (${esc(r.path_confidence || 'low')} confidence):</div>
        <div class="rr-path-note">${esc(r.path_notes[0] || '')}</div>
        ${routeInfo.length ? `<div class="rr-path-route">${routeInfo.join('  |  ')}</div>` : ''}
      </div>`;
    }

    // Notes
    const policyNotes = (r.notes || []).filter(n =>
      !n.startsWith('⚠ ZONE') && !n.startsWith('Zone policy:') &&
      !n.startsWith('⚠ PATH') && !n.startsWith('✓ PATH')
    );
    const notesHtml = policyNotes.length
      ? `<div class="rr-card-subsection">
          ${policyNotes.map(n => `<div class="rr-note">${esc(n)}</div>`).join('')}
        </div>` : '';

    const card = document.createElement('div');
    card.className = `rr-result-card result-card-${vClass}`;
    card.innerHTML = `
      <div class="rr-card-header">
        <div class="rr-card-flow">
          <code>${esc(r.src)}</code>
          <span class="rr-arrow">→</span>
          <code>${esc(r.dst)}</code>
          ${svcBadge}
          <span class="rr-pkg-label">${esc(r.adom)} / ${esc(r.pkg_name)}</span>
        </div>
        <div class="rr-card-badges">
          ${pathBadge}
          <span class="verdict-${vClass}">${esc(vLabel)}</span>
          <button class="btn btn-sm btn-secondary rr-detail-btn" data-idx="${idx}" title="Full details">⋯</button>
        </div>
      </div>

      ${zoneHtml}

      <div class="rr-card-fgt-block">
        <div class="rr-zone-block-label" style="margin-bottom:.4rem">FortiGate Policy</div>
        ${fgtHtml || '<div class="rr-no-rule">No matching rules found.</div>'}
        ${notesHtml}
        ${pathHtml}
      </div>
    `;
    container.appendChild(card);
  });

  if (!results.length) {
    container.innerHTML = '<div class="empty-state" style="padding:1.5rem">No results returned.</div>';
  }

  // CLI panel
  const cliSnippets = results.filter(r => r.fortios_cli).map(r => r.fortios_cli);
  const cliPanel  = document.getElementById('rrCliPanel');
  const cliOutput = document.getElementById('rrCliOutput');
  if (cliSnippets.length) {
    cliOutput.textContent = cliSnippets.join('\n\n' + '─'.repeat(60) + '\n\n');
    cliPanel.style.display = '';
  } else {
    cliPanel.style.display = 'none';
  }
}

/* ── Detail modal ───────────────────────────────────────────────────────────── */
function showDetail(idx) {
  const r = results[idx];
  if (!r) return;

  const vClass = verdictClass(r.verdict);
  const vLabel = verdictLabel(r.verdict);
  const zClass = zoneClass(r.zone_verdict);
  const zLabel = zoneLabel(r.zone_verdict);

  let html = `
    <div class="rr-detail-grid">
      <div class="rr-detail-row"><span class="rr-detail-label">Source</span><code>${esc(r.src)}</code></div>
      <div class="rr-detail-row"><span class="rr-detail-label">Destination</span><code>${esc(r.dst)}</code></div>
      <div class="rr-detail-row"><span class="rr-detail-label">Service</span>${esc(r.service) || '<em>any</em>'}</div>
      <div class="rr-detail-row"><span class="rr-detail-label">ADOM</span>${esc(r.adom)}</div>
      <div class="rr-detail-row"><span class="rr-detail-label">Package</span>${esc(r.pkg_name)}</div>
      ${r.device ? `<div class="rr-detail-row"><span class="rr-detail-label">Device</span>${esc(r.device)}</div>` : ''}
      <div class="rr-detail-row"><span class="rr-detail-label">FGT Verdict</span>
        <span class="verdict-${vClass}" style="font-weight:700">${esc(vLabel)}</span></div>
    </div>`;

  // Zone policy
  html += `<div class="rr-detail-section">
    <div class="rr-detail-section-title">Zone Segmentation Policy
      ${r.zone_available ? `<span class="verdict-${zClass}" style="margin-left:.5rem;font-weight:700">${esc(zLabel)}</span>` : '<span class="text-muted" style="margin-left:.5rem;font-size:.8rem">not available</span>'}
    </div>`;
  if (r.zone_available) {
    html += `<div class="rr-detail-row"><span class="rr-detail-label">Source Zones</span>
        ${esc((r.zone_src || []).join(', ') || '(none matched)')}</div>
      <div class="rr-detail-row"><span class="rr-detail-label">Dest Zones</span>
        ${esc((r.zone_dst || []).join(', ') || '(none matched)')}</div>`;
    if (r.zone_governing && r.zone_governing.length) {
      html += `<div style="margin-top:.5rem"><div class="rr-subsection-label">Governing rule:</div>
        ${r.zone_governing.map(ruleRowHtml).join('')}</div>`;
    } else if (r.zone_verdict === 'UNKNOWN') {
      html += `<div class="rr-no-rule">No policy rule covers this zone pair — treat as implicitly blocked.</div>`;
    }
    const allPols = r.zone_all_policies || [];
    if (allPols.length > (r.zone_governing || []).length) {
      html += `<details class="rr-details" style="margin-top:.4rem">
        <summary class="rr-details-summary">All matching rules (${allPols.length})</summary>
        <div class="rr-details-body">${allPols.map(ruleRowHtml).join('')}</div>
      </details>`;
    }
  }
  html += `</div>`;

  // Path analysis
  html += `<div class="rr-detail-section">
    <div class="rr-detail-section-title">Path Analysis</div>`;
  if (r.path_in_path === true)  html += `<div style="color:var(--success);font-weight:600;margin-bottom:.35rem">✓ Device is in the traffic path</div>`;
  if (r.path_in_path === false) html += `<div style="color:var(--warning);font-weight:600;margin-bottom:.35rem">⚠ Device may NOT be in the traffic path — proceed with caution</div>`;
  if (r.path_in_path === null)  html += `<div style="color:var(--text-muted);margin-bottom:.35rem">Path data unavailable</div>`;

  if (r.path_src_iface || r.path_src_route) {
    html += `<div class="rr-detail-row"><span class="rr-detail-label">Src Interface</span>${esc(r.path_src_iface || '—')}</div>`;
    if (r.path_src_route) {
      html += `<div class="rr-detail-row"><span class="rr-detail-label">Src Route</span>
        ${esc(r.path_src_route.network)} via ${esc(r.path_src_route.gateway || 'direct')} (${esc(r.path_src_route.interface || '?')})</div>`;
    }
  }
  if (r.path_dst_iface || r.path_dst_route) {
    html += `<div class="rr-detail-row"><span class="rr-detail-label">Dst Interface</span>${esc(r.path_dst_iface || '—')}</div>`;
    if (r.path_dst_route) {
      html += `<div class="rr-detail-row"><span class="rr-detail-label">Dst Route</span>
        ${esc(r.path_dst_route.network)} via ${esc(r.path_dst_route.gateway || 'direct')} (${esc(r.path_dst_route.interface || '?')})</div>`;
    }
  }
  (r.path_notes || []).forEach(n => {
    html += `<div class="rr-note" style="margin-top:.25rem">${esc(n)}</div>`;
  });
  html += `</div>`;

  // FortiGate matching rules
  if (r.matching_rules && r.matching_rules.length) {
    html += `<div class="rr-detail-section">
      <div class="rr-detail-section-title">Matching Rules</div>
      <table class="data-table" style="font-size:.82rem">
        <thead><tr><th>ID</th><th>Name</th><th>Action</th></tr></thead>
        <tbody>${r.matching_rules.map(m => `<tr>
          <td>${esc(m.id)}</td>
          <td>${esc(m.name || '—')}</td>
          <td style="font-weight:600;color:${m.action==='accept'?'var(--success)':'var(--danger)'}">${esc(m.action)}</td>
        </tr>`).join('')}</tbody>
      </table></div>`;
  }

  if (r.modifiable_rules && r.modifiable_rules.length) {
    html += `<div class="rr-detail-section">
      <div class="rr-detail-section-title">Rules That Could Be Modified</div>
      <table class="data-table" style="font-size:.82rem">
        <thead><tr><th>ID</th><th>Name</th><th>Suggestion</th></tr></thead>
        <tbody>${r.modifiable_rules.map(m => `<tr>
          <td>${esc(m.id)}</td><td>${esc(m.name || '—')}</td>
          <td style="color:var(--warning)">${esc(m.suggestion)}</td>
        </tr>`).join('')}</tbody>
      </table></div>`;
  }

  // All notes
  const allNotes = r.notes || [];
  if (allNotes.length) {
    html += `<div class="rr-detail-section">
      <div class="rr-detail-section-title">All Notes</div>
      ${allNotes.map(n => `<div class="rr-note">${esc(n)}</div>`).join('')}
    </div>`;
  }

  // CLI
  if (r.fortios_cli) {
    html += `<div class="rr-detail-section">
      <div class="rr-detail-section-title">FortiOS CLI</div>
      <pre class="rr-cli-block" style="margin-top:.5rem">${esc(r.fortios_cli)}</pre>
    </div>`;
  }

  document.getElementById('rrModalTitle').textContent =
    `${r.src} → ${r.dst}${r.service ? ' : ' + r.service : ''} — ${r.pkg_name}`;
  document.getElementById('rrModalBody').innerHTML = html;
  document.getElementById('rrDetailModal').style.display = '';
}

/* ── Clear all ──────────────────────────────────────────────────────────────── */
function clearAll() {
  flows    = [];
  packages = [];
  results  = [];
  renderFlows();
  renderPackages();
  document.getElementById('rrResults').style.display  = 'none';
  document.getElementById('rrCliPanel').style.display = 'none';
  document.getElementById('rrError').style.display    = 'none';
  document.getElementById('rrStatusLine').textContent = '';
  document.getElementById('rrZoneStatus').style.display = 'none';
  clearFlowInputs();
}

/* ── CLI copy / download ────────────────────────────────────────────────────── */
function copyCli() {
  const text = document.getElementById('rrCliOutput').textContent;
  navigator.clipboard.writeText(text).catch(() => {});
}

function downloadCli() {
  const text = document.getElementById('rrCliOutput').textContent;
  const a  = document.createElement('a');
  const bl = new Blob([text], { type: 'text/plain' });
  a.href   = URL.createObjectURL(bl);
  a.download = 'rule_review_cli.txt';
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ── Event wiring ───────────────────────────────────────────────────────────── */
document.getElementById('rrAdom').addEventListener('change', function () {
  if (this.value) loadPackages(this.value);
  else {
    const sel = document.getElementById('rrPackage');
    sel.innerHTML = '<option value="">— select package —</option>';
    sel.disabled = true;
    document.getElementById('rrAddPkgBtn').disabled = true;
  }
});

document.getElementById('rrPackage').addEventListener('change', function () {
  document.getElementById('rrAddPkgBtn').disabled = !this.value;
});

document.getElementById('rrAddFlowBtn').addEventListener('click', () => {
  addFlow(
    document.getElementById('rrSrc').value,
    document.getElementById('rrDst').value,
    document.getElementById('rrSvc').value,
    document.getElementById('rrComment').value,
  );
});

document.getElementById('rrComment').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('rrAddFlowBtn').click();
});

document.getElementById('rrAddPkgBtn').addEventListener('click', addPackage);
document.getElementById('rrReviewBtn').addEventListener('click', runReview);
document.getElementById('rrClearBtn').addEventListener('click', clearAll);
document.getElementById('rrCopyCliBtn').addEventListener('click', copyCli);
document.getElementById('rrDownloadCliBtn').addEventListener('click', downloadCli);

document.getElementById('rrModalClose').addEventListener('click', () => {
  document.getElementById('rrDetailModal').style.display = 'none';
});
document.getElementById('rrDetailModal').addEventListener('click', e => {
  if (e.target === document.getElementById('rrDetailModal'))
    document.getElementById('rrDetailModal').style.display = 'none';
});

document.getElementById('rrFlowTbody').addEventListener('click', e => {
  const btn = e.target.closest('.rr-remove-btn');
  if (!btn || btn.dataset.type !== 'flow') return;
  flows.splice(parseInt(btn.dataset.idx, 10), 1);
  renderFlows();
});

document.getElementById('rrPkgTbody').addEventListener('click', e => {
  const btn = e.target.closest('.rr-remove-btn');
  if (!btn || btn.dataset.type !== 'pkg') return;
  packages.splice(parseInt(btn.dataset.idx, 10), 1);
  renderPackages();
});

document.getElementById('rrResultCards').addEventListener('click', e => {
  const btn = e.target.closest('.rr-detail-btn');
  if (btn) showDetail(parseInt(btn.dataset.idx, 10));
});

document.getElementById('rrImportFile').addEventListener('change', function () {
  if (this.files && this.files[0]) handleImport(this.files[0]);
});

/* ── Init ───────────────────────────────────────────────────────────────────── */
loadAdoms();
checkZoneStatus();
document.getElementById('rrZoneStatus').style.display = '';

// ── AI Assist ─────────────────────────────────────────────────────────────

let aiAssistLastPayload = null;

function parseAiIPs(raw) {
  return raw.split(/[\n,]+/).map(s => s.trim()).filter(Boolean).join(', ');
}

function parseAiFirewalls(raw) {
  return raw.split(',').map(s => s.trim()).filter(Boolean).map(tok => {
    const [device, adom] = tok.split(':').map(s => (s || '').trim());
    return { device, adom };
  });
}

// ── Firewall device typeahead ────────────────────────────────────────────

let aiDeviceCache = null;   // [{device, adom}, ...] — fetched once, filtered client-side
let aiDeviceCachePromise = null;

function loadAiDeviceCache() {
  if (aiDeviceCachePromise) return aiDeviceCachePromise;
  aiDeviceCachePromise = fetch('/api/rule-review/devices')
    .then(resp => resp.ok ? resp.json() : [])
    .then(data => { aiDeviceCache = Array.isArray(data) ? data : []; return aiDeviceCache; })
    .catch(() => { aiDeviceCache = []; return aiDeviceCache; });
  return aiDeviceCachePromise;
}

function activeFirewallToken(input) {
  // The part being typed right now is whatever follows the last comma.
  const value = input.value;
  const lastComma = value.lastIndexOf(',');
  const start = lastComma === -1 ? 0 : lastComma + 1;
  return { start, end: value.length, text: value.slice(start).trim() };
}

function renderFirewallSuggestions(matches) {
  const list = document.getElementById('rrAiFirewallSuggestions');
  if (!matches.length) {
    list.style.display = 'none';
    list.innerHTML = '';
    return;
  }
  list.innerHTML = matches.slice(0, 8).map((m, i) =>
    `<li data-idx="${i}">${esc(m.device)} <span class="rr-suggestion-adom">${esc(m.adom)}</span></li>`
  ).join('');
  list.style.display = '';
}

function applyFirewallSuggestion(input, match) {
  const token = activeFirewallToken(input);
  const before = input.value.slice(0, token.start).replace(/,\s*$/, '');
  const prefix = before ? before + ', ' : '';
  input.value = `${prefix}${match.device}:${match.adom}, `;
  renderFirewallSuggestions([]);
  input.focus();
}

async function onFirewallInput(evt) {
  const input = evt.target;
  const token = activeFirewallToken(input);
  if (!token.text || token.text.includes(':')) {
    renderFirewallSuggestions([]);
    return;
  }
  const devices = await loadAiDeviceCache();
  const q = token.text.toLowerCase();
  const matches = devices.filter(d =>
    d.device.toLowerCase().includes(q) || d.adom.toLowerCase().includes(q)
  );
  // Only render if the user hasn't kept typing past this point already.
  if (activeFirewallToken(input).text.toLowerCase() !== q) return;
  renderFirewallSuggestions(matches);
  document.getElementById('rrAiFirewallSuggestions').querySelectorAll('li').forEach(li => {
    li.addEventListener('mousedown', (e) => {
      e.preventDefault(); // keep focus on the input through the click
      applyFirewallSuggestion(input, matches[Number(li.dataset.idx)]);
    });
  });
}

document.getElementById('rrAiFirewalls')?.addEventListener('input', onFirewallInput);
document.getElementById('rrAiFirewalls')?.addEventListener('focus', loadAiDeviceCache);
document.getElementById('rrAiFirewalls')?.addEventListener('blur', () => {
  // Delay so a suggestion's mousedown can fire before the list disappears.
  setTimeout(() => renderFirewallSuggestions([]), 150);
});

async function checkAiAssistAvailable() {
  try {
    const resp = await fetch('/api/rule-review/ai-assist-status');
    const data = await resp.json();
    if (!data.available) {
      document.getElementById('rrAiDisabledNotice').style.display = '';
      document.getElementById('rrAiSubmitBtn').disabled = true;
      const fqdnSubmit = document.getElementById('rrAiFqdnSubmitBtn');
      if (fqdnSubmit) fqdnSubmit.disabled = true;
    }
  } catch (e) {
    // Non-fatal — the form's own submit handler will surface any real error.
  }
}

async function runAiAssist(evt) {
  evt.preventDefault();
  const errEl = document.getElementById('rrAiError');
  const resultEl = document.getElementById('rrAiResult');
  const runningEl = document.getElementById('rrAiRunning');
  errEl.style.display = 'none';
  resultEl.style.display = 'none';
  runningEl.style.display = '';

  const payload = {
    src: parseAiIPs(document.getElementById('rrAiSrc').value),
    dst: parseAiIPs(document.getElementById('rrAiDst').value),
    service: document.getElementById('rrAiSvc').value.trim(),
    firewalls: parseAiFirewalls(document.getElementById('rrAiFirewalls').value),
    ticket_id: document.getElementById('rrAiTicket').value.trim(),
    justification: document.getElementById('rrAiJustification').value.trim(),
    src_group: document.getElementById('rrAiSrcGroup').value.trim(),
    dst_group: document.getElementById('rrAiDstGroup').value.trim(),
  };

  try {
    const resp = await fetch('/api/rule-review/ai-assist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    runningEl.style.display = 'none';
    if (!resp.ok) {
      errEl.textContent = data.error || `Request failed (${resp.status})`;
      errEl.style.display = '';
      return;
    }
    renderAiResult(data);
  } catch (e) {
    runningEl.style.display = 'none';
    errEl.textContent = 'Request failed: ' + e.message;
    errEl.style.display = '';
  }
}

function renderAiResult(data) {
  aiAssistLastPayload = data;
  const plan = data.plan;
  document.getElementById('rrAiVerdict').textContent =
    `${plan.cli_status}${plan.risk_level ? ' — Risk: ' + plan.risk_level : ''}`;
  document.getElementById('rrAiPlanSummary').textContent = plan.recommendation || '';

  const warningsEl = document.getElementById('rrAiWarnings');
  const warnings = plan.warnings || [];
  if (warnings.length) {
    warningsEl.innerHTML = '<strong>Warnings:</strong><ul>' +
      warnings.map(w => `<li>${w}</li>`).join('') + '</ul>';
    warningsEl.style.display = '';
  } else {
    warningsEl.innerHTML = '';
    warningsEl.style.display = 'none';
  }

  const approvalEl = document.getElementById('rrAiApproval');
  const approval = plan.approval || {};
  if (approval && Object.keys(approval).length) {
    const approvers = (approval.approvers || []).join(', ') || '(none listed)';
    approvalEl.innerHTML = [
      `<div><strong>Approvers:</strong> ${approvers}</div>`,
      `<div><strong>Peer review required:</strong> ${approval.peer_review ? 'Yes' : 'No'}</div>`,
      `<div><strong>Security review required:</strong> ${approval.security_review ? 'Yes' : 'No'}</div>`,
      `<div><strong>Change window:</strong> ${approval.change_window || ''}</div>`,
      `<div><strong>SLA:</strong> ${approval.sla_hours != null ? approval.sla_hours + ' hours' : ''}</div>`,
    ].join('');
    approvalEl.style.display = '';
  } else {
    approvalEl.innerHTML = '';
    approvalEl.style.display = 'none';
  }

  const pathEl = document.getElementById('rrAiPathRelevance');
  const pathEntries = Object.entries(data.path_relevance || {});
  if (pathEntries.length) {
    pathEl.innerHTML = pathEntries.map(([device, pr]) => {
      const status = pr.in_path === true ? 'In path' : pr.in_path === false ? 'Not in path' : 'Unknown';
      return `<div><strong>${device}:</strong> ${status} (${pr.confidence || 'low'} confidence)</div>`;
    }).join('');
    pathEl.style.display = '';
  } else {
    pathEl.style.display = 'none';
  }

  const narrEl = document.getElementById('rrAiNarrative');
  const narrErrEl = document.getElementById('rrAiNarrativeError');
  if (data.narrative) {
    narrEl.textContent = data.narrative;
    narrErrEl.style.display = 'none';
  } else {
    narrEl.textContent = '';
    narrErrEl.textContent = 'AI summary unavailable: ' + (data.narrative_error || 'unknown error');
    narrErrEl.style.display = '';
  }

  const cliLines = (plan.firewalls || [])
    .filter(fw => fw.policy_cli)
    .map(fw => `# ${fw.firewall}\n${fw.policy_cli}`);
  document.getElementById('rrAiCliOutput').textContent = cliLines.join('\n\n');

  document.getElementById('rrAiResult').style.display = '';
}

function copyAiCli() {
  const text = document.getElementById('rrAiCliOutput').textContent;
  navigator.clipboard.writeText(text).catch(() => {});
}

function downloadAiPackage() {
  if (!aiAssistLastPayload) return;
  const plan = aiAssistLastPayload.plan;
  const narrative = aiAssistLastPayload.narrative || '(AI summary unavailable)';
  const cli = document.getElementById('rrAiCliOutput').textContent;
  const approval = plan.approval || {};
  const approvalLines = [
    `Approvers: ${(approval.approvers || []).join(', ') || '(none listed)'}`,
    `Peer review required: ${approval.peer_review ? 'Yes' : 'No'}`,
    `Security review required: ${approval.security_review ? 'Yes' : 'No'}`,
    `Change window: ${approval.change_window || ''}`,
    `SLA: ${approval.sla_hours != null ? approval.sla_hours + ' hours' : ''}`,
  ];
  const warnings = plan.warnings || [];
  const text = [
    `Peer Review Package — ${plan.ticket_id || '(no ticket)'}`,
    '='.repeat(60),
    '',
    `Verdict: ${plan.cli_status}`,
    `Risk level: ${plan.risk_level || ''}`,
    '',
    'Warnings:',
    warnings.length ? warnings.map(w => `- ${w}`).join('\n') : '(none)',
    '',
    'Approval:',
    approvalLines.join('\n'),
    '',
    'AI-Generated Report:',
    narrative,
    '',
    'Generated CLI:',
    cli,
  ].join('\n');
  const a = document.createElement('a');
  const bl = new Blob([text], { type: 'text/plain' });
  a.href = URL.createObjectURL(bl);
  a.download = `peer_review_${plan.ticket_id || 'package'}.txt`;
  a.click();
  URL.revokeObjectURL(a.href);
}

document.getElementById('rrAiForm')?.addEventListener('submit', runAiAssist);
document.getElementById('rrAiCopyBtn')?.addEventListener('click', copyAiCli);
document.getElementById('rrAiDownloadBtn')?.addEventListener('click', downloadAiPackage);

// ── AI Assist: FQDN Allowlist mode ───────────────────────────────────────

function switchAiMode(mode) {
  const forms = {
    single: document.getElementById('rrAiForm'),
    fqdn: document.getElementById('rrAiFqdnForm'),
    hygiene_fix: document.getElementById('rrAiHygieneFixForm'),
  };
  const buttons = {
    single: document.getElementById('rrAiModeSingle'),
    fqdn: document.getElementById('rrAiModeFqdn'),
    hygiene_fix: document.getElementById('rrAiModeHygieneFix'),
  };
  const results = {
    single: document.getElementById('rrAiResult'),
    fqdn: document.getElementById('rrAiFqdnResult'),
    hygiene_fix: document.getElementById('rrAiHygieneFixResult'),
  };
  Object.keys(forms).forEach(key => {
    forms[key].style.display = key === mode ? '' : 'none';
    buttons[key].classList.toggle('btn-primary', key === mode);
    buttons[key].classList.toggle('btn-secondary', key !== mode);
    if (key !== mode) results[key].style.display = 'none';
  });
  if (mode === 'hygiene_fix' && document.getElementById('rrHfAdom').options.length <= 1) {
    loadHfAdoms();
  }
}

document.getElementById('rrAiModeSingle')?.addEventListener('click', () => switchAiMode('single'));
document.getElementById('rrAiModeFqdn')?.addEventListener('click', () => switchAiMode('fqdn'));
document.getElementById('rrAiModeHygieneFix')?.addEventListener('click', () => switchAiMode('hygiene_fix'));

// ── AI Assist: Hygiene Fix mode ──────────────────────────────────────────

let hfPkgPaths = {};   // package display name -> path, scoped to the Hygiene Fix form

async function loadHfAdoms() {
  const sel = document.getElementById('rrHfAdom');
  try {
    const resp = await fetch('/api/rule-review/adoms');
    if (resp.status === 401) { location.href = '/login'; return; }
    const adoms = await resp.json();
    if (!Array.isArray(adoms)) return;
    adoms.forEach(a => {
      const opt = document.createElement('option');
      opt.value = a; opt.textContent = a;
      sel.appendChild(opt);
    });
  } catch (_) {}
}

async function loadHfPackages(adom) {
  const sel = document.getElementById('rrHfPackage');
  sel.innerHTML = '<option value="">Loading…</option>';
  sel.disabled = true;
  hfPkgPaths = {};
  try {
    const resp = await fetch(`/api/rule-review/adoms/${encodeURIComponent(adom)}/packages`);
    if (resp.status === 401) { location.href = '/login'; return; }
    const pkgs = await resp.json();
    sel.innerHTML = '<option value="">— select package —</option>';
    if (Array.isArray(pkgs)) {
      pkgs.forEach(p => {
        hfPkgPaths[p.name] = p.path || p.name;
        const opt = document.createElement('option');
        opt.value = p.name; opt.textContent = p.name;
        sel.appendChild(opt);
      });
    }
    sel.disabled = false;
  } catch (_) {
    sel.innerHTML = '<option value="">Failed to load</option>';
  }
}

document.getElementById('rrHfAdom')?.addEventListener('change', (e) => {
  const adom = e.target.value;
  if (adom) loadHfPackages(adom);
});

let hfLastResult = null;
let hfSelectedOption = new Map();  // fix index -> selected option index

async function runHygieneFixAiAssist(evt) {
  evt.preventDefault();
  const errEl = document.getElementById('rrAiHygieneFixError');
  const resultEl = document.getElementById('rrAiHygieneFixResult');
  const runningEl = document.getElementById('rrAiHygieneFixRunning');
  errEl.style.display = 'none';
  resultEl.style.display = 'none';
  runningEl.style.display = '';

  const adom = document.getElementById('rrHfAdom').value;
  const pkgName = document.getElementById('rrHfPackage').value;
  const pkg = hfPkgPaths[pkgName] || pkgName;
  const fileInput = document.getElementById('rrHfFindingsFile');
  const file = fileInput.files[0];
  const text = document.getElementById('rrHfFindingsText').value;

  const fd = new FormData();
  fd.append('adom', adom);
  fd.append('pkg', pkg);
  if (file) {
    fd.append('findings_file', file);
  } else {
    fd.append('findings_text', text);
  }

  try {
    const resp = await fetch('/api/rule-review/ai-assist-hygiene-fix', { method: 'POST', body: fd });
    const data = await resp.json();
    runningEl.style.display = 'none';
    if (!resp.ok) {
      errEl.textContent = data.error || `Request failed (${resp.status})`;
      errEl.style.display = '';
      return;
    }
    hfSelectedOption = new Map();
    renderHygieneFixResult(data);
  } catch (e) {
    runningEl.style.display = 'none';
    errEl.textContent = 'Request failed: ' + e.message;
    errEl.style.display = '';
  }
}

document.getElementById('rrAiHygieneFixForm')?.addEventListener('submit', runHygieneFixAiAssist);

function hfActiveOption(fix, idx) {
  const optIdx = hfSelectedOption.get(idx) ?? 0;
  return fix.options[optIdx] || null;
}

function renderHygieneFixResult(data) {
  hfLastResult = data;

  const staleEl = document.getElementById('rrHfStaleWarning');
  if ((data.stale_findings || []).length) {
    staleEl.innerHTML = '<strong>Skipped (not found in the live package):</strong><ul>' +
      data.stale_findings.map(f => `<li>${esc(f.policy_name || f.policy_id)} (${esc(f.check)}): ${esc(f.reason)}</li>`).join('') +
      '</ul>';
    staleEl.style.display = '';
  } else {
    staleEl.innerHTML = '';
    staleEl.style.display = 'none';
  }

  const container = document.getElementById('rrHfFixesContainer');
  container.innerHTML = data.fixes.map((fix, idx) => {
    const active = hfActiveOption(fix, idx);
    const radios = fix.options.length > 1
      ? '<div class="rr-hf-options">' + fix.options.map((o, oi) => `
          <label style="margin-right:1rem">
            <input type="radio" name="hf-opt-${idx}" data-fix-idx="${idx}" data-opt-idx="${oi}" ${oi === (hfSelectedOption.get(idx) ?? 0) ? 'checked' : ''}>
            ${esc(o.label)}
          </label>`).join('') + '</div>'
      : '';
    const description = active ? esc(active.description) : esc(fix.detail);
    const cliText = active && active.cli.length ? active.cli.join('\n\n') : '(no CLI -- manual review required)';
    return `
      <div class="rr-hf-fix-card" style="border:1px solid var(--border-color, #ccc);border-radius:6px;padding:.75rem;margin-bottom:.75rem">
        <div><strong>${esc(fix.policy_name)}</strong> <span class="text-muted">(id ${esc(fix.policy_id)}, ${esc(fix.check)})</span></div>
        ${radios}
        <div style="margin:.5rem 0">${description}</div>
        <pre class="rr-cli-block" data-fix-idx="${idx}">${esc(cliText)}</pre>
      </div>`;
  }).join('');

  container.querySelectorAll('input[type=radio]').forEach(radio => {
    radio.addEventListener('change', (e) => {
      const fixIdx = Number(e.target.dataset.fixIdx);
      const optIdx = Number(e.target.dataset.optIdx);
      hfSelectedOption.set(fixIdx, optIdx);
      renderHygieneFixResult(hfLastResult);
    });
  });

  const narrEl = document.getElementById('rrHfNarrative');
  const narrErrEl = document.getElementById('rrHfNarrativeError');
  if (data.narrative) {
    narrEl.textContent = data.narrative;
    narrErrEl.style.display = 'none';
  } else {
    narrEl.textContent = '';
    narrErrEl.textContent = 'AI summary unavailable: ' + (data.narrative_error || 'unknown error');
    narrErrEl.style.display = '';
  }

  document.getElementById('rrAiHygieneFixResult').style.display = '';
}

function addFqdnRow() {
  const tbody = document.getElementById('rrAiFqdnRows');
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td><input type="text" class="fqdn-row-fqdn" placeholder="*.push.apple.com"></td>
    <td><input type="text" class="fqdn-row-ports" placeholder="443, 5223" style="width:6rem"></td>
    <td>
      <select class="fqdn-row-protocol">
        <option value="TCP">TCP</option>
        <option value="UDP">UDP</option>
      </select>
    </td>
    <td><input type="checkbox" class="fqdn-row-required" checked></td>
    <td><input type="text" class="fqdn-row-comment" placeholder="Optional"></td>
    <td><button type="button" class="btn btn-sm fqdn-row-remove">&times;</button></td>
  `;
  tr.querySelector('.fqdn-row-remove').addEventListener('click', () => tr.remove());
  tbody.appendChild(tr);
}

document.getElementById('rrAiFqdnAddRowBtn')?.addEventListener('click', addFqdnRow);

function collectFqdnRows() {
  return Array.from(document.querySelectorAll('#rrAiFqdnRows tr')).map(tr => ({
    fqdn: tr.querySelector('.fqdn-row-fqdn').value.trim(),
    ports: tr.querySelector('.fqdn-row-ports').value.split(',').map(p => p.trim()).filter(Boolean).map(Number),
    protocol: tr.querySelector('.fqdn-row-protocol').value,
    required: tr.querySelector('.fqdn-row-required').checked,
    comment: tr.querySelector('.fqdn-row-comment').value.trim(),
  })).filter(e => e.fqdn);
}

// Firewall typeahead — reuses the same aiDeviceCache/loadAiDeviceCache as the single-change form.
function renderFqdnFirewallSuggestions(matches) {
  const list = document.getElementById('rrAiFqdnFirewallSuggestions');
  if (!matches.length) {
    list.style.display = 'none';
    list.innerHTML = '';
    return;
  }
  list.innerHTML = matches.slice(0, 8).map((m, i) =>
    `<li data-idx="${i}">${esc(m.device)} <span class="rr-suggestion-adom">${esc(m.adom)}</span></li>`
  ).join('');
  list.style.display = '';
}

async function onFqdnFirewallInput(evt) {
  const input = evt.target;
  const token = activeFirewallToken(input);
  if (!token.text || token.text.includes(':')) {
    renderFqdnFirewallSuggestions([]);
    return;
  }
  const devices = await loadAiDeviceCache();
  const q = token.text.toLowerCase();
  const matches = devices.filter(d =>
    d.device.toLowerCase().includes(q) || d.adom.toLowerCase().includes(q)
  );
  if (activeFirewallToken(input).text.toLowerCase() !== q) return;
  renderFqdnFirewallSuggestions(matches);
  document.getElementById('rrAiFqdnFirewallSuggestions').querySelectorAll('li').forEach(li => {
    li.addEventListener('mousedown', (e) => {
      e.preventDefault();
      applyFirewallSuggestion(input, matches[Number(li.dataset.idx)]);
      renderFqdnFirewallSuggestions([]);
    });
  });
}

document.getElementById('rrAiFqdnFirewalls')?.addEventListener('input', onFqdnFirewallInput);
document.getElementById('rrAiFqdnFirewalls')?.addEventListener('focus', loadAiDeviceCache);
document.getElementById('rrAiFqdnFirewalls')?.addEventListener('blur', () => {
  setTimeout(() => renderFqdnFirewallSuggestions([]), 150);
});

async function runFqdnAiAssist(evt) {
  evt.preventDefault();
  const errEl = document.getElementById('rrAiFqdnError');
  const resultEl = document.getElementById('rrAiFqdnResult');
  const runningEl = document.getElementById('rrAiFqdnRunning');
  errEl.style.display = 'none';
  resultEl.style.display = 'none';
  runningEl.style.display = '';

  const srcIp = document.getElementById('rrAiFqdnSrc').value.trim();
  const ticketId = document.getElementById('rrAiFqdnTicket').value.trim();
  const firewalls = parseAiFirewalls(document.getElementById('rrAiFqdnFirewalls').value);
  const fileInput = document.getElementById('rrAiFqdnFile');
  const file = fileInput.files[0];

  try {
    let resp;
    if (file) {
      const fd = new FormData();
      fd.append('src_ip', srcIp);
      fd.append('ticket_id', ticketId);
      fd.append('firewalls', JSON.stringify(firewalls));
      fd.append('file', file);
      resp = await fetch('/api/rule-review/ai-assist-fqdn', { method: 'POST', body: fd });
    } else {
      const payload = {
        vendor: document.getElementById('rrAiFqdnVendor').value.trim(),
        category: document.getElementById('rrAiFqdnCategory').value.trim(),
        src_ip: srcIp,
        ticket_id: ticketId,
        firewalls,
        entries: collectFqdnRows(),
      };
      resp = await fetch('/api/rule-review/ai-assist-fqdn', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
    }
    const data = await resp.json();
    runningEl.style.display = 'none';
    if (!resp.ok) {
      errEl.textContent = data.error || `Request failed (${resp.status})`;
      errEl.style.display = '';
      return;
    }
    renderFqdnAiResult(data);
  } catch (e) {
    runningEl.style.display = 'none';
    errEl.textContent = 'Request failed: ' + e.message;
    errEl.style.display = '';
  }
}

function renderFqdnAiResult(data) {
  const plan = data.plan;

  const warningsEl = document.getElementById('rrAiFqdnWarnings');
  const warnings = plan.warnings || [];
  const intakeWarnings = plan.intake_warnings || [];
  const missingFields = plan.intake_missing_fields || [];
  const blocks = [];
  if (warnings.length) {
    blocks.push('<strong>Warnings:</strong><ul>' +
      warnings.map(w => `<li>${esc(w)}</li>`).join('') + '</ul>');
  }
  if (intakeWarnings.length) {
    blocks.push('<strong>Intake warnings (rows skipped or adjusted while ' +
      'parsing your entries):</strong><ul>' +
      intakeWarnings.map(w => `<li>${esc(w)}</li>`).join('') + '</ul>');
  }
  if (missingFields.length) {
    blocks.push('<strong>Missing required fields:</strong><ul>' +
      missingFields.map(f => `<li>${esc(f)}</li>`).join('') + '</ul>');
  }
  if (blocks.length) {
    warningsEl.innerHTML = blocks.join('');
    warningsEl.style.display = '';
  } else {
    warningsEl.innerHTML = '';
    warningsEl.style.display = 'none';
  }

  const perFwEl = document.getElementById('rrAiFqdnPerFirewall');
  perFwEl.innerHTML = (plan.per_firewall || []).map(fw => {
    const pol = fw.proposed_policy || {};
    const hasPolicy = !!pol.cli;

    // Labeled sections so the actual policy (name/package/interfaces) is
    // never buried, unlabeled, inside a wall of object-creation CLI.
    const sections = [];
    if ((fw.proposed_objects || []).length || pol.src_object_cli || (pol.service_object_cli_blocks || []).length) {
      const objCli = [
        ...(fw.proposed_objects || []).map(o => o.cli),
        pol.src_object_cli || '',
        ...(pol.service_object_cli_blocks || []),
      ].filter(Boolean).join('\n\n');
      sections.push(`<h4>New Address / Service Objects</h4><pre class="rr-cli-block">${esc(objCli)}</pre>`);
    }
    if (fw.proposed_group) {
      sections.push(`<h4>New Destination Group</h4><pre class="rr-cli-block">${esc(fw.proposed_group.cli)}</pre>`);
    }
    if (hasPolicy) {
      sections.push(`
        <h4>New Policy</h4>
        <div class="rr-hint">
          <strong>Name:</strong> ${esc(pol.name || '')} &middot;
          <strong>Package:</strong> ${esc(pol.package || '(unknown — verify in FortiManager)')} &middot;
          <strong>Interfaces:</strong> ${esc(pol.srcintf || 'any')} &rarr; ${esc(pol.dstintf || 'any')} &middot;
          <strong>Service:</strong> ${esc((pol.service || []).join(', '))}
        </div>
        <pre class="rr-cli-block">${esc(pol.cli)}</pre>
      `);
    }
    const cliSections = sections.join('');
    return `
      <div class="rr-section" style="margin-top:1rem">
        <h3>${esc(fw.firewall)} <span class="rr-zone-badge">${esc(fw.verdict)}</span></h3>
        <div>Coverage: ${esc(fw.coverage)}</div>
        ${fw.warnings && fw.warnings.length ? '<ul>' + fw.warnings.map(w => `<li>${esc(w)}</li>`).join('') + '</ul>' : ''}
        ${cliSections || '<div class="text-muted">No new configuration required.</div>'}
      </div>
    `;
  }).join('');

  const narrEl = document.getElementById('rrAiFqdnNarrative');
  const narrErrEl = document.getElementById('rrAiFqdnNarrativeError');
  if (data.narrative) {
    narrEl.textContent = data.narrative;
    narrErrEl.style.display = 'none';
  } else {
    narrEl.textContent = '';
    narrErrEl.textContent = 'AI summary unavailable: ' + (data.narrative_error || 'unknown error');
    narrErrEl.style.display = '';
  }

  document.getElementById('rrAiFqdnResult').style.display = '';
}

document.getElementById('rrAiFqdnForm')?.addEventListener('submit', runFqdnAiAssist);

checkAiAssistAvailable();
