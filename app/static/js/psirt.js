/* PSIRT Advisory Assessment — Device Review tab section */

let psirtExtracted = null;   // last extracted Advisory dict, before/after edits
let psirtAssessment = null;  // last completed PsirtAssessment dict

/* ── Availability check ───────────────────────────────────────────────────── */
async function checkPsirtAvailability() {
  try {
    const resp = await fetch('/api/device-review/psirt/extract-status');
    const data = await resp.json();
    const available = !!data.available;
    document.getElementById('psirtExtractBtn').disabled = !available;
    document.getElementById('psirtUnavailableNotice').style.display = available ? 'none' : '';
    return available;
  } catch (e) {
    return false;
  }
}

/* ── Paste vs upload toggle ───────────────────────────────────────────────── */
document.getElementById('psirtModePaste').addEventListener('click', () => {
  document.getElementById('psirtModePaste').classList.add('active');
  document.getElementById('psirtModeFile').classList.remove('active');
  document.getElementById('psirtEmailText').style.display = '';
  document.getElementById('psirtEmailFile').style.display = 'none';
});
document.getElementById('psirtModeFile').addEventListener('click', () => {
  document.getElementById('psirtModeFile').classList.add('active');
  document.getElementById('psirtModePaste').classList.remove('active');
  document.getElementById('psirtEmailText').style.display = 'none';
  document.getElementById('psirtEmailFile').style.display = '';
});

/* ── Extract ───────────────────────────────────────────────────────────────── */
document.getElementById('psirtExtractBtn').addEventListener('click', runPsirtExtract);

async function runPsirtExtract() {
  const errEl = document.getElementById('psirtExtractError');
  const runningEl = document.getElementById('psirtExtractRunning');
  errEl.style.display = 'none';
  runningEl.style.display = '';
  document.getElementById('psirtExtractBtn').disabled = true;

  const fileInput = document.getElementById('psirtEmailFile');
  const usingFile = document.getElementById('psirtEmailFile').style.display !== 'none'
    && fileInput.files.length > 0;

  try {
    let resp;
    if (usingFile) {
      const fd = new FormData();
      fd.append('file', fileInput.files[0]);
      resp = await fetch('/api/device-review/psirt/extract', { method: 'POST', body: fd });
    } else {
      const emailText = document.getElementById('psirtEmailText').value.trim();
      if (!emailText) { errEl.textContent = 'Paste the advisory text or choose a file.'; errEl.style.display = ''; return; }
      resp = await fetch('/api/device-review/psirt/extract', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email_text: emailText }),
      });
    }
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    if (!resp.ok) {
      errEl.textContent = data.field ? `${data.field}: ${data.error}` : (data.error || `Request failed (${resp.status})`);
      errEl.style.display = '';
      return;
    }
    psirtExtracted = data.advisory;
    populatePsirtReviewForm(psirtExtracted);
    document.getElementById('psirtReviewForm').style.display = '';
  } catch (e) {
    errEl.textContent = e.message;
    errEl.style.display = '';
  } finally {
    runningEl.style.display = 'none';
    document.getElementById('psirtExtractBtn').disabled = false;
  }
}

/* ── Review form ───────────────────────────────────────────────────────────── */
function populatePsirtReviewForm(advisory) {
  document.getElementById('psirtFieldAdvisoryId').value = advisory.advisory_id || '';
  document.getElementById('psirtFieldAdvisoryUrl').value = advisory.advisory_url || '';
  document.getElementById('psirtFieldCveIds').value = (advisory.cve_ids || []).join(', ');
  document.getElementById('psirtFieldSeverity').value = advisory.fortinet_severity || '';
  document.getElementById('psirtFieldCvss').value = advisory.cvss_score != null ? advisory.cvss_score : '';
  document.getElementById('psirtFieldWorkaround').value = advisory.workaround_text || '';
  document.getElementById('psirtFieldExploited').value = advisory.exploited_in_wild_text || '';

  const rowsEl = document.getElementById('psirtRangesRows');
  rowsEl.innerHTML = '';
  (advisory.affected_ranges || []).forEach(r => addPsirtRangeRow(r));
  if (!(advisory.affected_ranges || []).length) addPsirtRangeRow({});
}

function addPsirtRangeRow(r) {
  const rowsEl = document.getElementById('psirtRangesRows');
  const row = document.createElement('div');
  row.className = 'psirt-range-row';
  row.style = 'display:flex;gap:.4rem;margin-bottom:.4rem;flex-wrap:wrap';
  row.innerHTML = `
    <input type="text" class="form-control psirt-range-product" placeholder="Product (FortiOS)" style="max-width:140px" value="${escAttr(r.product || '')}">
    <input type="text" class="form-control psirt-range-min" placeholder="Min version" style="max-width:110px" value="${escAttr(r.min_version || '')}">
    <input type="text" class="form-control psirt-range-max" placeholder="Max version" style="max-width:110px" value="${escAttr(r.max_version || '')}">
    <input type="text" class="form-control psirt-range-fixed" placeholder="Fixed version" style="max-width:110px" value="${escAttr(r.fixed_version || '')}">
    <input type="text" class="form-control psirt-range-notes" placeholder="Notes" style="max-width:160px" value="${escAttr(r.notes || '')}">
    <button class="btn btn-xs" type="button" onclick="this.parentElement.remove()">&#10005;</button>
  `;
  rowsEl.appendChild(row);
}
document.getElementById('psirtAddRangeBtn').addEventListener('click', () => addPsirtRangeRow({}));

function escAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

function collectPsirtAdvisoryFromForm() {
  const cveIds = document.getElementById('psirtFieldCveIds').value
    .split(',').map(s => s.trim()).filter(Boolean);
  const ranges = [...document.querySelectorAll('#psirtRangesRows .psirt-range-row')].map(row => ({
    product: row.querySelector('.psirt-range-product').value.trim(),
    min_version: row.querySelector('.psirt-range-min').value.trim(),
    max_version: row.querySelector('.psirt-range-max').value.trim(),
    fixed_version: row.querySelector('.psirt-range-fixed').value.trim(),
    notes: row.querySelector('.psirt-range-notes').value.trim(),
  })).filter(r => r.product);
  const cvssRaw = document.getElementById('psirtFieldCvss').value.trim();
  return {
    advisory_id: document.getElementById('psirtFieldAdvisoryId').value.trim(),
    advisory_url: document.getElementById('psirtFieldAdvisoryUrl').value.trim(),
    cve_ids: cveIds,
    fortinet_severity: document.getElementById('psirtFieldSeverity').value.trim(),
    cvss_score: cvssRaw ? parseFloat(cvssRaw) : null,
    workaround_text: document.getElementById('psirtFieldWorkaround').value.trim(),
    exploited_in_wild_text: document.getElementById('psirtFieldExploited').value.trim(),
    affected_ranges: ranges,
    published_date: '', description: '', enrichment_degraded: false,
  };
}

/* ── Run assessment (progress loop over ADOM's devices, or bulk for "*") ────── */
document.getElementById('psirtRunBtn').addEventListener('click', runPsirtAssessment);

async function runPsirtAssessment() {
  const errEl = document.getElementById('psirtRunError');
  errEl.style.display = 'none';
  const adom = document.getElementById('psirtAdom').value;
  if (!adom) { errEl.textContent = 'Select an ADOM.'; errEl.style.display = ''; return; }

  const advisory = collectPsirtAdvisoryFromForm();
  if (!advisory.advisory_id || !advisory.cve_ids.length || !advisory.affected_ranges.length) {
    errEl.textContent = 'Advisory ID, at least one CVE ID, and at least one affected range are required.';
    errEl.style.display = '';
    return;
  }

  document.getElementById('psirtRunBtn').disabled = true;
  document.getElementById('psirtRunning').style.display = '';
  document.getElementById('psirtResults').style.display = 'none';
  document.getElementById('psirtProgressWrap').style.display = '';
  showPsirtProgress(0, 1, 'Running assessment…');

  try {
    const resp = await fetch('/api/device-review/psirt/assess', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ adom, advisory }),
    });
    if (resp.status === 401) { location.href = '/login'; return; }
    const data = await resp.json();
    if (!resp.ok) {
      errEl.textContent = data.error || `Request failed (${resp.status})`;
      errEl.style.display = '';
      return;
    }
    psirtAssessment = data;
    renderPsirtResults(data);
    document.getElementById('psirtResults').style.display = '';
  } catch (e) {
    errEl.textContent = e.message;
    errEl.style.display = '';
  } finally {
    document.getElementById('psirtRunBtn').disabled = false;
    document.getElementById('psirtRunning').style.display = 'none';
    document.getElementById('psirtProgressWrap').style.display = 'none';
  }
}

function showPsirtProgress(done, total, label) {
  const bar = document.getElementById('psirtProgressBar');
  const lbl = document.getElementById('psirtProgressLabel');
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  bar.style.width = pct + '%';
  bar.textContent = pct + '%';
  lbl.textContent = label;
}

/* ── Results rendering ────────────────────────────────────────────────────── */
function renderPsirtResults(data) {
  const priorityLabel = (data.priority || '').toUpperCase();
  const kevSuffix = data.kev_hit ? ' — KEV-LISTED' : '';
  document.getElementById('psirtSummary').textContent =
    `Priority: ${priorityLabel}${kevSuffix} — ${data.findings.length} device(s) evaluated. ${data.priority_rationale || ''}`;

  const warnEl = document.getElementById('psirtWarnings');
  if (data.warnings && data.warnings.length) {
    warnEl.innerHTML = '<strong>Warnings:</strong><ul>' + data.warnings.map(w => `<li>${escHtml(w)}</li>`).join('') + '</ul>';
    warnEl.style.display = '';
  } else {
    warnEl.style.display = 'none';
  }

  const tbody = document.getElementById('psirtTbody');
  tbody.innerHTML = data.findings.map(f => `
    <tr>
      <td>${escHtml(f.device)}</td>
      <td>${escHtml(f.adom)}</td>
      <td>${escHtml(f.product)}</td>
      <td>${escHtml(f.current_version || '—')}</td>
      <td>${f.in_range ? 'Yes' : 'No'}</td>
      <td>${escHtml((f.workaround_status || '').replace(/_/g, ' '))}</td>
      <td><span class="obj-type-badge">${escHtml((f.verdict || '').replace(/_/g, ' '))}</span></td>
      <td style="font-size:.82rem;color:var(--text-muted)">${escHtml(f.reason)}</td>
    </tr>
  `).join('') || '<tr><td colspan="8" class="empty-state">No devices evaluated.</td></tr>';
}

function escHtml(s) {
  const div = document.createElement('div');
  div.textContent = String(s ?? '');
  return div.innerHTML;
}

/* ── HTML report ───────────────────────────────────────────────────────────── */
document.getElementById('psirtReportBtn').addEventListener('click', async () => {
  if (!psirtAssessment) return;
  const resp = await fetch('/api/device-review/psirt/report', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assessment: psirtAssessment }),
  });
  const html = await resp.text();
  const win = window.open('', '_blank');
  if (win) { win.document.write(html); win.document.close(); }
});

/* ── Init ──────────────────────────────────────────────────────────────────── */
checkPsirtAvailability();
