/* Admin page — groups management + application log viewer */
(function () {
  'use strict';

  // ── Sub-tab switching ──────────────────────────────────────────────────────
  document.querySelectorAll('.admin-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.admin-tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.admin-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('panel-' + btn.dataset.panel).classList.add('active');
      if (btn.dataset.panel === 'logs') loadLogs();
      if (btn.dataset.panel === 'map-regions' && !_mapRegionsLoaded) loadMapRegions();
      if (btn.dataset.panel === 'external-api' && !_extApiLoaded) loadExtApi();
      if (btn.dataset.panel === 'ai-assist' && !_aiAssistLoaded) loadAiAssist();
      if (btn.dataset.panel === 'scheduled') { loadSMTP(); loadJobs(); loadDRJobs(); loadRHJobs(); }
      if (btn.dataset.panel === 'backup') { window.loadBackupConfig(); window.loadBackupJobs(); }
      if (btn.dataset.panel === 'zone-policy' && !_zonePolicyLoaded) loadZonePolicyEdit();
    });
  });

  // ══════════════════════  GROUPS  ═══════════════════════════════════════════

  let allTabs  = [];
  let allUsers = [];
  let allAdoms = [];          // [{name}] from /admin/api/adoms
  let pendingDeleteName = null;

  async function loadGroups() {
    const tbody = document.getElementById('groupsTbody');
    tbody.innerHTML = '<tr><td colspan="5" class="loading-placeholder">Loading…</td></tr>';

    const [groupsRes, tabsRes, usersRes, adomsRes] = await Promise.all([
      fetch('/admin/api/groups'),
      fetch('/admin/api/tabs'),
      fetch('/admin/api/users'),
      fetch('/admin/api/adoms'),
    ]);

    if (!groupsRes.ok || !tabsRes.ok || !usersRes.ok) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-danger">Failed to load data.</td></tr>';
      return;
    }

    const groups = await groupsRes.json();
    allTabs  = await tabsRes.json();
    allUsers = await usersRes.json();
    if (adomsRes.ok) {
      const adomData = await adomsRes.json();
      allAdoms = (adomData.adoms || []).map(n => ({ name: n }));
      const statusEl = document.getElementById('adomCacheStatus');
      if (statusEl && adomData.last_updated) {
        statusEl.textContent = `Last synced: ${adomData.last_updated}`;
      }
    }

    if (!groups.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state" style="padding:.85rem 1rem">No groups yet — click <strong>+ New Group</strong> to create one.</td></tr>';
      return;
    }

    const tabMap = Object.fromEntries(allTabs.map(t => [t.key, t.name]));
    tbody.innerHTML = groups.map(g => {
      let adomCell;
      if (!g.adom_restrict) {
        adomCell = '<span class="text-muted">All ADOMs</span>';
      } else if (!g.allowed_adoms || !g.allowed_adoms.length) {
        adomCell = '<span style="color:var(--danger)">None (restricted)</span>';
      } else {
        const preview = g.allowed_adoms.slice(0, 3).map(esc).join(', ');
        const extra   = g.allowed_adoms.length > 3 ? ` <span class="text-muted">+${g.allowed_adoms.length - 3} more</span>` : '';
        adomCell = preview + extra;
      }
      const adGroupsCell = (g.ad_groups && g.ad_groups.length)
        ? g.ad_groups.slice(0, 2).map(esc).join(', ')
          + (g.ad_groups.length > 2 ? ` <span class="text-muted">+${g.ad_groups.length - 2} more</span>` : '')
        : '<span class="text-muted">—</span>';
      return `
      <tr>
        <td><strong>${esc(g.name)}</strong></td>
        <td>${g.members.length ? g.members.map(esc).join(', ') : '<span class="text-muted">—</span>'}</td>
        <td>${adGroupsCell}</td>
        <td>${g.allowed_tabs.length
              ? g.allowed_tabs.map(k => `<span class="tab-badge">${esc(tabMap[k] || k)}</span>`).join(' ')
              : '<span class="text-muted">None</span>'}</td>
        <td>${adomCell}</td>
        <td>
          <button class="btn btn-sm btn-link" data-action="edit" data-group="${esc(g.name)}">Edit</button>
          <button class="btn btn-sm" style="background:rgba(220,53,69,.1);color:var(--danger);border:1px solid rgba(220,53,69,.25)"
                  data-action="delete" data-group="${esc(g.name)}">Delete</button>
        </td>
      </tr>`;
    }).join('');
  }

  // Event delegation for Edit / Delete buttons in the groups table
  document.getElementById('groupsTbody').addEventListener('click', e => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const name = btn.dataset.group;
    if (btn.dataset.action === 'edit') {
      fetch('/admin/api/groups').then(r => r.json()).then(groups => {
        const g = groups.find(x => x.name === name);
        if (g) openGroupModal('edit', g);
      });
    } else if (btn.dataset.action === 'delete') {
      pendingDeleteName = name;
      document.getElementById('deleteGroupName').textContent = name;
      document.getElementById('deleteModal').classList.remove('hidden');
    }
  });

  // ── Group Modal ────────────────────────────────────────────────────────────

  function openGroupModal(mode, group) {
    document.getElementById('groupModalMode').value = mode;
    document.getElementById('groupModalOrigName').value = group ? group.name : '';
    document.getElementById('groupModalTitle').textContent = mode === 'edit' ? 'Edit Group' : 'New Group';
    document.getElementById('groupNameInput').value = group ? group.name : '';
    document.getElementById('groupNameInput').disabled = (mode === 'edit');
    document.getElementById('groupModalError').classList.add('hidden');

    // Tab checkboxes
    const tabBox = document.getElementById('tabCheckboxes');
    tabBox.innerHTML = allTabs.map(t => `
      <label class="checkbox-label">
        <input type="checkbox" name="tab" value="${esc(t.key)}"
               ${group && group.allowed_tabs.includes(t.key) ? 'checked' : ''} />
        ${esc(t.name)}
      </label>`).join('');

    // Member checkboxes (only non-admin users)
    const memberBox = document.getElementById('memberCheckboxes');
    const viewers = allUsers.filter(u => u.role !== 'admin');
    if (!viewers.length) {
      memberBox.innerHTML = '<span class="text-muted" style="font-size:.82rem">No viewer accounts found.</span>';
    } else {
      memberBox.innerHTML = viewers.map(u => `
        <label class="checkbox-label">
          <input type="checkbox" name="member" value="${esc(u.username)}"
                 ${group && group.members.includes(u.username) ? 'checked' : ''} />
          ${esc(u.username)}
        </label>`).join('');
    }

    // AD group tags
    _setAdGroupTags(group ? (group.ad_groups || []) : []);

    // ADOM restrict toggle
    const restrict = group ? !!group.adom_restrict : false;
    document.getElementById('adomRestrictToggle').checked = restrict;
    _toggleAdomSection(restrict);

    // ADOM checkboxes
    _buildAdomCheckboxes(group ? (group.allowed_adoms || []) : []);

    document.getElementById('groupModal').classList.remove('hidden');
  }

  // ── AD Group tag helpers ───────────────────────────────────────────────────

  function _setAdGroupTags(tags) {
    const container = document.getElementById('adGroupTags');
    container.innerHTML = '';
    tags.forEach(t => _appendAdGroupTag(container, t));
  }

  function _appendAdGroupTag(container, value) {
    if (!value.trim()) return;
    const span = document.createElement('span');
    span.style.cssText = 'display:inline-flex;align-items:center;gap:.25rem;background:var(--surface-alt);border:1px solid var(--border);border-radius:4px;padding:.15rem .45rem;font-size:.82rem';
    span.dataset.value = value.trim();
    span.innerHTML = `${esc(value.trim())} <button type="button" style="background:none;border:none;cursor:pointer;color:var(--text-muted);font-size:1rem;line-height:1;padding:0" aria-label="Remove">&times;</button>`;
    span.querySelector('button').addEventListener('click', () => span.remove());
    container.appendChild(span);
  }

  function _getAdGroupTags() {
    return [...document.querySelectorAll('#adGroupTags [data-value]')].map(s => s.dataset.value);
  }

  document.getElementById('adGroupAdd').addEventListener('click', () => {
    const inp = document.getElementById('adGroupInput');
    const val = inp.value.trim();
    if (!val) return;
    // prevent exact duplicates
    if (!_getAdGroupTags().includes(val)) {
      _appendAdGroupTag(document.getElementById('adGroupTags'), val);
    }
    inp.value = '';
    inp.focus();
  });

  document.getElementById('adGroupInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('adGroupAdd').click();
    }
  });

  function _toggleAdomSection(show) {
    document.getElementById('adomCheckboxWrap').style.display = show ? '' : 'none';
  }

  function _buildAdomCheckboxes(selected) {
    const box = document.getElementById('adomCheckboxes');
    if (!allAdoms.length) {
      box.innerHTML = '<span class="text-muted" style="font-size:.82rem">No ADOMs loaded yet (FortiManager may be unreachable).</span>';
      return;
    }
    box.innerHTML = allAdoms.map(a => `
      <label class="checkbox-label">
        <input type="checkbox" name="adom" value="${esc(a.name)}"
               ${selected.includes(a.name) ? 'checked' : ''} />
        ${esc(a.name)}
      </label>`).join('');
  }

  document.getElementById('adomRestrictToggle').addEventListener('change', e => {
    _toggleAdomSection(e.target.checked);
  });

  document.getElementById('adomSelectAll').addEventListener('click', () => {
    document.querySelectorAll('#adomCheckboxes input[name=adom]').forEach(cb => cb.checked = true);
  });

  document.getElementById('adomSelectNone').addEventListener('click', () => {
    document.querySelectorAll('#adomCheckboxes input[name=adom]').forEach(cb => cb.checked = false);
  });

  document.getElementById('btnNewGroup').addEventListener('click', () => openGroupModal('create', null));

  function closeGroupModal() {
    document.getElementById('groupModal').classList.add('hidden');
  }
  document.getElementById('groupModalClose').addEventListener('click', closeGroupModal);
  document.getElementById('groupModalCancel').addEventListener('click', closeGroupModal);

  document.getElementById('groupModalSave').addEventListener('click', async () => {
    const mode         = document.getElementById('groupModalMode').value;
    const origName     = document.getElementById('groupModalOrigName').value;
    const name         = document.getElementById('groupNameInput').value.trim();
    const tabs         = [...document.querySelectorAll('#tabCheckboxes input[name=tab]:checked')].map(i => i.value);
    const members      = [...document.querySelectorAll('#memberCheckboxes input[name=member]:checked')].map(i => i.value);
    const adGroups     = _getAdGroupTags();
    const adomRestrict = document.getElementById('adomRestrictToggle').checked;
    const allowedAdoms = [...document.querySelectorAll('#adomCheckboxes input[name=adom]:checked')].map(i => i.value);
    const errEl        = document.getElementById('groupModalError');
    errEl.classList.add('hidden');

    if (!name) { showModalError('Group name is required.'); return; }

    const body = {
      members,
      ad_groups:     adGroups,
      allowed_tabs:  tabs,
      adom_restrict: adomRestrict,
      allowed_adoms: adomRestrict ? allowedAdoms : [],
    };

    let res;
    if (mode === 'create') {
      res = await fetch('/admin/api/groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, ...body }),
      });
    } else {
      res = await fetch(`/admin/api/groups/${encodeURIComponent(origName)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    }

    if (res.ok) {
      closeGroupModal();
      loadGroups();
    } else {
      const data = await res.json().catch(() => ({}));
      showModalError(data.error || 'Failed to save group.');
    }
  });

  function showModalError(msg) {
    const el = document.getElementById('groupModalError');
    el.textContent = msg;
    el.classList.remove('hidden');
  }

  // ── Delete Modal ───────────────────────────────────────────────────────────

  function closeDeleteModal() {
    document.getElementById('deleteModal').classList.add('hidden');
    pendingDeleteName = null;
  }
  document.getElementById('deleteModalClose').addEventListener('click', closeDeleteModal);
  document.getElementById('deleteModalCancel').addEventListener('click', closeDeleteModal);

  document.getElementById('deleteModalConfirm').addEventListener('click', async () => {
    if (!pendingDeleteName) return;
    const res = await fetch(`/admin/api/groups/${encodeURIComponent(pendingDeleteName)}`, { method: 'DELETE' });
    closeDeleteModal();
    if (res.ok) loadGroups();
  });

  // Close modals on overlay click
  document.getElementById('groupModal').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeGroupModal();
  });
  document.getElementById('deleteModal').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeDeleteModal();
  });


  // ══════════════════════  EXTERNAL API  ════════════════════════════════════

  let _extApiLoaded = false;

  async function loadExtApi() {
    const [settingsRes, tokensRes] = await Promise.all([
      fetch('/admin/api/settings'),
      fetch('/admin/api/tokens'),
    ]);
    if (!settingsRes.ok) return;
    const settings = await settingsRes.json();
    document.getElementById('extApiEnabled').checked = !!settings.external_api_enabled;
    document.getElementById('execCompliantVersions').value =
      (settings.executive_compliant_versions || []).join('\n');

    if (tokensRes.ok) {
      const tokens = await tokensRes.json();
      renderTokens(tokens);
    }
    _extApiLoaded = true;
  }

  function renderTokens(tokens) {
    const tbody = document.getElementById('tokensTbody');
    if (!tokens.length) {
      tbody.innerHTML = '<tr><td colspan="3" class="empty-state" style="padding:.85rem 1rem">No tokens yet — click <strong>+ New Token</strong> to create one.</td></tr>';
      return;
    }
    tbody.innerHTML = tokens.map(t => `
      <tr>
        <td><strong>${esc(t.name)}</strong></td>
        <td>${esc(t.created_by || '—')}</td>
        <td>
          <button class="btn btn-sm"
                  style="background:rgba(220,53,69,.1);color:var(--danger);border:1px solid rgba(220,53,69,.25)"
                  data-action="revoke" data-token-id="${esc(t.id)}">Revoke</button>
        </td>
      </tr>`).join('');
  }

  async function reloadTokens() {
    const res = await fetch('/admin/api/tokens');
    if (res.ok) renderTokens(await res.json());
  }

  // Save toggle
  document.getElementById('btnSaveExtApiToggle').addEventListener('click', async () => {
    const enabled = document.getElementById('extApiEnabled').checked;
    const msgEl = document.getElementById('extApiToggleMsg');
    const res = await fetch('/admin/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ external_api_enabled: enabled }),
    });
    if (res.ok) {
      msgEl.textContent = enabled ? 'External API enabled.' : 'External API disabled.';
      msgEl.style.color = enabled ? 'var(--success)' : 'var(--warning)';
    } else {
      msgEl.textContent = 'Failed to save.';
      msgEl.style.color = 'var(--danger)';
    }
    setTimeout(() => { msgEl.textContent = ''; }, 3000);
  });

  // Save executive-summary compliant versions
  document.getElementById('btnSaveExecVersions').addEventListener('click', async () => {
    const raw = document.getElementById('execCompliantVersions').value;
    const msgEl = document.getElementById('execVersionsMsg');
    const res = await fetch('/admin/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ executive_compliant_versions: raw }),
    });
    if (res.ok) {
      msgEl.textContent = 'Saved.';
      msgEl.style.color = 'var(--success)';
    } else {
      msgEl.textContent = 'Failed to save.';
      msgEl.style.color = 'var(--danger)';
    }
    setTimeout(() => { msgEl.textContent = ''; }, 3000);
  });

  // Revoke via event delegation
  document.getElementById('tokensTbody').addEventListener('click', async e => {
    const btn = e.target.closest('[data-action="revoke"]');
    if (!btn) return;
    if (!confirm('Revoke this token? Any program using it will lose access immediately.')) return;
    const res = await fetch(`/admin/api/tokens/${encodeURIComponent(btn.dataset.tokenId)}`, { method: 'DELETE' });
    if (res.ok) reloadTokens();
  });

  // ══════════════════════  AI ASSIST  ═══════════════════════════════════════

  let _aiAssistLoaded = false;

  async function loadAiAssist() {
    const settingsRes = await fetch('/admin/api/settings');
    if (!settingsRes.ok) return;
    const settings = await settingsRes.json();
    document.getElementById('aiAssistEnabled').checked = !!settings.ai_assist_enabled;
    _aiAssistLoaded = true;
    loadAiUsage('1h');
  }

  // ── Usage & cost chart ─────────────────────────────────────────────────

  async function loadAiUsage(range) {
    const chartEl = document.getElementById('aiUsageChart');
    const summaryEl = document.getElementById('aiUsageSummary');
    chartEl.innerHTML = '<div class="loading-placeholder">Loading…</div>';
    let url;
    if (range) {
      document.querySelectorAll('.ai-usage-range-btn').forEach(b =>
        b.classList.toggle('active', b.dataset.range === range));
      url = '/admin/api/ai-usage?range=' + encodeURIComponent(range);
    } else {
      document.querySelectorAll('.ai-usage-range-btn').forEach(b => b.classList.remove('active'));
      const start = document.getElementById('aiUsageStart').value;
      const end = document.getElementById('aiUsageEnd').value;
      if (!start || !end) { chartEl.innerHTML = '<div class="text-muted">Pick both dates.</div>'; return; }
      url = '/admin/api/ai-usage?start=' + encodeURIComponent(start + 'T00:00:00+00:00')
          + '&end=' + encodeURIComponent(end + 'T23:59:59+00:00');
    }

    const res = await fetch(url);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      chartEl.innerHTML = '<div class="text-muted">' + esc(err.error || 'Failed to load usage data.') + '</div>';
      summaryEl.innerHTML = '';
      return;
    }
    const data = await res.json();
    renderAiUsageSummary(summaryEl, data);
    renderAiUsageChart(chartEl, data);
  }

  function renderAiUsageSummary(el, data) {
    el.innerHTML = `
      <div class="ai-usage-stat"><strong>${data.total_calls}</strong><span>calls</span></div>
      <div class="ai-usage-stat"><strong>$${data.total_cost_usd.toFixed(4)}</strong><span>est. cost</span></div>
      <div class="ai-usage-stat"><strong>${data.total_failures}</strong><span>failures</span></div>
      <div class="ai-usage-stat"><strong>${(data.total_input_tokens + data.total_output_tokens).toLocaleString()}</strong><span>tokens</span></div>
    `;
  }

  function aiUsageAxisLabel(iso, showDate) {
    const d = new Date(iso);
    return showDate
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  function renderAiUsageChart(el, data) {
    const buckets = data.buckets || [];
    if (!buckets.length || !buckets.some(b => b.count > 0)) {
      el.innerHTML = '<div class="text-muted" style="padding:1rem 0">No AI Assist activity in this range.</div>';
      return;
    }
    const maxCost = Math.max(...buckets.map(b => b.cost_usd), 0.0001);
    const bars = buckets.map(b => {
      const pct = Math.max(2, Math.round((b.cost_usd / maxCost) * 100));
      const label = new Date(b.start).toLocaleString(undefined,
        { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
      const title = `${label}\n${b.count} call${b.count !== 1 ? 's' : ''} — $${b.cost_usd.toFixed(4)}`;
      return `<div class="ai-usage-bar-wrap" title="${esc(title)}">
        <div class="ai-usage-bar" style="height:${b.count ? pct : 0}%"></div>
      </div>`;
    }).join('');

    // Sub-1.5-day spans show a clock time per tick; longer spans show a date
    // — based on the actual data span, so this works for the custom date
    // picker too, not just the named range buttons.
    const spanHours = (new Date(data.end) - new Date(data.start)) / 3600000;
    const showDate = spanHours > 36;

    // 5 evenly-spaced tick labels (first, quarter points, last) so the axis
    // stays readable regardless of how many buckets there are.
    const tickIdxs = [...new Set([0, 0.25, 0.5, 0.75, 1].map(f =>
      Math.min(buckets.length - 1, Math.round(f * (buckets.length - 1)))
    ))];
    const axis = buckets.map((b, i) =>
      `<div class="ai-usage-tick">${tickIdxs.includes(i) ? esc(aiUsageAxisLabel(b.start, showDate)) : ''}</div>`
    ).join('');

    el.innerHTML = `<div class="ai-usage-bars">${bars}</div><div class="ai-usage-axis">${axis}</div>`;
  }

  document.querySelectorAll('.ai-usage-range-btn').forEach(btn => {
    btn.addEventListener('click', () => loadAiUsage(btn.dataset.range));
  });
  document.getElementById('btnAiUsageCustomRange')?.addEventListener('click', () => loadAiUsage(null));

  document.getElementById('btnSaveAiAssistToggle').addEventListener('click', async () => {
    const enabled = document.getElementById('aiAssistEnabled').checked;
    const msgEl = document.getElementById('aiAssistToggleMsg');
    const res = await fetch('/admin/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ai_assist_enabled: enabled }),
    });
    if (res.ok) {
      msgEl.textContent = enabled ? 'AI Assist enabled.' : 'AI Assist disabled.';
      msgEl.style.color = enabled ? 'var(--success)' : 'var(--warning)';
      checkHostMetricsAiAvailability();
    } else {
      msgEl.textContent = 'Failed to save.';
      msgEl.style.color = 'var(--danger)';
    }
    setTimeout(() => { msgEl.textContent = ''; }, 3000);
  });

  // New token modal
  function openNewTokenModal() {
    document.getElementById('newTokenName').value = '';
    document.getElementById('newTokenError').classList.add('hidden');
    document.getElementById('newTokenModal').classList.remove('hidden');
    document.getElementById('newTokenName').focus();
  }
  function closeNewTokenModal() {
    document.getElementById('newTokenModal').classList.add('hidden');
  }

  document.getElementById('btnNewToken').addEventListener('click', openNewTokenModal);
  document.getElementById('newTokenModalClose').addEventListener('click', closeNewTokenModal);
  document.getElementById('newTokenCancel').addEventListener('click', closeNewTokenModal);
  document.getElementById('newTokenModal').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeNewTokenModal();
  });

  document.getElementById('newTokenSave').addEventListener('click', async () => {
    const name = document.getElementById('newTokenName').value.trim();
    const errEl = document.getElementById('newTokenError');
    errEl.classList.add('hidden');
    if (!name) { errEl.textContent = 'Name is required.'; errEl.classList.remove('hidden'); return; }

    const res = await fetch('/admin/api/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      errEl.textContent = d.error || 'Failed to create token.';
      errEl.classList.remove('hidden');
      return;
    }
    const data = await res.json();
    closeNewTokenModal();
    reloadTokens();
    // Show the plaintext token once
    document.getElementById('tokenRevealValue').textContent = data.token;
    document.getElementById('tokenRevealModal').classList.remove('hidden');
  });

  // Token reveal modal
  document.getElementById('tokenRevealClose').addEventListener('click', () => {
    document.getElementById('tokenRevealModal').classList.add('hidden');
  });
  document.getElementById('tokenRevealDone').addEventListener('click', () => {
    document.getElementById('tokenRevealModal').classList.add('hidden');
  });
  document.getElementById('tokenRevealModal').addEventListener('click', e => {
    if (e.target === e.currentTarget) document.getElementById('tokenRevealModal').classList.add('hidden');
  });
  document.getElementById('btnCopyToken').addEventListener('click', () => {
    const val = document.getElementById('tokenRevealValue').textContent;
    navigator.clipboard.writeText(val).then(() => {
      const btn = document.getElementById('btnCopyToken');
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
    });
  });

  // Enter key in new-token name field
  document.getElementById('newTokenName').addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); document.getElementById('newTokenSave').click(); }
  });


  // ══════════════════════  MAP REGIONS  ═════════════════════════════════════

  let _mapRegionsLoaded = false;
  let _mapAllStates     = [];

  async function loadMapRegions() {
    const tbody = document.getElementById('mapRegionsTbody');
    tbody.innerHTML = '<tr><td colspan="4" class="loading-placeholder">Loading…</td></tr>';

    const res = await fetch('/admin/api/map-regions');
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-danger">Failed to load region data.</td></tr>';
      return;
    }
    const data = await res.json();
    _mapAllStates = data.all_states || [];
    _renderMapRegions(data);
    _mapRegionsLoaded = true;
  }

  // Build the inner HTML for one named-region <tr> (called for existing and new rows).
  function _makeRegionRow(r) {
    const assigned = new Set(r.states || []);
    const options  = _mapAllStates.map(s =>
      `<option value="${esc(s)}"${assigned.has(s) ? ' selected' : ''}>${esc(s)}</option>`
    ).join('');
    const color = r.color || '#888888';
    return `<tr class="region-row">
      <td style="vertical-align:top;padding-top:.5rem">
        <input type="text" class="form-control region-name-input"
               value="${esc(r.name)}" placeholder="Region name"
               style="font-size:.85rem;padding:.35rem .5rem;font-weight:500" />
      </td>
      <td>
        <select multiple class="region-states-select"
                style="width:100%;min-height:110px;border:1px solid var(--border);border-radius:4px;font-size:.82rem;padding:.2rem;background:var(--surface);color:var(--text)">
          ${options}
        </select>
        <p style="font-size:.75rem;color:var(--text-muted);margin:.25rem 0 0">
          Hold Ctrl / Cmd to select multiple states.
        </p>
      </td>
      <td style="vertical-align:top;padding-top:.5rem">
        <div style="display:flex;align-items:center;gap:.6rem">
          <input type="color" class="region-color-input" value="${esc(color)}"
                 style="width:44px;height:30px;border:1px solid var(--border);border-radius:4px;cursor:pointer;padding:2px" />
          <span class="region-color-hex" style="font-size:.82rem;font-family:monospace">${esc(color)}</span>
        </div>
      </td>
      <td style="vertical-align:top;padding-top:.4rem;text-align:center">
        <button class="delete-region-btn btn btn-sm" title="Delete region"
                style="background:rgba(220,53,69,.1);color:var(--danger);border:1px solid rgba(220,53,69,.25);padding:.2rem .55rem;font-size:1.1rem;line-height:1">&times;</button>
      </td>
    </tr>`;
  }

  function _renderMapRegions(data) {
    const tbody      = document.getElementById('mapRegionsTbody');
    const otherColor = data.other_color || '#333333';

    const regionRows = (data.regions || []).map(_makeRegionRow).join('');

    const otherRow = `<tr id="otherRegionRow" style="border-top:2px solid var(--border)">
      <td style="vertical-align:middle"><strong>Other</strong></td>
      <td style="font-size:.83rem;color:var(--text-muted);vertical-align:middle">
        Any state not assigned to a named region above
      </td>
      <td style="vertical-align:middle">
        <div style="display:flex;align-items:center;gap:.6rem">
          <input type="color" id="otherColorInput" value="${esc(otherColor)}"
                 style="width:44px;height:30px;border:1px solid var(--border);border-radius:4px;cursor:pointer;padding:2px" />
          <span id="otherColorHex" style="font-size:.82rem;font-family:monospace">${esc(otherColor)}</span>
        </div>
      </td>
      <td></td>
    </tr>`;

    tbody.innerHTML = regionRows + otherRow;
    _syncStateSelects();
  }

  // Event delegation — handles all interactions inside the tbody.
  const _mrTbody = document.getElementById('mapRegionsTbody');

  _mrTbody.addEventListener('input', e => {
    if (e.target.matches('.region-color-input')) {
      e.target.nextElementSibling.textContent = e.target.value;
    }
    if (e.target.id === 'otherColorInput') {
      document.getElementById('otherColorHex').textContent = e.target.value;
    }
  });

  _mrTbody.addEventListener('change', e => {
    if (e.target.matches('.region-states-select')) _syncStateSelects();
  });

  _mrTbody.addEventListener('click', e => {
    const btn = e.target.closest('.delete-region-btn');
    if (btn) { btn.closest('tr').remove(); _syncStateSelects(); }
  });

  // Disable any state option that is already selected in a different region's select.
  function _syncStateSelects() {
    const selects = [...document.querySelectorAll('.region-states-select')];
    selects.forEach(sel => {
      const takenElsewhere = new Set(
        selects
          .filter(s => s !== sel)
          .flatMap(s => [...s.options].filter(o => o.selected).map(o => o.value))
      );
      sel.querySelectorAll('option').forEach(opt => {
        if (takenElsewhere.has(opt.value)) {
          opt.disabled = true;
          opt.selected = false;
        } else {
          opt.disabled = false;
        }
      });
    });
  }

  function _showMapRegionsMsg(msg, isError) {
    const el = document.getElementById('mapRegionsMsg');
    el.textContent = msg;
    el.style.background = isError ? 'rgba(220,53,69,.12)' : 'rgba(40,167,69,.12)';
    el.style.border      = isError ? '1px solid rgba(220,53,69,.3)' : '1px solid rgba(40,167,69,.3)';
    el.style.color       = isError ? 'var(--danger)' : 'var(--success)';
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 4000);
  }

  document.getElementById('btnAddRegion').addEventListener('click', () => {
    const otherRow = document.getElementById('otherRegionRow');
    if (!otherRow) return;
    otherRow.insertAdjacentHTML('beforebegin', _makeRegionRow({ name: '', color: '#888888', states: [] }));
    _syncStateSelects();
    otherRow.previousElementSibling.querySelector('.region-name-input').focus();
  });

  document.getElementById('btnSaveRegionColors').addEventListener('click', async () => {
    const regions = [];
    document.querySelectorAll('#mapRegionsTbody .region-row').forEach(row => {
      const name   = row.querySelector('.region-name-input').value.trim();
      const color  = row.querySelector('.region-color-input').value;
      const states = [...row.querySelectorAll('.region-states-select option')]
                       .filter(o => o.selected && !o.disabled)
                       .map(o => o.value);
      regions.push({ name, color, states });
    });

    const otherInp = document.getElementById('otherColorInput');
    const body = { regions, other_color: otherInp ? otherInp.value : '#333333' };

    const res = await fetch('/admin/api/map-regions', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (res.ok) {
      const data = await res.json();
      _mapAllStates = data.all_states || _mapAllStates;
      _renderMapRegions(data);
      _showMapRegionsMsg('Region configuration saved. The map will update on next load.', false);
    } else {
      const err = await res.json().catch(() => ({}));
      _showMapRegionsMsg(err.error || 'Failed to save.', true);
    }
  });


  // ══════════════════════  LOGS  ═════════════════════════════════════════════

  const LOG_LEVEL_COLORS = {
    TRACE: 'var(--text-muted)',
    DEBUG: 'var(--accent)',
    INFO:  'var(--success)',
    WARN:  'var(--warning)',
    ERROR: 'var(--danger)',
  };

  let logMeta = null;

  async function loadLogs() {
    const level     = document.getElementById('logFilterLevel').value || '';
    const component = document.getElementById('logFilterComponent').value.trim();
    const params    = new URLSearchParams({ limit: 500 });
    if (level)     params.set('level', level);
    if (component) params.set('component', component);

    const res = await fetch(`/admin/api/logs?${params}`);
    if (!res.ok) { document.getElementById('logContainer').textContent = 'Failed to load logs.'; return; }

    const data = await res.json();
    logMeta = data;

    // Populate level selects if first load
    const levelSelect = document.getElementById('logLevelSelect');
    const filterSelect = document.getElementById('logFilterLevel');
    if (!levelSelect.options.length) {
      data.levels.forEach(l => {
        levelSelect.add(new Option(l, l));
        filterSelect.add(new Option(l, l));
      });
    }
    levelSelect.value = data.current_level;
    document.getElementById('logCurrentLevel').textContent = data.current_level;
    document.getElementById('logCount').textContent = data.count;

    renderLogs(data.entries);
  }

  function renderLogs(entries) {
    const container = document.getElementById('logContainer');
    if (!entries.length) {
      container.innerHTML = '<div class="empty-state" style="padding:1rem">No log entries match your filter.</div>';
      return;
    }
    container.innerHTML = entries.slice().reverse().map(e => {
      const color = LOG_LEVEL_COLORS[e.level] || 'var(--text)';
      const extra = e.extra ? ' ' + Object.entries(e.extra).map(([k,v]) => `${k}=${JSON.stringify(v)}`).join(' ') : '';
      return `<div class="log-line">
        <span class="log-ts">${esc(e.ts)}</span>
        <span class="log-level" style="color:${color}">${esc(e.level.padEnd(5))}</span>
        <span class="log-component">[${esc(e.component)}]</span>
        <span class="log-msg">${esc(e.message)}${esc(extra)}</span>
      </div>`;
    }).join('');
    container.scrollTop = 0;
  }

  document.getElementById('btnRefreshLogs').addEventListener('click', loadLogs);

  document.getElementById('btnApplyFilter').addEventListener('click', loadLogs);

  document.getElementById('btnSetLevel').addEventListener('click', async () => {
    const level = document.getElementById('logLevelSelect').value;
    const res = await fetch('/admin/api/logs/level', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ level }),
    });
    if (res.ok) loadLogs();
  });

  document.getElementById('btnClearLogs').addEventListener('click', async () => {
    if (!confirm('Clear all log entries from the in-memory buffer?')) return;
    await fetch('/admin/api/logs', { method: 'DELETE' });
    loadLogs();
  });


  // ══════════════════════  HELPERS  ═════════════════════════════════════════

  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }


  // ══════════════════════  HOST METRICS CHARTS  ══════════════════════════════

  const HM_CHARTS = [
    { key: 'cpu',  el: 'hmCpuChart' },
    { key: 'mem',  el: 'hmMemChart' },
    { key: 'disk', el: 'hmDiskChart' },
  ];

  function hmAxisLabel(ts, showDate) {
    const d = new Date(ts * 1000);
    return showDate
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  const HM_VB_W = 300;
  const HM_VB_H = 100;

  function renderHmChart(el, series, showDate) {
    if (!series.length) {
      el.innerHTML = '<div class="text-muted" style="padding:1rem 0">No data yet.</div>';
      return;
    }
    const n = series.length;
    const vals = series.map(p => p.v == null ? null : Math.max(0, Math.min(100, p.v)));
    const xAt = i => n === 1 ? HM_VB_W / 2 : (i / (n - 1)) * HM_VB_W;
    const yAt = v => HM_VB_H - (v / 100) * HM_VB_H;

    const pts = vals.map((v, i) => v == null ? null : `${xAt(i).toFixed(2)},${yAt(v).toFixed(2)}`);
    const linePts = pts.filter(p => p !== null).join(' ');
    const areaPts = linePts
      ? `0,${HM_VB_H} ${linePts} ${HM_VB_W},${HM_VB_H}`
      : '';

    const dots = vals.map((v, i) => {
      if (v == null) return '';
      const title = `${hmAxisLabel(series[i].ts, true)}: ${v.toFixed(1)}%`;
      return `<circle class="hm-dot" cx="${xAt(i).toFixed(2)}" cy="${yAt(v).toFixed(2)}" r="1.6">
        <title>${esc(title)}</title>
      </circle>`;
    }).join('');

    const svg = `<svg class="hm-svg" viewBox="0 0 ${HM_VB_W} ${HM_VB_H}" preserveAspectRatio="none">
      ${areaPts ? `<polygon class="hm-area" points="${areaPts}"></polygon>` : ''}
      ${linePts ? `<polyline class="hm-line" points="${linePts}"></polyline>` : ''}
      ${dots}
    </svg>`;

    const tickIdxs = [...new Set([0, 0.25, 0.5, 0.75, 1].map(f =>
      Math.min(n - 1, Math.round(f * (n - 1)))
    ))];
    const axis = series.map((p, i) =>
      `<div class="hm-tick">${tickIdxs.includes(i) ? esc(hmAxisLabel(p.ts, showDate)) : ''}</div>`
    ).join('');

    el.innerHTML = `<div class="hm-svg-wrap">${svg}</div><div class="hm-axis">${axis}</div>`;
  }

  async function loadHostMetrics(range) {
    document.querySelectorAll('.hm-range-btn').forEach(b =>
      b.classList.toggle('active', b.dataset.range === range));

    const res = await fetch('/admin/api/host-metrics?range=' + encodeURIComponent(range));
    if (!res.ok) return;
    const data = await res.json();
    const showDate = range === '7d' || range === '14d';
    HM_CHARTS.forEach(({ key, el }) => {
      renderHmChart(document.getElementById(el), data[key] || [], showDate);
    });
  }

  document.querySelectorAll('.hm-range-btn').forEach(btn => {
    btn.addEventListener('click', () => loadHostMetrics(btn.dataset.range));
  });

  loadHostMetrics('1h');
  setInterval(() => {
    const active = document.querySelector('.hm-range-btn.active');
    loadHostMetrics(active ? active.dataset.range : '1h');
  }, 60000);

  async function checkHostMetricsAiAvailability() {
    const box = document.getElementById('hmAiSummaryBox');
    if (!box) return;
    try {
      const resp = await fetch('/admin/api/settings');
      const data = await resp.json();
      box.style.display = data.ai_assist_enabled ? '' : 'none';
    } catch (e) {
      box.style.display = 'none';
    }
  }

  function wireHostMetricsAiSummaryButton() {
    const btn = document.getElementById('hmAiSummaryBtn');
    const out = document.getElementById('hmAiSummaryOutput');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.textContent = 'Generating…';
      out.textContent = '';
      try {
        const resp = await fetch('/admin/api/host-metrics/ai-summary');
        const data = await resp.json();
        out.textContent = data.narrative || ('AI summary unavailable: ' + (data.narrative_error || data.error || 'unknown error'));
      } catch (e) {
        out.textContent = 'AI summary request failed: ' + e.message;
      } finally {
        btn.disabled = false;
        btn.textContent = 'Generate AI Trend Summary';
      }
    });
  }

  checkHostMetricsAiAvailability();
  wireHostMetricsAiSummaryButton();

  // ══════════════════════  ZONE POLICY (Validate + Edit)  ════════════════════

  let _zonePolicyLoaded = false;

  function loadZonePolicyEdit() {
    _zonePolicyLoaded = true;
    loadZoneEditDropdowns();
  }

  document.getElementById('zpValidateBtn').addEventListener('click', async () => {
    document.getElementById('zpValidateResult').style.display = 'none';
    document.getElementById('zpValidateError').style.display  = 'none';
    document.getElementById('zpValidateRunning').style.display = '';
    document.getElementById('zpValidateBtn').disabled          = true;

    try {
      const resp = await fetch('/api/zone/validate');
      const data = await resp.json();
      if (!resp.ok || data.error) {
        const el = document.getElementById('zpValidateError');
        el.textContent = data.error || 'Validation failed.'; el.style.display = '';
        return;
      }
      renderZpValidateReport(data);
      document.getElementById('zpValidateResult').style.display = '';
    } catch (e) {
      const el = document.getElementById('zpValidateError');
      el.textContent = e.message; el.style.display = '';
    } finally {
      document.getElementById('zpValidateRunning').style.display = 'none';
      document.getElementById('zpValidateBtn').disabled          = false;
    }
  });

  function renderZpValidateReport(r) {
    const badge = document.getElementById('zpValidateBadge');
    badge.textContent = r.ok ? '✓ VALID' : '✗ INVALID';
    badge.className   = `zp-validate-badge ${r.ok ? 'zp-valid' : 'zp-invalid'}`;
    badge.title       = `${r.zone_count} zones · ${r.subnet_count} subnets · ${r.policy_count} policies`;

    const statsLine = document.createElement('div');
    statsLine.style.cssText = 'font-size:.82rem;color:var(--text-muted);margin-top:.35rem';
    statsLine.textContent   = `${r.zone_count} zones · ${r.subnet_count} subnets · ${r.policy_count} policy rules`;
    badge.after(statsLine);

    const errEl  = document.getElementById('zpValidateErrors');
    const warnEl = document.getElementById('zpValidateWarnings');

    errEl.innerHTML = r.errors.length
      ? `<div style="font-weight:600;color:var(--danger);margin-bottom:.3rem">Errors (${r.errors.length})</div>` +
        r.errors.map(e => `<div class="zp-issue zp-issue-error">&#10007; ${esc(e)}</div>`).join('')
      : `<div class="zp-issue zp-issue-ok">&#10003; No errors</div>`;

    warnEl.innerHTML = r.warnings.length
      ? `<div style="font-weight:600;color:var(--warning);margin-bottom:.3rem;margin-top:.5rem">Warnings (${r.warnings.length})</div>` +
        r.warnings.map(w => `<div class="zp-issue zp-issue-warn">&#9888; ${esc(w)}</div>`).join('')
      : '';
  }

  function zpFlash(msg, ok) {
    const el = document.getElementById('zpEditFlash');
    if (!el) return;
    el.textContent  = msg;
    el.className    = `alert ${ok ? 'alert-success' : 'alert-danger'}`;
    el.style.display = '';
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.style.display = 'none'; }, 6000);
  }

  async function zpEditPost(url, body) {
    const resp = await fetch(url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    return resp.json();
  }

  async function loadZoneEditDropdowns() {
    try {
      const r = await fetch('/api/zone/zones').then(x => x.json());
      const zones = (r.zones || []).map(z => z.name).sort();
      ['ezZoneRemoveSel','ezZoneModSel','ezSubnetZoneSel','ezSubnetRemZone',
       'epFromZone','epToZone'].forEach(id => {
        const sel = document.getElementById(id);
        if (!sel) return;
        sel.innerHTML = '<option value="">— select zone —</option>' +
          zones.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join('');
      });
    } catch (_) {}
  }

  function zpReloadAfterEdit() {
    loadZoneEditDropdowns();
  }

  document.getElementById('zpBackupBtn').addEventListener('click', async () => {
    const btn    = document.getElementById('zpBackupBtn');
    const status = document.getElementById('zpBackupStatus');
    btn.disabled = true;
    status.textContent = 'Backing up…';
    try {
      const resp = await fetch('/api/zone/backup', { method: 'POST' });
      const data = await resp.json();
      if (data.ok) {
        status.textContent = `Saved: ${data.filename}`;
        status.style.color = 'var(--success)';
      } else {
        status.textContent = data.error || 'Backup failed.';
        status.style.color = 'var(--danger)';
      }
    } catch (e) {
      status.textContent = e.message;
      status.style.color = 'var(--danger)';
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById('ezZoneAddBtn').addEventListener('click', async () => {
    const name = document.getElementById('ezZoneName').value.trim();
    if (!name) { zpFlash('Zone name is required.', false); return; }
    const r = await zpEditPost('/api/zone/zone/add', {
      name,
      domain:      document.getElementById('ezZoneDomain').value.trim() || 'Default',
      description: document.getElementById('ezZoneDesc').value.trim(),
      is_shared:   document.getElementById('ezZoneShared').checked,
    });
    zpFlash(r.ok ? r.message : r.error, r.ok);
    if (r.ok) {
      ['ezZoneName','ezZoneDomain','ezZoneDesc'].forEach(id => { document.getElementById(id).value = ''; });
      document.getElementById('ezZoneShared').checked = false;
      zpReloadAfterEdit();
    }
  });

  document.getElementById('ezZoneRemoveBtn').addEventListener('click', async () => {
    const name = document.getElementById('ezZoneRemoveSel').value;
    if (!name) { zpFlash('Select a zone first.', false); return; }
    if (!confirm(`Remove zone "${name}"? This cannot be undone.`)) return;
    const r = await zpEditPost('/api/zone/zone/remove', { name });
    zpFlash(r.ok ? r.message : r.error, r.ok);
    if (r.ok) zpReloadAfterEdit();
  });

  document.getElementById('ezZoneModBtn').addEventListener('click', async () => {
    const name  = document.getElementById('ezZoneModSel').value;
    const field = document.getElementById('ezZoneModField').value;
    const value = document.getElementById('ezZoneModVal').value.trim();
    if (!name || !value) { zpFlash('Select a zone and enter a value.', false); return; }
    const r = await zpEditPost('/api/zone/zone/modify', { name, field, value });
    zpFlash(r.ok ? r.message : r.error, r.ok);
    if (r.ok) { document.getElementById('ezZoneModVal').value = ''; zpReloadAfterEdit(); }
  });

  document.getElementById('ezSubnetAddBtn').addEventListener('click', async () => {
    const zone   = document.getElementById('ezSubnetZoneSel').value;
    const subnet = document.getElementById('ezSubnet').value.trim();
    if (!zone || !subnet) { zpFlash('Select a zone and enter a subnet.', false); return; }
    const r = await zpEditPost('/api/zone/subnet/add', {
      zone, subnet, description: document.getElementById('ezSubnetDesc').value.trim(),
    });
    zpFlash(r.ok ? r.message : r.error, r.ok);
    if (r.ok) {
      ['ezSubnet','ezSubnetDesc'].forEach(id => { document.getElementById(id).value = ''; });
      zpReloadAfterEdit();
    }
  });

  document.getElementById('ezSubnetRemBtn').addEventListener('click', async () => {
    const zone   = document.getElementById('ezSubnetRemZone').value;
    const subnet = document.getElementById('ezSubnetRemVal').value.trim();
    if (!zone || !subnet) { zpFlash('Select a zone and enter the subnet.', false); return; }
    const r = await zpEditPost('/api/zone/subnet/remove', { zone, subnet });
    zpFlash(r.ok ? r.message : r.error, r.ok);
    if (r.ok) { document.getElementById('ezSubnetRemVal').value = ''; zpReloadAfterEdit(); }
  });

  document.getElementById('epAddBtn').addEventListener('click', async () => {
    const body = {
      policy_set:  document.getElementById('epPolSet').value.trim(),
      from_zone:   document.getElementById('epFromZone').value,
      to_zone:     document.getElementById('epToZone').value,
      access_type: document.getElementById('epAccessType').value,
      severity:    document.getElementById('epSeverity').value,
      services:    document.getElementById('epServices').value.trim(),
      description: document.getElementById('epDesc').value.trim(),
    };
    if (!body.policy_set || !body.from_zone || !body.to_zone) {
      zpFlash('Policy set, from zone, and to zone are required.', false); return;
    }
    const r = await zpEditPost('/api/zone/policy/add', body);
    zpFlash(r.ok ? r.message : r.error, r.ok);
    if (r.ok) {
      ['epPolSet','epServices','epDesc'].forEach(id => { document.getElementById(id).value = ''; });
      zpReloadAfterEdit();
    }
  });

  document.getElementById('epModBtn').addEventListener('click', async () => {
    const idx   = parseInt(document.getElementById('epModIdx').value, 10);
    const field = document.getElementById('epModField').value;
    const value = document.getElementById('epModVal').value.trim();
    if (isNaN(idx) || !field || !value) {
      zpFlash('Index, field, and value are required.', false); return;
    }
    const r = await zpEditPost('/api/zone/policy/modify', { index: idx, field, value });
    zpFlash(r.ok ? r.message : r.error, r.ok);
    if (r.ok) { document.getElementById('epModVal').value = ''; zpReloadAfterEdit(); }
  });

  document.getElementById('epRemBtn').addEventListener('click', async () => {
    const idx = parseInt(document.getElementById('epModIdx').value, 10);
    if (isNaN(idx)) { zpFlash('Enter a policy index first.', false); return; }
    if (!confirm(`Remove policy rule #${idx}? This cannot be undone.`)) return;
    const r = await zpEditPost('/api/zone/policy/remove', { index: idx });
    zpFlash(r.ok ? r.message : r.error, r.ok);
    if (r.ok) { document.getElementById('epModIdx').value = ''; zpReloadAfterEdit(); }
  });

  // ── Boot ───────────────────────────────────────────────────────────────────
  loadGroups();
})();

/* ── Config-Diff: SMTP ───────────────────────────────────────────────────── */

async function loadSMTP() {
  const res = await fetch('/admin/api/smtp');
  if (!res.ok) return;
  const cfg = await res.json();
  document.getElementById('smtpHost').value          = cfg.host || '';
  document.getElementById('smtpPort').value          = cfg.port || 25;
  document.getElementById('smtpTls').value           = cfg.tls_mode || 'none';
  document.getElementById('smtpUsername').value      = cfg.username || '';
  document.getElementById('smtpPassword').value      = cfg.password || '';
  document.getElementById('smtpFrom').value          = cfg.from_address || '';
  document.getElementById('smtpRetentionDays').value = cfg.run_history_days || 30;
  document.getElementById('smtpEnabled').checked     = !!cfg.enabled;
}

async function saveSMTP() {
  const msg = document.getElementById('smtpMsg');
  const payload = {
    host:              document.getElementById('smtpHost').value.trim(),
    port:              parseInt(document.getElementById('smtpPort').value) || 25,
    tls_mode:          document.getElementById('smtpTls').value,
    username:          document.getElementById('smtpUsername').value.trim(),
    password:          document.getElementById('smtpPassword').value,
    from_address:      document.getElementById('smtpFrom').value.trim(),
    run_history_days:  parseInt(document.getElementById('smtpRetentionDays').value) || 30,
    enabled:           document.getElementById('smtpEnabled').checked,
  };
  const res = await fetch('/admin/api/smtp', { method: 'PUT',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': getCSRF()},
    body: JSON.stringify(payload) });
  msg.style.color = res.ok ? '#166534' : '#b91c1c';
  msg.textContent = res.ok ? 'Saved.' : 'Save failed.';
  setTimeout(() => msg.textContent = '', 3000);
}

async function testSMTP() {
  const msg = document.getElementById('smtpMsg');
  const to  = document.getElementById('smtpTestTo').value.trim();
  if (!to) { msg.style.color='#b91c1c'; msg.textContent='Enter a test recipient first.'; return; }
  msg.style.color = '#6b7280'; msg.textContent = 'Sending…';
  const res  = await fetch('/admin/api/smtp/test', { method: 'POST',
    headers: {'Content-Type':'application/json', 'X-CSRF-Token': getCSRF()},
    body: JSON.stringify({to}) });
  const data = await res.json();
  msg.style.color = data.ok ? '#166534' : '#b91c1c';
  msg.textContent = data.ok ? 'Test email sent!' : `Error: ${data.error}`;
}

/* ── Config-Diff: Jobs ───────────────────────────────────────────────────── */

const _DAY_CODES = ['SUN','MON','TUE','WED','THU','FRI','SAT'];
const _DAY_LABELS = {SUN:'Sun',MON:'Mon',TUE:'Tue',WED:'Wed',THU:'Thu',FRI:'Fri',SAT:'Sat'};

let _cdiffJobs = [];

async function loadJobs() {
  const res = await fetch('/admin/api/config-diff/jobs');
  _cdiffJobs = res.ok ? await res.json() : [];
  renderJobsTable();
}

function renderJobsTable() {
  const tbody = document.getElementById('jobsTableBody');
  if (!tbody) return;
  if (!_cdiffJobs.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="color:var(--text-muted);text-align:center">No scheduled jobs.</td></tr>';
    return;
  }
  tbody.innerHTML = _cdiffJobs.map(j => {
    const last = j.runs && j.runs[0];
    const ts   = last ? new Date(last.ran_at).toLocaleString() : '—';
    const badge = !last ? '<span style="color:var(--text-muted)">Never</span>'
      : last.status === 'ok'
        ? '<span style="color:#166534;font-weight:600">OK</span>'
        : `<span style="color:var(--danger);font-weight:600" title="${escH(last.error||'')}">ERROR</span>`;
    return `<tr>
      <td>${escH(j.adom)}</td>
      <td>${(j.days_of_week||[]).map(d=>_DAY_LABELS[d]||d).join(', ')}</td>
      <td>${escH(j.time)}</td>
      <td>${escH(j.format === 'pdf' ? 'HTML' : j.format.toUpperCase())}</td>
      <td>${escH(j.email)}</td>
      <td style="font-size:11px">${ts}</td>
      <td>${badge}</td>
      <td>
        <button class="btn-sm" onclick="editJob('${j.id}')">Edit</button>
        <button class="btn-sm" style="color:var(--danger)" onclick="deleteJob('${j.id}')">Delete</button>
        <button class="btn-sm" id="runBtn-${j.id}" onclick="runJobNow('${j.id}')">Run Now</button>
      </td>
    </tr>`;
  }).join('');
}

function escH(s) {
  return String(s||'').replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function loadJobAdoms() {
  const sel = document.getElementById('jobFormAdom');
  if (!sel) return;
  const res = await fetch('/admin/api/adoms');
  const data = res.ok ? await res.json() : [];
  sel.innerHTML = (data.adoms || []).map(a => `<option value="${escH(a)}">${escH(a)}</option>`).join('');
}

function showJobForm(job) {
  document.getElementById('jobFormTitle').textContent = job ? 'Edit Scheduled Export' : 'New Scheduled Export';
  document.getElementById('jobFormId').value      = job ? job.id : '';
  document.getElementById('jobFormAdom').value    = job ? job.adom : '';
  const activeDays = job ? (job.days_of_week || ['MON']) : ['MON'];
  _DAY_CODES.forEach(code => {
    const chk = document.getElementById('dayChk-' + code);
    if (chk) chk.checked = activeDays.includes(code);
  });
  document.getElementById('jobFormTime').value    = job ? job.time : '06:00';
  document.getElementById('jobFormFormat').value  = job ? job.format : 'pdf';
  document.getElementById('jobFormEmail').value   = job ? job.email : '';
  document.getElementById('jobFormEnabled').checked = job ? !!job.enabled : true;
  document.getElementById('jobFormAiSummaryEnabled').checked = job ? job.ai_summary_enabled !== false : true;
  document.getElementById('jobFormMsg').textContent = '';
  document.getElementById('jobForm').style.display = 'block';
  loadJobAdoms();
}

function cancelJobForm() {
  document.getElementById('jobForm').style.display = 'none';
}

function editJob(id) {
  const job = _cdiffJobs.find(j => j.id === id);
  if (job) showJobForm(job);
}

async function saveJob() {
  const msg    = document.getElementById('jobFormMsg');
  const id     = document.getElementById('jobFormId').value;
  const selectedDays = _DAY_CODES.filter(code => {
    const chk = document.getElementById('dayChk-' + code);
    return chk && chk.checked;
  });
  if (selectedDays.length === 0) {
    msg.style.color = 'var(--danger)';
    msg.textContent = 'Select at least one day.';
    return;
  }
  const payload = {
    adom:         document.getElementById('jobFormAdom').value,
    days_of_week: selectedDays,
    time:         document.getElementById('jobFormTime').value,
    format:       document.getElementById('jobFormFormat').value,
    email:        document.getElementById('jobFormEmail').value.trim(),
    enabled:      document.getElementById('jobFormEnabled').checked,
    ai_summary_enabled: document.getElementById('jobFormAiSummaryEnabled').checked,
  };
  const url    = id ? `/admin/api/config-diff/jobs/${id}` : '/admin/api/config-diff/jobs';
  const method = id ? 'PUT' : 'POST';
  const res    = await fetch(url, { method,
    headers: {'Content-Type':'application/json','X-CSRF-Token': getCSRF()},
    body: JSON.stringify(payload) });
  if (res.ok) {
    cancelJobForm();
    loadJobs();
  } else {
    const err = await res.json().catch(() => ({}));
    msg.style.color = 'var(--danger)';
    msg.textContent = err.error || 'Save failed.';
  }
}

async function deleteJob(id) {
  if (!confirm('Delete this scheduled export?')) return;
  await fetch(`/admin/api/config-diff/jobs/${id}`, { method: 'DELETE',
    headers: {'X-CSRF-Token': getCSRF()} });
  loadJobs();
}

async function runJobNow(id) {
  const btn = document.getElementById(`runBtn-${id}`);
  if (btn) { btn.disabled = true; btn.textContent = 'Running…'; }
  const runRes = await fetch(`/admin/api/config-diff/jobs/${id}/run`, { method: 'POST',
    headers: {'X-CSRF-Token': getCSRF()} });
  if (!runRes.ok) {
    if (btn) { btn.disabled = false; btn.textContent = 'Run Now'; }
    return;
  }
  // Poll status every 3s until done
  const poll = setInterval(async () => {
    try {
      const res  = await fetch(`/admin/api/config-diff/jobs/${id}/status`);
      const data = await res.json();
      if (!data.running) {
        clearInterval(poll);
        if (btn) { btn.disabled = false; btn.textContent = 'Run Now'; }
        loadJobs();
      }
    } catch (_) {
      clearInterval(poll);
      if (btn) { btn.disabled = false; btn.textContent = 'Run Now'; }
    }
  }, 3000);
}

function getCSRF() {
  return document.querySelector('meta[name="csrf-token"]')?.content || '';
}

/* ── Device Review: Scheduled Jobs ─────────────────────────────────────────── */

let _drJobs = [];

async function loadDRJobs() {
  const res = await fetch('/admin/api/device-review/jobs');
  _drJobs = res.ok ? await res.json() : [];
  renderDRJobsTable();
}

function renderDRJobsTable() {
  const tbody = document.getElementById('drJobsTableBody');
  if (!tbody) return;
  if (!_drJobs.length) {
    tbody.innerHTML = '<tr><td colspan="10" style="color:var(--text-muted);text-align:center">No scheduled jobs.</td></tr>';
    return;
  }
  const totalChecks = (DR_CHECK_DEFS || []).length;
  tbody.innerHTML = _drJobs.map(j => {
    const last  = j.runs && j.runs[0];
    const ts    = last ? new Date(last.ran_at).toLocaleString() : '—';
    const badge = !last
      ? '<span style="color:var(--text-muted)">Never</span>'
      : last.status === 'ok'
        ? `<span style="color:#166534;font-weight:600" title="Findings: ${last.total_findings||0} | Fails: ${last.fail_count||0}">OK</span>`
        : `<span style="color:var(--danger);font-weight:600" title="${escH(last.error||'')}">ERROR</span>`;
    const checksCount = j.checks && j.checks.length ? `${j.checks.length} / ${totalChecks}` : `All (${totalChecks})`;
    return `<tr>
      <td>${escH(j.name||'')}</td>
      <td>${escH(j.adom)}</td>
      <td>${(j.days_of_week||[]).map(d=>_DAY_LABELS[d]||d).join(', ')}</td>
      <td>${escH(j.time)}</td>
      <td>${escH(checksCount)}</td>
      <td>${escH(j.format === 'pdf' ? 'HTML' : (j.format||'').toUpperCase())}</td>
      <td>${escH(j.email)}</td>
      <td style="font-size:11px">${ts}</td>
      <td>${badge}</td>
      <td>
        <button class="btn-sm" onclick="editDRJob('${j.id}')">Edit</button>
        <button class="btn-sm" style="color:var(--danger)" onclick="deleteDRJob('${j.id}')">Delete</button>
        <button class="btn-sm" id="drRunBtn-${j.id}" onclick="runDRJobNow('${j.id}')">Run Now</button>
      </td>
    </tr>`;
  }).join('');
}

async function loadDRJobAdoms(selectedAdom) {
  const sel = document.getElementById('drJobFormAdom');
  if (!sel) return;
  const res  = await fetch('/admin/api/adoms');
  const data = res.ok ? await res.json() : {};
  sel.innerHTML = (data.adoms || []).map(a => `<option value="${escH(a)}">${escH(a)}</option>`).join('');
  if (selectedAdom !== undefined) sel.value = selectedAdom;
}

function showDRJobForm(job) {
  document.getElementById('drJobFormTitle').textContent = job ? 'Edit Device Review Job' : 'New Device Review Job';
  document.getElementById('drJobFormId').value      = job ? job.id : '';
  document.getElementById('drJobFormName').value    = job ? (job.name||'') : '';
  document.getElementById('drJobFormAdom').value    = job ? job.adom : '';
  const activeDays = job ? (job.days_of_week || ['MON']) : ['MON'];
  _DAY_CODES.forEach(code => {
    const chk = document.getElementById('drDayChk-' + code);
    if (chk) chk.checked = activeDays.includes(code);
  });
  document.getElementById('drJobFormTime').value    = job ? job.time : '06:00';
  document.getElementById('drJobFormFormat').value  = job ? job.format : 'pdf';
  document.getElementById('drJobFormEmail').value   = job ? job.email : '';
  document.getElementById('drJobFormEnabled').checked = job ? !!job.enabled : true;
  document.getElementById('drJobFormAiSummaryEnabled').checked = job ? job.ai_summary_enabled !== false : true;

  // Restore check selections
  const savedChecks = job && job.checks && job.checks.length ? new Set(job.checks) : null;
  document.querySelectorAll('input[name="drJobCheck"]').forEach(cb => {
    cb.checked = savedChecks ? savedChecks.has(cb.value) : true;
  });

  document.getElementById('drJobFormMsg').textContent = '';
  document.getElementById('drJobForm').style.display = 'block';
  updateDRParamsPanel();

  // Restore param values — must run after updateDRParamsPanel() creates the inputs
  if (job && job.check_params) {
    Object.entries(job.check_params).forEach(([checkKey, paramValues]) => {
      Object.entries(paramValues).forEach(([paramKey, val]) => {
        const inp = document.getElementById(`drAdminParam_${checkKey}_${paramKey}`);
        if (inp) inp.value = val;
      });
    });
  }

  loadDRJobAdoms(job ? job.adom : undefined);
}

function cancelDRJobForm() {
  document.getElementById('drJobForm').style.display = 'none';
}

function editDRJob(id) {
  const job = _drJobs.find(j => j.id === id);
  if (job) showDRJobForm(job);
}

function updateDRParamsPanel() {
  const checkedKeys = new Set(
    [...document.querySelectorAll('input[name="drJobCheck"]:checked')].map(cb => cb.value)
  );
  const panel  = document.getElementById('drParamsPanel');
  const fields = document.getElementById('drParamsFields');
  if (!panel || !fields) return;

  const active = (DR_CHECK_DEFS || []).filter(
    c => checkedKeys.has(c.key) && c.params_schema && c.params_schema.length > 0
  );

  if (!active.length) { panel.style.display = 'none'; return; }
  panel.style.display = '';

  // Preserve typed values before rebuild
  const savedValues = {};
  fields.querySelectorAll('.dr-admin-param-input').forEach(inp => {
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

      const inp = document.createElement('input');
      inp.type = 'text';
      inp.id   = `drAdminParam_${check.key}_${param.key}`;
      inp.dataset.checkKey  = check.key;
      inp.dataset.paramKey  = param.key;
      inp.placeholder = param.placeholder || '';
      inp.className   = 'form-control dr-admin-param-input';
      inp.style.cssText = 'max-width:360px;font-size:.88rem';

      const savedKey = `${check.key}_${param.key}`;
      if (savedValues[savedKey] !== undefined) inp.value = savedValues[savedKey];

      row.appendChild(lbl);
      row.appendChild(inp);
      fields.appendChild(row);
    });
  });
}

function _collectDRCheckParams() {
  const params = {};
  document.querySelectorAll('.dr-admin-param-input').forEach(inp => {
    const ck  = inp.dataset.checkKey;
    const pk  = inp.dataset.paramKey;
    const val = (inp.value || '').trim();
    if (!val) return;
    if (!params[ck]) params[ck] = {};
    params[ck][pk] = val;
  });
  return params;
}

async function saveDRJob() {
  const msg  = document.getElementById('drJobFormMsg');
  const id   = document.getElementById('drJobFormId').value;
  const selectedDays = _DAY_CODES.filter(code => {
    const chk = document.getElementById('drDayChk-' + code);
    return chk && chk.checked;
  });
  if (!selectedDays.length) {
    msg.style.color = 'var(--danger)';
    msg.textContent = 'Select at least one day.';
    return;
  }
  const selectedChecks = [...document.querySelectorAll('input[name="drJobCheck"]:checked')].map(cb => cb.value);
  const payload = {
    name:         document.getElementById('drJobFormName').value.trim(),
    adom:         document.getElementById('drJobFormAdom').value,
    days_of_week: selectedDays,
    time:         document.getElementById('drJobFormTime').value,
    checks:       selectedChecks,
    check_params: _collectDRCheckParams(),
    format:       document.getElementById('drJobFormFormat').value,
    email:        document.getElementById('drJobFormEmail').value.trim(),
    enabled:      document.getElementById('drJobFormEnabled').checked,
    ai_summary_enabled: document.getElementById('drJobFormAiSummaryEnabled').checked,
  };
  const url    = id ? `/admin/api/device-review/jobs/${id}` : '/admin/api/device-review/jobs';
  const method = id ? 'PUT' : 'POST';
  const res    = await fetch(url, { method,
    headers: {'Content-Type':'application/json','X-CSRF-Token': getCSRF()},
    body: JSON.stringify(payload) });
  if (res.ok) {
    cancelDRJobForm();
    loadDRJobs();
  } else {
    const err = await res.json().catch(() => ({}));
    msg.style.color = 'var(--danger)';
    msg.textContent = err.error || 'Save failed.';
  }
}

async function deleteDRJob(id) {
  if (!confirm('Delete this Device Review job?')) return;
  await fetch(`/admin/api/device-review/jobs/${id}`, { method: 'DELETE',
    headers: {'X-CSRF-Token': getCSRF()} });
  loadDRJobs();
}

async function runDRJobNow(id) {
  const btn = document.getElementById(`drRunBtn-${id}`);
  if (btn) { btn.disabled = true; btn.textContent = 'Running…'; }
  const runRes = await fetch(`/admin/api/device-review/jobs/${id}/run`, { method: 'POST',
    headers: {'X-CSRF-Token': getCSRF()} });
  if (!runRes.ok) {
    if (btn) { btn.disabled = false; btn.textContent = 'Run Now'; }
    return;
  }
  const poll = setInterval(async () => {
    try {
      const res  = await fetch(`/admin/api/device-review/jobs/${id}/status`);
      const data = await res.json();
      if (!data.running) {
        clearInterval(poll);
        if (btn) { btn.disabled = false; btn.textContent = 'Run Now'; }
        loadDRJobs();
      }
    } catch (_) {
      clearInterval(poll);
      if (btn) { btn.disabled = false; btn.textContent = 'Run Now'; }
    }
  }, 3000);
}

// ── Rule Hygiene Scheduled Jobs ──────────────────────────────────────────────

const _RH_CHECK_KEYS = [
  'unnamed','unlogged','shadow','disabled',
  'expired','unhit','missing_security_profile','redundant',
  'over_permissive'
];

async function loadRHJobs() {
  const res = await fetch('/admin/api/rule-hygiene/jobs');
  const jobs = await res.json();
  const tbody = document.getElementById('rhJobsTableBody');
  if (!jobs.length) {
    tbody.innerHTML = '<tr><td colspan="11" style="color:var(--text-muted);text-align:center">No scheduled jobs.</td></tr>';
    return;
  }
  tbody.innerHTML = jobs.map(j => {
    const lastRun = j.runs && j.runs[0];
    const lastRunStr = lastRun
      ? `${lastRun.ran_at.slice(0,16).replace('T',' ')} — ${lastRun.status}`
      : '—';
    const activeChecks = (j.checks && j.checks.length) ? j.checks.length + ' checks' : 'All checks';
    const days = (j.days_of_week || []).join(', ');
    const enabledBadge = j.enabled
      ? '<span class="badge badge-green">Enabled</span>'
      : '<span class="badge badge-gray">Disabled</span>';
    return `<tr>
      <td>${escH(j.name)}</td>
      <td>${escH(j.adom)}</td>
      <td>${escH(days)}</td>
      <td>${escH(j.time)}</td>
      <td>${escH(activeChecks)}</td>
      <td>${escH(j.format || 'html')}</td>
      <td>${escH(j.batch_size || 20)}</td>
      <td>${escH(j.email)}</td>
      <td style="font-size:11px">${escH(lastRunStr)}</td>
      <td>${enabledBadge}</td>
      <td>
        <button class="btn-sm" onclick="showRHJobForm('${j.id}')">Edit</button>
        <button class="btn-sm" id="rhRunBtn-${j.id}" onclick="runRHJobNow('${j.id}')">Run Now</button>
        <button class="btn-sm btn-danger" onclick="deleteRHJob('${j.id}')">Delete</button>
      </td>
    </tr>`;
  }).join('');
}

function showRHJobForm(id) {
  document.getElementById('rhJobForm').style.display = '';
  document.getElementById('rhJobFormId').value = id || '';
  document.getElementById('rhJobFormMsg').textContent = '';

  // Populate ADOM dropdown
  const adomSel = document.getElementById('rhJobFormAdom');
  adomSel.innerHTML = '<option value="">Loading…</option>';
  fetch('/admin/api/adoms').then(r => r.json()).then(data => {
    adomSel.innerHTML = (data.adoms || []).map(a => `<option value="${escH(a)}">${escH(a)}</option>`).join('');
    if (id) {
      fetch('/admin/api/rule-hygiene/jobs').then(r => r.json()).then(allJobs => {
        const job = allJobs.find(j => j.id === id);
        if (!job) return;
        document.getElementById('rhJobFormTitle').textContent = 'Edit Rule Hygiene Job';
        document.getElementById('rhJobFormName').value = job.name || '';
        adomSel.value = job.adom || '';
        document.getElementById('rhJobFormTime').value = job.time || '03:00';
        ['SUN','MON','TUE','WED','THU','FRI','SAT'].forEach(d => {
          document.getElementById(`rhDayChk-${d}`).checked =
            (job.days_of_week || []).includes(d);
        });
        _RH_CHECK_KEYS.forEach(k => {
          const el = document.getElementById(`rhChk-${k}`);
          if (el) el.checked = !job.checks.length || job.checks.includes(k);
        });
        document.getElementById('rhJobFormUnusedObjects').checked =
          !!job.include_unused_objects;
        document.getElementById('rhJobFormFormat').value = job.format || 'html';
        document.getElementById('rhJobFormBatchSize').value = job.batch_size || 20;
        document.getElementById('rhJobFormEmail').value = job.email || '';
        document.getElementById('rhJobFormEnabled').checked = !!job.enabled;
      });
    } else {
      document.getElementById('rhJobFormTitle').textContent = 'New Rule Hygiene Job';
      document.getElementById('rhJobFormName').value = '';
      document.getElementById('rhJobFormTime').value = '03:00';
      ['SUN','MON','TUE','WED','THU','FRI','SAT'].forEach(d => {
        document.getElementById(`rhDayChk-${d}`).checked = false;
      });
      _RH_CHECK_KEYS.forEach(k => {
        const el = document.getElementById(`rhChk-${k}`);
        if (el) el.checked = true;
      });
      document.getElementById('rhJobFormUnusedObjects').checked = false;
      document.getElementById('rhJobFormFormat').value = 'html';
      document.getElementById('rhJobFormBatchSize').value = '20';
      document.getElementById('rhJobFormEmail').value = '';
      document.getElementById('rhJobFormEnabled').checked = true;
    }
  });
}

function cancelRHJobForm() {
  document.getElementById('rhJobForm').style.display = 'none';
}

async function saveRHJob() {
  const id = document.getElementById('rhJobFormId').value;
  const days = ['SUN','MON','TUE','WED','THU','FRI','SAT']
    .filter(d => document.getElementById(`rhDayChk-${d}`).checked);
  const checks = _RH_CHECK_KEYS.filter(k => {
    const el = document.getElementById(`rhChk-${k}`);
    return el && el.checked;
  });
  const payload = {
    name: document.getElementById('rhJobFormName').value.trim(),
    adom: document.getElementById('rhJobFormAdom').value,
    days_of_week: days,
    time: document.getElementById('rhJobFormTime').value,
    checks: checks,
    include_unused_objects: document.getElementById('rhJobFormUnusedObjects').checked,
    format: document.getElementById('rhJobFormFormat').value,
    batch_size: parseInt(document.getElementById('rhJobFormBatchSize').value, 10) || 20,
    email: document.getElementById('rhJobFormEmail').value.trim(),
    enabled: document.getElementById('rhJobFormEnabled').checked,
  };
  const url    = id ? `/admin/api/rule-hygiene/jobs/${id}` : '/admin/api/rule-hygiene/jobs';
  const method = id ? 'PUT' : 'POST';
  const res = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCSRF() },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!res.ok) {
    document.getElementById('rhJobFormMsg').textContent = data.error || 'Save failed';
    return;
  }
  cancelRHJobForm();
  loadRHJobs();
}

async function deleteRHJob(id) {
  if (!confirm('Delete this rule hygiene job?')) return;
  const res = await fetch(`/admin/api/rule-hygiene/jobs/${id}`, {
    method: 'DELETE', headers: { 'X-CSRF-Token': getCSRF() },
  });
  if (!res.ok) { alert('Delete failed'); return; }
  loadRHJobs();
}

async function runRHJobNow(id) {
  const btn = document.getElementById(`rhRunBtn-${id}`);
  if (btn) { btn.disabled = true; btn.textContent = 'Running…'; }
  const runRes = await fetch(`/admin/api/rule-hygiene/jobs/${id}/run`, {
    method: 'POST', headers: { 'X-CSRF-Token': getCSRF() },
  });
  if (!runRes.ok) {
    if (btn) { btn.disabled = false; btn.textContent = 'Run Now'; }
    alert('Failed to start job.');
    return;
  }
  pollRHJobStatus(id, btn);
}

async function pollRHJobStatus(id, btn) {
  const res  = await fetch(`/admin/api/rule-hygiene/jobs/${id}/status`);
  const data = await res.json();
  if (data.running) {
    setTimeout(() => pollRHJobStatus(id, btn), 3000);
  } else {
    if (btn) { btn.disabled = false; btn.textContent = 'Run Now'; }
    loadRHJobs();
  }
}

// ── Backup sub-tab ────────────────────────────────────────────────────────────

(function () {
  // ── Config ─────────────────────────────────────────────────────────────────

  window.loadBackupConfig = async function() {
    const resp = await fetch('/admin/api/backup/config');
    if (!resp.ok) return;
    const cfg = await resp.json();
    document.getElementById('backupPassword').value = cfg.password || '';
    document.getElementById('backupDir').value = cfg.backup_dir || '/var/backups/4thealth';
    document.getElementById('backupExcludeTlsKey').checked = !!cfg.exclude_tls_key;
    const ftp = cfg.ftp || {};
    document.getElementById('backupFtpEnabled').checked = !!ftp.enabled;
    document.getElementById('backupFtpProtocol').value = ftp.protocol || 'sftp';
    document.getElementById('backupFtpHost').value = ftp.host || '';
    document.getElementById('backupFtpPort').value = ftp.port || 22;
    document.getElementById('backupFtpUsername').value = ftp.username || '';
    document.getElementById('backupFtpPassword').value = ftp.password || '';
    document.getElementById('backupFtpRemoteDir').value = ftp.remote_dir || '/backups/4thealth';
    toggleFtpWarning();
  };

  function toggleFtpWarning() {
    const proto = document.getElementById('backupFtpProtocol').value;
    const warn = document.getElementById('backupFtpWarning');
    if (warn) warn.style.display = proto === 'ftp' ? '' : 'none';
    const portEl = document.getElementById('backupFtpPort');
    if (portEl && !portEl.dataset.manuallySet) {
      portEl.value = (proto === 'sftp' || proto === 'scp') ? 22 : 21;
    }
  }

  document.getElementById('backupFtpProtocol')
    ?.addEventListener('change', toggleFtpWarning);

  // Show/hide password toggle
  document.getElementById('backupPasswordToggle')?.addEventListener('click', function () {
    const pw = document.getElementById('backupPassword');
    if (pw.type === 'password') {
      pw.type = 'text';
      this.textContent = 'Hide';
    } else {
      pw.type = 'password';
      this.textContent = 'Show';
    }
  });

  // Settings form save
  document.getElementById('backupSettingsForm')?.addEventListener('submit', async function (e) {
    e.preventDefault();
    const existing = await (await fetch('/admin/api/backup/config')).json();
    const ftp = existing.ftp || {};
    const payload = {
      password: document.getElementById('backupPassword').value,
      backup_dir: document.getElementById('backupDir').value,
      max_files: 20,
      exclude_tls_key: document.getElementById('backupExcludeTlsKey').checked,
      ftp: {
        enabled: document.getElementById('backupFtpEnabled').checked,
        protocol: document.getElementById('backupFtpProtocol').value,
        host: document.getElementById('backupFtpHost').value,
        port: parseInt(document.getElementById('backupFtpPort').value) || 22,
        username: document.getElementById('backupFtpUsername').value,
        password: document.getElementById('backupFtpPassword').value,
        remote_dir: document.getElementById('backupFtpRemoteDir').value,
      },
    };
    const resp = await fetch('/admin/api/backup/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCSRF() },
      body: JSON.stringify(payload),
    });
    const msg = document.getElementById('backupSettingsSaveMsg');
    if (resp.ok) {
      msg.textContent = '✓ Saved';
      msg.style.color = 'var(--success-color)';
      // Show password hint on first save
      const hint = document.getElementById('backupPasswordHint');
      if (hint && payload.password && payload.password !== '••••••') {
        hint.style.display = '';
        setTimeout(() => { hint.style.display = 'none'; }, 15000);
      }
    } else {
      const data = await resp.json();
      msg.textContent = data.error || 'Save failed';
      msg.style.color = 'var(--danger-color)';
    }
    msg.style.display = '';
    setTimeout(() => { msg.style.display = 'none'; }, 5000);
  });

  // FTP form save (reuses the same settings endpoint)
  document.getElementById('backupFtpForm')?.addEventListener('submit', async function (e) {
    e.preventDefault();
    // Get current settings to preserve password/dir/etc
    const existing = await (await fetch('/admin/api/backup/config')).json();
    const payload = {
      ...existing,
      password: existing.password,  // keep existing (masked) password
      ftp: {
        enabled: document.getElementById('backupFtpEnabled').checked,
        protocol: document.getElementById('backupFtpProtocol').value,
        host: document.getElementById('backupFtpHost').value,
        port: parseInt(document.getElementById('backupFtpPort').value) || 22,
        username: document.getElementById('backupFtpUsername').value,
        password: document.getElementById('backupFtpPassword').value,
        remote_dir: document.getElementById('backupFtpRemoteDir').value,
      },
    };
    await fetch('/admin/api/backup/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCSRF() },
      body: JSON.stringify(payload),
    });
  });

  // FTP test connection
  document.getElementById('backupFtpTestBtn')?.addEventListener('click', async function () {
    const ftpCfg = {
      protocol: document.getElementById('backupFtpProtocol').value,
      host: document.getElementById('backupFtpHost').value,
      port: parseInt(document.getElementById('backupFtpPort').value) || 22,
      username: document.getElementById('backupFtpUsername').value,
      password: document.getElementById('backupFtpPassword').value,
      remote_dir: document.getElementById('backupFtpRemoteDir').value,
    };
    const resultEl = document.getElementById('backupFtpTestResult');
    resultEl.textContent = 'Testing…';
    resultEl.style.display = '';
    const resp = await fetch('/admin/api/backup/ftp/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCSRF() },
      body: JSON.stringify(ftpCfg),
    });
    const data = await resp.json();
    resultEl.textContent = data.success ? '✓ ' + data.message : '✗ ' + data.message;
    resultEl.style.color = data.success ? 'var(--success-color)' : 'var(--danger-color)';
  });

  // ── One-time backup ─────────────────────────────────────────────────────────

  document.getElementById('backupRunNowBtn')?.addEventListener('click', async function () {
    const btn = this;
    const spinner = document.getElementById('backupRunNowSpinner');
    btn.disabled = true;
    spinner.style.display = '';

    try {
      const resp = await fetch('/admin/api/backup/run-now', { method: 'POST', headers: { 'X-CSRF-Token': getCSRF() } });
      if (!resp.ok) {
        const err = await resp.json();
        alert('Backup failed: ' + (err.error || 'Unknown error'));
        return;
      }
      const filename = resp.headers.get('X-Backup-Filename') || 'backup.zip';
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      const lastEl = document.getElementById('backupLastManual');
      lastEl.textContent = 'Last manual backup: ' + filename + ' (' + new Date().toLocaleString() + ')';
      lastEl.style.display = '';
    } finally {
      btn.disabled = false;
      spinner.style.display = 'none';
    }
  });

  // ── Scheduled jobs ──────────────────────────────────────────────────────────

  window.loadBackupJobs = async function() {
    const resp = await fetch('/admin/api/backup/jobs');
    if (!resp.ok) return;
    const jobs = await resp.json();
    const tbody = document.getElementById('backupJobsBody');
    if (!tbody) return;
    if (!jobs.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">No scheduled backup jobs.</td></tr>';
      return;
    }
    tbody.innerHTML = jobs.map(j => {
      const lastRun = j.runs && j.runs[0];
      const statusBadge = lastRun
        ? `<span class="badge ${lastRun.status === 'success' ? 'badge-success' : 'badge-danger'}">${escH(lastRun.status)}</span>`
        : '<span style="color:var(--text-muted)">Never</span>';
      const lastRunTime = lastRun ? new Date(lastRun.started_at).toLocaleString() : '—';
      return `<tr>
        <td>${escH(j.name)}</td>
        <td>${(j.days_of_week || []).join(', ')}</td>
        <td>${escH(j.time)}</td>
        <td>${lastRunTime}</td>
        <td>${statusBadge}</td>
        <td>
          <button class="btn btn-xs" onclick="backupEditJob('${escH(j.id)}')">Edit</button>
          <button class="btn btn-xs btn-danger" onclick="backupDeleteJob('${escH(j.id)}')">Delete</button>
          <button class="btn btn-xs" onclick="backupRunJobNow('${escH(j.id)}')">Run Now</button>
        </td>
      </tr>`;
    }).join('');
  };


  document.getElementById('backupAddJobBtn')?.addEventListener('click', function () {
    document.getElementById('backupJobId').value = '';
    document.getElementById('backupJobFormTitle').textContent = 'Add Backup Job';
    document.getElementById('backupJobName').value = '';
    document.getElementById('backupJobTime').value = '02:00';
    document.getElementById('backupJobEnabled').checked = true;
    document.querySelectorAll('#backupDayPicker input').forEach(cb => { cb.checked = false; });
    document.getElementById('backupJobFormError').style.display = 'none';
    document.getElementById('backupJobForm').style.display = '';
  });

  document.getElementById('backupJobCancelBtn')?.addEventListener('click', function () {
    document.getElementById('backupJobForm').style.display = 'none';
  });

  document.getElementById('backupJobSaveBtn')?.addEventListener('click', async function () {
    const jobId = document.getElementById('backupJobId').value;
    const days = Array.from(document.querySelectorAll('#backupDayPicker input:checked')).map(cb => cb.value);
    const payload = {
      name: document.getElementById('backupJobName').value.trim(),
      days_of_week: days,
      time: document.getElementById('backupJobTime').value,
      enabled: document.getElementById('backupJobEnabled').checked,
    };
    const url = jobId ? `/admin/api/backup/jobs/${jobId}` : '/admin/api/backup/jobs';
    const method = jobId ? 'PUT' : 'POST';
    const resp = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCSRF() },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) {
      const err = await resp.json();
      const errEl = document.getElementById('backupJobFormError');
      errEl.textContent = err.error || 'Save failed';
      errEl.style.display = '';
      return;
    }
    document.getElementById('backupJobForm').style.display = 'none';
    window.loadBackupJobs();
  });

  window.backupEditJob = async function (jobId) {
    const resp = await fetch('/admin/api/backup/jobs');
    const jobs = await resp.json();
    const job = jobs.find(j => j.id === jobId);
    if (!job) return;
    document.getElementById('backupJobId').value = job.id;
    document.getElementById('backupJobFormTitle').textContent = 'Edit Backup Job';
    document.getElementById('backupJobName').value = job.name || '';
    document.getElementById('backupJobTime').value = job.time || '02:00';
    document.getElementById('backupJobEnabled').checked = !!job.enabled;
    document.querySelectorAll('#backupDayPicker input').forEach(cb => {
      cb.checked = (job.days_of_week || []).includes(cb.value);
    });
    document.getElementById('backupJobFormError').style.display = 'none';
    document.getElementById('backupJobForm').style.display = '';
  };

  window.backupDeleteJob = async function (jobId) {
    if (!confirm('Delete this backup job?')) return;
    await fetch(`/admin/api/backup/jobs/${jobId}`, { method: 'DELETE', headers: { 'X-CSRF-Token': getCSRF() } });
    window.loadBackupJobs();
  };

  window.backupRunJobNow = async function (jobId) {
    const resp = await fetch(`/admin/api/backup/jobs/${jobId}/run`, { method: 'POST', headers: { 'X-CSRF-Token': getCSRF() } });
    if (resp.ok) {
      alert('Backup job queued. Check the jobs table for status in a moment.');
      setTimeout(window.loadBackupJobs, 3000);
    }
  };
})();
