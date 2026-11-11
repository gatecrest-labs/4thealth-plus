/* "Data as of" badge for views served from the inventory cache (F8).
 *
 * Shows when the collector last refreshed the inventory, flags stale or failed
 * ADOMs, and gives admins a throttled Refresh. Hidden when the cache is off or
 * nothing has been collected yet. Text is built with textContent only.
 */
(function () {
  const el = document.getElementById('invFreshness');
  if (!el) return;
  const isAdmin = el.dataset.admin === '1';
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';

  function ago(seconds) {
    if (seconds < 90) return 'just now';
    const m = Math.round(seconds / 60);
    if (m < 90) return m + ' min ago';
    return Math.round(m / 60) + ' h ago';
  }

  function render(body) {
    const rows = (body && body.adoms) || [];
    if (!body || !body.enabled || rows.length === 0) { el.hidden = true; return; }
    const ages = rows.map((r) => r.age_seconds).filter((a) => a !== null && a !== undefined);
    const oldest = ages.length ? Math.max(...ages) : null;
    const stale = rows.filter((r) => r.stale).length;
    const failed = rows.filter((r) => r.status === 'error').length;
    el.className = 'inv-freshness ' + (failed ? 'degraded' : stale ? 'stale' : 'fresh');
    el.replaceChildren();
    const label = document.createElement('span');
    label.textContent = oldest === null ? 'Data as of: unknown' : 'Data as of ' + ago(oldest);
    el.appendChild(label);
    if (failed || stale) {
      const warn = document.createElement('span');
      warn.className = 'inv-freshness-warn';
      warn.textContent = failed
        ? ' · ' + failed + ' ADOM(s) failed to refresh'
        : ' · ' + stale + ' ADOM(s) out of date';
      el.appendChild(warn);
    }
    if (isAdmin) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-sm btn-ghost inv-freshness-btn';
      btn.title = 'Ask the collector to refresh now';
      btn.textContent = '\u21BB';
      btn.addEventListener('click', refresh);
      el.appendChild(btn);
    }
    el.hidden = false;
  }

  async function load() {
    try {
      const resp = await fetch('/api/inventory/status');
      if (!resp.ok) { el.hidden = true; return; }
      render(await resp.json());
    } catch (_e) { el.hidden = true; }
  }

  async function refresh() {
    try {
      const resp = await fetch('/api/inventory/refresh', {
        method: 'POST', headers: { 'X-CSRF-Token': csrf },
      });
      const body = await resp.json().catch(() => ({}));
      el.title = resp.status === 429
        ? 'Refresh was requested recently; try again in ' + (body.retry_after || 60) + ' s'
        : 'Refresh requested; the collector picks it up within ~10 s';
      setTimeout(load, 15000);
    } catch (_e) { /* ignore */ }
  }

  load();
  setInterval(load, 60000);
})();
