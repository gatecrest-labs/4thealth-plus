/* "Data as of" label and Refresh for the policy store (F8).
 *
 * Pages declare window._policyFreshness = [{adom, pkg, mount}] (element ids). For
 * the selected ADOM + package it shows when the collector last fetched that
 * package, flags stale/failed data, and lets the user queue a refresh (the
 * collector serves it within ~10 s). Text is built with textContent only.
 */
(function () {
  const configs = window._policyFreshness || [];
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';

  function ago(seconds) {
    if (seconds < 90) return 'just now';
    const m = Math.round(seconds / 60);
    if (m < 90) return m + ' min ago';
    return Math.round(m / 60) + ' h ago';
  }

  function wire(cfg) {
    const adomEl = document.getElementById(cfg.adom);
    const pkgEl = document.getElementById(cfg.pkg);
    const mount = document.getElementById(cfg.mount);
    if (!adomEl || !pkgEl || !mount) return;
    let timer = null;

    function render(body, pkg) {
      const row = ((body && body.packages) || []).find((p) => p.pkg === pkg);
      if (!body || !body.enabled || !row || row.age_seconds === null) { mount.hidden = true; return; }
      mount.className = 'inv-freshness ' + (row.status === 'error' ? 'degraded' : row.stale ? 'stale' : 'fresh');
      mount.replaceChildren();
      const label = document.createElement('span');
      label.textContent = 'Policies as of ' + ago(row.age_seconds);
      mount.appendChild(label);
      if (row.status === 'error') {
        const warn = document.createElement('span');
        warn.className = 'inv-freshness-warn';
        warn.textContent = ' \u00B7 last refresh failed';
        mount.appendChild(warn);
      }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-sm btn-ghost inv-freshness-btn';
      btn.title = 'Ask the collector to refetch this package now';
      btn.textContent = '\u21BB';
      btn.addEventListener('click', () => refresh(pkg));
      mount.appendChild(btn);
      mount.hidden = false;
    }

    async function load() {
      const adom = adomEl.value;
      const pkg = pkgEl.value;
      if (!adom || !pkg) { mount.hidden = true; return null; }
      try {
        const resp = await fetch('/api/policy-store/status?adom=' + encodeURIComponent(adom));
        if (!resp.ok) { mount.hidden = true; return null; }
        const body = await resp.json();
        render(body, pkg);
        return (body.packages || []).find((p) => p.pkg === pkg) || null;
      } catch (_e) { mount.hidden = true; return null; }
    }

    async function refresh(pkg) {
      const before = await load();
      try {
        const resp = await fetch('/api/policy-store/refresh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
          body: JSON.stringify({ adom: adomEl.value, pkg }),
        });
        const body = await resp.json().catch(() => ({}));
        if (resp.status === 429) { mount.title = 'Try again in ' + (body.retry_after || 30) + ' s'; return; }
        if (!resp.ok) { mount.title = body.error || 'Refresh failed'; return; }
        mount.title = 'Refresh queued; the collector picks it up within ~10 s';
        let tries = 0;
        clearInterval(timer);
        timer = setInterval(async () => {
          const now = await load();
          tries += 1;
          if ((now && before && now.fetched_at !== before.fetched_at) || tries >= 12) clearInterval(timer);
        }, 5000);
      } catch (_e) { /* ignore */ }
    }

    adomEl.addEventListener('change', load);
    pkgEl.addEventListener('change', load);
    load();
  }

  configs.forEach(wire);
})();
