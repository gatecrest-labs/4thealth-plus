'use strict';

(function () {

// ── Region definitions — loaded from /api/map/regions at startup ─────────────
// Fallback values used if the API call fails.
const _FALLBACK_REGIONS = [
  { name: 'Upper Midwest', color: '#1976d2', states: new Set(['Minnesota', 'Wisconsin', 'North Dakota', 'South Dakota']) },
  { name: 'Colorado',      color: '#e53935', states: new Set(['Colorado']) },
  { name: 'Southwest',     color: '#43a047', states: new Set(['Texas', 'New Mexico']) },
];
const _FALLBACK_OTHER = { name: 'Other', color: '#333333', states: null };

let REGIONS      = [..._FALLBACK_REGIONS, _FALLBACK_OTHER];
let REGION_OTHER = _FALLBACK_OTHER;

async function loadRegions() {
  try {
    const r = await fetch('/api/map/regions');
    if (!r.ok) return;
    const data = await r.json();
    const named = (data.regions || []).map(rg => ({
      name:   rg.name,
      color:  rg.color,
      states: new Set(rg.states || []),
    }));
    REGION_OTHER = { name: 'Other', color: data.other_color || '#333333', states: null };
    REGIONS = [...named, REGION_OTHER];
  } catch (_) {
    // Keep fallback values
  }
}

function regionForState(stateName) {
  for (const r of REGIONS) {
    if (r.states && r.states.has(stateName)) return r;
  }
  return REGION_OTHER;
}

// ── State GeoJSON + point-in-polygon ─────────────────────────────────────────
let stateFeatures = [];   // loaded once from /static/vendor/us-states.json

async function loadStateGeoJSON() {
  const r = await fetch('/static/vendor/us-states.json');
  const gj = await r.json();
  stateFeatures = gj.features;
}

// Ray-casting point-in-polygon for a single ring (array of [lon,lat] pairs)
function pointInRing(lon, lat, ring) {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const [xi, yi] = ring[i];
    const [xj, yj] = ring[j];
    if (((yi > lat) !== (yj > lat)) &&
        (lon < (xj - xi) * (lat - yi) / (yj - yi) + xi)) {
      inside = !inside;
    }
  }
  return inside;
}

// Works for Polygon and MultiPolygon GeoJSON geometries
function pointInFeature(lon, lat, feature) {
  const geom = feature.geometry;
  if (!geom) return false;
  const rings = geom.type === 'Polygon'
    ? [geom.coordinates[0]]
    : geom.coordinates.map(poly => poly[0]);   // outer ring of each polygon
  return rings.some(ring => pointInRing(lon, lat, ring));
}

function stateForPoint(lat, lon) {
  for (const f of stateFeatures) {
    if (pointInFeature(lon, lat, f)) return f.properties.name;
  }
  return null;
}

// Cache state lookups — same coords will appear many times for clustered sites
const _stateCache = new Map();
function cachedStateForPoint(lat, lon) {
  const key = `${lat.toFixed(4)},${lon.toFixed(4)}`;
  if (!_stateCache.has(key)) _stateCache.set(key, stateForPoint(lat, lon));
  return _stateCache.get(key);
}

function colorForDevice(device) {
  const state = cachedStateForPoint(device.lat, device.lon);
  return regionForState(state).color;
}

function regionNameForDevice(device) {
  const state = cachedStateForPoint(device.lat, device.lon);
  const region = regionForState(state);
  return state ? `${state} (${region.name})` : region.name;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return 'never';
  try {
    const diff = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
    if (diff < 2)    return 'just now';
    if (diff < 60)   return `${diff}m ago`;
    if (diff < 1440) return `${Math.round(diff / 60)}h ago`;
    return `${Math.round(diff / 1440)}d ago`;
  } catch (e) { return iso; }
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── State ────────────────────────────────────────────────────────────────────

let activeAdoms   = null;   // null = all; Set of adom names when filtered
let leafletMap    = null;
let clusterGroup  = null;
let allDevices    = [];
let pollTimer     = null;
let markersByName = new Map();  // lowercase name → { marker, device }

// ── Leaflet initialisation ───────────────────────────────────────────────────

function initMap() {
  if (leafletMap) return;
  document.getElementById('mapLoading').style.display = 'none';

  leafletMap = L.map('mapContainer', {
    center: [38.5, -98.0],
    zoom: 4, minZoom: 2, maxZoom: 18,
    maxBounds: [[-85.051129, -180], [85.051129, 180]],
    maxBoundsViscosity: 1.0,
  });

  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    maxZoom: 18,
    noWrap: true,
  }).addTo(leafletMap);

  clusterGroup = L.markerClusterGroup({
    showCoverageOnHover: false,
    maxClusterRadius: 50,
    iconCreateFunction(cluster) {
      const count = cluster.getChildCount();
      // Majority-colour among child markers
      const tally = {};
      cluster.getAllChildMarkers().forEach(m => {
        const c = m.options._color || '#333';
        tally[c] = (tally[c] || 0) + 1;
      });
      const topColor = Object.entries(tally).sort((a, b) => b[1] - a[1])[0][0];
      const size = count >= 100 ? 'lg' : count >= 10 ? 'md' : 'sm';
      return L.divIcon({
        html: `<div class="map-cluster map-cluster-${size}" style="background:${topColor}">${count}</div>`,
        className: '',
        iconSize: size === 'lg' ? [46,46] : size === 'md' ? [38,38] : [30,30],
      });
    },
  });

  leafletMap.addLayer(clusterGroup);
}

// ── Marker creation ──────────────────────────────────────────────────────────

function makeMarker(device) {
  const color      = colorForDevice(device);
  const regionLabel = regionNameForDevice(device);

  const icon = L.divIcon({
    html: `<div class="map-pin" style="background:${color};border-color:${color}"></div>`,
    className: '',
    iconSize: [14, 14],
    iconAnchor: [7, 7],
  });

  const marker = L.marker([device.lat, device.lon], { icon, _color: color });

  const statusDot = device.status === 'green'
    ? '<span class="map-popup-dot green"></span>'
    : '<span class="map-popup-dot offline"></span>';

  const detailsLink = window._perms.firewalls
    ? `<div class="map-popup-footer">
         <a href="/firewalls?device=${encodeURIComponent(device.name)}&amp;adom=${encodeURIComponent(device.adom)}"
            class="map-popup-details-link">View Details &#x2192;</a>
       </div>`
    : '';

  const vdoms = Array.isArray(device.vdoms) ? device.vdoms.filter(Boolean) : [];
  const vdomRow = vdoms.length > 0
    ? `<tr><th>VDOMs</th><td>${vdoms.map(v => `<span class="map-vdom-badge">${esc(v)}</span>`).join(' ')}</td></tr>`
    : '';
  const multiVdomBadge = vdoms.length > 1
    ? ` <span class="map-vdom-count">${vdoms.length} VDOMs</span>`
    : '';

  marker.bindPopup(`
<div class="map-popup">
  <div class="map-popup-name">${statusDot}${esc(device.name)}${multiVdomBadge}</div>
  <table class="map-popup-table">
    <tr><th>Region</th><td><span class="map-popup-adom-dot" style="background:${esc(color)}"></span>${esc(regionLabel)}</td></tr>
    <tr><th>ADOM</th><td>${esc(device.adom)}</td></tr>
    <tr><th>Platform</th><td>${esc(device.platform)}</td></tr>
    <tr><th>Version</th><td>${esc(device.version)}</td></tr>
    ${device.desc ? `<tr><th>Desc</th><td>${esc(device.desc)}</td></tr>` : ''}
    ${vdomRow}
    <tr><th>Status</th><td>${esc(device.status)}</td></tr>
    <tr><th>Coords</th><td>${device.lat.toFixed(5)}, ${device.lon.toFixed(5)}</td></tr>
  </table>
  ${detailsLink}
</div>`, { maxWidth: 320 });

  return marker;
}

// ── Render / filter ──────────────────────────────────────────────────────────

function renderMarkers() {
  if (!clusterGroup) return;
  clusterGroup.clearLayers();
  markersByName.clear();

  const visible = activeAdoms === null
    ? allDevices
    : allDevices.filter(d => activeAdoms.has(d.adom));

  visible.forEach(d => {
    const m = makeMarker(d);
    clusterGroup.addLayer(m);
    markersByName.set(d.name.toLowerCase(), { marker: m, device: d });
  });

  const statsEl = document.getElementById('mapStats');
  if (statsEl) statsEl.textContent = `Showing ${visible.length} of ${allDevices.length} devices`;
}

// ── Device search ────────────────────────────────────────────────────────────

function searchDevice(query) {
  const msgEl = document.getElementById('mapSearchMsg');
  const q = query.trim();
  if (!q) { if (msgEl) msgEl.textContent = ''; return; }

  const entry = markersByName.get(q.toLowerCase());
  if (!entry) {
    // Check if device exists but is hidden by ADOM filter
    const exists = allDevices.some(d => d.name.toLowerCase() === q.toLowerCase());
    if (msgEl) msgEl.textContent = exists
      ? `"${q}" is not visible — check ADOM filter.`
      : `No device named "${q}" found.`;
    return;
  }

  if (msgEl) msgEl.textContent = '';
  clusterGroup.zoomToShowLayer(entry.marker, () => {
    entry.marker.openPopup();
    highlightMarker(entry.marker);
  });
}

function highlightMarker(marker) {
  const el = marker.getElement();
  if (!el) return;
  const pin = el.querySelector('.map-pin');
  if (!pin) return;
  pin.classList.remove('map-pin-highlight');
  // Force reflow so re-triggering the animation works if called twice
  void pin.offsetWidth;
  pin.classList.add('map-pin-highlight');
  setTimeout(() => pin.classList.remove('map-pin-highlight'), 2400);
}

// ── Health ledger ────────────────────────────────────────────────────────────

function updateHealthLedger() {
  const el = document.getElementById('mapHealthLedger');
  if (!el || !allDevices.length) return;
  const counts = { green: 0, yellow: 0, red: 0, offline: 0 };
  allDevices.forEach(d => {
    const s = d.status || 'offline';
    if (s in counts) counts[s]++;
    else counts.offline++;
  });
  const items = [
    { status: 'green',   label: 'Healthy',  count: counts.green },
    { status: 'yellow',  label: 'Warning',  count: counts.yellow },
    { status: 'red',     label: 'Critical', count: counts.red },
    { status: 'offline', label: 'Offline',  count: counts.offline },
  ];
  el.innerHTML = items.map(i =>
    `<span class="ledger-item">` +
      `<span class="status-dot ${i.status}"></span>` +
      `<span class="ledger-label">${i.label}</span>` +
      `<span class="ledger-count ledger-count-${i.status}">${i.count}</span>` +
    `</span>`
  ).join('');
  el.style.display = '';
}

// ── Legend (region-based) + ADOM filter UI ───────────────────────────────────

function buildLegend() {
  const legendEl = document.getElementById('mapLegend');
  if (!legendEl) return;
  legendEl.innerHTML = REGIONS.map(r =>
    `<span class="map-legend-item">
       <span class="map-legend-dot" style="background:${r.color}"></span>${esc(r.name)}
     </span>`
  ).join('');
}

function buildAdomFilter(adoms) {
  const filterEl = document.getElementById('mapAdomFilters');
  if (!filterEl) return;

  filterEl.innerHTML = adoms.map(a => {
    // Pick the most common region colour among devices in this ADOM
    const devicesInAdom = allDevices.filter(d => d.adom === a);
    const sampleColor = devicesInAdom.length ? colorForDevice(devicesInAdom[0]) : '#333';
    return `<label class="map-adom-check">
      <input type="checkbox" checked data-adom="${esc(a)}" />
      <span class="map-adom-swatch" style="background:${sampleColor}"></span>${esc(a)}
    </label>`;
  }).join('');

  filterEl.querySelectorAll('input[type=checkbox]').forEach(cb => {
    cb.addEventListener('change', () => syncFilter(filterEl));
  });

  document.getElementById('mapSelectAll').addEventListener('click', () => {
    filterEl.querySelectorAll('input').forEach(i => i.checked = true);
    activeAdoms = null;
    renderMarkers();
  });
  document.getElementById('mapSelectNone').addEventListener('click', () => {
    filterEl.querySelectorAll('input').forEach(i => i.checked = false);
    activeAdoms = new Set();
    renderMarkers();
  });
}

function syncFilter(filterEl) {
  const checked = [...filterEl.querySelectorAll('input:checked')].map(i => i.dataset.adom);
  activeAdoms = checked.length === filterEl.querySelectorAll('input').length
    ? null : new Set(checked);
  renderMarkers();
}

// ── Status bar ───────────────────────────────────────────────────────────────

function showStatusBar(text, detail, spinning) {
  const bar = document.getElementById('mapStatusBar');
  if (!bar) return;
  bar.style.display = 'flex';
  document.getElementById('mapStatusSpinner').style.display = spinning ? '' : 'none';
  document.getElementById('mapStatusText').textContent  = text;
  document.getElementById('mapProgressDetail').textContent = detail || '';
}

function hideStatusBar() {
  const bar = document.getElementById('mapStatusBar');
  if (bar) bar.style.display = 'none';
}

function updateLastUpdated(iso) {
  const el = document.getElementById('mapLastUpdated');
  if (el) el.textContent = iso ? `Updated ${fmtDate(iso)}` : '';
}

// ── Progress polling ──────────────────────────────────────────────────────────

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(pollStatus, 2500);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

async function pollStatus() {
  try {
    const r = await fetch('/api/map/status');
    if (!r.ok) return;
    const data = await r.json();
    const prog  = data.adom_progress || {};
    const total = Object.keys(prog).length;
    const done  = Object.values(prog).filter(v => v === 'ok' || v === 'error').length;
    const cur   = Object.entries(prog).find(([,v]) => v === 'running');
    let detail  = total ? `${done} / ${total} ADOMs${cur ? ' — ' + cur[0] : ''}` : '';
    showStatusBar('Refreshing device locations…', detail, true);
    if (data.status === 'ok' || data.status === 'error') {
      stopPolling();
      await loadDevices();
    }
  } catch (_) {}
}

// ── Main data load ────────────────────────────────────────────────────────────

async function loadDevices() {
  try {
    const r = await fetch('/api/map/devices');
    if (!r.ok) { showStatusBar(`Error loading map data (HTTP ${r.status})`, '', false); return; }
    const data = await r.json();

    if (data.status === 'running') { showStatusBar('Refreshing device locations…', '', true); startPolling(); return; }

    allDevices = data.devices || [];
    updateLastUpdated(data.last_updated);

    const adoms = [...new Set(allDevices.map(d => d.adom))].sort();

    initMap();
    buildLegend();
    buildAdomFilter(adoms);
    document.getElementById('mapControls').style.display = '';

    if (data.status === 'error') {
      showStatusBar(`Cache error: ${data.error || 'unknown'}`, '', false);
    } else if (data.status === 'pending') {
      showStatusBar('Location data is warming up — map will refresh automatically.', '', true);
      startPolling();
    } else {
      hideStatusBar();
    }

    renderMarkers();
    updateHealthLedger();
  } catch (err) {
    showStatusBar(`Failed to load map: ${err.message}`, '', false);
  }
}

// ── Refresh button (admin only) ───────────────────────────────────────────────

async function triggerRefresh() {
  const btn = document.getElementById('mapRefreshBtn');
  if (btn) btn.disabled = true;
  try {
    await fetch('/api/map/refresh', { method: 'POST' });
    showStatusBar('Refresh queued…', '', true);
    startPolling();
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  showStatusBar('Loading device locations…', '', true);

  if (window._perms.isAdmin) {
    const btn = document.getElementById('mapRefreshBtn');
    if (btn) { btn.style.display = ''; btn.addEventListener('click', triggerRefresh); }
  }

  const searchInput = document.getElementById('mapDeviceSearch');
  const searchBtn   = document.getElementById('mapSearchBtn');
  if (searchInput) {
    searchInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') searchDevice(searchInput.value);
    });
    searchInput.addEventListener('input', () => {
      const msgEl = document.getElementById('mapSearchMsg');
      if (msgEl && !searchInput.value.trim()) msgEl.textContent = '';
    });
  }
  if (searchBtn) {
    searchBtn.addEventListener('click', () => {
      if (searchInput) searchDevice(searchInput.value);
    });
  }

  await Promise.all([loadStateGeoJSON(), loadRegions()]);
  await loadDevices();
});

})();
