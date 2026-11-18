/* BGP / OSPF neighbor health classification (pure helpers, no DOM). */

function _nbrNorm(state) {
  return String(state == null ? '' : state).trim().toLowerCase();
}

function classifyBgpState(state) {
  return _nbrNorm(state) === 'established' ? 'ok' : 'bad';
}

function classifyOspfState(state) {
  // "Full/DR" -> "full"; "2-Way/DROther" -> "2-way"
  const s = _nbrNorm(state).split('/')[0].trim();
  if (s === 'full') return 'ok';
  if (s === '2-way') return 'warn';
  return 'bad';
}

function stateBadgeHtml(state, level) {
  const icons = { ok: '✓', warn: '!', bad: '✗' };
  const text = String(state == null ? '' : state).trim() || 'Unknown';
  const esc = text.replace(/&/g, '&amp;').replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  return `<span class="nbr-badge nbr-${level}">${icons[level] || ''} ${esc}</span>`;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { classifyBgpState, classifyOspfState, stateBadgeHtml };
}
