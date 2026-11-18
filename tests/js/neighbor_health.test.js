const test = require('node:test');
const assert = require('node:assert');
const { classifyBgpState, classifyOspfState, stateBadgeHtml } =
  require('../../app/static/js/neighbor_health.js');

test('BGP Established (any case) is ok', () => {
  assert.strictEqual(classifyBgpState('Established'), 'ok');
  assert.strictEqual(classifyBgpState('established'), 'ok');
});

test('BGP non-established and empty states are bad', () => {
  for (const s of ['Idle', 'Active', 'Connect', 'OpenSent', 'OpenConfirm', '', null, undefined]) {
    assert.strictEqual(classifyBgpState(s), 'bad', String(s));
  }
});

test('OSPF Full variants are ok', () => {
  for (const s of ['Full', 'FULL', 'Full/DR', 'Full/BDR']) {
    assert.strictEqual(classifyOspfState(s), 'ok', s);
  }
});

test('OSPF 2-Way variants are warn', () => {
  for (const s of ['2-Way', '2-Way/DROther']) {
    assert.strictEqual(classifyOspfState(s), 'warn', s);
  }
});

test('OSPF other and empty states are bad', () => {
  for (const s of ['Down', 'Init', 'Attempt', 'ExStart', 'Exchange', 'Loading', '', null]) {
    assert.strictEqual(classifyOspfState(s), 'bad', String(s));
  }
});

test('stateBadgeHtml escapes text and carries level class', () => {
  const h = stateBadgeHtml('<b>x</b>', 'bad');
  assert.ok(h.includes('&lt;b&gt;'));
  assert.ok(h.includes('nbr-bad'));
});

test('stateBadgeHtml shows Unknown for empty state', () => {
  assert.ok(stateBadgeHtml('', 'bad').includes('Unknown'));
});
