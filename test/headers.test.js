'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { analyze } = require('../src/headers');

function m(arr) { const out = {}; for (const [k, v] of arr) out[k.toLowerCase()] = v; return out; }

test('analyze: bare response flags the common 5', () => {
  const findings = analyze({});
  const ids = findings.map((f) => f.id);
  assert.ok(ids.includes('HSTS-MISSING'));
  assert.ok(ids.includes('CSP-MISSING'));
  assert.ok(ids.includes('XCTO-MISSING'));
  assert.ok(ids.includes('XFO-MISSING'));
  assert.ok(ids.includes('REFERRER-POLICY-MISSING'));
});

test('analyze: a hardened response produces no HIGH/MEDIUM findings', () => {
  const headers = m([
    ['strict-transport-security', 'max-age=31536000; includeSubDomains'],
    ['content-security-policy', "default-src 'self'; frame-ancestors 'none'"],
    ['x-frame-options', 'DENY'],
    ['x-content-type-options', 'nosniff'],
    ['referrer-policy', 'no-referrer'],
  ]);
  const findings = analyze(headers);
  assert.ok(findings.every((f) => f.severity !== 'HIGH' && f.severity !== 'MEDIUM'), JSON.stringify(findings));
});

test('analyze: frame-ancestors alone satisfies XFO check', () => {
  const headers = m([
    ['content-security-policy', "default-src 'self'; frame-ancestors 'none'"],
  ]);
  const findings = analyze(headers);
  assert.equal(findings.find((f) => f.id === 'XFO-MISSING'), undefined);
});

test('analyze: server version disclosure flagged', () => {
  const headers = m([['server', 'nginx/1.21.4']]);
  const f = analyze(headers).find((x) => x.id === 'SERVER-VERSION-DISCLOSURE');
  assert.ok(f);
  assert.match(f.evidence, /nginx\/1.21.4/);
});
