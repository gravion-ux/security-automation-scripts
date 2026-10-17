'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { findingsFor, WEAK_CIPHER_PATTERNS } = require('../src/tls');

const URL = 'https://example.test/';

test('tls: connection failure produces a single MEDIUM finding', () => {
  const f = findingsFor(URL, { ok: false, error: 'boom' });
  assert.equal(f.length, 1);
  assert.equal(f[0].id, 'TLS-CONNECT-FAILED');
  assert.equal(f[0].severity, 'MEDIUM');
});

test('tls: TLSv1 negotiation is HIGH', () => {
  const f = findingsFor(URL, { ok: true, protocol: 'TLSv1', cipher: 'TLS_RSA_WITH_AES_128_CBC_SHA', cert: { validTo: '' } });
  const dep = f.find((x) => x.id === 'TLS-DEPRECATED-PROTOCOL');
  assert.ok(dep);
  assert.equal(dep.severity, 'HIGH');
});

test('tls: TLSv1.3 + strong cipher + future cert → no findings', () => {
  const f = findingsFor(URL, {
    ok: true,
    protocol: 'TLSv1.3',
    cipher: 'TLS_AES_128_GCM_SHA256',
    cert: { validTo: '01 Jan 2031 00:00:00 GMT', sans: [] },
  });
  assert.deepEqual(f, []);
});

test('tls: 3DES cipher is HIGH', () => {
  const f = findingsFor(URL, { ok: true, protocol: 'TLSv1.2', cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', cert: { validTo: '' } });
  const weak = f.find((x) => x.id === 'TLS-WEAK-CIPHER');
  assert.ok(weak);
  assert.equal(weak.severity, 'HIGH');
});

test('tls: expired cert is CRITICAL', () => {
  const f = findingsFor(URL, { ok: true, protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', cert: { validTo: '01 Jan 2001 00:00:00 GMT' } });
  const exp = f.find((x) => x.id === 'TLS-CERT-EXPIRED');
  assert.ok(exp);
  assert.equal(exp.severity, 'CRITICAL');
});

test('WEAK_CIPHER_PATTERNS: matches the canonical weak ciphers', () => {
  for (const s of ['TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_NULL_SHA', 'TLS_RSA_EXPORT_WITH_RC4_40_MD5']) {
    assert.ok(WEAK_CIPHER_PATTERNS.some((re) => re.test(s)), s);
  }
});
