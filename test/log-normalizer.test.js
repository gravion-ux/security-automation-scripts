'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { normalize, normalizeLine } = require('../src/log-normalizer');

test('log: nginx access line is parsed', () => {
  const line = '127.0.0.1 - - [10/Oct/2025:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "curl/7.79.1"';
  const r = normalizeLine(line);
  assert.equal(r.source, 'nginx');
  assert.equal(r.method, 'GET');
  assert.equal(r.path, '/index.html');
  assert.equal(r.status, 200);
  assert.equal(r.bytes, 2326);
  assert.equal(r.client_ip, '127.0.0.1');
});

test('log: nginx with missing bytes is null', () => {
  const line = '10.0.0.1 - - [10/Oct/2025:13:55:36 +0000] "GET / HTTP/1.1" 200 -';
  const r = normalizeLine(line);
  assert.equal(r.source, 'nginx');
  assert.equal(r.bytes, null);
});

test('log: syslog line is parsed', () => {
  const line = '<134>Oct 11 22:14:15 hostname sshd[1234]: Accepted publickey for priyanshu';
  const r = normalizeLine(line);
  assert.equal(r.source, 'syslog');
  assert.equal(r.priority, 134);
  assert.equal(r.host, 'hostname');
  assert.equal(r.process, 'sshd[1234]');
  assert.match(r.message, /Accepted publickey/);
});

test('log: JSON line is parsed', () => {
  const line = '{"ts":"2025-10-10T00:00:00Z","event":"login","user":"alice"}';
  const r = normalizeLine(line);
  assert.equal(r.source, 'json');
  assert.equal(r.event, 'login');
  assert.equal(r.user, 'alice');
});

test('log: unknown line falls back to generic', () => {
  const r = normalizeLine('hello world');
  assert.equal(r.source, 'generic');
  assert.equal(r.line, 'hello world');
});

test('log: normalize handles a multi-line blob', () => {
  const text = [
    '127.0.0.1 - - [10/Oct/2025:13:55:36 +0000] "GET /a HTTP/1.1" 200 100',
    '<134>Oct 11 22:14:15 h sshd: ok',
    '{"k":"v"}',
    'unknown line',
  ].join('\n');
  const rs = normalize(text);
  assert.equal(rs.length, 4);
  assert.equal(rs[0].source, 'nginx');
  assert.equal(rs[1].source, 'syslog');
  assert.equal(rs[2].source, 'json');
  assert.equal(rs[3].source, 'generic');
});

test('log: empty / non-string inputs are handled', () => {
  assert.deepEqual(normalize(''), []);
  assert.equal(normalizeLine(null), null);
  assert.equal(normalizeLine(undefined), null);
  assert.equal(normalizeLine(''), null);
});
