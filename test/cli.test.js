'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const CLI = path.join(__dirname, '..', 'src', 'cli.js');

function run(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8', timeout: 10_000, ...opts,
  });
}

test('CLI: --help lists commands', () => {
  const r = run(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /sec-auto/);
  assert.match(r.stdout, /headers/);
  assert.match(r.stdout, /tls/);
  assert.match(r.stdout, /log/);
});

test('CLI: unknown command exits 2', () => {
  const r = run(['banana']);
  assert.equal(r.status, 2);
});

test('CLI: headers without --url exits 2', () => {
  const r = run(['headers']);
  assert.equal(r.status, 2);
});

test('CLI: demo runs end-to-end and emits findings', () => {
  const r = run(['demo']);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  const j = JSON.parse(r.stdout);
  assert.ok(Array.isArray(j.findings));
  assert.ok(j.findings.length > 0);
});

test('CLI: log --in normalizes a sample file', () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const sample = path.join(os.tmpdir(), `sec-auto-test-${Date.now()}.log`);
  fs.writeFileSync(sample, '127.0.0.1 - - [10/Oct/2025:13:55:36 +0000] "GET /a HTTP/1.1" 200 100\n');
  const r = run(['log', '--in', sample]);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  const lines = r.stdout.split('\n').filter(Boolean);
  assert.equal(lines.length, 1);
  const j = JSON.parse(lines[0]);
  assert.equal(j.source, 'nginx');
  assert.equal(j.status, 200);
  fs.unlinkSync(sample);
});
