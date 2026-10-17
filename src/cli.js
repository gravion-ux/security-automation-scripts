#!/usr/bin/env node
'use strict';

/**
 * sec-auto CLI.
 *
 *   sec-auto demo                                 # exercises every tool on a local mock
 *   sec-auto headers --url <authorized-url>       # header check
 *   sec-auto tls     --url <authorized-url>       # TLS posture check
 *   sec-auto log     --in <log-file>              # normalize a log file to JSONL
 *
 * All operations are read-only.
 */

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { analyze } = require('./headers');
const { inspect, findingsFor } = require('./tls');
const { normalize } = require('./log-normalizer');

const HELP = `sec-auto — small security automation utilities

Usage:
  sec-auto demo
  sec-auto headers --url <authorized-url>
  sec-auto tls --url <authorized-url>
  sec-auto log --in <file> [--out <file>]
  sec-auto --help

Notes:
  All probes are read-only.
`;

async function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    process.stdout.write(HELP);
    return 0;
  }
  const cmd = args[0];
  if (cmd === 'demo') return runDemo();
  if (cmd === 'headers') return runHeaders(args.slice(1));
  if (cmd === 'tls') return runTls(args.slice(1));
  if (cmd === 'log') return runLog(args.slice(1));
  process.stderr.write(`Unknown command: ${cmd}\n`);
  return 2;
}

function parseFlag(args, name) {
  const i = args.indexOf(`--${name}`);
  if (i < 0) return null;
  return args[i + 1];
}

function getRaw(urlText) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlText); } catch (e) { return reject(new Error(`bad URL: ${urlText}`)); }
    const transport = u.protocol === 'https:' ? require('node:https') : http;
    const req = transport.request({
      method: 'GET',
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search,
      headers: { 'user-agent': 'sec-auto/1.0' },
      timeout: 8000,
    }, (res) => {
      const headers = {};
      for (const [k, v] of Object.entries(res.headers)) headers[k.toLowerCase()] = v;
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, headers }));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.end();
  });
}

async function runHeaders(args) {
  const url = parseFlag(args, 'url');
  if (!url) { process.stderr.write('--url is required\n'); return 2; }
  const r = await getRaw(url);
  const findings = analyze(r.headers);
  process.stdout.write(JSON.stringify({ url, status: r.status, findings }, null, 2));
  return 0;
}

async function runTls(args) {
  const url = parseFlag(args, 'url');
  if (!url) { process.stderr.write('--url is required\n'); return 2; }
  const u = new URL(url);
  const r = await inspect(u);
  const findings = findingsFor(url, r);
  process.stdout.write(JSON.stringify({ url, tls: r, findings }, null, 2));
  return 0;
}

async function runLog(args) {
  const inFile = parseFlag(args, 'in');
  const outFile = parseFlag(args, 'out');
  if (!inFile) { process.stderr.write('--in is required\n'); return 2; }
  const text = fs.readFileSync(inFile, 'utf-8');
  const records = normalize(text);
  const out = records.map((r) => JSON.stringify(r)).join('\n');
  if (outFile) fs.writeFileSync(outFile, out + '\n');
  else process.stdout.write(out + '\n');
  return 0;
}

async function runDemo() {
  // tiny local mock that returns an insecure response
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', 'server': 'Demo/1.0' });
    res.end('hi');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const url = `http://127.0.0.1:${port}/`;
  const r = await getRaw(url);
  const findings = analyze(r.headers);
  process.stdout.write(JSON.stringify({ url, status: r.status, findings }, null, 2));
  server.close();
  return 0;
}

main(process.argv).then((c) => process.exit(typeof c === 'number' ? c : 0))
  .catch((err) => { process.stderr.write(`fatal: ${err && err.message ? err.message : err}\n`); process.exit(1); });
