'use strict';

/**
 * Log normalizer.
 *
 * Takes a line-oriented log stream and emits a normalized JSON record
 * per line. The supported input shapes are intentionally narrow — this
 * is meant to live in front of a SIEM, not to replace a real parser.
 *
 * Supported shapes (auto-detected per line):
 *   - nginx access:    <ip> - - [<ts>] "<method> <path> HTTP/1.1" <status> <bytes> ...
 *   - apache access:   same as nginx
 *   - syslog:          <pri> <ts> <host> <process>: <message>
 *   - json:            one JSON object per line
 *   - generic:         falls back to { line } for unknown lines
 *
 * No external dependencies. No I/O — the normalizer is a pure function
 * that takes a string and returns a record.
 */

function parseNginxLine(line) {
  // 127.0.0.1 - - [10/Oct/2025:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326
  const m = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d{3})\s+(\d+|-)/.exec(line);
  if (!m) return null;
  return {
    source: 'nginx',
    ts: m[2],
    client_ip: m[1],
    method: m[3],
    path: m[4],
    protocol: m[5],
    status: Number.parseInt(m[6], 10),
    bytes: m[7] === '-' ? null : Number.parseInt(m[7], 10),
    raw: line,
  };
}

function parseSyslogLine(line) {
  // <134>Oct 11 22:14:15 hostname app[123]: message
  const m = /^<(\d+)>([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$/.exec(line);
  if (!m) return null;
  return {
    source: 'syslog',
    priority: Number.parseInt(m[1], 10),
    ts: m[2],
    host: m[3],
    process: m[4],
    message: m[5],
    raw: line,
  };
}

function parseJsonLine(line) {
  try {
    const j = JSON.parse(line);
    if (j && typeof j === 'object') return { source: 'json', ...j, raw: line };
  } catch {}
  return null;
}

const PARSERS = [parseJsonLine, parseNginxLine, parseSyslogLine];

function normalizeLine(line) {
  if (typeof line !== 'string') return null;
  if (line.length === 0) return null;
  for (const p of PARSERS) {
    const r = p(line);
    if (r) return r;
  }
  return { source: 'generic', line, raw: line };
}

function normalize(text) {
  if (typeof text !== 'string') return [];
  return text.split(/\r?\n/).map(normalizeLine).filter(Boolean);
}

module.exports = { normalize, normalizeLine, parseNginxLine, parseSyslogLine, parseJsonLine };
