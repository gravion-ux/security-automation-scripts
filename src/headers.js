'use strict';

/**
 * HTTP header analyzer (CLI-friendly).
 *
 * Given an object of response headers (already lowercased keys), returns
 * a list of findings with stable ids, severities, and remediation text.
 *
 * No network calls. The CLI layer in src/cli.js performs the request
 * and passes the response headers in.
 */

const CHECKS = [
  {
    id: 'HSTS-MISSING',
    severity: 'LOW',
    category: 'transport',
    when: (h) => !('strict-transport-security' in h),
    evidence: 'No Strict-Transport-Security header on the response.',
    remediation: 'Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` at the edge.',
  },
  {
    id: 'CSP-MISSING',
    severity: 'MEDIUM',
    category: 'xss-hardening',
    when: (h) => !('content-security-policy' in h),
    evidence: 'No Content-Security-Policy header on the response.',
    remediation: "Adopt a CSP that starts with `default-src 'self'` and lists trusted sources explicitly.",
  },
  {
    id: 'XCTO-MISSING',
    severity: 'LOW',
    category: 'cache-and-content',
    when: (h) => h['x-content-type-options'] !== 'nosniff',
    evidence: 'X-Content-Type-Options is not "nosniff".',
    remediation: 'Send `X-Content-Type-Options: nosniff` on every response.',
  },
  {
    id: 'XFO-MISSING',
    severity: 'MEDIUM',
    category: 'xss-hardening',
    when: (h) => !('x-frame-options' in h) && !/frame-ancestors/i.test(h['content-security-policy'] || ''),
    evidence: 'No clickjacking protection (X-Frame-Options or CSP frame-ancestors).',
    remediation: "Add `X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`.",
  },
  {
    id: 'REFERRER-POLICY-MISSING',
    severity: 'LOW',
    category: 'information-disclosure',
    when: (h) => !('referrer-policy' in h),
    evidence: 'No Referrer-Policy header on the response.',
    remediation: "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
  },
  {
    id: 'SERVER-VERSION-DISCLOSURE',
    severity: 'INFO',
    category: 'information-disclosure',
    when: (h) => h.server && /\d/.test(h.server),
    evidence: (h) => `Server header discloses version: ${h.server}`,
    remediation: 'Strip version tokens from the Server header at the edge.',
  },
  {
    id: 'X-POWERED-BY',
    severity: 'INFO',
    category: 'information-disclosure',
    when: (h) => 'x-powered-by' in h,
    evidence: (h) => `X-Powered-By header present: ${h['x-powered-by']}`,
    remediation: 'Disable the X-Powered-By header at the framework or edge.',
  },
];

function analyze(headers) {
  const findings = [];
  for (const check of CHECKS) {
    let triggered = false;
    try { triggered = !!check.when(headers); } catch { triggered = false; }
    if (!triggered) continue;
    const ev = typeof check.evidence === 'function' ? check.evidence(headers) : check.evidence;
    findings.push({
      id: check.id,
      severity: check.severity,
      category: check.category,
      evidence: ev,
      remediation: check.remediation,
    });
  }
  return findings;
}

module.exports = { analyze, CHECKS };
