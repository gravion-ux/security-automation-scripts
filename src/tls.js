'use strict';

/**
 * TLS posture checker.
 *
 * Performs a single TLS handshake against the host:port derived from a
 * URL and returns a structured summary:
 *   - protocol version
 *   - cipher name
 *   - certificate fields (subject, issuer, valid_to, SANs)
 *
 * The check is read-only and never sends application data.
 */

const tls = require('node:tls');

const STRONG_PROTOCOLS = new Set(['TLSv1.2', 'TLSv1.3']);
const WEAK_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv3']);
const WEAK_CIPHER_PATTERNS = [/RC4/i, /3DES/i, /NULL/i, /EXPORT/i, /MD5/i];

function inspect(parsedUrl, opts = {}) {
  const { timeoutMs = 5000 } = opts;
  if (parsedUrl.protocol !== 'https:') {
    return Promise.resolve({ ok: false, error: 'TLS inspection skipped (not https).' });
  }
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: parsedUrl.hostname,
      port: Number.parseInt(parsedUrl.port || '443', 10),
      servername: parsedUrl.hostname,
      rejectUnauthorized: false,
      timeout: timeoutMs,
    });
    let done = false;
    function finish(result) {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch {}
      resolve(result);
    }
    socket.on('secureConnect', () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const sans = cert && cert.subjectAltName
          ? cert.subjectAltName.split(',').map((s) => s.trim()).filter((s) => s.startsWith('DNS:')).map((s) => s.slice(4))
          : [];
        finish({
          ok: true,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher() && socket.getCipher().name,
          cert: {
            subject: (cert && cert.subject && (cert.subject.CN || cert.subject.O)) || '',
            issuer: (cert && cert.issuer && (cert.issuer.CN || cert.issuer.O)) || '',
            validTo: (cert && cert.valid_to) || '',
            sans,
          },
        });
      } catch (err) {
        finish({ ok: false, error: `inspection failed: ${err && err.message || err}` });
      }
    });
    socket.on('timeout', () => finish({ ok: false, error: 'TLS timeout' }));
    socket.on('error', (err) => finish({ ok: false, error: `TLS error: ${err && err.message || err}` }));
  });
}

function findingsFor(urlText, result) {
  if (!result.ok) {
    return [{ id: 'TLS-CONNECT-FAILED', severity: 'MEDIUM', category: 'tls',
             evidence: result.error || 'unknown',
             remediation: 'Verify the host is reachable on 443/tcp with a valid certificate.' }];
  }
  const out = [];
  if (!STRONG_PROTOCOLS.has(result.protocol)) {
    if (WEAK_PROTOCOLS.has(result.protocol)) {
      out.push({ id: 'TLS-DEPRECATED-PROTOCOL', severity: 'HIGH', category: 'tls',
        evidence: `Server negotiated ${result.protocol} which is deprecated.`,
        remediation: 'Disable TLS 1.0/1.1 at the server / load balancer.' });
    } else {
      out.push({ id: 'TLS-UNKNOWN-PROTOCOL', severity: 'MEDIUM', category: 'tls',
        evidence: `Unexpected protocol: ${result.protocol}`,
        remediation: 'Verify the server permits only TLS 1.2+.' });
    }
  }
  if (result.cipher && WEAK_CIPHER_PATTERNS.some((re) => re.test(result.cipher))) {
    out.push({ id: 'TLS-WEAK-CIPHER', severity: 'HIGH', category: 'tls',
      evidence: `Weak cipher negotiated: ${result.cipher}`,
      remediation: 'Reorder cipher preferences so AEAD suites are tried first.' });
  }
  if (result.cert && result.cert.validTo) {
    const to = Date.parse(`${result.cert.validTo} GMT`);
    if (Number.isFinite(to)) {
      const days = Math.round((to - Date.now()) / 86_400_000);
      if (days < 0) {
        out.push({ id: 'TLS-CERT-EXPIRED', severity: 'CRITICAL', category: 'tls',
          evidence: `Certificate expired on ${result.cert.validTo}.`,
          remediation: 'Renew the certificate and redeploy.' });
      } else if (days < 14) {
        out.push({ id: 'TLS-CERT-EXPIRY-IMMINENT', severity: 'HIGH', category: 'tls',
          evidence: `Certificate expires in ${days} day(s).`,
          remediation: 'Renew before expiry.' });
      }
    }
  }
  return out;
}

module.exports = { inspect, findingsFor, STRONG_PROTOCOLS, WEAK_PROTOCOLS, WEAK_CIPHER_PATTERNS };
