# security-automation-scripts

A small, dependency-light toolkit of security automation utilities. Each
module is self-contained, can be imported individually, and is covered
by an automated test suite.

> **Scope statement.** Every script in this repository is read-only.
> None of them send payloads, mutate server state, or perform scans
> beyond the target URL the operator explicitly passes in.

## What's here

| path | purpose |
| --- | --- |
| `src/headers.js`      | HTTP response header analyzer |
| `src/tls.js`          | TLS posture checker (protocol, cipher, cert) |
| `src/log-normalizer.js` | nginx / syslog / JSON line → JSON record |
| `src/cli.js`          | `sec-auto` command-line entry |
| `test/*.test.js`      | automated coverage for every module |

## Quick start

```bash
npm test                 # run the test suite
node src/cli.js demo     # exercise every tool on a local mock server
node src/cli.js headers --url https://your-staging.example.com
node src/cli.js tls     --url https://your-staging.example.com
node src/cli.js log     --in /var/log/nginx/access.log --out normalized.jsonl
```

## Design choices

- **No external dependencies.** Everything is implemented in
  Node.js standard library.
- **Read-only.** No script writes to the network beyond a single `GET`
  for the header check, a TLS handshake for the TLS check, and local
  file I/O for the log normalizer.
- **Stable, evidence-led findings.** Every finding has a stable id,
  severity, evidence, and remediation. The same input always produces
  the same output.
- **JSON in / JSON out.** Every tool produces a JSON-serializable
  result that's easy to feed into a CI check or a SIEM.

## Security considerations

- The TLS check inspects the metadata Node.js exposes from a
  handshake. It does not benchmark PFS, session resumption, or
  negotiated curves.
- The header check is posture-only. It does not model the business
  impact of any specific missing header on a given application.
- The log normalizer is a coarse first pass. A real parser (e.g. for
  ELB, CloudFront, or a custom application log format) should replace
  it where the format matters.

## License

MIT — see [`LICENSE`](./LICENSE).
