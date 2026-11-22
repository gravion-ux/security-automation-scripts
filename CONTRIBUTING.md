# Contributing to security-automation-scripts

Thanks for helping! This repo collects small, focused security
automation scripts for reconnaissance, validation and testing —
currently a security-headers checker, a TLS configuration checker and a
log normalizer. Each script is standalone, deterministic and safe to run
against systems you own or are authorized to assess.

## Ground rules

- **Authorized use only.** Scripts that touch a network target are for
  your own systems or engagements with written permission.
- **Zero runtime dependencies.** Node.js standard library only.
- **Read-only by default.** Scripts report; they do not modify the
  target. Anything that would change state on a target does not belong
  here.

## Development setup

Requires Node.js 18 or newer. There is nothing to install.

```bash
git clone https://github.com/gravion-ux/security-automation-scripts.git
cd security-automation-scripts
npm test
```

## Running the tests

```bash
npm test        # headers, tls, log-normalizer and cli suites
npm run demo    # run the bundled demo inputs through the CLI
```

## Adding a script

1. Put the script under `src/`, following the existing structure: pure
   analysis functions separated from the CLI wrapper, so the logic is
   testable without any network.
2. Add tests in `test/` using local fixtures only — tests must never
   require a live external target.
3. Add the script to the README's list with a one-line description and
   an example invocation.

## Pull request workflow

1. Fork and branch from `main`: `feat/<short-name>` or `fix/<short-name>`.
2. Run `npm test` and `npm run demo` locally — both must pass.
3. Open the PR against `main` with: what changed, why, and the fixture
   tests that prove it.
4. CI must be green (Node 18, 20 and 22).
5. One logical change per PR.
