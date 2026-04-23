# Security Policy

## Reporting

Report security vulnerabilities to security@deepadata.com.

## Known Issues

### Dev-time vulnerabilities (vitest dependency chain)

Two moderate-severity advisories affect transitive dependencies
of vitest (our test runner):

- esbuild GHSA-67mh-4wv8-2f99 (dev server origin validation)
- vite GHSA-4w7w-66w2-5vf9 (dev server path traversal)

**Scope:** Both vulnerabilities affect local dev-server mode
only. They do not affect:
- The published npm package (built dist/ only)
- The ddna CLI in any usage
- Production extraction, sealing, or verification operations
- CI environments running tests in non-public networks

**Fix path:** Resolution requires upgrading vitest from 2.x
to 4.x, a semver-major change with breaking API differences.
This is tracked as a planned upgrade rather than an
emergency fix.

**Last reviewed:** 2026-04-23
