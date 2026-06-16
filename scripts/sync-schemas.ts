#!/usr/bin/env tsx
/**
 * Sync bundled schemas from the published `edm-spec` npm package.
 *
 * Usage:
 *   tsx scripts/sync-schemas.ts           # write into schemas/
 *   tsx scripts/sync-schemas.ts <outDir>  # write into <outDir> (CI check)
 *
 * Resolves the installed `edm-spec` package (a regular dependency pinned in
 * package.json / package-lock.json), then copies schema/edm.v0.8.*.schema.json
 * and schema/fragments/*.json out of node_modules into the destination.
 * Exits non-zero on any failure.
 *
 * Enforces directionality: bundled schemas are a read-only mirror of the
 * canonical edm-spec release. The npm version pin replaces the former git-SHA
 * pin; .edm-spec-version records the synced version for traceability.
 * See planning/SCHEMA_SYNC_PROCESS_2026-04-24.md in deepadata-com.
 */
import { createRequire } from 'node:module';
import { cpSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// ddna-tools bundles only the current EDM major.minor schema. Bump this
// when the package targets a new EDM version. Fragments are always copied in full.
const ROOT_SCHEMA_PREFIX = 'edm.v0.8.';
const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const PIN_FILE = join(ROOT, 'schemas', '.edm-spec-version');
const DEFAULT_OUT = join(ROOT, 'schemas');

const require = createRequire(import.meta.url);

/** Resolve the installed edm-spec package's schema/ directory. */
function resolveEdmSpecSchemaDir(): { schemaDir: string; version: string } {
  const pkgPath = require.resolve('edm-spec/package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as { version: string };
  return { schemaDir: join(dirname(pkgPath), 'schema'), version: pkg.version };
}

function writePin(version: string): void {
  const body = [
    version,
    '# edm-spec pin — npm version of the published emotional-data-model/edm-spec',
    '# package used to populate schemas/ and schemas/fragments/. The authoritative',
    '# pin is the version range in package.json (resolved in package-lock.json);',
    '# this file records the version last synced via scripts/sync-schemas.ts.',
    '',
  ].join('\n');
  writeFileSync(PIN_FILE, body);
}

function main(): void {
  const outDir = process.argv[2] ? resolve(process.argv[2]) : DEFAULT_OUT;
  const { schemaDir, version } = resolveEdmSpecSchemaDir();

  mkdirSync(outDir, { recursive: true });
  mkdirSync(join(outDir, 'fragments'), { recursive: true });

  for (const f of readdirSync(schemaDir)) {
    if (f.startsWith(ROOT_SCHEMA_PREFIX) && f.endsWith('.schema.json')) {
      cpSync(join(schemaDir, f), join(outDir, f));
    }
  }
  const srcFragments = join(schemaDir, 'fragments');
  for (const f of readdirSync(srcFragments)) {
    if (f.endsWith('.json')) {
      cpSync(join(srcFragments, f), join(outDir, 'fragments', f));
    }
  }

  // Record the synced version only on a real sync into schemas/, not the CI
  // temp-dir drift check (which diffs against the committed bundle and excludes
  // .edm-spec-version).
  if (outDir === DEFAULT_OUT) {
    writePin(version);
  }

  console.log(`Synced edm-spec@${version} → ${outDir}`);
}

main();
