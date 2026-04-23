#!/usr/bin/env tsx
/**
 * Sync bundled schemas from canonical edm-spec at the pinned SHA.
 *
 * Usage:
 *   tsx scripts/sync-schemas.ts           # write into schemas/
 *   tsx scripts/sync-schemas.ts <outDir>  # write into <outDir> (CI check)
 *
 * Reads schemas/.edm-spec-version for the pinned SHA. Clones edm-spec,
 * checks out the pin, copies schema/*.schema.json and schema/fragments/*.json
 * into the destination. Exits non-zero on any failure.
 *
 * Enforces directionality: bundled schemas are a read-only mirror of canonical.
 * See planning/SCHEMA_SYNC_PROCESS_2026-04-24.md in deepadata-com.
 */
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = 'https://github.com/emotional-data-model/edm-spec.git';
// ddna-tools bundles only the current EDM major.minor schema. Bump this
// when the package targets a new EDM version. Fragments are always copied in full.
const ROOT_SCHEMA_PREFIX = 'edm.v0.8.';
const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');
const PIN_FILE = join(ROOT, 'schemas', '.edm-spec-version');
const DEFAULT_OUT = join(ROOT, 'schemas');

function readPin(): string {
  const raw = readFileSync(PIN_FILE, 'utf-8');
  const sha = raw.split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('#'));
  if (!sha) throw new Error(`No SHA found in ${PIN_FILE}`);
  return sha;
}

function main(): void {
  const outDir = process.argv[2] ? resolve(process.argv[2]) : DEFAULT_OUT;
  const sha = readPin();
  const tmp = mkdtempSync(join(tmpdir(), 'edm-spec-sync-'));
  try {
    // core.autocrlf=false preserves canonical LF line endings on Windows clones.
    execFileSync('git', ['-c', 'core.autocrlf=false', 'clone', '--quiet', REPO, tmp], { stdio: 'inherit' });
    execFileSync('git', ['-C', tmp, '-c', 'core.autocrlf=false', 'checkout', '--quiet', sha], { stdio: 'inherit' });

    const srcSchema = join(tmp, 'schema');
    mkdirSync(outDir, { recursive: true });
    mkdirSync(join(outDir, 'fragments'), { recursive: true });

    for (const f of readdirSync(srcSchema)) {
      if (f.startsWith(ROOT_SCHEMA_PREFIX) && f.endsWith('.schema.json')) {
        cpSync(join(srcSchema, f), join(outDir, f));
      }
    }
    const srcFragments = join(srcSchema, 'fragments');
    for (const f of readdirSync(srcFragments)) {
      if (f.endsWith('.json')) {
        cpSync(join(srcFragments, f), join(outDir, 'fragments', f));
      }
    }
    console.log(`Synced edm-spec@${sha.slice(0, 7)} → ${outDir}`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

main();
