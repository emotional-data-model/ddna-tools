/**
 * Single source of truth for the EDM schema version this tool consumes.
 *
 * Everything derives from the installed `edm-spec` package (ADR-0030: the
 * published spec is canonical; ddna-tools consumes it like any other user
 * of the open code). Bumping the dependency updates every stamp, banner,
 * and validator label — no literal EDM version strings belong anywhere
 * else in runtime code.
 *
 * Enum vocabularies are NOT restated here either: src/lib/validate.ts
 * derives them from the bundled schema fragments, which are themselves a
 * sync mirror of the installed spec (scripts/sync-schemas.ts).
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const specPkg = require('edm-spec/package.json') as { version?: string };
const version = specPkg.version;

if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) {
  throw new Error(
    `edm-spec package version missing or malformed: ${JSON.stringify(version)}`
  );
}

/** The EDM schema version, e.g. "0.8.3". Stamped into artifact meta.version. */
export const EDM_VERSION: string = version as string;

const [major, minor] = EDM_VERSION.split('.');

/** The version line, e.g. "0.8". */
export const EDM_VERSION_LINE = `${major}.${minor}`;

/**
 * The version segment used in schema $id URLs, bundled schema filenames,
 * and /schemas/edm/ paths. The edm-spec convention pins these at the
 * patch-zero of the line (e.g. "v0.8.0" while the spec is at 0.8.3).
 */
export const EDM_SCHEMA_URL_VERSION = `v${EDM_VERSION_LINE}.0`;

/** Human label, e.g. "v0.8.3". */
export const EDM_VERSION_LABEL = `v${EDM_VERSION}`;
