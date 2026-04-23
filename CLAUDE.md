# ddna-tools

CLI and library for extracting, sealing, verifying, and inspecting EDM artifacts as .ddna envelopes.

**Last session:** 2026-04-23 — v0.3.0 published to npm (ADR-0023 open extraction migration)

## What This Repo Is

- **Current version:** v0.3.0
- **License:** MIT (open source)
- **npm:** `ddna-tools`
- **Remote:** github.com/emotional-data-model/ddna-tools

The reference implementation for the complete EDM artifact pipeline:

1. **Extract** — Transform text into structured EDM artifacts using LLM (BYOK: Anthropic, OpenAI, Kimi)
2. **Validate** — Check artifact against bundled v0.8.0 schema
3. **Seal** — Create cryptographically signed .ddna envelope (Ed25519, JCS, W3C Data Integrity)
4. **Verify** — Validate envelope signature offline
5. **Inspect** — Display envelope contents

Canonical profiles only (essential/extended/full). Partner profiles (`partner:` prefix) are registry-gated at deepadata.com per spec §3.7.6 and not implemented here by design — see ADR-0023.

## Role in the DeepaData System

```
raw text + LLM API key
    ↓
ddna extract (LLM extraction + domain assembly)
    ↓
.edm.json artifact
    ↓
ddna validate (schema check against bundled v0.8.0)
    ↓
ddna seal (Ed25519 local signing)
    ↓
.ddna envelope
    ↓
ddna verify (offline signature check)
```

Self-sealing via ddna-tools is free and requires no API key.
DeepaData-issued seals (via /api/v1/issue) add a registry entry: discoverable, revocable, verifiable by third parties.

## CLI Commands

| Command | Description |
|---------|-------------|
| `ddna extract` | Extract EDM artifact from text using LLM (BYOK: requires API key) |
| `ddna validate` | Validate EDM artifact against v0.8.0 schema |
| `ddna seal` | Seal artifact into .ddna envelope (local Ed25519 signing) |
| `ddna verify` | Verify .ddna envelope signature |
| `ddna inspect` | Display envelope contents (human/JSON) |
| `ddna keygen` | Generate Ed25519 key pair with DID identifier |
| `ddna redact` | Redact sensitive fields for stateless mode |
| `ddna check-ttl` | Check if artifact has expired (default 24h TTL) |

## Library API

**Sealing & Verification:**
- `seal()`, `sealSync()` — create .ddna envelope
- `verify()`, `verifySync()` — verify envelope signature
- `inspect()`, `inspectJson()` — read envelope contents
- `keygen()` — generate Ed25519 key pair
- `validate()`, `isValid()` — schema validation
- `validateEdmSchema()`, `validateEdmSchemaSync()` — profile-aware validation
- `redact()` — stateless mode
- `isExpired()` — TTL check

**Extraction (v0.3.0):**
- `extractWithLlm()`, `createAnthropicClient()` — Anthropic Claude
- `extractWithOpenAI()`, `createOpenAIClient()` — OpenAI GPT
- `extractWithKimi()`, `createKimiClient()` — Kimi K2

**Domain Factories:**
- `createMeta()`, `createGovernance()`, `createTelemetry()`, `createSystem()`, `createCrosswalks()`

**Assembler:**
- `assembleProfileArtifact()` — assemble complete EDM artifact from extracted fields

## Hard Constraints

| Constraint | Reason |
|---|---|
| Do not implement partner profile extraction | Partner profiles are registry-gated per spec §3.7.6; canonical profiles only in OSS |
| Do not modify bundled schemas without upstream change | Bundled schemas in schemas/ are copies of canonical edm-spec; sync required |

If asked to add partner profile support, stop and reference ADR-0017 and spec §3.7.6.

## Schema Synchronisation

Bundled schemas in `schemas/` are a read-only mirror of canonical `emotional-data-model/edm-spec` at the SHA pinned in `schemas/.edm-spec-version`. Per session 2026-04-23, a local schema fork was flagged and reverted; the rule is now enforced mechanically.

**Updating bundled schemas:**
1. Land the change upstream in edm-spec.
2. Bump the SHA in `schemas/.edm-spec-version`.
3. Run `npx tsx scripts/sync-schemas.ts`.
4. Commit the resulting diff.

**Drift enforcement:**
CI workflow `.github/workflows/schema-sync-check.yml` runs on every pull request and push to main. It re-runs `scripts/sync-schemas.ts` into a temp dir and diffs against bundled. A non-empty diff fails the job — PRs cannot merge with drifted schemas.

**Filter:** `sync-schemas.ts` copies root schemas matching `edm.v0.8.*` plus all fragments. Bump `ROOT_SCHEMA_PREFIX` in the script when the package targets a new EDM major.minor.

Enum values are derived from bundled schemas at module init (`src/lib/validate.ts:45-105`, commit `b1cfefa`). The sync feeds those schemas; it does not replace the derivation pattern.

Design: `deepadata-com/planning/SCHEMA_SYNC_PROCESS_2026-04-24.md`. edm-sdk Zod synchronisation is deferred per that document §5 pending generator evaluation.

## Standards Implemented

- W3C Data Integrity 1.0 (eddsa-jcs-2022 cryptosuite)
- RFC 8785 JSON Canonicalization Scheme
- RFC 8032 Ed25519 signatures
- did:key method for verification

## Source of Truth

→ **See `deepadata-com/planning/CLAUDE_PROJECT.md`**

The platform repo (deepadata-com) is the source of truth for session state, version alignment, and task tracking.
