# ddna-tools

CLI for sealing, verifying, and inspecting .ddna envelopes.

## What This Repo Is

The open-source command-line toolkit for working with .ddna
envelopes — the signed artifact format that wraps EDM data.
Self-sealing is free. This repo enables local cryptographic
operations without touching the DeepaData platform.

- **Current version:** v0.2.0
- **License:** MIT (open source)
- **npm:** `ddna-tools`
- **Remote:** github.com/emotional-data-model/ddna-tools

## Role in the DeepaData System

```
   edm-sdk (produces EDM artifacts)
       ↓
→ ddna-tools (seal, verify, inspect) ← YOU ARE HERE
       ↓ self-sealed envelopes or
   deepadata-com (CA-issued seals with registry entry)
```

Self-sealing via ddna-tools is free and requires no API key.
DeepaData-issued seals (via /api/v1/issue) add a registry
entry: discoverable, revocable, verifiable by third parties.

## CLI Commands

- `ddna seal` — Seal EDM artifact into signed .ddna envelope
- `ddna verify` — Validate envelope signature using did:key
- `ddna inspect` — Display envelope contents (human/JSON)
- `ddna keygen` — Generate Ed25519 key pairs with DID identifiers

## Library API

- `seal()`, `verify()`, `inspect()`, `keygen()`
- `hexToKey()`, `keyToHex()` — key format conversion

## Standards Implemented

- W3C Data Integrity 1.0 (eddsa-jcs-2022 cryptosuite)
- RFC 8785 JSON Canonicalization Scheme
- RFC 8032 Ed25519 signatures
- did:key method for verification

## OSS Boundary

This repo is MIT licensed. It implements the signing mechanics
but does NOT write to any registry. Registry writes require
the DeepaData platform API.

## Source of Truth

→ **See `deepadata-com/planning/CLAUDE_PROJECT.md`**
