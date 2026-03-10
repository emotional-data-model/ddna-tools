# deepadata-ddna-tools

Reference implementation for the .ddna signing specification. Creates and verifies W3C Data Integrity Proofs using Ed25519 signatures with JSON Canonicalization Scheme (JCS).

## Pricing Tiers

### Free (no API key needed)
- `keygen()` — generate Ed25519 key pair
- `verify()` — verify a sealed .ddna envelope
- `inspect()` — read envelope contents
- `redact()` — stateless mode, null sensitive fields
- `validate()` — schema validation against EDM v0.6.0
- `isExpired()` — check artifact TTL (24h default)

### Commercial (API key required)
- `seal()` — create tamper-evident .ddna envelope
  - See https://deepadata.com/pricing for current rates
  - **Get API key:** https://deepadata.com/api-keys

## Installation

```bash
npm install -g deepadata-ddna-tools
```

Or use directly with npx:

```bash
npx deepadata-ddna-tools <command>
```

## Quick Start

```bash
# Generate a key pair (free)
ddna keygen --output mykey

# Validate an EDM artifact (free)
ddna validate artifact.edm.json

# Seal an EDM artifact (requires API key)
export DEEPADATA_API_KEY=your-api-key
ddna seal --key mykey.key --did did:key:z6Mk... artifact.edm.json

# Verify the sealed envelope (free)
ddna verify artifact.ddna

# Inspect envelope details (free)
ddna inspect artifact.ddna

# Redact for stateless mode (free)
ddna redact artifact.edm.json -o redacted.json

# Check TTL expiry (free)
ddna check-ttl artifact.edm.json
```

## Free Commands

### `ddna keygen`

Generate an Ed25519 key pair with DID identifier.

```bash
ddna keygen [options]
```

**Options:**
- `-o, --output <prefix>` - Output file prefix (creates `<prefix>.key` and `<prefix>.pub`)
- `--json` - Output as JSON to stdout

### `ddna verify`

Verify the signature on a `.ddna` envelope.

```bash
ddna verify [options] <input>
```

**Options:**
- `--skip-timestamp` - Skip timestamp validation

### `ddna inspect`

Inspect a `.ddna` envelope and display its contents.

```bash
ddna inspect [options] <input>
```

**Options:**
- `--json` - Output as JSON

### `ddna validate`

Validate an EDM artifact against the v0.6.0 schema.

```bash
ddna validate [options] <input>
```

**Options:**
- `--json` - Output as JSON

**Example:**
```bash
ddna validate artifact.edm.json
# VALID - Schema validation passed
#   Schema Version: 0.6.0
```

### `ddna redact`

Redact sensitive fields for stateless mode. Nulls:
- Gravity: recall_triggers, retrieval_keys, nearby_themes
- Milky_Way: location_context, associated_people
- Meta: owner_user_id, source_context

```bash
ddna redact [options] <input>
```

**Options:**
- `-o, --output <path>` - Output path (default: stdout)
- `--json` - Output with statistics

### `ddna check-ttl`

Check if artifact has expired based on created_at timestamp.

```bash
ddna check-ttl [options] <input>
```

**Options:**
- `--ttl <hours>` - Custom TTL in hours (default: 24)
- `--json` - Output as JSON

**Example:**
```bash
ddna check-ttl artifact.edm.json
# VALID - Artifact is within TTL
#   Created: 2026-03-07T10:00:00.000Z
#   Age: 2.5 hours
#   TTL: 24 hours
#   Remaining: 21.5 hours
```

## Commercial Commands

### `ddna seal`

Seal an EDM artifact into a `.ddna` envelope with a cryptographic signature.

**Requires:** DeepaData API key (see https://deepadata.com/pricing)

```bash
ddna seal [options] <input>
```

**Arguments:**
- `<input>` - Path to EDM artifact (`.edm.json` or `.json`)

**Options:**
- `-k, --key <path>` - Path to private key file (hex-encoded) **[required]**
- `-d, --did <url>` - DID URL for verification method **[required]**
- `-a, --api-key <key>` - DeepaData API key (or set `DEEPADATA_API_KEY` env var)
- `-o, --output <path>` - Output path (default: `<input>.ddna`)
- `--jurisdiction <code>` - Override jurisdiction code (e.g., AU, US)
- `--expires <iso8601>` - Proof expiration timestamp

**Example:**
```bash
export DEEPADATA_API_KEY=dda_live_xxxxx
ddna seal --key mykey.key --did did:key:z6MkiTBz1... artifact.edm.json
```

## Library Usage

```typescript
import {
  // Free functions
  keygen,
  verify,
  inspect,
  validate,
  redact,
  isExpired,
  hexToKey,
  keyToHex,
  // Commercial (requires API key)
  seal,
} from 'deepadata-ddna-tools';

// Generate keys (free)
const keys = keygen();
console.log('DID:', keys.did);

// Validate against schema (free)
const validation = validate(edmPayload);
if (!validation.valid) {
  console.error('Validation errors:', validation.errors);
}

// Redact for stateless mode (free)
const { artifact: redacted, fieldsRedacted } = redact(edmPayload);
console.log(`Redacted ${fieldsRedacted} fields`);

// Check TTL (free)
const ttl = isExpired(edmPayload, 24);
if (ttl.expired) {
  console.log('Artifact expired');
}

// Seal an EDM artifact (requires API key)
const envelope = await seal(edmPayload, keys.privateKey, keys.did, {
  apiKey: process.env.DEEPADATA_API_KEY, // or set env var
});

// Verify the envelope (free)
const result = await verify(envelope);
console.log('Valid:', result.valid);
```

## EDM Conformance Levels

| Level | Name | What it means | DeepaData involvement |
|-------|------|---------------|----------------------|
| Level 1 | Compliant | Valid EDM schema | None (open source tools) |
| Level 2 | Sealed | Cryptographically signed .ddna | API key required |
| Level 3 | Certified | Third-party audit + attestation | Commercial agreement |

## Specification

This implementation follows the [DDNA Signing Model Specification](https://github.com/emotional-data-model/edm-spec/blob/main/docs/DDNA_SIGNING_MODEL.md).

**Key standards:**
- [W3C Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
- [RFC 8785 JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/rfc8785/)
- [RFC 8032 Ed25519 Signatures](https://datatracker.ietf.org/doc/rfc8032/)
- [did:key Method](https://w3c-ccg.github.io/did-method-key/)

## Envelope Structure

A `.ddna` envelope contains three components:

```json
{
  "ddna_header": {
    "ddna_version": "1.1",
    "created_at": "2026-01-15T10:00:00Z",
    "edm_version": "0.6.0",
    "jurisdiction": "AU",
    "exportability": "allowed"
  },
  "edm_payload": {
    "meta": { ... },
    "core": { ... }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6Mk...",
    "proofPurpose": "assertionMethod",
    "proofValue": "z..."
  }
}
```

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev -- keygen

# Build
npm run build

# Run tests
npm test
```

## License

MIT
