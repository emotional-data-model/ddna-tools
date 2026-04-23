# ddna-tools

Reference implementation for .ddna envelope specification — extraction, sealing, and verification.

An EDM artifact encodes what mattered at capture time. This package provides the complete OSS pipeline:

1. **Extract** — Transform emotionally rich text into structured EDM artifacts using LLM extraction
2. **Seal** — Create cryptographically verifiable .ddna envelopes (Ed25519, JCS, W3C Data Integrity Proofs)
3. **Verify** — Validate signatures and inspect envelope contents

## Why use ddna-tools?

- **Extract** with your own LLM API key (Anthropic, OpenAI, or Kimi)
- **Seal** artifacts locally with your own signing keys — no API required
- **Verify** any .ddna envelope offline — portable trust across platforms

Canonical profiles only (essential/extended/full). Partner profiles require DeepaData API per EDM spec §3.7.6.

## Installation

```bash
npm install -g ddna-tools
```

Or use directly with npx:

```bash
npx ddna-tools <command>
```

## Quick Start

```bash
# Extract from text (requires ANTHROPIC_API_KEY env var)
echo "I remember dad's workshop, the smell of sawdust..." | ddna extract - -o memory.edm.json

# Or use OpenAI/Kimi
ddna extract journal.txt --provider openai -o memory.edm.json

# Generate a key pair
ddna keygen --output mykey

# Validate against EDM v0.8.0 schema
ddna validate memory.edm.json

# Seal the artifact (local signing)
ddna seal --key mykey.key --did did:key:z6Mk... memory.edm.json

# Verify the sealed envelope
ddna verify memory.ddna

# Inspect envelope details
ddna inspect memory.ddna

# Redact for stateless mode
ddna redact memory.edm.json -o redacted.json

# Check TTL expiry
ddna check-ttl memory.edm.json
```

## Commands

### `ddna extract`

Extract EDM artifact from text using LLM (BYOK: Bring Your Own Key).

```bash
ddna extract [options] <input>
```

**Arguments:**
- `<input>` - Path to text file or `-` for stdin

**Options:**
- `-p, --provider <provider>` - LLM provider: anthropic, openai, kimi (default: anthropic)
- `-m, --model <model>` - Model to use (provider-specific default if omitted)
- `--profile <profile>` - EDM profile: essential, extended, full (default: full)
- `-o, --output <path>` - Output path (default: stdout)
- `--json` - Output full result with confidence (default: just extracted fields)

**Environment Variables:**
- `ANTHROPIC_API_KEY` - Required for Anthropic provider
- `OPENAI_API_KEY` - Required for OpenAI provider
- `MOONSHOT_API_KEY` or `KIMI_API_KEY` - Required for Kimi provider
- `OPENROUTER_API_KEY` - Alternative for Kimi via OpenRouter

**Example:**
```bash
# Extract with Anthropic Claude (default)
export ANTHROPIC_API_KEY=sk-ant-...
ddna extract journal.txt -o memory.edm.json

# Extract with OpenAI GPT-4
export OPENAI_API_KEY=sk-...
ddna extract journal.txt --provider openai -o memory.edm.json

# Extract essential profile only (faster, cheaper)
ddna extract journal.txt --profile essential -o memory.edm.json

# Pipe from stdin
cat notes.txt | ddna extract - --json
```

### `ddna keygen`

Generate an Ed25519 key pair with DID identifier.

```bash
ddna keygen [options]
```

**Options:**
- `-o, --output <prefix>` - Output file prefix (creates `<prefix>.key` and `<prefix>.pub`)
- `--json` - Output as JSON to stdout

### `ddna seal`

Seal an EDM artifact into a `.ddna` envelope with a cryptographic signature.

```bash
ddna seal [options] <input>
```

**Arguments:**
- `<input>` - Path to EDM artifact (`.edm.json` or `.json`)

**Options:**
- `-k, --key <path>` - Path to private key file (hex-encoded) **[required]**
- `-d, --did <url>` - DID URL for verification method **[required]**
- `-o, --output <path>` - Output path (default: `<input>.ddna`)
- `--jurisdiction <code>` - Override jurisdiction code (e.g., GDPR, CCPA)
- `--expires <iso8601>` - Proof expiration timestamp
- `--domain <domain>` - Domain restriction for proof
- `--challenge <value>` - Challenge value for proof
- `--nonce <value>` - Nonce for replay prevention

**Example:**
```bash
ddna seal --key mykey.key --did did:key:z6MkiTBz1... artifact.edm.json
```

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

Validate an EDM artifact against the v0.7.0 schema.

```bash
ddna validate [options] <input>
```

**Options:**
- `--json` - Output as JSON

**Example:**
```bash
ddna validate artifact.edm.json
# VALID - Schema validation passed
#   Schema Version: 0.7.0
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

## Library Usage

### Extraction

```typescript
import {
  extractWithLlm,
  createAnthropicClient,
  extractWithOpenAI,
  createOpenAIClient,
  extractWithKimi,
  createKimiClient,
} from 'ddna-tools';

// Anthropic Claude extraction
const anthropic = createAnthropicClient(process.env.ANTHROPIC_API_KEY);
const result = await extractWithLlm(anthropic, { text: 'I remember...' }, undefined, 'full');
console.log('Extracted:', result.extracted);
console.log('Confidence:', result.confidence);

// OpenAI extraction
const openai = createOpenAIClient(process.env.OPENAI_API_KEY);
const result2 = await extractWithOpenAI(openai, { text: 'I remember...' }, 'gpt-4o-mini', 0, 'extended');

// Kimi K2 extraction
const kimi = createKimiClient(process.env.KIMI_API_KEY);
const result3 = await extractWithKimi(kimi, { text: 'I remember...' }, undefined, 'essential');
```

### Sealing & Verification

```typescript
import {
  keygen,
  seal,
  verify,
  inspect,
  validate,
  redact,
  isExpired,
  hexToKey,
  keyToHex,
} from 'ddna-tools';

// Generate keys
const keys = keygen();
console.log('DID:', keys.did);

// Validate against schema
const validation = validate(edmPayload);
if (!validation.valid) {
  console.error('Validation errors:', validation.errors);
}

// Seal an EDM artifact (local signing)
const envelope = await seal(edmPayload, keys.privateKey, keys.did);

// Verify the envelope
const result = await verify(envelope);
console.log('Valid:', result.valid);

// Redact for stateless mode
const { artifact: redacted, fieldsRedacted } = redact(edmPayload);
console.log(`Redacted ${fieldsRedacted} fields`);

// Check TTL
const ttl = isExpired(edmPayload, 24);
if (ttl.expired) {
  console.log('Artifact expired');
}
```

## EDM Conformance Levels

| Level | Name      | Requires                            |
|-------|-----------|-------------------------------------|
| 1     | Compliant | EDM schema validation               |
| 2     | Sealed    | Own signing key (open)              |
| 3     | Certified | DeepaData API (Extended/Full only)  |

### Profile x Conformance Matrix

| Profile   | Compliant | Sealed | Certified |
|-----------|-----------|--------|-----------|
| Essential | Yes       | Yes    | No        |
| Extended  | Yes       | Yes    | Yes       |
| Full      | Yes       | Yes    | Yes       |

**Notes:**
- **Compliant** and **Sealed** are achievable with open-source tools only
- **Certified** requires DeepaData commercial API for third-party attestation
- Essential profile is not eligible for Certified conformance

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
    "edm_version": "0.7.0",
    "jurisdiction": "GDPR",
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

## In the EDM stack

```
Raw text
↓
extractWithLlm() — ddna-tools (BYOK)   ← you are here
↓
EDM artifact (significance encoded)
↓
seal() — ddna-tools                    ← you are here
↓
.ddna envelope (portable, verifiable)
↓
DeepaData registry (certified, addressable)
```

**Open vs Commercial:**
- Extraction, sealing, verification: **Open** (this package)
- Certification, activation layer: **Commercial** (DeepaData API)

## License

MIT
