/**
 * deepadata-ddna-tools v0.2.0
 * Reference implementation for .ddna signing specification
 *
 * W3C Data Integrity Proofs with eddsa-jcs-2022 cryptosuite
 *
 * ## Free (no API key needed)
 * - keygen() — generate Ed25519 key pair
 * - verify() — verify a sealed .ddna envelope
 * - inspect() — read envelope contents
 * - redact() — stateless mode, null sensitive fields
 * - validate() — schema validation
 * - isExpired() — check artifact TTL
 *
 * ## Commercial (API key required)
 * - seal() — create tamper-evident .ddna envelope
 *
 * Get API key at https://deepadata.com/api-keys
 * See https://deepadata.com/pricing for current rates.
 */

// Core signing functions (seal requires API key)
export { seal, sealSync, SealingApiKeyError, SealingApiError, SchemaValidationError } from './seal.js';
export type { SealOptions } from './seal.js';

// Verification (free)
export { verify, verifySync } from './verify.js';
export type { VerifyOptions } from './verify.js';

// Inspection (free)
export { inspect, inspectEnvelope, inspectJson } from './inspect.js';

// Key generation (free)
export { keygen, deriveKeyPair, keyToHex, hexToKey } from './keygen.js';

// Stateless mode utilities (free)
export { redact, isExpired, isStateless } from './stateless.js';
export type { RedactionResult, TtlResult } from './stateless.js';

// Schema validation (free)
export { validate, isValid } from './validate.js';
export type { ValidationResult, ValidationError } from './validate.js';

// EDM profile schema validation (free)
export {
  validateEdmSchema,
  detectProfile,
  formatValidationErrors,
} from './validate-schema.js';
export type {
  EdmProfile,
  SchemaValidationResult,
  SchemaValidationError as SchemaError,
} from './validate-schema.js';

// DID utilities
export { publicKeyToDid, didToPublicKey, isValidDidUrl, resolveVerificationMethod } from './did.js';

// Types
export type {
  DdnaEnvelope,
  DdnaHeader,
  DataIntegrityProof,
  ProofOptions,
  EdmPayload,
  EdmMeta,
  SigningDocument,
  VerifyResult,
  KeyPair,
  InspectionResult,
  RetentionPolicy,
  AuditEntry,
} from './types.js';
