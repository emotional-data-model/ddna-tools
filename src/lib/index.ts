/**
 * ddna-tools v0.3.0
 * Reference implementation for .ddna signing specification
 *
 * W3C Data Integrity Proofs with eddsa-jcs-2022 cryptosuite
 *
 * All operations are local. No external API required.
 *
 * - keygen() — generate Ed25519 key pair with DID
 * - seal() — create tamper-evident .ddna envelope (local signing)
 * - verify() — verify a sealed .ddna envelope
 * - inspect() — read envelope contents
 * - redact() — stateless mode, null sensitive fields
 * - validate() — schema validation against EDM v0.6.0
 * - isExpired() — check artifact TTL
 */

// Core signing functions (local Ed25519 signing)
export { seal, sealSync, SealingKeyError, SchemaValidationError } from './seal.js';
export type { SealOptions } from './seal.js';

// Verification
export { verify, verifySync } from './verify.js';
export type { VerifyOptions } from './verify.js';

// Inspection
export { inspect, inspectEnvelope, inspectJson } from './inspect.js';

// Key generation
export { keygen, deriveKeyPair, keyToHex, hexToKey } from './keygen.js';

// Stateless mode utilities
export { redact, isExpired, isStateless } from './stateless.js';
export type { RedactionResult, TtlResult } from './stateless.js';

// Schema validation
export { validate, isValid } from './validate.js';
export type { ValidationResult, ValidationError } from './validate.js';

// EDM profile schema validation (v0.6.0)
// validateEdmSchema (async) fetches from canonical URL with bundled fallback
// validateEdmSchemaSync uses bundled schemas only (for sync contexts)
export {
  validateEdmSchema,
  validateEdmSchemaSync,
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
