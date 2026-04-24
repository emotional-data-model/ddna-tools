/**
 * Domain Extractors
 * Populates domains not handled by LLM extraction
 * Supports profile-aware artifact assembly
 *
 * Migrated from deepadata-edm-sdk per ADR-0023 (canonical profiles in OSS)
 */
import { randomUUID } from "crypto";
import type { EdmProfile, LlmExtractedFields } from "./types.js";

// =============================================================================
// EDM Schema Version
// =============================================================================
export const EDM_SCHEMA_VERSION = "0.8.0";

// =============================================================================
// Domain Types (self-contained to avoid SDK dependency)
// =============================================================================

export interface Meta {
  id: string;
  version: string;
  profile: EdmProfile;
  created_at: string;
  updated_at: string | null;
  locale: string | null;
  owner_user_id: string | null;
  parent_id: string | null;
  visibility: "private" | "shared" | "public";
  pii_tier: "none" | "low" | "moderate" | "high" | "extreme";
  source_type: "text" | "image" | "audio" | "video" | "mixed";
  source_context: string | null;
  consent_basis: string;
  consent_scope: string | null;
  consent_revoked_at: string | null;
  tags: string[];
}

export interface Governance {
  jurisdiction: "GDPR" | "CCPA" | "HIPAA" | "PIPEDA" | "LGPD" | "None" | "Mixed" | null;
  retention_policy: {
    basis: "user_defined" | "legal" | "business_need";
    ttl_days: number | null;
    on_expiry: "soft_delete" | "hard_delete" | "anonymize";
  };
  subject_rights: {
    portable: boolean;
    erasable: boolean;
    explainable: boolean;
  };
  exportability: "allowed" | "restricted" | "forbidden";
  k_anonymity: {
    k: number | null;
    groups: string[];
  };
  policy_labels: string[];
  masking_rules: string[];
}

export interface Telemetry {
  entry_confidence: number;
  extraction_model: string;
  extraction_provider: "anthropic" | "openai" | "kimi" | null;
  extraction_notes: string | null;
}

export interface System {
  embeddings: Array<{
    model: string;
    vector: number[];
    created_at: string;
  }>;
  indices: {
    waypoint_ids: string[];
  };
}

export interface Crosswalks {
  plutchik_primary: string | null;
  geneva_emotion_wheel: string | null;
  DSM5_specifiers: string | null;
  ISO_27557_labels: string | null;
}

export interface ExtractionMetadata {
  subjectId?: string;
  locale?: string;
  parentId?: string;
  visibility?: Meta["visibility"];
  piiTier?: Meta["pii_tier"];
  consentBasis: "consent" | "contract" | "legitimate_interest" | "none";
  jurisdiction?: Governance["jurisdiction"];
  tags?: string[];
  retentionPolicyBasis?: Governance["retention_policy"]["basis"];
}

// =============================================================================
// META Domain
// =============================================================================
export function createMeta(
  metadata: ExtractionMetadata,
  sourceType: Meta["source_type"],
  profile: EdmProfile = "full"
): Meta {
  return {
    id: randomUUID(),
    version: EDM_SCHEMA_VERSION,
    profile,
    created_at: new Date().toISOString(),
    updated_at: null,
    locale: metadata.locale ?? null,
    owner_user_id: metadata.subjectId ?? null,
    parent_id: metadata.parentId ?? null,
    visibility: metadata.visibility ?? "private",
    pii_tier: metadata.piiTier ?? "moderate",
    source_type: sourceType,
    source_context: null,
    consent_basis: metadata.consentBasis,
    consent_scope: null,
    consent_revoked_at: null,
    tags: metadata.tags ?? [],
  };
}

// =============================================================================
// GOVERNANCE Domain
// =============================================================================
export function createGovernance(metadata: ExtractionMetadata): Governance {
  // Default subject rights based on jurisdiction
  const defaultRights = getDefaultSubjectRights(metadata.jurisdiction ?? null);

  return {
    jurisdiction: metadata.jurisdiction ?? null,
    retention_policy: {
      basis: metadata.retentionPolicyBasis ?? "user_defined",
      ttl_days: null, // No automatic expiry by default
      on_expiry: "soft_delete",
    },
    subject_rights: defaultRights,
    exportability: "allowed",
    k_anonymity: {
      k: null,
      groups: [],
    },
    policy_labels: determinePolicyLabels(metadata.piiTier),
    masking_rules: [],
  };
}

function getDefaultSubjectRights(
  jurisdiction: Governance["jurisdiction"]
): Governance["subject_rights"] {
  // GDPR and similar provide strong rights
  if (jurisdiction === "GDPR" || jurisdiction === "LGPD") {
    return {
      portable: true,
      erasable: true,
      explainable: true,
    };
  }

  // CCPA provides most rights
  if (jurisdiction === "CCPA") {
    return {
      portable: true,
      erasable: true,
      explainable: false,
    };
  }

  // HIPAA is strict on health data
  if (jurisdiction === "HIPAA") {
    return {
      portable: true,
      erasable: true,
      explainable: true,
    };
  }

  // Default: provide basic rights
  return {
    portable: true,
    erasable: true,
    explainable: false,
  };
}

function determinePolicyLabels(
  piiTier: Meta["pii_tier"] | undefined
): Governance["policy_labels"] {
  if (!piiTier || piiTier === "none") {
    return ["none"];
  }
  if (piiTier === "extreme" || piiTier === "high") {
    return ["sensitive"];
  }
  return [];
}

// =============================================================================
// TELEMETRY Domain
// =============================================================================
export function createTelemetry(
  confidence: number,
  model: string,
  notes: string | null,
  provider?: "anthropic" | "openai" | "kimi" | null
): Telemetry {
  return {
    entry_confidence: confidence,
    extraction_model: model,
    extraction_provider: provider ?? null,
    extraction_notes: notes,
  };
}

// =============================================================================
// SYSTEM Domain
// =============================================================================
export function createSystem(): System {
  // System domain is populated by downstream systems (embedding, indexing)
  // ddna-tools creates empty structure
  return {
    embeddings: [],
    indices: {
      waypoint_ids: [],
    },
  };
}

// =============================================================================
// CROSSWALKS Domain
// =============================================================================
export function createCrosswalks(extracted: LlmExtractedFields): Crosswalks {
  // Map emotion_primary to Plutchik
  const plutchikMapping: Record<string, string> = {
    joy: "joy",
    sadness: "sadness",
    fear: "fear",
    anger: "anger",
    wonder: "surprise", // Plutchik uses surprise
    peace: "trust", // Closest Plutchik equivalent
    tenderness: "trust",
    reverence: "trust",
    // v0.8.0 additions - map to closest Plutchik
    frustration: "anger",
    disappointment: "sadness",
    relief: "joy",
    gratitude: "joy",
    longing: "sadness",
    hope: "anticipation",
    anxiety: "fear",
    pride: "joy",
    shame: "sadness",
  };

  const emotionPrimary = extracted.constellation.emotion_primary;
  const plutchikPrimary = emotionPrimary
    ? (plutchikMapping[emotionPrimary] ?? null)
    : null;

  return {
    plutchik_primary: plutchikPrimary,
    geneva_emotion_wheel: null, // Requires more complex mapping
    DSM5_specifiers: null, // Should not be auto-populated
    ISO_27557_labels: null, // Future standard
  };
}

// =============================================================================
// Source Type Detection
// =============================================================================
export function detectSourceType(
  hasText: boolean,
  hasImage: boolean
): Meta["source_type"] {
  if (hasText && hasImage) {
    return "mixed";
  }
  if (hasImage) {
    return "image";
  }
  return "text";
}
