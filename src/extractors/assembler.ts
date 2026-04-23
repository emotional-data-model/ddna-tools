/**
 * EDM Artifact Assembler
 * Combines LLM-extracted fields with metadata to create complete artifacts
 * Enforces exact field-level profile filtering per EDM spec
 *
 * Migrated from deepadata-edm-sdk per ADR-0023 (canonical profiles in OSS)
 */
import type { EdmProfile, LlmExtractedFields } from "./types.js";
import type { ExtractionMetadata } from "./domain-extractors.js";
import {
  createMeta,
  createGovernance,
  createTelemetry,
  createSystem,
  createCrosswalks,
  detectSourceType,
} from "./domain-extractors.js";

// =============================================================================
// Profile Field Definitions
// =============================================================================

/**
 * Essential Profile: 5 domains, 24 fields
 * Target: memory platforms, agent frameworks, AI assistants
 */
export const ESSENTIAL_PROFILE_FIELDS = {
  meta: [
    "id",
    "version",
    "profile",
    "created_at",
    "owner_user_id",
    "consent_basis",
    "visibility",
    "pii_tier",
  ],
  core: ["anchor", "spark", "wound", "fuel", "bridge", "echo"],
  constellation: ["emotion_primary", "emotion_subtone", "narrative_arc"],
  governance: ["jurisdiction", "retention_policy", "subject_rights"],
  telemetry: ["entry_confidence", "extraction_model"],
} as const;

/**
 * Extended Profile: 7 domains, 50 fields
 * Target: journaling apps, companion AI, workplace wellness
 * Impulse domain is NOT included in Extended profile
 */
export const EXTENDED_PROFILE_FIELDS = {
  meta: [
    "id",
    "version",
    "profile",
    "created_at",
    "owner_user_id",
    "consent_basis",
    "visibility",
    "pii_tier",
  ],
  core: ["anchor", "spark", "wound", "fuel", "bridge", "echo", "narrative"],
  constellation: [
    "emotion_primary",
    "emotion_subtone",
    "higher_order_emotion",
    "meta_emotional_state",
    "interpersonal_affect",
    "narrative_arc",
    "relational_dynamics",
    "temporal_context",
    "memory_type",
    "media_format",
    "narrative_archetype",
    "symbolic_anchor",
    "relational_perspective",
    "temporal_rhythm",
    "identity_thread",
    "expressed_insight",
    "transformational_pivot",
    "somatic_signature",
  ],
  milky_way: [
    "event_type",
    "location_context",
    "associated_people",
    "visibility_context",
    "tone_shift",
  ],
  gravity: [
    "emotional_weight",
    "valence",
    "tether_type",
    "recurrence_pattern",
    "strength_score",
  ],
  governance: ["jurisdiction", "retention_policy", "subject_rights"],
  telemetry: ["entry_confidence", "extraction_model"],
} as const;

/**
 * Full Profile: all 10 domains, all fields
 * Target: therapy platforms, clinical tools, regulated systems
 */
export const FULL_PROFILE_FIELDS = {
  meta: [
    "id",
    "version",
    "profile",
    "created_at",
    "updated_at",
    "locale",
    "owner_user_id",
    "parent_id",
    "visibility",
    "pii_tier",
    "source_type",
    "source_context",
    "consent_basis",
    "consent_scope",
    "consent_revoked_at",
    "tags",
  ],
  core: ["anchor", "spark", "wound", "fuel", "bridge", "echo", "narrative"],
  constellation: [
    "emotion_primary",
    "emotion_subtone",
    "higher_order_emotion",
    "meta_emotional_state",
    "interpersonal_affect",
    "narrative_arc",
    "relational_dynamics",
    "temporal_context",
    "memory_type",
    "media_format",
    "narrative_archetype",
    "symbolic_anchor",
    "relational_perspective",
    "temporal_rhythm",
    "identity_thread",
    "expressed_insight",
    "transformational_pivot",
    "somatic_signature",
    "arc_type",
  ],
  milky_way: [
    "event_type",
    "location_context",
    "associated_people",
    "visibility_context",
    "tone_shift",
  ],
  gravity: [
    "emotional_weight",
    "emotional_density",
    "valence",
    "viscosity",
    "gravity_type",
    "tether_type",
    "recall_triggers",
    "retrieval_keys",
    "nearby_themes",
    "recurrence_pattern",
    "strength_score",
    "temporal_decay",
    "resilience_markers",
    "adaptation_trajectory",
  ],
  impulse: [
    "primary_energy",
    "drive_state",
    "motivational_orientation",
    "temporal_focus",
    "directionality",
    "social_visibility",
    "urgency",
    "risk_posture",
    "agency_level",
    "regulation_state",
    "attachment_style",
    "coping_style",
  ],
  governance: [
    "jurisdiction",
    "retention_policy",
    "subject_rights",
    "exportability",
    "k_anonymity",
    "policy_labels",
    "masking_rules",
  ],
  telemetry: [
    "entry_confidence",
    "extraction_model",
    "extraction_provider",
    "extraction_notes",
  ],
  system: ["embeddings", "indices"],
  crosswalks: [
    "plutchik_primary",
    "geneva_emotion_wheel",
    "DSM5_specifiers",
    "ISO_27557_labels",
  ],
} as const;

/**
 * Get profile field definitions
 */
export function getProfileFields(
  profile: EdmProfile
): Record<string, readonly string[]> {
  switch (profile) {
    case "essential":
      return ESSENTIAL_PROFILE_FIELDS;
    case "extended":
      return EXTENDED_PROFILE_FIELDS;
    case "full":
      return FULL_PROFILE_FIELDS;
    default:
      // Should not reach here for canonical profiles
      return FULL_PROFILE_FIELDS;
  }
}

/**
 * Get domains included in a profile
 */
export function getProfileDomains(profile: EdmProfile): string[] {
  return Object.keys(getProfileFields(profile));
}

// =============================================================================
// Profile Filtering
// =============================================================================

/**
 * Filter an object to include only specified fields
 */
function filterObjectFields<T extends Record<string, unknown>>(
  obj: T,
  allowedFields: readonly string[]
): Partial<T> {
  const filtered: Partial<T> = {};
  for (const field of allowedFields) {
    if (field in obj) {
      (filtered as Record<string, unknown>)[field] = obj[field];
    }
  }
  return filtered;
}

/**
 * Filter nested governance fields for Essential/Extended profiles
 */
function filterGovernanceFields(
  governance: Record<string, unknown>,
  allowedFields: readonly string[]
): Record<string, unknown> {
  const filtered: Record<string, unknown> = {};

  for (const field of allowedFields) {
    if (field in governance) {
      const value = governance[field];

      // For retention_policy, filter to basis, ttl_days, on_expiry only
      if (field === "retention_policy" && value && typeof value === "object") {
        const rp = value as Record<string, unknown>;
        filtered[field] = {
          basis: rp.basis,
          ttl_days: rp.ttl_days,
          on_expiry: rp.on_expiry,
        };
      }
      // For subject_rights, filter to portable, erasable, explainable only
      else if (
        field === "subject_rights" &&
        value &&
        typeof value === "object"
      ) {
        const sr = value as Record<string, unknown>;
        filtered[field] = {
          portable: sr.portable,
          erasable: sr.erasable,
          explainable: sr.explainable,
        };
      } else {
        filtered[field] = value;
      }
    }
  }

  return filtered;
}

/**
 * Filter artifact to include only fields defined for the declared profile
 * Per EDM Profile Invariants: out-of-profile fields MUST be omitted entirely
 */
export function filterByProfile(
  artifact: Record<string, unknown>,
  profile: EdmProfile
): Record<string, unknown> {
  const profileFields = getProfileFields(profile);
  const filtered: Record<string, unknown> = {};

  for (const [domain, fields] of Object.entries(profileFields)) {
    const domainData = artifact[domain];
    if (domainData && typeof domainData === "object") {
      if (domain === "governance") {
        filtered[domain] = filterGovernanceFields(
          domainData as Record<string, unknown>,
          fields
        );
      } else {
        filtered[domain] = filterObjectFields(
          domainData as Record<string, unknown>,
          fields
        );
      }
    }
  }

  return filtered;
}

// =============================================================================
// Assembly Context and Types
// =============================================================================

export interface AssemblyContext {
  confidence: number;
  model: string;
  profile: EdmProfile;
  provider?: "anthropic" | "openai" | "kimi";
  notes: string | null;
  hasText: boolean;
  hasImage: boolean;
}

/**
 * Profile-specific extracted fields (union type)
 */
type ProfileExtractedFields = Record<string, unknown>;

// =============================================================================
// Artifact Assembly
// =============================================================================

/**
 * Assemble a profile-specific EDM artifact from extracted fields and metadata
 * Returns only the domains defined for the declared profile
 */
export function assembleProfileArtifact(
  extracted: ProfileExtractedFields,
  metadata: ExtractionMetadata,
  context: AssemblyContext
): Record<string, unknown> {
  const sourceType = detectSourceType(context.hasText, context.hasImage);
  const profile = context.profile;
  const profileFields = getProfileFields(profile);

  // Create metadata domains
  const meta = createMeta(metadata, sourceType, profile);
  const governance = createGovernance(metadata);
  const telemetry = createTelemetry(
    context.confidence,
    context.model,
    context.notes,
    context.provider
  );

  // Post-process constellation: default media_format to source type if null
  // Schema enum doesn't include null, so we must provide a valid default
  const constellation = extracted.constellation as Record<string, unknown> | undefined;
  if (constellation && constellation.media_format === null) {
    constellation.media_format = sourceType === "mixed" ? "photo_with_story" : sourceType;
  }

  // Build artifact with only profile-specific domains
  const artifact: Record<string, unknown> = {
    meta: filterObjectFields(meta as unknown as Record<string, unknown>, profileFields.meta ?? []),
    core: extracted.core,
    constellation: constellation,
    governance: filterGovernanceFields(
      governance as unknown as Record<string, unknown>,
      profileFields.governance ?? []
    ),
    telemetry: filterObjectFields(telemetry as unknown as Record<string, unknown>, profileFields.telemetry ?? []),
  };

  // Add extended/full domains if present in extracted data
  if (extracted.milky_way) {
    artifact.milky_way = extracted.milky_way;
  }
  if (extracted.gravity) {
    artifact.gravity = extracted.gravity;
  }
  if (extracted.impulse) {
    artifact.impulse = extracted.impulse;
  }

  // Add full-only domains
  if (profile === "full") {
    artifact.system = createSystem();
    artifact.crosswalks = createCrosswalks(
      extracted as unknown as LlmExtractedFields
    );
  }

  return artifact;
}
