/**
 * Extraction Types for ddna-tools
 * Standalone type definitions for canonical profile extraction
 *
 * These types mirror the EDM specification but are self-contained
 * to avoid SDK dependency. Partner profiles are not included
 * per ADR-0023 (canonical profiles only in OSS).
 */

/**
 * EDM Canonical Profiles
 * Partner profiles (partner:*) are intentionally excluded from OSS
 * per EDM spec §3.7.6 (registry-gated)
 */
export type EdmProfile = 'essential' | 'extended' | 'full';

/**
 * Input for extraction
 */
export interface ExtractionInput {
  /** Primary text content */
  text: string;
  /** Optional base64-encoded image */
  image?: string;
  /** Optional image media type */
  imageMediaType?: 'image/jpeg' | 'image/png' | 'image/gif' | 'image/webp';
}

/**
 * Core domain fields
 */
export interface Core {
  anchor: string | null;
  spark: string | null;
  wound: string | null;
  fuel: string | null;
  bridge: string | null;
  echo: string | null;
  narrative?: string | null;
}

/**
 * Constellation domain fields
 */
export interface Constellation {
  emotion_primary: string | null;
  emotion_subtone: string[];
  higher_order_emotion?: string | null;
  meta_emotional_state?: string | null;
  interpersonal_affect?: string | null;
  narrative_arc: string | null;
  relational_dynamics?: string | null;
  temporal_context?: string | null;
  memory_type?: string | null;
  media_format?: string | null;
  narrative_archetype?: string | null;
  symbolic_anchor?: string | null;
  relational_perspective?: string | null;
  temporal_rhythm?: string | null;
  identity_thread?: string | null;
  expressed_insight?: string | null;
  transformational_pivot?: boolean;
  somatic_signature?: string | null;
  arc_type?: string | null;
}

/**
 * MilkyWay domain fields
 */
export interface MilkyWay {
  event_type: string | null;
  location_context: string | null;
  associated_people: string[];
  visibility_context: string | null;
  tone_shift: string | null;
}

/**
 * Gravity domain fields
 */
export interface Gravity {
  emotional_weight: number;
  emotional_density?: string | null;
  valence: string | null;
  viscosity?: string | null;
  gravity_type?: string | null;
  tether_type: string | null;
  recall_triggers?: string[];
  retrieval_keys?: string[];
  nearby_themes?: string[];
  recurrence_pattern: string | null;
  strength_score: number;
  temporal_decay?: string | null;
  resilience_markers?: string[] | null;
  adaptation_trajectory?: string | null;
}

/**
 * Impulse domain fields
 */
export interface Impulse {
  primary_energy: string | null;
  drive_state: string | null;
  motivational_orientation: string | null;
  temporal_focus: string | null;
  directionality: string | null;
  social_visibility: string | null;
  urgency: string | null;
  risk_posture: string | null;
  agency_level: string | null;
  regulation_state: string | null;
  attachment_style: string | null;
  coping_style: string | null;
}

/**
 * Essential profile extracted fields (9 fields)
 */
export interface EssentialExtracted {
  core: Pick<Core, 'anchor' | 'spark' | 'wound' | 'fuel' | 'bridge' | 'echo'>;
  constellation: Pick<Constellation, 'emotion_primary' | 'emotion_subtone' | 'narrative_arc'>;
}

/**
 * Extended profile extracted fields (35 fields)
 */
export interface ExtendedExtracted {
  core: Core;
  constellation: Constellation;
  milky_way: MilkyWay;
  gravity: Pick<Gravity, 'emotional_weight' | 'valence' | 'tether_type' | 'recurrence_pattern' | 'strength_score'>;
}

/**
 * Full profile extracted fields (all domains)
 */
export interface FullExtracted {
  core: Core;
  constellation: Constellation;
  milky_way: MilkyWay;
  gravity: Gravity;
  impulse: Impulse;
}

/**
 * Extracted fields union type
 */
export type LlmExtractedFields = EssentialExtracted | ExtendedExtracted | FullExtracted;

/**
 * Extraction result
 */
export interface LlmExtractionResult {
  extracted: LlmExtractedFields;
  confidence: number;
  model: string;
  profile: EdmProfile;
  notes: string | null;
}
