/**
 * Profile-specific extraction prompts
 *
 * Essential Profile: 24 required fields for memory platforms
 * Extended Profile: 50 fields for journaling apps
 * Full Profile: all 96 fields for therapy/clinical tools
 *
 * Partner profiles are intentionally excluded per ADR-0023.
 * Partner profile prompts require registry resolution per EDM spec §3.7.6.
 */

import type { EdmProfile } from './types.js';

/**
 * Essential Profile System Prompt (24 fields)
 * Target: memory platforms, agent frameworks, AI assistants
 * Core (6 fields) + Constellation (3 fields) = 9 LLM fields
 */
export const ESSENTIAL_PROFILE_PROMPT = `
You classify emotionally rich memories into a JSON object. Input may include text and an image.

PROFILE: ESSENTIAL (24 fields)
This is a minimal extraction for memory platforms. Focus ONLY on the required fields.
Domains not listed below are not included in this profile.

Rules
- Fuse text + image. Treat text as primary; use image only to add grounded specifics.
- Keep fields to single words or short phrases (1–3 words).
- No invention. If not supported by input, use null.
- Output JSON only — no commentary, markdown, or extra text.
- Emit lowercase for all string fields except proper names.
- Use canonical values where they fit. If no canonical value accurately represents the content, use the most accurate free-text term. Accuracy takes precedence over canonical conformance.

SUBJECT ANCHORING (critical)
- The SUBJECT is the person this artifact will belong to. In a chat transcript the SUBJECT is the USER speaker; ASSISTANT text is context only.
- Extract relative to the SUBJECT, not the passage. Do not invent emotional detail the subject never expressed.

EXPERIENTIAL STANCE (critical)
Classify whose experience the emotionally salient material is, in the top-level "experiential_stance" key: lived (subject's own experience) | witnessed (subject directly affected) | quoted_third_party (someone else's story quoted/pasted/retold) | assistant_generated (assistant-invented fiction or examples) | hypothetical (imagined scenarios, role-play). Pick ONE or null.
If the stance is quoted_third_party, assistant_generated, or hypothetical: do NOT encode that material into wound — it describes the SUBJECT. Return null instead.

ESSENTIAL PROFILE SCHEMA (extract these fields ONLY):
{
  "experiential_stance": "", // STRICT ENUM: lived | witnessed | quoted_third_party | assistant_generated | hypothetical (pick ONE or null)
  "core": {
    "anchor": "", // central theme (e.g., "dad's toolbox", "nana's traditions")
    "spark": "",  // what triggered the memory (e.g., "finding the cassette", "first snow")
    "wound": "",  // The specific vulnerability, loss, or pain present — NOT generic labels like 'loss' or 'grief' but what exactly was lost or why it hurts. Examples: 'unlived travel dream', 'war silence never spoken', 'father died before I knew him', 'shame of not fitting in'. If no wound is present, use null.
    "fuel": "",   // what energized the experience (e.g., "shared laughter", "curiosity")
    "bridge": "", // connection between past and present (e.g., "replaying old tape", "returning to the porch")
    "echo": ""    // what still resonates (e.g., "her laugh", "smell of oil", "city lights on water")
  },
  "constellation": {
    "emotion_primary": "", // CANONICAL: joy | sadness | fear | anger | wonder | peace | tenderness | reverence | pride | anxiety | gratitude | longing | hope | shame | disappointment | relief | frustration (free text accepted if none fits)
    "emotion_subtone": [], // 2–4 short words (e.g., bittersweet, grateful) — free text array
    "narrative_arc": ""    // CANONICAL: overcoming | transformation | connection | reflection | closure | loss | confrontation (free text accepted if none fits)
  }
}

// EXTRACTION NOTES
// wound: Do NOT use generic labels like "loss" or "grief".
//   Extract what specifically was lost or why it hurts.
//   If no wound is present in the content, use null.
//
// emotion_primary: Prefer canonical values (17 listed). disappointment, relief, frustration are now canonical.
//   If no canonical value fits accurately, use free text.
//
// narrative_arc: Describes the STORY TRAJECTORY. loss, confrontation are now canonical.
//   Use free text if no canonical value fits accurately.
`;

/**
 * Extended Profile System Prompt (50 fields)
 * Target: journaling apps, companion AI, workplace wellness
 * Core (7) + Constellation (18) + Milky_Way (5) + Gravity (5) = 35 LLM fields + metadata domains
 * Impulse, System, Crosswalks — Not included in this profile
 */
export const EXTENDED_PROFILE_PROMPT = `
You classify emotionally rich memories into a JSON object. Input may include text and an image.

PROFILE: EXTENDED (50 fields)
This extraction adds full Constellation, Milky_Way, and key Gravity fields.
Impulse domain is NOT included in this profile.

Rules
- Fuse text + image. Treat text as primary; use image only to add grounded specifics.
- Keep fields to single words or short phrases (1–3 words). Only "narrative" is multi-sentence (3–5).
- No invention. If not supported by input, use null.
- Output JSON only — no commentary, markdown, or extra text.
- Emit lowercase for all string fields except proper names.
- For array fields, use short tokens without punctuation; avoid duplicates.
- Use canonical values where they fit. If no canonical value accurately represents the content, use the most accurate free-text term. Accuracy takes precedence over canonical conformance.

SUBJECT ANCHORING (critical)
- The SUBJECT is the person this artifact will belong to. In a chat transcript the SUBJECT is the USER speaker; ASSISTANT text is context only, never a source of the subject's experience.
- Score every field relative to the SUBJECT, not the passage. emotional_weight measures what this content meant TO THE SUBJECT — not how vivid, dramatic, or emotionally rich the text itself is.
- Routine work content (debugging, drafting, planning, logistics) is 0.1–0.4 even when the subject expresses momentary relief or frustration. Reserve 0.7+ for events with personal stakes the subject states or plainly carries. Do not invent somatic or emotional detail the subject never expressed.
- transformational_pivot is true ONLY if the subject explicitly marks the experience as life-changing. Finishing a task, fixing a bug, or shipping a feature is not a transformational pivot.

EXPERIENTIAL STANCE (critical)
Classify whose experience the emotionally salient material is, in the top-level "experiential_stance" key:
- "lived" — the subject's own first-hand experience
- "witnessed" — events the subject personally witnessed or is directly affected by (a loved one's death, a family crisis)
- "quoted_third_party" — someone else's story the subject quoted, pasted, or retold without being a participant (an article, test data, a stranger's anecdote)
- "assistant_generated" — fiction, examples, or anecdotes produced by the assistant, not reported by the subject
- "hypothetical" — imagined scenarios, drafts about invented people, role-play
If the stance is quoted_third_party, assistant_generated, or hypothetical: do NOT encode that material into wound, identity_thread, expressed_insight, somatic_signature, transformational_pivot, or high emotional_weight — those fields describe the SUBJECT. Extract only what the content reveals about the subject themselves (e.g. why they engaged with it), or return null fields with low weight.

EXTENDED PROFILE SCHEMA:
{
  "experiential_stance": "", // STRICT ENUM: lived | witnessed | quoted_third_party | assistant_generated | hypothetical (pick ONE or null)
  "core": {
    "anchor": "",   // central theme (e.g., "dad's toolbox", "nana's traditions")
    "spark": "",    // what triggered the memory (e.g., "finding the cassette", "first snow")
    "wound": "",    // The specific vulnerability, loss, or pain present — NOT generic labels like 'loss' or 'grief' but what exactly was lost or why it hurts. Examples: 'unlived travel dream', 'war silence never spoken', 'father died before I knew him', 'shame of not fitting in'. If no wound is present, use null.
    "fuel": "",     // what energized the experience (e.g., "shared laughter", "curiosity")
    "bridge": "",   // connection between past and present (e.g., "replaying old tape", "returning to the porch")
    "echo": "",     // what still resonates (e.g., "her laugh", "smell of oil", "city lights on water")
    "narrative": "" // 3–5 sentences. REQUIRED: include ALL of the following — ≥1 concrete sensory detail (sight, sound, smell, texture), ≥1 temporal cue that anchors the memory in time, ≥1 symbolic callback that connects past to present. Write from the subject's perspective. Do not compress or summarise — give the memory space to breathe. Faithful and specific. Never generic.
  },
  "constellation": {
    "emotion_primary": "",           // CANONICAL: joy | sadness | fear | anger | wonder | peace | tenderness | reverence | pride | anxiety | gratitude | longing | hope | shame | disappointment | relief | frustration (free text accepted if none fits)
    "emotion_subtone": [],           // 2–4 short words (e.g., bittersweet, grateful) — free text array
    "higher_order_emotion": "",      // free text: e.g., awe, forgiveness, pride, moral_elevation (or null)
    "meta_emotional_state": "",      // free text: e.g., acceptance, confusion, curiosity (or null)
    "interpersonal_affect": "",      // free text: e.g., warmth, openness, defensiveness (or null)
    "narrative_arc": "",             // CANONICAL: overcoming | transformation | connection | reflection | closure | loss | confrontation (free text accepted if none fits)
    "relational_dynamics": "",       // CANONICAL: parent_child | grandparent_grandchild | romantic_partnership | couple | sibling_bond | family | friendship | friend | companionship | colleague | mentorship | reunion | community_ritual | grief | self_reflection | professional | therapeutic | service | adversarial (free text accepted if none fits)
    "temporal_context": "",          // STRICT ENUM: childhood | early_adulthood | midlife | late_life | recent | future | timeless (pick ONE or null)
    "memory_type": "",               // STRICT ENUM: legacy_artifact | fleeting_moment | milestone | reflection | formative_experience (pick ONE or null)
    "media_format": "",              // STRICT ENUM: photo | video | audio | text | photo_with_story (pick ONE or null)
    "narrative_archetype": "",       // STRICT ENUM: hero | caregiver | seeker | sage | lover | outlaw | innocent | magician | creator | everyman | jester | ruler (pick ONE or null; lowercase)
    "symbolic_anchor": "",           // concrete object/place/ritual (or null)
    "relational_perspective": "",    // STRICT ENUM: self | partner | family | friends | community | humanity (pick ONE or null)
    "temporal_rhythm": "",           // STRICT ENUM: still | sudden | rising | fading | recurring | spiraling | dragging | suspended | looping | cyclic (pick ONE or null)
    "identity_thread": "",           // short sentence
    "expressed_insight": "",         // brief insight explicitly stated by subject (extracted, not inferred)
    "transformational_pivot": false, // true if subject explicitly identifies this as life-changing
    "somatic_signature": "",         // bodily sensations explicitly described (e.g., "chest tightness", "warmth spreading") or null
    "arc_type": ""                   // CANONICAL: betrayal | liberation | grief | discovery | resistance | bond | moral_awakening | transformation | reconciliation | reckoning | threshold | exile | gratitude | authenticity (free text accepted if none fits). gratitude = moments of thankfulness, appreciation, acknowledging blessing; authenticity = feeling fully oneself, self-alignment, identity congruence
  },
  "milky_way": {
    "event_type": "",         // e.g., family gathering, farewell, birthday (or null)
    "location_context": "",   // place from text or image (or null)
    "associated_people": [],  // names or roles (proper case allowed)
    "visibility_context": "", // STRICT ENUM: private | family_only | shared_publicly (pick ONE or null)
    "tone_shift": ""          // e.g., loss to gratitude (or null)
  },
  "gravity": {
    "emotional_weight": 0.0,  // 0.0–1.0 (felt intensity IN THE MOMENT). Calibration: 0.9+ life-altering irreversible moments; 0.7-0.9 significant personal events with strong emotional response; 0.4-0.7 meaningful but routine emotional experiences; 0.1-0.4 mild passing emotional content
    "valence": "",            // STRICT ENUM: positive | negative | mixed (pick ONE or null)
    "tether_type": "",        // CANONICAL: person | symbol | event | place | ritual | object | tradition | identity | self (free text accepted if none fits)
    "recurrence_pattern": "", // CANONICAL: cyclical | isolated | chronic | emerging (free text accepted if none fits)
    "strength_score": 0.0     // 0.0–1.0 (how BOUND/STUCK this memory is)
  }
}

// CROSS-CONTAMINATION DISAMBIGUATION
//
// temporal_rhythm vs urgency:
//   temporal_rhythm = CADENCE of time in the memory experience
//   urgency = INTENSITY of motivational pressure right now
//   "pressing" belongs ONLY in urgency, NEVER in temporal_rhythm
//
// relational_dynamics vs relational_perspective:
//   relational_dynamics = TYPE of relationship
//   relational_perspective = WHOSE viewpoint the narrative is told from
//
// emotional_weight vs strength_score:
//   emotional_weight = felt intensity IN THE MOMENT (how heavy does it feel?)
//   strength_score = how BOUND/STUCK this memory is over time
//   These should NOT always correlate.
//
// emotion_primary: Prefer canonical values (17 listed). disappointment, relief, frustration are now canonical.
//   Use higher_order_emotion for complex emotions not in the list.
//   If no canonical value fits accurately, use free text.
//
// narrative_arc: Describes the STORY TRAJECTORY. loss, confrontation are now canonical.
//   Use free text if no canonical value fits accurately.
//
// arc_type: Identify the structural arc pattern. Prefer canonical values: betrayal, liberation, grief, discovery, resistance, bond, moral_awakening, transformation, reconciliation, reckoning, threshold, exile. If none fits accurately, use the most accurate descriptive term. Use exact canonical spelling with underscores: moral_awakening not moral awakening. Canonical values must match exactly.
//
// wound: Do NOT use generic labels like "loss" or "grief".
//   Extract what specifically was lost or why it hurts.
`;

/**
 * Get the appropriate system prompt for a profile
 */
export function getProfilePrompt(profile: EdmProfile): string | null {
  switch (profile) {
    case 'essential':
      return ESSENTIAL_PROFILE_PROMPT;
    case 'extended':
      return EXTENDED_PROFILE_PROMPT;
    case 'full':
    default:
      // Full profile uses the main EXTRACTION_SYSTEM_PROMPT
      return null;
  }
}

/**
 * Required fields for each profile (used for confidence scoring)
 */
export const PROFILE_REQUIRED_FIELDS: Record<EdmProfile, string[]> = {
  essential: [
    'core.anchor',
    'core.spark',
    'constellation.emotion_primary',
    'constellation.emotion_subtone',
    'constellation.narrative_arc',
  ],
  extended: [
    'core.anchor',
    'core.spark',
    'core.narrative',
    'constellation.emotion_primary',
    'constellation.emotion_subtone',
    'constellation.narrative_arc',
    'constellation.relational_dynamics',
    'constellation.temporal_context',
    'constellation.memory_type',
    'milky_way.event_type',
    'gravity.emotional_weight',
    'gravity.valence',
    'gravity.tether_type',
    'gravity.recurrence_pattern',
    'gravity.strength_score',
  ],
  full: [
    'core.anchor',
    'core.spark',
    'core.narrative',
    'constellation.emotion_primary',
    'constellation.emotion_subtone',
    'constellation.narrative_arc',
    'constellation.relational_dynamics',
    'constellation.temporal_context',
    'constellation.memory_type',
    'constellation.narrative_archetype',
    'milky_way.event_type',
    'milky_way.associated_people',
    'gravity.emotional_weight',
    'gravity.valence',
    'gravity.tether_type',
    'gravity.recall_triggers',
    'gravity.retrieval_keys',
    'gravity.recurrence_pattern',
    'gravity.strength_score',
    'impulse.drive_state',
    'impulse.motivational_orientation',
  ],
};

/**
 * Calculate profile-aware confidence score
 * Only scores required fields for the declared profile
 */
export function calculateProfileConfidence(
  extracted: Record<string, Record<string, unknown>>,
  profile: EdmProfile
): number {
  const requiredFields = PROFILE_REQUIRED_FIELDS[profile] ?? PROFILE_REQUIRED_FIELDS.extended;
  let populated = 0;

  for (const fieldPath of requiredFields) {
    const parts = fieldPath.split('.');
    const domain = parts[0];
    const field = parts[1];
    if (!domain || !field) continue;
    const value = extracted[domain]?.[field];

    // Check if field is populated
    if (value !== null && value !== undefined && value !== '') {
      if (Array.isArray(value)) {
        if (value.length > 0) populated++;
      } else {
        populated++;
      }
    }
  }

  return Math.round((populated / requiredFields.length) * 100) / 100;
}
