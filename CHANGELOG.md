# Changelog

All notable changes to ddna-tools will be documented in this file.
(Started at v0.4.0; earlier releases are summarised below.)

### v0.4.0

Extraction parity with deepadata-edm-sdk 0.8.9 extraction semantics.
Emitted artifacts remain EDM v0.8.0 — `experiential_stance` never enters
the artifact body.

- feat(prompts): all three canonical-profile prompts now require a
  top-level `experiential_stance` classification (lived | witnessed |
  quoted_third_party | assistant_generated | hypothetical) and forbid
  encoding non-subject material into subject significance fields. Prompt
  text is copied verbatim from the SDK so golden-vector parity holds.
- feat(prompts): subject-anchored significance scoring —
  `emotional_weight` measures what the content meant TO THE SUBJECT,
  routine work content is calibrated 0.1–0.4, and
  `transformational_pivot` requires the subject explicitly marking the
  experience life-changing.
- feat(guard): deterministic experiential-stance attribution guard,
  always on in all three provider extractors (Anthropic, OpenAI, Kimi).
  On a non-subject stance it clears `core.wound`,
  `constellation.{identity_thread, expressed_insight, somatic_signature}`,
  forces `transformational_pivot=false`, nulls the impulse domain, and
  floors `gravity.emotional_weight` / `gravity.strength_score` at 0.2.
  `witnessed` is a subject stance and is not demoted. The SDK's optional
  LLM classifier verification layer is commercial-path and intentionally
  not included; the deterministic guard is the OSS floor.
- feat(api): `LlmExtractionResult` gains `experientialStance` and
  `stanceFieldsCleared`; `notes` now carries the stance telemetry note
  (surfaces as `telemetry.extraction_notes` in full-profile artifacts).
  New exports: `EXPERIENTIAL_STANCE`, `ExperientialStance`,
  `isNonSubjectStance`, `takeStance`, `applyStanceGuard`, `consumeStance`.
- feat(cli): `ddna extract` reports stance and any guard demotions in the
  file-output summary; `--json` carries them in the extraction result.
- docs(readme): documented the conversation-input boundary — extraction
  takes flat text; the SDK's `frameTranscript` / `chunkConversation`
  conversation layer is not part of this path.
- test: per-stance demotion contract and profile × stance artifact
  conformance against the bundled v0.8.0 schemas (no stance leakage,
  Ajv-valid, demotions are explicit nulls).

### v0.3.0

- Open extraction (ADR-0023): canonical-profile extraction (essential /
  extended / full) for Anthropic, OpenAI, and Kimi under MIT, BYOK.
  Partner profiles remain registry-gated per EDM spec §3.7.6.

### v0.2.0 and earlier

- Seal, verify, inspect, keygen, validate, redact, check-ttl — .ddna
  envelope tooling (Ed25519, RFC 8785 JCS, W3C Data Integrity).
