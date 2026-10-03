# Canonical JSON v1

## Purpose
Defines Canonical JSON v1 encoding used for hashing configuration objects, policy records, and deterministic manifests (Tier 1).

## Invariants
- Tier 1: encoding must be identical for same logical value.
- Allowed value types for hashed configs: object, array, string, boolean, null, integer. Floats forbidden.
- UTF-8 output; object keys sorted lexicographically by Unicode scalar values; no whitespace outside strings.
- Hash: BLAKE3(canonical_json_bytes).

## Acceptance Tests
- Golden vector tests validate canonical bytes; separate tests check hash stability.
- Float rejection tests return `KC_CANON_JSON_FLOAT_FORBIDDEN`.

## Algorithm (v1)
Pseudocode:
1) Parse JSON into internal value type with allowed types.
2) Serialize without whitespace:
   - object: `{` + pairs sorted by key + `}`
   - array: `[` + elements in order + `]`
   - string: JSON escaping; do not escape `/`
   - integer: base-10 ASCII, no leading zeros except `0`
   - bool/null: `true`/`false`/`null`

## Tie-break rules
- Object keys sorted lexicographically by Unicode scalar values.

## Version boundary behavior
- Any encoding rule change is Tier 1 breaking: bump Canonical JSON version and update dependent hashes and golden vectors.

## Error codes
- `KC_CANON_JSON_PARSE_FAILED`
- `KC_CANON_JSON_FLOAT_FORBIDDEN`

## Reference API (kc_core)
- `canon_json::to_canonical_bytes(value: &serde_json::Value) -> AppResult<Vec<u8>>`
- `canon_json::hash_canonical(value: &serde_json::Value) -> AppResult<String>`  // returns `blake3:<hex>`
