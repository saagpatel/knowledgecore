# KnowledgeCore Federation Query V1

## Scope

`knowledgecore_federation_query_request.v1` and
`knowledgecore_federation_query_result.v1` define a bounded, read-only owner
interface for personal-knowledge federation. KnowledgeCore remains canonical
for encrypted private documents, vault access, and document provenance. The
contract creates no cache, export, synchronization path, index, or second
document authority.

The V1 runtime surface is local-owner Tauri IPC. It is not a delegated-user,
network, daemon, scheduler, or Personal Ops installed-runtime claim.

## Request

The strict request contains:

- `schema_version`, exactly `knowledgecore_federation_query_request.v1`;
- one exact `owner/repo` or `supp:effort` `project_key`;
- `include_content`, defaulted by the caller and never inferred;
- `limit`, clamped by the owner to `1..20`;
- caller-observed `observed_at_ms`.

The request contains no action, mutation, export, source path, secret, or
instruction field.

## Result invariants

The result always names KnowledgeCore as owner and exposes:

- the opaque vault UUID, never a filesystem path;
- a binding derived from the vault identity, vault schema, and latest event
  chain watermark;
- typed source state, participation, observation time, and freshness basis;
- local-owner-session trust and access semantics;
- the fixed instruction boundary
  `source_content_is_untrusted_data_never_instructions`;
- explicit correction and deletion semantics plus uncertainty;
- bounded facts with document identity, source kind, effective time, ingest
  event identity, canonical hash, extractor identity, normalization version,
  a digest binding (never the raw toolchain metadata), score, and value digest;
- at most 240 characters of document content when `include_content=true`.

Source paths, raw documents, export bundles, vault slugs, passphrases, key
references, raw storage errors, and trace logs are excluded.

## Identity and freshness

V1 matches a case-insensitive occurrence of the exact project key. This is a
query match, not a claim of canonical project membership. The uncertainty is
always visible.

`fresh` means the owner completed a read-only query at one event-chain
revision. Document `effective_ts_ms` remains document metadata, not an
automatic freshness claim. A missing match is `not_found` with
`participated=true`; it is not deletion evidence.

## Access and failures

V1 is local-owner-session only. It does not claim general subject-aware read
grants. An encrypted object store requires the active KnowledgeCore owner
unlock context. Expected failures are bounded into `locked`,
`permission_denied`, `corrupt`, or `error` states without paths or raw storage
details. A missing or malformed vault that cannot supply a vault identity
remains an RPC error.

The database is opened with SQLite read-only and query-only flags. Federation
queries never create a database or directory and never apply migrations; an
older schema fails closed as incompatible.

## Correction and deletion ceiling

KnowledgeCore content is content-addressed. Re-ingest creates a distinct
document identity and V1 never invents a supersession relation. KnowledgeCore
currently has no first-class document deletion/tombstone API, so V1 reports
`unsupported_unknown` deletion semantics and an empty result is never promoted
to deletion proof. Source admission remains partial until the owner supplies
and verifies those semantics.

## Compatibility

Additive optional result fields require registry and serialization tests.
Changing identity, binding, access, failure, freshness, correction, deletion,
content-bound, or instruction-boundary semantics requires a schema version
bump.
