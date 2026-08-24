# Document Lifecycle Events and Federation Query V2

## Scope and ownership

KnowledgeCore remains canonical for private documents, canonical text, vault
access, provenance, and document lifecycle. This contract adds no lifecycle
table, second store, cache, migration, backfill, or physical deletion path.
Lifecycle truth is appended to the existing hash-linked owner event chain.

The V1 federation contract remains unchanged and honestly reports correction
and deletion as unsupported or unknown. Only the strict V2 contract interprets
the lifecycle events defined here.

## Owner lifecycle request and event

`knowledgecore_document_lifecycle_request.v1` accepts one owner mutation:

- `supersede`, with one distinct replacement document identity; or
- `tombstone`, with no replacement.

Every request carries a canonical source document ID, an explicit subject,
bounded reason, and caller-controlled effective time. The mutation is denied
unless the existing policy engine returns an explicit allow for action
`document.lifecycle.write` and the source document. Existing role names do not
implicitly grant this permission.

An accepted request appends `knowledgecore_document_lifecycle_event.v1` as
either `document.lifecycle.superseded.v1` or
`document.lifecycle.tombstoned.v1`. The event pins:

- source document ID and current canonical hash;
- replacement document ID and current canonical hash for supersession;
- authorized subject, bounded owner reason, and effective time.

The public federation notice exposes a BLAKE3 digest of the reason, never the
raw reason. Owner storage retains the raw event for audit.

## Resolution and failure rules

Resolution follows supersession edges until an active or tombstoned terminal
document. A source with more than one lifecycle event is `conflicted`; no event
order, timestamp, or score chooses a winner. A cycle, missing source or
replacement, malformed event, event-chain mismatch, changed pinned canonical
hash, or depth over 100 fails the lifecycle-aware source as `corrupt`.

The supported mutation path prevents a second transition on the same source
and prevents selecting an already transitioned replacement. The resolver still
recognizes conflict or corruption in imported, damaged, or concurrent owner
event data rather than masking it.

Tombstone means logical suppression from default federation results. It does
not remove `docs`, `canonical_text`, `objects`, or object-store bytes and is not
proof of physical erasure. Physical deletion remains outside this contract.

## Federation V2

`knowledgecore_federation_query_request.v2` retains the bounded V1 request
shape and limits. `knowledgecore_federation_query_result.v2` adds:

- `match_disposition`: `none`, `active`, `suppressed`,
  `active_and_suppressed`, `conflicted`, or `unknown`;
- active facts explicitly marked `lifecycle_state=active`;
- content-free `lifecycle_notices` bound to source/replacement document hashes,
  event IDs, event hashes, event times, authorized subjects, and reason digests.

The V2 query verifies the complete owner event chain before participation. An
active matching document may return bounded content only when requested. A
matching superseded, tombstoned, or conflicted document returns a lifecycle
notice and no snippet or historical content. Active and suppressed matches can
coexist. Conflicts remain visible and never collapse into consensus.

`fresh` means the query completed against the verified owner event-chain
revision exposed in `source_revision` and `binding`. It does not claim current
installed-runtime adoption, delegated read authorization, scheduler state,
provider state, or human use.

## RPC and compatibility

The local-owner Tauri surface adds `federation_query_v2` and
`document_lifecycle_mutate`. Tauri remains thin orchestration over `kc_core`.
Both request shapes reject unknown fields. V1 callers remain compatible and do
not receive inferred lifecycle semantics.

Changing lifecycle actions, hash binding, policy action, conflict resolution,
logical-deletion behavior, result binding, content suppression, or instruction
boundary requires a schema version bump and schema/runtime/RPC tests.
