# Sync v1 Filesystem Snapshots

## Purpose
Define deterministic push/pull synchronization against a filesystem target using immutable snapshot folders and a deterministic conflict artifact.

## Invariants
- Sync target is a directory containing `head.json`, `snapshots/`, and `conflicts/`.
- Snapshot ids are deterministic hashes derived from manifest hash + `now_ms`.
- Conflict handling never auto-merges; it emits a deterministic conflict artifact and fails.
- Pull applies only top-level snapshot data trees (`db`, `store`, `index`) and never mutates `vault.json`.
- Snapshot archive size, extracted entry count, and extraction path validation are resource and safety boundaries; production default changes require explicit approval.

## Non-goals
- Bidirectional merge strategies.
- Remote transport protocols.
- Background sync daemons.

## Interface contract
- Core service operations: `sync_status`, `sync_push`, `sync_pull`.
- CLI operations:
  - `kc_cli sync status <vault_path> <target_path>`
  - `kc_cli sync push <vault_path> <target_path> --now-ms <ms>`
  - `kc_cli sync pull <vault_path> <target_path> --now-ms <ms>`
- RPC operations:
  - `sync_status`, `sync_push`, `sync_pull`

## Determinism and ordering rules
- Snapshot copies are written in sorted path order.
- Conflict artifact JSON is canonicalized.
- Conflict artifact filename is deterministic from `now_ms` and artifact hash prefix.

## Failure modes and AppError mapping
- `KC_SYNC_TARGET_INVALID` for missing/invalid target structures.
- `KC_SYNC_STATE_FAILED` for local sync state read/write failures.
- `KC_SYNC_CONFLICT` for detected divergence with emitted conflict artifact.
- `KC_SYNC_APPLY_FAILED` for snapshot-apply failures.

## Acceptance tests
- Clean push writes head + snapshot and updates local sync state.
- Clean pull applies remote snapshot content to local vault.
- Divergence emits deterministic conflict artifact and hard-fails.
- Oversized or path-unsafe snapshot fixtures fail deterministically without writing outside the temp vault.
- RPC and CLI contract tests pass.

## Rollout gate
- N2 Rust + desktop gates pass.

## Stop conditions
- Any automatic merge behavior appears.
- Conflict artifact omission on divergence.
- Non-deterministic snapshot or conflict ordering.
