# Security Readiness Checkpoint - 2026-06-19

## Purpose
Capture the current security/readiness state after the June 2026 audit, first desktop boundary-hardening slice, and dependency gate refresh.

## Verified Current State
- Canonical repo path: `/Users/d/Projects/knowledgecore`.
- Canonical branch: `main`.
- Working tree was clean before the hardening slice.
- KnowledgeCore remains local-first by default.
- Optional S3 sync support exists and must remain explicitly configured.
- No vault format migration, crypto migration, private document ingest, or cloud operation was performed during this checkpoint.

## Verification Evidence
| Command | Result | Notes |
|---|---|---|
| `cargo fmt --all -- --check` | PASS | Formatting gate. |
| `cargo test --workspace --exclude apps_desktop_tauri` | PASS | Main Rust workspace gate. |
| `cargo test -p kc_core` | PASS | Full core gate after sync-auth helper and recovery verifier hardening. |
| `cargo test -p kc_core --test db_encryption` | PASS | DB encryption lifecycle coverage pins unsupported metadata, idempotent encrypted-state detection, wrong-key failure, and migration artifact cleanup. |
| `cargo test -p kc_cli db_encrypt_enable_and_migrate_round_trip` | PASS | CLI DB-encryption status reports derived lifecycle state. |
| `cargo test -p kc_cli recovery` | PASS | CLI recovery generate/verify and escrow restore paths accept the stricter verifier. |
| `cargo test -p apps_desktop_tauri` | PASS | Desktop config, RPC, and RPC schema tests. |
| `cargo build -p apps_desktop_tauri` | PASS | Tauri crate accepts the desktop config and capability manifest. |
| `cargo test -p apps_desktop_tauri rpc_vault_lock_status_unlock_and_lock_round_trip` | PASS | Tauri lock-status RPC includes derived DB encryption state. |
| `cargo test -p kc_core recovery` | PASS | Recovery verifier now proves decrypt/restore behavior and rejects matching-hash forged blobs. |
| `cargo test -p kc_core recovery_restore_drill_unlocks_generated_encrypted_fixture` | PASS | Generated-fixture recovery drill proves restored passphrase decrypts an encrypted object-store fixture inside recovery module test scope. |
| `cargo test -p kc_core ingest_resource_limit_rejects_oversized_generated_payload` | PASS | Opt-in ingest byte limit rejects generated oversized payload before events/docs writes. |
| `cargo test -p kc_core unpack_zip_snapshot_limits` | PASS | Opt-in sync snapshot zip limits reject generated oversized archive/entry-count fixtures without extraction writes. |
| `cargo test -p kc_extract pdf_resource_limits` | PASS | Opt-in PDF extraction limits reject generated oversized input and extracted text. |
| `cargo test -p kc_index vector_resource_limits` | PASS | Opt-in vector limits reject generated oversized batch/text fixtures without persisting rows. |
| `cargo test -p kc_core rpc_scan_folder_resource_limit_rejects_deep_generated_tree_before_ingesting` | PASS | Core/RPC scan-folder boundary enforces production depth defaults before doc writes. |
| `cargo test -p kc_cli cli_scan_folder_resource_limit_rejects_deep_generated_tree_before_ingesting` | PASS | CLI scan-folder enforces production depth defaults before doc writes. |
| `node ./scripts/audit-rust.mjs` | PASS | Zero vulnerabilities; 16 reviewed informational warnings remain with `review_by` `2026-07-19`. |
| `node ./scripts/dependency-watch.mjs --no-fail` | PASS | Advisory mode confirms watched dependencies are current. |
| `node ./scripts/dependency-watch.mjs` | PASS | Strict mode confirms `tauri`, `tauri-utils`, `lancedb`, `lance`, and `lance-index` are current. |
| `pnpm install --frozen-lockfile` | BLOCKED | Explicit user approval was given, but the Codex tool policy rejected the install with `approval required by policy, but AskForApproval is set to Never`. Rechecked in the Codex follow-up lane with the same result. |
| `pnpm install --offline --frozen-lockfile --ignore-scripts` | BLOCKED | Offline local install is rejected by the same tool policy. |
| `pnpm -C apps/desktop/ui lint` | BLOCKED | Repo-local `apps/desktop/ui/node_modules` is absent, so `eslint` is not available until a local install can run. |
| `pnpm -C apps/desktop/ui test` | BLOCKED | Repo-local `apps/desktop/ui/node_modules` is absent, so `vitest` is not available until a local install can run. |
| `pnpm -C apps/desktop/ui build` | BLOCKED | Repo-local `apps/desktop/ui/node_modules` is absent, so `vite` is not available until a local install can run. |
| `pnpm fetch --frozen-lockfile --prod=false` | PASS | Populated repo-local pnpm virtual-store content under `node_modules/.pnpm` without creating usable package links. |
| `pnpm --filter knowledgecore-ui deploy /tmp/knowledgecore-ui-deploy-codex-1781859269 --offline --prod=false --legacy` | PASS | Created a temp UI package with lockfile versions; no repo-local `apps/desktop/ui/node_modules` was created. |
| `/tmp/knowledgecore-ui-deploy-codex-1781859269/node_modules/.bin/eslint "src/**/*.{ts,tsx}"` | PASS | Exact lockfile deployed versions. |
| `/tmp/knowledgecore-ui-deploy-codex-1781859269/node_modules/.bin/vitest run` | PASS | Exact lockfile deployed versions after linking missing `@rolldown/binding-darwin-arm64` from the repo pnpm virtual store into the temp deploy. |
| `/tmp/knowledgecore-ui-deploy-codex-1781859269/node_modules/.bin/vite build --config vite.config.ts` | PASS | Exact lockfile deployed versions after the same temp-only native binding link. |
| `/tmp/knowledgecore-ui-deploy-codex-1781859269/node_modules/.bin/tsc --noEmit --project tsconfig.json` | PASS | Exact lockfile deployed versions. |
| `/tmp/knowledgecore-ui-deploy-state-1781862044/node_modules/.bin/tsc --noEmit --project tsconfig.json` | PASS | Fresh temp deploy from current source verifies the widened lock-status RPC type. |
| `/tmp/knowledgecore-ui-deploy-state-1781862044/node_modules/.bin/vitest run` | PASS | Fresh temp deploy after temp-only `@rolldown/binding-darwin-arm64` link. |

## Hardening Applied
- Desktop window now has a stable `main` label.
- Desktop CSP is no longer `null`; it is restricted to local app content, Tauri IPC, local asset loading, and no object/form/frame embedding.
- Desktop capability manifest now binds the local `main` window without granting core plugin APIs or remote URL access.
- Regression tests pin the CSP, local-only window binding, and empty core/plugin permission posture.
- Watched desktop/index dependencies were refreshed: `tauri` `2.11.3`, `tauri-utils` `2.9.3`, `lancedb` `0.30.0`, `lance` `7.0.0`, and `lance-index` `7.0.0`.
- `kc_index` direct Arrow dependencies now align with the LanceDB 0.30 graph at Arrow 58.
- Stale dependency-watch and RustSec policy entries for removed LanceDB/Tantivy/Rand transitives were pruned.
- Sync authorship hardening is captured as an approval-gated plan in `docs/20-sync-authorship-hardening-plan-2026-06-19.md`.
- UI lint, test, build, and typecheck gates passed from a temp deploy using lockfile package versions because repo-local `pnpm install` remains tool-policy blocked; `node_modules/.pnpm` content exists, but `apps/desktop/ui/node_modules` is still absent.
- Compatible Ed25519 sync authorship verification is now wired for v3 heads: incoming heads prefer Ed25519 verification against the trusted device public key and verified certificate chain, with legacy BLAKE3-derived signatures still accepted for compatibility.
- S3 sync emits Ed25519 author signatures only when `KC_SYNC_AUTHOR_SIGNING_KEY_HEX` is explicitly provided and matches the verified local author device key; otherwise it preserves legacy v3 signature emission.
- Sync head parsing now supports optional `author_signature_alg = "ed25519_sync_head_v1"` as a v3 extension. Declared Ed25519 heads must pass Ed25519 verification and cannot fall back to legacy BLAKE3-derived signatures; unknown declared algorithms fail closed.
- Local sync signing key custody is now implemented behind explicit trust-device enrollment: schema v12 adds `sync_signing_keys`, private Ed25519 seeds are encrypted with XChaCha20-Poly1305 using the vault unlock passphrase boundary, CLI/desktop surfaces expose enrollment/status/soft-delete/rotation controls, and S3 sync emits `author_signature_alg = "ed25519_sync_head_v1"` only when the custody key is unlocked and matches the verified local author device.
- Read-only sync auth readiness reporting is now exposed through CLI/core-service/desktop RPC and classifies remote heads without writes, migrations, fallback removal, cloud expansion, or strict-mode enforcement.
- Sync auth rollout evidence now includes generated readiness fixtures and a multi-target CLI summary that counts strict-ready, strict-blocked, legacy-fallback-dependent, invalid, and per-classification targets without creating missing targets.
- Read-only `sync auth-strict-check` now provides an opt-in rollout gate that fails with `KC_SYNC_AUTH_STRICT_BLOCKED` unless every provided target is strict-ready. Default strict pull also blocks non-strict-ready remote heads before apply, explicit compatibility pull remains available, and push behavior, target contents, and vault formats remain unchanged.
- Default strict sync auth for pull entrypoints is now captured in `docs/26-sync-default-strict-auth-rollout-plan-2026-06-19.md`; explicit compatibility pull remains available, and legacy fallback removal remains unimplemented until separately approved.
- Sync signing-key status/delete surfaces now return explicit re-enrollment guidance when local custody is missing, retired, or deleted; the guidance states private signing keys are not recoverable and does not add export, escrow, restore, cloud custody, or sync writer behavior.
- Recovery verification now decrypts `key_blob.enc` with the recovery phrase-derived key, checks the deterministic recovery nonce, rejects empty restored passphrases, and includes regressions for matching-hash forged blobs that cannot decrypt.
- DB encryption lifecycle tests now pin unsupported mode/KDF rejection, idempotent already-encrypted migration detection, wrong-key failure for encrypted DB migration, and absence of stale `.sqlcipher.tmp` / `.pre-sqlcipher.bak` artifacts after successful migration.
- SQLCipher production state semantics are captured as an approval-gated design note in `docs/21-sqlcipher-state-model-plan-2026-06-19.md`; the documented decision is a future `vault.json` v4 `db_encryption.state` boundary, with no schema or runtime behavior changed in this lane.
- SQLCipher status-only state derivation now reports v3/v4-equivalent states through core status, CLI DB-encryption JSON, and Tauri lock-status RPC without persisting `db_encryption.state` or rewriting vault files.
- Recovery restore drill and resource guardrails are captured as an approval-gated implementation plan in `docs/22-recovery-drill-and-resource-guardrails-plan-2026-06-19.md`; the plan uses generated fixtures only and does not change runtime limits, vault formats, or cloud behavior.
- Generated-fixture recovery restore drill tests now prove the recovery blob restores the vault passphrase and that the restored passphrase decrypts a generated encrypted object-store fixture; missing bundle-file coverage is pinned with `KC_RECOVERY_BUNDLE_INVALID`.
- Opt-in resource-limit helpers and generated-fixture tests now cover ingest byte limits, sync snapshot zip archive/entry limits, PDF extraction input/output byte limits, and vector batch/text limits with `KC_RESOURCE_LIMIT_EXCEEDED`.
- Approved production resource-limit defaults and wiring slices are captured in `docs/23-production-resource-limits-decision-2026-06-19.md`; CLI/RPC ingest, default PDF byte extraction, OCR page-count validation, S3 sync pull zip extraction, filesystem snapshot directory apply preflight, and CLI index rebuild now pass default limits.

## Current Risk Posture
- High: sync head v3 authorship now supports Ed25519 verification, encrypted local key custody, env-key signing, and strict declared-algorithm enforcement, but undeclared legacy BLAKE3-derived signatures are still accepted for compatibility until fallback removal is approved.
- High: object-store KDF metadata still has a constant default salt id. Any per-vault random salt change requires explicit migration design approval.
- High: SQLCipher enable/migrate lifecycle has status-only state derivation and a v4 explicit-state decision, but persisting `db_encryption.state` remains approval-gated.
- Medium: recovery verification, generated-fixture restore drill coverage, opt-in resource-limit tests, and approved production resource-limit wiring slices are in place; future resource-limit work should focus on compatibility tuning and any newly approved surfaces.
- Medium: AWS recovery escrow code remains emulation-gated at runtime despite docs describing an AWS SDK backend.
- Medium: OIDC/device identity flows remain local/simulated unless a real token/JWKS verification design is approved.
- Medium: PDF/OCR extraction now has byte and OCR page-count guardrails; maximum page limits for non-OCR PDF text extraction remain a future design decision if needed.
- Medium: RustSec still reports 16 reviewed informational warnings, mostly GTK3/Tauri Linux backend transitives plus macro/unicode transitives; they are policy-gated for review by `2026-07-19`.

## Approval Gates
- Do not weaken crypto or change key derivation parameters without design approval and test vectors.
- Do not change vault formats or schema metadata without migration design, fixture updates, and rollback coverage.
- Do not run data migrations, ingest private documents, or scan broad local paths without explicit target-path approval.
- Do not introduce background sync or new cloud sync behavior without explicit design approval.
- Do not promote S3 sync, managed identity, or recovery escrow to production-ready until their current risk items are resolved and verified.

## Next Recommended Lane
1. Decide whether to proceed with the v4 `db_encryption.state` schema implementation and compatibility fixtures.
2. Decide whether non-OCR PDF page-count limits are needed beyond the current PDF byte and OCR page-count guardrails.
3. Plan the next RustSec review before `2026-07-19`, especially the GTK3/Tauri Linux backend chain and the remaining macro/unicode transitives.
4. Restore repo-local UI dependencies in a non-blocked environment if local `pnpm lint`, `pnpm test`, and `pnpm -C apps/desktop/ui build` must be run exactly in place rather than from a temp deploy.
