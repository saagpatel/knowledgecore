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
| `cargo test -p kc_cli recovery` | PASS | CLI recovery generate/verify and escrow restore paths accept the stricter verifier. |
| `cargo test -p apps_desktop_tauri` | PASS | Desktop config, RPC, and RPC schema tests. |
| `cargo build -p apps_desktop_tauri` | PASS | Tauri crate accepts the desktop config and capability manifest. |
| `cargo test -p kc_core recovery` | PASS | Recovery verifier now proves decrypt/restore behavior and rejects matching-hash forged blobs. |
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
- Non-migrating Ed25519 sync authorship verification helpers and tests were added behind the still-unwired `kc_core::sync_auth` module.
- Recovery verification now decrypts `key_blob.enc` with the recovery phrase-derived key, checks the deterministic recovery nonce, rejects empty restored passphrases, and includes regressions for matching-hash forged blobs that cannot decrypt.

## Current Risk Posture
- Critical: sync head v3 authorship is still not a cryptographic Ed25519 signature. The current implementation derives the author signature from public BLAKE3 inputs.
- High: object-store KDF metadata still has a constant default salt id. Any per-vault random salt change requires explicit migration design approval.
- High: SQLCipher enable/migrate lifecycle remains staged and needs a stronger state machine before broad production use.
- Medium: recovery verification now proves core decrypt/restore behavior, but operator-level restore workflow coverage and recovery drill documentation still need to be finished.
- Medium: AWS recovery escrow code remains emulation-gated at runtime despite docs describing an AWS SDK backend.
- Medium: OIDC/device identity flows remain local/simulated unless a real token/JWKS verification design is approved.
- Medium: sync snapshot extraction, recursive ingest, PDF/OCR extraction, and vector persistence still need resource guardrails.
- Medium: RustSec still reports 16 reviewed informational warnings, mostly GTK3/Tauri Linux backend transitives plus macro/unicode transitives; they are policy-gated for review by `2026-07-19`.

## Approval Gates
- Do not weaken crypto or change key derivation parameters without design approval and test vectors.
- Do not change vault formats or schema metadata without migration design, fixture updates, and rollback coverage.
- Do not run data migrations, ingest private documents, or scan broad local paths without explicit target-path approval.
- Do not introduce background sync or new cloud sync behavior without explicit design approval.
- Do not promote S3 sync, managed identity, or recovery escrow to production-ready until their current risk items are resolved and verified.

## Next Recommended Lane
1. Decide key custody and schema transition for wiring Ed25519 signed sync heads into runtime acceptance.
2. Add targeted tests or short design notes for DB encryption lifecycle states, operator-level recovery restore drills, and resource limits.
3. Design-gate the remaining crypto work: per-vault random KDF salt migration and SQLCipher `pending/enabled/migrated` state semantics.
4. Plan the next RustSec review before `2026-07-19`, especially the GTK3/Tauri Linux backend chain and the remaining macro/unicode transitives.
5. Restore repo-local UI dependencies in a non-blocked environment if local `pnpm lint`, `pnpm test`, and `pnpm -C apps/desktop/ui build` must be run exactly in place rather than from a temp deploy.
