import { describe, expect, it } from "vitest";
import type { DesktopRpcApi, RpcResp } from "../src/api/rpc";
import { askQuestion } from "../src/features/ask";
import { loadDocumentRange } from "../src/features/document";
import { listEvents, listJobs } from "../src/features/events";
import { exportBundle, verifyBundle } from "../src/features/exportVerify";
import {
  ingestInboxStart,
  ingestInboxStop,
  ingestScanFolder
} from "../src/features/ingest";
import {
  acquireLineageScopeLock,
  acquireLineageLock,
  addLineageOverlay,
  addLineagePolicy,
  bindLineagePolicy,
  grantLineageRole,
  listLineagePolicies,
  listLineageRoles,
  listLineageOverlays,
  loadLineageLockStatus,
  queryLineage,
  queryLineageV2,
  releaseLineageLock,
  revokeLineageRole,
  removeLineageOverlay
} from "../src/features/lineage";
import { loadRelated } from "../src/features/related";
import { runSearch } from "../src/features/search";
import {
  addVaultRecoveryEscrowProvider,
  completeTrustIdentity,
  enrollTrustDevice,
  enableVaultEncryption,
  listTrustDevices,
  generateVaultRecovery,
  loadVaultRecoveryEscrowStatus,
  listVaultRecoveryEscrowProviders,
  enableVaultRecoveryEscrow,
  rotateAllVaultRecoveryEscrow,
  rotateVaultRecoveryEscrow,
  restoreVaultRecoveryEscrow,
  lockVault,
  loadVaultLockStatus,
  loadVaultRecoveryStatus,
  loadSettingsDependencies,
  loadSyncMergePreview,
  loadSyncStatus,
  loadVaultEncryptionStatus,
  migrateVaultEncryption,
  runSyncPull,
  runSyncPush,
  startTrustIdentity,
  verifyVaultRecovery,
  verifyTrustDeviceChain,
  unlockVault
} from "../src/features/settings";
import { vaultInit, vaultOpen } from "../src/features/vault";

function ok<T>(data: T): Promise<RpcResp<T>> {
  return Promise.resolve({ ok: true, data });
}

function mockApi(): DesktopRpcApi {
  return {
    vaultInit: () => ok({ vault_id: "v1" }),
    vaultOpen: () => ok({ vault_id: "v1", vault_slug: "demo" }),
    trustIdentityStart: () =>
      ok({
        provider_id: "default",
        state: "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        authorization_url: "https://default.oidc.knowledgecore.local?aud=kc-desktop:default"
      }),
    trustIdentityComplete: () =>
      ok({
        session_id: "11111111-1111-1111-1111-111111111111",
        provider_id: "default",
        subject: "alice@example.com",
        expires_at_ms: 12345
      }),
    trustDeviceEnroll: () =>
      ok({
        device_id: "22222222-2222-2222-2222-222222222222",
        label: "desktop",
        fingerprint: "aaaaaaaa:bbbbbbbb:cccccccc:dddddddd:eeeeeeee:ffffffff:11111111:22222222",
        cert_id: "33333333-3333-3333-3333-333333333333",
        cert_chain_hash:
          "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      }),
    trustDeviceVerifyChain: () =>
      ok({
        cert_id: "33333333-3333-3333-3333-333333333333",
        device_id: "22222222-2222-2222-2222-222222222222",
        provider_id: "default",
        subject: "alice@example.com",
        cert_chain_hash:
          "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        verified_at_ms: 42,
        expires_at_ms: 12345
      }),
    trustDeviceList: () =>
      ok({
        devices: [
          {
            device_id: "22222222-2222-2222-2222-222222222222",
            label: "desktop",
            fingerprint:
              "aaaaaaaa:bbbbbbbb:cccccccc:dddddddd:eeeeeeee:ffffffff:11111111:22222222",
            verified_at_ms: 42,
            created_at_ms: 41
          }
        ]
      }),
    trustProviderAdd: () =>
      ok({
        provider_id: "default",
        issuer: "https://default.oidc.knowledgecore.local",
        audience: "kc-desktop:default",
        jwks_url: "https://default.oidc.knowledgecore.local/.well-known/jwks.json",
        enabled: true,
        created_at_ms: 42,
        updated_at_ms: 42
      }),
    trustProviderDisable: () =>
      ok({
        provider_id: "default",
        issuer: "https://default.oidc.knowledgecore.local",
        audience: "kc-desktop:default",
        jwks_url: "https://default.oidc.knowledgecore.local/.well-known/jwks.json",
        enabled: false,
        created_at_ms: 42,
        updated_at_ms: 43
      }),
    trustProviderList: () =>
      ok({
        providers: [
          {
            provider_id: "default",
            issuer: "https://default.oidc.knowledgecore.local",
            audience: "kc-desktop:default",
            jwks_url: "https://default.oidc.knowledgecore.local/.well-known/jwks.json",
            enabled: true,
            created_at_ms: 42,
            updated_at_ms: 42
          }
        ]
      }),
    trustProviderDiscover: () =>
      ok({
        provider_id: "default",
        issuer: "https://default.oidc.knowledgecore.local",
        audience: "kc-desktop:default",
        jwks_url: "https://default.oidc.knowledgecore.local/.well-known/jwks.json",
        enabled: true,
        created_at_ms: 42,
        updated_at_ms: 42
      }),
    trustPolicySet: () =>
      ok({
        provider_id: "default",
        max_clock_skew_ms: 300000,
        require_claims_json: "{\"tenant\":\"demo\"}",
        updated_at_ms: 44
      }),
    trustPolicySetTenantTemplate: () =>
      ok({
        provider_id: "default",
        max_clock_skew_ms: 300000,
        require_claims_json: "{\"tenant\":\"demo\"}",
        updated_at_ms: 45
      }),
    vaultLockStatus: () =>
      ok({
        db_encryption_enabled: true,
        unlocked: true,
        mode: "sqlcipher_v4",
        key_reference: "vaultdb:v1"
      }),
    vaultUnlock: () =>
      ok({
        status: {
          db_encryption_enabled: true,
          unlocked: true,
          mode: "sqlcipher_v4",
          key_reference: "vaultdb:v1"
        }
      }),
    vaultLock: () =>
      ok({
        status: {
          db_encryption_enabled: true,
          unlocked: false,
          mode: "sqlcipher_v4",
          key_reference: "vaultdb:v1"
        }
      }),
    vaultEncryptionStatus: () =>
      ok({
        enabled: false,
        mode: "object_store_xchacha20poly1305",
        key_reference: null,
        kdf_algorithm: "argon2id",
        objects_total: 1,
        objects_encrypted: 0
      }),
    vaultEncryptionEnable: () =>
      ok({
        status: {
          enabled: true,
          mode: "object_store_xchacha20poly1305",
          key_reference: "vault:v1",
          kdf_algorithm: "argon2id",
          objects_total: 1,
          objects_encrypted: 0
        }
      }),
    vaultEncryptionMigrate: () =>
      ok({
        status: {
          enabled: true,
          mode: "object_store_xchacha20poly1305",
          key_reference: "vault:v1",
          kdf_algorithm: "argon2id",
          objects_total: 1,
          objects_encrypted: 1
        },
        migrated_objects: 1,
        already_encrypted_objects: 0,
        event_id: 42
      }),
    vaultRecoveryStatus: () =>
      ok({
        vault_id: "v1",
        encryption_enabled: true,
        last_bundle_path: null
      }),
    vaultRecoveryGenerate: () =>
      ok({
        bundle_path: "/tmp/recovery",
        recovery_phrase: "abcd1234-efgh5678-ijkl9012-mnop3456",
        manifest: {
          schema_version: 2,
          vault_id: "v1",
          created_at_ms: 7,
          phrase_checksum:
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          payload_hash:
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
      }),
    vaultRecoveryEscrowStatus: () =>
      ok({
        enabled: true,
        provider: "aws",
        provider_available: true,
        updated_at_ms: 8,
        details_json: "{}"
      }),
    vaultRecoveryEscrowEnable: () =>
      ok({
        status: {
          enabled: true,
          provider: "aws",
          provider_available: true,
          updated_at_ms: 8,
          details_json: "{}"
        }
      }),
    vaultRecoveryEscrowRotate: () =>
      ok({
        status: {
          enabled: true,
          provider: "aws",
          provider_available: true,
          updated_at_ms: 9,
          details_json: "{}"
        },
        bundle_path: "/tmp/recovery",
        recovery_phrase: "abcd1234-efgh5678-ijkl9012-mnop3456",
        manifest: {
          schema_version: 2,
          vault_id: "v1",
          created_at_ms: 9,
          phrase_checksum:
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          payload_hash:
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
      }),
    vaultRecoveryEscrowRestore: () =>
      ok({
        status: {
          enabled: true,
          provider: "aws",
          provider_available: true,
          updated_at_ms: 10,
          details_json: "{}"
        },
        bundle_path: "/tmp/recovery",
        restored_bytes: 42,
        manifest: {
          schema_version: 2,
          vault_id: "v1",
          created_at_ms: 9,
          phrase_checksum:
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          payload_hash:
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
      }),
    vaultRecoveryEscrowProviderAdd: () =>
      ok({
        provider: {
          provider: "aws",
          priority: 0,
          config_ref: "kms://alias/kc",
          enabled: true,
          provider_available: true,
          updated_at_ms: 10
        }
      }),
    vaultRecoveryEscrowProviderList: () =>
      ok({
        providers: [
          {
            provider: "aws",
            priority: 0,
            config_ref: "kms://alias/kc",
            enabled: true,
            provider_available: true,
            updated_at_ms: 10
          }
        ]
      }),
    vaultRecoveryEscrowRotateAll: () =>
      ok({
        rotated: [
          {
            provider: "aws",
            bundle_path: "/tmp/recovery/aws",
            recovery_phrase: "abcd1234-efgh5678-ijkl9012-mnop3456",
            manifest: {
              schema_version: 2,
              vault_id: "v1",
              created_at_ms: 9,
              phrase_checksum:
                "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              payload_hash:
                "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            updated_at_ms: 10
          }
        ]
      }),
    vaultRecoveryVerify: () =>
      ok({
        manifest: {
          schema_version: 2,
          vault_id: "v1",
          created_at_ms: 7,
          phrase_checksum:
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          payload_hash:
            "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
      }),
    ingestScanFolder: () => ok({ ingested: 2 }),
    ingestInboxStart: () => ok({ job_id: "j1", doc_id: "d1" }),
    ingestInboxStop: () => ok({ stopped: true }),
    searchQuery: () => ok({ hits: [{ doc_id: "d1", score: 1, snippet: "s" }] }),
    locatorResolve: () => ok({ text: "doc text" }),
    exportBundle: () => ok({ bundle_path: "/tmp/bundle" }),
    verifyBundle: () => ok({ exit_code: 0, report: {} }),
    askQuestion: () => ok({ answer_text: "a", trace_path: "/tmp/trace" }),
    eventsList: () => ok({ events: [{ event_id: 1, ts_ms: 1, event_type: "ingest" }] }),
    jobsList: () => ok({ jobs: ["j1"] }),
    syncStatus: () =>
      ok({
        target_path: "s3://demo-bucket/kc",
        remote_head: null,
        seen_remote_snapshot_id: null,
        last_applied_manifest_hash: null
      }),
    syncPush: () =>
      ok({
        snapshot_id: "snap-1",
        manifest_hash: "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        remote_head: {
          schema_version: 1,
          snapshot_id: "snap-1",
          manifest_hash:
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          created_at_ms: 6
        }
      }),
    syncPull: () =>
      ok({
        snapshot_id: "snap-1",
        manifest_hash: "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        remote_head: {
          schema_version: 1,
          snapshot_id: "snap-1",
          manifest_hash:
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          created_at_ms: 6
        }
      }),
    syncMergePreview: () =>
      ok({
        target_path: "s3://demo-bucket/kc",
        seen_remote_snapshot_id: "snap-0",
        remote_snapshot_id: "snap-1",
        report: {
          schema_version: 2,
          merge_policy: "conservative_plus_v2",
          safe: true,
          generated_at_ms: 8,
          local: {
            object_hashes: [],
            lineage_overlay_ids: []
          },
          remote: {
            object_hashes: [
              "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
            lineage_overlay_ids: []
          },
          overlap: {
            object_hashes: [],
            lineage_overlay_ids: []
          },
          reasons: [],
          decision_trace: ["policy=conservative_plus_v2"]
        }
      }),
    lineageQuery: () =>
      ok({
        schema_version: 1,
        seed_doc_id: "d1",
        depth: 1,
        generated_at_ms: 9,
        nodes: [
          { node_id: "doc:d1", kind: "doc", label: "d1", metadata: {} },
          { node_id: "chunk:c1", kind: "chunk", label: "Chunk 0", metadata: {} }
        ],
        edges: [
          {
            from_node_id: "doc:d1",
            to_node_id: "chunk:c1",
            relation: "contains_chunk",
            evidence: "ordinal:0"
          }
        ]
      }),
    lineageQueryV2: () =>
      ok({
        schema_version: 2,
        seed_doc_id: "d1",
        depth: 1,
        generated_at_ms: 9,
        nodes: [
          { node_id: "doc:d1", kind: "doc", label: "d1", metadata: {} },
          { node_id: "chunk:c1", kind: "chunk", label: "Chunk 0", metadata: {} }
        ],
        edges: [
          {
            from_node_id: "doc:d1",
            to_node_id: "chunk:c1",
            relation: "contains_chunk",
            evidence: "ordinal:0",
            origin: "system"
          }
        ]
      }),
    lineageOverlayAdd: () =>
      ok({
        overlay: {
          overlay_id: "blake3:overlay",
          doc_id: "d1",
          from_node_id: "doc:d1",
          to_node_id: "chunk:c2",
          relation: "supports",
          evidence: "manual",
          created_at_ms: 10,
          created_by: "tester"
        }
      }),
    lineageLockAcquire: () =>
      ok({
        lease: {
          doc_id: "d1",
          owner: "tester",
          token: "blake3:lock-token",
          acquired_at_ms: 10,
          expires_at_ms: 10 + 15 * 60 * 1000
        }
      }),
    lineageLockRelease: () =>
      ok({
        released: true
      }),
    lineageLockStatus: () =>
      ok({
        doc_id: "d1",
        held: true,
        owner: "tester",
        acquired_at_ms: 10,
        expires_at_ms: 10 + 15 * 60 * 1000,
        expired: false
      }),
    lineageRoleGrant: () =>
      ok({
        binding: {
          subject_id: "tester",
          role_name: "editor",
          role_rank: 20,
          granted_by: "desktop",
          granted_at_ms: 10
        }
      }),
    lineageRoleRevoke: () =>
      ok({
        revoked: true
      }),
    lineageRoleList: () =>
      ok({
        bindings: [
          {
            subject_id: "tester",
            role_name: "editor",
            role_rank: 20,
            granted_by: "desktop",
            granted_at_ms: 10
          }
        ]
      }),
    lineagePolicyAdd: () =>
      ok({
        policy: {
          policy_id: "blake3:policy",
          policy_name: "allow-overlay",
          effect: "allow",
          priority: 200,
          condition_json: "{\"action\":\"lineage.overlay.write\"}",
          created_by: "desktop",
          created_at_ms: 10
        }
      }),
    lineagePolicyBind: () =>
      ok({
        binding: {
          subject_id: "tester",
          policy_id: "blake3:policy",
          policy_name: "allow-overlay",
          effect: "allow",
          priority: 200,
          condition_json: "{\"action\":\"lineage.overlay.write\"}",
          bound_by: "desktop",
          bound_at_ms: 10
        }
      }),
    lineagePolicyList: () =>
      ok({
        bindings: [
          {
            subject_id: "tester",
            policy_id: "blake3:policy",
            policy_name: "allow-overlay",
            effect: "allow",
            priority: 200,
            condition_json: "{\"action\":\"lineage.overlay.write\"}",
            bound_by: "desktop",
            bound_at_ms: 10
          }
        ]
      }),
    lineageLockAcquireScope: () =>
      ok({
        lease: {
          scope_kind: "doc",
          scope_value: "d1",
          owner: "tester",
          token: "blake3:scope-lock-token",
          acquired_at_ms: 10,
          expires_at_ms: 10 + 15 * 60 * 1000
        }
      }),
    lineageOverlayRemove: () =>
      ok({
        removed_overlay_id: "blake3:overlay"
      }),
    lineageOverlayList: () =>
      ok({
        overlays: [
          {
            overlay_id: "blake3:overlay",
            doc_id: "d1",
            from_node_id: "doc:d1",
            to_node_id: "chunk:c2",
            relation: "supports",
            evidence: "manual",
            created_at_ms: 10,
            created_by: "tester"
          }
        ]
      })
  };
}

describe("feature controllers", () => {
  it("routes all feature actions through rpc envelopes", async () => {
    const api = mockApi();

    expect(
      await vaultInit(api, { vault_path: "/tmp/v", vault_slug: "demo", now_ms: 1 })
    ).toMatchObject({ kind: "data" });
    expect(await vaultOpen(api, { vault_path: "/tmp/v" })).toMatchObject({
      kind: "data"
    });
    expect(
      await ingestScanFolder(api, {
        vault_path: "/tmp/v",
        scan_root: "/tmp/scan",
        source_kind: "notes",
        now_ms: 2
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await ingestInboxStart(api, {
        vault_path: "/tmp/v",
        file_path: "/tmp/f.txt",
        source_kind: "notes",
        now_ms: 2
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await ingestInboxStop(api, {
        vault_path: "/tmp/v",
        job_id: "j1"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await runSearch(api, {
        vault_path: "/tmp/v",
        query: "q",
        now_ms: 3
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await loadRelated(api, {
        vault_path: "/tmp/v",
        query: "q",
        now_ms: 3
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await loadDocumentRange(api, {
        vault_path: "/tmp/v",
        locator: {
          v: 1,
          doc_id: "d1",
          canonical_hash: "h1",
          range: { start: 0, end: 3 }
        }
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await askQuestion(api, {
        vault_path: "/tmp/v",
        question: "what?",
        now_ms: 4
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await exportBundle(api, {
        vault_path: "/tmp/v",
        export_dir: "/tmp/e",
        include_vectors: true,
        now_ms: 5
      })
    ).toMatchObject({ kind: "data" });
    expect(await verifyBundle(api, { bundle_path: "/tmp/bundle" })).toMatchObject({
      kind: "data"
    });
    expect(await listEvents(api, { vault_path: "/tmp/v" })).toMatchObject({
      kind: "data"
    });
    expect(await listJobs(api, { vault_path: "/tmp/v" })).toMatchObject({
      kind: "data"
    });
    expect(
      await loadSettingsDependencies(api, {
        vault_path: "/tmp/v"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await startTrustIdentity(api, {
        vault_path: "/tmp/v",
        provider: "default",
        now_ms: 1
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await completeTrustIdentity(api, {
        vault_path: "/tmp/v",
        provider: "default",
        code: "auth-code",
        now_ms: 1
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await enrollTrustDevice(api, {
        vault_path: "/tmp/v",
        device_label: "desktop",
        now_ms: 1
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await verifyTrustDeviceChain(api, {
        vault_path: "/tmp/v",
        device_id: "22222222-2222-2222-2222-222222222222",
        now_ms: 1
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await listTrustDevices(api, {
        vault_path: "/tmp/v"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await loadVaultLockStatus(api, {
        vault_path: "/tmp/v"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await unlockVault(api, {
        vault_path: "/tmp/v",
        passphrase: "pass"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await lockVault(api, {
        vault_path: "/tmp/v"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await loadVaultEncryptionStatus(api, {
        vault_path: "/tmp/v"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await enableVaultEncryption(api, {
        vault_path: "/tmp/v",
        passphrase: "pass"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await migrateVaultEncryption(api, {
        vault_path: "/tmp/v",
        passphrase: "pass",
        now_ms: 6
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await loadVaultRecoveryStatus(api, {
        vault_path: "/tmp/v"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await loadVaultRecoveryEscrowStatus(api, {
        vault_path: "/tmp/v"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await enableVaultRecoveryEscrow(api, {
        vault_path: "/tmp/v",
        provider: "aws",
        now_ms: 6
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await addVaultRecoveryEscrowProvider(api, {
        vault_path: "/tmp/v",
        provider: "aws",
        config_ref: "kms://alias/kc",
        now_ms: 6
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await listVaultRecoveryEscrowProviders(api, {
        vault_path: "/tmp/v"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await rotateVaultRecoveryEscrow(api, {
        vault_path: "/tmp/v",
        passphrase: "pass",
        now_ms: 6
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await rotateAllVaultRecoveryEscrow(api, {
        vault_path: "/tmp/v",
        passphrase: "pass",
        now_ms: 6
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await restoreVaultRecoveryEscrow(api, {
        vault_path: "/tmp/v",
        bundle_path: "/tmp/recovery",
        now_ms: 6
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await generateVaultRecovery(api, {
        vault_path: "/tmp/v",
        output_dir: "/tmp/recovery",
        passphrase: "pass",
        now_ms: 6
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await verifyVaultRecovery(api, {
        vault_path: "/tmp/v",
        bundle_path: "/tmp/recovery",
        recovery_phrase: "phrase"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await loadSyncStatus(api, {
        vault_path: "/tmp/v",
        target_path: "s3://demo-bucket/kc"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await runSyncPush(api, {
        vault_path: "/tmp/v",
        target_path: "s3://demo-bucket/kc",
        now_ms: 7
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await runSyncPull(api, {
        vault_path: "/tmp/v",
        target_path: "s3://demo-bucket/kc",
        auto_merge: "conservative_plus_v2",
        now_ms: 8
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await runSyncPull(api, {
        vault_path: "/tmp/v",
        target_path: "s3://demo-bucket/kc",
        auto_merge: "conservative_plus_v3",
        now_ms: 8
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await loadSyncMergePreview(api, {
        vault_path: "/tmp/v",
        target_path: "s3://demo-bucket/kc",
        policy: "conservative_plus_v2",
        now_ms: 8
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await loadSyncMergePreview(api, {
        vault_path: "/tmp/v",
        target_path: "s3://demo-bucket/kc",
        policy: "conservative_plus_v3",
        now_ms: 8
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await queryLineage(api, {
        vault_path: "/tmp/v",
        seed_doc_id: "d1",
        depth: 1,
        now_ms: 9
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await queryLineageV2(api, {
        vault_path: "/tmp/v",
        seed_doc_id: "d1",
        depth: 1,
        now_ms: 9
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await acquireLineageLock(api, {
        vault_path: "/tmp/v",
        doc_id: "d1",
        owner: "tester",
        now_ms: 10
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await loadLineageLockStatus(api, {
        vault_path: "/tmp/v",
        doc_id: "d1",
        now_ms: 10
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await grantLineageRole(api, {
        vault_path: "/tmp/v",
        subject: "tester",
        role: "editor",
        granted_by: "desktop",
        now_ms: 10
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await listLineageRoles(api, {
        vault_path: "/tmp/v"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await addLineagePolicy(api, {
        vault_path: "/tmp/v",
        name: "allow-overlay",
        effect: "allow",
        condition_json: "{\"action\":\"lineage.overlay.write\"}",
        created_by: "desktop",
        now_ms: 10
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await bindLineagePolicy(api, {
        vault_path: "/tmp/v",
        subject: "tester",
        policy: "allow-overlay",
        bound_by: "desktop",
        now_ms: 10
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await listLineagePolicies(api, {
        vault_path: "/tmp/v"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await revokeLineageRole(api, {
        vault_path: "/tmp/v",
        subject: "tester",
        role: "editor"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await acquireLineageScopeLock(api, {
        vault_path: "/tmp/v",
        scope_kind: "doc",
        scope_value: "d1",
        owner: "tester",
        now_ms: 10
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await addLineageOverlay(api, {
        vault_path: "/tmp/v",
        doc_id: "d1",
        from_node_id: "doc:d1",
        to_node_id: "chunk:c2",
        relation: "supports",
        evidence: "manual",
        lock_token: "blake3:lock-token",
        created_at_ms: 10,
        created_by: "tester"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await listLineageOverlays(api, {
        vault_path: "/tmp/v",
        doc_id: "d1"
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await removeLineageOverlay(api, {
        vault_path: "/tmp/v",
        overlay_id: "blake3:overlay",
        lock_token: "blake3:lock-token",
        now_ms: 11
      })
    ).toMatchObject({ kind: "data" });
    expect(
      await releaseLineageLock(api, {
        vault_path: "/tmp/v",
        doc_id: "d1",
        token: "blake3:lock-token"
      })
    ).toMatchObject({ kind: "data" });
  });
});
