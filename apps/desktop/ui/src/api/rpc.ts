export type AppError = {
  schema_version: number;
  code: string;
  category: string;
  message: string;
  retryable: boolean;
  details: unknown;
};

export type RpcOk<T> = { ok: true; data: T };
export type RpcErr = { ok: false; error: AppError };
export type RpcResp<T> = RpcOk<T> | RpcErr;

type TauriInvoke = (cmd: string, args?: unknown) => Promise<unknown>;

function notWired(): RpcErr {
  return {
    ok: false,
    error: {
      schema_version: 1,
      code: "KC_RPC_NOT_WIRED",
      category: "rpc",
      message: "RPC invoke layer is not wired in this runtime",
      retryable: true,
      details: {}
    }
  };
}

function tauriInvoke(): TauriInvoke | null {
  const g = globalThis as Record<string, unknown>;
  const tauri = g.__TAURI__ as
    | { core?: { invoke?: TauriInvoke }; tauri?: { invoke?: TauriInvoke } }
    | undefined;
  return tauri?.core?.invoke ?? tauri?.tauri?.invoke ?? null;
}

export async function rpc<TReq, TRes>(cmd: string, req: TReq): Promise<RpcResp<TRes>> {
  const invoke = tauriInvoke();
  if (!invoke) {
    return notWired();
  }

  try {
    const raw = await invoke(cmd, req as unknown);
    if (typeof raw !== "object" || raw === null || !("ok" in raw)) {
      return {
        ok: false,
        error: {
          schema_version: 1,
          code: "KC_RPC_INVALID_RESPONSE",
          category: "rpc",
          message: "RPC response is not a valid envelope",
          retryable: false,
          details: { cmd }
        }
      };
    }
    const envelope = raw as RpcResp<TRes>;
    return envelope;
  } catch (error) {
    return {
      ok: false,
      error: {
        schema_version: 1,
        code: "KC_RPC_INVOKE_FAILED",
        category: "rpc",
        message: "RPC invoke failed",
        retryable: true,
        details: { cmd, error: String(error) }
      }
    };
  }
}

export type VaultInitReq = { vault_path: string; vault_slug: string };
export type VaultInitReqV1 = { vault_path: string; vault_slug: string; now_ms: number };
export type VaultInitRes = { vault_id: string };
export type VaultOpenReq = { vault_path: string };
export type VaultOpenRes = { vault_id: string; vault_slug: string };
export type TrustIdentityStartReq = {
  vault_path: string;
  provider: string;
  now_ms: number;
};
export type TrustIdentityStartRes = {
  provider_id: string;
  state: string;
  authorization_url: string;
};
export type TrustIdentityCompleteReq = {
  vault_path: string;
  provider: string;
  code: string;
  now_ms: number;
};
export type TrustIdentityCompleteRes = {
  session_id: string;
  provider_id: string;
  subject: string;
  expires_at_ms: number;
};
export type TrustDeviceEnrollReq = {
  vault_path: string;
  device_label: string;
  now_ms: number;
};
export type TrustDeviceEnrollRes = {
  device_id: string;
  label: string;
  fingerprint: string;
  cert_id: string;
  cert_chain_hash: string;
};
export type TrustDeviceVerifyChainReq = {
  vault_path: string;
  device_id: string;
  now_ms: number;
};
export type TrustDeviceVerifyChainRes = {
  cert_id: string;
  device_id: string;
  provider_id: string;
  subject: string;
  cert_chain_hash: string;
  verified_at_ms: number | null;
  expires_at_ms: number;
};
export type TrustDeviceListReq = { vault_path: string };
export type TrustDeviceListItem = {
  device_id: string;
  label: string;
  fingerprint: string;
  verified_at_ms: number | null;
  created_at_ms: number;
};
export type TrustDeviceListRes = { devices: TrustDeviceListItem[] };
export type TrustProviderAddReq = {
  vault_path: string;
  provider_id: string;
  issuer: string;
  aud: string;
  jwks: string;
  now_ms: number;
};
export type TrustProviderDisableReq = {
  vault_path: string;
  provider_id: string;
  now_ms: number;
};
export type TrustProviderListReq = { vault_path: string };
export type TrustProviderDiscoverReq = {
  vault_path: string;
  issuer: string;
  now_ms: number;
};
export type TrustProvider = {
  provider_id: string;
  issuer: string;
  audience: string;
  jwks_url: string;
  enabled: boolean;
  created_at_ms: number;
  updated_at_ms: number;
};
export type TrustProviderRes = TrustProvider;
export type TrustProviderListRes = { providers: TrustProvider[] };
export type TrustPolicySetReq = {
  vault_path: string;
  provider_id: string;
  max_clock_skew_ms: number;
  require_claims_json: string;
  now_ms: number;
};
export type TrustPolicySetTenantTemplateReq = {
  vault_path: string;
  provider: string;
  tenant_id: string;
  now_ms: number;
};
export type TrustPolicySetRes = {
  provider_id: string;
  max_clock_skew_ms: number;
  require_claims_json: string;
  updated_at_ms: number;
};
export type VaultLockStatusReq = { vault_path: string };
export type VaultLockStatusRes = {
  db_encryption_enabled: boolean;
  unlocked: boolean;
  mode: string;
  key_reference: string | null;
  state: string;
};
export type VaultUnlockReq = { vault_path: string; passphrase: string };
export type VaultUnlockRes = { status: VaultLockStatusRes };
export type VaultLockReq = { vault_path: string };
export type VaultLockRes = { status: VaultLockStatusRes };
export type VaultEncryptionStatusReq = { vault_path: string };
export type VaultEncryptionStatusRes = {
  enabled: boolean;
  mode: string;
  key_reference: string | null;
  kdf_algorithm: string;
  objects_total: number;
  objects_encrypted: number;
};
export type VaultEncryptionEnableReq = { vault_path: string; passphrase: string };
export type VaultEncryptionEnableRes = { status: VaultEncryptionStatusRes };
export type VaultEncryptionMigrateReq = {
  vault_path: string;
  passphrase: string;
  now_ms: number;
};
export type VaultEncryptionMigrateRes = {
  status: VaultEncryptionStatusRes;
  migrated_objects: number;
  already_encrypted_objects: number;
  event_id: number;
};
export type VaultRecoveryStatusReq = { vault_path: string };
export type VaultRecoveryStatusRes = {
  vault_id: string;
  encryption_enabled: boolean;
  last_bundle_path: string | null;
};
export type RecoveryManifest = {
  schema_version: number;
  vault_id: string;
  created_at_ms: number;
  phrase_checksum: string;
  payload_hash: string;
};
export type VaultRecoveryEscrowStatusReq = { vault_path: string };
export type VaultRecoveryEscrowStatusRes = {
  enabled: boolean;
  provider: string;
  provider_available: boolean;
  updated_at_ms: number | null;
  details_json: string;
};
export type VaultRecoveryEscrowEnableReq = {
  vault_path: string;
  provider: string;
  now_ms: number;
};
export type VaultRecoveryEscrowEnableRes = { status: VaultRecoveryEscrowStatusRes };
export type VaultRecoveryEscrowRotateReq = {
  vault_path: string;
  passphrase: string;
  now_ms: number;
};
export type VaultRecoveryEscrowRotateRes = {
  status: VaultRecoveryEscrowStatusRes;
  bundle_path: string;
  recovery_phrase: string;
  manifest: RecoveryManifest;
};
export type VaultRecoveryEscrowRestoreReq = {
  vault_path: string;
  bundle_path: string;
  now_ms: number;
};
export type VaultRecoveryEscrowRestoreRes = {
  status: VaultRecoveryEscrowStatusRes;
  bundle_path: string;
  restored_bytes: number;
  manifest: RecoveryManifest;
};
export type VaultRecoveryEscrowProviderAddReq = {
  vault_path: string;
  provider: string;
  config_ref: string;
  now_ms: number;
};
export type VaultRecoveryEscrowProviderListReq = {
  vault_path: string;
};
export type VaultRecoveryEscrowProviderItem = {
  provider: string;
  priority: number;
  config_ref: string;
  enabled: boolean;
  provider_available: boolean;
  updated_at_ms: number;
};
export type VaultRecoveryEscrowProviderAddRes = {
  provider: VaultRecoveryEscrowProviderItem;
};
export type VaultRecoveryEscrowProviderListRes = {
  providers: VaultRecoveryEscrowProviderItem[];
};
export type VaultRecoveryEscrowRotateAllReq = {
  vault_path: string;
  passphrase: string;
  now_ms: number;
};
export type VaultRecoveryEscrowRotateAllItem = {
  provider: string;
  bundle_path: string;
  recovery_phrase: string;
  manifest: RecoveryManifest;
  updated_at_ms: number;
};
export type VaultRecoveryEscrowRotateAllRes = {
  rotated: VaultRecoveryEscrowRotateAllItem[];
};
export type VaultRecoveryGenerateReq = {
  vault_path: string;
  output_dir: string;
  passphrase: string;
  now_ms: number;
};
export type VaultRecoveryGenerateRes = {
  bundle_path: string;
  recovery_phrase: string;
  manifest: RecoveryManifest;
};
export type VaultRecoveryVerifyReq = {
  vault_path: string;
  bundle_path: string;
  recovery_phrase: string;
};
export type VaultRecoveryVerifyRes = {
  manifest: RecoveryManifest;
};
export type IngestScanFolderReq = {
  vault_path: string;
  scan_root: string;
  source_kind: string;
  now_ms: number;
};
export type IngestScanFolderRes = { ingested: number };
export type IngestInboxStartReq = {
  vault_path: string;
  file_path: string;
  source_kind: string;
  now_ms: number;
};
export type IngestInboxStartRes = { job_id: string; doc_id: string };
export type IngestInboxStopReq = { vault_path: string; job_id: string };
export type IngestInboxStopRes = { stopped: boolean };
export type SearchQueryReq = { vault_path: string; query: string; now_ms: number; limit?: number };
export type SearchHit = { doc_id: string; score: number; snippet: string };
export type SearchQueryRes = { hits: SearchHit[] };
export type LocatorV1 = { v: number; doc_id: { 0: string } | string; canonical_hash: { 0: string } | string; range: { start: number; end: number }; hints?: unknown };
export type LocatorResolveReq = { vault_path: string; locator: LocatorV1 };
export type LocatorResolveRes = { text: string };
export type ExportBundleReq = {
  vault_path: string;
  export_dir: string;
  include_vectors: boolean;
  now_ms: number;
};
export type ExportBundleRes = { bundle_path: string };
export type VerifyBundleReq = { bundle_path: string };
export type VerifyBundleRes = { exit_code: number; report: unknown };
export type AskQuestionReq = { vault_path: string; question: string; now_ms: number };
export type AskQuestionRes = { answer_text: string; trace_path: string };
export type EventsListReq = { vault_path: string; limit?: number };
export type EventItem = { event_id: number; ts_ms: number; event_type: string };
export type EventsListRes = { events: EventItem[] };
export type JobsListReq = { vault_path: string };
export type JobsListRes = { jobs: string[] };
export type SyncHead = {
  schema_version: number;
  snapshot_id: string;
  manifest_hash: string;
  created_at_ms: number;
};
export type SyncStatusReq = { vault_path: string; target_path: string };
export type SyncStatusRes = {
  target_path: string;
  remote_head: SyncHead | null;
  seen_remote_snapshot_id: string | null;
  last_applied_manifest_hash: string | null;
};
export type SyncPushReq = { vault_path: string; target_path: string; now_ms: number };
export type SyncPushRes = {
  snapshot_id: string;
  manifest_hash: string;
  remote_head: SyncHead;
};
export type SyncPullReq = {
  vault_path: string;
  target_path: string;
  auto_merge?: string | null;
  now_ms: number;
};
export type SyncPullRes = {
  snapshot_id: string;
  manifest_hash: string;
  remote_head: SyncHead;
};
export type SyncMergePreviewReq = {
  vault_path: string;
  target_path: string;
  policy?: string | null;
  now_ms: number;
};
export type SyncMergeChangeSet = {
  object_hashes: string[];
  lineage_overlay_ids: string[];
};
export type SyncMergePreviewReport = {
  schema_version: number;
  merge_policy: string;
  safe: boolean;
  generated_at_ms: number;
  local: SyncMergeChangeSet;
  remote: SyncMergeChangeSet;
  overlap: SyncMergeChangeSet;
  reasons: string[];
  decision_trace?: string[] | null;
};
export type SyncMergePreviewRes = {
  target_path: string;
  seen_remote_snapshot_id: string | null;
  remote_snapshot_id: string;
  report: SyncMergePreviewReport;
};
export type LineageQueryReq = {
  vault_path: string;
  seed_doc_id: string;
  depth: number;
  now_ms: number;
};
export type LineageNode = {
  node_id: string;
  kind: string;
  label: string;
  metadata: unknown;
};
export type LineageEdge = {
  from_node_id: string;
  to_node_id: string;
  relation: string;
  evidence: string;
};
export type LineageQueryRes = {
  schema_version: number;
  seed_doc_id: string;
  depth: number;
  generated_at_ms: number;
  nodes: LineageNode[];
  edges: LineageEdge[];
};
export type LineageEdgeV2 = {
  from_node_id: string;
  to_node_id: string;
  relation: string;
  evidence: string;
  origin: string;
};
export type LineageQueryV2Req = LineageQueryReq;
export type LineageQueryV2Res = {
  schema_version: number;
  seed_doc_id: string;
  depth: number;
  generated_at_ms: number;
  nodes: LineageNode[];
  edges: LineageEdgeV2[];
};
export type LineageOverlayEntry = {
  overlay_id: string;
  doc_id: string;
  from_node_id: string;
  to_node_id: string;
  relation: string;
  evidence: string;
  created_at_ms: number;
  created_by: string;
};
export type LineageOverlayAddReq = {
  vault_path: string;
  doc_id: string;
  from_node_id: string;
  to_node_id: string;
  relation: string;
  evidence: string;
  lock_token: string;
  created_at_ms: number;
  created_by?: string;
};
export type LineageOverlayAddRes = { overlay: LineageOverlayEntry };
export type LineageOverlayRemoveReq = {
  vault_path: string;
  overlay_id: string;
  lock_token: string;
  now_ms: number;
};
export type LineageOverlayRemoveRes = { removed_overlay_id: string };
export type LineageOverlayListReq = { vault_path: string; doc_id: string };
export type LineageOverlayListRes = { overlays: LineageOverlayEntry[] };
export type LineageLockAcquireReq = {
  vault_path: string;
  doc_id: string;
  owner: string;
  now_ms: number;
};
export type LineageLockLease = {
  doc_id: string;
  owner: string;
  token: string;
  acquired_at_ms: number;
  expires_at_ms: number;
};
export type LineageLockAcquireRes = { lease: LineageLockLease };
export type LineageLockReleaseReq = {
  vault_path: string;
  doc_id: string;
  token: string;
};
export type LineageLockReleaseRes = { released: boolean };
export type LineageLockStatusReq = { vault_path: string; doc_id: string; now_ms: number };
export type LineageLockStatusRes = {
  doc_id: string;
  held: boolean;
  owner: string | null;
  acquired_at_ms: number | null;
  expires_at_ms: number | null;
  expired: boolean;
};
export type LineageRoleBinding = {
  subject_id: string;
  role_name: string;
  role_rank: number;
  granted_by: string;
  granted_at_ms: number;
};
export type LineageRoleGrantReq = {
  vault_path: string;
  subject: string;
  role: string;
  granted_by?: string | null;
  now_ms: number;
};
export type LineageRoleGrantRes = { binding: LineageRoleBinding };
export type LineageRoleRevokeReq = {
  vault_path: string;
  subject: string;
  role: string;
};
export type LineageRoleRevokeRes = { revoked: boolean };
export type LineageRoleListReq = { vault_path: string };
export type LineageRoleListRes = { bindings: LineageRoleBinding[] };
export type LineagePolicy = {
  policy_id: string;
  policy_name: string;
  effect: string;
  priority: number;
  condition_json: string;
  created_by: string;
  created_at_ms: number;
};
export type LineagePolicyAddReq = {
  vault_path: string;
  name: string;
  effect: string;
  condition_json: string;
  created_by?: string | null;
  now_ms: number;
};
export type LineagePolicyAddRes = { policy: LineagePolicy };
export type LineagePolicyBinding = {
  subject_id: string;
  policy_id: string;
  policy_name: string;
  effect: string;
  priority: number;
  condition_json: string;
  bound_by: string;
  bound_at_ms: number;
};
export type LineagePolicyBindReq = {
  vault_path: string;
  subject: string;
  policy: string;
  bound_by?: string | null;
  now_ms: number;
};
export type LineagePolicyBindRes = { binding: LineagePolicyBinding };
export type LineagePolicyListReq = { vault_path: string };
export type LineagePolicyListRes = { bindings: LineagePolicyBinding[] };
export type LineageScopeLockLease = {
  scope_kind: string;
  scope_value: string;
  owner: string;
  token: string;
  acquired_at_ms: number;
  expires_at_ms: number;
};
export type LineageLockAcquireScopeReq = {
  vault_path: string;
  scope_kind: string;
  scope_value: string;
  owner: string;
  now_ms: number;
};
export type LineageLockAcquireScopeRes = { lease: LineageScopeLockLease };
export const rpcMethods = {
  vaultInit: (req: VaultInitReqV1) => rpc<VaultInitReqV1, VaultInitRes>("vault_init", req),
  vaultOpen: (req: VaultOpenReq) => rpc<VaultOpenReq, VaultOpenRes>("vault_open", req),
  trustIdentityStart: (req: TrustIdentityStartReq) =>
    rpc<TrustIdentityStartReq, TrustIdentityStartRes>("trust_identity_start", req),
  trustIdentityComplete: (req: TrustIdentityCompleteReq) =>
    rpc<TrustIdentityCompleteReq, TrustIdentityCompleteRes>("trust_identity_complete", req),
  trustDeviceEnroll: (req: TrustDeviceEnrollReq) =>
    rpc<TrustDeviceEnrollReq, TrustDeviceEnrollRes>("trust_device_enroll", req),
  trustDeviceVerifyChain: (req: TrustDeviceVerifyChainReq) =>
    rpc<TrustDeviceVerifyChainReq, TrustDeviceVerifyChainRes>("trust_device_verify_chain", req),
  trustDeviceList: (req: TrustDeviceListReq) =>
    rpc<TrustDeviceListReq, TrustDeviceListRes>("trust_device_list", req),
  trustProviderAdd: (req: TrustProviderAddReq) =>
    rpc<TrustProviderAddReq, TrustProviderRes>("trust_provider_add", req),
  trustProviderDisable: (req: TrustProviderDisableReq) =>
    rpc<TrustProviderDisableReq, TrustProviderRes>("trust_provider_disable", req),
  trustProviderList: (req: TrustProviderListReq) =>
    rpc<TrustProviderListReq, TrustProviderListRes>("trust_provider_list", req),
  trustProviderDiscover: (req: TrustProviderDiscoverReq) =>
    rpc<TrustProviderDiscoverReq, TrustProviderRes>("trust_provider_discover", req),
  trustPolicySet: (req: TrustPolicySetReq) =>
    rpc<TrustPolicySetReq, TrustPolicySetRes>("trust_policy_set", req),
  trustPolicySetTenantTemplate: (req: TrustPolicySetTenantTemplateReq) =>
    rpc<TrustPolicySetTenantTemplateReq, TrustPolicySetRes>(
      "trust_policy_set_tenant_template",
      req
    ),
  vaultLockStatus: (req: VaultLockStatusReq) =>
    rpc<VaultLockStatusReq, VaultLockStatusRes>("vault_lock_status", req),
  vaultUnlock: (req: VaultUnlockReq) => rpc<VaultUnlockReq, VaultUnlockRes>("vault_unlock", req),
  vaultLock: (req: VaultLockReq) => rpc<VaultLockReq, VaultLockRes>("vault_lock", req),
  vaultEncryptionStatus: (req: VaultEncryptionStatusReq) =>
    rpc<VaultEncryptionStatusReq, VaultEncryptionStatusRes>("vault_encryption_status", req),
  vaultEncryptionEnable: (req: VaultEncryptionEnableReq) =>
    rpc<VaultEncryptionEnableReq, VaultEncryptionEnableRes>("vault_encryption_enable", req),
  vaultEncryptionMigrate: (req: VaultEncryptionMigrateReq) =>
    rpc<VaultEncryptionMigrateReq, VaultEncryptionMigrateRes>("vault_encryption_migrate", req),
  vaultRecoveryStatus: (req: VaultRecoveryStatusReq) =>
    rpc<VaultRecoveryStatusReq, VaultRecoveryStatusRes>("vault_recovery_status", req),
  vaultRecoveryEscrowStatus: (req: VaultRecoveryEscrowStatusReq) =>
    rpc<VaultRecoveryEscrowStatusReq, VaultRecoveryEscrowStatusRes>(
      "vault_recovery_escrow_status",
      req
    ),
  vaultRecoveryEscrowEnable: (req: VaultRecoveryEscrowEnableReq) =>
    rpc<VaultRecoveryEscrowEnableReq, VaultRecoveryEscrowEnableRes>(
      "vault_recovery_escrow_enable",
      req
    ),
  vaultRecoveryEscrowRotate: (req: VaultRecoveryEscrowRotateReq) =>
    rpc<VaultRecoveryEscrowRotateReq, VaultRecoveryEscrowRotateRes>(
      "vault_recovery_escrow_rotate",
      req
    ),
  vaultRecoveryEscrowRestore: (req: VaultRecoveryEscrowRestoreReq) =>
    rpc<VaultRecoveryEscrowRestoreReq, VaultRecoveryEscrowRestoreRes>(
      "vault_recovery_escrow_restore",
      req
    ),
  vaultRecoveryEscrowProviderAdd: (req: VaultRecoveryEscrowProviderAddReq) =>
    rpc<VaultRecoveryEscrowProviderAddReq, VaultRecoveryEscrowProviderAddRes>(
      "vault_recovery_escrow_provider_add",
      req
    ),
  vaultRecoveryEscrowProviderList: (req: VaultRecoveryEscrowProviderListReq) =>
    rpc<VaultRecoveryEscrowProviderListReq, VaultRecoveryEscrowProviderListRes>(
      "vault_recovery_escrow_provider_list",
      req
    ),
  vaultRecoveryEscrowRotateAll: (req: VaultRecoveryEscrowRotateAllReq) =>
    rpc<VaultRecoveryEscrowRotateAllReq, VaultRecoveryEscrowRotateAllRes>(
      "vault_recovery_escrow_rotate_all",
      req
    ),
  vaultRecoveryGenerate: (req: VaultRecoveryGenerateReq) =>
    rpc<VaultRecoveryGenerateReq, VaultRecoveryGenerateRes>("vault_recovery_generate", req),
  vaultRecoveryVerify: (req: VaultRecoveryVerifyReq) =>
    rpc<VaultRecoveryVerifyReq, VaultRecoveryVerifyRes>("vault_recovery_verify", req),
  ingestScanFolder: (req: IngestScanFolderReq) => rpc<IngestScanFolderReq, IngestScanFolderRes>("ingest_scan_folder", req),
  ingestInboxStart: (req: IngestInboxStartReq) => rpc<IngestInboxStartReq, IngestInboxStartRes>("ingest_inbox_start", req),
  ingestInboxStop: (req: IngestInboxStopReq) => rpc<IngestInboxStopReq, IngestInboxStopRes>("ingest_inbox_stop", req),
  searchQuery: (req: SearchQueryReq) => rpc<SearchQueryReq, SearchQueryRes>("search_query", req),
  locatorResolve: (req: LocatorResolveReq) => rpc<LocatorResolveReq, LocatorResolveRes>("locator_resolve", req),
  exportBundle: (req: ExportBundleReq) => rpc<ExportBundleReq, ExportBundleRes>("export_bundle", req),
  verifyBundle: (req: VerifyBundleReq) => rpc<VerifyBundleReq, VerifyBundleRes>("verify_bundle", req),
  askQuestion: (req: AskQuestionReq) => rpc<AskQuestionReq, AskQuestionRes>("ask_question", req),
  eventsList: (req: EventsListReq) => rpc<EventsListReq, EventsListRes>("events_list", req),
  jobsList: (req: JobsListReq) => rpc<JobsListReq, JobsListRes>("jobs_list", req),
  syncStatus: (req: SyncStatusReq) => rpc<SyncStatusReq, SyncStatusRes>("sync_status", req),
  syncPush: (req: SyncPushReq) => rpc<SyncPushReq, SyncPushRes>("sync_push", req),
  syncPull: (req: SyncPullReq) => rpc<SyncPullReq, SyncPullRes>("sync_pull", req),
  syncMergePreview: (req: SyncMergePreviewReq) =>
    rpc<SyncMergePreviewReq, SyncMergePreviewRes>("sync_merge_preview", req),
  lineageQuery: (req: LineageQueryReq) =>
    rpc<LineageQueryReq, LineageQueryRes>("lineage_query", req),
  lineageQueryV2: (req: LineageQueryV2Req) =>
    rpc<LineageQueryV2Req, LineageQueryV2Res>("lineage_query_v2", req),
  lineageOverlayAdd: (req: LineageOverlayAddReq) =>
    rpc<LineageOverlayAddReq, LineageOverlayAddRes>("lineage_overlay_add", req),
  lineageOverlayRemove: (req: LineageOverlayRemoveReq) =>
    rpc<LineageOverlayRemoveReq, LineageOverlayRemoveRes>("lineage_overlay_remove", req),
  lineageOverlayList: (req: LineageOverlayListReq) =>
    rpc<LineageOverlayListReq, LineageOverlayListRes>("lineage_overlay_list", req),
  lineageLockAcquire: (req: LineageLockAcquireReq) =>
    rpc<LineageLockAcquireReq, LineageLockAcquireRes>("lineage_lock_acquire", req),
  lineageLockRelease: (req: LineageLockReleaseReq) =>
    rpc<LineageLockReleaseReq, LineageLockReleaseRes>("lineage_lock_release", req),
  lineageLockStatus: (req: LineageLockStatusReq) =>
    rpc<LineageLockStatusReq, LineageLockStatusRes>("lineage_lock_status", req),
  lineageRoleGrant: (req: LineageRoleGrantReq) =>
    rpc<LineageRoleGrantReq, LineageRoleGrantRes>("lineage_role_grant", req),
  lineageRoleRevoke: (req: LineageRoleRevokeReq) =>
    rpc<LineageRoleRevokeReq, LineageRoleRevokeRes>("lineage_role_revoke", req),
  lineageRoleList: (req: LineageRoleListReq) =>
    rpc<LineageRoleListReq, LineageRoleListRes>("lineage_role_list", req),
  lineagePolicyAdd: (req: LineagePolicyAddReq) =>
    rpc<LineagePolicyAddReq, LineagePolicyAddRes>("lineage_policy_add", req),
  lineagePolicyBind: (req: LineagePolicyBindReq) =>
    rpc<LineagePolicyBindReq, LineagePolicyBindRes>("lineage_policy_bind", req),
  lineagePolicyList: (req: LineagePolicyListReq) =>
    rpc<LineagePolicyListReq, LineagePolicyListRes>("lineage_policy_list", req),
  lineageLockAcquireScope: (req: LineageLockAcquireScopeReq) =>
    rpc<LineageLockAcquireScopeReq, LineageLockAcquireScopeRes>(
      "lineage_lock_acquire_scope",
      req
    )
};

export type DesktopRpcApi = typeof rpcMethods;

export function createDesktopRpcApi(): DesktopRpcApi {
  return rpcMethods;
}
