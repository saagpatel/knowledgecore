use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kc_cli")]
#[command(about = "KnowledgeCore CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Vault {
        #[command(subcommand)]
        cmd: VaultCmd,
    },
    Trust {
        #[command(subcommand)]
        cmd: TrustCmd,
    },
    Ingest {
        #[command(subcommand)]
        cmd: IngestCmd,
    },
    Export {
        vault_path: String,
        export_dir: String,
        #[arg(long)]
        zip: bool,
    },
    Verify {
        bundle_path: String,
    },
    Index {
        #[command(subcommand)]
        cmd: IndexCmd,
    },
    Gc {
        #[command(subcommand)]
        cmd: GcCmd,
    },
    Deps {
        #[command(subcommand)]
        cmd: DepsCmd,
    },
    Bench {
        #[command(subcommand)]
        cmd: BenchCmd,
    },
    Fixtures {
        #[command(subcommand)]
        cmd: FixturesCmd,
    },
    Sync {
        #[command(subcommand)]
        cmd: SyncCmd,
    },
    Lineage {
        #[command(subcommand)]
        cmd: LineageCmd,
    },
}

#[derive(Subcommand)]
pub enum VaultCmd {
    Init {
        vault_path: String,
        vault_slug: String,
    },
    Open {
        vault_path: String,
    },
    Verify {
        vault_path: String,
    },
    Unlock {
        vault_path: String,
        #[arg(long = "passphrase-env")]
        passphrase_env: String,
    },
    Lock {
        vault_path: String,
    },
    LockStatus {
        vault_path: String,
    },
    Encrypt {
        #[command(subcommand)]
        cmd: VaultEncryptCmd,
    },
    DbEncrypt {
        #[command(subcommand)]
        cmd: VaultDbEncryptCmd,
    },
    Recovery {
        #[command(subcommand)]
        cmd: VaultRecoveryCmd,
    },
}

#[derive(Subcommand)]
pub enum VaultEncryptCmd {
    Status {
        vault_path: String,
    },
    Enable {
        vault_path: String,
        #[arg(long = "passphrase-env")]
        passphrase_env: String,
    },
    Migrate {
        vault_path: String,
        #[arg(long = "passphrase-env")]
        passphrase_env: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
}

#[derive(Subcommand)]
pub enum VaultDbEncryptCmd {
    Status {
        vault_path: String,
    },
    Enable {
        vault_path: String,
        #[arg(long = "passphrase-env")]
        passphrase_env: String,
    },
    Migrate {
        vault_path: String,
        #[arg(long = "passphrase-env")]
        passphrase_env: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
}

#[derive(Subcommand)]
pub enum VaultRecoveryCmd {
    Status {
        vault_path: String,
    },
    Escrow {
        #[command(subcommand)]
        cmd: VaultRecoveryEscrowCmd,
    },
    Generate {
        vault_path: String,
        #[arg(long)]
        output: String,
        #[arg(long = "passphrase-env")]
        passphrase_env: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    Verify {
        vault_path: String,
        #[arg(long)]
        bundle: String,
        #[arg(long = "phrase-env")]
        phrase_env: String,
    },
}

#[derive(Subcommand)]
pub enum VaultRecoveryEscrowCmd {
    Status {
        vault_path: String,
    },
    Provider {
        #[command(subcommand)]
        cmd: VaultRecoveryEscrowProviderCmd,
    },
    Enable {
        vault_path: String,
        #[arg(long)]
        provider: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    Rotate {
        vault_path: String,
        #[arg(long = "passphrase-env")]
        passphrase_env: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    RotateAll {
        vault_path: String,
        #[arg(long = "passphrase-env")]
        passphrase_env: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    Restore {
        vault_path: String,
        #[arg(long)]
        bundle: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
}

#[derive(Subcommand)]
pub enum VaultRecoveryEscrowProviderCmd {
    Add {
        vault_path: String,
        #[arg(long = "provider")]
        provider: String,
        #[arg(long = "config-ref")]
        config_ref: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    List {
        vault_path: String,
    },
}

#[derive(Subcommand)]
pub enum TrustCmd {
    Identity {
        #[command(subcommand)]
        cmd: TrustIdentityCmd,
    },
    Device {
        #[command(subcommand)]
        cmd: TrustDeviceCmd,
    },
    Provider {
        #[command(subcommand)]
        cmd: TrustProviderCmd,
    },
    Policy {
        #[command(subcommand)]
        cmd: TrustPolicyCmd,
    },
}

#[derive(Subcommand)]
pub enum TrustIdentityCmd {
    Start {
        vault_path: String,
        #[arg(long = "provider")]
        provider: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    Complete {
        vault_path: String,
        #[arg(long = "provider")]
        provider: String,
        #[arg(long = "code")]
        code: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
}

#[derive(Subcommand)]
pub enum TrustDeviceCmd {
    Enroll {
        vault_path: String,
        #[arg(long = "device-label")]
        device_label: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    EnrollSigningKey {
        vault_path: String,
        #[arg(long = "device-label")]
        device_label: String,
        #[arg(long = "passphrase-env")]
        passphrase_env: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    VerifyChain {
        vault_path: String,
        #[arg(long = "device-id")]
        device_id: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    List {
        vault_path: String,
    },
}

#[derive(Subcommand)]
pub enum TrustProviderCmd {
    Add {
        vault_path: String,
        #[arg(long = "provider-id")]
        provider_id: String,
        #[arg(long = "issuer")]
        issuer: String,
        #[arg(long = "aud")]
        aud: String,
        #[arg(long = "jwks")]
        jwks: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    Disable {
        vault_path: String,
        #[arg(long = "provider-id")]
        provider_id: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    List {
        vault_path: String,
    },
    Discover {
        vault_path: String,
        #[arg(long = "issuer")]
        issuer: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
}

#[derive(Subcommand)]
pub enum TrustPolicyCmd {
    Set {
        vault_path: String,
        #[arg(long = "provider-id")]
        provider_id: String,
        #[arg(long = "max-clock-skew-ms")]
        max_clock_skew_ms: i64,
        #[arg(long = "require-claims")]
        require_claims: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
    SetTenantTemplate {
        vault_path: String,
        #[arg(long = "provider")]
        provider: String,
        #[arg(long = "tenant-id")]
        tenant_id: String,
        #[arg(long = "now-ms")]
        now_ms: Option<i64>,
    },
}

#[derive(Subcommand)]
pub enum IngestCmd {
    ScanFolder {
        vault_path: String,
        scan_root: String,
        source_kind: String,
    },
    InboxOnce {
        vault_path: String,
        file_path: String,
        source_kind: String,
    },
}

#[derive(Subcommand)]
pub enum IndexCmd {
    Rebuild { vault_path: String },
}

#[derive(Subcommand)]
pub enum GcCmd {
    Run { vault_path: String },
}

#[derive(Subcommand)]
pub enum DepsCmd {
    Check,
}

#[derive(Subcommand)]
pub enum BenchCmd {
    Run {
        #[arg(long)]
        corpus: String,
    },
}

#[derive(Subcommand)]
pub enum FixturesCmd {
    Generate {
        #[arg(long)]
        corpus: String,
    },
}

#[derive(Subcommand)]
pub enum SyncCmd {
    Status {
        vault_path: String,
        target_path: String,
    },
    Push {
        vault_path: String,
        target_path: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
    Pull {
        vault_path: String,
        target_path: String,
        #[arg(long = "auto-merge")]
        auto_merge: Option<String>,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
    MergePreview {
        vault_path: String,
        target_path: String,
        #[arg(long = "policy")]
        policy: Option<String>,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
}

#[derive(Subcommand)]
pub enum LineageCmd {
    Overlay {
        #[command(subcommand)]
        cmd: LineageOverlayCmd,
    },
    Role {
        #[command(subcommand)]
        cmd: LineageRoleCmd,
    },
    Policy {
        #[command(subcommand)]
        cmd: LineagePolicyCmd,
    },
    Lock {
        #[command(subcommand)]
        cmd: LineageLockCmd,
    },
}

#[derive(Subcommand)]
pub enum LineageOverlayCmd {
    Add {
        vault_path: String,
        doc_id: String,
        from_node_id: String,
        to_node_id: String,
        relation: String,
        evidence: String,
        lock_token: String,
        #[arg(long, default_value = "cli")]
        created_by: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
    Remove {
        vault_path: String,
        overlay_id: String,
        lock_token: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
    List {
        vault_path: String,
        doc_id: String,
    },
}

#[derive(Subcommand)]
pub enum LineageLockCmd {
    Acquire {
        vault_path: String,
        doc_id: String,
        owner: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
    AcquireScope {
        vault_path: String,
        #[arg(long = "scope")]
        scope_kind: String,
        #[arg(long = "scope-value")]
        scope_value: String,
        owner: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
    Release {
        vault_path: String,
        doc_id: String,
        token: String,
    },
    Status {
        vault_path: String,
        doc_id: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
}

#[derive(Subcommand)]
pub enum LineageRoleCmd {
    Grant {
        vault_path: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        role: String,
        #[arg(long, default_value = "cli")]
        granted_by: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
    Revoke {
        vault_path: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        role: String,
    },
    List {
        vault_path: String,
    },
}

#[derive(Subcommand)]
pub enum LineagePolicyCmd {
    Add {
        vault_path: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        effect: String,
        #[arg(long = "condition-json")]
        condition_json: String,
        #[arg(long, default_value = "cli")]
        created_by: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
    Bind {
        vault_path: String,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        policy: String,
        #[arg(long, default_value = "cli")]
        bound_by: String,
        #[arg(long = "now-ms")]
        now_ms: i64,
    },
    List {
        vault_path: String,
    },
}
