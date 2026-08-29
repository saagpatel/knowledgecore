use kc_core::app_error::{AppError, AppResult};
use kc_core::federation::{
    federation_query_service_v2_authorized, FederationQueryRequestV2, FederationQueryResultV2,
};
use kc_core::rpc_service::vault_unlock_service;
use kc_core::vault::{vault_open, vault_paths};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::raw::c_int;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const FEDERATION_TRANSPORT_REQUEST_SCHEMA: &str =
    "knowledgecore_federation_transport_request.v1";
pub const FEDERATION_TRANSPORT_RESPONSE_SCHEMA: &str =
    "knowledgecore_federation_transport_response.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_SESSION_ID_CHARS: usize = 200;
const POSIX_SIGINT: c_int = 2;
const POSIX_SIGTERM: c_int = 15;
const POSIX_SIG_ERR: *const () = usize::MAX as *const ();

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn signal(signal: c_int, handler: *const ()) -> *const ();
}

extern "C" fn request_shutdown(_signal: c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

struct SignalGuard {
    previous_sigint: *const (),
    previous_sigterm: *const (),
}

impl SignalGuard {
    fn install() -> AppResult<Self> {
        SHUTDOWN_REQUESTED.store(false, Ordering::Relaxed);
        // SAFETY: POSIX SIGINT/SIGTERM and signal(3) are available on every target that
        // supports the Unix socket transport in this module. The handler only performs
        // a lock-free atomic store and is restored before this guard is dropped.
        let previous_sigint = unsafe { signal(POSIX_SIGINT, request_shutdown as *const ()) };
        if previous_sigint == POSIX_SIG_ERR {
            return Err(transport_error(
                "KC_FEDERATION_SIGNAL_HANDLER_FAILED",
                "failed installing the local federation SIGINT handler",
                false,
            ));
        }
        // SAFETY: same contract as the SIGINT installation above.
        let previous_sigterm = unsafe { signal(POSIX_SIGTERM, request_shutdown as *const ()) };
        if previous_sigterm == POSIX_SIG_ERR {
            // SAFETY: previous_sigint was returned by signal(3) for this signal.
            let _ = unsafe { signal(POSIX_SIGINT, previous_sigint) };
            return Err(transport_error(
                "KC_FEDERATION_SIGNAL_HANDLER_FAILED",
                "failed installing the local federation SIGTERM handler",
                false,
            ));
        }
        Ok(Self {
            previous_sigint,
            previous_sigterm,
        })
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        // SAFETY: both handler values were returned by signal(3) for these signals.
        let _ = unsafe { signal(POSIX_SIGTERM, self.previous_sigterm) };
        // SAFETY: both handler values were returned by signal(3) for these signals.
        let _ = unsafe { signal(POSIX_SIGINT, self.previous_sigint) };
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FederationTransportRequestV1 {
    schema_version: String,
    session_id: String,
    query: FederationQueryRequestV2,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct FederationTransportErrorV1 {
    code: String,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum FederationTransportResponseV1 {
    Ok {
        schema_version: String,
        result: FederationQueryResultV2,
    },
    Error {
        schema_version: String,
        error: FederationTransportErrorV1,
    },
}

fn transport_error(code: &str, message: &str, retryable: bool) -> AppError {
    AppError::new(
        code,
        "federation_transport",
        message,
        retryable,
        serde_json::json!({}),
    )
}

fn now_ms() -> AppResult<i64> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        transport_error(
            "KC_FEDERATION_TRANSPORT_CLOCK_INVALID",
            "system clock is before the Unix epoch",
            false,
        )
    })?;
    i64::try_from(duration.as_millis()).map_err(|_| {
        transport_error(
            "KC_FEDERATION_TRANSPORT_CLOCK_INVALID",
            "system clock is outside the supported range",
            false,
        )
    })
}

fn public_error_response(code: &str, message: &str) -> FederationTransportResponseV1 {
    FederationTransportResponseV1::Error {
        schema_version: FEDERATION_TRANSPORT_RESPONSE_SCHEMA.to_string(),
        error: FederationTransportErrorV1 {
            code: code.to_string(),
            message: message.to_string(),
        },
    }
}

fn parse_request(
    bytes: &[u8],
) -> Result<FederationTransportRequestV1, FederationTransportResponseV1> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(public_error_response(
            "KC_FEDERATION_TRANSPORT_REQUEST_INVALID",
            "federation transport request is empty or exceeds the size limit",
        ));
    }
    let request = serde_json::from_slice::<FederationTransportRequestV1>(bytes).map_err(|_| {
        public_error_response(
            "KC_FEDERATION_TRANSPORT_REQUEST_INVALID",
            "federation transport request is malformed or has unsupported fields",
        )
    })?;
    if request.schema_version != FEDERATION_TRANSPORT_REQUEST_SCHEMA
        || request.session_id.trim().is_empty()
        || request.session_id.chars().count() > MAX_SESSION_ID_CHARS
    {
        return Err(public_error_response(
            "KC_FEDERATION_TRANSPORT_REQUEST_INVALID",
            "federation transport request schema or session binding is invalid",
        ));
    }
    Ok(request)
}

fn handle_request(vault_path: &Path, bytes: &[u8]) -> FederationTransportResponseV1 {
    let request = match parse_request(bytes) {
        Ok(request) => request,
        Err(response) => return response,
    };
    match federation_query_service_v2_authorized(
        vault_path,
        &request.session_id,
        match now_ms() {
            Ok(value) => value,
            Err(error) => {
                return public_error_response(
                    &error.code,
                    "KnowledgeCore owner clock is unavailable",
                )
            }
        },
        &request.query,
    ) {
        Ok(result) => FederationTransportResponseV1::Ok {
            schema_version: FEDERATION_TRANSPORT_RESPONSE_SCHEMA.to_string(),
            result,
        },
        Err(error) => public_error_response(
            &error.code,
            "KnowledgeCore federation request was rejected by the owner boundary",
        ),
    }
}

fn serve_connection(vault_path: &Path, mut stream: UnixStream) -> AppResult<()> {
    stream
        .set_read_timeout(Some(CONNECTION_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(CONNECTION_TIMEOUT)))
        .map_err(|_| {
            transport_error(
                "KC_FEDERATION_TRANSPORT_IO_FAILED",
                "failed applying local transport timeouts",
                true,
            )
        })?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut stream)
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            transport_error(
                "KC_FEDERATION_TRANSPORT_IO_FAILED",
                "failed reading local federation request",
                true,
            )
        })?;
    let response = handle_request(vault_path, &bytes);
    let mut encoded = serde_json::to_vec(&response).map_err(|_| {
        transport_error(
            "KC_FEDERATION_TRANSPORT_RESPONSE_INVALID",
            "failed serializing bounded federation response",
            false,
        )
    })?;
    if encoded.len() > MAX_RESPONSE_BYTES {
        encoded = serde_json::to_vec(&public_error_response(
            "KC_FEDERATION_TRANSPORT_RESPONSE_TOO_LARGE",
            "bounded federation response exceeds the transport size limit",
        ))
        .map_err(|_| {
            transport_error(
                "KC_FEDERATION_TRANSPORT_RESPONSE_INVALID",
                "failed serializing bounded federation error response",
                false,
            )
        })?;
    }
    encoded.push(b'\n');
    stream.write_all(&encoded).map_err(|_| {
        transport_error(
            "KC_FEDERATION_TRANSPORT_IO_FAILED",
            "failed writing local federation response",
            true,
        )
    })
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketGuard {
    fn new(path: &Path) -> AppResult<Self> {
        let metadata = fs::symlink_metadata(path).map_err(|_| {
            transport_error(
                "KC_FEDERATION_SOCKET_UNAVAILABLE",
                "failed reading the bound federation socket",
                false,
            )
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn bind_owner_socket(socket_path: &Path) -> AppResult<(UnixListener, SocketGuard)> {
    if !socket_path.is_absolute() {
        return Err(transport_error(
            "KC_FEDERATION_SOCKET_INVALID",
            "federation socket path must be absolute",
            false,
        ));
    }
    let parent = socket_path.parent().ok_or_else(|| {
        transport_error(
            "KC_FEDERATION_SOCKET_INVALID",
            "federation socket parent is unavailable",
            false,
        )
    })?;
    let parent_metadata = fs::metadata(parent).map_err(|_| {
        transport_error(
            "KC_FEDERATION_SOCKET_INVALID",
            "federation socket parent must already exist",
            false,
        )
    })?;
    if !parent_metadata.is_dir() || parent_metadata.permissions().mode() & 0o022 != 0 {
        return Err(transport_error(
            "KC_FEDERATION_SOCKET_INSECURE",
            "federation socket parent must be a private owner directory",
            false,
        ));
    }
    if fs::symlink_metadata(socket_path).is_ok() {
        return Err(transport_error(
            "KC_FEDERATION_SOCKET_EXISTS",
            "federation socket path already exists; owner cleanup is required",
            false,
        ));
    }
    let listener = UnixListener::bind(socket_path).map_err(|_| {
        transport_error(
            "KC_FEDERATION_SOCKET_UNAVAILABLE",
            "failed binding the local federation socket",
            true,
        )
    })?;
    let guard = SocketGuard::new(socket_path)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).map_err(|_| {
        transport_error(
            "KC_FEDERATION_SOCKET_UNAVAILABLE",
            "failed restricting the local federation socket",
            false,
        )
    })?;
    Ok((listener, guard))
}

pub fn run_serve(
    vault_path: &str,
    socket_path: &str,
    passphrase_env: Option<&str>,
    max_requests: Option<usize>,
) -> AppResult<()> {
    if matches!(max_requests, Some(0)) {
        return Err(transport_error(
            "KC_FEDERATION_TRANSPORT_REQUEST_INVALID",
            "max_requests must be greater than zero",
            false,
        ));
    }
    let vault_path = Path::new(vault_path);
    let vault = vault_open(vault_path)?;
    if let Some(env_name) = passphrase_env {
        let passphrase = std::env::var(env_name)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                transport_error(
                    "KC_ENCRYPTION_REQUIRED",
                    "the selected passphrase environment variable is missing or empty",
                    false,
                )
            })?;
        vault_unlock_service(vault_path, &passphrase)?;
    }
    let paths = vault_paths(vault_path);
    if paths.db != vault_path.join(vault.db.relative_path) {
        return Err(transport_error(
            "KC_FEDERATION_TRANSPORT_BINDING_INVALID",
            "vault database binding is inconsistent",
            false,
        ));
    }

    let _signal_guard = SignalGuard::install()?;
    let (listener, _guard) = bind_owner_socket(Path::new(socket_path))?;
    listener.set_nonblocking(true).map_err(|_| {
        transport_error(
            "KC_FEDERATION_TRANSPORT_IO_FAILED",
            "failed configuring the local federation listener",
            true,
        )
    })?;
    println!(
        "{}",
        serde_json::json!({
            "schema_version": FEDERATION_TRANSPORT_RESPONSE_SCHEMA,
            "status": "ready"
        })
    );
    let mut served = 0usize;
    while !SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _address)) => {
                let _ = serve_connection(vault_path, stream);
                served += 1;
                if max_requests.is_some_and(|limit| served >= limit) {
                    break;
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(transport_error(
                    "KC_FEDERATION_TRANSPORT_IO_FAILED",
                    "failed accepting a local federation request",
                    true,
                ))
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::validator_for;
    use kc_core::canonical::persist_canonical_text;
    use kc_core::db::open_db;
    use kc_core::federation::{
        DOCUMENT_FEDERATION_READ_ACTION, FEDERATION_QUERY_REQUEST_SCHEMA_V2,
    };
    use kc_core::hashing::blake3_hex_prefixed;
    use kc_core::ingest::{ingest_bytes, IngestBytesReq};
    use kc_core::lineage_policy::{lineage_policy_add, lineage_policy_bind};
    use kc_core::object_store::ObjectStore;
    use kc_core::services::CanonicalTextArtifact;
    use kc_core::trust_identity::{trust_identity_complete, trust_identity_start};
    use kc_core::types::{CanonicalHash, ObjectHash};
    use kc_core::vault::vault_init;
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn hash_schema() -> serde_json::Value {
        serde_json::json!({ "type": "string", "pattern": "^blake3:[0-9a-f]{64}$" })
    }

    fn optional_hash_schema() -> serde_json::Value {
        serde_json::json!({ "oneOf": [{ "type": "null" }, hash_schema()] })
    }

    fn federation_query_request_v2_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["schema_version", "project_key", "include_content", "limit", "observed_at_ms"],
            "properties": {
                "schema_version": { "const": FEDERATION_QUERY_REQUEST_SCHEMA_V2 },
                "project_key": { "type": "string", "minLength": 1, "maxLength": 200 },
                "include_content": { "type": "boolean" },
                "limit": { "type": "integer", "minimum": 0 },
                "observed_at_ms": { "type": "integer", "minimum": 0 }
            },
            "additionalProperties": false
        })
    }

    fn federation_fact_value_v2_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["sourceKind", "effectiveTsMs", "ingestedEventId", "canonicalHash", "extractor"],
            "properties": {
                "sourceKind": { "type": "string", "minLength": 1 },
                "effectiveTsMs": { "type": "integer" },
                "ingestedEventId": { "type": "integer", "minimum": 0 },
                "canonicalHash": hash_schema(),
                "extractor": {
                    "type": "object",
                    "required": ["name", "version", "normalizationVersion", "toolchain"],
                    "properties": {
                        "name": { "type": "string", "minLength": 1 },
                        "version": { "type": "string" },
                        "normalizationVersion": { "type": "integer" },
                        "toolchain": {
                            "type": "object",
                            "required": ["digest"],
                            "properties": { "digest": hash_schema() },
                            "additionalProperties": false
                        }
                    },
                    "additionalProperties": false
                },
                "snippet": { "type": "string", "maxLength": 240 }
            },
            "additionalProperties": false
        })
    }

    fn federation_query_result_v2_schema() -> serde_json::Value {
        let source_state = serde_json::json!({
            "enum": ["ready", "not_found", "locked", "permission_denied", "corrupt", "error"]
        });
        let lifecycle_state =
            serde_json::json!({ "enum": ["active", "superseded", "tombstoned", "conflicted"] });
        let terminal_state = serde_json::json!({ "enum": ["active", "tombstoned", "conflicted"] });
        let event_ref = serde_json::json!({
            "type": "object",
            "required": [
                "event_id", "event_hash", "event_at_ms", "action", "source_item_id",
                "source_canonical_hash", "replacement_source_item_id",
                "replacement_canonical_hash", "authorization_subject_digest", "reason_digest"
            ],
            "properties": {
                "event_id": { "type": "integer", "minimum": 1 },
                "event_hash": hash_schema(),
                "event_at_ms": { "type": "integer", "minimum": 0 },
                "action": { "enum": ["supersede", "tombstone"] },
                "source_item_id": hash_schema(),
                "source_canonical_hash": hash_schema(),
                "replacement_source_item_id": optional_hash_schema(),
                "replacement_canonical_hash": optional_hash_schema(),
                "authorization_subject_digest": hash_schema(),
                "reason_digest": hash_schema()
            },
            "additionalProperties": false
        });
        let notice = serde_json::json!({
            "type": "object",
            "required": ["source_item_id", "initial_state", "terminal_state", "terminal_source_item_id", "events"],
            "properties": {
                "source_item_id": hash_schema(),
                "initial_state": lifecycle_state,
                "terminal_state": terminal_state,
                "terminal_source_item_id": optional_hash_schema(),
                "events": { "type": "array", "minItems": 1, "maxItems": 100, "items": event_ref }
            },
            "additionalProperties": false
        });
        let fact = serde_json::json!({
            "type": "object",
            "required": ["fact_id", "fact_key", "source_item_id", "observed_at_ms", "score", "lifecycle_state", "value", "value_digest"],
            "properties": {
                "fact_id": { "type": "string", "minLength": 1 },
                "fact_key": { "const": "private_document.match" },
                "source_item_id": hash_schema(),
                "observed_at_ms": { "type": "integer" },
                "score": { "type": "number" },
                "lifecycle_state": { "const": "active" },
                "value": federation_fact_value_v2_schema(),
                "value_digest": hash_schema()
            },
            "additionalProperties": false
        });
        serde_json::json!({
            "type": "object",
            "required": [
                "schema_version", "source_id", "owner", "canonicality", "state",
                "participated", "vault_id", "binding", "source_revision", "observed_at_ms",
                "freshness", "freshness_basis", "trust_semantics", "access_mode",
                "instruction_boundary", "correction_semantics", "deletion_semantics",
                "query_match_semantics", "match_disposition", "uncertainty",
                "lifecycle_notices", "facts"
            ],
            "properties": {
                "schema_version": { "const": kc_core::federation::FEDERATION_QUERY_RESULT_SCHEMA_V2 },
                "source_id": { "const": "knowledgecore" },
                "owner": { "const": "knowledgecore" },
                "canonicality": { "type": "string", "minLength": 1 },
                "state": source_state,
                "participated": { "type": "boolean" },
                "vault_id": { "type": "string", "format": "uuid" },
                "binding": optional_hash_schema(),
                "source_revision": {
                    "oneOf": [
                        { "type": "null" },
                        {
                            "type": "object",
                            "required": ["event_id", "event_hash", "event_at_ms"],
                            "properties": {
                                "event_id": { "type": "integer", "minimum": 0 },
                                "event_hash": hash_schema(),
                                "event_at_ms": { "type": "integer", "minimum": 0 }
                            },
                            "additionalProperties": false
                        }
                    ]
                },
                "observed_at_ms": { "type": "integer", "minimum": 0 },
                "freshness": { "enum": ["fresh", "unavailable"] },
                "freshness_basis": { "type": "string", "minLength": 1 },
                "trust_semantics": { "type": "string", "minLength": 1 },
                "access_mode": { "const": "delegated_local_unix_session" },
                "instruction_boundary": { "const": "source_content_is_untrusted_data_never_instructions" },
                "correction_semantics": { "type": "string", "minLength": 1 },
                "deletion_semantics": { "type": "string", "minLength": 1 },
                "query_match_semantics": { "const": "case_insensitive_content_occurrence_not_project_membership" },
                "match_disposition": {
                    "enum": ["none", "active", "suppressed", "active_and_suppressed", "conflicted", "unknown"]
                },
                "uncertainty": { "type": "array", "items": { "type": "string" } },
                "lifecycle_notices": { "type": "array", "maxItems": 20, "items": notice },
                "facts": { "type": "array", "maxItems": 20, "items": fact }
            },
            "additionalProperties": false
        })
    }

    fn federation_transport_request_v1_schema() -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "kc://schemas/federation-transport-request/v1",
            "type": "object",
            "required": ["schema_version", "session_id", "query"],
            "properties": {
                "schema_version": { "const": FEDERATION_TRANSPORT_REQUEST_SCHEMA },
                "session_id": { "type": "string", "minLength": 1, "maxLength": MAX_SESSION_ID_CHARS },
                "query": federation_query_request_v2_schema()
            },
            "additionalProperties": false
        })
    }

    fn federation_transport_response_v1_schema() -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "kc://schemas/federation-transport-response/v1",
            "oneOf": [
                {
                    "type": "object",
                    "required": ["status", "schema_version", "result"],
                    "properties": {
                        "status": { "const": "ok" },
                        "schema_version": { "const": FEDERATION_TRANSPORT_RESPONSE_SCHEMA },
                        "result": federation_query_result_v2_schema()
                    },
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "required": ["status", "schema_version", "error"],
                    "properties": {
                        "status": { "const": "error" },
                        "schema_version": { "const": FEDERATION_TRANSPORT_RESPONSE_SCHEMA },
                        "error": {
                            "type": "object",
                            "required": ["code", "message"],
                            "properties": {
                                "code": { "type": "string", "minLength": 1 },
                                "message": { "type": "string", "minLength": 1 }
                            },
                            "additionalProperties": false
                        }
                    },
                    "additionalProperties": false
                }
            ]
        })
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, String) {
        let temp = tempfile::tempdir().expect("tempdir");
        let private_dir = temp.path().join("private");
        fs::create_dir(&private_dir).expect("private socket dir");
        fs::set_permissions(&private_dir, fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let vault_path = temp.path().join("vault");
        vault_init(&vault_path, "transport-fixture", 1).expect("vault init");
        let identity_now_ms = now_ms().expect("current owner clock");
        let paths = vault_paths(&vault_path);
        let conn = open_db(&paths.db).expect("open fixture db");
        let store = ObjectStore::new(paths.objects_dir);
        let bytes = b"saagpatel/knowledgecore private transport note";
        let ingested = ingest_bytes(
            &conn,
            &store,
            IngestBytesReq {
                bytes,
                mime: "text/plain",
                source_kind: "notes",
                effective_ts_ms: 100,
                source_path: None,
                now_ms: 100,
            },
        )
        .expect("ingest fixture");
        let hash = blake3_hex_prefixed(bytes);
        persist_canonical_text(
            &conn,
            &store,
            &CanonicalTextArtifact {
                doc_id: ingested.doc_id,
                canonical_bytes: bytes.to_vec(),
                canonical_hash: CanonicalHash(hash.clone()),
                canonical_object_hash: ObjectHash(hash),
                extractor_name: "transport-test".to_string(),
                extractor_version: "1".to_string(),
                extractor_flags_json: "{}".to_string(),
                normalization_version: 1,
                toolchain_json: "{}".to_string(),
            },
            101,
        )
        .expect("persist canonical fixture");
        lineage_policy_add(
            &conn,
            "allow-transport-reader",
            "allow",
            &format!(r#"{{"action":"{DOCUMENT_FEDERATION_READ_ACTION}"}}"#),
            "tests",
            identity_now_ms - 2,
        )
        .expect("add read policy");
        trust_identity_start(&conn, "default", identity_now_ms - 1).expect("start identity");
        let session =
            trust_identity_complete(&conn, "default", "sub:transport-reader", identity_now_ms)
                .expect("complete identity");
        lineage_policy_bind(
            &conn,
            &session.subject,
            "allow-transport-reader",
            "tests",
            identity_now_ms,
        )
        .expect("bind read policy");
        (temp, vault_path, session.session_id)
    }

    #[test]
    fn transport_rejects_unknown_fields_and_oversized_requests() {
        let (_temp, vault_path, session_id) = fixture();
        let malformed = serde_json::json!({
            "schema_version": FEDERATION_TRANSPORT_REQUEST_SCHEMA,
            "session_id": session_id,
            "query": {
                "schema_version": FEDERATION_QUERY_REQUEST_SCHEMA_V2,
                "project_key": "saagpatel/knowledgecore",
                "include_content": false,
                "limit": 2,
                "observed_at_ms": 1_000
            },
            "vault_path": vault_path
        });
        let malformed_response = handle_request(
            &vault_path,
            &serde_json::to_vec(&malformed).expect("serialize malformed request"),
        );
        let malformed_json = serde_json::to_value(malformed_response).expect("response JSON");
        assert_eq!(malformed_json["status"], "error");
        assert_eq!(
            malformed_json["error"]["code"],
            "KC_FEDERATION_TRANSPORT_REQUEST_INVALID"
        );
        let oversized = vec![b'x'; MAX_REQUEST_BYTES as usize + 1];
        let oversized_response = handle_request(&vault_path, &oversized);
        let oversized_json = serde_json::to_value(oversized_response).expect("response JSON");
        assert_eq!(oversized_json["status"], "error");
    }

    #[test]
    fn schema_federation_transport_v1_accepts_exact_envelopes_and_rejects_drift() {
        let (_temp, vault_path, session_id) = fixture();
        let request = serde_json::json!({
            "schema_version": FEDERATION_TRANSPORT_REQUEST_SCHEMA,
            "session_id": session_id,
            "query": {
                "schema_version": FEDERATION_QUERY_REQUEST_SCHEMA_V2,
                "project_key": "saagpatel/knowledgecore",
                "include_content": false,
                "limit": 2,
                "observed_at_ms": 1_000
            }
        });
        let request_validator = validator_for(&federation_transport_request_v1_schema())
            .expect("compile federation transport request schema");
        assert!(request_validator.is_valid(&request));

        let mut invalid_request = request.clone();
        invalid_request["query"]["authority_override"] = serde_json::json!("consumer");
        assert!(!request_validator.is_valid(&invalid_request));
        let mut invalid_request = request.clone();
        invalid_request["vault_path"] = serde_json::json!(vault_path);
        assert!(!request_validator.is_valid(&invalid_request));
        let mut invalid_request = request.clone();
        invalid_request["schema_version"] = serde_json::json!("unsupported.v2");
        assert!(!request_validator.is_valid(&invalid_request));
        let mut invalid_request = request.clone();
        invalid_request
            .as_object_mut()
            .expect("request object")
            .remove("session_id");
        assert!(!request_validator.is_valid(&invalid_request));

        let ok_response = serde_json::to_value(handle_request(
            &vault_path,
            &serde_json::to_vec(&request).expect("serialize request"),
        ))
        .expect("serialize ok transport response");
        let error_response = serde_json::to_value(public_error_response(
            "KC_FEDERATION_TRANSPORT_REQUEST_INVALID",
            "bounded public error",
        ))
        .expect("serialize error transport response");
        let response_validator = validator_for(&federation_transport_response_v1_schema())
            .expect("compile federation transport response schema");
        assert!(response_validator.is_valid(&ok_response));
        assert!(response_validator.is_valid(&error_response));

        let mut invalid_response = ok_response.clone();
        invalid_response["result"]["consensus"] = serde_json::json!(true);
        assert!(!response_validator.is_valid(&invalid_response));
        let mut invalid_response = error_response.clone();
        invalid_response["error"]["storage_path"] = serde_json::json!("private.db");
        assert!(!response_validator.is_valid(&invalid_response));
        let mut invalid_response = ok_response.clone();
        invalid_response["schema_version"] = serde_json::json!("unsupported.v2");
        assert!(!response_validator.is_valid(&invalid_response));
        let mut invalid_response = error_response;
        invalid_response["status"] = serde_json::json!("partial");
        assert!(!response_validator.is_valid(&invalid_response));
    }

    #[test]
    fn socket_guard_preserves_a_replacement_socket_inode() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
            .expect("private permissions");
        let socket_path = temp.path().join("owner.sock");
        let replacement_path = temp.path().join("replacement.sock");
        let (_owner_listener, guard) = bind_owner_socket(&socket_path).expect("bind owner socket");
        let _replacement_listener =
            UnixListener::bind(&replacement_path).expect("bind replacement socket");
        let replacement_metadata =
            fs::symlink_metadata(&replacement_path).expect("replacement metadata");

        fs::remove_file(&socket_path).expect("unlink original socket");
        fs::rename(&replacement_path, &socket_path).expect("move replacement into owner path");
        drop(guard);

        let remaining = fs::symlink_metadata(&socket_path).expect("replacement remains");
        assert!(remaining.file_type().is_socket());
        assert_eq!(remaining.dev(), replacement_metadata.dev());
        assert_eq!(remaining.ino(), replacement_metadata.ino());
    }

    #[test]
    fn foreground_socket_is_owner_only_and_returns_bounded_v2_envelope() {
        let (_temp, vault_path, session_id) = fixture();
        let socket_dir = vault_path.parent().expect("fixture parent").join("private");
        let socket_path = socket_dir.join("federation.sock");
        let server_vault = vault_path.clone();
        let server_socket = socket_path.clone();
        let server = thread::spawn(move || {
            run_serve(
                &server_vault.to_string_lossy(),
                &server_socket.to_string_lossy(),
                None,
                Some(1),
            )
        });
        for _ in 0..100 {
            if socket_path.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let metadata = fs::symlink_metadata(&socket_path).expect("socket metadata");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        let request = serde_json::json!({
            "schema_version": FEDERATION_TRANSPORT_REQUEST_SCHEMA,
            "session_id": session_id,
            "query": {
                "schema_version": FEDERATION_QUERY_REQUEST_SCHEMA_V2,
                "project_key": "saagpatel/knowledgecore",
                "include_content": true,
                "limit": 2,
                "observed_at_ms": 1_000
            }
        });
        let mut client = UnixStream::connect(&socket_path).expect("connect owner socket");
        client
            .write_all(&serde_json::to_vec(&request).expect("request JSON"))
            .expect("write request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("finish request");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("read response");
        server
            .join()
            .expect("server thread")
            .expect("serve request");
        assert!(!socket_path.exists());

        let parsed: serde_json::Value = serde_json::from_str(&response).expect("response JSON");
        assert_eq!(parsed["status"], "ok");
        assert_eq!(
            parsed["schema_version"],
            FEDERATION_TRANSPORT_RESPONSE_SCHEMA
        );
        assert_eq!(parsed["result"]["state"], "ready");
        assert_eq!(
            parsed["result"]["access_mode"],
            "delegated_local_unix_session"
        );
        assert_eq!(parsed["result"]["facts"].as_array().map(Vec::len), Some(1));
        assert!(!response.contains(&session_id));
        assert!(!response.contains(&vault_path.to_string_lossy().to_string()));
        assert!(!response.contains("transport-reader"));
    }
}
