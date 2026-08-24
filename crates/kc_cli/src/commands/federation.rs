use kc_core::app_error::{AppError, AppResult};
use kc_core::federation::{
    federation_query_service_v2_authorized, FederationQueryRequestV2, FederationQueryResultV2,
};
use kc_core::rpc_service::vault_unlock_service;
use kc_core::vault::{vault_open, vault_paths};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const FEDERATION_TRANSPORT_REQUEST_SCHEMA: &str =
    "knowledgecore_federation_transport_request.v1";
pub const FEDERATION_TRANSPORT_RESPONSE_SCHEMA: &str =
    "knowledgecore_federation_transport_response.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SESSION_ID_CHARS: usize = 200;

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

    let (listener, _guard) = bind_owner_socket(Path::new(socket_path))?;
    println!(
        "{}",
        serde_json::json!({
            "schema_version": FEDERATION_TRANSPORT_RESPONSE_SCHEMA,
            "status": "ready"
        })
    );
    let mut served = 0usize;
    for incoming in listener.incoming() {
        let stream = incoming.map_err(|_| {
            transport_error(
                "KC_FEDERATION_TRANSPORT_IO_FAILED",
                "failed accepting a local federation request",
                true,
            )
        })?;
        let _ = serve_connection(vault_path, stream);
        served += 1;
        if max_requests.is_some_and(|limit| served >= limit) {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
