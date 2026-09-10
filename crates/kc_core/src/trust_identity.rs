use crate::app_error::{AppError, AppResult};
use crate::canon_json::to_canonical_bytes;
use crate::hashing::blake3_hex_prefixed;
use crate::trust_policy::ensure_session_policy_allows;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

const DEFAULT_SESSION_TTL_MS: i64 = 60 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityProviderRecord {
    pub provider_id: String,
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub enabled: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityStartResult {
    pub provider_id: String,
    pub state: String,
    pub authorization_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentitySessionRecord {
    pub session_id: String,
    pub provider_id: String,
    pub subject: String,
    pub claim_subset_json: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCertificateRecord {
    pub cert_id: String,
    pub device_id: String,
    pub provider_id: String,
    pub subject: String,
    pub cert_chain_hash: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub verified_at_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorIdentityRecord {
    pub device_id: String,
    pub fingerprint: String,
    pub cert_id: String,
    pub cert_chain_hash: String,
}

fn identity_error(code: &str, message: &str, details: serde_json::Value) -> AppError {
    AppError::new(code, "trust_identity", message, false, details)
}

fn provider_ref_is_issuer(provider_ref: &str) -> bool {
    let trimmed = provider_ref.trim();
    trimmed.starts_with("https://") || trimmed.starts_with("http://")
}

fn normalize_issuer(issuer: &str) -> AppResult<String> {
    let normalized = issuer.trim().trim_end_matches('/').to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(identity_error(
            "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
            "issuer is required",
            serde_json::json!({}),
        ));
    }
    if !provider_ref_is_issuer(&normalized) {
        return Err(identity_error(
            "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
            "issuer must use http(s) scheme",
            serde_json::json!({ "issuer": normalized }),
        ));
    }
    Ok(normalized)
}

pub fn provider_id_from_issuer(issuer: &str) -> AppResult<String> {
    let normalized = normalize_issuer(issuer)?;
    let hash =
        blake3_hex_prefixed(format!("kc.trust.provider.discovery.v1\n{}", normalized).as_bytes());
    Ok(format!("auto-{}", &hash[7..19]))
}

fn default_issuer(provider_id: &str) -> String {
    format!("https://{}.oidc.knowledgecore.local", provider_id)
}

fn default_audience(provider_id: &str) -> String {
    format!("kc-desktop:{}", provider_id)
}

fn default_jwks_url(provider_id: &str) -> String {
    format!("{}/.well-known/jwks.json", default_issuer(provider_id))
}

pub fn discover_identity_provider(
    conn: &Connection,
    issuer: &str,
    now_ms: i64,
) -> AppResult<IdentityProviderRecord> {
    let normalized_issuer = normalize_issuer(issuer)?;
    let provider_id = provider_id_from_issuer(&normalized_issuer)?;
    let audience = default_audience(&provider_id);
    let jwks_url = format!("{}/.well-known/jwks.json", normalized_issuer);
    upsert_identity_provider_with_jwks(
        conn,
        &provider_id,
        &normalized_issuer,
        &audience,
        &jwks_url,
        now_ms,
    )
}

fn canonical_json_string(value: serde_json::Value) -> AppResult<String> {
    let bytes = to_canonical_bytes(&value)?;
    String::from_utf8(bytes).map_err(|e| {
        identity_error(
            "KC_TRUST_IDENTITY_INVALID",
            "failed building canonical claim subset JSON",
            serde_json::json!({ "error": e.to_string() }),
        )
    })
}

fn load_provider(
    conn: &Connection,
    provider_id: &str,
) -> AppResult<Option<IdentityProviderRecord>> {
    conn.query_row(
        "SELECT provider_id, issuer, audience, jwks_url, enabled, created_at_ms, updated_at_ms
         FROM trust_providers
         WHERE provider_id=?1",
        [provider_id],
        |row| {
            Ok(IdentityProviderRecord {
                provider_id: row.get(0)?,
                issuer: row.get(1)?,
                audience: row.get(2)?,
                jwks_url: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
                created_at_ms: row.get(5)?,
                updated_at_ms: row.get(6)?,
            })
        },
    )
    .optional()
    .or_else(|e| {
        // Compatibility fallback for vaults that still only have the legacy table.
        conn.query_row(
            "SELECT provider_id, issuer, audience, enabled, created_at_ms
             FROM identity_providers
             WHERE provider_id=?1",
            [provider_id],
            |row| {
                Ok(IdentityProviderRecord {
                    provider_id: row.get(0)?,
                    issuer: row.get(1)?,
                    audience: row.get(2)?,
                    jwks_url: format!("{}/.well-known/jwks.json", row.get::<_, String>(1)?),
                    enabled: row.get::<_, i64>(3)? != 0,
                    created_at_ms: row.get(4)?,
                    updated_at_ms: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|fallback_err| {
            identity_error(
                "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
                "failed reading identity provider",
                serde_json::json!({
                    "error": fallback_err.to_string(),
                    "fallback_error": e.to_string(),
                    "provider_id": provider_id
                }),
            )
        })
    })
}

pub fn upsert_identity_provider(
    conn: &Connection,
    provider_id: &str,
    issuer: &str,
    audience: &str,
    now_ms: i64,
) -> AppResult<IdentityProviderRecord> {
    upsert_identity_provider_with_jwks(
        conn,
        provider_id,
        issuer,
        audience,
        &default_jwks_url(provider_id),
        now_ms,
    )
}

pub fn upsert_identity_provider_with_jwks(
    conn: &Connection,
    provider_id: &str,
    issuer: &str,
    audience: &str,
    jwks_url: &str,
    now_ms: i64,
) -> AppResult<IdentityProviderRecord> {
    if provider_id.trim().is_empty() {
        return Err(identity_error(
            "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
            "provider_id is required",
            serde_json::json!({}),
        ));
    }

    conn.execute(
        "INSERT INTO trust_providers(provider_id, issuer, audience, jwks_url, enabled, created_at_ms, updated_at_ms)
         VALUES(?1, ?2, ?3, ?4, 1, ?5, ?5)
         ON CONFLICT(provider_id) DO UPDATE SET
           issuer=excluded.issuer,
           audience=excluded.audience,
           jwks_url=excluded.jwks_url,
           enabled=1,
           updated_at_ms=excluded.updated_at_ms",
        params![provider_id, issuer, audience, jwks_url, now_ms],
    )
    .map_err(|e| {
        identity_error(
            "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
            "failed writing trust provider",
            serde_json::json!({ "error": e.to_string(), "provider_id": provider_id }),
        )
    })?;

    // Keep legacy table in sync for compatibility.
    conn.execute(
        "INSERT INTO identity_providers(provider_id, issuer, audience, enabled, created_at_ms)
         VALUES(?1, ?2, ?3, 1, ?4)
         ON CONFLICT(provider_id) DO UPDATE SET issuer=excluded.issuer, audience=excluded.audience, enabled=1",
        params![provider_id, issuer, audience, now_ms],
    )
    .map_err(|e| {
        identity_error(
            "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
            "failed writing identity provider",
            serde_json::json!({ "error": e.to_string(), "provider_id": provider_id }),
        )
    })?;

    load_provider(conn, provider_id)?.ok_or_else(|| {
        identity_error(
            "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
            "identity provider missing after upsert",
            serde_json::json!({ "provider_id": provider_id }),
        )
    })
}

pub fn trust_provider_add(
    conn: &Connection,
    provider_id: &str,
    issuer: &str,
    audience: &str,
    jwks_url: &str,
    now_ms: i64,
) -> AppResult<IdentityProviderRecord> {
    if issuer.trim().is_empty() || audience.trim().is_empty() || jwks_url.trim().is_empty() {
        return Err(identity_error(
            "KC_TRUST_PROVIDER_POLICY_INVALID",
            "issuer, audience, and jwks_url are required",
            serde_json::json!({
                "provider_id": provider_id,
                "issuer": issuer,
                "audience": audience,
                "jwks_url": jwks_url
            }),
        ));
    }
    upsert_identity_provider_with_jwks(conn, provider_id, issuer, audience, jwks_url, now_ms)
}

pub fn trust_provider_disable(
    conn: &Connection,
    provider_id: &str,
    now_ms: i64,
) -> AppResult<IdentityProviderRecord> {
    let provider = load_provider(conn, provider_id)?.ok_or_else(|| {
        identity_error(
            "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
            "identity provider is not registered",
            serde_json::json!({ "provider_id": provider_id }),
        )
    })?;

    conn.execute(
        "UPDATE trust_providers SET enabled=0, updated_at_ms=?2 WHERE provider_id=?1",
        params![provider_id, now_ms],
    )
    .map_err(|e| {
        identity_error(
            "KC_TRUST_PROVIDER_DISABLED",
            "failed disabling trust provider",
            serde_json::json!({ "error": e.to_string(), "provider_id": provider_id }),
        )
    })?;
    conn.execute(
        "UPDATE identity_providers SET enabled=0 WHERE provider_id=?1",
        params![provider_id],
    )
    .map_err(|e| {
        identity_error(
            "KC_TRUST_PROVIDER_DISABLED",
            "failed disabling legacy identity provider",
            serde_json::json!({ "error": e.to_string(), "provider_id": provider_id }),
        )
    })?;

    let mut out = provider;
    out.enabled = false;
    out.updated_at_ms = now_ms;
    Ok(out)
}

pub fn trust_provider_list(conn: &Connection) -> AppResult<Vec<IdentityProviderRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT provider_id, issuer, audience, jwks_url, enabled, created_at_ms, updated_at_ms
             FROM trust_providers
             ORDER BY provider_id ASC",
        )
        .map_err(|e| {
            identity_error(
                "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
                "failed preparing trust provider list query",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let rows = stmt
        .query_map([], |row| {
            Ok(IdentityProviderRecord {
                provider_id: row.get(0)?,
                issuer: row.get(1)?,
                audience: row.get(2)?,
                jwks_url: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
                created_at_ms: row.get(5)?,
                updated_at_ms: row.get(6)?,
            })
        })
        .map_err(|e| {
            identity_error(
                "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
                "failed querying trust provider list",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| {
            identity_error(
                "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
                "failed decoding trust provider row",
                serde_json::json!({ "error": e.to_string() }),
            )
        })?);
    }
    Ok(out)
}

pub fn trust_identity_start(
    conn: &Connection,
    provider_ref: &str,
    now_ms: i64,
) -> AppResult<IdentityStartResult> {
    let provider = if provider_ref_is_issuer(provider_ref) {
        discover_identity_provider(conn, provider_ref, now_ms)?
    } else {
        match load_provider(conn, provider_ref)? {
            Some(existing) => existing,
            None => upsert_identity_provider(
                conn,
                provider_ref,
                &default_issuer(provider_ref),
                &default_audience(provider_ref),
                now_ms,
            )?,
        }
    };

    if !provider.enabled {
        return Err(identity_error(
            "KC_TRUST_PROVIDER_DISABLED",
            "identity provider is disabled",
            serde_json::json!({ "provider_id": provider.provider_id }),
        ));
    }

    let state = blake3_hex_prefixed(
        format!(
            "kc.trust.oidc.state.v1\n{}\n{}\n{}",
            provider.provider_id, provider.issuer, now_ms
        )
        .as_bytes(),
    );
    let authorization_url = format!(
        "{}?aud={}&state={}",
        provider.issuer, provider.audience, state
    );
    Ok(IdentityStartResult {
        provider_id: provider.provider_id,
        state,
        authorization_url,
    })
}

fn normalized_subject(provider_id: &str, auth_code: &str) -> String {
    if let Some(value) = auth_code.strip_prefix("sub:") {
        value.trim().to_string()
    } else {
        blake3_hex_prefixed(
            format!("kc.trust.oidc.subject.v1\n{}\n{}", provider_id, auth_code).as_bytes(),
        )
    }
}

pub fn trust_identity_complete(
    conn: &Connection,
    provider_ref: &str,
    auth_code: &str,
    now_ms: i64,
) -> AppResult<IdentitySessionRecord> {
    let provider = if provider_ref_is_issuer(provider_ref) {
        discover_identity_provider(conn, provider_ref, now_ms)?
    } else {
        load_provider(conn, provider_ref)?.ok_or_else(|| {
            identity_error(
                "KC_TRUST_OIDC_PROVIDER_UNAVAILABLE",
                "identity provider is not registered",
                serde_json::json!({ "provider_id": provider_ref }),
            )
        })?
    };
    if !provider.enabled {
        return Err(identity_error(
            "KC_TRUST_PROVIDER_DISABLED",
            "identity provider is disabled",
            serde_json::json!({ "provider_id": provider.provider_id }),
        ));
    }
    if auth_code.trim().is_empty() {
        return Err(identity_error(
            "KC_TRUST_IDENTITY_INVALID",
            "auth_code is required",
            serde_json::json!({ "provider_id": provider.provider_id }),
        ));
    }

    let provider_id = provider.provider_id.clone();
    let provider_issuer = provider.issuer.clone();
    let provider_audience = provider.audience.clone();

    let subject = normalized_subject(&provider_id, auth_code);
    let issued_at_ms = now_ms;
    let expires_at_ms = now_ms + DEFAULT_SESSION_TTL_MS;
    let claim_subset_json = canonical_json_string(serde_json::json!({
        "aud": provider_audience,
        "exp": expires_at_ms,
        "iat": issued_at_ms,
        "iss": provider_issuer,
        "sub": subject
    }))?;
    let session_id = uuid::Uuid::new_v4().to_string();

    conn.execute(
        "INSERT INTO identity_sessions(session_id, provider_id, subject, claim_subset_json, issued_at_ms, expires_at_ms, created_at_ms)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            session_id,
            provider_id,
            subject,
            claim_subset_json,
            issued_at_ms,
            expires_at_ms,
            now_ms
        ],
    )
    .map_err(|e| {
        identity_error(
            "KC_TRUST_IDENTITY_INVALID",
            "failed creating identity session",
            serde_json::json!({ "error": e.to_string(), "provider_id": provider_ref }),
        )
    })?;

    ensure_session_policy_allows(
        conn,
        &provider.provider_id,
        &session_id,
        &claim_subset_json,
        issued_at_ms,
        expires_at_ms,
        now_ms,
    )?;

    Ok(IdentitySessionRecord {
        session_id,
        provider_id: provider.provider_id,
        subject,
        claim_subset_json,
        issued_at_ms,
        expires_at_ms,
        created_at_ms: now_ms,
    })
}

fn latest_session_subject(conn: &Connection, provider_id: &str, now_ms: i64) -> AppResult<String> {
    conn.query_row(
        "SELECT s.subject
         FROM identity_sessions s
         JOIN trust_providers p ON p.provider_id=s.provider_id
         LEFT JOIN trust_session_revocations r ON r.session_id=s.session_id
         WHERE s.provider_id=?1
           AND s.expires_at_ms>=?2
           AND p.enabled=1
           AND r.session_id IS NULL
         ORDER BY s.created_at_ms DESC, s.session_id DESC
         LIMIT 1",
        params![provider_id, now_ms],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|e| {
        identity_error(
            "KC_TRUST_IDENTITY_INVALID",
            "failed reading identity session",
            serde_json::json!({ "error": e.to_string(), "provider_id": provider_id }),
        )
    })?
    .ok_or_else(|| {
        identity_error(
            "KC_TRUST_IDENTITY_INVALID",
            "no non-expired identity session available for provider",
            serde_json::json!({ "provider_id": provider_id }),
        )
    })
}

fn device_fingerprint(conn: &Connection, device_id: &str) -> AppResult<String> {
    conn.query_row(
        "SELECT fingerprint
         FROM trusted_devices
         WHERE device_id=?1 AND verified_at_ms IS NOT NULL",
        [device_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|e| {
        identity_error(
            "KC_TRUST_DEVICE_NOT_ENROLLED",
            "failed reading trusted device fingerprint",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
        )
    })?
    .ok_or_else(|| {
        identity_error(
            "KC_TRUST_DEVICE_NOT_ENROLLED",
            "device must be trusted and verified before enrollment",
            serde_json::json!({ "device_id": device_id }),
        )
    })
}

pub fn expected_cert_chain_hash(cert_id: &str, device_id: &str, fingerprint: &str) -> String {
    blake3_hex_prefixed(
        format!(
            "kc.trust.cert.chain.v1\n{}\n{}\n{}",
            cert_id, device_id, fingerprint
        )
        .as_bytes(),
    )
}

pub fn trust_device_enroll(
    conn: &Connection,
    provider_id: &str,
    device_id: &str,
    now_ms: i64,
) -> AppResult<DeviceCertificateRecord> {
    let fingerprint = device_fingerprint(conn, device_id)?;
    let subject = latest_session_subject(conn, provider_id, now_ms)?;
    let cert_id = uuid::Uuid::new_v4().to_string();
    let cert_chain_hash = expected_cert_chain_hash(&cert_id, device_id, &fingerprint);
    let expires_at_ms = now_ms + DEFAULT_SESSION_TTL_MS;

    conn.execute(
        "INSERT INTO device_certificates(
           cert_id, device_id, provider_id, subject, cert_chain_hash,
           issued_at_ms, expires_at_ms, verified_at_ms, created_at_ms
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
        params![
            cert_id,
            device_id,
            provider_id,
            subject,
            cert_chain_hash,
            now_ms,
            expires_at_ms,
            now_ms
        ],
    )
    .map_err(|e| {
        identity_error(
            "KC_TRUST_DEVICE_NOT_ENROLLED",
            "failed creating device certificate record",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
        )
    })?;

    Ok(DeviceCertificateRecord {
        cert_id,
        device_id: device_id.to_string(),
        provider_id: provider_id.to_string(),
        subject,
        cert_chain_hash,
        issued_at_ms: now_ms,
        expires_at_ms,
        verified_at_ms: None,
        created_at_ms: now_ms,
    })
}

fn load_certificate(
    conn: &Connection,
    cert_id: &str,
) -> AppResult<Option<DeviceCertificateRecord>> {
    conn.query_row(
        "SELECT cert_id, device_id, provider_id, subject, cert_chain_hash, issued_at_ms, expires_at_ms, verified_at_ms, created_at_ms
         FROM device_certificates
         WHERE cert_id=?1",
        [cert_id],
        |row| {
            Ok(DeviceCertificateRecord {
                cert_id: row.get(0)?,
                device_id: row.get(1)?,
                provider_id: row.get(2)?,
                subject: row.get(3)?,
                cert_chain_hash: row.get(4)?,
                issued_at_ms: row.get(5)?,
                expires_at_ms: row.get(6)?,
                verified_at_ms: row.get(7)?,
                created_at_ms: row.get(8)?,
            })
        },
    )
    .optional()
    .map_err(|e| {
        identity_error(
            "KC_TRUST_CERT_CHAIN_INVALID",
            "failed reading device certificate record",
            serde_json::json!({ "error": e.to_string(), "cert_id": cert_id }),
        )
    })
}

pub fn latest_device_certificate(
    conn: &Connection,
    device_id: &str,
) -> AppResult<Option<DeviceCertificateRecord>> {
    conn.query_row(
        "SELECT cert_id, device_id, provider_id, subject, cert_chain_hash, issued_at_ms, expires_at_ms, verified_at_ms, created_at_ms
         FROM device_certificates
         WHERE device_id=?1
         ORDER BY created_at_ms DESC, cert_id DESC
         LIMIT 1",
        [device_id],
        |row| {
            Ok(DeviceCertificateRecord {
                cert_id: row.get(0)?,
                device_id: row.get(1)?,
                provider_id: row.get(2)?,
                subject: row.get(3)?,
                cert_chain_hash: row.get(4)?,
                issued_at_ms: row.get(5)?,
                expires_at_ms: row.get(6)?,
                verified_at_ms: row.get(7)?,
                created_at_ms: row.get(8)?,
            })
        },
    )
    .optional()
    .map_err(|e| {
        identity_error(
            "KC_TRUST_CERT_CHAIN_INVALID",
            "failed reading latest device certificate",
            serde_json::json!({ "error": e.to_string(), "device_id": device_id }),
        )
    })
}

pub fn trust_device_verify_chain(
    conn: &Connection,
    device_id: &str,
    now_ms: i64,
) -> AppResult<DeviceCertificateRecord> {
    let certificate = latest_device_certificate(conn, device_id)?.ok_or_else(|| {
        identity_error(
            "KC_TRUST_CERT_CHAIN_INVALID",
            "device has no certificate enrollment",
            serde_json::json!({ "device_id": device_id }),
        )
    })?;
    let fingerprint = device_fingerprint(conn, &certificate.device_id)?;
    let expected_chain =
        expected_cert_chain_hash(&certificate.cert_id, &certificate.device_id, &fingerprint);
    if expected_chain != certificate.cert_chain_hash {
        return Err(identity_error(
            "KC_TRUST_CERT_CHAIN_INVALID",
            "certificate chain hash mismatch",
            serde_json::json!({
                "cert_id": certificate.cert_id,
                "expected": expected_chain,
                "actual": certificate.cert_chain_hash
            }),
        ));
    }

    conn.execute(
        "UPDATE device_certificates SET verified_at_ms=?1 WHERE cert_id=?2",
        params![now_ms, certificate.cert_id],
    )
    .map_err(|e| {
        identity_error(
            "KC_TRUST_CERT_CHAIN_INVALID",
            "failed updating certificate verification timestamp",
            serde_json::json!({ "error": e.to_string(), "cert_id": certificate.cert_id }),
        )
    })?;

    load_certificate(conn, &certificate.cert_id)?.ok_or_else(|| {
        identity_error(
            "KC_TRUST_CERT_CHAIN_INVALID",
            "certificate disappeared after verification",
            serde_json::json!({ "cert_id": certificate.cert_id }),
        )
    })
}

pub fn verified_author_identity(conn: &Connection) -> AppResult<AuthorIdentityRecord> {
    conn.query_row(
        "SELECT d.device_id, d.fingerprint, c.cert_id, c.cert_chain_hash
         FROM device_certificates c
         JOIN trusted_devices d ON d.device_id=c.device_id
         WHERE d.verified_at_ms IS NOT NULL
           AND c.verified_at_ms IS NOT NULL
         ORDER BY c.created_at_ms ASC, c.cert_id ASC
         LIMIT 1",
        [],
        |row| {
            Ok(AuthorIdentityRecord {
                device_id: row.get(0)?,
                fingerprint: row.get(1)?,
                cert_id: row.get(2)?,
                cert_chain_hash: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(|e| {
        identity_error(
            "KC_TRUST_DEVICE_NOT_ENROLLED",
            "failed loading verified author identity",
            serde_json::json!({ "error": e.to_string() }),
        )
    })?
    .ok_or_else(|| {
        identity_error(
            "KC_TRUST_DEVICE_NOT_ENROLLED",
            "no verified enrolled author identity is available",
            serde_json::json!({}),
        )
    })
}

pub fn verify_author_chain(
    conn: &Connection,
    device_id: &str,
    cert_id: &str,
    chain_hash_value: &str,
) -> AppResult<()> {
    let cert = load_certificate(conn, cert_id)?.ok_or_else(|| {
        identity_error(
            "KC_TRUST_CERT_CHAIN_INVALID",
            "certificate record not found",
            serde_json::json!({ "cert_id": cert_id }),
        )
    })?;
    if cert.device_id != device_id {
        return Err(identity_error(
            "KC_TRUST_CERT_CHAIN_INVALID",
            "certificate is not bound to requested device",
            serde_json::json!({ "cert_id": cert_id, "device_id": device_id }),
        ));
    }
    if cert.verified_at_ms.is_none() {
        return Err(identity_error(
            "KC_TRUST_DEVICE_NOT_ENROLLED",
            "certificate chain is not verified",
            serde_json::json!({ "cert_id": cert_id, "device_id": device_id }),
        ));
    }
    if cert.cert_chain_hash != chain_hash_value {
        return Err(identity_error(
            "KC_TRUST_CERT_CHAIN_INVALID",
            "certificate chain hash does not match",
            serde_json::json!({
                "cert_id": cert_id,
                "expected": cert.cert_chain_hash,
                "actual": chain_hash_value
            }),
        ));
    }
    Ok(())
}
