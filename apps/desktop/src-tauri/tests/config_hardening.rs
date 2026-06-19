use std::path::Path;

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(path: impl AsRef<Path>) -> serde_json::Value {
    let path = path.as_ref();
    let bytes = std::fs::read(path).unwrap_or_else(|err| {
        panic!("failed reading {}: {err}", path.display());
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        panic!("failed parsing {}: {err}", path.display());
    })
}

#[test]
fn tauri_config_uses_restrictive_local_csp() {
    let config = read_json(manifest_dir().join("tauri.conf.json"));
    let csp = config
        .pointer("/app/security/csp")
        .and_then(|value| value.as_str())
        .expect("desktop csp must be a non-null string");

    for required in [
        "default-src 'self'",
        "script-src 'self'",
        "connect-src 'self' ipc: http://ipc.localhost",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ] {
        assert!(
            csp.contains(required),
            "desktop csp is missing required directive: {required}"
        );
    }

    for forbidden in ["default-src *", "script-src *", "unsafe-eval"] {
        assert!(
            !csp.contains(forbidden),
            "desktop csp contains forbidden directive: {forbidden}"
        );
    }
}

#[test]
fn primary_window_has_stable_local_capability_binding() {
    let config = read_json(manifest_dir().join("tauri.conf.json"));
    let window = config
        .pointer("/app/windows/0")
        .and_then(|value| value.as_object())
        .expect("primary desktop window must be configured");
    assert_eq!(
        window.get("label").and_then(|value| value.as_str()),
        Some("main")
    );

    let capability = read_json(manifest_dir().join("capabilities/main.json"));
    assert_eq!(
        capability
            .get("identifier")
            .and_then(|value| value.as_str()),
        Some("main-local-vault")
    );
    assert_eq!(
        capability.get("windows").and_then(|value| value.as_array()),
        Some(&vec![serde_json::Value::String("main".to_string())])
    );
    assert!(
        capability.get("remote").is_none(),
        "main desktop capability must not grant remote URL access"
    );

    let permissions = capability
        .get("permissions")
        .and_then(|value| value.as_array())
        .expect("main desktop capability must declare permissions");
    assert!(
        permissions.is_empty(),
        "main desktop capability must not grant core plugin permissions"
    );
}
