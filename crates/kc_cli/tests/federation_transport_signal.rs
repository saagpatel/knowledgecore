use kc_core::vault::vault_init;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn wait_for_socket(&mut self, socket_path: &Path) {
        for _ in 0..400 {
            if socket_path.exists() {
                return;
            }
            if let Some(status) = self.child.try_wait().expect("poll federation server") {
                panic!("federation server exited before binding: {status}");
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("federation server did not bind its socket");
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        for _ in 0..400 {
            if let Some(status) = self.child.try_wait().expect("poll federation server") {
                return status;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("federation server did not exit after shutdown signal");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[test]
fn federation_transport_signals_remove_socket_and_permit_rebind() {
    for signal in ["TERM", "INT"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let vault_path = temp.path().join("vault");
        vault_init(&vault_path, "signal-cleanup-fixture", 1).expect("vault init");
        let socket_dir = temp.path().join("private");
        fs::create_dir(&socket_dir).expect("private socket dir");
        fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o700))
            .expect("private socket permissions");
        let socket_path = socket_dir.join(format!("federation-{signal}.sock"));

        let child = Command::new(env!("CARGO_BIN_EXE_kc_cli"))
            .args([
                "federation",
                "serve",
                &vault_path.to_string_lossy(),
                "--socket-path",
                &socket_path.to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn federation server");
        let mut server = ChildGuard { child };
        server.wait_for_socket(&socket_path);

        let signal_status = Command::new("/bin/kill")
            .args([format!("-{signal}"), server.child.id().to_string()])
            .status()
            .expect("send shutdown signal");
        assert!(signal_status.success(), "failed sending SIG{signal}");

        let exit_status = server.wait_for_exit();
        assert!(
            exit_status.success(),
            "federation server failed after SIG{signal}: {exit_status}"
        );
        assert!(
            !socket_path.exists(),
            "socket remained after SIG{signal} shutdown"
        );

        let rebound = UnixListener::bind(&socket_path).expect("rebind cleaned socket path");
        drop(rebound);
        fs::remove_file(&socket_path).expect("remove rebound test socket");
    }
}
