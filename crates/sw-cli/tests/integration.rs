use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;
use sw_ipc::IpcMessage;
use tempfile::tempdir;

fn spawn_mock_server<F>(handler: F) -> (tempfile::TempDir, PathBuf, std::thread::JoinHandle<()>)
where
    F: FnOnce(IpcMessage) -> IpcMessage + Send + 'static,
{
    let dir = tempdir().expect("Failed to create tempdir");
    let socket_path = dir.path().join("mock_agent.sock");
    let sock_clone = socket_path.clone();

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime");

        rt.block_on(async move {
            let listener =
                tokio::net::UnixListener::bind(&sock_clone).expect("Failed to bind socket");
            let (mut stream, _) = listener.accept().await.expect("Failed to accept");
            let req = sw_ipc::read_message(&mut stream)
                .await
                .expect("Failed to read message");
            let resp = handler(req);
            sw_ipc::write_message(&mut stream, &resp)
                .await
                .expect("Failed to write message");
        });
    });

    let start = std::time::Instant::now();
    while !socket_path.exists() {
        if start.elapsed() > std::time::Duration::from_secs(5) {
            panic!("Mock server socket creation timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    (dir, socket_path, handle)
}

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("silverwarden"));
}

#[test]
fn test_cli_status_no_agent() {
    let non_existent = PathBuf::from("/tmp/nonexistent_silverwarden_agent_sock.sock");
    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.args(["--socket", non_existent.to_str().unwrap(), "status"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("El archivo de socket no existe"));
}

#[test]
fn test_cli_status_with_mock_agent() {
    let (_dir, socket_path, handle) = spawn_mock_server(|req| {
        assert_eq!(req.action, "Status");
        IpcMessage::new(
            "Success",
            serde_json::json!({
                "locked": false,
                "has_pin": true,
                "logged_in": true,
                "version": "0.1.0"
            }),
        )
    });

    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.args(["--socket", socket_path.to_str().unwrap(), "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Estado del Agente SilverWarden (v0.1.0)",
        ))
        .stdout(predicate::str::contains("Bloqueado:        No"))
        .stdout(predicate::str::contains("PIN configurado:  Sí"))
        .stdout(predicate::str::contains("Sesión iniciada:  Sí"));

    handle.join().unwrap();
}

#[test]
fn test_cli_unlock_with_mock_agent() {
    let (_dir, socket_path, handle) = spawn_mock_server(|req| {
        assert_eq!(req.action, "Unlock");
        assert_eq!(req.payload.get("pin").unwrap(), "1234");
        IpcMessage::new("Success", serde_json::json!({"status": "unlocked"}))
    });

    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.args([
        "--socket",
        socket_path.to_str().unwrap(),
        "unlock",
        "--pin",
        "1234",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("Bóveda desbloqueada con éxito."));

    handle.join().unwrap();
}

#[test]
fn test_cli_unlock_agent_error() {
    let (_dir, socket_path, handle) = spawn_mock_server(|req| {
        assert_eq!(req.action, "Unlock");
        IpcMessage::new("Error", serde_json::json!({"error": "PIN incorrecto"}))
    });

    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.args([
        "--socket",
        socket_path.to_str().unwrap(),
        "unlock",
        "--pin",
        "wrong_pin",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("Error del agente: PIN incorrecto"));

    handle.join().unwrap();
}

#[test]
fn test_cli_lock_with_mock_agent() {
    let (_dir, socket_path, handle) = spawn_mock_server(|req| {
        assert_eq!(req.action, "Lock");
        IpcMessage::new("Success", serde_json::json!({}))
    });

    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.args(["--socket", socket_path.to_str().unwrap(), "lock"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Bóveda bloqueada y sesiones en memoria eliminadas.",
        ));

    handle.join().unwrap();
}

#[test]
fn test_cli_pin_set_with_mock_agent() {
    let (_dir, socket_path, handle) = spawn_mock_server(|req| {
        assert_eq!(req.action, "PinSet");
        assert_eq!(req.payload.get("pin").unwrap(), "998877");
        IpcMessage::new("Success", serde_json::json!({}))
    });

    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.args([
        "--socket",
        socket_path.to_str().unwrap(),
        "pin",
        "set",
        "--pin",
        "998877",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("PIN configurado exitosamente."));

    handle.join().unwrap();
}

#[test]
fn test_cli_pin_update_with_mock_agent() {
    let (_dir, socket_path, handle) = spawn_mock_server(|req| {
        assert_eq!(req.action, "PinUpdate");
        assert_eq!(req.payload.get("old_pin").unwrap(), "111111");
        assert_eq!(req.payload.get("new_pin").unwrap(), "222222");
        IpcMessage::new("Success", serde_json::json!({}))
    });

    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.args([
        "--socket",
        socket_path.to_str().unwrap(),
        "pin",
        "update",
        "--old-pin",
        "111111",
        "--new-pin",
        "222222",
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("PIN actualizado exitosamente."));

    handle.join().unwrap();
}

#[test]
fn test_cli_local_commands() {
    let temp_home = tempdir().unwrap();

    // Sync without login must fail with clear error
    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.env("HOME", temp_home.path().to_str().unwrap())
        .arg("sync")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "No hay sesión iniciada. Ejecuta 'silverwarden login' primero.",
        ));

    // SSH List
    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.args(["ssh", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Listando claves SSH registradas...",
        ));

    // SSH Add
    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.args(["ssh", "add", "id_ed25519"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Registrando clave SSH id_ed25519"));
}

#[test]
fn test_cli_goldwarden_go_conflict_warning() {
    let temp_dir = tempdir().unwrap();
    let home = temp_dir.path().to_path_buf();
    let go_sock = home.join(".goldwarden.sock");
    std::fs::write(&go_sock, b"").unwrap();

    let mut cmd = Command::cargo_bin("silverwarden").unwrap();
    cmd.env("HOME", home.to_str().unwrap())
        .args(["--socket", "/tmp/nonexistent.sock", "status"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "ADVERTENCIA: Goldwarden Go está corriendo",
        ));
}
