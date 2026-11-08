use crate::*;

pub async fn handle(dry_run: &bool, no_enable: &bool) -> Result<String, CliError> {
    let exec_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "silverwarden".to_string());

    let unit_content = systemd::render_systemd_unit(&exec_path);
    let policy_content = systemd::render_polkit_policy();

    let home = std::env::var("HOME").map_err(|e| CliError::Config(format!("No HOME: {e}")))?;
    let systemd_dir = PathBuf::from(&home).join(".config/systemd/user");
    let polkit_dir = PathBuf::from(&home).join(".local/share/polkit-1/actions");
    let unit_path = systemd_dir.join("silverwarden.service");
    let policy_path = polkit_dir.join("org.silverwarden.unlock.policy");

    if *dry_run {
        return Ok(format!(
            "=== {} ===\n{}\n=== {} ===\n{}\n",
            unit_path.display(),
            unit_content,
            policy_path.display(),
            policy_content,
        ));
    }

    std::fs::create_dir_all(&systemd_dir).map_err(|e| CliError::Io(e.to_string()))?;
    std::fs::create_dir_all(&polkit_dir).map_err(|e| CliError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&systemd_dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(&polkit_dir, std::fs::Permissions::from_mode(0o700));
    }

    std::fs::write(&unit_path, &unit_content).map_err(|e| CliError::Io(e.to_string()))?;
    std::fs::write(&policy_path, &policy_content).map_err(|e| CliError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&unit_path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600));
    }

    let verify_output = std::process::Command::new("systemd-analyze")
        .arg("verify")
        .arg(&unit_path)
        .output();
    let mut warnings = Vec::new();
    match verify_output {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            warnings.push(format!(
                "systemd-analyze verify advirtió: {}",
                stderr.trim()
            ));
        }
        Err(_) => {
            warnings.push("systemd-analyze no disponible; se omite la verificación".to_string());
        }
    }

    let mut systemctl_messages = Vec::new();
    if !no_enable {
        let reload = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
        if let Ok(out) = reload {
            if !out.status.success() {
                systemctl_messages.push(format!(
                    "systemctl --user daemon-reload falló: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        } else {
            systemctl_messages.push(
                "systemctl no disponible; ejecuta manualmente: systemctl --user daemon-reload"
                    .to_string(),
            );
        }

        let enable = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "silverwarden.service"])
            .output();
        match enable {
            Ok(out) if out.status.success() => {
                systemctl_messages
                    .push("Servicio silverwarden.service habilitado y arrancado".to_string());
            }
            Ok(out) => {
                systemctl_messages.push(format!(
                            "systemctl --user enable --now falló: {}. Ejecuta manualmente: systemctl --user enable --now silverwarden.service",
                            String::from_utf8_lossy(&out.stderr).trim()
                        ));
            }
            Err(_) => {
                systemctl_messages.push(
                            "systemctl no disponible; ejecuta manualmente: systemctl --user enable --now silverwarden.service".to_string(),
                        );
            }
        }
    }

    let mut out = format!(
        "Instalado:\n  {}\n  {}\n",
        unit_path.display(),
        policy_path.display(),
    );
    if !warnings.is_empty() {
        out.push_str("\nAdvertencias:\n");
        for w in warnings {
            out.push_str(&format!("  - {}\n", w));
        }
    }
    if !systemctl_messages.is_empty() {
        out.push_str("\nSystemctl:\n");
        for m in systemctl_messages {
            out.push_str(&format!("  - {}\n", m));
        }
    }
    Ok(out)
}
